/*
 * Copyright (C) 2008 Search Solution Corporation. All rights reserved by Search Solution.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */


/*
 * cm_server_util.cpp -
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>            /* isalpha()        */

#if defined(WINDOWS)
#include <process.h>
#include <winsock2.h>
#include <psapi.h>
#include <sys/locking.h>
#include <Tlhelp32.h>
#include <sys/timeb.h>
#include <winternl.h>
#else
#include <sys/types.h>        /* umask()          */
#include <sys/stat.h>         /* umask(), stat()  */
#include <unistd.h>
#include <dirent.h>           /* opendir() ...    */
#include <pwd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/statvfs.h>
#include <netdb.h>
#include <arpa/inet.h>
#if defined(LINUX)
#include <sys/wait.h>
#endif /* LINUX */
#if !defined(HPUX)
#include <sys/procfs.h>
#endif
#include <sys/file.h>
#endif

#if defined(AIX)
#include <libperfstat.h>
#endif

#include "cm_log.h"
#include "cm_connect_info.h"
#include "cm_porting.h"
#include "cm_server_util.h"
#include "cm_dep.h"
#include "cm_config.h"
#include "cm_job_task.h"
#include "cm_cmd_exec.h"
#include "cm_text_encryption.h"
#include "cm_stat.h"
#include "cm_user.h"

#include <assert.h>

#ifdef FSERVER_SLAVE
#define DEF_TASK_FUNC(TASK_FUNC_PTR)    TASK_FUNC_PTR
#else
#define DEF_TASK_FUNC(TASK_FUNC_PTR)    NULL
#endif

/* for ut_getdelim */
#define MAX_LINE ((int)(10*1024*1024))
#define MIN_CHUNK 4096

static T_FSERVER_TASK_INFO task_info[] = {
    {"startinfo", TS_STARTINFO, 0, DEF_TASK_FUNC (ts_startinfo), FSVR_SA, ALL_AUTHORITY},
    {"userinfo", TS_USERINFO, 0, DEF_TASK_FUNC (ts_userinfo), FSVR_CS, ALL_AUTHORITY},
    {"createuser", TS_CREATEUSER, 1, DEF_TASK_FUNC (ts_create_user), FSVR_CS, AU_DBO},
    {"deleteuser", TS_DELETEUSER, 1, DEF_TASK_FUNC (ts_delete_user), FSVR_CS, AU_DBO},
    {"updateuser", TS_UPDATEUSER, 1, DEF_TASK_FUNC (ts_update_user), FSVR_CS, AU_DBO},
    {"createdb", TS_CREATEDB, 1, DEF_TASK_FUNC (tsCreateDB), FSVR_SA, AU_DBC},
    {"deletedb", TS_DELETEDB, 1, DEF_TASK_FUNC (tsDeleteDB), FSVR_SA, AU_DBC},
    {"renamedb", TS_RENAMEDB, 1, DEF_TASK_FUNC (tsRenameDB), FSVR_SA, AU_DBC},
    {"startdb", TS_STARTDB, 0, DEF_TASK_FUNC (tsStartDB), FSVR_NONE, AU_DBC | AU_DBO},
    {"stopdb", TS_STOPDB, 0, DEF_TASK_FUNC (tsStopDB), FSVR_CS,AU_DBC | AU_DBO},
    {"dbspaceinfo", TS_DBSPACEINFO, 0, DEF_TASK_FUNC (tsDbspaceInfo), FSVR_SA_CS, ALL_AUTHORITY},
    {"classinfo", TS_CLASSINFO, 0, DEF_TASK_FUNC (ts_class_info), FSVR_SA_CS, ALL_AUTHORITY},
    {"class", TS_CLASS, 0, DEF_TASK_FUNC (ts_class), FSVR_CS, ALL_AUTHORITY},
    {"setsysparam", TS_SETSYSPARAM, 1, DEF_TASK_FUNC (ts_set_sysparam), FSVR_NONE, AU_DBC | AU_DBO},
    {"getallsysparam", TS_GETALLSYSPARAM, 0, DEF_TASK_FUNC (ts_get_all_sysparam), FSVR_NONE, ALL_AUTHORITY},
    {"addvoldb", TS_ADDVOLDB, 1, DEF_TASK_FUNC (tsRunAddvoldb), FSVR_SA_CS, AU_DBC | AU_DBO},
    {"getloginfo", TS_GETLOGINFO, 0, DEF_TASK_FUNC (ts_get_log_info), FSVR_NONE, ALL_AUTHORITY},
    {"viewlog", TS_VIEWLOG, 0, DEF_TASK_FUNC (ts_view_log), FSVR_NONE, ALL_AUTHORITY},
    {"viewlog2", TS_VIEWLOG, 0, DEF_TASK_FUNC (ts_view_log), FSVR_NONE, ALL_AUTHORITY},
    {"resetlog", TS_RESETLOG, 0, DEF_TASK_FUNC (ts_reset_log), FSVR_NONE, AU_DBC | AU_DBO},
    {"getenv", TS_GETENV, 0, DEF_TASK_FUNC (tsGetEnvironment), FSVR_SA_UC, ALL_AUTHORITY},
    {"updateattribute", TS_UPDATEATTRIBUTE, 1, DEF_TASK_FUNC (ts_update_attribute), FSVR_CS, ALL_AUTHORITY},
    {"kill_process", TS_KILL_PROCESS, 1, DEF_TASK_FUNC (ts_kill_process), FSVR_NONE, AU_DBC | AU_DBO},
    {"copydb", TS_COPYDB, 1, DEF_TASK_FUNC (ts_copydb), FSVR_SA, AU_DBC},
    {"optimizedb", TS_OPTIMIZEDB, 1, DEF_TASK_FUNC (ts_optimizedb), FSVR_SA_CS, AU_DBC | AU_DBO},
    {"plandump", TS_PLANDUMP, 1, DEF_TASK_FUNC (ts_plandump), FSVR_CS, ALL_AUTHORITY},
    {"paramdump", TS_PARAMDUMP, 1, DEF_TASK_FUNC (ts_paramdump), FSVR_SA_CS, ALL_AUTHORITY},
    {"statdump", TS_STATDUMP, 1, DEF_TASK_FUNC (ts_statdump), FSVR_CS, ALL_AUTHORITY},
    {"checkdb", TS_CHECKDB, 0, DEF_TASK_FUNC (ts_checkdb), FSVR_SA_CS, AU_DBC | AU_DBO},
    {"compactdb", TS_COMPACTDB, 1, DEF_TASK_FUNC (ts_compactdb), FSVR_SA, AU_DBC | AU_DBO},
    {"backupdbinfo", TS_BACKUPDBINFO, 0, DEF_TASK_FUNC (ts_backupdb_info), FSVR_NONE, ALL_AUTHORITY},
    {"backupdb", TS_BACKUPDB, 0, DEF_TASK_FUNC (ts_backupdb), FSVR_SA_CS, AU_DBC | AU_DBO},
    {"unloaddb", TS_UNLOADDB, 1, DEF_TASK_FUNC (ts_unloaddb), FSVR_SA, AU_DBC | AU_DBO},
    {"unloadinfo", TS_UNLOADDBINFO, 0, DEF_TASK_FUNC (ts_unloaddb_info), FSVR_NONE, ALL_AUTHORITY},
    {"loaddb", TS_LOADDB, 1, DEF_TASK_FUNC (ts_loaddb), FSVR_SA, AU_DBC | AU_DBO},
    {"gettransactioninfo", TS_GETTRANINFO, 0, DEF_TASK_FUNC (ts_get_tran_info), FSVR_CS, ALL_AUTHORITY},
    {"killtransaction", TS_KILLTRAN, 1, DEF_TASK_FUNC (ts_killtran), FSVR_CS, AU_DBC | AU_DBO | AU_MON},
    {"lockdb", TS_LOCKDB, 0, DEF_TASK_FUNC (ts_lockdb), FSVR_CS, ALL_AUTHORITY},
    {"getbackuplist", TS_GETBACKUPLIST, 0, DEF_TASK_FUNC (ts_get_backup_list), FSVR_NONE, ALL_AUTHORITY},
    {"restoredb", TS_RESTOREDB, 1, DEF_TASK_FUNC (ts_restoredb), FSVR_SA, AU_DBC | AU_DBO},
    {"backupvolinfo", TS_BACKUPVOLINFO, 0, DEF_TASK_FUNC (ts_backup_vol_info), FSVR_SA, ALL_AUTHORITY},
    {"getdbsize", TS_GETDBSIZE, 0, DEF_TASK_FUNC (ts_get_dbsize), FSVR_SA_CS, ALL_AUTHORITY},
    {"getbackupinfo", TS_GETBACKUPINFO, 0, DEF_TASK_FUNC (ts_get_backup_info), FSVR_NONE, ALL_AUTHORITY},
    {"addbackupinfo", TS_ADDBACKUPINFO, 1, DEF_TASK_FUNC (ts_add_backup_info), FSVR_NONE, AU_DBC | AU_DBO | AU_JOB},
    {"deletebackupinfo", TS_DELETEBACKUPINFO, 1, DEF_TASK_FUNC (ts_delete_backup_info), 
                         FSVR_NONE, AU_DBC | AU_DBO | AU_JOB},
    {"setbackupinfo", TS_SETBACKUPINFO, 0, DEF_TASK_FUNC (ts_set_backup_info), FSVR_NONE, AU_DBC | AU_DBO | AU_JOB},
    {"getautoaddvol", TS_GETAUTOADDVOL, 0, DEF_TASK_FUNC (ts_get_auto_add_vol), FSVR_NONE, ALL_AUTHORITY},
    {"setautoaddvol", TS_SETAUTOADDVOL, 1, DEF_TASK_FUNC (ts_set_auto_add_vol), FSVR_NONE, AU_DBC | AU_DBO},
    {"checkdir", TS_CHECKDIR, 0, DEF_TASK_FUNC (ts_check_dir), FSVR_NONE, ALL_AUTHORITY},
    {"getautobackupdberrlog", TS_AUTOBACKUPDBERRLOG, 0, DEF_TASK_FUNC (ts_get_autobackupdb_error_log), 
                              FSVR_NONE, ALL_AUTHORITY},
    {"getautoexecqueryerrlog", TS_AUTOEXECQUERYERRLOG, 0, DEF_TASK_FUNC (ts_get_autoexecquery_error_log),
                               FSVR_NONE, ALL_AUTHORITY},
    {"getdbmtuserinfo", TS_GETDBMTUSERINFO, 0, DEF_TASK_FUNC (tsGetDBMTUserInfo), 
                               FSVR_NONE, ALL_AUTHORITY},
    {"deletedbmtuser", TS_DELETEDBMTUSER, 1, DEF_TASK_FUNC (tsDeleteDBMTUser), FSVR_NONE, AU_DBC},
    {"updatedbmtuser", TS_UPDATEDBMTUSER, 1, DEF_TASK_FUNC (tsUpdateDBMTUser), FSVR_NONE, AU_DBC},
    {"setdbmtpasswd", TS_SETDBMTPASSWD, 1,DEF_TASK_FUNC (tsChangeDBMTUserPasswd), FSVR_NONE, ALL_AUTHORITY ^ AU_DBC},
    {"adddbmtuser", TS_ADDDBMTUSER, 1, DEF_TASK_FUNC (tsCreateDBMTUser), FSVR_NONE, AU_DBC},
    {"getaddvolstatus", TS_GETADDVOLSTATUS, 0, DEF_TASK_FUNC (ts_get_addvol_status), FSVR_NONE, ALL_AUTHORITY},
    {"getautoaddvollog", TS_GETAUTOADDVOLLOG, 0, DEF_TASK_FUNC (tsGetAutoaddvolLog), FSVR_UC, ALL_AUTHORITY},
    {"getinitbrokersinfo", TS2_GETINITUNICASINFO, 0, DEF_TASK_FUNC (ts2_get_unicas_info), FSVR_UC, ALL_AUTHORITY},
    {"getbrokersinfo", TS2_GETUNICASINFO, 0, DEF_TASK_FUNC (ts2_get_unicas_info), FSVR_UC, ALL_AUTHORITY},
    {"startbroker", TS2_STARTUNICAS, 0, DEF_TASK_FUNC (ts2_start_unicas), FSVR_UC, AU_DBC | AU_DBO | AU_BRK},
    {"stopbroker", TS2_STOPUNICAS, 0, DEF_TASK_FUNC (ts2_stop_unicas), FSVR_UC, AU_DBC | AU_DBO | AU_BRK},
    {"getadminloginfo", TS2_GETADMINLOGINFO, 0, DEF_TASK_FUNC (ts2_get_admin_log_info), FSVR_UC, ALL_AUTHORITY},
    {"getlogfileinfo", TS2_GETLOGFILEINFO, 0, DEF_TASK_FUNC (ts2_get_logfile_info), FSVR_UC, ALL_AUTHORITY},
    {"getaddbrokerinfo", TS2_GETADDBROKERINFO, 0, DEF_TASK_FUNC (ts2_get_add_broker_info), FSVR_UC, ALL_AUTHORITY},
    {"deletebroker", TS2_DELETEBROKER, 1, DEF_TASK_FUNC (ts2_delete_broker), FSVR_UC, AU_DBC | AU_DBO | AU_BRK},
    {"getbrokerstatus", TS2_GETBROKERSTATUS, 0, DEF_TASK_FUNC (ts2_get_broker_status), FSVR_UC, ALL_AUTHORITY},
    {"broker_setparam", TS2_SETBROKERCONF, 1, DEF_TASK_FUNC (ts2_set_broker_conf), FSVR_UC, AU_DBC | AU_DBO | AU_BRK},
    {"broker_start", TS2_STARTBROKER, 0, DEF_TASK_FUNC (ts2_start_broker), FSVR_UC, AU_DBC | AU_DBO | AU_BRK},
    {"broker_stop", TS2_STOPBROKER, 0, DEF_TASK_FUNC (ts2_stop_broker), FSVR_UC, AU_DBC | AU_DBO | AU_BRK},
    {"broker_restart", TS2_RESTARTBROKERAS, 0, DEF_TASK_FUNC (ts2_restart_broker_as), 
                       FSVR_UC, AU_DBC | AU_DBO | AU_BRK},
    {"checkfile", TS_CHECKFILE, 0, DEF_TASK_FUNC (ts_check_file), FSVR_NONE, ALL_AUTHORITY},
    {"loadaccesslog", TS_LOADACCESSLOG, 0, DEF_TASK_FUNC (ts_load_access_log), FSVR_NONE, ALL_AUTHORITY},
    {"getaccesslogfiles", TS_GETACCESSLOGFILES, 0, DEF_TASK_FUNC (ts_get_access_log_files), FSVR_NONE, ALL_AUTHORITY},
    {"geterrorlogfiles", TS_GETERRORLOGFILES, 0, DEF_TASK_FUNC (ts_get_error_log_files), FSVR_NONE, ALL_AUTHORITY},
    {"addtrigger", TS_ADDNEWTRIGGER, 1, DEF_TASK_FUNC (ts_trigger_operation), FSVR_SA_CS, AU_DBC | AU_DBO},
    {"altertrigger", TS_ALTERTRIGGER, 1, DEF_TASK_FUNC (ts_trigger_operation), FSVR_SA_CS, AU_DBC | AU_DBO},
    {"droptrigger", TS_DROPTRIGGER, 1, DEF_TASK_FUNC (ts_trigger_operation), FSVR_SA_CS, AU_DBC | AU_DBO},
    {"gettriggerinfo", TS_GETTRIGGERINFO, 0, DEF_TASK_FUNC (ts_get_triggerinfo), FSVR_SA_CS, ALL_AUTHORITY},
    {"getautoexecquery", TS_GETAUTOEXECQUERY, 0, DEF_TASK_FUNC (ts_get_autoexec_query), FSVR_SA_CS, ALL_AUTHORITY},
    {"setautoexecquery", TS_SETAUTOEXECQUERY, 1, DEF_TASK_FUNC (ts_set_autoexec_query), 
                         FSVR_SA_CS, AU_DBC | AU_DBO | AU_JOB},
    {"getdiagdata", TS_GET_DIAGDATA, 0, DEF_TASK_FUNC (ts_get_diagdata), FSVR_NONE, ALL_AUTHORITY},
    {"getbrokerdiagdata", TS_GET_BROKER_DIAGDATA, 0, DEF_TASK_FUNC (ts_get_broker_diagdata), FSVR_NONE, ALL_AUTHORITY},
    {"addstatustemplate", TS_ADDSTATUSTEMPLATE, 0, DEF_TASK_FUNC (ts_addstatustemplate), 
                          FSVR_NONE, AU_DBC | AU_DBO | AU_MON},
    {"updatestatustemplate", TS_UPDATESTATUSTEMPLATE, 0, DEF_TASK_FUNC (ts_updatestatustemplate), 
                             FSVR_NONE, AU_DBC | AU_DBO | AU_MON},
    {"removestatustemplate", TS_REMOVESTATUSTEMPLATE, 0, DEF_TASK_FUNC (ts_removestatustemplate), 
                             FSVR_NONE, AU_DBC | AU_DBO | AU_MON},
    {"getstatustemplate", TS_GETSTATUSTEMPLATE, 0, DEF_TASK_FUNC (ts_getstatustemplate), FSVR_NONE, ALL_AUTHORITY},
    {"analyzecaslog", TS_ANALYZECASLOG, 0, DEF_TASK_FUNC (ts_analyzecaslog), FSVR_NONE, ALL_AUTHORITY},
    {"executecasrunner", TS_EXECUTECASRUNNER, 0, DEF_TASK_FUNC (ts_executecasrunner), 
                         FSVR_NONE, AU_DBC | AU_DBO | AU_BRK | AU_MON},
    {"removecasrunnertmpfile", TS_REMOVECASRUNNERTMPFILE, 0, DEF_TASK_FUNC (ts_removecasrunnertmpfile), 
                               FSVR_NONE, AU_DBC | AU_DBO | AU_BRK | AU_MON},
    {"getcaslogtopresult", TS_GETCASLOGTOPRESULT, 0, DEF_TASK_FUNC (ts_getcaslogtopresult), FSVR_NONE, ALL_AUTHORITY},
    {"dbmtuserlogin", TS_DBMTUSERLOGIN, 0, DEF_TASK_FUNC (tsDBMTUserLogin), FSVR_NONE, ALL_AUTHORITY},
    {"removelog", TS_REMOVE_LOG, 0, DEF_TASK_FUNC (ts_remove_log), FSVR_NONE, ALL_AUTHORITY},
    {"getdbprocstat", TS_GETDBPROCSTAT, 0, DEF_TASK_FUNC (ts_get_dbproc_stat), FSVR_SA_CS, ALL_AUTHORITY},
    {"gethoststat", TS_GETHOSTSTAT, 0, DEF_TASK_FUNC (ts_get_host_stat), FSVR_SA_CS, ALL_AUTHORITY},
    {"heartbeatlist", TS_HEARTBEAT_LIST, 0, DEF_TASK_FUNC (ts_heartbeat_list), FSVR_SA_CS, ALL_AUTHORITY},
    {"changemode", TS_CHANGEMODE, 0, DEF_TASK_FUNC (ts_changemode), FSVR_CS, AU_DBC | AU_DBO},
    {"getdbmode", TS_GETDBMODE, 0, DEF_TASK_FUNC (ts_get_db_mode), FSVR_SA_CS, ALL_AUTHORITY},
    {"getstandbyserverstat", TS_GET_STANDBY_SERVER_STAT, 0, DEF_TASK_FUNC (ts_get_standby_server_stat), 
                             FSVR_SA_CS, ALL_AUTHORITY},
    {"rolechange", TS_ROLE_CHANGE, 0, DEF_TASK_FUNC (ts_role_change), FSVR_CS, AU_DBC | AU_DBO},
    {"userverify", TS_USER_VERIFY, 0, DEF_TASK_FUNC (ts_user_verify), FSVR_SA_CS, ALL_AUTHORITY},
    {"runsqlstatement", TS_RUN_SQL_STATEMENT, 0, DEF_TASK_FUNC (ts_run_sql_statement), FSVR_SA_CS, ALL_AUTHORITY},
    {"writeandsaveconf", TS_WRITE_AND_SAVE_CONF, 0, DEF_TASK_FUNC (ts_write_and_save_conf), FSVR_SA_CS, AU_DBC | AU_DBO},
    {"getfiletotallinenum", TS_GET_FILE_TOTAL_LINE_NUM, 0, DEF_TASK_FUNC (ts_get_file_total_line_num), FSVR_SA_CS, ALL_AUTHORITY},
    {"runscript", TS_RUN_SCRIPT, 0, DEF_TASK_FUNC (ts_run_script), FSVR_SA_CS, ALL_AUTHORITY},
    {"copyfolder", TS_COPY_FOLDER, 0, DEF_TASK_FUNC (ts_copy_folder), FSVR_SA_CS, AU_DBC | AU_DBO},
    {"deletefolder", TS_DELETE_FOLDER, 0, DEF_TASK_FUNC (ts_delete_folder), FSVR_SA_CS, AU_DBC | AU_DBO},
    {"getfolderswithkeyword", TS_GET_FOLDERS_WITH_KEYWORD, 0,DEF_TASK_FUNC (ts_get_folders_with_keyword), 
                              FSVR_SA_CS, ALL_AUTHORITY},
    {"getenvvarbyname", TS_GET_ENVVAR_BY_NAME, 0, DEF_TASK_FUNC (ts_get_envvar_by_name), FSVR_SA_CS, ALL_AUTHORITY},
    {"errortrace", TS_ERROR_TRACE, 0, DEF_TASK_FUNC (ts_error_trace), FSVR_SA_CS, ALL_AUTHORITY},
    {"login", TS_LOGIN, 0, DEF_TASK_FUNC (ts_login), FSVR_SA_CS, ALL_AUTHORITY},
    {"logout", TS_LOGOUT, 0, DEF_TASK_FUNC (ts_logout), FSVR_SA_CS, ALL_AUTHORITY},
    {"getcmsenv", TS_GET_CMS_ENV, 0, DEF_TASK_FUNC (ts_get_cms_env), FSVR_SA_CS, ALL_AUTHORITY},
    {"keepalive", TS_KEEPALIVE, 0, DEF_TASK_FUNC (ts_keepalive), FSVR_CS, ALL_AUTHORITY},
    {"removefiles", TS_REMOVE_FILES, 0, DEF_TASK_FUNC (ts_remove_files), FSVR_NONE, AU_DBC | AU_DBO},
    {"#jobtest", TS_JOB_TEST, 0, DEF_TASK_FUNC (ts_job_test), FSVR_NONE, ALL_AUTHORITY},
    {"dbspace", TS_DB_SPACE_INFO, 0, DEF_TASK_FUNC (ts_dbs_spaceInfo), FSVR_NONE, ALL_AUTHORITY},
    {"shard_start", TS_SHARD_START, 0, DEF_TASK_FUNC (ts_shard_start), FSVR_NONE, AU_DBC | AU_DBO | AU_BRK},
    {"shard_stop", TS_SHARD_STOP, 0, DEF_TASK_FUNC (ts_shard_stop), FSVR_NONE, AU_DBC | AU_DBO | AU_BRK},
    {"getshardinfo", TS_GET_SHARD_INFO, 0, DEF_TASK_FUNC (ts_get_shard_info), FSVR_NONE, ALL_AUTHORITY},
    {"getshardstatus", TS_GET_SHARD_STATUS, 0, DEF_TASK_FUNC (ts_get_shard_status), FSVR_NONE, ALL_AUTHORITY},
    {"broker_changer", TS_BROKER_CHANGER, 0, DEF_TASK_FUNC (ts_broker_changer), FSVR_NONE, AU_DBC | AU_DBO | AU_BRK},
    {"ha_start", TS_HA_START, 0, DEF_TASK_FUNC (ts_ha_start), FSVR_NONE, AU_DBC | AU_DBO},
    {"ha_stop", TS_HA_STOP, 0, DEF_TASK_FUNC (ts_ha_stop), FSVR_NONE, AU_DBC | AU_DBO},
    {"ha_status", TS_HA_STATUS, 0, DEF_TASK_FUNC (ts_ha_status), FSVR_NONE, ALL_AUTHORITY},
    {"ha_copylogdb", TS_HA_COPYLOGDB, 0, DEF_TASK_FUNC (ts_ha_copylogdb), FSVR_NONE, AU_DBC | AU_DBO},
    {"ha_applylogdb", TS_HA_APPLYLOGDB, 0, DEF_TASK_FUNC (ts_ha_applylogdb), FSVR_NONE, AU_DBC | AU_DBO},
    {"ha_reload", TS_HA_RELOAD, 0, DEF_TASK_FUNC (ts_ha_reload), FSVR_NONE, AU_DBC | AU_DBO},
    {"list_dir", TS_LIST_DIR, 0, DEF_TASK_FUNC (ts_list_dir), FSVR_NONE, ALL_AUTHORITY},
    {"autoupdate", TS_AUTO_UPDATE, 0, DEF_TASK_FUNC (ts_auto_update), FSVR_NONE, AU_ADMIN},
    {"isupdatesuccess", TS_IS_UPDATE_SUCCESS, 0, DEF_TASK_FUNC (ts_is_update_success), FSVR_NONE, AU_ADMIN},
    {"monitorprocess", TS_MONITOR_PROCESS, 0, DEF_TASK_FUNC (ts_monitor_process), FSVR_NONE, ALL_AUTHORITY},
    {"generatecert", TS_GENERATE_CERT, 0, DEF_TASK_FUNC (ts_generate_cert), FSVR_NONE, ALL_AUTHORITY},
    {NULL, TS_UNDEFINED, 0, NULL, FSVR_NONE, 0}
};

#if defined(WINDOWS)

typedef BOOL (WINAPI * GET_SYSTEM_TIMES) (LPFILETIME, LPFILETIME, LPFILETIME);
typedef NTSTATUS (WINAPI * NT_QUERY_SYSTEM_INFORMATION) (SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

/*
 * 0 - init_state.
 * 1 - load GetSystemTime.
 * 2 - load NtQuerySystemInformation.
 * 3 - error state.
 */
static volatile int s_symbol_loaded = 0;
static volatile GET_SYSTEM_TIMES s_pfnGetSystemTimes = NULL;
static volatile NT_QUERY_SYSTEM_INFORMATION s_pfnNtQuerySystemInformation = NULL;
#endif

static int _maybe_ip_addr (char *hostname);
static int _ip_equal_hostent (struct hostent *hp, char *token);
static int get_short_filename (char *ret_name, int ret_name_len,
                               char *short_filename);
static bool is_process_running (const char *process_name, unsigned int sleep_time);

/**
* is_process_running is to check process running or not by checking pid
* process_name: the name of process that must be in $CUBRID/bin
* sleep_time: millisecond
*/
static bool
is_process_running (const char *process_name, unsigned int sleep_time)
{
    FILE *input = NULL;
    char buf[16], cmd[PATH_MAX];

    SLEEP_MILISEC (0, sleep_time);

#if !defined (DO_NOT_USE_CUBRIDENV)
    sprintf (cmd, "%s/%s/%s getpid", sco.szCubrid, CUBRID_DIR_BIN,
             process_name);
#else
    sprintf (cmd, "%s/%s getpid", CUBRID_BINDIR, process_name);
#endif
    input = popen (cmd, "r");
    if (input == NULL)
    {
        return false;
    }

    memset (buf, '\0', sizeof (buf));
    if ((fgets (buf, 16, input) == NULL) || atoi (buf) <= 0)
    {
        pclose (input);
        return false;
    }

    pclose (input);

    return true;
}

#if !defined(WINDOWS)
int
run_child_linux (const char *pname, const char *const argv[], int wait_flag,
                 const char *stdin_file, char *stdout_file, char *stderr_file,
                 int *exit_status)
{
    int pid = 0;

    if (exit_status != NULL)
    {
        *exit_status = 0;
    }
    
    if (wait_flag)
        signal (SIGCHLD, SIG_DFL);
    else
        signal (SIGCHLD, SIG_IGN);

    pid = fork ();
    if (pid == 0)
    {
        FILE *fp = NULL;

        close_all_fds (3);

        if (stdin_file != NULL)
        {
            fp = fopen (stdin_file, "r");
            if (fp != NULL)
            {
                dup2 (fileno (fp), 0);
                fclose (fp);
            }
        }

        if (stdout_file != NULL)
        {
            unlink (stdout_file);
            fp = fopen (stdout_file, "w");
            if (fp != NULL)
            {
                dup2 (fileno (fp), 1);
                fclose (fp);
            }
        }

        
        if (stderr_file != NULL)
        {
            unlink (stderr_file);
            fp = fopen (stderr_file, "w");
            if (fp != NULL)
            {
                dup2 (fileno (fp), 2);
                fclose (fp);
            }
        }

        execv (pname, (char *const *) argv);
        exit (0);
    }

    if (pid < 0)
        return -1;

    if (wait_flag)
    {
        int status = 0;
        waitpid (pid, &status, 0);
        if (exit_status != NULL)
            *exit_status = status;
        return 0;
    }
    else
    {
        return pid;
    }
}
#endif

int
_op_check_is_localhost (char *token, char *hname)
{
    struct hostent *hp;

    if ((hp = gethostbyname (hname)) == NULL)
    {
        return -1;
    }

    /* if token is an ip address. */
    if (_maybe_ip_addr (token) > 0)
    {
        /* if token equal 127.0.0.1 or the ip is in the list of hname. */
        if ((strcmp (token, "127.0.0.1") == 0)
            || _ip_equal_hostent (hp, token) == 0)
        {
            return 0;
        }
    }
    else
    {
        /*
        * if token is not an ip address,
        * then compare it with the hostname ignore case.
        */
        if ((strcasecmp (token, hname) == 0)
            || (strcasecmp (token, "localhost") == 0))
        {
            return 0;
        }
    }
    return -1;
}

static int
_maybe_ip_addr (char *hostname)
{
    if (hostname == NULL)
    {
        return 0;
    }
    return (isdigit (hostname[0]) ? 1 : 0);
}

static int
_ip_equal_hostent (struct hostent *hp, char *token)
{
    int i;
    int retval = -1;
    const char *tmpstr = NULL;
    struct in_addr inaddr;

    if (hp == NULL)
    {
        return retval;
    }

    for (i = 0; hp->h_addr_list[i] != NULL; i++)
    {
        /* change ip address of hname to string. */
        inaddr.s_addr = *(unsigned long *) hp->h_addr_list[i];
        tmpstr = inet_ntoa (inaddr);

        /* compare the ip string with token. */
        if (strcmp (token, tmpstr) == 0)
        {
            retval = 0;
            break;
        }
    }
    return retval;
}

void
append_host_to_dbname (char *name_buf, const char *dbname, int buf_len)
{
    snprintf (name_buf, buf_len, "%s@127.0.0.1", dbname);
}

void *
increase_capacity (void *ptr, int block_size, int old_count, int new_count)
{
    if (new_count <= old_count || new_count <= 0)
        return NULL;

    if (ptr == NULL)
    {
        if ((ptr = MALLOC (block_size * new_count)) == NULL)
            return NULL;
        memset (ptr, 0, block_size * new_count);
    }
    else
    {
        if ((ptr = realloc (ptr, block_size * new_count)) == NULL)
            return NULL;
        memset ((char *) ptr + old_count * block_size, 0,
                block_size * (new_count - old_count));
    }

    return ptr;
}

char *
strcpy_limit (char *dest, const char *src, int buf_len)
{
    strncpy (dest, src, buf_len - 1);
    dest[buf_len - 1] = '\0';
    return dest;
}

int
ut_getdelim (char **lineptr, int *n, int delimiter, FILE * fp)
{
    int result = -1;
    int cur_len = 0;
    int c;

    if (lineptr == NULL || n == NULL || fp == NULL)
    {
        return -1;
    }

    if (*lineptr == NULL || *n == 0)
    {
        char *new_lineptr;
        *n = MIN_CHUNK;
        new_lineptr = (char *) realloc (*lineptr, *n);

        if (new_lineptr == NULL)
        {
            return -1;
        }
        *lineptr = new_lineptr;
    }

    for (;;)
    {
        c = getc (fp);
        if (c == EOF)
        {
            result = -1;
            break;
        }

        /* Make enough space for len+1 (for final NUL) bytes. */
        if (cur_len + 1 >= *n)
        {
            int line_len = 2 * *n + 1;
            char *new_lineptr;

            if (line_len > MAX_LINE)
            {
                line_len = MAX_LINE;
            }
            if (cur_len + 1 >= line_len)
            {
                return -1;
            }

            new_lineptr = (char *) realloc (*lineptr, line_len);
            if (new_lineptr == NULL)
            {
                return -1;
            }

            *lineptr = new_lineptr;
            *n = line_len;
        }
        (*lineptr)[cur_len] = c;
        cur_len++;

        if (c == delimiter)
            break;
    }
    (*lineptr)[cur_len] = '\0';
    result = cur_len ? cur_len : result;

    return result;
}

int
ut_getline (char **lineptr, int *n, FILE * fp)
{
    return ut_getdelim (lineptr, n, '\n', fp);
}

void
uRemoveCRLF (char *str)
{
    size_t i;
    if (str == NULL)
        return;
    for (i = strlen (str) - 1; (i >= 0) && (str[i] == 10 || str[i] == 13); i--)
    {
        str[i] = '\0';
    }
}

char *
time_to_str (time_t t, const char *fmt, char *buf, int type)
{
    struct tm ltm;
    struct tm *tm_p;

    tm_p = localtime (&t);
    if (tm_p == NULL)
    {
        *buf = '\0';
        return buf;
    }
    ltm = *tm_p;

    if (type == TIME_STR_FMT_DATE)
        sprintf (buf, fmt, ltm.tm_year + 1900, ltm.tm_mon + 1, ltm.tm_mday);
    else if (type == TIME_STR_FMT_TIME)
        sprintf (buf, fmt, ltm.tm_hour, ltm.tm_min, ltm.tm_sec);
    else                /* TIME_STR_FMT_DATE_TIME */
        sprintf (buf, fmt, ltm.tm_year + 1900, ltm.tm_mon + 1, ltm.tm_mday,
                 ltm.tm_hour, ltm.tm_min, ltm.tm_sec);
    return buf;
}

int
uStringEqual (const char *str1, const char *str2)
{
    if (str1 == NULL || str2 == NULL)
        return 0;
    if (strcmp (str1, str2) == 0)
        return 1;
    return 0;
}

int
uStringEqualIgnoreCase (const char *str1, const char *str2)
{
    if (str1 == NULL || str2 == NULL)
        return 0;
    if (strcasecmp (str1, str2) == 0)
        return 1;
    return 0;
}

void
write_manager_error_log (const char * protocol_str, const char * msg)
{
    char message[DBMT_ERROR_MSG_SIZE];

    snprintf (message, DBMT_ERROR_MSG_SIZE, "%s %s", protocol_str, msg);

    LOG_ERROR (message);
}

void
ut_error_log (nvplist * req, const char *errmsg)
{
    const char *id, *addr, *task;
    char strbuf[512];

    if ((task = nv_get_val (req, "task")) == NULL)
        task = "-";
    if ((addr = nv_get_val (req, "_CLIENTIP")) == NULL)
        addr = "-";
    if ((id = nv_get_val (req, "_ID")) == NULL)
        id = "-";
    if (errmsg == NULL)
        errmsg = "-";

    snprintf(strbuf, sizeof(strbuf), "%s %s %s %s", ACCESS_ERR, id, addr, task);

    write_manager_error_log (strbuf, errmsg);
}

void
write_manager_access_log (const char * protocol_str, const char * msg)
{
    char message[DBMT_ERROR_MSG_SIZE];

    snprintf (message, DBMT_ERROR_MSG_SIZE, "%s %s", protocol_str, msg);

    LOG_INFO (message);
}

void
ut_access_log (nvplist * req, const char *msg)
{
    const char *id, *cli_addr, *task;
    char strbuf[512];

    strbuf[0] = '\0';

    if ((task = nv_get_val (req, "task")) == NULL)
        task = "-";
    if ((cli_addr = nv_get_val (req, "_CLIENTIP")) == NULL)
        cli_addr = "-";
    if ((id = nv_get_val (req, "_ID")) == NULL)
        id = "-";
    if (msg == NULL)
        msg = "";

    snprintf(strbuf, sizeof(strbuf), "%s %s %s %s", ACCESS_LOG, id, cli_addr, task);

    write_manager_access_log (strbuf, msg);
}

int
ut_get_task_info (const char *task, char *access_log_flag,
                  T_TASK_FUNC * task_func, T_USER_AUTH * auth)
{
    int i;

    for (i = 0; task_info[i].task_str != NULL; i++)
    {
        if (uStringEqual (task, task_info[i].task_str))
        {
            if (access_log_flag)
                *access_log_flag = task_info[i].access_log_flag;
            if (task_func)
                *task_func = task_info[i].task_func;

            if (auth)
            {
                *auth = task_info[i].user_auth;
            }
            return task_info[i].task_code;
        }
    }

    return TS_UNDEFINED;
}

int
ut_send_response (SOCKET fd, nvplist * res)
{
    int i;

    if (res == NULL)
        return -1;

    for (i = 0; i < res->nvplist_size; ++i)
    {
        if (res->nvpairs[i] == NULL)
            continue;
        write_to_socket (fd, dst_buffer (res->nvpairs[i]->name),
                         dst_length (res->nvpairs[i]->name));
        write_to_socket (fd, dst_buffer (res->delimiter), res->delimiter->dlen);

        if (strncmp (res->nvpairs[i]->name->dbuf, ENCRYPT_SIGN,
                     strlen (ENCRYPT_SIGN)) == 0)
        {
            int str_len;
            char *encrypt_buf;

            str_len = dst_length (res->nvpairs[i]->value);
            str_len = MAX (str_len, MIN_ENCRYPT_LEN);

            /* make the len to be multiple of 8. */
            str_len = MAKE_MUTIPLE_EIGHT (str_len);

            if ((encrypt_buf = (char *) MALLOC (str_len * 2 + 1)) == NULL)
                return -1;

            uEncrypt (str_len, dst_buffer (res->nvpairs[i]->value),
                      encrypt_buf);
            write_to_socket (fd, encrypt_buf, (int) strlen (encrypt_buf));

            FREE_MEM (encrypt_buf);
        }
        else
        {
            write_to_socket (fd, dst_buffer (res->nvpairs[i]->value),
                             dst_length (res->nvpairs[i]->value));
        }
        write_to_socket (fd, dst_buffer (res->endmarker), res->endmarker->dlen);
    }
    write_to_socket (fd, dst_buffer (res->listcloser), res->listcloser->dlen);

    return 0;
}

/*
 *  read incoming data and construct name-value pair list of request
 */
int
ut_receive_request (SOCKET fd, nvplist * req)
{
    int rc;
    char c;
    dstring *linebuf = NULL;
    char *p;

    linebuf = dst_create ();

    while ((rc = read_from_socket (fd, &c, 1)) == 1)
    {
        char *dstbuf;

        if (c == '\n')
        {
            /* if null string, stop parsing */
            if (dst_length (linebuf) == 0)
            {
                dst_destroy (linebuf);
                return 0;
            }

            dstbuf = dst_buffer (linebuf);
            if (dstbuf != NULL)
            {
                p = strchr (dstbuf, ':');
                if (p)
                {
                    *p = '\0';
                    p++;
                    if (strncmp (dstbuf, ENCRYPT_SIGN, strlen (ENCRYPT_SIGN)) == 0)
                    {
                        int len;
                        char *decrypt_buf;

                        len = (int) strlen (p);
                        if (len % 2)
                            goto error_return;

                        len /= 2;
                        if ((decrypt_buf = (char *) MALLOC (len + 1)) == NULL)
                            goto error_return;

                        /* decrypt the value. */
                        uDecrypt (len, p, decrypt_buf);
                        nv_add_nvp (req, dstbuf + strlen (ENCRYPT_SIGN),
                                    decrypt_buf);
                        free (decrypt_buf);
                    }
                    else
                    {
                        nv_add_nvp (req, dst_buffer (linebuf), p);
                    }
                }
            }
            dst_reset (linebuf);
        }
        else
        {
            if (c != '\r')
            dst_append (linebuf, &c, 1);
        }
    }

error_return:
    dst_destroy (linebuf);
    return -1;
}

void
ut_daemon_start (void)
{
#if defined(WINDOWS)
    return;
#else
    int childpid;

    /* Ignore the terminal stop signals */
    signal (SIGTTOU, SIG_IGN);
    signal (SIGTTIN, SIG_IGN);
    signal (SIGTSTP, SIG_IGN);

#if 0
    /* to make it run in background */
    signal (SIGHUP, SIG_IGN);
    childpid = PROC_FORK ();
    if (childpid > 0)
        exit (0);            /* kill parent */
#endif

    /* setpgrp(); */
    setsid ();            /* become process group leader and  */
    /* disconnect from control terminal */

    signal (SIGHUP, SIG_IGN);
    childpid = PROC_FORK ();    /* to prevent from reaquiring control terminal */
    if (childpid > 0)
        exit (0);            /* kill parent */

#if 0
    /* change current working directory */
    chdir ("/");
    /* clear umask */
    umask (0);
#endif
#endif /* ifndef WINDOWS */
}

int
ut_write_pid (char *pid_file)
{
    FILE *pidfp;

    pidfp = fopen (pid_file, "w");
    if (pidfp == NULL)
    {
        perror ("fopen");
        return -1;
    }
    fprintf (pidfp, "%d\n", (int) getpid ());
    fclose (pidfp);
    return 0;
}

void
server_fd_clear (fd_set srv_fds)
{
#if !defined(WINDOWS)
    SOCKET i;
    int fd;

    for (i = 3; i < 1024; i++)
    {
        if (!FD_ISSET (i, &srv_fds))
            close (i);
    }

    fd = open ("/dev/null", O_RDWR);
#ifndef DIAG_DEBUG
    dup2 (fd, 1);
#endif
    dup2 (fd, 2);
#endif /* !WINDOWS */
}

int
uRetrieveDBDirectory (const char *dbname, char *target)
{
    int ret_val = ERR_NO_ERROR;
#ifdef    WINDOWS
    char temp_name[512];
#endif

    ret_val = uReadDBtxtFile (dbname, 1, target);
#ifdef    WINDOWS
    if (ret_val == ERR_NO_ERROR)
    {
        strcpy (temp_name, target);
        memset (target, '\0', strlen (target));
        if (GetLongPathName (temp_name, target, PATH_MAX) == 0)
        {
            strcpy (target, temp_name);
        }
    }
#endif

    return ret_val;
}

int
_isRegisteredDB (char *dn)
{
    if (uReadDBtxtFile (dn, 0, NULL) == ERR_NO_ERROR)
        return 1;

    return 0;
}

#if 0
/* dblist should have enough space  */
/* db names are delimited by '\0' for ease of using it */
int
uReadDBnfo (char *dblist)
{
    int retval = 0;
    char strbuf[512];
    char *p;
    FILE *infp;
    int lock_fd;

    lock_fd =
        uCreateLockFile (conf_get_dbmt_file (FID_LOCK_PSVR_DBINFO, strbuf));
    if (lock_fd < 0)
        return -1;

    infp = fopen (conf_get_dbmt_file (FID_PSVR_DBINFO_TEMP, strbuf), "r");
    if (infp == NULL)
    {
        retval = -1;
    }
    else
    {
        fgets (strbuf, sizeof (strbuf), infp);
        retval = atoi (strbuf);

        p = dblist;
        while (fgets (strbuf, sizeof (strbuf), infp))
        {
            ut_trim (strbuf);
            strcpy (p, strbuf);
            p += (strlen (p) + 1);
        }
        fclose (infp);
    }

    uRemoveLockFile (lock_fd);

    return retval;
}
#endif
void
uWriteDBnfo (void)
{
    T_SERVER_STATUS_RESULT *cmd_res;

    cmd_res = cmd_server_status ();
    uWriteDBnfo2 (cmd_res);
    cmd_servstat_result_free (cmd_res);
}

void
uWriteDBnfo2 (T_SERVER_STATUS_RESULT * cmd_res)
{
    int i;
    int dbcnt;
    char strbuf[1024];
    int dbvect[MAX_INSTALLED_DB];
    int lock_fd;
    FILE *outfp;
    T_SERVER_STATUS_INFO *info;

    lock_fd =
        uCreateLockFile (conf_get_dbmt_file (FID_LOCK_PSVR_DBINFO, strbuf));
    if (lock_fd < 0)
        return;

    outfp = fopen (conf_get_dbmt_file (FID_PSVR_DBINFO_TEMP, strbuf), "w");
    if (outfp != NULL)
    {
        dbcnt = 0;
        if (cmd_res == NULL)
        {
            fprintf (outfp, "%d\n", dbcnt);
        }
        else
        {
            info = (T_SERVER_STATUS_INFO *) cmd_res->result;
            for (i = 0; i < cmd_res->num_result; i++)
            {
                if (_isRegisteredDB (info[i].db_name))
                {
                    dbvect[dbcnt] = i;
                    ++dbcnt;
                }
            }
            fprintf (outfp, "%d\n", dbcnt);
            info = (T_SERVER_STATUS_INFO *) cmd_res->result;
            for (i = 0; i < dbcnt; i++)
                fprintf (outfp, "%s\n", info[dbvect[i]].db_name);
        }
        fclose (outfp);
    }

    uRemoveLockFile (lock_fd);
}

int
ut_get_dblist (nvplist * res, char dbdir_flag)
{
    FILE *infile;
    char *dbinfo[4];
    char strbuf[1024], file[PATH_MAX];
    char hname[128];
    struct hostent *hp;
    unsigned char ip_addr[4];
    char *token = NULL;

    snprintf (file, PATH_MAX - 1, "%s/%s", sco.szCubrid_databases,
              CUBRID_DATABASE_TXT);
    if ((infile = fopen (file, "rt")) == NULL)
    {
        return ERR_DATABASETXT_OPEN;
    }

    memset (hname, 0, sizeof (hname));
    gethostname (hname, sizeof (hname));
    if ((hp = gethostbyname (hname)) == NULL)
    {
        fclose (infile);
        return ERR_NO_ERROR;
    }
    memcpy (ip_addr, hp->h_addr_list[0], 4);

    nv_add_nvp (res, "open", "dblist");
    while (fgets (strbuf, sizeof (strbuf), infile))
    {
        ut_trim (strbuf);

        if ((strbuf[0] == '#') || (string_tokenize (strbuf, dbinfo, 4) < 0))
        {
            continue;
        }

        for (token = strtok (dbinfo[2], ":"); token != NULL;
            token = strtok (NULL, ":"))
        {
            if ((hp = gethostbyname (token)) == NULL)
                continue;

            if (_op_check_is_localhost (token, hname) >= 0)
            {
#ifdef JSON_SUPPORT
                nv_add_nvp (res, "open", "dbs");
#endif
                nv_add_nvp (res, "dbname", dbinfo[0]);

                if (dbdir_flag)
                {
                    nv_add_nvp (res, "dbdir", dbinfo[1]);
                }
#ifdef JSON_SUPPORT
                nv_add_nvp (res, "close", "dbs");
#endif
                break;
            }
        }
    }
    nv_add_nvp (res, "close", "dblist");
    fclose (infile);
    return ERR_NO_ERROR;
}

int
uCreateLockFile (char *lockfile)
{
    int outfd;
#if !defined(WINDOWS)
    struct flock lock;
#endif

    outfd = open (lockfile, O_WRONLY | O_CREAT | O_TRUNC, 0666);

    if (outfd < 0)
        return outfd;

#if defined(WINDOWS)
    while (_locking (outfd, _LK_NBLCK, 1) < 0)
        Sleep (100);
#else
    lock.l_type = F_WRLCK;
    lock.l_start = 0;
    lock.l_whence = SEEK_SET;
    lock.l_len = 0;

    while (fcntl (outfd, F_SETLK, &lock) < 0)
        SLEEP_MILISEC (0, 10);
#endif

    return outfd;
}

void
uRemoveLockFile (int outfd)
{
#if !defined(WINDOWS)
    struct flock lock;

    lock.l_type = F_UNLCK;
    lock.l_start = 0;
    lock.l_whence = SEEK_SET;
    lock.l_len = 0;
#endif

#if defined(WINDOWS)
    _locking (outfd, _LK_UNLCK, 1);
#else
    fcntl (outfd, F_SETLK, &lock);
#endif
    close (outfd);
}

int
uRemoveDir (char *dir, int remove_file_in_dir)
{
    char path[1024];
    char command[2048];

    if (dir == NULL)
        return ERR_DIR_REMOVE_FAIL;

    strcpy (path, dir);
    memset (command, '\0', sizeof (command));
    ut_trim (path);

#if defined(WINDOWS)
    unix_style_path (path);
#endif

    if (access (path, F_OK) == 0)
    {
        if (remove_file_in_dir == REMOVE_DIR_FORCED)
        {
            sprintf (command, "%s %s \"%s\"", DEL_DIR, DEL_DIR_OPT, path);
            if (system (command) == -1)
                return ERR_DIR_REMOVE_FAIL;
        }
        else
        {
            if (rmdir (path) == -1)
            return ERR_DIR_REMOVE_FAIL;
        }
    }

    return ERR_NO_ERROR;
}

#if defined(WINDOWS)
int
folder_copy (const char *src_folder, const char *dest_folder)
{
    WIN32_FIND_DATA FileData;
    HANDLE hSearch;
    DWORD dwAttrs;
    char src_dir[PATH_MAX];
    char dest_dir[PATH_MAX];
    char search_file[PATH_MAX];
    int retval = 0;

    if (src_dir == NULL || dest_dir == NULL)
        goto err_return;

    strcpy_limit (src_dir, src_folder, sizeof (src_dir));
    strcpy_limit (dest_dir, dest_folder, sizeof (dest_dir));
    ut_trim (src_dir);
    ut_trim (dest_dir);

    /* create a new directory. */
    if (access (dest_dir, F_OK) != 0)
    {
        if (uCreateDir (dest_dir) != ERR_NO_ERROR)
            goto err_return;
    }

    if (access (src_dir, F_OK) != 0 || access (dest_dir, F_OK) != 0)
        goto err_clean_return;

    unix_style_path (src_dir);
    unix_style_path (dest_dir);

    /* Start searching for text files in the current directory. */
    snprintf (search_file, sizeof (search_file), "%s/*", src_dir);
    hSearch = FindFirstFile (search_file, &FileData);

    if (hSearch == INVALID_HANDLE_VALUE)
        goto err_clean_return;

    while (FindNextFile (hSearch, &FileData))
    {
        char src_path[PATH_MAX];
        char dest_path[PATH_MAX];

        snprintf (src_path, PATH_MAX - 1, "%s/%s", src_dir, FileData.cFileName);
        snprintf (dest_path, PATH_MAX - 1, "%s/%s", dest_dir,
                  FileData.cFileName);

        if (FileData.dwFileAttributes == FILE_ATTRIBUTE_DIRECTORY)
        {
            /* ignore folder "." and "..". */
            if (strcmp (FileData.cFileName, ".") == 0
                || strcmp (FileData.cFileName, "..") == 0)
                continue;

            folder_copy (src_path, dest_path);
            continue;
        }

        if (file_copy (src_path, dest_path) == 0)
        {
            dwAttrs = GetFileAttributes (dest_path);
            if (dwAttrs == INVALID_FILE_ATTRIBUTES)
                goto err_clean_return;
        }
        else
        {
            goto err_clean_return;
        }
    }

    /* Close the search handle. */
    FindClose (hSearch);

    return 0;

err_clean_return:
    uRemoveDir (dest_dir, REMOVE_DIR_FORCED);
err_return:
    FindClose (hSearch);
    return -1;
}
#else
int
folder_copy (const char *src_folder, const char *dest_folder)
{
    char src_dir[PATH_MAX];
    char dest_dir[PATH_MAX];
    struct dirent *dirp;
    struct stat statbuf;
    DIR *dp = NULL;

    if (src_dir == NULL || dest_dir == NULL)
        goto err_return;

    strcpy_limit (src_dir, src_folder, sizeof (src_dir));
    strcpy_limit (dest_dir, dest_folder, sizeof (dest_dir));
    ut_trim (src_dir);
    ut_trim (dest_dir);

    if (access (dest_dir, F_OK) != 0)
    {
        if (uCreateDir (dest_dir) != ERR_NO_ERROR)
            goto err_return;
    }

    if (access (src_dir, F_OK) != 0 || access (dest_dir, F_OK) != 0)
        goto err_clean_return;

    stat (src_dir, &statbuf);
    chmod (dest_dir, statbuf.st_mode);

    /* copy all the files that in src_path to dest_path. */
    dp = opendir (src_dir);
    if (dp == NULL)
        goto err_clean_return;

    while ((dirp = readdir (dp)) != NULL)
    {
        char src_path[PATH_MAX];
        char dest_path[PATH_MAX];

        snprintf (src_path, sizeof (src_path) - 1, "%s/%s", src_dir,
                  dirp->d_name);
        snprintf (dest_path, sizeof (dest_path) - 1, "%s/%s", dest_dir,
                  dirp->d_name);

        stat (src_path, &statbuf);

        if (S_ISDIR (statbuf.st_mode))
        {
            if (uStringEqual (dirp->d_name, ".")
                || uStringEqual (dirp->d_name, ".."))
                continue;

            if (folder_copy (src_path, dest_path) < 0)
                goto err_clean_return;
        }
        else
        {
            if (file_copy (src_path, dest_path) < 0)
                goto err_clean_return;
        }
    }

    closedir (dp);

    return 0;

err_clean_return:
    uRemoveDir (dest_dir, REMOVE_DIR_FORCED);
err_return:
    if (dp != NULL)
    {
        closedir (dp);
    }
    return -1;
}
#endif

int
uCreateDir (char *new_dir)
{
    char *p, path[1024];

    if (new_dir == NULL)
        return ERR_DIR_CREATE_FAIL;
    memset (path, 0, 1024);
    strncpy (path, new_dir, 1023);
    ut_trim (path);

#if defined(WINDOWS)
    unix_style_path (path);
#endif

#if defined(WINDOWS)
    if (path[0] == '/')
        p = path + 1;
    else if (strlen (path) > 3 && path[2] == '/')
        p = path + 3;
    else
        return ERR_DIR_CREATE_FAIL;
#else
    if (path[0] != '/')
        return ERR_DIR_CREATE_FAIL;
    p = path + 1;
#endif

    while (p != NULL)
    {
        p = strchr (p, '/');
        if (p != NULL)
            *p = '\0';
        if (access (path, F_OK) < 0)
        {
            if (mkdir (path, 0700) < 0)
            {
                return ERR_DIR_CREATE_FAIL;
            }
        }
        if (p != NULL)
        {
            *p = '/';
            p++;
        }
    }
    return ERR_NO_ERROR;
}

void
close_all_fds (int init_fd)
{
    int i;

    for (i = init_fd; i < 1024; i++)
    {
        close (i);
    }
}

char *
ut_trim (char *str)
{
    char *p;
    char *s;

    if (str == NULL)
        return (str);

    for (s = str;
        *s != '\0' && (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r');
        s++)
        ;
    if (*s == '\0')
    {
        *str = '\0';
        return (str);
    }

    /* *s must be a non-white char */
    for (p = s; *p != '\0'; p++)
    ;
    for (p--; *p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'; p--)
    ;
    *++p = '\0';

    if (s != str)
        memmove (str, s, strlen (s) + 1);

    return (str);
}

#if defined(WINDOWS)
int
ut_disk_free_space (char *path)
{
    char buf[1024];
    DWORD a, b, c, d;

    strcpy (buf, path);
    ut_trim (buf);
    if (buf[1] == ':')
        strcpy (buf + 2, "/");
    else
        strcpy (buf, "c:/");

    if (GetDiskFreeSpace (buf, &a, &b, &c, &d) == 0)
        return 0;

    return ((c >> 10) * ((b * a) >> 10));
}
#else
int
ut_disk_free_space (char *path)
{
    struct statvfs sv;

    if (statvfs (path, &sv) < 0)
        return 0;

    return ((((sv.f_bavail) >> 10) * sv.f_frsize) >> 10);
}
#endif

char *
ip2str (unsigned char *ip, char *ip_str)
{
    sprintf (ip_str, "%d.%d.%d.%d", (unsigned char) ip[0],
             (unsigned char) ip[1],
             (unsigned char) ip[2], (unsigned char) ip[3]);
    return ip_str;
}

int
string_tokenize_accept_laststring_space (char *str, char *tok[], int num_tok)
{
    int i;
    char *p;

    tok[0] = str;
    for (i = 1; i < num_tok; i++)
    {
        tok[i] = strpbrk (tok[i - 1], " \t");
        if (tok[i] == NULL)
            return -1;
        *(tok[i]) = '\0';
        p = (tok[i]) + 1;
        for (; *p && (*p == ' ' || *p == '\t'); p++)
        ;
        if (*p == '\0')
            return -1;
        tok[i] = p;
    }

    return 0;
}

int
string_tokenize (char *str, char *tok[], int num_tok)
{
    int i;
    char *p;

    tok[0] = str;
    for (i = 1; i < num_tok; i++)
    {
        tok[i] = strpbrk (tok[i - 1], " \t");
        if (tok[i] == NULL)
            return -1;
        *(tok[i]) = '\0';
        p = (tok[i]) + 1;
        for (; *p && (*p == ' ' || *p == '\t'); p++)
        ;
        if (*p == '\0')
            return -1;
        tok[i] = p;
    }
    p = strpbrk (tok[num_tok - 1], " \t");
    if (p)
        *p = '\0';

    return 0;
}

int
string_tokenize2 (char *str, char *tok[], int num_tok, int c)
{
    int i;
    char *p;

    for (i = 0; i < num_tok; i++)
        tok[i] = NULL;

    if (str == NULL)
        return -1;

    tok[0] = str;
    for (i = 1; i < num_tok; i++)
    {
        tok[i] = strchr (tok[i - 1], c);
        if (tok[i] == NULL)
            return -1;
        *(tok[i]) = '\0';
        (tok[i])++;
    }
    p = strchr (tok[num_tok - 1], c);
    if (p)
        *p = '\0';

    return 0;
}

int
read_from_socket (SOCKET sock_fd, char *buf, int size)
{
    int read_len;
    fd_set read_mask;
    int nfound;
    int maxfd;

    FD_ZERO (&read_mask);
    FD_SET (sock_fd, (fd_set *) & read_mask);
    maxfd = (int) sock_fd + 1;
again:
    nfound = select (maxfd, &read_mask, (fd_set *) 0, (fd_set *) 0, NULL);
    if (nfound < 0)
    {
        goto again;        /* interrupted by a signal */
    }

    if (FD_ISSET (sock_fd, (fd_set *) & read_mask))
    {
        read_len = recv (sock_fd, buf, size, 0);
    }
    else
    {
        return -1;
    }

    return read_len;
}

int
write_to_socket (SOCKET sock_fd, const char *buf, int size)
{
    int write_len;
    fd_set write_mask;
    int nfound;
    int maxfd;

    if (IS_INVALID_SOCKET (sock_fd))
    {
        return -1;
    }

    FD_ZERO (&write_mask);
    FD_SET (sock_fd, (fd_set *) & write_mask);
    maxfd = (int) sock_fd + 1;
again:
    nfound = select (maxfd, (fd_set *) 0, &write_mask, (fd_set *) 0, NULL);
    if (nfound < 0)
    {
        goto again;        /* interrupted by a signal */
    }

    if (FD_ISSET (sock_fd, (fd_set *) & write_mask))
    {
        write_len = send (sock_fd, buf, size, 0);
    }
    else
    {
        return -1;
    }

    return write_len;
}

#if defined(WINDOWS)
int
kill (int pid, int signo)
{
    HANDLE phandle;

    phandle = OpenProcess (PROCESS_TERMINATE, FALSE, pid);
    if (phandle == NULL)
    {
        int error = GetLastError ();
        if (error == ERROR_ACCESS_DENIED)
            errno = EPERM;
        else
            errno = ESRCH;
        return -1;
    }

    if (signo == SIGTERM)
        TerminateProcess (phandle, 0);

    CloseHandle (phandle);
    return 0;
}
#endif

#if defined(WINDOWS)
void
unix_style_path (char *path)
{
    char *p;
    for (p = path; *p; p++)
    {
        if (*p == '\\')
        *p = '/';
    }
}

char *
nt_style_path (char *path, char *new_path_buf)
{
    char *p;
    char *q;
    char tmp_path_buf[1024];

    if (path == new_path_buf)
    {
        strcpy (tmp_path_buf, path);
        q = tmp_path_buf;
    }
    else
    {
        q = new_path_buf;
    }
    if (strlen (path) < 2 || path[1] != ':')
    {
        *q++ = _getdrive () + 'A' - 1;
        *q++ = ':';
        *q++ = '\\';
    }

    for (p = path; *p; p++, q++)
    {
        if (*p == '/')
            *q = '\\';
        else
            *q = *p;
    }
    *q = '\0';
    for (q--; q != new_path_buf; q--)
    {
        if (*q == '\\')
            *q = '\0';
        else
            break;
    }
    if (*q == ':')
    {
        q++;
        *q++ = '\\';
        *q++ = '\\';
        *q = '\0';
    }
    if (path == new_path_buf)
    {
        strcpy (new_path_buf, tmp_path_buf);
    }
    return new_path_buf;
}
#endif

int
make_version_info (const char *cli_ver, int *major_ver, int *minor_ver)
{
    const char *p;
    if (cli_ver == NULL)
        return 0;

    p = cli_ver;
    *major_ver = atoi (p);
    p = strchr (p, '.');
    if (p != NULL)
        *minor_ver = atoi (p + 1);
    else
        *minor_ver = 0;

    return 1;
}

int
file_copy (char *src_file, char *dest_file)
{
    char strbuf[1024];
    int src_fd, dest_fd;
    size_t read_size, write_size;
    int mode = 0644;

#if !defined(WINDOWS)
    struct stat statbuf;

    if (stat (src_file, &statbuf) == 0)
        mode = statbuf.st_mode;
#endif

    if ((src_fd = open (src_file, O_RDONLY)) == -1)
        return -1;

    if ((dest_fd = open (dest_file, O_WRONLY | O_CREAT | O_TRUNC, mode)) == -1)
    {
        close (src_fd);
        return -1;
    }

#if defined(WINDOWS)
    if (setmode (src_fd, O_BINARY) == -1 || setmode (dest_fd, O_BINARY) == -1)
    {
        close (src_fd);
        close (dest_fd);
        return -1;
    }
#endif

    while ((read_size = read (src_fd, strbuf, sizeof (strbuf))) > 0)
    {
        if (read_size > sizeof (strbuf)
            || (write_size =
            write (dest_fd, strbuf, (unsigned int) read_size)) < read_size)
        {
            close (src_fd);
            close (dest_fd);
            unlink (dest_file);
            return -1;
        }
    }

    close (src_fd);
    close (dest_fd);

    return 0;
}

int
move_file (char *src_file, char *dest_file)
{
    if (file_copy (src_file, dest_file) < 0)
    {
        return -1;
    }
    else
        unlink (src_file);

    return 0;
}

#if defined(WINDOWS)
void
remove_end_of_dir_ch (char *path)
{
    if (path && path[strlen (path) - 1] == '\\')
        path[strlen (path) - 1] = '\0';
}
#endif

int
is_cmserver_process (int pid, const char *module_name)
{
#if defined(WINDOWS)
    HANDLE hModuleSnap = NULL;
    MODULEENTRY32 me32 = { 0 };

    hModuleSnap = CreateToolhelp32Snapshot (TH32CS_SNAPMODULE, pid);
    if (hModuleSnap == (HANDLE) - 1)
        return -1;

    me32.dwSize = sizeof (MODULEENTRY32);

    if (Module32First (hModuleSnap, &me32))
    {
        do
        {
            if (strcasecmp (me32.szModule, module_name) == 0)
            {
                CloseHandle (hModuleSnap);
                return 1;
            }
        }
        while (Module32Next (hModuleSnap, &me32));
    }
    CloseHandle (hModuleSnap);
    return 0;
#elif defined(LINUX)
    FILE *fp = NULL;
    char proc_path[PATH_MAX];
    char cmd_line[LINE_MAX];
    char *cmd_name = NULL;

    snprintf (proc_path, sizeof (proc_path), "/proc/%d/cmdline", pid);

    if (access (proc_path, F_OK) != 0)
    {
        return 0;
    }

    if ((fp = fopen (proc_path, "r")) == NULL)
    {
        return 0;
    }

    if (fread (cmd_line, sizeof (char), sizeof (cmd_line) - 1, fp) <= 0)
    {
        fclose (fp);
        return 0;
    }

    // Only the module_name should be compared
    cmd_name = strrchr (cmd_line, '/');
    if (cmd_name == NULL)
    {
        cmd_name = cmd_line;
    }
    else
    {
        cmd_name += 1;
    }

    if (!uStringEqual (cmd_name, module_name))
    {
        fclose (fp);
        return 0;
    }

    fclose (fp);
    return 1;
#elif defined(AIX)
    const char *argv[10];
    int argc = 0;
    int return_value = 0;
    char cmjs_pid[10];
    char result_file[1024];
    char buf[1024], cur_pid[10], prog_name[32];
    FILE *fRes;

    /*Init var */
    cmjs_pid[0] = '\0';
    result_file[0] = '\0';
    buf[0] = '\0';
    cur_pid[0] = '\0';
    prog_name[0] = '\0';

    snprintf (cmjs_pid, sizeof (cmjs_pid) - 1, "%d", pid);
    snprintf (result_file, sizeof (result_file) - 1, "%s/DBMT_js.%d",
              sco.dbmt_tmp_dir, (int) getpid ());
    argv[argc++] = "/usr/bin/ps";
    argv[argc++] = "-e";
    argv[argc] = NULL;

    if (run_child (argv, 1, NULL, result_file, NULL, NULL) < 0)
    {                /* ps */
        return -1;
    }

    fRes = fopen (result_file, "r");
    if (fRes)
    {
        while (fgets (buf, 1024, fRes))
        {
            if (sscanf (buf, "%9s %*s %*s %31s", cur_pid, prog_name) != 2)
            {
                continue;
            }

            if (strcmp (cur_pid, cmjs_pid) == 0
                && strcmp (prog_name, module_name) == 0)
            {
                return_value = 1;
                break;
            }
        }

        fclose (fRes);
    }

    unlink (result_file);
    return return_value;
#endif
}

int
make_default_env (void)
{
    int retval = ERR_NO_ERROR;
    char strbuf[512];
    FILE *fd;

    /* create log/manager directory */
#if !defined (DO_NOT_USE_CUBRIDENV)
    sprintf (strbuf, "%s/%s", sco.szCubrid, DBMT_LOG_DIR);
#else
    sprintf (strbuf, "%s", DBMT_LOG_DIR);
#endif
    if ((retval = uCreateDir (strbuf)) != ERR_NO_ERROR)
        return retval;

    /* create var/manager direcory */
#if !defined (DO_NOT_USE_CUBRIDENV)
    sprintf (strbuf, "%s/%s", sco.szCubrid, DBMT_PID_DIR);
#else
    sprintf (strbuf, "%s", DBMT_PID_DIR);
#endif
    if ((retval = uCreateDir (strbuf)) != ERR_NO_ERROR)
        return retval;

    /* create databases directory */
    sprintf (strbuf, "%s", sco.szCubrid_databases);
    if ((retval = uCreateDir (strbuf)) != ERR_NO_ERROR)
        return retval;

    /* if databases.txt file doesn't exist, create 0 byte file. */
    sprintf (strbuf, "%s/%s", sco.szCubrid_databases, CUBRID_DATABASE_TXT);
    if (access (strbuf, F_OK) < 0)
    {
        if ((fd = fopen (strbuf, "a")) == NULL)
            return ERR_FILE_CREATE_FAIL;
        fclose (fd);
    }
    return retval;
}


/*
 *  dbid, dbpasswd is filled by this function
 *  caller must provide space for dbid, dbpasswd
 */
int
_ut_get_dbaccess (nvplist * req, char *dbid, char *dbpasswd)
{
    int retval;
    char *ip, *port, *dbname;
    char _dbmt_error[1024];
    T_DBMT_CON_DBINFO con_dbinfo;

    dbid[0] = dbpasswd[0] = '\0';

    ip = nv_get_val (req, "_IP");
    port = nv_get_val (req, "_PORT");
    dbname = nv_get_val (req, "dbname");

    /* read conlist */
    memset (&con_dbinfo, 0, sizeof (T_DBMT_CON_DBINFO));
    if ((retval =
        dbmt_con_read_dbinfo (&con_dbinfo, ip, port, dbname,
                              _dbmt_error)) <= 0)
    {
        return 0;
    }

    /* extract db user info */
    strcpy (dbid, con_dbinfo.uid);
    uDecrypt (PASSWD_LENGTH, con_dbinfo.passwd, dbpasswd);

    return 1;
}


/* Generate status, note and write to log */
void
uGenerateStatus (nvplist * req, nvplist * res, int retval,
                 const char *_dbmt_error)
{
    char strbuf[1024];

    if ((retval == -1) || (retval == 0))
        return;

    if ((retval == 1) || (retval == ERR_NO_ERROR))
    {
        nv_update_val (res, "status", "success");
        return;
    }

    if (retval == ERR_FILE_COMPRESS)
    {
        nv_update_val (res, "status", "success");
        nv_update_val (res, "note",
                       "Can't compress the file. Download original file");
        return;
    }

    nv_update_val (res, "status", "failure");
    switch (retval)
    {
    case ERR_GENERAL_ERROR:
        sprintf (strbuf, "Unknown general error");
        break;
    case ERR_UNDEFINED_TASK:
        sprintf (strbuf, "Undefined request - %s", _dbmt_error);
        break;
    case ERR_DBDIRNAME_NULL:
        sprintf (strbuf, "Can not find the directory database(%s) is located",
                 _dbmt_error);
        break;
    case ERR_GET_FILE:
        sprintf (strbuf, "Can't get requested files");
        break;
    case ERR_REQUEST_FORMAT:
        sprintf (strbuf, "Invalid request format");
        break;
    case ERR_DATABASETXT_OPEN:
        sprintf (strbuf, "'%s' open error", CUBRID_DATABASE_TXT);
        break;
    case ERR_USER_CAPABILITY:
        sprintf (strbuf, "Failed to get user profile for '%s'", _dbmt_error);
        break;
    case ERR_FILE_INTEGRITY:
        sprintf (strbuf, "Password file(%s) integrity failure", _dbmt_error);
        break;
    case ERR_SYSTEM_CALL:
        sprintf (strbuf, "Command returned error : %s", _dbmt_error);
        break;
    case ERR_PASSWORD_FILE:
        sprintf (strbuf, "Password file(%s) open error", _dbmt_error);
        break;
    case ERR_PARAM_MISSING:
        sprintf (strbuf, "Parameter(%s) missing in the request", _dbmt_error);
        break;
    case ERR_DIR_CREATE_FAIL:
        sprintf (strbuf, "Directory(%s) creation failed", _dbmt_error);
        break;
    case ERR_FILE_OPEN_FAIL:
        sprintf (strbuf, "File(%s) open error", _dbmt_error);
        break;
    case ERR_STANDALONE_MODE:
        sprintf (strbuf, "Database(%s) is running in standalone mode",
                 _dbmt_error);
        break;
    case ERR_DB_ACTIVE:
        sprintf (strbuf, "Database(%s) is active state.", _dbmt_error);
        break;
    case ERR_DB_INACTIVE:
        sprintf (strbuf, "Database(%s) is not active state", _dbmt_error);
        break;
    case ERR_DB_NONEXISTANT:
        sprintf (strbuf, "Database(%s) does not exist", _dbmt_error);
        break;
    case ERR_DBMTUSER_EXIST:
        sprintf (strbuf, "CUBRID Manager user(%s) already exist", _dbmt_error);
        break;
    case ERR_DIROPENFAIL:
        sprintf (strbuf, "Failed to read directory(%s)", _dbmt_error);
        break;
    case ERR_PERMISSION:
        sprintf (strbuf, "No permission for %s", _dbmt_error);
        break;
    case ERR_INVALID_TOKEN:
        sprintf (strbuf,
                 "Request is rejected due to invalid token. Please reconnect.");
        break;
    case ERR_SYSTEM_CALL_CON_DUMP:
        sprintf (strbuf, "%s", _dbmt_error);
        break;
    case ERR_STAT:
        sprintf (strbuf, "Failed to get the file information");
        break;
    case ERR_OPENDIR:
        sprintf (strbuf, "Failed to open the directory");
        break;
    case ERR_UNICASCONF_OPEN:
        sprintf (strbuf, "Failed to open unicas.conf");
        break;
    case ERR_UNICASCONF_PARAM_MISSING:
        sprintf (strbuf, "Specified parameter does not exist in unicas.conf");
        break;
    case ERR_DBLOGIN_FAIL:
        sprintf (strbuf, "Failed to log in to database using id:%s",
                 _dbmt_error);
        break;
    case ERR_DBRESTART_FAIL:
        sprintf (strbuf, "Failed to restart database(%s)", _dbmt_error);
        break;
    case ERR_DBUSER_NOTFOUND:
        sprintf (strbuf, "Database user (%s) not found", _dbmt_error);
        break;
    case ERR_DBPASSWD_CLEAR:
        sprintf (strbuf, "Failed to clear existing password - %s", _dbmt_error);
        break;
    case ERR_DBPASSWD_SET:
        sprintf (strbuf, "Failed to set new password - %s", _dbmt_error);
        break;
    case ERR_MEM_ALLOC:
        sprintf (strbuf, "Memory allocation error.");
        break;
    case ERR_TMPFILE_OPEN_FAIL:
        sprintf (strbuf, "Temporal file open error.");
        break;
    case ERR_WITH_MSG:
        strcpy_limit (strbuf, _dbmt_error, sizeof (strbuf));
        break;
    case ERR_UPA_SYSTEM:
        sprintf (strbuf, "Authentication System Error.");
        break;
    case ERR_TEMPLATE_ALREADY_EXIST:
        sprintf (strbuf, "Template (%s) already exist.", _dbmt_error);
        break;
    case ERR_WARNING:
        strcpy_limit (strbuf, _dbmt_error, sizeof (strbuf));
        nv_update_val (res, "status", "warning");
        break;
    default:
        sprintf (strbuf, "error");
        break;
    }
    nv_update_val (res, "note", strbuf);
    ut_error_log (req, strbuf);
}


/* validate token and insert id */
int
ut_validate_token (nvplist * req)
{
    T_USER_TOKEN_INFO *token_info;

    time_t active_time = 0;
    time_t now_time = time (NULL);

    //int retval;

    char *ip, *port, *id, *tok[3];
    char *token, token_content[TOKEN_LENGTH + 1];

    if (!strcmp (nv_get_val (req, "task"), "login") ||
        !strcmp (nv_get_val (req, "task"), "getcmsenv"))
    {
        ut_access_log (req, "task = login or getcmsenv.");
        return 1;
    }

    if ((token = nv_get_val (req, "token")) == NULL)
    {
        return 0;
    }
    ut_access_log (req, "task != login or getcmsenv.");

    uDecrypt (TOKEN_LENGTH, token, token_content);

    if (string_tokenize2 (token_content, tok, 3, ':') < 0)
        return 0;

    ip = tok[0];
    port = tok[1];
    id = tok[2];

    ut_access_log (req, id);

    token_info = dbmt_user_search_token_info (id);
    if (token_info == NULL)
    {
        ut_access_log (req, "can't find registered token.");
        return 0;
    }

    if (strcmp (token_info->token, token))
    {
        ut_access_log (req, "tokens aren't equal!");
        return 0;
    }

    ut_get_token_active_time (&active_time);

    if (now_time - token_info->login_time > active_time)
    {
        return 0;
    }

    token_info->login_time = now_time;

    nv_add_nvp (req, "_IP", ip);
    nv_add_nvp (req, "_PORT", port);
    nv_add_nvp (req, "_ID", id);


    /* check if ip is an existing ip */
    //retval = dbmt_con_search (ip, port, cli_ver);

    return 1;
}

/*
 *   client ip : client port : dbmt id : pserver pid
 *      15            5           8           5      = 33 + 4 = 37
 *   40 - 37 = 8.
 *   Thus, 3 bytes for checksum
 */
char *
ut_token_generate (char *client_ip, char *client_port, char *dbmt_id,
                   int proc_id, time_t login_time)
{
    char sbuf[TOKEN_LENGTH + 1];
    char token_string[TOKEN_ENC_LENGTH];
    size_t i, len;

    if ((client_ip == NULL) || (client_port == NULL) || (dbmt_id == NULL))
        return NULL;
    memset (sbuf, 0, TOKEN_LENGTH + 1);
    snprintf (sbuf, TOKEN_LENGTH, "%s:%s:%s:%d:%lu", client_ip, client_port,
              dbmt_id, proc_id, login_time);
    len = strlen (sbuf);
    /* insert padding to checksum part */
    for (i = len; i < TOKEN_LENGTH; ++i)
        sbuf[i] = '*';
    sbuf[i] = '\0';

    uEncrypt (TOKEN_LENGTH, sbuf, token_string);

    return strdup (token_string);
}

void
_accept_connection (nvplist * cli_request, nvplist * cli_response)
{
    char *pstrbuf;
    char *client_ip, *client_port, *client_id, *client_ver;
#ifdef WINDOWS
    HANDLE proc_id = (HANDLE) getpid ();
#else
    pid_t proc_id = (pid_t) getpid ();
#endif

    time_t login_time = time (NULL);

    client_ip = nv_get_val (cli_request, "_CLIENTIP");
    client_port = nv_get_val (cli_request, "_CLIENTPORT");
    client_id = nv_get_val (cli_request, "id");
    client_ver = nv_get_val (cli_request, "clientver");

    /* generate token and record new connection to file */
    pstrbuf =
        ut_token_generate (client_ip, client_port, client_id, getpid (),
                           login_time);
    nv_add_nvp (cli_response, "token", pstrbuf);

    dbmt_con_add (client_ip, client_port, client_ver, client_id);

    ut_access_log (cli_request, "before add token into token list.");
    dbmt_user_new_token_info (client_id, client_ip, client_port, pstrbuf,
                              proc_id, login_time);

    free (pstrbuf);
    return;
}


#if defined (WINDOWS)
int
gettimeofday (struct timeval *tp, void *tzp)
{
    struct _timeb tm;
    _ftime (&tm);
    tp->tv_sec = (long) tm.time;
    tp->tv_usec = tm.millitm * 1000;
    return 0;
}
#endif

void
_ut_timeval_diff (struct timeval *start, struct timeval *end, int *res_msec)
{
    int sec, msec;

    sec = end->tv_sec - start->tv_sec;
    msec = (end->tv_usec / 1000) - (start->tv_usec / 1000);
    *res_msec = sec * 1000 + msec;
}


#if defined(WINDOWS)
int
ut_run_child (const char *bin_path, const char *const argv[], int wait_flag,
              const char *stdin_file, const char *stdout_file,
              const char *stderr_file, int *exit_status)
{
    int new_pid;
    STARTUPINFO start_info;
    PROCESS_INFORMATION proc_info;
    BOOL res;
    int i, cmd_arg_len;
    char cmd_arg[1024];
    BOOL inherit_flag = FALSE;
    HANDLE hStdIn = INVALID_HANDLE_VALUE;
    HANDLE hStdOut = INVALID_HANDLE_VALUE;
    HANDLE hStdErr = INVALID_HANDLE_VALUE;

    if (exit_status != NULL)
        *exit_status = 0;

    for (i = 0, cmd_arg_len = 0; argv[i]; i++)
    {
        cmd_arg_len += sprintf (cmd_arg + cmd_arg_len, "\"%s\" ", argv[i]);
    }

    GetStartupInfo (&start_info);
    start_info.wShowWindow = SW_HIDE;

    if (stdin_file)
    {
        hStdIn =
            CreateFile (stdin_file, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hStdIn != INVALID_HANDLE_VALUE)
        {
            SetHandleInformation (hStdIn, HANDLE_FLAG_INHERIT,
                                  HANDLE_FLAG_INHERIT);
            start_info.dwFlags = STARTF_USESTDHANDLES;
            start_info.hStdInput = hStdIn;
            inherit_flag = TRUE;
        }
    }
    if (stdout_file)
    {
        hStdOut =
            CreateFile (stdout_file, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hStdOut != INVALID_HANDLE_VALUE)
        {
            SetHandleInformation (hStdOut, HANDLE_FLAG_INHERIT,
                                  HANDLE_FLAG_INHERIT);
            start_info.dwFlags = STARTF_USESTDHANDLES;
            start_info.hStdOutput = hStdOut;
            inherit_flag = TRUE;
        }
    }
    if (stderr_file)
    {
        hStdErr =
        CreateFile (stderr_file, GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hStdErr != INVALID_HANDLE_VALUE)
        {
            SetHandleInformation (hStdErr, HANDLE_FLAG_INHERIT,
                                  HANDLE_FLAG_INHERIT);
            start_info.dwFlags = STARTF_USESTDHANDLES;
            start_info.hStdError = hStdErr;
            inherit_flag = TRUE;
        }
    }

    res = CreateProcess (bin_path, cmd_arg, NULL, NULL, inherit_flag,
                         CREATE_NO_WINDOW, NULL, NULL, &start_info, &proc_info);

    if (hStdIn != INVALID_HANDLE_VALUE)
    {
        CloseHandle (hStdIn);
    }
    if (hStdOut != INVALID_HANDLE_VALUE)
    {
        CloseHandle (hStdOut);
    }
    if (hStdErr != INVALID_HANDLE_VALUE)
    {
        CloseHandle (hStdErr);
    }

    if (res == FALSE)
    {
        return -1;
    }

    new_pid = proc_info.dwProcessId;

    if (wait_flag)
    {
        DWORD status = 0;
        //WaitForSingleObject (proc_info.hProcess, INFINITE);
        //GetExitCodeProcess (proc_info.hProcess, &status);
        if (exit_status != NULL)
            *exit_status = status;
        CloseHandle (proc_info.hProcess);
        CloseHandle (proc_info.hThread);
        return 0;
    }
    else
    {
        CloseHandle (proc_info.hProcess);
        CloseHandle (proc_info.hThread);
        return new_pid;
    }
}
#else
int
ut_run_child (const char *bin_path, const char *const argv[], int wait_flag,
              const char *stdin_file, const char *stdout_file,
              const char *stderr_file, int *exit_status)
{
    int pid;

    if (exit_status != NULL)
        *exit_status = 0;

    if (wait_flag)
        signal (SIGCHLD, SIG_DFL);
    else
        signal (SIGCHLD, SIG_IGN);
    pid = fork ();
    if (pid == 0)
    {
        FILE *fp;

        close_all_fds (3);

        if (stdin_file != NULL)
        {
            fp = fopen (stdin_file, "r");
            if (fp != NULL)
            {
                dup2 (fileno (fp), 0);
                fclose (fp);
            }
        }
        if (stdout_file != NULL)
        {
            unlink (stdout_file);
            fp = fopen (stdout_file, "w");
            if (fp != NULL)
            {
                dup2 (fileno (fp), 1);
                fclose (fp);
            }
        }
        if (stderr_file != NULL)
        {
            unlink (stderr_file);
            fp = fopen (stderr_file, "w");
            if (fp != NULL)
            {
                dup2 (fileno (fp), 2);
                fclose (fp);
            }
        }

        execv (bin_path, (char *const *) argv);
        exit (0);
    }

    if (pid < 0)
        return -1;

    if (wait_flag)
    {
        int status = 0;
        waitpid (pid, &status, 0);
        if (exit_status != NULL)
            *exit_status = status;
        return 0;
    }
    else
    {
        return pid;
    }
}
#endif

typedef struct _dir_file_node
{
    char *file_name;
    struct _dir_file_node *next;
    struct _dir_file_node *prev;
} dir_file_node;

typedef struct _dir_file_list_head
{
    unsigned int file_num;
    dir_file_node *head;
} dir_file_list_head;

static int
add_node_to_list (dir_file_list_head * file_head, const char *file_name)
{
    dir_file_node *file_node;
    if (file_head == NULL || file_name == NULL)
        return -1;

    file_node = (dir_file_node *) malloc (sizeof (dir_file_node));
    if (file_node == NULL)
        return -1;

    file_node->file_name = strdup (file_name);
    file_node->next = file_head->head;
    if (file_head->head)
        file_head->head->prev = file_node;
    file_node->prev = NULL;
    file_head->head = file_node;
    file_head->file_num++;
    return 0;
}

static void
remove_node_from_list (dir_file_list_head * file_head,
                       dir_file_node * file_node)
{
    if (file_head == NULL || file_node == NULL)
        return;

    if (file_node->prev)
        file_node->prev->next = file_node->next;
    else if (file_node->next)
    {
        file_node->next->prev = NULL;
        file_head->head = file_node->next;
    }
    if (file_node->next)
        file_node->next->prev = file_node->prev;
    else if (file_node->prev)
        file_node->prev->next = NULL;

    file_head->file_num--;
    return;
}

static void
free_file_list (dir_file_list_head * file_head)
{
    dir_file_node *pnode, *pnext;
    if (file_head == NULL)
        return;
    pnode = file_head->head;
    while (pnode)
    {
        pnext = pnode->next;

        if (pnode->file_name)
            free (pnode->file_name);
        free (pnode);
        pnode = pnext;
    }
    file_head->head = NULL;
    file_head->file_num = 0;
    return;
}


#if defined(WINDOWS)
static int
scan_dir (const char *scan_path, const char *pattern,
          dir_file_list_head * file_list)
{
    WIN32_FIND_DATA FileData;
    HANDLE hSearch = NULL;
    BOOL finished = FALSE;
    char dir_path[256];

    if (file_list == NULL)
        return -1;

    snprintf (dir_path, 256, "%s/*.*", scan_path);
    hSearch = FindFirstFile (dir_path, &FileData);
    if (hSearch == INVALID_HANDLE_VALUE)
        return -1;

    while (!finished)
    {
        if (strstr (FileData.cFileName, pattern))
            add_node_to_list (file_list, FileData.cFileName);
        finished = !FindNextFile (hSearch, &FileData);
    }
    FindClose (hSearch);
    return 0;
}
#else
static int
scan_dir (const char *scan_path, const char *pattern,
          dir_file_list_head * file_list)
{
    DIR *dp;
    struct dirent *ep;
    dp = opendir (scan_path);
    if (dp == NULL)
        return -1;
    while ((ep = readdir (dp)) != NULL)
    {
        if (strstr (ep->d_name, pattern))
            add_node_to_list (file_list, ep->d_name);
    }
    closedir (dp);

    return 0;
}
#endif

int
remove_extra_subdir (const char *dirpath, const char *pattern,
                     unsigned int save_num)
{
    dir_file_list_head file_list = { 0, NULL };
    dir_file_node *pnode, *pnext;
    char file_path[260];
    if (scan_dir (dirpath, pattern, &file_list) < 0)
        return -1;

    while (file_list.file_num > save_num)
    {
        pnode = file_list.head;
        pnext = pnode;
        while (pnext)
        {
            if (strcmp (pnode->file_name, pnext->file_name) > 0)
                pnode = pnext;
            pnext = pnext->next;
        }
        snprintf (file_path, 260, "%s/%s", dirpath, pnode->file_name);
        uRemoveDir (file_path, REMOVE_DIR_FORCED);
        remove_node_from_list (&file_list, pnode);
    }

    free_file_list (&file_list);
    return 0;
}

int
IsValidUserName (const char *pUserName)
{
    size_t len = 0;
    size_t idx = 0;
    if (!pUserName || !*pUserName)
        return -1;

    len = strlen (pUserName);
    if (len < 4 || len > 32)
    {
        return -1;
    }

    // If the first char isn't 'a'-'z' or 'A'-'Z', then return error
    if (!((pUserName[0] >= 'a' && pUserName[0] <= 'z')
        || (pUserName[0] >= 'A' && pUserName[0] <= 'Z')))
    {
        return -1;
    }

    // If the char isn't 'a'-'z', 'A'-'Z', '0'-'9' or '_', then return error
    for (idx = 1; idx < len; idx++)
    {
        if (!((pUserName[idx] >= 'a' && pUserName[idx] <= 'z')
            || (pUserName[idx] >= 'A' && pUserName[idx] <= 'Z')
            || (pUserName[idx] >= '0' && pUserName[idx] <= '9')
            || (pUserName[idx] == '_')))
        {
            return -1;
        }
    }
    return 0;
}

int
ut_get_token_active_time (time_t * active_time)
{
    char file_name[PATH_MAX];
    char line_buf[LINE_MAX];
    FILE *in_file = NULL;
    char *pos = NULL;

    file_name[0] = '\0';
    line_buf[0] = '\0';

    conf_get_dbmt_file (FID_DBMT_CONF, file_name);
    in_file = fopen (file_name, "r");

    if (in_file == NULL)
    {
        return 1;
    }

    *active_time = 0;
    while (fgets (line_buf, LINE_MAX, in_file) != NULL)
    {
        if (line_buf[0] == '#')
        {
            continue;
        }

        if ((pos = strstr (line_buf, "=")) != NULL &&
            strstr (line_buf, "token_active_time") != NULL)
        {
            char tmp_str[LINE_MAX];
            strcpy (tmp_str, pos + 1);

            *active_time = atoi (tmp_str);

            break;
        }
    }
    fclose (in_file);

    if (*active_time == 0)
    {
        *active_time = 7200;
    }

    return 0;
}

int
ut_validate_auth (nvplist * req)
{
    T_USER_AUTH auth_task = 0;
    T_USER_AUTH auth_user = 0;
    T_DBMT_USER dbmt_user;
    T_DBMT_USER_AUTHINFO *auth_info = NULL;
    char *task = NULL;
    char *user_id = NULL;
    char dbmt_error[DBMT_ERROR_MSG_SIZE];
    int num_authinfo = 0;
    int i = 0;            // loop var

    dbmt_error[0] = '\0';

    task = nv_get_val (req, "task");
    user_id = nv_get_val (req, "_ID");

    if (task == NULL)
    {
        return 0;
    }

    if (!strcmp (task, "login") || !strcmp (task, "getcmsenv"))
    {
        return 1;
    }

    if (user_id == NULL)
    {
        return 0;
    }

    if (ut_get_task_info (task, NULL, NULL, &auth_task) == 0)
    {
        // As the task doesn't exist, this failure will be checked in next step. 
        return 1;
    }

    if (dbmt_user_read (&dbmt_user, dbmt_error) != ERR_NO_ERROR)
    {
        return 0;
    }

    for (i = 0; i < dbmt_user.num_dbmt_user; ++i)
    {
        if (!strcmp (dbmt_user.user_info[i].user_name, user_id))
        {
            auth_info = dbmt_user.user_info[i].authinfo;
            num_authinfo = dbmt_user.user_info[i].num_authinfo;
            break;
        }
    }

    for (i = 0; i < num_authinfo; ++i)
    {
        if (!strcmp (auth_info[i].domain, "user_auth"))
        {
            auth_user = atoi (auth_info[i].auth);
            break;
        }
    }

    // assign default authority to old users. 
    if (auth_user == 0)
    {
        if (!strcmp (user_id, "admin"))
        {
            auth_user = AU_ADMIN;
        }
        else
        {
            auth_user = ALL_AUTHORITY;
        }
    }

    if (auth_user == AU_ADMIN)
    {
        return 1;
    }

    return (auth_user & auth_task) ? 1 : 0;

}

static int
get_short_filename (char *ret_name, int ret_name_len,
                    char *short_filename)
{
    char *ptr = NULL;
    char *path_p = NULL;
    unsigned int filename_len = 0;

#if defined(WINDOWS)
    path_p = strrchr (short_filename, '\\');
#else
    path_p = strrchr (short_filename, '/');
#endif

    if (path_p != NULL)
    {
        return -1;
    }

    if (short_filename == NULL)
    {
        return -1;
    }

    if (ret_name_len <= (int) strlen (short_filename))
    {
        return -1;
    }

    ptr = strrchr (short_filename, '.');
    if (ptr == NULL)
    {
        snprintf (ret_name, strlen (short_filename) + 1, short_filename);
        return -1;
    }

    filename_len = (unsigned int) (ptr - short_filename);

    snprintf (ret_name, filename_len + 1, short_filename);

    return 0;
}

int
ut_get_filename (char *fullpath, int with_ext, char *ret_filename)
{
    char *filename = NULL;
    char short_filename[PATH_MAX];

    short_filename[0] = '\0';

    if (fullpath == NULL)
    {
        return -1;
    }

#if defined(WINDOWS)
    filename = strrchr (fullpath, '\\');
#else
    filename = strrchr (fullpath, '/');
#endif

    if ((filename == NULL) || ((filename + 1) == NULL))
    {
        return -1;
    }

    if (with_ext == 1)
    {
        snprintf (ret_filename, PATH_MAX, filename + 1);
        return 0;
    }
    else
    {
        if (get_short_filename (short_filename, PATH_MAX, filename + 1) != 0)
        {
            return -1;
        }
        snprintf (ret_filename, PATH_MAX, short_filename);
    }
    return 0;
}


#if defined(WINDOWS)

static int
get_cpu_time (__int64 * kernel, __int64 * user, __int64 * idle)
{
    /* this logic allow multi thread init multiple times */
    if (s_symbol_loaded == 0)
    {
        /*
        * kernel32.dll and ntdll.dll is essential DLL about user process.
        * when a process started, that means kernel32.dll and ntdll.dll
        * already load in process memory space.
        * so call LoadLibrary() and FreeLibrary() function once, only
        * increase and decrease dll reference counter. this behavior does
        * not cause kernel32.dll or ntdll.dll unload from current process.
        */

        /*
        * first try find function GetSystemTimes(). Windows OS suport this
        * function since Windows XP SP1, Vista, Server 2003 or Server 2008.
        */
        HMODULE module = LoadLibraryA ("kernel32.dll");
        s_pfnGetSystemTimes =
            (GET_SYSTEM_TIMES) GetProcAddress (module, "GetSystemTimes");
        FreeLibrary (module);

        if (s_pfnGetSystemTimes != NULL)
        {
            s_symbol_loaded = 1;
        }
        else
        {
            /*
            * OS may be is Windows 2000 or Windows XP. (does not support Windows 9x/NT)
            * try find function NtQuerySystemInformation()
            */
            module = LoadLibraryA ("ntdll.dll");
            s_pfnNtQuerySystemInformation = (NT_QUERY_SYSTEM_INFORMATION)
                                             GetProcAddress (module, "NtQuerySystemInformation");
            FreeLibrary (module);

            if (s_pfnNtQuerySystemInformation == NULL)
            {
                s_symbol_loaded = 3;
            }
            else
            {
                s_symbol_loaded = 2;
            }
        }
    }

    if (s_symbol_loaded == 1)
    {
        FILETIME kernel_time, user_time, idle_time;
        ULARGE_INTEGER lk, lu, li;

        s_pfnGetSystemTimes (&idle_time, &kernel_time, &user_time);

        lk.HighPart = kernel_time.dwHighDateTime;
        lk.LowPart = kernel_time.dwLowDateTime;
        lu.HighPart = user_time.dwHighDateTime;
        lu.LowPart = user_time.dwLowDateTime;
        li.HighPart = idle_time.dwHighDateTime;
        li.LowPart = idle_time.dwLowDateTime;

        /* In win32 system, lk includes "System Idle Process" time,
        * so we should exclude it */
        *kernel = lk.QuadPart - li.QuadPart;
        *user = lu.QuadPart;
        *idle = li.QuadPart;

        return 0;
    }
    else if (s_symbol_loaded == 2)
    {
        SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION sppi;
        ULONG len;

        s_pfnNtQuerySystemInformation (SystemProcessorPerformanceInformation,
                                       &sppi, sizeof (sppi), &len);

        /* In win32 system, sppi.KernelTime includes "System Idle Process"
        * time, so we should exclude it */
        *kernel = sppi.KernelTime.QuadPart - sppi.IdleTime.QuadPart;
        *user = sppi.UserTime.QuadPart;
        *idle = sppi.IdleTime.QuadPart;

        return 0;
    }

    return -1;
}

BOOL
SetPrivilege (HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    /* receives LUID of privilege */
    if (!LookupPrivilegeValue (NULL, lpszPrivilege, &luid))
    {
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
    {
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    }
    else
    {
        tp.Privileges[0].Attributes = 0;
    }

    if (!AdjustTokenPrivileges (hToken, FALSE, &tp,
                                sizeof (TOKEN_PRIVILEGES), NULL, NULL))
    {
        return FALSE;
    }

    if (GetLastError () == ERROR_NOT_ALL_ASSIGNED)
    {
        return FALSE;
    }

    return TRUE;
}

int
ut_get_proc_stat (T_CMS_PROC_STAT * stat, int pid)
{
    ULARGE_INTEGER lk, lu;
    FILETIME dummy1, dummy2, kt, ut;
    PROCESS_MEMORY_COUNTERS pmc;
    MEMORYSTATUSEX ms;
    HANDLE hProcess = NULL, hToken = NULL;
    int ret = 0;

    stat->pid = pid;
    if (!OpenThreadToken (GetCurrentThread (),
                          (TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY), 
                          FALSE, &hToken))
    {
        if (GetLastError () == ERROR_NO_TOKEN)
        {
            if (!ImpersonateSelf (SecurityImpersonation))
            {
                return -1;
            }

            if (!OpenThreadToken (GetCurrentThread (),
                                  (TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY),
                                  FALSE, &hToken))
            {
                return -1;
            }
        }
        else
        {
            return -1;
        }
    }

    /* enable SeDebugPrivilege */
    if (!SetPrivilege (hToken, SE_DEBUG_NAME, TRUE))
    {
        ret = -1;
        goto error_exit;
    }

    hProcess = OpenProcess (PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL)
    {
        ret = -1;
        goto error_exit;
    }

    if (!GetProcessTimes (hProcess, &dummy1, &dummy2, &kt, &ut))
    {
        ret = -1;
        goto error_exit;
    }

    lk.HighPart = kt.dwHighDateTime;
    lk.LowPart = kt.dwLowDateTime;
    lu.HighPart = ut.dwHighDateTime;
    lu.LowPart = ut.dwLowDateTime;

    stat->cpu_kernel = lk.QuadPart;
    stat->cpu_user = lu.QuadPart;

    memset (&pmc, 0, sizeof (pmc));
    pmc.cb = sizeof (pmc);

    if (!GetProcessMemoryInfo (hProcess, &pmc, sizeof (pmc)))
    {
        ret = -1;
        goto error_exit;
    }

    stat->mem_physical = pmc.WorkingSetSize;

    memset (&ms, 0, sizeof (ms));
    ms.dwLength = sizeof (ms);

    if (!GlobalMemoryStatusEx (&ms))
    {
        ret = -1;
        goto error_exit;
    }

    stat->mem_virtual = ms.ullTotalVirtual - ms.ullAvailVirtual;

error_exit:
    if (hProcess != NULL)
    {
        CloseHandle (hProcess);
    }
    if (hToken != NULL)
    {
        CloseHandle (hToken);
    }
    return ret;
}

int
ut_get_host_stat (T_CMS_HOST_STAT * stat, char *_dbmt_error)
{
    __int64 kernel, user, idle;
    PERFORMANCE_INFORMATION pi;

    if (stat == NULL)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "Invalid parameter: %s.",
                  "stat");
        return ERR_WITH_MSG;
    }

    if (get_cpu_time (&kernel, &user, &idle) != 0)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE,
                  "Failed to get the cpu information.");
        return ERR_WITH_MSG;
    }

    stat->cpu_kernel = kernel;
    stat->cpu_user = user;
    stat->cpu_idle = idle;
    stat->cpu_iowait = 0;

    memset (&pi, 0, sizeof (pi));
    pi.cb = sizeof (pi);
    if (!GetPerformanceInfo (&pi, sizeof (pi)))
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE,
                  "Failed to get the memory information.");
        return ERR_WITH_MSG;
    }

    stat->mem_physical_total = ((__int64) pi.PhysicalTotal) * pi.PageSize;
    stat->mem_physical_free = ((__int64) pi.PhysicalAvailable) * pi.PageSize;
    stat->mem_swap_total = ((__int64) pi.CommitLimit) * pi.PageSize;
    stat->mem_swap_free =
    ((__int64) (pi.CommitLimit - pi.CommitTotal)) * pi.PageSize;

    return ERR_NO_ERROR;
}

#elif defined(AIX)

int
ut_get_proc_stat (T_CMS_PROC_STAT * stat, int pid)
{
    struct pstatus proc_stat;
    struct psinfo proc_psinfo;
    char file_name[PATH_MAX];
    int fd = -1;
    long int ticks_per_sec = 0;

    file_name[0] = '\0';

    if (stat == NULL)
    {
        return -1;
    }

    ticks_per_sec = sysconf (_SC_CLK_TCK);
    snprintf (file_name, PATH_MAX, "/proc/%d/status", pid);

    fd = open (file_name, O_RDONLY);
    if (fd == -1)
    {
        return -1;
    }
    if (read (fd, (void *) &proc_stat, sizeof (struct pstatus)) == -1)
    {
        close (fd);
        return -1;
    }
    close (fd);

    stat->cpu_user =
        (uint64_t) ((proc_stat.pr_utime.tv_sec +
        proc_stat.pr_utime.tv_nsec * 10e-9) * ticks_per_sec);
    stat->cpu_kernel =
        (uint64_t) ((proc_stat.pr_stime.tv_sec +
        proc_stat.pr_stime.tv_nsec * 10e-9) * ticks_per_sec);

    snprintf (file_name, PATH_MAX, "/proc/%d/psinfo", pid);

    fd = open (file_name, O_RDONLY);
    if (fd == -1)
    {
        return -1;
    }
    if (read (fd, (void *) &proc_psinfo, sizeof (struct psinfo)) == -1)
    {
        close (fd);
        return -1;
    }
    close (fd);

    stat->mem_virtual = proc_psinfo.pr_size * 1024;
    stat->mem_physical = proc_psinfo.pr_rssize * 1024;

    return 0;
}

int
ut_get_host_stat (T_CMS_HOST_STAT * stat, char *_dbmt_error)
{
    perfstat_cpu_total_t cpu_stat;
    perfstat_memory_total_t mem_info;

    if (stat == NULL)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "Invalid parameter: %s.", "stat");
        return ERR_WITH_MSG;
    }
    if (perfstat_cpu_total (NULL, &cpu_stat, sizeof (perfstat_cpu_total_t), 1) == -1)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE,
                  "Failed to get the cpu information.");
        return ERR_WITH_MSG;
    }
    stat->cpu_user = cpu_stat.user;
    stat->cpu_kernel = cpu_stat.sys;
    stat->cpu_idle = cpu_stat.idle;
    stat->cpu_iowait = cpu_stat.wait;

    if (perfstat_memory_total
        (NULL, &mem_info, sizeof (perfstat_memory_total_t), 1) == -1)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE,
                  "Failed to get the memory information.");
        return ERR_WITH_MSG;
    }
    stat->mem_physical_total = mem_info.real_total * 4 * 1024;
    stat->mem_physical_free = mem_info.real_free * 4 * 1024;
    stat->mem_swap_total = mem_info.pgsp_total * 4 * 1024;
    stat->mem_swap_free = mem_info.pgsp_free * 4 * 1024;

    return ERR_NO_ERROR;
}

#else

int
ut_get_proc_stat (T_CMS_PROC_STAT * stat, int pid)
{
    long vmem_pages;
    long rmem_pages;
    char fname[PATH_MAX];
    FILE *cpufp = NULL;
    FILE *memfp = NULL;

    vmem_pages = 0;
    rmem_pages = 0;
    fname[0] = '\0';

    if (stat == NULL || pid == 0)
    {
        return -1;
    }

    stat->pid = pid;

    snprintf (fname, PATH_MAX - 1, "/proc/%d/stat", (int) pid);
    cpufp = fopen (fname, "r");
    if (!cpufp)
    {
        return -1;
    }

    snprintf (fname, PATH_MAX - 1, "/proc/%d/statm", (int) pid);
    memfp = fopen (fname, "r");
    if (memfp == NULL)
    {
        fclose (cpufp);
        return -1;
    }
#if __WORDSIZE == 64
    fscanf (cpufp, "%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%lu%lu",
            &stat->cpu_user, &stat->cpu_kernel);
    fscanf (memfp, "%lu%lu", &vmem_pages, &rmem_pages);    /* 'size' and 'resident' in stat file */
#else
    fscanf (cpufp, "%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%*s%llu%llu",
            &stat->cpu_user, &stat->cpu_kernel);
    fscanf (memfp, "%lu%lu", &vmem_pages, &rmem_pages);    /* 'size' and 'resident' in stat file */
#endif

    stat->mem_virtual = vmem_pages * sysconf (_SC_PAGESIZE);
    stat->mem_physical = rmem_pages * sysconf (_SC_PAGESIZE);

    fclose (cpufp);
    fclose (memfp);

    return 0;
}

int
ut_get_host_stat (T_CMS_HOST_STAT * stat, char *_dbmt_error)
{
    char linebuf[LINE_MAX];
    char prefix[50];
    uint64_t nice;
    uint64_t buffers;
    uint64_t cached;
    FILE *cpufp = NULL;
    FILE *memfp = NULL;
    int n_cpuitem = 0;
    int n_memitem = 0;
    const char *stat_file = "/proc/stat";
    const char *meminfo_file = "/proc/meminfo";

    linebuf[0] = '\0';
    prefix[0] = '\0';

    if (stat == NULL)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "Invalid parameter: %s.", "stat");
        return ERR_WITH_MSG;
    }
    cpufp = fopen (stat_file, "r");
    if (cpufp == NULL)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", "stat_file");
        return ERR_FILE_OPEN_FAIL;
    }
    memfp = fopen (meminfo_file, "r");
    if (memfp == NULL)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", "meminfo_file");
        return ERR_FILE_OPEN_FAIL;
    }

    while (fgets (linebuf, sizeof (linebuf), cpufp))
    {
        sscanf (linebuf, "%49s", prefix);
        if (!strcmp (prefix, "cpu"))
        {
#if __WORDSIZE == 64
            sscanf (linebuf, "%*s%lu%lu%lu%lu%lu", &stat->cpu_user, &nice,
                    &stat->cpu_kernel, &stat->cpu_idle, &stat->cpu_iowait);
#else   
            sscanf (linebuf, "%*s%llu%llu%llu%llu%llu", &stat->cpu_user, &nice,
                    &stat->cpu_kernel, &stat->cpu_idle, &stat->cpu_iowait);
#endif

            stat->cpu_user += nice;
            n_cpuitem++;
            break;
        }
    }
    if (n_cpuitem != 1)
    {
        goto error_handle;
    }

    while (fgets (linebuf, sizeof (linebuf), memfp))
    {
        sscanf (linebuf, "%49s", prefix);
        if (!strcmp (prefix, "MemTotal:"))
        {
#if __WORDSIZE == 64
            sscanf (linebuf, "%*s%lu", &stat->mem_physical_total);
#else
            sscanf (linebuf, "%*s%llu", &stat->mem_physical_total);
#endif
            n_memitem++;
        }
        if (!strcmp (prefix, "MemFree:"))
        {
#if __WORDSIZE == 64
            sscanf (linebuf, "%*s%lu", &stat->mem_physical_free);
#else
            sscanf (linebuf, "%*s%llu", &stat->mem_physical_free);
#endif
            n_memitem++;
        }
        if (!strcmp (prefix, "Buffers:"))
        {
#if __WORDSIZE == 64
            sscanf (linebuf, "%*s%lu", &buffers);
#else
            sscanf (linebuf, "%*s%llu", &buffers);
#endif
        }
        if (!strcmp (prefix, "Cached:"))
        {
#if __WORDSIZE == 64
            sscanf (linebuf, "%*s%lu", &cached);
#else
            sscanf (linebuf, "%*s%llu", &cached);
#endif
        }
        if (!strcmp (prefix, "SwapTotal:"))
        {
#if __WORDSIZE == 64
            sscanf (linebuf, "%*s%lu", &stat->mem_swap_total);
#else
            sscanf (linebuf, "%*s%llu", &stat->mem_swap_total);
#endif
            n_memitem++;
        }
        if (!strcmp (prefix, "SwapFree:"))
        {
#if __WORDSIZE == 64
            sscanf (linebuf, "%*s%lu", &stat->mem_swap_free);
#else
            sscanf (linebuf, "%*s%llu", &stat->mem_swap_free);
#endif
            n_memitem++;
        }
    }
    if (n_memitem != 4)
    {
        goto error_handle;
    }

    stat->mem_physical_free += (buffers + cached);

    stat->mem_physical_total *= 1024;
    stat->mem_physical_free *= 1024;
    stat->mem_swap_total *= 1024;
    stat->mem_swap_free *= 1024;

    fclose (cpufp);
    fclose (memfp);
    return ERR_NO_ERROR;

error_handle:
    snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", "read host info error.");
    fclose (cpufp);
    fclose (memfp);
    return ERR_WITH_MSG;
}

#endif // WINDOWS

int
ut_record_cubrid_utility_log_stderr (const char *msg)
{
    if (msg == NULL)
    {
        return -1;
    }
#if !defined(WINDOWS)
    fprintf (stderr, msg);
#endif
    cm_util_log_write_errstr (msg);

    return 0;
}

int
ut_record_cubrid_utility_log_stdout (const char *msg)
{
    if (msg == NULL)
    {
        return -1;
    }
#if !defined(WINDOWS)
    fprintf (stdout, msg);
#endif
    cm_util_log_write_errstr (msg);

    return 0;
}
