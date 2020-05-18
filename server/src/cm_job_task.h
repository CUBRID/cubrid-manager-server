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
 * cm_job_task.h -
 */

#ifndef _CM_JOB_TASK_H_
#define _CM_JOB_TASK_H_

#if defined(WINDOWS)
#include <io.h>
#endif

#include "cm_dep.h"

#define DBMT_ERROR_MSG_SIZE    5000

#ifndef TASKNAME_LEN
#define TASKNAME_LEN           50
#endif

#ifndef SIZE_BUFFER_MAX
#define SIZE_BUFFER_MAX        1024
#endif

#define SET_TRANSACTION_NO_WAIT_MODE_ENV()                                              \
      do {                                                                              \
      putenv((char *) "CUBRID_LOCK_TIMEOUT_IN_SECS=1");                                 \
      putenv((char *) "CUBRID_ISOLATION_LEVEL=TRAN_READ_COMMITTED");                    \
    } while (0)

typedef enum
{
  TS_UNDEFINED,
  TS_STARTINFO,
  TS_USERINFO,
  TS_CREATEUSER,
  TS_DELETEUSER,
  TS_CREATEDB,
  TS_DELETEDB,
  TS_RENAMEDB,
  TS_STARTDB,
  TS_STOPDB,
  TS_UPDATEUSER,
  TS_DBSPACEINFO,
  TS_CLASSINFO,
  TS_CLASS,
  TS_RENAMECLASS,
  TS_DROPCLASS,
  TS_SETSYSPARAM,
  TS_GETALLSYSPARAM,
  TS_ADDVOLDB,
  TS_CREATECLASS,
  TS_CREATEVCLASS,
  TS_GETLOGINFO,
  TS_VIEWLOG,
  TS_RESETLOG,
  TS_ADDATTRIBUTE,
  TS_DROPATTRIBUTE,
  TS_UPDATEATTRIBUTE,
  TS_ADDCONSTRAINT,
  TS_DROPCONSTRAINT,
  TS_ADDSUPER,
  TS_DROPSUPER,
  TS_GETSUPERCLASSESINFO,
  TS_ADDRESOLUTION,
  TS_DROPRESOLUTION,
  TS_ADDMETHOD,
  TS_DROPMETHOD,
  TS_UPDATEMETHOD,
  TS_ADDMETHODFILE,
  TS_DROPMETHODFILE,
  TS_ADDQUERYSPEC,
  TS_DROPQUERYSPEC,
  TS_CHANGEQUERYSPEC,
  TS_VALIDATEQUERYSPEC,
  TS_VALIDATEVCLASS,
  TS_COPYDB,
  TS_OPTIMIZEDB,
  TS_STATDUMP,
  TS_CHECKDB,
  TS_COMPACTDB,
  TS_BACKUPDBINFO,
  TS_BACKUPDB,
  TS_UNLOADDB,
  TS_UNLOADDBINFO,
  TS_LOADDB,
  TS_GETTRANINFO,
  TS_KILLTRAN,
  TS_LOCKDB,
  TS_GETBACKUPLIST,
  TS_RESTOREDB,
  TS_BACKUPVOLINFO,
  TS_GETDBSIZE,
  TS_GETDBMTUSERINFO,
  TS_DELETEDBMTUSER,
  TS_UPDATEDBMTUSER,
  TS_SETDBMTPASSWD,
  TS_ADDDBMTUSER,
  TS_GETBACKUPINFO,
  TS_ADDBACKUPINFO,
  TS_DELETEBACKUPINFO,
  TS_SETBACKUPINFO,
  TS_GETDBERROR,
  TS_GETAUTOADDVOL,
  TS_SETAUTOADDVOL,
  TS_GENERALDBINFO,
  TS_LOADACCESSLOG,
  TS_GETACCESSLOGFILES,
  TS_GETERRORLOGFILES,
  TS_CHECKDIR,
  TS_AUTOBACKUPDBERRLOG,
  TS_AUTOEXECQUERYERRLOG,
  TS_KILL_PROCESS,
  TS_GETENV,
  TS_GETACCESSRIGHT,
  TS_GETADDVOLSTATUS,
  TS_GETHISTORY,
  TS_SETHISTORY,
  TS_GETHISTORYFILELIST,
  TS_READHISTORYFILE,
  TS_CHECKAUTHORITY,
  TS_GETAUTOADDVOLLOG,
  TS2_GETINITUNICASINFO,
  TS2_GETUNICASINFO,
  TS2_STARTUNICAS,
  TS2_STOPUNICAS,
  TS2_GETADMINLOGINFO,
  TS2_GETLOGFILEINFO,
  TS2_ADDBROKER,
  TS2_GETADDBROKERINFO,
  TS2_DELETEBROKER,
  TS2_RENAMEBROKER,
  TS2_GETBROKERSTATUS,
  TS2_GETBROKERCONF,
  TS2_GETBROKERONCONF,
  TS2_SETBROKERCONF,
  TS2_SETBROKERONCONF,
  TS2_STARTBROKER,
  TS2_STOPBROKER,
  TS2_SUSPENDBROKER,
  TS2_RESUMEBROKER,
  TS2_BROKERJOBFIRST,
  TS2_BROKERJOBINFO,
  TS2_ADDBROKERAS,
  TS2_DROPBROKERAS,
  TS2_RESTARTBROKERAS,
  TS2_GETBROKERSTATUSLOG,
  TS2_GETBROKERMCONF,
  TS2_SETBROKERMCONF,
  TS2_GETBROKERASLIMIT,
  TS2_GETBROKERENVINFO,
  TS2_SETBROKERENVINFO,
  TS2_ACCESSLISTADDIP,
  TS2_ACCESSLISTDELETEIP,
  TS2_ACCESSLISTINFO,
  TS_CHECKFILE,
  TS_REGISTERLOCALDB,
  TS_REMOVELOCALDB,
  TS_ADDNEWTRIGGER,
  TS_ALTERTRIGGER,
  TS_DROPTRIGGER,
  TS_GETTRIGGERINFO,
  TS_GETFILE,
  TS_GETAUTOEXECQUERY,
  TS_SETAUTOEXECQUERY,
  TS_GETDIAGINFO,
  TS_GET_DIAGDATA,
  TS_GET_BROKER_DIAGDATA,
  TS_ADDSTATUSTEMPLATE,
  TS_REMOVESTATUSTEMPLATE,
  TS_UPDATESTATUSTEMPLATE,
  TS_GETSTATUSTEMPLATE,
  TS_GETCASLOGFILELIST,
  TS_ANALYZECASLOG,
  TS_EXECUTECASRUNNER,
  TS_REMOVECASRUNNERTMPFILE,
  TS_GETCASLOGTOPRESULT,
  TS_DBMTUSERLOGIN,
  TS_CHANGEOWNER,
  TS_REMOVE_LOG,
  TS_PARAMDUMP,
  TS_PLANDUMP,
  TS_GETHOSTSTAT,
  TS_GETDBPROCSTAT,
  TS_CHANGEMODE,
  TS_HEARTBEAT_LIST,
  TS_HEARTBEAT_DEACT,
  TS_HEARTBEAT_ACT,
  TS_GET_STANDBY_SERVER_STAT,
  TS_GETDBMODE,
  TS_ROLE_CHANGE,
  TS_USER_VERIFY,
  TS_RUN_SCRIPT,
  TS_GET_FOLDERS_WITH_KEYWORD,
  TS_WRITE_AND_SAVE_CONF,
  TS_RUN_SQL_STATEMENT,
  TS_COPY_FOLDER,
  TS_DELETE_FOLDER,
  TS_GET_FILE_TOTAL_LINE_NUM,
  TS_GET_ENVVAR_BY_NAME,
  TS_ERROR_TRACE,
  TS_LOGIN,
  TS_LOGOUT,
  TS_GET_CMS_ENV,
  TS_KEEPALIVE,
  TS_REMOVE_FILES,
  TS_JOB_TEST,
  TS_DB_SPACE_INFO,
  TS_SHARD_START,
  TS_SHARD_STOP,
  TS_GET_SHARD_INFO,
  TS_GET_SHARD_STATUS,
  TS_BROKER_CHANGER,
  TS_HA_START,
  TS_HA_STOP,
  TS_HA_STATUS,
  TS_HA_APPLYLOGDB,
  TS_HA_COPYLOGDB,
  TS_HA_RELOAD,
  TS_LIST_DIR,
  TS_AUTO_UPDATE,
  TS_IS_UPDATE_SUCCESS,
  TS_MONITOR_PROCESS,
  TS_GENERATE_CERT
} T_TASK_CODE;

typedef enum
{
  FSVR_NONE,
  FSVR_SA,
  FSVR_CS,
  FSVR_SA_CS,
  FSVR_UC,
  FSVR_SA_UC
} T_FSVR_TYPE;

typedef int (*T_TASK_FUNC) (nvplist *req, nvplist *res, char *_dbmt_error);

typedef unsigned int T_USER_AUTH;

enum
{
  AU_DBC = 1,
  AU_DBO = 2,
  AU_BRK = 4,
  AU_MON = 8,
  AU_JOB = 16,
  AU_VAR = 32,
  AU_ADMIN = (1u << (sizeof (unsigned) * 8 - 1))
};

#define ALL_AUTHORITY (AU_DBC | AU_DBO | AU_MON | AU_JOB | AU_BRK | AU_VAR)

typedef struct
{
  const char *task_str;
  int task_code;
  char access_log_flag;
  T_TASK_FUNC task_func;
  T_FSVR_TYPE fsvr_type;
  T_USER_AUTH user_auth;

} T_FSERVER_TASK_INFO;

int ts_userinfo (nvplist *in, nvplist *out, char *_dbmt_error);
int ts_create_user (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_delete_user (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_update_user (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_class_info (nvplist *in, nvplist *out, char *_dbmt_error);
int ts_class (nvplist *in, nvplist *out, char *_dbmt_error);
int ts_update_attribute (nvplist *in, nvplist *out, char *_dbmt_error);
int ts2_get_unicas_info (nvplist *in, nvplist *out, char *_dbmt_error);
int ts2_start_unicas (nvplist *in, nvplist *out, char *_dbmt_error);
int ts2_stop_unicas (nvplist *in, nvplist *out, char *_dbmt_error);
int ts2_get_admin_log_info (nvplist *in, nvplist *out, char *_dbmt_error);
int ts2_get_logfile_info (nvplist *in, nvplist *out, char *_dbmt_error);
int ts2_get_add_broker_info (nvplist *in, nvplist *out, char *_dbmt_error);
int ts2_delete_broker (nvplist *in, nvplist *out, char *_dbmt_error);
int ts2_get_broker_status (nvplist *in, nvplist *out, char *_dbmt_error);
int ts2_set_broker_conf (nvplist *in, nvplist *out, char *_dbmt_error);
int ts2_start_broker (nvplist *in, nvplist *out, char *_dbmt_error);
int ts2_stop_broker (nvplist *in, nvplist *out, char *_dbmt_error);
int ts2_restart_broker_as (nvplist *in, nvplist *out, char *_dbmt_error);
int ts_set_sysparam (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_get_all_sysparam (nvplist *req, nvplist *res, char *_dbmt_error);
int tsCreateDBMTUser (nvplist *req, nvplist *res, char *_dbmt_error);
int tsDeleteDBMTUser (nvplist *req, nvplist *res, char *_dbmt_error);
int tsUpdateDBMTUser (nvplist *req, nvplist *res, char *_dbmt_error);
int tsChangeDBMTUserPasswd (nvplist *req, nvplist *res, char *_dbmt_error);
int tsGetDBMTUserInfo (nvplist *req, nvplist *res, char *_dbmt_error);
int tsCreateDB (nvplist *req, nvplist *res, char *_dbmt_error);
int tsDeleteDB (nvplist *req, nvplist *res, char *_dbmt_error);
int tsRenameDB (nvplist *req, nvplist *res, char *_dbmt_error);
int tsStartDB (nvplist *req, nvplist *res, char *_dbmt_error);
int tsStopDB (nvplist *req, nvplist *res, char *_dbmt_error);
int tsDbspaceInfo (nvplist *req, nvplist *res, char *_dbmt_error);
int tsRunAddvoldb (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_copydb (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_optimizedb (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_plandump (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_paramdump (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_statdump (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_checkdb (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_compactdb (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_backupdb (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_unloaddb (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_loaddb (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_restoredb (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_backup_vol_info (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_get_dbsize (nvplist *req, nvplist *res, char *_dbmt_error);
int tsGetEnvironment (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_startinfo (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_kill_process (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_backupdb_info (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_unloaddb_info (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_get_backup_info (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_set_backup_info (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_add_backup_info (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_delete_backup_info (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_get_log_info (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_view_log (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_reset_log (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_get_autostart_db (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_set_autostart_db (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_get_auto_add_vol (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_set_auto_add_vol (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_get_addvol_status (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_get_tran_info (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_killtran (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_lockdb (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_get_backup_list (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_load_access_log (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_get_access_log_files (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_get_error_log_files (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_check_dir (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_get_autobackupdb_error_log (nvplist *req, nvplist *res,
                                   char *_dbmt_error);
int ts_get_autoexecquery_error_log (nvplist *req, nvplist *res,
                                    char *_dbmt_error);
int tsGetAutoaddvolLog (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_check_file (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_trigger_operation (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_get_triggerinfo (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_set_autoexec_query (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_get_autoexec_query (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_get_diagdata (nvplist *req, nvplist *res, char *diag_error);
int ts_get_broker_diagdata (nvplist *req, nvplist *res, char *diag_error);
int ts_addstatustemplate (nvplist *req, nvplist *res, char *diag_error);
int ts_removestatustemplate (nvplist *req, nvplist *res, char *diag_error);
int ts_updatestatustemplate (nvplist *req, nvplist *res, char *diag_error);
int ts_getstatustemplate (nvplist *req, nvplist *res, char *diag_error);
#if 0                /* ACTIVITY_PROFILE */
int ts_addactivitytemplate (nvplist *req, nvplist *res, char *diag_error);
int ts_removeactivitytemplate (nvplist *req, nvplist *res,
                               char *diag_error);
int ts_updateactivitytemplate (nvplist *req, nvplist *res,
                               char *diag_error);
int ts_getactivitytemplate (nvplist *req, nvplist *res, char *diag_error);
#endif
int ts_analyzecaslog (nvplist *req, nvplist *res, char *diag_error);
int ts_executecasrunner (nvplist *req, nvplist *res, char *diag_error);
int ts_removecasrunnertmpfile (nvplist *req, nvplist *res,
                               char *diag_error);
int ts_getcaslogtopresult (nvplist *cli_request, nvplist *cli_response,
                           char *diag_error);
int ts_get_ldb_class_att (nvplist *req, nvplist *res, char *_dbmt_error);
int tsDBMTUserLogin (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_remove_log (nvplist *in, nvplist *out, char *_dbmt_error);
int ts_get_host_stat (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_get_dbproc_stat (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_changemode (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_heartbeat_list (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_get_standby_server_stat (nvplist *req, nvplist *res,
                                char *_dbmt_error);
int ts_get_db_mode (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_role_change (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_user_verify (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_write_and_save_conf (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_run_sql_statement (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_get_folders_with_keyword (nvplist *req, nvplist *res,
                                 char *_dbmt_error);
int ts_run_script (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_copy_folder (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_delete_folder (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_get_file_total_line_num (nvplist *req, nvplist *res,
                                char *_dbmt_error);
int ts_get_envvar_by_name (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_error_trace (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_login (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_logout (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_get_cms_env (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_keepalive (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_remove_files (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_job_test (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_dbs_spaceInfo (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_shard_start (nvplist *req, nvplist *res, char *err_buf);
int ts_shard_stop (nvplist *req, nvplist *res, char *err_buf);
int ts_get_shard_info (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_get_shard_status (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_broker_changer (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_ha_start (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_ha_stop (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_ha_status (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_ha_reload (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_ha_applylogdb (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_ha_copylogdb (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_list_dir (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_auto_update (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_is_update_success (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_monitor_process (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_generate_cert (nvplist *req, nvplist *res, char *_dbmt_error);
int
ts_add_nvp_time (nvplist *ref, const char *name, time_t t, const char *fmt,
                 int type);

#endif /* _CM_JOB_TASK_H_ */
