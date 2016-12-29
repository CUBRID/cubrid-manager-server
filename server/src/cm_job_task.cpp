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
 * cm_job_task.cpp -
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <ctype.h>            /* isalpha(), isspace() */
#include <fcntl.h>
#include <errno.h>

#if defined(WINDOWS)
#include <process.h>
#include <winsock2.h>
#include <windows.h>
#include <io.h>
#include <tlhelp32.h>
#else
#include <sys/types.h>        /* umask()         */
#include <sys/stat.h>         /* umask(), stat() */
#include <fnmatch.h>
#include <libgen.h>           /* strfind() */
#include <sys/shm.h>
#include <unistd.h>
#include <sys/wait.h>         /* wait()          */
#include <dirent.h>           /* opendir() ...   */
#include <pwd.h>              /* getpwuid_r() */
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/utsname.h>
#include <pthread.h>
#if !defined(HPUX)
#include <sys/procfs.h>
#endif
#endif

#include "cm_log.h"
#include "cm_stat.h"
#include "cm_porting.h"
#include "cm_server_util.h"
#include "cm_job_task.h"
#include "cm_auto_task.h"
#include "cm_dep.h"
#include "cm_config.h"
#include "cm_cmd_exec.h"
#include "cm_user.h"
#include "cm_text_encryption.h"
#include "cm_connect_info.h"
#include "cm_server_autoupdate.h"

#include "openssl/pem.h"
#include "openssl/conf.h"
#include "openssl/x509v3.h"
#include "openssl/md5.h"
#ifndef OPENSSL_NO_ENGINE
#include "openssl/engine.h"
#endif

#include <list>
#include <string>

#include<assert.h>

using namespace std;

#define PATTERN_LOG 1
#define PATTERN_VOL 2

#define MAX_MSG_LINE  10000

#define DBMT_ERR_MSG_SET(ERR_BUF, MSG)    \
    strncpy(ERR_BUF, MSG, DBMT_ERROR_MSG_SIZE - 1)
#define CUBRID_ERR_MSG_SET(ERR_BUF)       \
    DBMT_ERR_MSG_SET(ERR_BUF, db_error_string(1))

#define MAX_BROKER_NAMELENGTH 128
#define MAX_AS_COUNT          200
#define SET_LONGLONG_STR(STR, LL_VALUE) sprintf(STR, "%lld", (long long) LL_VALUE);

#define QUERY_BUFFER_MAX        4096

#if !defined(WINDOWS)
#define STRING_APPEND(buffer_p, avail_size_holder, ...)                      \
    do {                                                                     \
        if (avail_size_holder > 0) {                                         \
            int n = snprintf (buffer_p, avail_size_holder, __VA_ARGS__);     \
            if (n > 0)        {                                              \
                if ((size_t) n < avail_size_holder) {                        \
                    buffer_p += n; avail_size_holder -= n;                   \
                } else {                                                     \
                    buffer_p += (avail_size_holder - 1);                     \
                    avail_size_holder = 0;                                   \
                }                                                            \
            }                                                                \
        }                                                                    \
    } while (0)
#else /* !WINDOWS */
#define STRING_APPEND(buffer_p, avail_size_holder, ...)                      \
    do {                                                                     \
        if (avail_size_holder > 0) {                                         \
            int n = _snprintf (buffer_p, avail_size_holder, __VA_ARGS__);    \
            if (n < 0 || (size_t) n >= avail_size_holder) {                  \
                buffer_p += (avail_size_holder - 1);                         \
                avail_size_holder = 0;                                       \
                *buffer_p = '\0';                                            \
            } else {                                                         \
                buffer_p += n; avail_size_holder -= n;                       \
            }                                                                \
        }                                                                    \
    } while (0)
#endif /* !WINDOWS */

extern T_EMGR_VERSION CLIENT_VERSION;
extern T_USER_TOKEN_INFO *user_token_info;

typedef struct
{
    char dbname[DB_NAME_LEN];
    char server_mode[64];
    char server_msg[1024];
} T_DB_MODE_INFO;

typedef struct
{
    char hostname[MAXHOSTNAMELEN];
    char dbname[DB_NAME_LEN];
    char logpath[PATH_MAX];
    char state[64];
    int pid;
    char mode[16];        /* mode of copylogdb proc. */
} T_HA_LOG_PROC_INFO;

typedef struct
{
    char dbname[DB_NAME_LEN];
    int pid;
    char state[64];
} T_HA_DB_PROC_INFO;

typedef struct
{
    char dbname[DB_NAME_LEN];
    int num_ap;
    int num_cp;
    T_DB_MODE_INFO *dbmode_info;
    T_HA_DB_PROC_INFO *dbproc_info;
    T_HA_LOG_PROC_INFO *applylogdb_info;
    T_HA_LOG_PROC_INFO *copylogdb_info;
} T_HA_DBSERVER_INFO;

typedef struct
{
    char hostname[MAXHOSTNAMELEN];
    char ip[64];
    char state[64];
    int priority;
} T_HA_NODE_INFO;

typedef struct
{
    int num_dbinfo;
    int num_nodeinfo;
    T_HA_DBSERVER_INFO *db_info;
    T_HA_NODE_INFO *node_info;
    char current_node[MAXHOSTNAMELEN];
    char current_node_state[64];
} T_HA_SERVER_INFO_ALL;

typedef struct
{
    INT64 delay_time;
    INT64 insert_counter;
    INT64 update_counter;
    INT64 delete_counter;
    INT64 commit_counter;
    INT64 fail_counter;
} T_STANDBY_SERVER_STAT;

typedef struct
{
    INT64 num_req;
    INT64 num_query;
    INT64 num_tran;
    INT64 num_long_query;
    INT64 num_long_tran;
    INT64 num_error_query;
    int num_busy_count;
    int num_session;
} T_BROKER_DIAGDATA;


#if defined(WINDOWS)
static void replace_colon (char *path);
#endif

static char *to_upper_str (char *str, char *buf);
static char *to_lower_str (char *str, char *buf);
static int uca_conf_write (T_CM_BROKER_CONF * uc_conf, char *del_broekr,
                           char *_dbmt_error);
static char *get_user_name (int uid, char *name_buf);
static const char *_op_get_port_from_config (T_CM_BROKER_CONF * uc_conf,
                                             char *broker_name);

static int _tsParseSpacedb (nvplist * req, nvplist * res, char *dbname,
                            char *_dbmt_error, T_SPACEDB_RESULT * cmd_res);
static void _ts_gen_spaceinfo (nvplist * res, const char *filename,
                               const char *dbinstalldir, const char *type, int pagesize);

static void _tsAppendDBMTUserList (nvplist * res, T_DBMT_USER * dbmt_user,
                                   int return_dbmt_pwd, char *_dbmt_error);
static int _ts_lockdb_parse_us (nvplist * res, FILE * infile);

static int get_dbitemdir (char *item_dir, size_t item_dir_size, char *dbname,
                          char *err_buf, int itemtype);
static int get_dblogdir (char *log_dir, size_t log_dir_size, char *dbname,
                         char *err_buf);
static int get_dbvoldir (char *vol_dir, size_t vol_dir_size, char *dbname,
                         char *err_buf);
static int op_make_triggerinput_file_add (nvplist * req, char *input_filename);
static int op_make_triggerinput_file_drop (nvplist * req, char *input_filename);
static int op_make_triggerinput_file_alter (nvplist * req, char *input_filename);

static int get_broker_info_from_filename (char *path, char *br_name, int *as_id);
static char *_ts_get_error_log_param (char *dbname);

static char *cm_get_abs_file_path (const char *filename, char *buf);
static int check_dbpath (char *dir, char *_dbmt_error);

static int file_to_nvpairs (char *filepath, nvplist * res);
static int file_to_nvp_by_separator (FILE * fp, nvplist * res, char separator);
static int obsolete_version_autoexecquery_conf (const char *conf_line);
static int alter_dblocation (const char *dbname, const char *new_dbpath);
static void print_db_stat_to_res (T_CM_DB_PROC_STAT * db_stat, nvplist * res);
static int record_ha_topology_to_struct (FILE * infile, int get_all_dbmode,
                                         char *dblist, char *_dbmt_error, T_HA_SERVER_INFO_ALL ** all_info_out);
static char *get_mode_from_output_file (char *mode, int buf_len,
                                        FILE * outputfile, char *_dbmt_error);
static void dbinfo_list_free (T_HA_SERVER_INFO_ALL * all_info);
static void print_dbinfo_list_to_res (T_HA_SERVER_INFO_ALL * all_info,
                                      nvplist * res);
static void print_ha_proc_info (T_HA_LOG_PROC_INFO * ha_log_proc,
                                int elem_num, int is_copylogdb, nvplist * res);
static int dbname_exist_in_dbinfo_list (int nitem, char *dbname,
                                        T_HA_SERVER_INFO_ALL * all_info);
static char *get_ip_from_hostname (char *hostname, char *ipaddr, int ip_len);
static int parse_standby_server_stat (T_STANDBY_SERVER_STAT * stat,
                                      FILE * outfile, char *_dbmt_error);
static int analyze_heartbeat_cmd_outfile (FILE * infile, char *_dbmt_error);
static char *cub_admin_cmd_name (char *cmd_name, int buf_len);
static int cmd_get_db_mode (T_DB_MODE_INFO * dbmode, char *dbname,
                            char *dbmt_error);
static int fill_dbmode_into_dbinfo_list (T_HA_SERVER_INFO_ALL ** all_info,
                                         char *_dbmt_error);
static int parse_ha_proc_msg_to_all_info_array (char *buf, char *_dbmt_error,
                                                T_HA_SERVER_INFO_ALL ** all_info, int *nitem,
                                                int *nalloc, int *nproc_alloc, int get_all_dbmode,
                                                char *dblist);
static int parse_ha_node_to_all_info_array (char *buf, T_HA_SERVER_INFO_ALL ** all_info,
                                            int *node_alloc, char *_dbmt_error);
static int is_name_in_list (char *dbname, char *dblist);
static int cmd_heartbeat_list (T_HA_SERVER_INFO_ALL ** all_info,
                               int get_all_dbmode, char *dblist, char *_dbmt_error);
static int cmd_heartbeat_act (char *_dbmt_error);
static int cmd_heartbeat_deact (char *_dbmt_error);
static int cmd_changemode (char *dbname, char *modify, char *force,
                           char *server_mode_out, int mode_len, char *_dbmt_error);
static int run_csql_statement (const char *sql_stat, char *dbname,
                               char *dbuser, char *dbpasswd, char *outfilepath, char *_dbmt_error);

static void set_copylogdb_mode (T_HA_LOG_PROC_INFO * copylogdb);

static int _op_get_session_from_broker (char *broker_list,
                                        T_CM_CAS_INFO_ALL * cas_info_all);
static void _op_print_br_diagdata_to_res (nvplist * res,
                                          T_BROKER_DIAGDATA br_diagdata);
static int _write_conf_to_file (nvplist * req, char *conf_path);
static int _get_folders_with_keyword (char *search_folder_path,
                                      const char *keyword, nvplist * res, char *_dbmt_error);
static int _get_block_from_log (FILE * fp, char *block_buf, int len);
static int
_update_nvplist_name (nvplist * ref, const char *name, const char *value);
static int
_get_confpath_by_name (const char *conf_name, char *conf_path, int buflen);

static void _write_auto_update_log (char *line_buf, int is_success);
static char *_get_format_time ();
static void read_stdout_stderr_as_err (char *tmp_out_file, char *tmp_err_file,
                                       char *_dbmt_error);
static int _run_child (const char *const argv[], int wait_flag,
                       char *task_name, char *stdout_file, char *_dbmt_error);
static int _check_backup_info (const char *conf_item[], int check_backupid,
                               char *_dbmt_error);
static int _verify_user_passwd (char *dbname, char *dbuser, char *dbpasswd,
                                char *_dbmt_error);
static int _add_extensions (X509 * cert, int nid, char *value);
static void _add_issuer_info (X509_NAME * name, const char *item_name,
                              char *item_value);
static int _make_cert (nvplist * req, X509 ** x509p, EVP_PKEY ** pkeyp,
                       int bits, char *_dbmt_error);
static int _hash_cert (char *hash_value, char *file_path);
static int _is_default_cert (char *_dbmt_error);
static int _is_exist_default_backup_cert (char *_dbmt_error);
static int _backup_cert (char *_dbmt_error);
static int _recover_cert (char *_dbmt_error);

static int
_verify_user_passwd (char *dbname, char *dbuser, char *dbpasswd,
                     char *_dbmt_error)
{
    int retval = ERR_NO_ERROR;

    /* every user can access db_user table. */
    const char *sql_stat = "select 1 from db_root";

    if (dbname == NULL)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", "dbname");
        return ERR_PARAM_MISSING;
    }

    if (dbuser == NULL)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", "dbuser");
        return ERR_PARAM_MISSING;
    }

    /*
    * using csql to verify the user's password.
    */
    retval = run_csql_statement (sql_stat, dbname, dbuser, dbpasswd, NULL, _dbmt_error);    /* csql */

    return retval;
}

static int
_run_child (const char *const argv[], int wait_flag, char *task_name,
            char *stdout_file, char *_dbmt_error)
{
    char tmp_out_file[PATH_MAX];
    char tmp_err_file[PATH_MAX];

    int exit_code = 0;
    int ret_val = ERR_NO_ERROR;

    tmp_out_file[0] = '\0';
    tmp_err_file[0] = '\0';

    if (stdout_file == NULL)
    {
        snprintf (tmp_out_file, PATH_MAX, "%s/%s.%u.out.tmp",
                  sco.dbmt_tmp_dir, task_name, getpid ());
    }
    else
    {
        snprintf (tmp_out_file, PATH_MAX, stdout_file);
    }
    snprintf (tmp_err_file, PATH_MAX, "%s/%s.%u.err.tmp",
              sco.dbmt_tmp_dir, task_name, getpid ());

    if (run_child
    (argv, wait_flag, NULL, tmp_out_file, tmp_err_file, &exit_code) < 0)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", argv[0]);
        ret_val = ERR_SYSTEM_CALL;
        goto rm_return;
    }

    if (read_error_file (tmp_err_file, _dbmt_error, DBMT_ERROR_MSG_SIZE) < 0)
    {
        ret_val = ERR_WITH_MSG;
        goto rm_return;
    }

    if (exit_code != EXIT_SUCCESS)
    {
        read_stdout_stderr_as_err (tmp_out_file, NULL, _dbmt_error);
        ret_val = ERR_WITH_MSG;
        goto rm_return;
    }

rm_return:
    if (stdout_file == NULL)
    {
        unlink (tmp_out_file);
    }
    unlink (tmp_err_file);
    return ret_val;
}

static int
_add_nvp_time (nvplist * ref, const char *name, time_t t, const char *fmt,
               int type)
{
    char strbuf[64];
    if (t == 0)
    {
        return (nv_add_nvp (ref, name, ""));
    }
    else
    {
        time_to_str (t, fmt, strbuf, type);
        return (nv_add_nvp (ref, name, strbuf));
    }
}

/* if cubrid.conf's error_log is null, construct it by default value if existing */
static char *
_ts_get_error_log_param (char *dbname)
{
    char *tok[2];
    FILE *infile;
    char buf[PATH_MAX], dbdir[PATH_MAX];

    if ((uRetrieveDBDirectory (dbname, dbdir)) != ERR_NO_ERROR)
    {
        return NULL;
    }

#if !defined (DO_NOT_USE_CUBRIDENV)
    snprintf (buf, PATH_MAX - 1, "%s/conf/%s", sco.szCubrid, CUBRID_CUBRID_CONF);
#else
    snprintf (buf, PATH_MAX - 1, "%s/%s", CUBRID_CONFDIR, CUBRID_CUBRID_CONF);
#endif

    if ((infile = fopen (buf, "r")) == NULL)
    {
        return NULL;
    }

    while (fgets (buf, sizeof (buf), infile))
    {
        ut_trim (buf);
        if (isalpha ((int) buf[0]))
        {
            if (string_tokenize2 (buf, tok, 2, '=') < 0)
            {
                continue;
            }
            if (uStringEqual (tok[0], "error_log"))
            {
                fclose (infile);
                if (tok[1][0] == '\0')
                {
                    return NULL;
                }
#if defined(WINDOWS)
                unix_style_path (tok[1]);
#endif
                return (strdup (tok[1]));
            }
        }
    }
    fclose (infile);
    return NULL;
}

int
ts_get_broker_diagdata (nvplist * cli_request, nvplist * cli_response,
                        char *_dbmt_error)
{
    int i;
    char *broker_list = NULL;
    T_CM_BROKER_INFO_ALL uc_info;
    T_CM_BROKER_INFO *br_info = NULL;
    T_BROKER_DIAGDATA br_diagdata;
    T_CM_ERROR error;
    int get_all_diagdata = 0;

    memset (&br_diagdata, 0, sizeof (T_BROKER_DIAGDATA));

    /* get broker info, if broker name is NULL then get all of them,
    else get specified broker diagdata. */
    broker_list = nv_get_val (cli_request, "bname");

    if (broker_list == NULL)
    {
        get_all_diagdata = 1;
    }

    if (cm_get_broker_info (&uc_info, &error) < 0)
    {
        strcpy (_dbmt_error, error.err_msg);
        return ERR_NO_ERROR;
    }

    _add_nvp_time (cli_response, "time", time (NULL),
                   "%04d/%02d/%02d %02d:%02d:%02d", TIME_STR_FMT_DATE_TIME);

    for (i = 0; i < uc_info.num_info; i++)
    {
        br_info = uc_info.br_info + i;

        if (strcmp (br_info->status, "OFF") == 0)
        {
            continue;
        }

        if (get_all_diagdata || is_name_in_list (br_info->name, broker_list))
        {
            int session = 0;
            T_CM_CAS_INFO_ALL cas_info_all;

            session = _op_get_session_from_broker (br_info->name, &cas_info_all);

            if (session < 0)
            {
                strcpy_limit (_dbmt_error, "Couldn't get session from broker", DBMT_ERROR_MSG_SIZE);
                return ERR_WITH_MSG;
            }

            br_diagdata.num_req += br_info->num_req;
            br_diagdata.num_query += br_info->num_query;
            br_diagdata.num_tran += br_info->num_tran;
            br_diagdata.num_long_query += br_info->num_long_query;
            br_diagdata.num_long_tran += br_info->num_long_tran;
            br_diagdata.num_error_query += br_info->num_error_query;
            br_diagdata.num_busy_count += br_info->num_busy_count;
            br_diagdata.num_session += session;

            /* if the bname_list is not NULL, then get each broker diagdata. */
            if (get_all_diagdata == 0)
            {
                nv_add_nvp (cli_response, "open", "broker");
                nv_add_nvp (cli_response, "bname", br_info->name);
                _op_print_br_diagdata_to_res (cli_response, br_diagdata);
                nv_add_nvp (cli_response, "close", "broker");

                /* init br_diagdata to get the next broker diagdata. */
                memset (&br_diagdata, 0, sizeof (T_BROKER_DIAGDATA));
            }

            /* free spaces that malloced in cm_cas_info_free */
            cm_cas_info_free (&cas_info_all, NULL);
        }
    }

    /* free spaces that malloced in cm_broker_info_free */
    cm_broker_info_free (&uc_info);

    /* return the sum of the diagdata to res, when bname token is NULL. */
    if (get_all_diagdata)
    {
        _op_print_br_diagdata_to_res (cli_response, br_diagdata);
    }

    return ERR_NO_ERROR;
}

static int
_op_get_session_from_broker (char *broker_list,
                             T_CM_CAS_INFO_ALL * cas_info_all)
{
    int i;
    int session_t = 0;
    T_CM_CAS_INFO *as_info = NULL;
    T_CM_ERROR error;

    if (cm_get_cas_info (broker_list, cas_info_all, NULL, &error) < 0)
    {
        return -1;
    }

    for (i = 0; i < cas_info_all->num_info; i++)
    {
        as_info = cas_info_all->as_info + i;
        if (uStringEqual (as_info->status, "BUSY"))
        {
            session_t += 1;
        }
    }
    return session_t;
}

static void
_op_print_br_diagdata_to_res (nvplist * res, T_BROKER_DIAGDATA br_diagdata)
{
#ifdef JSON_SUPPORT
    nv_add_nvp (res, "open", "cas_mon");
#else
    nv_add_nvp (res, "cas_mon", "start");
#endif

    /*
    * "cas_mon_act_session" is left for campatibility, from version 8.3.1
    * the "cas_mon_session" is used instead of "cas_mon_act_session"
    */
    nv_add_nvp_int (res, "cas_mon_act_session", br_diagdata.num_busy_count);

    nv_add_nvp_int (res, "cas_mon_session", br_diagdata.num_busy_count);
    nv_add_nvp_int (res, "cas_mon_active", br_diagdata.num_session);
    nv_add_nvp_int64 (res, "cas_mon_req", br_diagdata.num_req);
    nv_add_nvp_int64 (res, "cas_mon_query", br_diagdata.num_query);
    nv_add_nvp_int64 (res, "cas_mon_tran", br_diagdata.num_tran);
    nv_add_nvp_int64 (res, "cas_mon_long_query", br_diagdata.num_long_query);
    nv_add_nvp_int64 (res, "cas_mon_long_tran", br_diagdata.num_long_tran);
    nv_add_nvp_int64 (res, "cas_mon_error_query", br_diagdata.num_error_query);

#ifdef JSON_SUPPORT
    nv_add_nvp (res, "close", "cas_mon");
#else
    nv_add_nvp (res, "cas_mon", "end");
#endif
}

int
ts_get_diagdata (nvplist * cli_request, nvplist * cli_response,
                 char *_dbmt_error)
{
    int i;
    /*T_CM_DIAG_MONITOR_DB_VALUE server_result; */
    char *db_name, *broker_name;
    char *mon_db, *mon_cas;
    T_CM_BROKER_INFO_ALL uc_info;
    T_CM_BROKER_INFO *br_info;
    int num_busy_count = 0;
    INT64 num_req, num_query, num_tran, num_long_query, num_long_tran,
    num_error_query;
    T_CM_ERROR error;

    db_name = nv_get_val (cli_request, "db_name");
    mon_db = nv_get_val (cli_request, "mon_db");
    mon_cas = nv_get_val (cli_request, "mon_cas");

    /*
    if (cm_get_diag_data (&server_result, db_name, mon_db) == 0)
    {
#ifdef JSON_SUPPORT
        nv_add_nvp (cli_response, "open", "db_mon");
#else
        nv_add_nvp (cli_response, "db_mon", "start");
#endif
        nv_add_nvp_int64 (cli_response, "mon_cub_query_open_page",
                          server_result.query_open_page);
        nv_add_nvp_int64 (cli_response, "mon_cub_query_opened_page",
                          server_result.query_opened_page);
        nv_add_nvp_int64 (cli_response, "mon_cub_query_slow_query",
                          server_result.query_slow_query);
        nv_add_nvp_int64 (cli_response, "mon_cub_query_full_scan",
                          server_result.query_full_scan);
        nv_add_nvp_int64 (cli_response, "mon_cub_lock_deadlock",
                          server_result.lock_deadlock);
        nv_add_nvp_int64 (cli_response, "mon_cub_lock_request",
                          server_result.lock_request);
        nv_add_nvp_int64 (cli_response, "mon_cub_conn_cli_request",
                          server_result.conn_cli_request);
        nv_add_nvp_int64 (cli_response, "mon_cub_conn_aborted_clients",
                          server_result.conn_aborted_clients);
        nv_add_nvp_int64 (cli_response, "mon_cub_conn_conn_req",
                          server_result.conn_conn_req);
        nv_add_nvp_int64 (cli_response, "mon_cub_conn_conn_reject",
                          server_result.conn_conn_reject);
        nv_add_nvp_int64 (cli_response, "mon_cub_buffer_page_write",
                          server_result.buffer_page_write);
        nv_add_nvp_int64 (cli_response, "mon_cub_buffer_page_read",
                          server_result.buffer_page_read);
#ifdef JSON_SUPPORT
        nv_add_nvp (cli_response, "close", "db_mon");
#else
        nv_add_nvp (cli_response, "db_mon", "end");
#endif
    }
    */

    if (mon_cas != NULL && strcmp (mon_cas, "yes") == 0)
    {
        num_req = num_query = num_tran = num_long_query = num_long_tran =
            num_error_query = 0;

        broker_name = nv_get_val (cli_request, "broker_name");

        if (cm_get_broker_info (&uc_info, &error) < 0)
        {
            strcpy (_dbmt_error, error.err_msg);
            return ERR_NO_ERROR;
        }

        for (i = 0; i < uc_info.num_info; i++)
        {
            br_info = uc_info.br_info + i;

            if (strcmp (br_info->status, "OFF") != 0 &&
                (broker_name == NULL || strcasecmp (broker_name, br_info->name) == 0))
            {
                num_req += br_info->num_req;
                num_query += br_info->num_query;
                num_tran += br_info->num_tran;
                num_long_query += br_info->num_long_query;
                num_long_tran += br_info->num_long_tran;
                num_error_query += br_info->num_error_query;
                num_busy_count += br_info->num_busy_count;
            }
        }
#ifdef JSON_SUPPORT
        nv_add_nvp (cli_response, "open", "cas_mon");
#else
        nv_add_nvp (cli_response, "cas_mon", "start");
#endif
        nv_add_nvp_int (cli_response, "cas_mon_act_session", num_busy_count);
        nv_add_nvp_int64 (cli_response, "cas_mon_req", num_req);
        nv_add_nvp_int64 (cli_response, "cas_mon_query", num_query);
        nv_add_nvp_int64 (cli_response, "cas_mon_tran", num_tran);
        nv_add_nvp_int64 (cli_response, "cas_mon_long_query", num_long_query);
        nv_add_nvp_int64 (cli_response, "cas_mon_long_tran", num_long_tran);
        nv_add_nvp_int64 (cli_response, "cas_mon_error_query", num_error_query);

#ifdef JSON_SUPPORT
        nv_add_nvp (cli_response, "close", "cas_mon");
#else
        nv_add_nvp (cli_response, "cas_mon", "end");
#endif
    }

    return ERR_NO_ERROR;
}

int
ts_userinfo (nvplist * req, nvplist * res, char *_dbmt_error)
{
    int retval;

    retval = cm_ts_userinfo (req, res, _dbmt_error);

    if (retval != ERR_NO_ERROR)
        return retval;

    _update_nvplist_name (res, "name", ENCRYPT_ARG ("name"));
    _update_nvplist_name (res, "id", ENCRYPT_ARG ("id"));

    return ERR_NO_ERROR;
}

int
ts_create_user (nvplist * req, nvplist * res, char *_dbmt_error)
{
    return cm_ts_create_user (req, res, _dbmt_error);
}

int
ts_delete_user (nvplist * req, nvplist * res, char *_dbmt_error)
{
    int retval;
    char *db_uid = nv_get_val (req, "username");

    if ((retval = cm_ts_delete_user (req, res, _dbmt_error)) == ERR_NO_ERROR)
    {
        auto_conf_execquery_delete_by_dbuser (db_uid);
    }

    return retval;
}

int
ts_update_user (nvplist * req, nvplist * res, char *_dbmt_error)
{
    T_DBMT_USER dbmt_user;
    const char *new_db_user_name;
    const char *new_db_user_pass;
    char *db_name;
    int i, ret;

    new_db_user_name = nv_get_val (req, "username");
    new_db_user_pass = nv_get_val (req, "userpass");
    db_name = nv_get_val (req, "_DBNAME");

    if (new_db_user_pass)
    {
        if (uStringEqual (new_db_user_pass, "__NULL__")
            || uStringEqual (new_db_user_pass, ""))
        {
            sprintf (_dbmt_error, "%s", "user password is empty!");
            return ERR_WITH_MSG;
        }
    }

    ret = cm_ts_update_user (req, res, _dbmt_error);
    if (ret != ERR_NO_ERROR)
    {
        return ret;
    }

#ifndef PK_AUTHENTICAITON
    if (new_db_user_pass)
    {
        char hexacoded[PASSWD_ENC_LENGTH];
        /* update cmdb.pass dbinfo */
        if (dbmt_user_read (&dbmt_user, _dbmt_error) == ERR_NO_ERROR)
        {
            int src_dbinfo;

            for (i = 0; i < dbmt_user.num_dbmt_user; i++)
            {
                src_dbinfo =
                    dbmt_user_search (&(dbmt_user.user_info[i]), db_name);
                if (src_dbinfo < 0)
                {
                    continue;
                }
                if (strcmp
                    (dbmt_user.user_info[i].dbinfo[src_dbinfo].uid, new_db_user_name) != 0)
                {
                    continue;
                }
            }
            dbmt_user_write_auth (&dbmt_user, _dbmt_error);
            dbmt_user_free (&dbmt_user);
        }

        /* update db_user's passwd in autoexecquery.conf */
        uEncrypt (PASSWD_LENGTH, new_db_user_pass, hexacoded);
        auto_conf_execquery_update_dbuser (new_db_user_name, new_db_user_name, hexacoded);
    }
#endif
    return ERR_NO_ERROR;
}


int
ts_class_info (nvplist * req, nvplist * res, char *_dbmt_error)
{
    return cm_ts_class_info (req, res, _dbmt_error);
}

int
ts_class (nvplist * req, nvplist * res, char *_dbmt_error)
{
    return cm_ts_class (req, res, _dbmt_error);
}

#if defined(WINDOWS)
static void
replace_colon (char *path)
{
    char *p;
    for (p = path; *p; p++)
    {
        if (*p == '|')
        *p = ':';
    }
}
#endif

int
ts_update_attribute (nvplist * req, nvplist * res, char *_dbmt_error)
{
    return cm_ts_update_attribute (req, res, _dbmt_error);
}

int
ts2_get_unicas_info (nvplist * in, nvplist * out, char *_dbmt_error)
{
    T_CM_BROKER_INFO_ALL uc_info;
    int i;
    T_CM_BROKER_CONF uc_conf;
    T_CM_ERROR error;
    char *broker_name;

    broker_name = nv_get_val (in, "bname");
    memset (&uc_info, 0, sizeof (T_CM_BROKER_INFO_ALL));
    if (cm_get_broker_conf (&uc_conf, NULL, &error) < 0)
    {
        strcpy (_dbmt_error, error.err_msg);
        return ERR_WITH_MSG;
    }
    if (cm_get_broker_info (&uc_info, &error) < 0)
    {
        char *p;
        int tmp_val;

        strcpy (_dbmt_error, error.err_msg);
        nv_add_nvp (out, "open", "brokersinfo");
        for (i = 0; i < uc_conf.num_broker; i++)
        {
            /*
            *add broker info to response according to the requested
            * dbname.if dbname is null, then print all the brokers.
            */
            if ((broker_name != NULL) &&
                (uc_info.br_info != NULL) &&
                (strcmp (uc_info.br_info[i].name, broker_name) != 0))
            {
                continue;
            }
            nv_add_nvp (out, "open", "broker");
            nv_add_nvp (out, "name",
            cm_br_conf_get_value (&(uc_conf.br_conf[i]), "%"));
            nv_add_nvp (out, "port",
                        cm_br_conf_get_value (&(uc_conf.br_conf[i]), "BROKER_PORT"));
            nv_add_nvp (out, "appl_server_shm_id",
                        cm_br_conf_get_value (&(uc_conf.br_conf[i]), "APPL_SERVER_SHM_ID"));
            p = cm_br_conf_get_value (&(uc_conf.br_conf[i]), "SOURCE_ENV");
            tmp_val = 1;
            if (p == NULL || *p == '\0')
                tmp_val = 0;
            nv_add_nvp_int (out, "source_env", tmp_val);
            p = cm_br_conf_get_value (&(uc_conf.br_conf[i]), "ACCESS_LIST");
            tmp_val = 1;
            if (p == NULL || *p == '\0')
                tmp_val = 0;
            nv_add_nvp_int (out, "access_list", tmp_val);
            nv_add_nvp (out, "close", "broker");
        }
        nv_add_nvp (out, "close", "brokersinfo");
        nv_add_nvp (out, "brokerstatus", "OFF");
    }
    else
    {
        char *shmid;
        nv_add_nvp (out, "open", "brokersinfo");
        for (i = 0; i < uc_info.num_info; i++)
        {
            /*
            *add broker info to response according to the requested
            * dbname.if dbname is null, then print all the brokers.
            */
            if ((broker_name != NULL) &&
                (uc_info.br_info != NULL) &&
                (strcmp (uc_info.br_info[i].name, broker_name) != 0))
            {
                continue;
            }
            nv_add_nvp (out, "open", "broker");
            nv_add_nvp (out, "name", uc_info.br_info[i].name);
            nv_add_nvp (out, "type", uc_info.br_info[i].as_type);
            if (strcmp (uc_info.br_info[i].status, "OFF") != 0)
            {
                nv_add_nvp_int (out, "pid", uc_info.br_info[i].pid);
                nv_add_nvp_int (out, "port", uc_info.br_info[i].port);
                nv_add_nvp_int (out, "as", uc_info.br_info[i].num_as);
                nv_add_nvp_int (out, "jq", uc_info.br_info[i].num_job_q);
#ifdef GET_PSINFO
                nv_add_nvp_int (out, "thr", uc_info.br_info[i].num_thr);
                nv_add_nvp_float (out, "cpu", uc_info.br_info[i].pcpu, "%.2f");
                nv_add_nvp_int (out, "time", uc_info.br_info[i].cpu_time);
#endif
                nv_add_nvp_int (out, "req", uc_info.br_info[i].num_req);
                nv_add_nvp_int64 (out, "tran", uc_info.br_info[i].num_tran);
                nv_add_nvp_int64 (out, "query", uc_info.br_info[i].num_query);
                nv_add_nvp_int64 (out, "long_tran", uc_info.br_info[i].num_long_tran);
                nv_add_nvp_int64 (out, "long_query", uc_info.br_info[i].num_long_query);
                nv_add_nvp_int64 (out, "error_query", uc_info.br_info[i].num_error_query);
                nv_add_nvp_float (out, "long_tran_time",
                                  uc_info.br_info[i].long_transaction_time / 1000.0f, "%.2f");
                nv_add_nvp_float (out, "long_query_time",
                                  uc_info.br_info[i].long_query_time / 1000.0f, "%.2f");

                nv_add_nvp (out, "keep_conn", uc_info.br_info[i].keep_connection);

                nv_add_nvp (out, "auto", uc_info.br_info[i].auto_add);
                nv_add_nvp (out, "ses", uc_info.br_info[i].session_timeout);
                nv_add_nvp (out, "sqll", uc_info.br_info[i].sql_log_mode);
                nv_add_nvp (out, "log", uc_info.br_info[i].log_dir);
                nv_add_nvp (out, "access_mode", uc_info.br_info[i].access_mode);
            }
            else
            {
                nv_add_nvp (out, "port", _op_get_port_from_config (&uc_conf, uc_info.br_info[i].name));
            }
            nv_add_nvp (out, "state", uc_info.br_info[i].status);
            nv_add_nvp_int (out, "source_env",
                            uc_info.br_info[i].source_env_flag);
            nv_add_nvp_int (out, "access_list",
                            uc_info.br_info[i].access_list_flag);
            shmid =
                cm_br_conf_get_value (cm_conf_find_broker(&uc_conf, uc_info.br_info[i].name), 
                                      "APPL_SERVER_SHM_ID");
            nv_add_nvp (out, "appl_server_shm_id", shmid);
            nv_add_nvp (out, "close", "broker");
        }
        nv_add_nvp (out, "close", "brokersinfo");
        nv_add_nvp (out, "brokerstatus", "ON");
        cm_broker_info_free (&uc_info);
    }

    cm_broker_conf_free (&uc_conf);
    return ERR_NO_ERROR;
}


int
ts2_start_unicas (nvplist * in, nvplist * out, char *_dbmt_error)
{
    T_CM_ERROR error;
    if (cm_broker_env_start (&error) < 0)
    {
        strcpy (_dbmt_error, error.err_msg);
        return ERR_WITH_MSG;
    }

    return ERR_NO_ERROR;
}

int
ts2_stop_unicas (nvplist * in, nvplist * out, char *_dbmt_error)
{
    T_CM_ERROR error;
    if (cm_broker_env_stop (&error) < 0)
    {
        strcpy (_dbmt_error, error.err_msg);
        return ERR_WITH_MSG;
    }

    return ERR_NO_ERROR;
}

int
ts2_get_admin_log_info (nvplist * in, nvplist * out, char *_dbmt_error)
{
    char buf[PATH_MAX];
    struct stat statbuf;

    cm_get_broker_file (UC_FID_ADMIN_LOG, buf);

    if (stat (buf, &statbuf) != 0)
    {
        return ERR_STAT;
    }
    nv_add_nvp (out, "open", "adminloginfo");
    nv_add_nvp (out, "path", buf);
    nv_add_nvp (out, "owner", get_user_name (statbuf.st_uid, buf));
    nv_add_nvp_int (out, "size", statbuf.st_size);
    _add_nvp_time (out, "lastupdate", statbuf.st_mtime, "%04d.%02d.%02d", NV_ADD_DATE);
    nv_add_nvp (out, "close", "adminloginfo");

    return ERR_NO_ERROR;
}

int
ts2_get_logfile_info (nvplist * in, nvplist * out, char *_dbmt_error)
{
#if defined(WINDOWS)
    HANDLE handle;
    WIN32_FIND_DATA data;
    char find_file[PATH_MAX];
    int found;
#else
    DIR *dp;
    struct dirent *dirp;
#endif
    struct stat statbuf;
    T_CM_BROKER_CONF uc_conf;
    char logdir[PATH_MAX], err_logdir[PATH_MAX], access_logdir[PATH_MAX];
    const char *v;
    char *bname, *from, buf[1024], scriptdir[PATH_MAX];
    char *cur_file;
    T_CM_ERROR error;

    bname = nv_get_val (in, "broker");
    from = nv_get_val (in, "from");
    nv_add_nvp (out, "broker", bname);
    nv_add_nvp (out, "from", from);
    nv_add_nvp (out, "open", "logfileinfo");

    if (bname == NULL)
    {
        strcpy (_dbmt_error, "broker");
        return ERR_PARAM_MISSING;
    }
    chdir (sco.szCubrid);
    if (cm_get_broker_conf (&uc_conf, NULL, &error) < 0)
    {
        strcpy (_dbmt_error, error.err_msg);
        return ERR_WITH_MSG;
    }
    v = cm_br_conf_get_value (cm_conf_find_broker (&uc_conf, bname), "ERROR_LOG_DIR");
    if (v == NULL)
    {
        v = BROKER_LOG_DIR "/error_log";
    }
    cm_get_abs_file_path (v, err_logdir);

    v = cm_br_conf_get_value (cm_conf_find_broker (&uc_conf, bname), "LOG_DIR");
    if (v == NULL)
    {
        v = BROKER_LOG_DIR "/sql_log";
    }
    cm_get_abs_file_path (v, logdir);

    cm_get_abs_file_path (BROKER_LOG_DIR, access_logdir);

    cm_broker_conf_free (&uc_conf);

#if defined(WINDOWS)
    snprintf (find_file, PATH_MAX - 1, "%s/*", access_logdir);
    handle = FindFirstFile (find_file, &data);
    if (handle != INVALID_HANDLE_VALUE)
#else
    dp = opendir (access_logdir);
    if (dp != NULL)
#endif
    {
#if defined(WINDOWS)
        for (found = 1; found; found = FindNextFile (handle, &data))
#else
        while ((dirp = readdir (dp)) != NULL)
#endif
        {
#if defined(WINDOWS)
            cur_file = data.cFileName;
#else
            cur_file = dirp->d_name;
#endif
          if (strstr (cur_file, bname) != NULL)
            {
                nv_add_nvp (out, "open", "logfile");
                if (strstr (cur_file, "access") != NULL)
                {
                    nv_add_nvp (out, "type", "access");
                }
                snprintf (buf, sizeof (buf) - 1, "%s/%s", access_logdir, cur_file);
                nv_add_nvp (out, "path", buf);
                stat (buf, &statbuf);
                nv_add_nvp (out, "owner", get_user_name (statbuf.st_uid, buf));
                nv_add_nvp_int (out, "size", statbuf.st_size);
                _add_nvp_time (out, "lastupdate", statbuf.st_mtime, "%04d.%02d.%02d", NV_ADD_DATE);
                nv_add_nvp (out, "close", "logfile");
            }
        }
#if defined(WINDOWS)
    FindClose (handle);
#else
    closedir (dp);
#endif
    }
#if defined(WINDOWS)
    snprintf (find_file, PATH_MAX - 1, "%s/*", err_logdir);
    handle = FindFirstFile (find_file, &data);
    if (handle != INVALID_HANDLE_VALUE)
#else
    dp = opendir (err_logdir);
    if (dp != NULL)
#endif
    {
#if defined(WINDOWS)
        for (found = 1; found; found = FindNextFile (handle, &data))
#else
        while ((dirp = readdir (dp)) != NULL)
#endif
        {
#if defined(WINDOWS)
            cur_file = data.cFileName;
#else
            cur_file = dirp->d_name;
#endif
            if (strstr (cur_file, bname) != NULL)
            {
                nv_add_nvp (out, "open", "logfile");
                if (strstr (cur_file, "access") != NULL)
                {
                    nv_add_nvp (out, "type", "access");
                }
                else if (strstr (cur_file, "err") != NULL)
                {
                    nv_add_nvp (out, "type", "error");
                }
                snprintf (buf, sizeof (buf) - 1, "%s/%s", err_logdir, cur_file);
                nv_add_nvp (out, "path", buf);
                stat (buf, &statbuf);
                nv_add_nvp (out, "owner", get_user_name (statbuf.st_uid, buf));
                nv_add_nvp_int (out, "size", statbuf.st_size);
                _add_nvp_time (out, "lastupdate", statbuf.st_mtime, "%04d.%02d.%02d", NV_ADD_DATE);
                nv_add_nvp (out, "close", "logfile");
            }
        }
#if defined(WINDOWS)
        FindClose (handle);
#else
        closedir (dp);
#endif
    }
#if defined(WINDOWS)
    snprintf (find_file, PATH_MAX - 1, "%s/*", logdir);
    handle = FindFirstFile (find_file, &data);
    if (handle != INVALID_HANDLE_VALUE)
#else
    dp = opendir (logdir);
    if (dp != NULL)
#endif
    {
#if defined(WINDOWS)
        for (found = 1; found; found = FindNextFile (handle, &data))
#else
        while ((dirp = readdir (dp)) != NULL)
#endif
        {
#if defined(WINDOWS)
            cur_file = data.cFileName;
#else
            cur_file = dirp->d_name;
#endif
            if (strstr (cur_file, bname) != NULL)
            {
                nv_add_nvp (out, "open", "logfile");
                if (strstr (cur_file, "access") != NULL)
                {
                    nv_add_nvp (out, "type", "access");
                }
                snprintf (buf, sizeof (buf) - 1, "%s/%s", logdir, cur_file);
                nv_add_nvp (out, "path", buf);
                stat (buf, &statbuf);
                nv_add_nvp (out, "owner", get_user_name (statbuf.st_uid, buf));
                nv_add_nvp_int (out, "size", statbuf.st_size);
                _add_nvp_time (out, "lastupdate", statbuf.st_mtime, "%04d.%02d.%02d", NV_ADD_DATE);
                nv_add_nvp (out, "close", "logfile");
            }
        }
#if defined(WINDOWS)
        FindClose (handle);
#else
        closedir (dp);
#endif
    }
    snprintf (scriptdir, PATH_MAX - 1, "%s", logdir);
#if defined(WINDOWS)
    snprintf (find_file, PATH_MAX - 1, "%s/*", scriptdir);
    handle = FindFirstFile (find_file, &data);
    if (handle != INVALID_HANDLE_VALUE)
#else
    dp = opendir (scriptdir);
    if (dp != NULL)
#endif
    {

        sprintf (bname, "%s_", bname);
#if defined(WINDOWS)
        for (found = 1; found; found = FindNextFile (handle, &data))
#else
        while ((dirp = readdir (dp)) != NULL)
#endif
        {
#if defined(WINDOWS)
            cur_file = data.cFileName;
#else
            cur_file = dirp->d_name;
#endif

            if (strstr (cur_file, bname) != NULL)
            {
                nv_add_nvp (out, "open", "logfile");
                nv_add_nvp (out, "type", "script");
                snprintf (buf, sizeof (buf) - 1, "%s/%s", scriptdir, cur_file);
                nv_add_nvp (out, "path", buf);
                stat (buf, &statbuf);
                nv_add_nvp (out, "owner", get_user_name (statbuf.st_uid, buf));
                nv_add_nvp_int (out, "size", statbuf.st_size);
                _add_nvp_time (out, "lastupdate", statbuf.st_mtime, "%04d.%02d.%02d", NV_ADD_DATE);
                nv_add_nvp (out, "close", "logfile");
            }
        }
#if defined(WINDOWS)
        FindClose (handle);
#else
        closedir (dp);
#endif
    }
    nv_add_nvp (out, "close", "logfileinfo");

    return ERR_NO_ERROR;
}

int
ts2_get_add_broker_info (nvplist * in, nvplist * out, char *_dbmt_error)
{
    FILE *infile;
    char broker_conf_path[PATH_MAX], strbuf[1024];

    cm_get_broker_file (UC_FID_CUBRID_BROKER_CONF, broker_conf_path);

    if (access (broker_conf_path, F_OK) < 0)
    {
        return ERR_FILE_OPEN_FAIL;
    }

    infile = fopen (broker_conf_path, "r");
    if (infile == NULL)
    {
        strcpy (_dbmt_error, broker_conf_path);
        return ERR_FILE_OPEN_FAIL;
    }

    nv_add_nvp (out, "confname", "broker");
    nv_add_nvp (out, "open", "conflist");

    while (fgets (strbuf, sizeof (strbuf), infile) != NULL)
    {
        uRemoveCRLF (strbuf);
        nv_add_nvp (out, "confdata", strbuf);
    }
    nv_add_nvp (out, "close", "conflist");
    fclose (infile);

    return ERR_NO_ERROR;
}

int
ts2_delete_broker (nvplist * in, nvplist * out, char *_dbmt_error)
{
    char *bname;
    int retval = ERR_NO_ERROR;
    T_CM_BROKER_CONF uc_conf;
    T_CM_ERROR error;

    if ((bname = nv_get_val (in, "bname")) == NULL)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", "bname");
        return ERR_PARAM_MISSING;
    }

    if (cm_get_broker_conf (&uc_conf, NULL, &error) < 0)
    {
        strcpy (_dbmt_error, error.err_msg);
        return ERR_WITH_MSG;
    }

    retval = uca_conf_write (&uc_conf, bname, _dbmt_error);

    cm_broker_conf_free (&uc_conf);

    return retval;
}


int
ts2_get_broker_status (nvplist * in, nvplist * out, char *_dbmt_error)
{
    T_CM_CAS_INFO_ALL as_info_set;
    T_CM_JOB_INFO_ALL job_info_set;
    T_CM_ERROR error;
    char *bname, buf[1024];
    char *blist;
    int more_than_one_broker = 0;
    int i;

    if ((blist = nv_get_val (in, "bname")) == NULL)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", "bname");
        return ERR_PARAM_MISSING;
    }

    /* if there is more than one brokers, there should be more than one ',' separator. */
    if (strstr (blist, ",") != NULL)
    {
        more_than_one_broker = 1;
    }

    while (blist != NULL)
    {
        bname = blist;

        if ((blist = strchr (blist, ',')) != NULL)
        {
            blist[0] = '\0';
            blist++;
        }

        ut_trim (bname);

        if (more_than_one_broker != 0)
        {
            nv_add_nvp (out, "open", "broker");
        }

        nv_add_nvp (out, "bname", bname);
        _add_nvp_time (out, "time", time (NULL),
                       "%04d/%02d/%02d %02d:%02d:%02d", TIME_STR_FMT_DATE_TIME);
        if (cm_get_cas_info (bname, &as_info_set, &job_info_set, &error) >= 0)
        {
            for (i = 0; i < as_info_set.num_info; i++)
            {
                if (strcmp (as_info_set.as_info[i].service_flag, "ON") != 0)
                    continue;

                nv_add_nvp (out, "open", "asinfo");

                nv_add_nvp_int (out, "as_id", as_info_set.as_info[i].id);
                nv_add_nvp_int (out, "as_pid", as_info_set.as_info[i].pid);
                nv_add_nvp_int (out, "as_c",
                                as_info_set.as_info[i].num_request);
                /* add "as_port" nvp in windows:
                as_port only shows up on windows platform. */
#if defined(WINDOWS)
                nv_add_nvp_int (out, "as_port", as_info_set.as_info[i].as_port);
#endif
                nv_add_nvp_int (out, "as_psize", as_info_set.as_info[i].psize);
                nv_add_nvp (out, "as_status", as_info_set.as_info[i].status);
                nv_add_nvp_float (out, "as_cpu", as_info_set.as_info[i].pcpu, "%.2f");
                cm_cpu_time_str (as_info_set.as_info[i].cpu_time, buf);
                nv_add_nvp (out, "as_ctime", buf);
                _add_nvp_time (out, "as_lat",
                               as_info_set.as_info[i].last_access_time, 
                               "%02d/%02d/%02d %02d:%02d:%02d", NV_ADD_DATE_TIME);
                nv_add_nvp (out, "as_cur", as_info_set.as_info[i].log_msg);
                nv_add_nvp_int64 (out, "as_num_query", as_info_set.as_info[i].num_queries_processed);
                nv_add_nvp_int64 (out, "as_num_tran", as_info_set.as_info[i].num_transactions_processed);
                nv_add_nvp_int64 (out, "as_long_query", as_info_set.as_info[i].num_long_queries);
                nv_add_nvp_int64 (out, "as_long_tran", as_info_set.as_info[i].num_long_transactions);
                nv_add_nvp_int64 (out, "as_error_query", as_info_set.as_info[i].num_error_queries);
                nv_add_nvp (out, "as_dbname", as_info_set.as_info[i].database_name);
                nv_add_nvp (out, "as_dbhost", as_info_set.as_info[i].database_host);
                _add_nvp_time (out, "as_lct", as_info_set.as_info[i].last_connect_time,
                               "%02d/%02d/%02d %02d:%02d:%02d", NV_ADD_DATE_TIME);
                /* add "as_client_ip" nvp. */
                nv_add_nvp (out, "as_client_ip", as_info_set.as_info[i].clt_ip_addr);
                nv_add_nvp (out, "close", "asinfo");
            }
            for (i = 0; i < job_info_set.num_info; i++)
            {
                nv_add_nvp (out, "open", "jobinfo");
                nv_add_nvp_int (out, "job_id", job_info_set.job_info[i].id);
                nv_add_nvp_int (out, "job_priority",
                                job_info_set.job_info[i].priority);
                nv_add_nvp (out, "job_ip", job_info_set.job_info[i].ipstr);
                _add_nvp_time (out, "job_time",
                               job_info_set.job_info[i].recv_time, "%02d:%02d:%02d", NV_ADD_TIME);
                snprintf (buf, sizeof (buf) - 1, "%s:%s",
                          job_info_set.job_info[i].script, job_info_set.job_info[i].prgname);
                nv_add_nvp (out, "job_request", buf);
                nv_add_nvp (out, "close", "jobinfo");
            }
            cm_cas_info_free (&as_info_set, &job_info_set);
        }
        if (more_than_one_broker != 0)
        {
            nv_add_nvp (out, "close", "broker");
        }
    }

    return ERR_NO_ERROR;
}



int
ts2_set_broker_conf (nvplist * in, nvplist * out, char *_dbmt_error)
{
    FILE *outfile;
    char broker_conf_path[PATH_MAX];
    char *conf, *confdata;
    int nv_len, i;

    cm_get_broker_file (UC_FID_CUBRID_BROKER_CONF, broker_conf_path);

    if ((outfile = fopen (broker_conf_path, "w")) == NULL)
    {
        return ERR_TMPFILE_OPEN_FAIL;
    }

    nv_len = in->nvplist_leng;
    for (i = 1; i < nv_len; i++)
    {
        nv_lookup (in, i, &conf, &confdata);
        if ((conf != NULL) && (strcmp (conf, "confdata") == 0))
        {
            if (confdata == NULL)
            {
                fprintf (outfile, "\n");
            }
            else
            {
                fprintf (outfile, "%s\n", confdata);
            }
        }
    }

    fclose (outfile);

    return ERR_NO_ERROR;
}


int
ts2_start_broker (nvplist * in, nvplist * out, char *_dbmt_error)
{
    char *bname;
    T_CM_ERROR error;

    if ((bname = nv_get_val (in, "bname")) == NULL)
    {
        strcpy (_dbmt_error, "broker name");
        return ERR_PARAM_MISSING;
    }

    if (cm_broker_on (bname, &error) < 0)
    {
        strcpy (_dbmt_error, error.err_msg);
        return ERR_WITH_MSG;
    }
    return ERR_NO_ERROR;
}

int
ts2_stop_broker (nvplist * in, nvplist * out, char *_dbmt_error)
{
    char *bname;
    T_CM_ERROR error;

    if ((bname = nv_get_val (in, "bname")) == NULL)
    {
        strcpy (_dbmt_error, "broker name");
        return ERR_PARAM_MISSING;
    }

    if (cm_broker_off (bname, &error) < 0)
    {
        strcpy (_dbmt_error, error.err_msg);
        return ERR_WITH_MSG;
    }
    return ERR_NO_ERROR;
}

int
ts2_restart_broker_as (nvplist * in, nvplist * out, char *_dbmt_error)
{
    char *bname, *asnum;
    T_CM_ERROR error;
    T_CM_BROKER_INFO_ALL uc_info;

    int num_as = 0;

    bname = nv_get_val (in, "bname");
    asnum = nv_get_val (in, "asnum");

    if (bname == NULL)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", "bname");
        return ERR_PARAM_MISSING;
    }

    if (asnum == NULL)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", "asnum");
        return ERR_PARAM_MISSING;
    }

    if (cm_get_broker_info (&uc_info, &error) < 0)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", error.err_msg);
        return ERR_WITH_MSG;
    }

    num_as = atoi (asnum);
    if ((num_as <= 0) || (num_as > uc_info.br_info->num_as))
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE,
                  "Broker query id(%d) is not exist.", num_as);
        return ERR_WITH_MSG;
    }

    if (cm_broker_as_restart (bname, num_as, &error) < 0)
    {
        strcpy (_dbmt_error, error.err_msg);
        return ERR_WITH_MSG;
    }
    return ERR_NO_ERROR;
}

int
ts_set_sysparam (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char conf_path[PATH_MAX];
    char *conf_name;

    conf_name = nv_get_val (req, "confname");
    if (conf_name == NULL)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", "confname");
        return ERR_PARAM_MISSING;
    }

    if (_get_confpath_by_name (conf_name, conf_path, sizeof (conf_path)) < 0)
    {
        strcpy (_dbmt_error, "confname error");
        return ERR_WITH_MSG;
    }

    if (_write_conf_to_file (req, conf_path) < 0)
    {
        return ERR_TMPFILE_OPEN_FAIL;
    }

    return ERR_NO_ERROR;
}

int
ts_get_all_sysparam (nvplist * req, nvplist * res, char *_dbmt_error)
{
    FILE *infile;
    char conf_path[PATH_MAX], strbuf[1024 * 200];
    char *conf_name;

    conf_name = nv_get_val (req, "confname");
    if (conf_name == NULL)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", "confname");
        return ERR_PARAM_MISSING;
    }

    if (_get_confpath_by_name (conf_name, conf_path, sizeof (conf_path)) < 0)
    {
        strcpy (_dbmt_error, "confname error");
        return ERR_WITH_MSG;
    }

    if (access (conf_path, F_OK) < 0)
    {
        return ERR_FILE_OPEN_FAIL;
    }

    infile = fopen (conf_path, "r");
    if (infile == NULL)
    {
        strcpy (_dbmt_error, conf_path);
        return ERR_FILE_OPEN_FAIL;
    }

    nv_add_nvp (res, "confname", conf_name);
    nv_add_nvp (res, "open", "conflist");

    while (fgets (strbuf, sizeof (strbuf), infile) != NULL)
    {
        uRemoveCRLF (strbuf);
        nv_add_nvp (res, "confdata", strbuf);
    }
    nv_add_nvp (res, "close", "conflist");
    fclose (infile);

    return ERR_NO_ERROR;
}

static int
_get_confpath_by_name (const char *conf_name, char *conf_path, int buflen)
{
    int retval = 0;

    if (uStringEqual (conf_name, "cubridconf"))
    {
        snprintf (conf_path, buflen - 1, "%s/conf/%s", sco.szCubrid,
                  CUBRID_CUBRID_CONF);
    }
    else if (uStringEqual (conf_name, "cmconf"))
    {
        snprintf (conf_path, buflen - 1, "%s/conf/%s", sco.szCubrid,
                  CUBRID_DBMT_CONF);
    }
    else if (uStringEqual (conf_name, "haconf"))
    {
        snprintf (conf_path, buflen - 1, "%s/conf/%s", sco.szCubrid,
                  CUBRID_HA_CONF);
    }
    else if (uStringEqual (conf_name, "databases"))
    {
        snprintf (conf_path, buflen - 1, "%s/%s", sco.szCubrid_databases,
                  CUBRID_DATABASE_TXT);
    }
    else
    {
        snprintf (conf_path, buflen - 1, "%s/conf/%s", sco.szCubrid, conf_name);
    }

    return retval;
}

static int
_write_conf_to_file (nvplist * req, char *conf_path)
{
    char *conf, *conf_data;
    int nv_len, i;
    FILE *outfile = NULL;

    if ((outfile = fopen (conf_path, "w")) == NULL)
    {
        return -1;
    }

    nv_len = req->nvplist_leng;
    for (i = 1; i < nv_len; i++)
    {
        nv_lookup (req, i, &conf, &conf_data);
        if ((conf != NULL) && (strcmp (conf, "confdata") == 0))
        {
            if (conf_data == NULL)
            {
                fprintf (outfile, "\n");
            }
            else
            {
                fprintf (outfile, "%s\n", conf_data);
            }
        }
    }

    fclose (outfile);

    return 0;
}

int
tsCreateDBMTUser (nvplist * req, nvplist * res, char *_dbmt_error)
{
    int num_authinfo = 0, num_dbmt_user;
    char *dbmt_id, *passwd_p;
    int i, retval;
    char dbmt_passwd[PASSWD_ENC_LENGTH];
    T_DBMT_USER dbmt_user;
    T_DBMT_USER_AUTHINFO *authinfo = NULL;

    const char *casauth, *dbcreate, *status_monitor;

    memset (&dbmt_user, 0, sizeof (T_DBMT_USER));

    if ((dbmt_id = nv_get_val (req, "targetid")) == NULL)
    {
        sprintf (_dbmt_error, "%s", "target id");
        return ERR_PARAM_MISSING;
    }
    if ((passwd_p = nv_get_val (req, "password")) == NULL)
    {
        sprintf (_dbmt_error, "%s", "password");
        return ERR_PARAM_MISSING;
    }

    if (0 != IsValidUserName (dbmt_id))
    {
        sprintf (_dbmt_error,
                 "Invalid user name!User name should begin with a letter,and  can only contain letters, digits, or underscore.");
        return ERR_WITH_MSG;
    }

    if (strlen (passwd_p) > PASSWD_LENGTH)
    {
        sprintf (_dbmt_error, "invalid password!");
        return ERR_WITH_MSG;
    }

    uEncrypt (PASSWD_LENGTH, passwd_p, dbmt_passwd);

    if ((retval = dbmt_user_read (&dbmt_user, _dbmt_error)) != ERR_NO_ERROR)
    {
        return retval;
    }
    num_dbmt_user = dbmt_user.num_dbmt_user;
    for (i = 0; i < num_dbmt_user; i++)
    {
        if (strcmp (dbmt_user.user_info[i].user_name, dbmt_id) == 0)
        {
            dbmt_user_free (&dbmt_user);
            sprintf (_dbmt_error, "%s", dbmt_id);
            return ERR_DBMTUSER_EXIST;
        }
    }

    /* set authority info */
    if ((casauth = nv_get_val (req, "casauth")) == NULL)
    {
        casauth = "";
    }
    authinfo =
        (T_DBMT_USER_AUTHINFO *) increase_capacity (authinfo,
                                                    sizeof (T_DBMT_USER_AUTHINFO), 
                                                    num_authinfo, num_authinfo + 1);
    if (authinfo == NULL)
    {
        dbmt_user_free (&dbmt_user);
        return ERR_MEM_ALLOC;
    }
    num_authinfo++;
    dbmt_user_set_authinfo (&(authinfo[num_authinfo - 1]), "unicas", casauth);

    if ((dbcreate = nv_get_val (req, "dbcreate")) == NULL)
    {
        dbcreate = "";
    }
    authinfo =
        (T_DBMT_USER_AUTHINFO *) increase_capacity (authinfo,
                                                    sizeof (T_DBMT_USER_AUTHINFO), 
                                                    num_authinfo, num_authinfo + 1);
    if (authinfo == NULL)
    {
        dbmt_user_free (&dbmt_user);
        return ERR_MEM_ALLOC;
    }
    num_authinfo++;
    dbmt_user_set_authinfo (&(authinfo[num_authinfo - 1]), "dbcreate", dbcreate);

    if ((status_monitor = nv_get_val (req, "statusmonitorauth")) == NULL)
    status_monitor = "";
    authinfo =
        (T_DBMT_USER_AUTHINFO *) increase_capacity (authinfo,
                                                    sizeof (T_DBMT_USER_AUTHINFO), 
                                                    num_authinfo, num_authinfo + 1);
    if (authinfo == NULL)
    {
        dbmt_user_free (&dbmt_user);
        return ERR_MEM_ALLOC;
    }
    num_authinfo++;
    dbmt_user_set_authinfo (&(authinfo[num_authinfo - 1]), "statusmonitorauth", status_monitor);

    /* set user info */
    dbmt_user.user_info =
        (T_DBMT_USER_INFO *) increase_capacity (dbmt_user.user_info,
                                                sizeof (T_DBMT_USER_INFO), 
                                                num_dbmt_user, num_dbmt_user + 1);
    if (dbmt_user.user_info == NULL)
    {
        dbmt_user_free (&dbmt_user);
        if (authinfo != NULL)
        {
            free (authinfo);
        }
        return ERR_MEM_ALLOC;
    }
    num_dbmt_user++;
    dbmt_user_set_userinfo (&(dbmt_user.user_info[num_dbmt_user - 1]), dbmt_id,
                            dbmt_passwd, num_authinfo, authinfo, 0, NULL);
    dbmt_user.num_dbmt_user = num_dbmt_user;

    retval = dbmt_user_write_auth (&dbmt_user, _dbmt_error);
    if (retval != ERR_NO_ERROR)
    {
        dbmt_user_free (&dbmt_user);
        return retval;
    }
    dbmt_user_write_pass (&dbmt_user, _dbmt_error);

    /* add dblist */
    retval = ut_get_dblist (res, 0);
    if (retval != ERR_NO_ERROR)
    {
        ut_error_log (req, "error while adding database lists to response");
        return retval;
    }

    _tsAppendDBMTUserList (res, &dbmt_user, 0, _dbmt_error);
    dbmt_user_free (&dbmt_user);

    return tsUpdateDBMTUser (req, res, _dbmt_error);
}


int
tsDeleteDBMTUser (nvplist * req, nvplist * res, char *_dbmt_error)
{
    T_DBMT_USER dbmt_user;
    char *dbmt_id;
    int i, retval, usr_index;
    char file[PATH_MAX];

    if ((dbmt_id = nv_get_val (req, "targetid")) == NULL)
    {
        sprintf (_dbmt_error, "%s", "target id");
        return ERR_PARAM_MISSING;
    }

    if ((retval = dbmt_user_read (&dbmt_user, _dbmt_error)) != ERR_NO_ERROR)
        return retval;

    usr_index = -1;
    for (i = 0; i < dbmt_user.num_dbmt_user; i++)
    {
        if (strcmp (dbmt_user.user_info[i].user_name, dbmt_id) == 0)
        {
            dbmt_user.user_info[i].user_name[0] = '\0';
            usr_index = i;
            break;
        }
    }
    if (usr_index < 0)
    {
        strcpy (_dbmt_error, conf_get_dbmt_file2 (FID_DBMT_CUBRID_PASS, file));
        dbmt_user_free (&dbmt_user);
        return ERR_FILE_INTEGRITY;
    }

    retval = dbmt_user_write_auth (&dbmt_user, _dbmt_error);
    if (retval != ERR_NO_ERROR)
    {
        dbmt_user_free (&dbmt_user);
        return retval;
    }
    dbmt_user_write_pass (&dbmt_user, _dbmt_error);

    /* add dblist */
    retval = ut_get_dblist (res, 0);
    if (retval != ERR_NO_ERROR)
    {
        return retval;
    }

    _tsAppendDBMTUserList (res, &dbmt_user, 0, _dbmt_error);
    dbmt_user_free (&dbmt_user);

    return ERR_NO_ERROR;
}

int
tsUpdateDBMTUser (nvplist * req, nvplist * res, char *_dbmt_error)
{
    int i, j, usr_index, retval;
    int cas_idx = -1, dbcreate_idx = -1, status_monitor_idx = -1;
    char *dbmt_id;
    char file[PATH_MAX];
    T_DBMT_USER dbmt_user;
    T_DBMT_USER_DBINFO *usr_dbinfo = NULL;
    T_DBMT_USER_AUTHINFO *usr_authinfo = NULL;
    int num_dbinfo = 0, num_authinfo = 0;
    char *z_name, *z_value;
    char *dbname, *dbid, *dbpassword, *casauth, *dbcreate, *status_monitor;
    char *broker_address;

    int is_update_auth = 0;

    memset (&dbmt_user, 0, sizeof (T_DBMT_USER));

    if ((dbmt_id = nv_get_val (req, "targetid")) == NULL)
    {
        sprintf (_dbmt_error, "%s", "target id");
        return ERR_PARAM_MISSING;
    }

    for (i = 0; i < req->nvplist_leng; ++i)
    {
        dbname = dbid = dbpassword = NULL;
        broker_address = NULL;

        nv_lookup (req, i, &z_name, &z_value);

        if (uStringEqual (z_name, "open")
            && uStringEqual (z_value, "authoritylist"))
        {
            is_update_auth = 1;
            continue;
        }

        if (uStringEqual (z_name, "open") && uStringEqual (z_value, "dbauth"))
        {
            nv_lookup (req, ++i, &z_name, &z_value);
            while (!uStringEqual (z_name, "close"))
            {
                if (uStringEqual (z_name, "dbname"))
                {
                    dbname = z_value;
                }
                else if (uStringEqual (z_name, "dbid"))
                {
                    dbid = z_value;
                }
                else if (uStringEqual (z_name, "dbpassword"))
                {
                    dbpassword = z_value;
                }
                else if (uStringEqual (z_name, "dbbrokeraddress"))
                {
                    broker_address = z_value;
                }
                else
                {
                    if (usr_dbinfo != NULL)
                    {
                        free (usr_dbinfo);
                    }
                    return ERR_REQUEST_FORMAT;
                }
                nv_lookup (req, ++i, &z_name, &z_value);
                if (i >= req->nvplist_leng)
                    break;
            }
        }
        if (dbname == NULL || dbid == NULL)
        {
            continue;
        }
        usr_dbinfo =
            (T_DBMT_USER_DBINFO *) increase_capacity (usr_dbinfo,
                                                      sizeof (T_DBMT_USER_DBINFO), 
                                                      num_dbinfo, num_dbinfo + 1);
        if (usr_dbinfo == NULL)
        {
            return ERR_MEM_ALLOC;
        }
        num_dbinfo++;
        dbmt_user_set_dbinfo (&(usr_dbinfo[num_dbinfo - 1]), dbname, "admin",
                              dbid, broker_address);
    }

    if ((casauth = nv_get_val (req, "casauth")) != NULL)
    {
        cas_idx = num_authinfo;

    }
    if ((dbcreate = nv_get_val (req, "dbcreate")) != NULL)
    {
        dbcreate_idx = num_authinfo + 1;

    }
    if ((status_monitor = nv_get_val (req, "statusmonitorauth")) != NULL)
    {
        status_monitor_idx = num_authinfo + 2;

    }

    if ((casauth != NULL) || (dbcreate != NULL))
    {
        usr_authinfo =
            (T_DBMT_USER_AUTHINFO *) increase_capacity (usr_authinfo,
                                                        sizeof (T_DBMT_USER_AUTHINFO), 
                                                        num_authinfo, num_authinfo + 3);
        if (usr_authinfo == NULL)
        {
            free (usr_dbinfo);
            return ERR_MEM_ALLOC;
        }
        num_authinfo += 3;
    }

    if (casauth != NULL && cas_idx >= 0)
    {
        dbmt_user_set_authinfo (&(usr_authinfo[cas_idx]), "unicas", casauth);
    }
    if (dbcreate != NULL && dbcreate_idx >= 0)
    {
        dbmt_user_set_authinfo (&(usr_authinfo[dbcreate_idx]), "dbcreate", dbcreate);
    }
    if (status_monitor != NULL && status_monitor_idx >= 0)
    {
        dbmt_user_set_authinfo (&(usr_authinfo[status_monitor_idx]),
                                "statusmonitorauth", status_monitor);
    }

    if ((retval = dbmt_user_read (&dbmt_user, _dbmt_error)) != ERR_NO_ERROR)
    {
        if (usr_dbinfo != NULL)
        {
            free (usr_dbinfo);
        }
        if (usr_authinfo != NULL)
        {
            free (usr_authinfo);
        }
        return retval;
    }

    usr_index = -1;
    for (i = 0; i < dbmt_user.num_dbmt_user; i++)
    {
        if (strcmp (dbmt_user.user_info[i].user_name, dbmt_id) == 0)
        {
            usr_index = i;
            break;
        }
    }
    if (usr_index < 0)
    {
        strcpy (_dbmt_error, conf_get_dbmt_file2 (FID_DBMT_CUBRID_PASS, file));
        dbmt_user_free (&dbmt_user);
        if (usr_dbinfo != NULL)
        {
            free (usr_dbinfo);
        }
        if (usr_authinfo != NULL)
        {
            free (usr_authinfo);
        }
        return ERR_FILE_INTEGRITY;
    }

    /* auth info */
    if (dbmt_user.user_info[usr_index].authinfo == NULL)
    {
        dbmt_user.user_info[usr_index].num_authinfo = num_authinfo;
        dbmt_user.user_info[usr_index].authinfo = usr_authinfo;
        usr_authinfo = NULL;

    }
    else if (usr_authinfo != NULL)
    {
        T_DBMT_USER_INFO *current_user_info =
            (T_DBMT_USER_INFO *) & (dbmt_user.user_info[usr_index]);

        for (j = 0; j < num_authinfo; j++)
        {
            int find_idx = -1;
            for (i = 0; i < current_user_info->num_authinfo; i++)
            {
                if (strcmp (current_user_info->authinfo[i].domain, usr_authinfo[j].domain) == 0)
                {
                    find_idx = i;
                    break;
                }
            }
            if (find_idx == -1)
            {
                current_user_info->authinfo =
                    (T_DBMT_USER_AUTHINFO *) increase_capacity (current_user_info->authinfo,
                                                                sizeof (T_DBMT_USER_AUTHINFO),
                                                                current_user_info->num_authinfo,
                                                                current_user_info->num_authinfo + 1);
                if (current_user_info->authinfo == NULL)
                {
                    if (usr_dbinfo)
                    {
                        free (usr_dbinfo);
                    }
                    if (usr_authinfo)
                    {
                        free (usr_authinfo);
                    }
                    return ERR_MEM_ALLOC;
                }
                current_user_info->num_authinfo++;
                find_idx = current_user_info->num_authinfo - 1;
            }
            dbmt_user_set_authinfo (&(current_user_info->authinfo[find_idx]),
                                    usr_authinfo[j].domain, usr_authinfo[j].auth);
        }
    }

    /* db info */
    if (dbmt_user.user_info[usr_index].dbinfo == NULL)
    {
        dbmt_user.user_info[usr_index].num_dbinfo = num_dbinfo;
        dbmt_user.user_info[usr_index].dbinfo = usr_dbinfo;
        usr_dbinfo = NULL;

    }
    else if (usr_dbinfo != NULL)
    {
        T_DBMT_USER_INFO *current_user_info =
            (T_DBMT_USER_INFO *) & (dbmt_user.user_info[usr_index]);

        for (j = 0; j < num_dbinfo; j++)
        {
            int find_idx = -1;
            for (i = 0; i < current_user_info->num_dbinfo; i++)
            {
                if (strcmp (current_user_info->dbinfo[i].dbname, usr_dbinfo[j].dbname) == 0)
                {
                    find_idx = i;
                    break;
                }
            }
            if (find_idx == -1)
            {
                current_user_info->dbinfo =
                    (T_DBMT_USER_DBINFO *) increase_capacity (current_user_info->dbinfo,
                                                              sizeof (T_DBMT_USER_DBINFO), 
                                                              current_user_info->num_dbinfo,
                                                              current_user_info->num_dbinfo + 1);
                if (current_user_info->dbinfo == NULL)
                {
                    FREE_MEM (usr_dbinfo);
                    FREE_MEM (usr_authinfo);
                    return ERR_MEM_ALLOC;
                }
                current_user_info->num_dbinfo++;
                find_idx = current_user_info->num_dbinfo - 1;
            }
            dbmt_user_set_dbinfo (&(current_user_info->dbinfo[find_idx]),
                                  usr_dbinfo[j].dbname, usr_dbinfo[j].auth,
                                  usr_dbinfo[j].uid, usr_dbinfo[j].broker_address);
        }
    }

    retval = dbmt_user_write_auth (&dbmt_user, _dbmt_error);
    if (retval != ERR_NO_ERROR)
    {
        dbmt_user_free (&dbmt_user);
        if (usr_dbinfo)
        {
            free (usr_dbinfo);
        }
        if (usr_authinfo)
        {
            free (usr_authinfo);
        }
        return retval;
    }

    /* add dblist */
    retval = ut_get_dblist (res, 0);
    if (retval != ERR_NO_ERROR)
    {
        return retval;
    }

    _tsAppendDBMTUserList (res, &dbmt_user, 0, _dbmt_error);
    dbmt_user_free (&dbmt_user);
    if (usr_dbinfo)
    {
        free (usr_dbinfo);
    }
    if (usr_authinfo)
    {
        free (usr_authinfo);
    }
    return ERR_NO_ERROR;
}

int
tsChangeDBMTUserPasswd (nvplist * req, nvplist * res, char *_dbmt_error)
{
    T_DBMT_USER dbmt_user;
    int i, retval, usr_index;
    char *dbmt_id, *new_passwd;
    char file[PATH_MAX];

    if ((dbmt_id = nv_get_val (req, "targetid")) == NULL)
    {
        sprintf (_dbmt_error, "%s", "target id");
        return ERR_PARAM_MISSING;
    }
    if ((new_passwd = nv_get_val (req, "newpassword")) == NULL)
    {
        sprintf (_dbmt_error, "%s", "new password");
        return ERR_PARAM_MISSING;
    }

    if (!strcmp (new_passwd, ""))
    {
        sprintf (_dbmt_error, "%s", "NULL password");
        return ERR_WITH_MSG;
    }

    if ((retval = dbmt_user_read (&dbmt_user, _dbmt_error)) != ERR_NO_ERROR)
    {
        return retval;
    }
    usr_index = -1;
    for (i = 0; i < dbmt_user.num_dbmt_user; i++)
    {
        if (strcmp (dbmt_user.user_info[i].user_name, dbmt_id) == 0)
        {
            if (new_passwd == NULL)
            {
                dbmt_user.user_info[i].user_passwd[0] = '\0';
            }
            else
            {
                char hexacoded[PASSWD_ENC_LENGTH];

                uEncrypt (PASSWD_LENGTH, new_passwd, hexacoded);
                strcpy (dbmt_user.user_info[i].user_passwd, hexacoded);
            }
            usr_index = i;
            break;
        }
    }
    if (usr_index < 0)
    {
        strcpy (_dbmt_error, conf_get_dbmt_file2 (FID_DBMT_CUBRID_PASS, file));
        dbmt_user_free (&dbmt_user);
        return ERR_FILE_INTEGRITY;
    }

    retval = dbmt_user_write_pass (&dbmt_user, _dbmt_error);
    if (retval != ERR_NO_ERROR)
    {
        dbmt_user_free (&dbmt_user);
        return retval;
    }

    /* add dblist */
    retval = ut_get_dblist (res, 0);
    if (retval != ERR_NO_ERROR)
    {
        return retval;
    }

    _tsAppendDBMTUserList (res, &dbmt_user, 0, _dbmt_error);
    dbmt_user_free (&dbmt_user);

    return ERR_NO_ERROR;
}


int
tsGetDBMTUserInfo (nvplist * req, nvplist * res, char *_dbmt_error)
{
    T_DBMT_USER dbmt_user;
    int retval;

    retval = ut_get_dblist (res, 0);
    if (retval != ERR_NO_ERROR)
    {
        return retval;
    }
    retval = dbmt_user_read (&dbmt_user, _dbmt_error);
    if (retval != ERR_NO_ERROR)
    {
        return retval;
    }
    _tsAppendDBMTUserList (res, &dbmt_user, 1, _dbmt_error);
    dbmt_user_free (&dbmt_user);

    return ERR_NO_ERROR;
}

int
tsCreateDB (nvplist * req, nvplist * res, char *_dbmt_error)
{
    int retval = ERR_NO_ERROR;
    char *dbname = NULL;
    char *dbmt_user_name = NULL;
    char *charset = NULL;

    char *dbpagenum = NULL;
    char *dbpagesize = NULL;
    char *logpagenum = NULL;
    char *logpagesize = NULL;
    char dbvolsize[512];
    char logvolsize[512];

    char *genvolpath = NULL;
    char *logvolpath = NULL;
#if defined(WINDOWS)
    char logvolpath_buf[1024];
#endif
    char *overwrite_config_file = NULL;
    char targetdir[PATH_MAX];
    char extvolfile[PATH_MAX];
    char createdb_err_file[PATH_MAX];
    char *ip, *port;
    T_DBMT_USER dbmt_user;
    T_DBMT_CON_DBINFO con_dbinfo;
    char cmd_name[CUBRID_CMD_NAME_LEN];
    const char *argv[20];
    int argc = 0;
    int gen_dir_created, log_dir_created, ext_dir_created;

    targetdir[0] = '\0';
    extvolfile[0] = '\0';
    createdb_err_file[0] = '\0';

    gen_dir_created = log_dir_created = ext_dir_created = 0;

    if ((dbname = nv_get_val (req, "dbname")) == NULL)
    {
        strcpy (_dbmt_error, "database name");
        return ERR_PARAM_MISSING;
    }

    if ((dbpagenum = nv_get_val (req, "numpage")) == NULL)
    {
        strcpy (_dbmt_error, "numpage");
        return ERR_PARAM_MISSING;
    }

    if ((dbpagesize = nv_get_val (req, "pagesize")) == NULL)
    {
        strcpy (_dbmt_error, "pagesize");
        return ERR_PARAM_MISSING;
    }

    if ((logpagenum = nv_get_val (req, "logsize")) == NULL)
    {
        strcpy (_dbmt_error, "logsize");
        return ERR_PARAM_MISSING;
    }

    if ((logpagesize = nv_get_val (req, "logpagesize")) == NULL)
    {
        strcpy (_dbmt_error, "logpagesize");
        return ERR_PARAM_MISSING;
    }

    if ((dbmt_user_name = nv_get_val (req, "_ID")) == NULL)
    {
        strcpy (_dbmt_error, "_ID");
        return ERR_PARAM_MISSING;
    }

    if ((charset = nv_get_val (req, "charset")) == NULL)
    {
        strcpy (_dbmt_error, "charset");
        return ERR_PARAM_MISSING;
    }

    genvolpath = nv_get_val (req, "genvolpath");
    logvolpath = nv_get_val (req, "logvolpath");
    overwrite_config_file = nv_get_val (req, "overwrite_config_file");

    if (genvolpath == NULL)
    {
        strcpy (_dbmt_error, "volumn path");
        return ERR_PARAM_MISSING;
    }

    if ((retval = check_dbpath (genvolpath, _dbmt_error)) != ERR_NO_ERROR)
    {
        return retval;
    }

    if (logvolpath != NULL && logvolpath[0] == '\0')
    {
        logvolpath = NULL;
    }

    if (logvolpath != NULL
        && (retval = check_dbpath (logvolpath, _dbmt_error)) != ERR_NO_ERROR)
    {
        return retval;
    }

    /* caculate dbvolsize & logvolsize */
    snprintf (dbvolsize, sizeof (dbvolsize) - 1, "%lldB",
              ((long long) atoi (dbpagesize) * (long long) atoi (dbpagenum)));
    snprintf (logvolsize, sizeof (logvolsize) - 1, "%lldB",
              ((long long) atoi (logpagesize) * (long long) atoi (logpagenum)));

    /* create directory */
    strcpy (targetdir, genvolpath);
    if (access (genvolpath, F_OK) < 0)
    {
        retval = uCreateDir (genvolpath);
        if (retval != ERR_NO_ERROR)
        {
            return retval;
        }
        else
        {
            gen_dir_created = 1;
        }
    }

    if (logvolpath != NULL && access (logvolpath, F_OK) < 0)
    {
        retval = uCreateDir (logvolpath);
        if (retval != ERR_NO_ERROR)
        {
            return retval;
        }
        else
        {
            log_dir_created = 1;
        }
    }

    if (access (genvolpath, W_OK) < 0)
    {
        sprintf (_dbmt_error, "%s: %s\n", genvolpath, strerror (errno));
        return ERR_WITH_MSG;
    }

    if (logvolpath != NULL && access (logvolpath, W_OK) < 0)
    {
        sprintf (_dbmt_error, "%s: %s\n", genvolpath, strerror (errno));
        return ERR_WITH_MSG;
    }

    /* copy config file to the directory and update config file */
    if ((overwrite_config_file == NULL)    /* for backword compatibility */
        || (strcasecmp (overwrite_config_file, "NO") != 0))
    {
        char strbuf[1024];
        FILE *infile = NULL;
        FILE *outfile = NULL;
        char dstrbuf[PATH_MAX];

#if !defined (DO_NOT_USE_CUBRIDENV)
        snprintf (dstrbuf, PATH_MAX - 1, "%s/conf/%s", sco.szCubrid,
                  CUBRID_CUBRID_CONF);
#else
        snprintf (dstrbuf, PATH_MAX - 1, "%s/%s", CUBRID_CONFDIR,
                  CUBRID_CUBRID_CONF);
#endif
        infile = fopen (dstrbuf, "r");
        if (infile == NULL)
        {
            strcpy (_dbmt_error, dstrbuf);
            return ERR_FILE_OPEN_FAIL;
        }

        snprintf (dstrbuf, PATH_MAX - 1, "%s/%s", targetdir, CUBRID_CUBRID_CONF);
        outfile = fopen (dstrbuf, "w");
        if (outfile == NULL)
        {
            fclose (infile);
            strcpy (_dbmt_error, dstrbuf);
            return ERR_FILE_OPEN_FAIL;
        }

        while (fgets (strbuf, sizeof (strbuf), infile))
        {
            const char *param;

            param = "data_buffer_pages";
            if (!strncmp (strbuf, param, strlen (param))
                && nv_get_val (req, param))
            {
                fprintf (outfile, "%s=%s\n", param, nv_get_val (req, param));
                continue;
            }

            param = "media_failure_support";
            if (!strncmp (strbuf, param, strlen (param))
                && nv_get_val (req, param))
            {
                fprintf (outfile, "%s=%s\n", param, nv_get_val (req, param));
                continue;
            }

            param = "max_clients";
            if (!strncmp (strbuf, param, strlen (param))
                && nv_get_val (req, param))
            {
                fprintf (outfile, "%s=%s\n", param, nv_get_val (req, param));
                continue;
            }

            fputs (strbuf, outfile);
        }
        fclose (infile);
        fclose (outfile);
    }

    /* remove warning out of space message.
    * judge creation failed if created page size is smaller then
    * 343 page, write message with volumn expend to error file.
    */
    if (0)
    {
        FILE *infile = NULL;
        FILE *outfile = NULL;
        char oldfilename[PATH_MAX];
        char newfilename[PATH_MAX];
        memset (oldfilename, '\0', sizeof (oldfilename));
        memset (newfilename, '\0', sizeof (newfilename));

        snprintf (oldfilename, PATH_MAX - 1, "%s/%s", targetdir,
                  CUBRID_CUBRID_CONF);
        infile = fopen (oldfilename, "r");
        if (infile == NULL)
        {
            strcpy (_dbmt_error, oldfilename);
            return ERR_FILE_OPEN_FAIL;
        }

        snprintf (newfilename, PATH_MAX - 1, "%s/tempcubrid.conf", targetdir);
        outfile = fopen (newfilename, "w");
        if (outfile == NULL)
        {
            fclose (infile);
            strcpy (_dbmt_error, newfilename);
            return ERR_FILE_OPEN_FAIL;
        }

        fclose (infile);
        fclose (outfile);

        unlink (oldfilename);
        rename (newfilename, oldfilename);
    }

    /* construct spec file */
    if (1)
    {
        int pos, len, i;
        char *tn, *tv;
        FILE *outfile;
        char buf[1024], *val[3];
#if defined(WINDOWS)
        char val2_buf[1024];
#endif

        snprintf (extvolfile, PATH_MAX - 1, "%s/extvol.spec", targetdir);
        outfile = fopen (extvolfile, "w");
        if (outfile == NULL)
        {
            strcpy (_dbmt_error, extvolfile);
            return ERR_FILE_OPEN_FAIL;
        }

        nv_locate (req, "exvol", &pos, &len);
        for (i = pos; i < len + pos; ++i)
        {
            nv_lookup (req, i, &tn, &tv);
            if (tv == NULL)
                continue;
            strcpy (buf, tv);
            if (string_tokenize2 (buf, val, 3, ';') < 0)
            {
                continue;
            }

#if defined(WINDOWS)
            val[2] = nt_style_path (val[2], val2_buf);
#endif
            fprintf (outfile, "NAME %s PATH %s PURPOSE %s NPAGES %s\n\n",
                     tn, val[2], val[0], val[1]);
            /* create directory, if needed */
            if (access (val[2], F_OK) < 0)
            {
                retval = uCreateDir (val[2]);
                if (retval != ERR_NO_ERROR)
                {
                    fclose (outfile);
                    return retval;
                }
                else
                {
                    ext_dir_created = 1;
                }
            }
        }
        fclose (outfile);
    }

    /* construct command */
    cubrid_cmd_name (cmd_name);
#if defined(WINDOWS)
    nt_style_path (targetdir, targetdir);
#endif
    argv[argc++] = cmd_name;
    argv[argc++] = UTIL_OPTION_CREATEDB;

    argv[argc++] = "--" CREATE_FILE_PATH_L;
    argv[argc++] = targetdir;

    argv[argc++] = "--" CREATE_DB_VOLUMN_SIZE_L;
    argv[argc++] = dbvolsize;

    argv[argc++] = "--" CREATE_LOG_VOLUMN_SIZE_L;
    argv[argc++] = logvolsize;

    if (dbpagesize)
    {
        argv[argc++] = "--" CREATE_DB_PAGE_SIZE_L;
        argv[argc++] = dbpagesize;
    }
    if (logpagesize)
    {
        argv[argc++] = "--" CREATE_LOG_PAGE_SIZE_L;
        argv[argc++] = logpagesize;
    }
    if (logvolpath)
    {
#if defined(WINDOWS)
        logvolpath = nt_style_path (logvolpath, logvolpath_buf);
        /*
        remove_end_of_dir_ch(logvolpath);
        */
#endif
        argv[argc++] = "--" CREATE_LOG_PATH_L;
        argv[argc++] = logvolpath;
    }
    if (extvolfile[0] != '\0')
    {
        argv[argc++] = "--" CREATE_MORE_VOLUME_FILE_L;
        argv[argc++] = extvolfile;
    }

    argv[argc++] = dbname;
    argv[argc++] = charset;
    argv[argc++] = NULL;

    snprintf (createdb_err_file, PATH_MAX, "%s/createdb_err_file.%d.tmp",
              sco.dbmt_tmp_dir, (int) getpid ());

    retval = run_child (argv, 1, NULL, NULL, createdb_err_file, NULL);    /* createdb */

    if (read_error_file (createdb_err_file, _dbmt_error, DBMT_ERROR_MSG_SIZE) < 0)
    {
        int pos, len, i;
        char *tn, *tv;
        char buf[1024], *val[3];

        if ((access (genvolpath, F_OK) == 0) && (gen_dir_created))
            uRemoveDir (genvolpath, REMOVE_DIR_FORCED);
        if ((logvolpath != NULL) && (access (logvolpath, F_OK) == 0)
            && (log_dir_created))
            uRemoveDir (logvolpath, REMOVE_DIR_FORCED);

        nv_locate (req, "exvol", &pos, &len);
        for (i = pos; i < len + pos; ++i)
        {
            nv_lookup (req, i, &tn, &tv);
            if (tv == NULL)
            {
                continue;
            }
            strcpy (buf, tv);
            if (string_tokenize2 (buf, val, 3, ';') < 0)
            {
                continue;
            }
            if ((access (val[2], F_OK) == 0) && (ext_dir_created))
                uRemoveDir (val[2], REMOVE_DIR_FORCED);    /* ext vol path */
        }
        unlink (createdb_err_file);
        return ERR_WITH_MSG;
    }
  unlink (createdb_err_file);

    if (retval < 0)
    {
        int pos, len, i;
        char *tn, *tv;
        char buf[1024], *val[3];

        if (access (genvolpath, F_OK) == 0)
        {
            uRemoveDir (genvolpath, REMOVE_DIR_FORCED);
        }
        if (logvolpath != NULL && access (logvolpath, F_OK) == 0)
        {
            uRemoveDir (logvolpath, REMOVE_DIR_FORCED);
        }

        nv_locate (req, "exvol", &pos, &len);
        for (i = pos; i < len + pos; ++i)
        {
            nv_lookup (req, i, &tn, &tv);
            if (tv == NULL)
            {
                continue;
            }
            strcpy (buf, tv);
            if (string_tokenize2 (buf, val, 3, ';') < 0)
            {
                continue;
            }
            if (access (val[2], F_OK) == 0)
                uRemoveDir (val[2], REMOVE_DIR_FORCED);    /* ext vol path */
        }

        sprintf (_dbmt_error, "%s", argv[0]);
        return ERR_SYSTEM_CALL;
    }

    /* add dbinfo to cmdb.pass */
    if (dbmt_user_read (&dbmt_user, _dbmt_error) == ERR_NO_ERROR)
    {
        int i;
        T_DBMT_USER_DBINFO tmp_dbinfo;

        memset (&tmp_dbinfo, 0, sizeof (tmp_dbinfo));
        dbmt_user_set_dbinfo (&tmp_dbinfo, dbname, dbmt_user_name, "dba", "");

        dbmt_user_db_delete (&dbmt_user, dbname);
        for (i = 0; i < dbmt_user.num_dbmt_user; i++)
        {
            if (strcmp (dbmt_user.user_info[i].user_name, dbmt_user_name) == 0)
            {
                if (dbmt_user_add_dbinfo
                    (&(dbmt_user.user_info[i]), &tmp_dbinfo) == ERR_NO_ERROR)
                {
                    dbmt_user_write_auth (&dbmt_user, _dbmt_error);
                }
                break;
            }
        }
        dbmt_user_free (&dbmt_user);
    }

    /* add dbinfo to conlist */
    memset (&con_dbinfo, 0, sizeof (con_dbinfo));
    dbmt_con_set_dbinfo (&con_dbinfo, dbname, "dba", "");
    ip = nv_get_val (req, "_IP");
    port = nv_get_val (req, "_PORT");
    dbmt_con_write_dbinfo (&con_dbinfo, ip, port, dbname, 1, _dbmt_error);

    /* restore warn out of space value */
    if (0)
    {
        char strbuf[1024];
        FILE *infile = NULL;
        FILE *outfile = NULL;
        char oldfilename[PATH_MAX];
        char newfilename[PATH_MAX];
        memset (oldfilename, '\0', sizeof (oldfilename));
        memset (newfilename, '\0', sizeof (newfilename));

        snprintf (oldfilename, PATH_MAX - 1, "%s/%s", targetdir,
                  CUBRID_CUBRID_CONF);
        infile = fopen (oldfilename, "r");
        if (infile == NULL)
        {
            strcpy (_dbmt_error, oldfilename);
            return ERR_FILE_OPEN_FAIL;
        }

        snprintf (newfilename, PATH_MAX - 1, "%s/tempcubrid.conf", targetdir);
        outfile = fopen (newfilename, "w");
        if (outfile == NULL)
        {
            fclose (infile);
            strcpy (_dbmt_error, newfilename);
            return ERR_FILE_OPEN_FAIL;
        }

        while (fgets (strbuf, sizeof (strbuf), infile))
        {
            const char *p;
            p = "warn_outofspace_factor";
            if (!strncmp (strbuf, p, strlen (p)))
            {
                fprintf (outfile, "%s", p);
                continue;
            }

            fputs (strbuf, outfile);
        }
        fclose (infile);
        fclose (outfile);

        unlink (oldfilename);
        rename (newfilename, oldfilename);
    }

    if ((overwrite_config_file == NULL)    /* for backward compatibility */
        || (strcasecmp (overwrite_config_file, "NO") != 0))
    {
        char strbuf[PATH_MAX];

        snprintf (strbuf, PATH_MAX - 1, "%s/%s", targetdir, CUBRID_CUBRID_CONF);
        unlink (strbuf);
    }

    if (extvolfile[0] != '\0')
    {
        unlink (extvolfile);
    }
    return ERR_NO_ERROR;
}

int
tsDeleteDB (nvplist * req, nvplist * res, char *_dbmt_error)
{
    T_DBMT_USER dbmt_user;
    int retval = ERR_NO_ERROR;
    char *dbname = NULL, *delbackup;
    char cubrid_err_file[PATH_MAX];
    char cmd_name[CUBRID_CMD_NAME_LEN];
    const char *argv[6];
    int argc = 0;

    /*dbvol path & db log path. */
    char dbvolpath[PATH_MAX];
    char dblogpath[PATH_MAX];

    cubrid_err_file[0] = '\0';

    if ((dbname = nv_get_val (req, "_DBNAME")) == NULL)
    {
        sprintf (_dbmt_error, "%s", "database name");
        return ERR_PARAM_MISSING;
    }

    if (_isRegisteredDB (dbname) == 0)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", dbname);
        return ERR_DB_NONEXISTANT;
    }

    delbackup = nv_get_val (req, "delbackup");

    cubrid_cmd_name (cmd_name);
    argv[argc++] = cmd_name;
    argv[argc++] = UTIL_OPTION_DELETEDB;
    if (uStringEqual (delbackup, "y"))
        argv[argc++] = "--" DELETE_DELETE_BACKUP_L;
    argv[argc++] = dbname;
    argv[argc++] = NULL;

    snprintf (cubrid_err_file, PATH_MAX, "%s/%s.%u.err.tmp",
              sco.dbmt_tmp_dir, "deletedb", getpid ());

    /*get dbvolpath and dblogpath. */
    get_dbvoldir (dbvolpath, sizeof (dbvolpath), dbname, cubrid_err_file);
    get_dblogdir (dblogpath, sizeof (dblogpath), dbname, cubrid_err_file);

    retval = run_child (argv, 1, NULL, NULL, cubrid_err_file, NULL);    /* deletedb */

    if (read_error_file (cubrid_err_file, _dbmt_error, DBMT_ERROR_MSG_SIZE) < 0)
    {
        if (access (cubrid_err_file, F_OK) == 0)
        {
            unlink (cubrid_err_file);
        }
        return ERR_WITH_MSG;
    }
    if (access (cubrid_err_file, F_OK) == 0)
    {
        unlink (cubrid_err_file);
    }
    if (retval < 0)
    {
        strcpy (_dbmt_error, argv[0]);
        return ERR_SYSTEM_CALL;
    }

    auto_conf_addvol_delete (FID_AUTO_ADDVOLDB_CONF, dbname);
    auto_conf_backup_delete (FID_AUTO_BACKUPDB_CONF, dbname);
    auto_conf_history_delete (FID_AUTO_HISTORY_CONF, dbname);
    auto_conf_execquery_delete (FID_AUTO_EXECQUERY_CONF, dbname);

    if (dbmt_user_read (&dbmt_user, _dbmt_error) == ERR_NO_ERROR)
    {
        dbmt_user_db_delete (&dbmt_user, dbname);
        dbmt_user_write_auth (&dbmt_user, _dbmt_error);
        dbmt_user_free (&dbmt_user);
    }

    /* The following delete sequence can delete folder hierarchy like :
    * <database log folder>/<database vol folder>
    * and <database vol folder>/<database log folder>.
    */
    rmdir (dbvolpath);
    rmdir (dblogpath);
    rmdir (dbvolpath);

    return ERR_NO_ERROR;
}

int
tsRenameDB (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char *dbname = NULL;
    char *newdbname = NULL;
    char *exvolpath = NULL;
    char *advanced = NULL;
    char *forcedel = NULL;
    char task_name[10];

    const char *argv[10];

    int argc = 0;
    int retval = 0;
    T_DB_SERVICE_MODE db_mode;
    T_DBMT_USER dbmt_user;

    char cmd_name[CUBRID_CMD_NAME_LEN];
    char tmpfile[PATH_MAX];

    cmd_name[0] = '\0';
    tmpfile[0] = '\0';
    task_name[0] = '\0';

    if ((dbname = nv_get_val (req, "_DBNAME")) == NULL)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", "dbname");
        return ERR_PARAM_MISSING;
    }
    if ((newdbname = nv_get_val (req, "rename")) == NULL)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", "rename");
        return ERR_PARAM_MISSING;
    }
    if ((exvolpath = nv_get_val (req, "exvolpath")) == NULL)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", "exvolpath");
        return ERR_PARAM_MISSING;
    }
    if ((advanced = nv_get_val (req, "advanced")) == NULL)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", "advanced");
        return ERR_PARAM_MISSING;
    }
    if ((forcedel = nv_get_val (req, "forcedel")) == NULL)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", "forcedel");
        return ERR_PARAM_MISSING;
    }

    db_mode = uDatabaseMode (dbname, NULL);
    if (db_mode == DB_SERVICE_MODE_SA)
    {
        sprintf (_dbmt_error, "%s", dbname);
        return ERR_STANDALONE_MODE;
    }
    else if (db_mode == DB_SERVICE_MODE_CS)
    {
        sprintf (_dbmt_error, "%s", dbname);
        return ERR_DB_ACTIVE;
    }

    cubrid_cmd_name (cmd_name);
    argv[argc++] = cmd_name;
    argv[argc++] = UTIL_OPTION_RENAMEDB;

    if (uStringEqual (advanced, "on"))
    {
        FILE *outfile;
        int i, flag = 0, line = 0;
        char *n, *v;
#if defined(WINDOWS)
        char n_buf[1024], v_buf[1024];
#endif
        char *p;

        snprintf (tmpfile, PATH_MAX - 1, "%s/DBMT_task_%d.%d", sco.dbmt_tmp_dir,
                  TS_RENAMEDB, (int) getpid ());
        if ((outfile = fopen (tmpfile, "w")) == NULL)
        {
            return ERR_TMPFILE_OPEN_FAIL;
        }
        for (i = 0; i < req->nvplist_leng; i++)
        {
            nv_lookup (req, i, &n, &v);
            if (n == NULL || v == NULL)
            {
                fclose (outfile);
                if (v != NULL)
                {
                    strcpy (_dbmt_error, v);
                    return ERR_DIR_CREATE_FAIL;
                }
                else
                {
                    strcpy (_dbmt_error, "Lost all parameters.");
                    return ERR_WITH_MSG;
                }
            }

            if (!strcmp (n, "open") && !strcmp (v, "volume"))
            {
                flag = 1;
            }
            else if (!strcmp (n, "close") && !strcmp (v, "volume"))
            {
                flag = 0;
                break;
            }
            else if (flag == 1)
            {
#if defined(WINDOWS)
                replace_colon (n);
                replace_colon (v);
#endif
                p = strrchr (v, '/');
                if (p)
                *p = '\0';
                if (uCreateDir (v) != ERR_NO_ERROR)
                {
                    fclose (outfile);
                    strcpy (_dbmt_error, v);
                    return ERR_DIR_CREATE_FAIL;
                }
                if (p)
                    *p = '/';
#if defined(WINDOWS)
                n = nt_style_path (n, n_buf);
                v = nt_style_path (v, v_buf);
#endif
                fprintf (outfile, "%d %s %s\n", line++, n, v);

            }            /* close "else if (flag == 1)" */
        }            /* close "for" loop */
        fclose (outfile);
        argv[argc++] = "--" RENAME_CONTROL_FILE_L;
        argv[argc++] = tmpfile;
    }                /* close "if (adv_flag != NULL)" */
    else if (exvolpath != NULL && !uStringEqual (exvolpath, "none"))
    {
        if (uCreateDir (exvolpath) != ERR_NO_ERROR)
        {
            strcpy (_dbmt_error, exvolpath);
            return ERR_DIR_CREATE_FAIL;
        }
        argv[argc++] = "--" RENAME_EXTENTED_VOLUME_PATH_L;
        argv[argc++] = exvolpath;
    }

    if (uStringEqual (forcedel, "y"))
        argv[argc++] = "--" RENAME_DELETE_BACKUP_L;

    argv[argc++] = dbname;
    argv[argc++] = newdbname;
    argv[argc++] = NULL;

    snprintf (task_name, TASKNAME_LEN, "%s", "renamedb");
    retval = _run_child (argv, 1, task_name, NULL, _dbmt_error);
    if (retval != ERR_NO_ERROR)
    {
        return retval;
    }

    auto_conf_addvol_rename (FID_AUTO_ADDVOLDB_CONF, dbname, newdbname);
    auto_conf_backup_rename (FID_AUTO_BACKUPDB_CONF, dbname, newdbname);
    auto_conf_history_rename (FID_AUTO_HISTORY_CONF, dbname, newdbname);
    auto_conf_execquery_rename (FID_AUTO_EXECQUERY_CONF, dbname, newdbname);

    if (dbmt_user_read (&dbmt_user, _dbmt_error) == ERR_NO_ERROR)
    {
        int i, j;
        for (i = 0; i < dbmt_user.num_dbmt_user; i++)
        {
            for (j = 0; j < dbmt_user.user_info[i].num_dbinfo; j++)
            {
                if (strcmp (dbmt_user.user_info[i].dbinfo[j].dbname, dbname) == 0)
                {
                    strcpy (dbmt_user.user_info[i].dbinfo[j].dbname, newdbname);
                }
            }
        }
        dbmt_user_write_auth (&dbmt_user, _dbmt_error);
        dbmt_user_free (&dbmt_user);
    }

    return ERR_NO_ERROR;
}

int
tsStartDB (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char *dbname;
    char err_buf[ERR_MSG_SIZE];
    T_DB_SERVICE_MODE db_mode;
    int retval;

    if ((dbname = nv_get_val (req, "_DBNAME")) == NULL)
    {
        sprintf (_dbmt_error, "%s", "database name");
        return ERR_PARAM_MISSING;
    }

    db_mode = uDatabaseMode (dbname, NULL);
    if (db_mode == DB_SERVICE_MODE_SA)
    {
        sprintf (_dbmt_error, "%s", dbname);
        return ERR_STANDALONE_MODE;
    }
    if (db_mode == DB_SERVICE_MODE_CS)
    {
        return ERR_NO_ERROR;
    }

    retval = cmd_start_server (dbname, err_buf, sizeof (err_buf));
    if (retval < 0)
    {
        DBMT_ERR_MSG_SET (_dbmt_error, err_buf);
        return ERR_WITH_MSG;
    }
    else if (retval == 1)
    {
        DBMT_ERR_MSG_SET (_dbmt_error, err_buf);
    }

    /* recount active db num and write to file */
    uWriteDBnfo ();

    return retval == 0 ? ERR_NO_ERROR : ERR_WARNING;
}

int
tsStopDB (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char *dbname;

    if ((dbname = nv_get_val (req, "_DBNAME")) == NULL)
    {
        sprintf (_dbmt_error, "%s", "database name");
        return ERR_PARAM_MISSING;
    }

    if (cmd_stop_server (dbname, _dbmt_error, DBMT_ERROR_MSG_SIZE) < 0)
    {
        return ERR_WITH_MSG;
    }

    /* recount active db num and write to file */
    uWriteDBnfo ();

    return ERR_NO_ERROR;
}

int
tsDbspaceInfo (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char *dbname = NULL;
    int retval = ERR_NO_ERROR;
    char dbname_at_hostname[MAXHOSTNAMELEN + DB_NAME_LEN];
    int ha_mode = 0;
    T_CUBRID_MODE cubrid_mode;
    T_SPACEDB_RESULT *cmd_res;
    T_DB_SERVICE_MODE db_mode;

    /* get dbname */
    if ((dbname = nv_get_val (req, "_DBNAME")) == NULL)
    {
        sprintf (_dbmt_error, "%s", "database name");
        return ERR_PARAM_MISSING;
    }

    db_mode = uDatabaseMode (dbname, &ha_mode);
    if (db_mode == DB_SERVICE_MODE_SA)
    {
        sprintf (_dbmt_error, "%s", dbname);
        return ERR_STANDALONE_MODE;
    }

    nv_add_nvp (res, "dbname", dbname);
    nv_add_nvp (res, "pagesize", "-1");
    nv_add_nvp (res, "logpagesize", "-1");

    cubrid_mode =
        (db_mode == DB_SERVICE_MODE_NONE) ? CUBRID_MODE_SA : CUBRID_MODE_CS;

    if (ha_mode != 0)
    {
        append_host_to_dbname (dbname_at_hostname, dbname, sizeof (dbname_at_hostname));
        cmd_res = cmd_spacedb (dbname_at_hostname, cubrid_mode);
    }
    else
    {
        cmd_res = cmd_spacedb (dbname, cubrid_mode);
    }

    if (cmd_res == NULL)
    {
        sprintf (_dbmt_error, "spacedb %s", dbname);
        retval = ERR_SYSTEM_CALL;
    }
    else if (cmd_res->err_msg[0])
    {
        strcpy (_dbmt_error, cmd_res->err_msg);
        retval = ERR_WITH_MSG;
    }
    else
    {
        retval = _tsParseSpacedb (req, res, dbname, _dbmt_error, cmd_res);
    }
    cmd_spacedb_result_free (cmd_res);

    return retval;
}

static int
nv_append_nvp (nvplist * dest, const nvplist * src)
{
    int i;

    if (dest == NULL || src == NULL)
        return -1;

    for (i = 0; i < src->nvplist_size; ++i)
    {
        if (src->nvpairs[i] == NULL
            || dst_buffer (src->nvpairs[i]->name) == NULL)
            continue;

        nv_add_nvp (dest, dst_buffer (src->nvpairs[i]->name),
        dst_buffer (src->nvpairs[i]->value));
    }

    return 1;
}

int
ts_dbs_spaceInfo (nvplist * req, nvplist * res, char *_dbmt_error)
{
    int i, sect, sect_len;
    char *tval;
    nvplist *cli_request;
    nvplist *cli_response;

    cli_request = nv_create (5, NULL, "\n", ":", "\n");
    cli_response = nv_create (5, NULL, "\n", ":", "\n");
    nv_add_nvp (cli_request, "_DBNAME", "");

    nv_locate (req, "dblist", &sect, &sect_len);
    if (sect >= 0)
    {
        for (i = 0; i < sect_len; ++i)
        {
            nv_lookup (req, sect + i, NULL, &tval);
            nv_update_val (cli_request, "_DBNAME", tval);
            nv_add_nvp (res, "open", tval);
            if (tsDbspaceInfo (cli_request, cli_response, _dbmt_error) == ERR_NO_ERROR)
            {
                nv_append_nvp (res, cli_response);
            }
            nv_reset_nvp (cli_response);
            nv_add_nvp (res, "close", tval);
        }
    }
    nv_destroy (cli_request);
    nv_destroy (cli_response);
    return ERR_NO_ERROR;
}

int
tsRunAddvoldb (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char *dbname = NULL;
    char dbname_at_hostname[MAXHOSTNAMELEN + DB_NAME_LEN];
    int ha_mode = 0;
    char *volpu = NULL;
    char *volpath = NULL;
    char *dbvolsize = NULL;
    char dbvolsize_t[512];
#if defined(WINDOWS)
    char volpath_buf[PATH_MAX];
#endif
    char *volname = NULL;
    char db_dir[PATH_MAX];
    T_DB_SERVICE_MODE db_mode;
    char err_file[PATH_MAX];
    int ret;
    char cmd_name[CUBRID_CMD_NAME_LEN];
    const char *argv[15];
    int argc = 0;
    int free_space_mb;

    err_file[0] = '\0';

    if ((dbname = nv_get_val (req, "_DBNAME")) == NULL)
    {
        sprintf (_dbmt_error, "%s", "database name");
        return ERR_PARAM_MISSING;
    }

    db_mode = uDatabaseMode (dbname, &ha_mode);
    if (db_mode == DB_SERVICE_MODE_SA)
    {
        sprintf (_dbmt_error, "%s", dbname);
        return ERR_STANDALONE_MODE;
    }

    if ((volpu = nv_get_val (req, "purpose")) == NULL)
    {
        sprintf (_dbmt_error, "%s", "purpose");
        return ERR_PARAM_MISSING;
    }

    volpath = nv_get_val (req, "path");
    volname = nv_get_val (req, "volname");

    if ((dbvolsize = nv_get_val (req, "size_need_mb")) == NULL)
    {
        sprintf (_dbmt_error, "%s", "size_nee_mb");
        return ERR_PARAM_MISSING;
    }

    if (uRetrieveDBDirectory (dbname, db_dir) != ERR_NO_ERROR)
    {
        strcpy (_dbmt_error, dbname);
        return ERR_DBDIRNAME_NULL;
    }

    /* check permission of the directory */
    if (access (db_dir, W_OK | X_OK | R_OK) < 0)
    {
        sprintf (_dbmt_error, "%s", db_dir);
        return ERR_PERMISSION;
    }

    if (volpath == NULL)
        volpath = db_dir;

    if (access (volpath, F_OK) < 0)
    {
        if (uCreateDir (volpath) != ERR_NO_ERROR)
        {
            sprintf (_dbmt_error, "%s", volpath);
            return ERR_DIR_CREATE_FAIL;
        }
    }

    free_space_mb = ut_disk_free_space (volpath);
    if (dbvolsize && (free_space_mb < atoi (dbvolsize)))
    {
        sprintf (_dbmt_error, "Not enough free space in disk.");
        return ERR_WITH_MSG;
    }

    /*
    * Get the dbvolsize, the format looks like: size_need_mb:2.047(MB)
    */
    snprintf (dbvolsize_t, sizeof (dbvolsize_t) - 1, "%lldB",
              (long long) (atof (dbvolsize) * BYTES_IN_M));

    cubrid_cmd_name (cmd_name);
    argv[argc++] = cmd_name;
    argv[argc++] = UTIL_OPTION_ADDVOLDB;

    if (db_mode == DB_SERVICE_MODE_NONE)
        argv[argc++] = "--" ADDVOL_SA_MODE_L;

#if defined(WINDOWS)
    volpath = nt_style_path (volpath, volpath_buf);
#endif

    argv[argc++] = "--" ADDVOL_FILE_PATH_L;
    argv[argc++] = volpath;

    if (volname)
    {
        argv[argc++] = "--" ADDVOL_VOLUME_NAME_L;
        argv[argc++] = volname;
    }

    argv[argc++] = "--" ADDVOL_DB_VOLUMN_SIZE_L;
    argv[argc++] = dbvolsize_t;

    argv[argc++] = "--" ADDVOL_PURPOSE_L;
    argv[argc++] = volpu;

    if (ha_mode != 0)
    {
        append_host_to_dbname (dbname_at_hostname, dbname, sizeof (dbname_at_hostname));
        argv[argc++] = dbname_at_hostname;
    }
    else
    {
        argv[argc++] = dbname;
    }

    argv[argc++] = NULL;

    snprintf (err_file, PATH_MAX, "%s/%s.%u.err.tmp", sco.dbmt_tmp_dir, "runaddvoldb", getpid ());

    ret = run_child (argv, 1, NULL, NULL, err_file, NULL);    /* addvoldb */
    if (read_error_file (err_file, _dbmt_error, DBMT_ERROR_MSG_SIZE) < 0)
    {
        if (access (err_file, F_OK) == 0)
        {
            unlink (err_file);
        }
        return ERR_WITH_MSG;
    }

    if (access (err_file, F_OK) == 0)
    {
        unlink (err_file);
    }
    if (ret < 0)
    {
        sprintf (_dbmt_error, "%s", argv[0]);
        return ERR_SYSTEM_CALL;
    }

    nv_add_nvp (res, "dbname", dbname);
    nv_add_nvp (res, "purpose", volpu);

    return ERR_NO_ERROR;
}

int
ts_copydb (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char *srcdbname = NULL;
    char *destdbname = NULL;
    char *logpath = NULL;
    char *destdbpath = NULL;
    char *exvolpath = NULL;
    int move_flag = 0;
    int overwrite_flag = 0;
    int adv_flag = 0;
    char tmpfile[PATH_MAX], cmd_name[CUBRID_CMD_NAME_LEN],
    lob_base_path[PATH_MAX];
    char src_conf_file[PATH_MAX], dest_conf_file[PATH_MAX], conf_dir[PATH_MAX];
    int i = -1;
    int retval = -1;
    char cubrid_err_file[PATH_MAX];
    T_DBMT_USER dbmt_user;
    T_DB_SERVICE_MODE db_mode;
    const char *argv[15];
    int argc = 0;

    /* init var */
    tmpfile[0] = '\0';
    cmd_name[0] = '\0';
    lob_base_path[0] = '\0';
    src_conf_file[0] = '\0';
    dest_conf_file[0] = '\0';
    conf_dir[0] = '\0';
    cubrid_err_file[0] = '\0';

    if ((srcdbname = nv_get_val (req, "srcdbname")) == NULL)
    {
        strcpy (_dbmt_error, "source database name");
        return ERR_PARAM_MISSING;
    }
    if ((destdbname = nv_get_val (req, "destdbname")) == NULL)
    {
        strcpy (_dbmt_error, "destination database name");
        return ERR_PARAM_MISSING;
    }

    adv_flag = uStringEqual (nv_get_val (req, "advanced"), "on") ? 1 : 0;
    overwrite_flag = uStringEqual (nv_get_val (req, "overwrite"), "y") ? 1 : 0;
    move_flag = uStringEqual (nv_get_val (req, "move"), "y") ? 1 : 0;

    if ((logpath = nv_get_val (req, "logpath")) == NULL)
    {
        strcpy (_dbmt_error, "log path");
        return ERR_PARAM_MISSING;
    }
    if ((destdbpath = nv_get_val (req, "destdbpath")) == NULL && adv_flag == 0)
    {
        strcpy (_dbmt_error, "database directory path");
        return ERR_PARAM_MISSING;
    }
    if ((exvolpath = nv_get_val (req, "exvolpath")) == NULL && adv_flag == 0)
    {
        strcpy (_dbmt_error, "extended volume path");
        return ERR_PARAM_MISSING;
    }

    db_mode = uDatabaseMode (srcdbname, NULL);
    if (db_mode == DB_SERVICE_MODE_SA)
    {
        sprintf (_dbmt_error, "%s", srcdbname);
        return ERR_STANDALONE_MODE;
    }
    else if (db_mode == DB_SERVICE_MODE_CS)
    {
        sprintf (_dbmt_error, "%s", srcdbname);
        return ERR_DB_ACTIVE;
    }

    /* create command */
    cubrid_cmd_name (cmd_name);
    argv[argc++] = cmd_name;
    argv[argc++] = UTIL_OPTION_COPYDB;
    argv[argc++] = "--" COPY_LOG_PATH_L;
    argv[argc++] = logpath;

    if (adv_flag)
    {
        FILE *outfile;
        int flag = 0, line = 0;
        char *n, *v;
#if defined(WINDOWS)
        char n_buf[1024], v_buf[1024];
#endif
        char *p;

        snprintf (tmpfile, PATH_MAX - 1, "%s/DBMT_task_%d.%d", sco.dbmt_tmp_dir, TS_COPYDB, (int) getpid ());
        if ((outfile = fopen (tmpfile, "w")) == NULL)
        {
            return ERR_TMPFILE_OPEN_FAIL;
        }
        for (i = 0; i < req->nvplist_leng; i++)
        {
            nv_lookup (req, i, &n, &v);
            if (n == NULL || v == NULL)
            {
                fclose (outfile);
                if (v != NULL)
                {
                    strcpy (_dbmt_error, v);
                }
                return ERR_DIR_CREATE_FAIL;
            }

            if (!strcmp (n, "open") && !strcmp (v, "volume"))
                flag = 1;
            else if (!strcmp (n, "close") && !strcmp (v, "volume"))
                flag = 0;
            else if (flag == 1)
            {
#if defined(WINDOWS)
                replace_colon (n);
                replace_colon (v);
#endif
                p = strrchr (v, '/');
                if (p)
                    *p = '\0';
                snprintf (lob_base_path, PATH_MAX - 1, "%s/lob", v);
                if (uCreateDir (lob_base_path) != ERR_NO_ERROR)
                {
                    fclose (outfile);
                    strcpy (_dbmt_error, lob_base_path);
                    return ERR_DIR_CREATE_FAIL;
                }
                if (p)
                    *p = '/';
#if defined(WINDOWS)
                n = nt_style_path (n, n_buf);
                v = nt_style_path (v, v_buf);
#endif
                fprintf (outfile, "%d %s %s\n", line++, n, v);
            }
        }
        fclose (outfile);
        argv[argc++] = "--" COPY_CONTROL_FILE_L;
        argv[argc++] = tmpfile;
    }
    else
    {                /* adv_flag == 0 */
        snprintf (lob_base_path, PATH_MAX - 1, "%s/lob", destdbpath);
        if (uCreateDir (lob_base_path) != ERR_NO_ERROR)
        {
            strcpy (_dbmt_error, lob_base_path);
            return ERR_DIR_CREATE_FAIL;
        }
        if (uCreateDir (exvolpath) != ERR_NO_ERROR)
        {
            strcpy (_dbmt_error, exvolpath);
            return ERR_DIR_CREATE_FAIL;
        }
        argv[argc++] = "--" COPY_FILE_PATH_L;
        argv[argc++] = destdbpath;
        argv[argc++] = "--" COPY_EXTENTED_VOLUME_PATH_L;
        argv[argc++] = exvolpath;
    }
    if (overwrite_flag)
    {
        argv[argc++] = "--" COPY_REPLACE_L;
    }
    argv[argc++] = "-" COPY_LOB_BASE_PATH_S;
    argv[argc++] = lob_base_path;
    argv[argc++] = srcdbname;
    argv[argc++] = destdbname;
    argv[argc++] = NULL;

    if (uCreateDir (logpath) != ERR_NO_ERROR)
    {
        strcpy (_dbmt_error, logpath);
        return ERR_DIR_CREATE_FAIL;
    }

    snprintf (cubrid_err_file, PATH_MAX, "%s/%s.%u.err.tmp",
              sco.dbmt_tmp_dir, "copydb", getpid ());

    retval = run_child (argv, 1, NULL, NULL, cubrid_err_file, NULL);    /* copydb */
    if (adv_flag)
        unlink (tmpfile);
    if (read_error_file (cubrid_err_file, _dbmt_error, DBMT_ERROR_MSG_SIZE) < 0)
    {
        if (access (cubrid_err_file, F_OK) == 0)
        {
            unlink (cubrid_err_file);
        }
        return ERR_WITH_MSG;
    }
    if (access (cubrid_err_file, F_OK) == 0)
    {
        unlink (cubrid_err_file);
    }
    if (retval < 0)
    {
        strcpy (_dbmt_error, argv[0]);
        return ERR_SYSTEM_CALL;
    }

    /* copy config file */
    if (uRetrieveDBDirectory (srcdbname, conf_dir) != ERR_NO_ERROR)
    {
        strcpy (_dbmt_error, srcdbname);
        return ERR_DBDIRNAME_NULL;
    }
    snprintf (src_conf_file, sizeof (src_conf_file) - 1, "%s/%s", conf_dir, CUBRID_CUBRID_CONF);

    if (uRetrieveDBDirectory (destdbname, conf_dir) != ERR_NO_ERROR)
    {
        strcpy (_dbmt_error, destdbname);
        return ERR_DBDIRNAME_NULL;
    }
    snprintf (dest_conf_file, sizeof (dest_conf_file) - 1, "%s/%s", conf_dir, CUBRID_CUBRID_CONF);

    /* Doesn't copy if src and desc is same */
    if (strcmp (src_conf_file, dest_conf_file) != 0)
        file_copy (src_conf_file, dest_conf_file);

    /* if move, delete exist database */
    if (move_flag)
    {
        char cmd_name[CUBRID_CMD_NAME_LEN];
        const char *argv[5];

        cubrid_cmd_name (cmd_name);
        argv[0] = cmd_name;
        argv[1] = UTIL_OPTION_DELETEDB;
        argv[2] = srcdbname;
        argv[3] = NULL;
        retval = run_child (argv, 1, NULL, NULL, NULL, NULL);    /* deletedb */
        if (retval < 0)
        {
            strcpy (_dbmt_error, argv[0]);
            return ERR_SYSTEM_CALL;
        }
    }

  /* cmdb.pass update after delete */
  if (dbmt_user_read (&dbmt_user, _dbmt_error) != ERR_NO_ERROR)
    {
        goto copydb_finale;
    }

    dbmt_user_db_delete (&dbmt_user, destdbname);
    for (i = 0; i < dbmt_user.num_dbmt_user; i++)
    {
        int dbinfo_idx;
        T_DBMT_USER_DBINFO tmp_info;

        dbinfo_idx = dbmt_user_search (&(dbmt_user.user_info[i]), srcdbname);
        if (dbinfo_idx < 0)
            continue;
        tmp_info = dbmt_user.user_info[i].dbinfo[dbinfo_idx];
        strcpy (tmp_info.dbname, destdbname);
        if (dbmt_user_add_dbinfo (&(dbmt_user.user_info[i]), &tmp_info) != ERR_NO_ERROR)
        {
            dbmt_user_free (&dbmt_user);
            goto copydb_finale;
        }
    }
    if (move_flag)
    {
        dbmt_user_db_delete (&dbmt_user, srcdbname);
    }
    dbmt_user_write_auth (&dbmt_user, _dbmt_error);
    dbmt_user_free (&dbmt_user);

copydb_finale:
    return ERR_NO_ERROR;
}

int
ts_plandump (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char *dbname = NULL;
    char dbname_at_hostname[MAXHOSTNAMELEN + DB_NAME_LEN];
    int ha_mode = 0;
    T_DB_SERVICE_MODE db_mode;
    char cmd_name[CUBRID_CMD_NAME_LEN];
    char *plandrop = NULL;
    const char *argv[10];
    int argc = 0;
    char cubrid_err_file[PATH_MAX];
    char tmpfilepath[PATH_MAX];
    int retval = ERR_NO_ERROR;

    cubrid_err_file[0] = '\0';

    if ((dbname = nv_get_val (req, "dbname")) == NULL)
    {
        strcpy (_dbmt_error, "database name");
        return ERR_PARAM_MISSING;
    }
    plandrop = nv_get_val (req, "plandrop");

    /*
    * check the running mode of current database,
    * return error if it is DB_SERVICE_MODE_SA.
    */
    db_mode = uDatabaseMode (dbname, &ha_mode);
    if (db_mode == DB_SERVICE_MODE_SA)
    {
        sprintf (_dbmt_error, "%s", dbname);
        return ERR_STANDALONE_MODE;
    }

    cubrid_cmd_name (cmd_name);
    argv[argc++] = cmd_name;
    argv[argc++] = UTIL_OPTION_PLANDUMP;
    if (uStringEqual (plandrop, "y"))
    {
        argv[argc++] = "--" PLANDUMP_DROP_L;
    }

    if (ha_mode != 0)
    {
        append_host_to_dbname (dbname_at_hostname, dbname,
                               sizeof (dbname_at_hostname));
        argv[argc++] = dbname_at_hostname;
    }
    else
    {
        argv[argc++] = dbname;
    }

    argv[argc++] = NULL;

    snprintf (cubrid_err_file, PATH_MAX, "%s/%s.%u.err.tmp",
              sco.dbmt_tmp_dir, "plandump", getpid ());

    /*
    * create a new tmp file to record the content
    * that returned by plandump.
    */
    snprintf (tmpfilepath, PATH_MAX - 1, "%s/DBMT_task_%d.%d",
              sco.dbmt_tmp_dir, TS_PLANDUMP, (int) getpid ());

    if (run_child (argv, 1, NULL, tmpfilepath, cubrid_err_file, NULL) < 0)    /* plandump */
    {
        strcpy (_dbmt_error, argv[0]);
        retval = ERR_SYSTEM_CALL;
        goto rm_tmpfile;
    }

    if (read_error_file (cubrid_err_file, _dbmt_error, DBMT_ERROR_MSG_SIZE) < 0)
    {
        retval = ERR_WITH_MSG;
        goto rm_tmpfile;
    }

    /* add file content to response line by line. */
    nv_add_nvp (res, "open", "log");
    if (file_to_nvpairs (tmpfilepath, res) < 0)
    {
        retval = ERR_TMPFILE_OPEN_FAIL;
    }
    nv_add_nvp (res, "close", "log");

rm_tmpfile:
    unlink (tmpfilepath);
    if (access (cubrid_err_file, F_OK) == 0)
    {
        unlink (cubrid_err_file);
    }
    return retval;
}

int
ts_paramdump (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char *dbname = NULL;
    char dbname_at_hostname[MAXHOSTNAMELEN + DB_NAME_LEN];
    int ha_mode = 0;
    char *bothclientserver = NULL;
    T_DB_SERVICE_MODE db_mode;
    char cmd_name[CUBRID_CMD_NAME_LEN];
    const char *argv[10];
    int argc = 0;
    char cubrid_err_file[PATH_MAX];
    FILE *infile = NULL;
    char tmpfilepath[PATH_MAX];
    int retval = ERR_NO_ERROR;

    cubrid_err_file[0] = '\0';

    if ((dbname = nv_get_val (req, "dbname")) == NULL)
    {
        strcpy (_dbmt_error, "database name");
        return ERR_PARAM_MISSING;
    }

    /* add  both & SA & CS mode. */
    bothclientserver = nv_get_val (req, "both");

    /*
    * check the running mode of current database,
    * return error if it is DB_SERVICE_MODE_SA.
    */
    db_mode = uDatabaseMode (dbname, &ha_mode);
    if (db_mode == DB_SERVICE_MODE_SA)
    {
        sprintf (_dbmt_error, "%s", dbname);
        return ERR_STANDALONE_MODE;
    }

    cubrid_cmd_name (cmd_name);
    argv[argc++] = cmd_name;
    argv[argc++] = UTIL_OPTION_PARAMDUMP;
    if (db_mode == DB_SERVICE_MODE_NONE)
    {
        argv[argc++] = "--" PARAMDUMP_SA_MODE_L;
    }
    else
    {
        argv[argc++] = "--" PARAMDUMP_CS_MODE_L;
    }

    if (uStringEqual (bothclientserver, "y"))
    {
        argv[argc++] = "--" PARAMDUMP_BOTH_L;
    }

    if (ha_mode != 0)
    {
        append_host_to_dbname (dbname_at_hostname, dbname, sizeof (dbname_at_hostname));
        argv[argc++] = dbname_at_hostname;
    }
    else
    {
        argv[argc++] = dbname;
    }

    argv[argc++] = NULL;

    snprintf (cubrid_err_file, PATH_MAX, "%s/%s.%u.err.tmp", sco.dbmt_tmp_dir, "paramdump", getpid ());

    /*
    * create a new tmp file to record the content
    * that returned by plandump.
    */
    snprintf (tmpfilepath, PATH_MAX - 1, "%s/DBMT_task_%d.%d", sco.dbmt_tmp_dir, TS_PARAMDUMP, (int) getpid ());

    if (run_child (argv, 1, NULL, tmpfilepath, cubrid_err_file, NULL) < 0)    /* paramdump */
    {
        strcpy (_dbmt_error, argv[0]);
        retval = ERR_SYSTEM_CALL;
        goto rm_tmpfile;
    }

    if (read_error_file (cubrid_err_file, _dbmt_error, DBMT_ERROR_MSG_SIZE) < 0)
    {
        retval = ERR_WITH_MSG;
        goto rm_tmpfile;
    }

    /* add dbname to response. */
    nv_add_nvp (res, "dbname", dbname);

    if ((infile = fopen (tmpfilepath, "r")) == NULL)
    {
        retval = ERR_TMPFILE_OPEN_FAIL;
        goto rm_tmpfile;
    }

    /* add file content to response line by line. */
    if (file_to_nvp_by_separator (infile, res, '=') < 0)
    {
        const char *tmperr = "Can't parse tmpfile of paramdump.";
        strncpy (_dbmt_error, tmperr, strlen (tmperr));
        retval = ERR_WITH_MSG;
        fclose (infile);
        goto rm_tmpfile;
    }
    /* close tmp file. */
    fclose (infile);

rm_tmpfile:
    unlink (tmpfilepath);
    if (access (cubrid_err_file, F_OK) == 0)
    {
        unlink (cubrid_err_file);
    }
    return retval;
}

int
ts_optimizedb (nvplist * req, nvplist * res, char *_dbmt_error)
{
    return cm_ts_optimizedb (req, res, _dbmt_error);
}

int
ts_checkdb (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char dbname_at_hostname[MAXHOSTNAMELEN + DB_NAME_LEN];
    char cmd_name[CUBRID_CMD_NAME_LEN];
    char task_name[10];
    const char *argv[7];
    T_DB_SERVICE_MODE db_mode;

    int ha_mode = 0;
    int argc = 0;
    int retval = 0;

    char *dbname = NULL;
    char *repair_db = NULL;

    dbname_at_hostname[0] = '\0';
    cmd_name[0] = '\0';

    if ((repair_db = nv_get_val (req, "repairdb")) == NULL)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", "repairdb");
        return ERR_PARAM_MISSING;
    }

    if ((dbname = nv_get_val (req, "dbname")) == NULL)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", "dbname");
        return ERR_PARAM_MISSING;
    }
    if (_isRegisteredDB (dbname) == 0)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", dbname);
        return ERR_DB_NONEXISTANT;
    }

    db_mode = uDatabaseMode (dbname, &ha_mode);
    if (db_mode == DB_SERVICE_MODE_SA)
    {
        sprintf (_dbmt_error, "%s", dbname);
        return ERR_STANDALONE_MODE;
    }

    cubrid_cmd_name (cmd_name);
    argv[argc++] = cmd_name;
    argv[argc++] = UTIL_OPTION_CHECKDB;
    if (db_mode == DB_SERVICE_MODE_NONE)
        argv[argc++] = "--" CHECK_SA_MODE_L;
    else
        argv[argc++] = "--" CHECK_CS_MODE_L;

    if (uStringEqual (repair_db, "y"))
        argv[argc++] = "--" CHECK_REPAIR_L;

    if (ha_mode != 0)
    {
        append_host_to_dbname (dbname_at_hostname, dbname,
                               sizeof (dbname_at_hostname));
        argv[argc++] = dbname_at_hostname;
    }
    else
    {
        argv[argc++] = dbname;
    }

    argv[argc++] = NULL;

    snprintf (task_name, TASKNAME_LEN, "%s", "checkdb");
    retval = _run_child (argv, 1, task_name, NULL, _dbmt_error);

    return retval;
}

int
ts_statdump (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char *dbname;
    char dbname_at_hostname[MAXHOSTNAMELEN + DB_NAME_LEN];
    int ha_mode = 0;
    T_CM_DB_EXEC_STAT exec_stat;
    T_CM_ERROR err_buf;
    int retval = -1;
    T_DB_SERVICE_MODE db_mode;

    memset (&exec_stat, 0, sizeof (T_CM_DB_EXEC_STAT));
    memset (&err_buf, 0, sizeof (T_CM_ERROR));

    /* check the parameters of input. */
    if ((dbname = nv_get_val (req, "dbname")) == NULL)
    {
        strcpy (_dbmt_error, "dbname");
        retval = ERR_PARAM_MISSING;
        goto statdump_finale;
    }

    /* check the database mode. */
    db_mode = uDatabaseMode (dbname, &ha_mode);
    if (db_mode == DB_SERVICE_MODE_SA)
    {
        sprintf (_dbmt_error, "%s", dbname);
        retval = ERR_STANDALONE_MODE;
        goto statdump_finale;
    }

    if (ha_mode != 0)
    {
        append_host_to_dbname (dbname_at_hostname, dbname, sizeof (dbname_at_hostname));
        retval = cm_get_db_exec_stat (dbname_at_hostname, &exec_stat, &err_buf);
    }
    else
    {
        retval = cm_get_db_exec_stat (dbname, &exec_stat, &err_buf);
    }

    /* call cm_get_db_exec_stat to get stat infomation. */
    if (retval < 0)
    {
        /* return error with message if the operation is not success. */
        strcpy (_dbmt_error, err_buf.err_msg);
        retval = ERR_WITH_MSG;
        goto statdump_finale;
    }

    /* set res with parameter in exec_stat. */
    nv_add_nvp (res, "dbname", dbname);
    _add_nvp_time (res, "time", time (NULL), "%04d/%02d/%02d %02d:%02d:%02d", TIME_STR_FMT_DATE_TIME);

    /* Execution statistics for the file io */
    nv_add_nvp_int (res, "num_file_creates", exec_stat.file_num_creates);
    nv_add_nvp_int (res, "num_file_removes", exec_stat.file_num_removes);
    nv_add_nvp_int (res, "num_file_ioreads", exec_stat.file_num_ioreads);
    nv_add_nvp_int (res, "num_file_iowrites", exec_stat.file_num_iowrites);
    nv_add_nvp_int (res, "num_file_iosynches", exec_stat.file_num_iosynches);
    nv_add_nvp_int (res, "num_file_page_allocs", exec_stat.file_num_page_allocs);
    nv_add_nvp_int (res, "num_file_page_deallocs", exec_stat.file_num_page_deallocs);

    /* Execution statistics for the page buffer manager */
    nv_add_nvp_int (res, "num_data_page_fetches", exec_stat.pb_num_fetches);
    nv_add_nvp_int (res, "num_data_page_dirties", exec_stat.pb_num_dirties);
    nv_add_nvp_int (res, "num_data_page_ioreads", exec_stat.pb_num_ioreads);
    nv_add_nvp_int (res, "num_data_page_iowrites", exec_stat.pb_num_iowrites);
    nv_add_nvp_int (res, "num_data_page_victims", exec_stat.pb_num_victims);
    nv_add_nvp_int (res, "num_data_page_iowrites_for_replacement", exec_stat.pb_num_replacements);

    /* Execution statistics for the log manager */
    nv_add_nvp_int (res, "num_log_page_ioreads", exec_stat.log_num_ioreads);
    nv_add_nvp_int (res, "num_log_page_iowrites", exec_stat.log_num_iowrites);
    nv_add_nvp_int (res, "num_log_append_records", exec_stat.log_num_appendrecs);
    nv_add_nvp_int (res, "num_log_archives", exec_stat.log_num_archives);
#if 0                //no use
    nv_add_nvp_int (res, "num_log_start_checkpoints", exec_stat.log_num_start_checkpoints);
    nv_add_nvp_int (res, "num_log_end_checkpoints", exec_stat.log_num_end_checkpoints);
#endif
    nv_add_nvp_int (res, "num_log_wals", exec_stat.log_num_wals);

    /* Execution statistics for the lock manager */
    nv_add_nvp_int (res, "num_page_locks_acquired", exec_stat.lk_num_acquired_on_pages);
    nv_add_nvp_int (res, "num_object_locks_acquired", exec_stat.lk_num_acquired_on_objects);
    nv_add_nvp_int (res, "num_page_locks_converted", exec_stat.lk_num_converted_on_pages);
    nv_add_nvp_int (res, "num_object_locks_converted", exec_stat.lk_num_converted_on_objects);
    nv_add_nvp_int (res, "num_page_locks_re_requested", exec_stat.lk_num_re_requested_on_pages);
    nv_add_nvp_int (res, "num_object_locks_re_requested", exec_stat.lk_num_re_requested_on_objects);
    nv_add_nvp_int (res, "num_page_locks_waits", exec_stat.lk_num_waited_on_pages);
    nv_add_nvp_int (res, "num_object_locks_waits", exec_stat.lk_num_waited_on_objects);

    /* Execution statistics for transactions */
    nv_add_nvp_int (res, "num_tran_commits", exec_stat.tran_num_commits);
    nv_add_nvp_int (res, "num_tran_rollbacks", exec_stat.tran_num_rollbacks);
    nv_add_nvp_int (res, "num_tran_savepoints", exec_stat.tran_num_savepoints);
    nv_add_nvp_int (res, "num_tran_start_topops", exec_stat.tran_num_start_topops);
    nv_add_nvp_int (res, "num_tran_end_topops", exec_stat.tran_num_end_topops);
    nv_add_nvp_int (res, "num_tran_interrupts", exec_stat.tran_num_interrupts);

    /* Execution statistics for the btree manager */
    nv_add_nvp_int (res, "num_btree_inserts", exec_stat.bt_num_inserts);
    nv_add_nvp_int (res, "num_btree_deletes", exec_stat.bt_num_deletes);
    nv_add_nvp_int (res, "num_btree_updates", exec_stat.bt_num_updates);
    nv_add_nvp_int (res, "num_btree_covered", exec_stat.bt_num_covered);
    nv_add_nvp_int (res, "num_btree_noncovered", exec_stat.bt_num_noncovered);
    nv_add_nvp_int (res, "num_btree_resumes", exec_stat.bt_num_resumes);
    nv_add_nvp_int (res, "num_btree_multirange_optimization", exec_stat.bt_num_multi_range_opt);
    nv_add_nvp_int (res, "num_btree_splits", exec_stat.bt_num_splits);
    nv_add_nvp_int (res, "num_btree_merges", exec_stat.bt_num_merges);
    nv_add_nvp_int (res, "num_btree_get_stats", exec_stat.bt_num_get_stats);

    /* Execution statistics for the query manager */
    nv_add_nvp_int (res, "num_query_selects", exec_stat.qm_num_selects);
    nv_add_nvp_int (res, "num_query_inserts", exec_stat.qm_num_inserts);
    nv_add_nvp_int (res, "num_query_deletes", exec_stat.qm_num_deletes);
    nv_add_nvp_int (res, "num_query_updates", exec_stat.qm_num_updates);
    nv_add_nvp_int (res, "num_query_sscans", exec_stat.qm_num_sscans);
    nv_add_nvp_int (res, "num_query_iscans", exec_stat.qm_num_iscans);
    nv_add_nvp_int (res, "num_query_lscans", exec_stat.qm_num_lscans);
    nv_add_nvp_int (res, "num_query_setscans", exec_stat.qm_num_setscans);
    nv_add_nvp_int (res, "num_query_methscans", exec_stat.qm_num_methscans);
    nv_add_nvp_int (res, "num_query_nljoins", exec_stat.qm_num_nljoins);
    nv_add_nvp_int (res, "num_query_mjoins", exec_stat.qm_num_mjoins);
    nv_add_nvp_int (res, "num_query_objfetches", exec_stat.qm_num_objfetches);
    nv_add_nvp_int (res, "num_query_holdable_cursors", exec_stat.qm_num_holdable_cursors);

    /* Execution statistics for external sort */
    nv_add_nvp_int (res, "num_sort_io_pages", exec_stat.sort_num_io_pages);
    nv_add_nvp_int (res, "num_sort_data_pages", exec_stat.sort_num_data_pages);

    /* Execution statistics for network communication */
    nv_add_nvp_int (res, "num_network_requests", exec_stat.net_num_requests);

    /* flush control stat */
    nv_add_nvp_int (res, "num_adaptive_flush_pages", exec_stat.fc_num_pages);
    nv_add_nvp_int (res, "num_adaptive_flush_log_pages", exec_stat.fc_num_log_pages);
    nv_add_nvp_int (res, "num_adaptive_flush_max_pages", exec_stat.fc_tokens);

    /* prior lsa info */
    nv_add_nvp_int (res, "num_prior_lsa_list_size", exec_stat.prior_lsa_list_size);
    nv_add_nvp_int (res, "num_prior_lsa_list_maxed", exec_stat.prior_lsa_list_maxed);
    nv_add_nvp_int (res, "num_prior_lsa_list_removed", exec_stat.prior_lsa_list_removed);

    /* best space info */
    nv_add_nvp_int (res, "num_heap_stats_bestspace_entries", exec_stat.hf_stats_bestspace_entries);
    nv_add_nvp_int (res, "num_heap_stats_bestspace_maxed", exec_stat.hf_stats_bestspace_maxed);

    /* HA replication delay */
    nv_add_nvp_int (res, "time_ha_replication_delay", exec_stat.ha_repl_delay);

    /* Execution statistics for Plan cache */
    nv_add_nvp_int (res, "num_plan_cache_add", exec_stat.pc_num_add);
    nv_add_nvp_int (res, "num_plan_cache_lookup", exec_stat.pc_num_lookup);
    nv_add_nvp_int (res, "num_plan_cache_hit", exec_stat.pc_num_hit);
    nv_add_nvp_int (res, "num_plan_cache_miss", exec_stat.pc_num_miss);
    nv_add_nvp_int (res, "num_plan_cache_full", exec_stat.pc_num_full);
    nv_add_nvp_int (res, "num_plan_cache_delete", exec_stat.pc_num_delete);
    nv_add_nvp_int (res, "num_plan_cache_invalid_xasl_id", exec_stat.pc_num_invalid_xasl_id);
    nv_add_nvp_int (res, "num_plan_cache_query_string_hash_entries", exec_stat.pc_num_query_string_hash_entries);
    nv_add_nvp_int (res, "num_plan_cache_xasl_id_hash_entries", exec_stat.pc_num_xasl_id_hash_entries);
    nv_add_nvp_int (res, "num_plan_cache_class_oid_hash_entries", exec_stat.pc_num_class_oid_hash_entries);

    /* Other statistics */
    nv_add_nvp_int (res, "data_page_buffer_hit_ratio", exec_stat.pb_hit_ratio);

    retval = ERR_NO_ERROR;

statdump_finale:
    return retval;
}

int
ts_compactdb (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char cmd_name[CUBRID_CMD_NAME_LEN];
    char out_file[PATH_MAX];
    char err_file[PATH_MAX];

    const char *argv[10];
    T_DB_SERVICE_MODE db_mode;

    int exit_code = 0;
    int argc = 0;
    int retval = ERR_NO_ERROR;
    int createtmpfile = 0;

    char *dbname = NULL;
    char *verbose = NULL;

    cmd_name[0] = '\0';
    out_file[0] = '\0';
    err_file[0] = '\0';

    dbname = nv_get_val (req, "dbname");
    if (dbname == NULL)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", "dbname");
        return ERR_PARAM_MISSING;
    }
    if (_isRegisteredDB (dbname) == 0)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", dbname);
        return ERR_DB_NONEXISTANT;
    }

    verbose = nv_get_val (req, "verbose");
    if (verbose == NULL)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", "verbose");
        return ERR_PARAM_MISSING;
    }

    db_mode = uDatabaseMode (dbname, NULL);
    if (db_mode == DB_SERVICE_MODE_SA)
    {
        sprintf (_dbmt_error, "%s", dbname);
        return ERR_STANDALONE_MODE;
    }

    cubrid_cmd_name (cmd_name);
    argv[argc++] = cmd_name;
    argv[argc++] = UTIL_OPTION_COMPACTDB;
    if (uStringEqual (verbose, "y"))
    {
        argv[argc++] = "--" COMPACT_VERBOSE_L;
        createtmpfile = 1;
    }

    if (db_mode == DB_SERVICE_MODE_CS)
    {
        argv[argc++] = "--" COMPACT_CS_MODE_L;
    }
    else if (db_mode == DB_SERVICE_MODE_NONE)
    {
        argv[argc++] = "--" COMPACT_SA_MODE_L;
    }

    argv[argc++] = dbname;
    argv[argc++] = NULL;

    if (createtmpfile != 0)
    {
        snprintf (out_file, PATH_MAX, "%s/DBMT_task_%d.%d",
                  sco.dbmt_tmp_dir, TS_COMPACTDB, (int) getpid ());
    }
    else
    {
        snprintf (out_file, PATH_MAX, "%s/%s.%u.out.tmp",
                  sco.dbmt_tmp_dir, "compactdb", getpid ());
    }

    snprintf (err_file, PATH_MAX, "%s/%s.%u.err.tmp",
              sco.dbmt_tmp_dir, "compactdb", getpid ());

    if (run_child (argv, 1, NULL, out_file, err_file, &exit_code) < 0)
    {                /* compactdb */
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", argv[0]);
        retval = ERR_SYSTEM_CALL;
        goto rm_tmpfile;
    }

    if (read_error_file (err_file, _dbmt_error, DBMT_ERROR_MSG_SIZE) < 0)
    {
        retval = ERR_WITH_MSG;
        goto rm_tmpfile;
    }

    if (exit_code != EXIT_SUCCESS)
    {
        read_stdout_stderr_as_err (out_file, NULL, _dbmt_error);
        retval = ERR_WITH_MSG;
        goto rm_tmpfile;
    }

    if (createtmpfile != 0)
    {
        nv_add_nvp (res, "open", "log");
        /* add file content to response line by line. */
        if (file_to_nvpairs (out_file, res) < 0)
        {
            retval = ERR_TMPFILE_OPEN_FAIL;
        }
        nv_add_nvp (res, "close", "log");
    }

rm_tmpfile:
    unlink (out_file);
    unlink (err_file);
    return retval;
}

int
ts_backupdb (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char *dbname, *level, *removelog, *volname, *backupdir, *check;
    char dbname_at_hostname[MAXHOSTNAMELEN + DB_NAME_LEN];
    int ha_mode = 0;
    char *mt, *zip, *safe_replication;
    char backupfilepath[PATH_MAX];
    char inputfilepath[PATH_MAX];
    char cmd_name[CUBRID_CMD_NAME_LEN];
    char sp_option[256];
    const char *argv[16];
    int argc = 0;
    FILE *inputfile;
    T_DB_SERVICE_MODE db_mode;
    char cubrid_err_file[PATH_MAX];

    cubrid_err_file[0] = '\0';

    if ((dbname = nv_get_val (req, "dbname")) == NULL)
    {
        strcpy (_dbmt_error, "database name");
        return ERR_PARAM_MISSING;
    }

    db_mode = uDatabaseMode (dbname, &ha_mode);
    if (db_mode == DB_SERVICE_MODE_SA)
    {
        sprintf (_dbmt_error, "%s", dbname);
        return ERR_STANDALONE_MODE;
    }
    level = nv_get_val (req, "level");
    volname = nv_get_val (req, "volname");
    backupdir = nv_get_val (req, "backupdir");
    removelog = nv_get_val (req, "removelog");
    check = nv_get_val (req, "check");
    mt = nv_get_val (req, "mt");
    zip = nv_get_val (req, "zip");
    safe_replication = nv_get_val (req, "safereplication");

    if (backupdir == NULL)
    {
        strcpy (_dbmt_error, "backupdir");
        return ERR_PARAM_MISSING;
    }

    snprintf (backupfilepath, PATH_MAX - 1, "%s/%s", backupdir, volname);

    /* create directory */
    if (access (backupfilepath, F_OK) < 0)
    {
        if (uCreateDir (backupfilepath) != ERR_NO_ERROR)
        {
            strcpy (_dbmt_error, backupfilepath);
            return ERR_DIR_CREATE_FAIL;
        }
    }

    cubrid_cmd_name (cmd_name);
    argv[argc++] = cmd_name;
    argv[argc++] = UTIL_OPTION_BACKUPDB;
    if (db_mode == DB_SERVICE_MODE_NONE)
        argv[argc++] = "--" BACKUP_SA_MODE_L;
    else
        argv[argc++] = "--" BACKUP_CS_MODE_L;
    argv[argc++] = "--" BACKUP_LEVEL_L;
    argv[argc++] = level;
    argv[argc++] = "--" BACKUP_DESTINATION_PATH_L;
    argv[argc++] = backupfilepath;
    if (uStringEqual (removelog, "y"))
        argv[argc++] = "--" BACKUP_REMOVE_ARCHIVE_L;
    if (uStringEqual (check, "n"))
        argv[argc++] = "--" BACKUP_NO_CHECK_L;
    if (mt != NULL)
    {
        argv[argc++] = "--" BACKUP_THREAD_COUNT_L;
        argv[argc++] = mt;
    }
    if (zip != NULL && uStringEqual (zip, "y"))
    {
        argv[argc++] = "--" BACKUP_COMPRESS_L;
    }

    if (safe_replication != NULL && uStringEqual (safe_replication, "y"))
    {
        snprintf (sp_option, sizeof (sp_option) - 1,
                  "--safe-page-id `repl_safe_page %s`", dbname);
        argv[argc++] = sp_option;
    }

    if (ha_mode != 0)
    {
        append_host_to_dbname (dbname_at_hostname, dbname,
                               sizeof (dbname_at_hostname));
        argv[argc++] = dbname_at_hostname;
    }
    else
    {
        argv[argc++] = dbname;
    }

    argv[argc++] = NULL;

    snprintf (inputfilepath, PATH_MAX - 1, "%s/DBMT_task_%d.%d",
              sco.dbmt_tmp_dir, TS_BACKUPDB, (int) getpid ());
    inputfile = fopen (inputfilepath, "w");
    if (inputfile)
    {
        fprintf (inputfile, "y");
        fclose (inputfile);
    }
    else
    {
        return ERR_FILE_OPEN_FAIL;
    }

    snprintf (cubrid_err_file, PATH_MAX, "%s/%s.%u.err.tmp",
              sco.dbmt_tmp_dir, "backupdb", getpid ());

    if (run_child (argv, 1, inputfilepath, NULL, cubrid_err_file, NULL) < 0)
    {                /* backupdb */
        strcpy (_dbmt_error, argv[0]);
        unlink (inputfilepath);
        if (access (cubrid_err_file, F_OK) == 0)
        {
            unlink (cubrid_err_file);
        }
        return ERR_SYSTEM_CALL;
    }

    unlink (inputfilepath);

    if (read_error_file (cubrid_err_file, _dbmt_error, DBMT_ERROR_MSG_SIZE) < 0)
    {
        if (access (cubrid_err_file, F_OK) == 0)
        {
            unlink (cubrid_err_file);
        }
        return ERR_WITH_MSG;
    }

    if (access (cubrid_err_file, F_OK) == 0)
    {
        unlink (cubrid_err_file);
    }
    return ERR_NO_ERROR;
}

int
ts_unloaddb (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char *dbname, *targetdir, *usehash, *hashdir, *target, *s1, *s2,
    *ref, *classonly, *delimit, *estimate, *prefix, *cach, *lofile,
    buf[PATH_MAX], infofile[PATH_MAX], tmpfile[PATH_MAX], temp[PATH_MAX],
    n[256], v[256], cname[256], p1[64], p2[8], p3[8];

    char dbname_at_hostname[MAXHOSTNAMELEN + DB_NAME_LEN];
    int ha_mode = 0;
    char cmd_name[CUBRID_CMD_NAME_LEN];
    char cubrid_err_file[PATH_MAX];
    FILE *infile, *outfile;
    int i, flag = 0, no_class = 0, index_exist = 0, trigger_exist = 0;
    struct stat statbuf;
    const char *argv[30];
    int argc = 0;
    T_DB_SERVICE_MODE db_mode;
    char fullpath[PATH_MAX];
    char dba_user[32] = "dba";
    char *dbuser = NULL;
    char *dbpasswd = NULL;

    cubrid_err_file[0] = '\0';

    dbname = nv_get_val (req, "dbname");
    if (dbname == NULL)
    {
        strcpy (_dbmt_error, "database name");
        return ERR_PARAM_MISSING;
    }

    targetdir = nv_get_val (req, "targetdir");
    usehash = nv_get_val (req, "usehash");
    hashdir = nv_get_val (req, "hashdir");
    target = nv_get_val (req, "target");
    ref = nv_get_val (req, "ref");
    classonly = nv_get_val (req, "classonly");
    delimit = nv_get_val (req, "delimit");
    estimate = nv_get_val (req, "estimate");
    prefix = nv_get_val (req, "prefix");
    cach = nv_get_val (req, "cach");
    lofile = nv_get_val (req, "lofile");
    dbuser = nv_get_val (req, "dbuser");
    dbpasswd = nv_get_val (req, "dbpasswd");

    if (target == NULL)
    {
        strcpy (_dbmt_error, "target");
        return ERR_PARAM_MISSING;
    }

    db_mode = uDatabaseMode (dbname, &ha_mode);
    if (db_mode == DB_SERVICE_MODE_SA)
    {
        sprintf (_dbmt_error, "%s", dbname);
        return ERR_STANDALONE_MODE;
    }

    if (targetdir == NULL)
    {
        strcpy (_dbmt_error, "targetdir");
        return ERR_PARAM_MISSING;
    }

    if (strcmp (targetdir, "+D") == 0)
    {
        snprintf (fullpath, sizeof (fullpath) - 1, "%s/files/", sco.szCWMPath);
    }
    else
    {
        snprintf (fullpath, sizeof (fullpath) - 1, "%s", targetdir);
    }

    if (access (fullpath, F_OK) < 0)
    {
        if (uCreateDir (fullpath) != ERR_NO_ERROR)
        {
            strcpy (_dbmt_error, targetdir);
            return ERR_DIR_CREATE_FAIL;
        }
    }

    /* Verify password for dbuser */
    if (dbuser == NULL)
    {
        dbuser = dba_user;
    }
    if (_verify_user_passwd (dbname, dbuser, dbpasswd, _dbmt_error) != ERR_NO_ERROR)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE,
                  "Invalid password or missing password for database(%s): dbuser(%s).", dbname, dbuser);
        return ERR_WITH_MSG;
    }
    /* makeup upload class list file */
    snprintf (tmpfile, PATH_MAX - 1, "%s/DBMT_task_101.%d", sco.dbmt_tmp_dir, (int) getpid ());
    if ((outfile = fopen (tmpfile, "w")) == NULL)
    {
        return ERR_TMPFILE_OPEN_FAIL;
    }
    for (i = 0; i < req->nvplist_leng; i++)
    {
        nv_lookup (req, i, &s1, &s2);
        if (s1 == NULL)
        {
            continue;
        }

        if (!strcmp (s1, "open"))
        {
            flag = 1;
        }
        else if (!strcmp (s1, "close"))
        {
            flag = 0;
        }
        else if (flag == 1 && !strcmp (s1, "classname"))
        {
            snprintf (buf, sizeof (buf) - 1, "%s\n", s2);
            fputs (buf, outfile);
            no_class++;
        }
    }
    fclose (outfile);

    /* makeup command and execute */
    cubrid_cmd_name (cmd_name);
    argv[argc++] = cmd_name;
    argv[argc++] = UTIL_OPTION_UNLOADDB;
    if (db_mode == DB_SERVICE_MODE_NONE)
        argv[argc++] = "--" UNLOAD_SA_MODE_L;
    else
        argv[argc++] = "--" UNLOAD_CS_MODE_L;
    if (no_class > 0)
    {
        argv[argc++] = "--" UNLOAD_INPUT_CLASS_FILE_L;
        argv[argc++] = tmpfile;
    }
    argv[argc++] = "--" UNLOAD_OUTPUT_PATH_L;
    argv[argc++] = fullpath;
    if ((usehash != NULL) && (strcmp (usehash, "yes") == 0))
    {
        argv[argc++] = "--" UNLOAD_HASH_FILE_L;
        argv[argc++] = hashdir;
    }

    if (strcmp (target, "both") == 0)
    {
        argv[argc++] = "--" UNLOAD_SCHEMA_ONLY_L;
        argv[argc++] = "--" UNLOAD_DATA_ONLY_L;
    }
    else if (strcmp (target, "schema") == 0)
    {
        argv[argc++] = "--" UNLOAD_SCHEMA_ONLY_L;
    }
    else if (strcmp (target, "object") == 0)
    {
        argv[argc++] = "--" UNLOAD_DATA_ONLY_L;
    }

    if (uStringEqual (ref, "yes"))
        argv[argc++] = "--" UNLOAD_INCLUDE_REFERENCE_L;
    if (uStringEqual (classonly, "yes"))
        argv[argc++] = "--" UNLOAD_INPUT_CLASS_ONLY_L;
    if (uStringEqual (delimit, "yes"))
        argv[argc++] = "--" UNLOAD_USE_DELIMITER_L;
    if (estimate != NULL && !uStringEqual (estimate, "none"))
    {
        argv[argc++] = "--" UNLOAD_ESTIMATED_SIZE_L;
        argv[argc++] = estimate;
    }
    if (prefix != NULL && !uStringEqual (prefix, "none"))
    {
        argv[argc++] = "--" UNLOAD_OUTPUT_PREFIX_L;
        argv[argc++] = prefix;
    }
    if (cach != NULL && !uStringEqual (cach, "none"))
    {
        argv[argc++] = "--" UNLOAD_CACHED_PAGES_L;
        argv[argc++] = cach;
    }
    if (lofile != NULL && !uStringEqual (lofile, "none"))
    {
        argv[argc++] = "--" UNLOAD_LO_COUNT_L;
        argv[argc++] = lofile;
    }

    if (ha_mode != 0)
    {
        append_host_to_dbname (dbname_at_hostname, dbname,
                               sizeof (dbname_at_hostname));
        argv[argc++] = dbname_at_hostname;
    }
    else
    {
        argv[argc++] = dbname;
    }

    argv[argc++] = "--" UNLOAD_USER_L;
    argv[argc++] = dbuser;

    if (dbpasswd != NULL)
    {
        argv[argc++] = "--" UNLOAD_PASSWORD_L;
        argv[argc++] = dbpasswd;
    }

    argv[argc++] = NULL;

    snprintf (cubrid_err_file, PATH_MAX, "%s/%s.%u.err.tmp",
              sco.dbmt_tmp_dir, "unloaddb", getpid ());

    if (run_child (argv, 1, NULL, NULL, cubrid_err_file, NULL) < 0)
    {                /* unloaddb */
        strcpy (_dbmt_error, argv[0]);
        unlink (tmpfile);
        if (access (cubrid_err_file, F_OK) == 0)
        {
            unlink (cubrid_err_file);
        }
        return ERR_SYSTEM_CALL;
    }

    if (read_error_file (cubrid_err_file, _dbmt_error, DBMT_ERROR_MSG_SIZE) < 0)
    {
        unlink (tmpfile);
        if (access (cubrid_err_file, F_OK) == 0)
        {
            unlink (cubrid_err_file);
        }
        return ERR_WITH_MSG;
    }
    if (access (cubrid_err_file, F_OK) == 0)
    {
        unlink (cubrid_err_file);
    }
    unlink (tmpfile);

    /* makeup upload result information in unload.log file */
    snprintf (buf, sizeof (buf) - 1, "%s_unloaddb.log", dbname);
    nv_add_nvp (res, "open", "result");
    if ((infile = fopen (buf, "rt")) != NULL)
    {
        flag = 0;
        while (fgets (buf, sizeof (buf), infile))
        {
            if (buf[0] == '-')
            {
                flag++;
            }
            else if (flag == 2 &&
                sscanf (buf, "%255s %*s %63s %7s %*s %7s", cname, p1, p2, p3) == 4)
            {
                snprintf (buf, sizeof (buf) - 1, "%s %s/%s", p1, p2, p3);
                nv_add_nvp (res, cname, buf);
            }
        }
        fclose (infile);
    }
    nv_add_nvp (res, "close", "result");
    unlink ("unload.log");

    /* save uploaded result file to 'unloaddb.info' file */
    flag = 0;
    snprintf (infofile, PATH_MAX - 1, "%s/unloaddb.info",
    sco.szCubrid_databases);
    if ((infile = fopen (infofile, "rt")) == NULL)
    {
        outfile = fopen (infofile, "w");
        if (outfile == NULL)
        {
            strcpy (_dbmt_error, infofile);
            return ERR_FILE_OPEN_FAIL;
        }

        snprintf (buf, sizeof (buf) - 1, "%% %s\n", dbname);
        fputs (buf, outfile);

        if (!strcmp (target, "both"))
        {
            fprintf (outfile, "schema %s/%s%s\n", targetdir, dbname,
                     CUBRID_UNLOAD_EXT_SCHEMA);
            fprintf (outfile, "object %s/%s%s\n", targetdir, dbname,
                     CUBRID_UNLOAD_EXT_OBJ);
        }
        else if (!strcmp (target, "schema"))
        {
            fprintf (outfile, "schema %s/%s%s\n", targetdir, dbname,
                     CUBRID_UNLOAD_EXT_SCHEMA);
        }
        else if (!strcmp (target, "object"))
        {
            fprintf (outfile, "object %s/%s%s\n", targetdir, dbname,
                     CUBRID_UNLOAD_EXT_OBJ);
        }

        /* check index file and append if exist */
        snprintf (buf, sizeof (buf) - 1, "%s/%s%s", targetdir, dbname,
                  CUBRID_UNLOAD_EXT_INDEX);
        if (stat (buf, &statbuf) == 0)
        {
            fprintf (outfile, "index %s/%s%s\n", targetdir, dbname,
                     CUBRID_UNLOAD_EXT_INDEX);
        }
        /* check trigger file and append if exist */
        snprintf (buf, sizeof (buf) - 1, "%s/%s%s", targetdir, dbname,
                  CUBRID_UNLOAD_EXT_TRIGGER);
        if (stat (buf, &statbuf) == 0)
        {
            fprintf (outfile, "trigger %s/%s%s\n", targetdir, dbname,
                     CUBRID_UNLOAD_EXT_TRIGGER);
        }
        fclose (outfile);
    }
    else
    {
        snprintf (tmpfile, PATH_MAX - 1, "%s/DBMT_task_102.%d",
                  sco.dbmt_tmp_dir, (int) getpid ());
        outfile = fopen (tmpfile, "w");
        if (outfile == NULL)
        {
            fclose (infile);
            strcpy (_dbmt_error, tmpfile);
            return ERR_TMPFILE_OPEN_FAIL;
        }

        while (fgets (buf, sizeof (buf), infile))
        {
            if (sscanf (buf, "%255s %255s", n, v) != 2)
            {
                fputs (buf, outfile);
                continue;
            }
            if (!strcmp (n, "%") && !strcmp (v, dbname))
            {
                fputs (buf, outfile);

                if (!strcmp (target, "both"))
                {
                    fprintf (outfile, "schema %s/%s%s\n", targetdir, dbname,
                             CUBRID_UNLOAD_EXT_SCHEMA);
                    fprintf (outfile, "object %s/%s%s\n", targetdir, dbname,
                             CUBRID_UNLOAD_EXT_OBJ);
                }
                else if (!strcmp (target, "schema"))
                {
                    fprintf (outfile, "schema %s/%s%s\n", targetdir, dbname,
                             CUBRID_UNLOAD_EXT_SCHEMA);
                }
                else if (!strcmp (target, "object"))
                {
                    fprintf (outfile, "object %s/%s%s\n", targetdir, dbname,
                             CUBRID_UNLOAD_EXT_OBJ);
                }

                /* check index file and append if exist */
                snprintf (temp, PATH_MAX - 1, "%s/%s%s", targetdir, dbname,
                          CUBRID_UNLOAD_EXT_INDEX);
                if (stat (temp, &statbuf) == 0)
                {
                    fprintf (outfile, "index %s/%s%s\n", targetdir, dbname,
                             CUBRID_UNLOAD_EXT_INDEX);
                    index_exist = 1;
                }
                /* check trigger file and append if exist */
                snprintf (temp, PATH_MAX - 1, "%s/%s%s", targetdir, dbname,
                          CUBRID_UNLOAD_EXT_TRIGGER);
                if (stat (temp, &statbuf) == 0)
                {
                    fprintf (outfile, "trigger %s/%s%s\n", targetdir, dbname,
                             CUBRID_UNLOAD_EXT_TRIGGER);
                    trigger_exist = 1;
                }
                flag = 1;
                continue;
            }
            if (!strcmp (target, "both") || !strcmp (target, "schema"))
            {
                snprintf (temp, PATH_MAX - 1, "%s/%s%s", targetdir, dbname,
                          CUBRID_UNLOAD_EXT_SCHEMA);
                if (!strcmp (n, "schema") && !strcmp (v, temp))
                    continue;
            }
            if (!strcmp (target, "both") || !strcmp (target, "object"))
            {
                snprintf (temp, PATH_MAX - 1, "%s/%s%s", targetdir, dbname,
                          CUBRID_UNLOAD_EXT_OBJ);
                if (!strcmp (n, "object") && !strcmp (v, temp))
                    continue;
            }
            if (index_exist)
            {
                snprintf (temp, PATH_MAX - 1, "%s/%s%s", targetdir, dbname,
                          CUBRID_UNLOAD_EXT_INDEX);
                if (!strcmp (n, "index") && !strcmp (v, temp))
                    continue;
            }
            if (trigger_exist)
            {
                snprintf (temp, PATH_MAX - 1, "%s/%s%s", targetdir, dbname,
                          CUBRID_UNLOAD_EXT_TRIGGER);
                if (!strcmp (n, "trigger") && !strcmp (v, temp))
                    continue;
            }
            fputs (buf, outfile);
        }            /* end of while(fgets()) */
        if (flag == 0)
        {
            fprintf (outfile, "%% %s\n", dbname);
            if (!strcmp (target, "both"))
            {
                fprintf (outfile, "schema %s/%s%s\n", targetdir, dbname,
                         CUBRID_UNLOAD_EXT_SCHEMA);
                fprintf (outfile, "object %s/%s%s\n", targetdir, dbname,
                         CUBRID_UNLOAD_EXT_OBJ);
            }
            else if (!strcmp (target, "schema"))
            {
                fprintf (outfile, "schema %s/%s%s\n", targetdir, dbname,
                         CUBRID_UNLOAD_EXT_SCHEMA);
            }
            else if (!strcmp (target, "object"))
            {
                fprintf (outfile, "object %s/%s%s\n", targetdir, dbname,
                         CUBRID_UNLOAD_EXT_OBJ);
            }
            /* check index file and append if exist */
            snprintf (temp, PATH_MAX - 1, "%s/%s%s", targetdir, dbname,
                      CUBRID_UNLOAD_EXT_INDEX);
            if (stat (temp, &statbuf) == 0)
            {
                fprintf (outfile, "index %s/%s%s\n", targetdir, dbname,
                         CUBRID_UNLOAD_EXT_INDEX);
                index_exist = 1;
            }
            /* check trigger file and append if exist */
            snprintf (temp, PATH_MAX - 1, "%s/%s%s", targetdir, dbname,
                      CUBRID_UNLOAD_EXT_TRIGGER);
            if (stat (temp, &statbuf) == 0)
            {
                fprintf (outfile, "trigger %s/%s%s\n", targetdir, dbname,
                         CUBRID_UNLOAD_EXT_TRIGGER);
                trigger_exist = 1;
            }
        }
        fclose (infile);
        fclose (outfile);

        /* copyback */
        infile = fopen (tmpfile, "rt");
        if (infile == NULL)
        {
            strcpy (_dbmt_error, tmpfile);
            return ERR_TMPFILE_OPEN_FAIL;
        }

        outfile = fopen (infofile, "w");
        if (outfile == NULL)
        {
            strcpy (_dbmt_error, infofile);
            fclose (infile);
            return ERR_FILE_OPEN_FAIL;
        }

        while (fgets (buf, sizeof (buf), infile))
        {
            fputs (buf, outfile);
        }
        fclose (infile);
        fclose (outfile);
        unlink (tmpfile);
    }                /* end of if */

    return ERR_NO_ERROR;
}

int
ts_loaddb (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char *dbname, *checkoption, *period, *user, *schema, *object, *index,
    *error_control_file, *ignore_class_file, *estimated, *oiduse, *nolog,
    *statisticsuse, tmpfile[PATH_MAX];

    T_DB_SERVICE_MODE db_mode;
    char *dbuser, *dbpasswd;
    char cubrid_err_file[PATH_MAX];
    int retval;
    char cmd_name[CUBRID_CMD_NAME_LEN];
    const char *argv[32];
    int argc = 0;

    cubrid_err_file[0] = '\0';

    if ((dbname = nv_get_val (req, "_DBNAME")) == NULL)
    {
        sprintf (_dbmt_error, "%s", "database name");
        return ERR_PARAM_MISSING;
    }

    dbuser = nv_get_val (req, "_DBID");
    dbpasswd = nv_get_val (req, "_DBPASSWD");
    checkoption = nv_get_val (req, "checkoption");
    period = nv_get_val (req, "period");
    user = nv_get_val (req, "user");
    schema = nv_get_val (req, "schema");
    object = nv_get_val (req, "object");
    index = nv_get_val (req, "index");
    error_control_file = nv_get_val (req, "errorcontrolfile");
    ignore_class_file = nv_get_val (req, "ignoreclassfile");
#if 0                /* will be added */
    trigger = nv_get_val (req, "trigger");
#endif
    estimated = nv_get_val (req, "estimated");
    oiduse = nv_get_val (req, "oiduse");
    nolog = nv_get_val (req, "nolog");
    statisticsuse = nv_get_val (req, "statisticsuse");

    db_mode = uDatabaseMode (dbname, NULL);
    if (db_mode == DB_SERVICE_MODE_SA)
    {
        sprintf (_dbmt_error, "%s", dbname);
        return ERR_STANDALONE_MODE;
    }
    else if (db_mode == DB_SERVICE_MODE_CS)
    {
        sprintf (_dbmt_error, "%s", dbname);
        return ERR_DB_ACTIVE;
    }

    snprintf (tmpfile, PATH_MAX - 1, "%s/DBMT_task_%d.%d", sco.dbmt_tmp_dir,
              TS_LOADDB, (int) getpid ());
    cubrid_cmd_name (cmd_name);

    argc = 0;
    argv[argc++] = cmd_name;
    argv[argc++] = UTIL_OPTION_LOADDB;

    if (checkoption != NULL)
    {
        if (strcmp (checkoption, "syntax") == 0)
        {
            argv[argc++] = "--" LOAD_CHECK_ONLY_L;
        }
        else if (strcmp (checkoption, "load") == 0)
        {
            argv[argc++] = "--" LOAD_LOAD_ONLY_L;
        }
    }

    if (dbuser)
    {
        argv[argc++] = "--" LOAD_USER_L;
        argv[argc++] = dbuser;
        if (dbpasswd)
        {
            argv[argc++] = "--" LOAD_PASSWORD_L;
            argv[argc++] = dbpasswd;
        }
    }

    /*    argv[argc++] = "-v"; */
    if (period != NULL && !uStringEqual (period, "none"))
    {
        argv[argc++] = "--" LOAD_PERIODIC_COMMIT_L;
        argv[argc++] = period;
    }

    if ((schema != NULL) && (strcmp (schema, "none") != 0))
    {
        argv[argc++] = "--" LOAD_SCHEMA_FILE_L;
        argv[argc++] = schema;
    }

    if ((object != NULL) && (strcmp (object, "none") != 0))
    {
        argv[argc++] = "--" LOAD_DATA_FILE_L;
        argv[argc++] = object;
    }

    if ((index != NULL) && (strcmp (index, "none") != 0))
    {
        argv[argc++] = "--" LOAD_INDEX_FILE_L;
        argv[argc++] = index;
    }

#if 0                /* will be added */
    if (trigger != NULL && !uStringEqual (trigger, "none"))
    {
        argv[argc++] = "-tf";
        argv[argc++] = trigger;
    }
#endif

    if (estimated != NULL && !uStringEqual (estimated, "none"))
    {
        argv[argc++] = "--" LOAD_ESTIMATED_SIZE_L;
        argv[argc++] = estimated;
    }

    if (uStringEqual (oiduse, "no"))
        argv[argc++] = "--" LOAD_NO_OID_L;

    if (uStringEqual (statisticsuse, "no"))
        argv[argc++] = "--" LOAD_NO_STATISTICS_L;

    if (uStringEqual (nolog, "yes"))
        argv[argc++] = "--" LOAD_IGNORE_LOGGING_L;

    if (error_control_file != NULL
        && !uStringEqual (error_control_file, "none"))
    {
        argv[argc++] = "--" LOAD_ERROR_CONTROL_FILE_L;
        argv[argc++] = error_control_file;
    }

    if (ignore_class_file != NULL && !uStringEqual (ignore_class_file, "none"))
    {
        argv[argc++] = "--" LOAD_IGNORE_CLASS_L;
        argv[argc++] = ignore_class_file;
    }
    argv[argc++] = dbname;
    argv[argc++] = NULL;

    snprintf (cubrid_err_file, PATH_MAX, "%s/%s.%u.err.tmp",
              sco.dbmt_tmp_dir, "loaddb", getpid ());

    retval = run_child (argv, 1, NULL, tmpfile, cubrid_err_file, NULL);    /* loaddb */
    if (retval < 0)
    {
        if (access (cubrid_err_file, F_OK) == 0)
        {
            unlink (cubrid_err_file);
        }
        strcpy (_dbmt_error, argv[0]);
        return ERR_SYSTEM_CALL;
    }

    if (file_to_nvpairs (tmpfile, res) < 0)
    {
        if (access (cubrid_err_file, F_OK) == 0)
        {
            unlink (cubrid_err_file);
        }
        strcpy (_dbmt_error, tmpfile);
        return ERR_TMPFILE_OPEN_FAIL;
    }
    unlink (tmpfile);

    /* the error file may not exist, don't check the error of it. */
    file_to_nvpairs (cubrid_err_file, res);

    if (access (cubrid_err_file, F_OK) == 0)
    {
        unlink (cubrid_err_file);
    }
    if (uStringEqualIgnoreCase (nv_get_val (req, "delete_orignal_files"), "y"))
    {
        if (schema)
            unlink (schema);
        if (object)
            unlink (object);
        if (index)
            unlink (index);
    }

    return ERR_NO_ERROR;
}

int
ts_restoredb (nvplist * req, nvplist * res, char *_dbmt_error)
{
    int retval = ERR_NO_ERROR;
    char *dbname, *date, *lv, *pathname, *partial, *recovery_path;
    char cmd_name[CUBRID_CMD_NAME_LEN];
    const char *argv[17];
    int argc = 0;
    T_DB_SERVICE_MODE db_mode;
    char cubrid_err_file[PATH_MAX];
    int status;

    cubrid_err_file[0] = '\0';

    dbname = nv_get_val (req, "dbname");
    db_mode = uDatabaseMode (dbname, NULL);
    if (db_mode == DB_SERVICE_MODE_SA)
    {
        sprintf (_dbmt_error, "%s", dbname);
        return ERR_STANDALONE_MODE;
    }
    else if (db_mode == DB_SERVICE_MODE_CS)
    {
        sprintf (_dbmt_error, "%s", dbname);
        return ERR_DB_ACTIVE;
    }

    date = nv_get_val (req, "date");
    lv = nv_get_val (req, "level");
    pathname = nv_get_val (req, "pathname");
    partial = nv_get_val (req, "partial");
    recovery_path = nv_get_val (req, "recoverypath");

    cubrid_cmd_name (cmd_name);
    argv[argc++] = cmd_name;
    argv[argc++] = UTIL_OPTION_RESTOREDB;
    if ((date != NULL) && (strcmp (date, "none") != 0))
    {
        argv[argc++] = "--" RESTORE_UP_TO_DATE_L;
        argv[argc++] = date;
    }
    argv[argc++] = "--" RESTORE_LEVEL_L;
    argv[argc++] = lv;
    if (pathname != NULL && !uStringEqual (pathname, "none"))
    {
        argv[argc++] = "--" RESTORE_BACKUP_FILE_PATH_L;
        argv[argc++] = pathname;
    }
    if (uStringEqual (partial, "y"))
        argv[argc++] = "--" RESTORE_PARTIAL_RECOVERY_L;

    if (recovery_path != NULL && !uStringEqual (recovery_path, "")
        && !uStringEqual (recovery_path, "none"))
    {
        /* use -u option to specify restore database path */
        argv[argc++] = "--" RESTORE_USE_DATABASE_LOCATION_PATH_L;

        if ((retval =
            check_dbpath (recovery_path, _dbmt_error)) != ERR_NO_ERROR)
        {
            return retval;
        }
        if (access (recovery_path, F_OK) < 0)
        {
            retval = uCreateDir (recovery_path);
            if (retval != ERR_NO_ERROR)
            {
                return retval;
            }
        }

        if ((retval = alter_dblocation (dbname, recovery_path)) != ERR_NO_ERROR)
        {
            return retval;
        }
    }
    argv[argc++] = dbname;
    argv[argc++] = NULL;

    snprintf (cubrid_err_file, PATH_MAX, "%s/%s.%u.err.tmp",
              sco.dbmt_tmp_dir, "restoredb", getpid ());

    if (run_child (argv, 1, NULL, NULL, cubrid_err_file, &status) < 0)
    {
        strcpy_limit (_dbmt_error, argv[0], DBMT_ERROR_MSG_SIZE);
        if (access (cubrid_err_file, F_OK) == 0)
        {
            unlink (cubrid_err_file);
        }
        return ERR_SYSTEM_CALL;
    }

    if (status != 0 && read_error_file (cubrid_err_file, _dbmt_error,
                                        DBMT_ERROR_MSG_SIZE) < 0)
    {
        if (access (cubrid_err_file, F_OK) == 0)
        {
            unlink (cubrid_err_file);
        }
        return ERR_WITH_MSG;
    }

    if (access (cubrid_err_file, F_OK) == 0)
    {
        unlink (cubrid_err_file);
    }
    return ERR_NO_ERROR;
}

int
ts_backup_vol_info (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char *dbname, *lv, *pathname, buf[1024], tmpfile[PATH_MAX];
    int ret;
    FILE *infile;
    char cmd_name[CUBRID_CMD_NAME_LEN];
    const char *argv[10];
    int argc = 0;

    dbname = nv_get_val (req, "dbname");
    snprintf (tmpfile, PATH_MAX - 1, "%s/DBMT_task_%d.%d", sco.dbmt_tmp_dir,
              TS_BACKUPVOLINFO, (int) getpid ());

    if (uIsDatabaseActive (dbname))
    {
        sprintf (_dbmt_error, "%s", dbname);
        return ERR_DB_ACTIVE;
    }

    if (uDatabaseMode (dbname, NULL) == DB_SERVICE_MODE_SA)
    {
        sprintf (_dbmt_error, "%s", dbname);
        return ERR_STANDALONE_MODE;
    }

    lv = nv_get_val (req, "level");
    pathname = nv_get_val (req, "pathname");

    cubrid_cmd_name (cmd_name);
    argv[argc++] = cmd_name;
    argv[argc++] = UTIL_OPTION_RESTOREDB;
    argv[argc++] = "--" RESTORE_LIST_L;
    if (lv != NULL &&
        (uStringEqual (lv, "0") || uStringEqual (lv, "1")
        || uStringEqual (lv, "2")))
    {
        argv[argc++] = "--" RESTORE_LEVEL_L;
        argv[argc++] = lv;
    }
    if (pathname != NULL && !uStringEqual (pathname, "none"))
    {
        argv[argc++] = "--" RESTORE_BACKUP_FILE_PATH_L;
        argv[argc++] = pathname;
    }

    argv[argc++] = dbname;
    argv[argc++] = NULL;

#if defined(WINDOWS)
    ret = run_child (argv, 1, NULL, tmpfile, NULL, NULL);    /* restoredb -t */
#else
    ret = run_child (argv, 1, "/dev/null", tmpfile, NULL, NULL);    /* restoredb -t */
#endif
    if (ret < 0)
    {
        sprintf (_dbmt_error, "%s", argv[0]);
        return ERR_SYSTEM_CALL;
    }

    infile = fopen (tmpfile, "r");
    if (infile == NULL)
    {
        strcpy (_dbmt_error, tmpfile);
        return ERR_TMPFILE_OPEN_FAIL;
    }

    while (fgets (buf, sizeof (buf), infile))
    {
        uRemoveCRLF (buf);
        nv_add_nvp (res, "line", buf);
    }
    fclose (infile);
    unlink (tmpfile);

    return ERR_NO_ERROR;
}

int
ts_get_dbsize (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char *dbname;
    char dbname_at_hostname[MAXHOSTNAMELEN + DB_NAME_LEN];
    int ha_mode = 0;
    char strbuf[PATH_MAX], dbdir[PATH_MAX];
    int pagesize, no_tpage = 0, log_size = 0, baselen;
    struct stat statbuf;
    T_SPACEDB_RESULT *cmd_res;
    T_CUBRID_MODE cubrid_mode;
    int i;
#if defined(WINDOWS)
    char find_file[PATH_MAX];
    WIN32_FIND_DATA data;
    HANDLE handle;
    int found;
#else
    DIR *dirp;
    struct dirent *dp;
#endif
    char *cur_file;

    /* get dbname */
    if ((dbname = nv_get_val (req, "dbname")) == NULL)
    {
        sprintf (_dbmt_error, "%s", "database name");
        return ERR_PARAM_MISSING;
    }

    if (uRetrieveDBDirectory (dbname, dbdir) != ERR_NO_ERROR)
    {
        strcpy (_dbmt_error, dbname);
        return ERR_DBDIRNAME_NULL;
    }

    cubrid_mode =
        (uDatabaseMode (dbname, &ha_mode) ==
         DB_SERVICE_MODE_NONE) ? CUBRID_MODE_SA : CUBRID_MODE_CS;

    if (ha_mode != 0)
    {
        append_host_to_dbname (dbname_at_hostname, dbname,
                               sizeof (dbname_at_hostname));
        cmd_res = cmd_spacedb (dbname_at_hostname, cubrid_mode);
    }
    else
    {
        cmd_res = cmd_spacedb (dbname, cubrid_mode);
    }

    if (cmd_res == NULL || cmd_res->err_msg[0])
    {
        sprintf (_dbmt_error, "spacedb %s", dbname);
        cmd_spacedb_result_free (cmd_res);
        return ERR_SYSTEM_CALL;
    }

    for (i = 0; i < cmd_res->num_vol; i++)
    {
        no_tpage += cmd_res->vol_info[i].total_page;
    }
    for (i = 0; i < cmd_res->num_tmp_vol; i++)
    {
        no_tpage += cmd_res->tmp_vol_info[i].total_page;
    }
    pagesize = cmd_res->page_size;
    cmd_spacedb_result_free (cmd_res);

    /* get log volume info */
#if defined(WINDOWS)
    snprintf (find_file, PATH_MAX - 1, "%s/*", dbdir);
    if ((handle = FindFirstFile (find_file, &data)) == INVALID_HANDLE_VALUE)
#else
    if ((dirp = opendir (dbdir)) == NULL)
#endif
    {
        sprintf (_dbmt_error, "%s", dbdir);
        return ERR_DIROPENFAIL;
    }

    baselen = strlen (dbname);
#if defined(WINDOWS)
    for (found = 1; found; found = FindNextFile (handle, &data))
#else
    while ((dp = readdir (dirp)) != NULL)
#endif
    {
#if defined(WINDOWS)
        cur_file = data.cFileName;
#else
        cur_file = dp->d_name;
#endif
        if (!strncmp (cur_file + baselen, "_lginf", 6)
            || !strcmp (cur_file + baselen, CUBRID_ACT_LOG_EXT)
            || !strncmp (cur_file + baselen, CUBRID_ARC_LOG_EXT, CUBRID_ARC_LOG_EXT_LEN))
        {
            snprintf (strbuf, sizeof (strbuf) - 1, "%s/%s", dbdir, cur_file);
            stat (strbuf, &statbuf);
            log_size += statbuf.st_size;
        }
    }

#if defined(WINDOWS)
    FindClose (handle);
#else
    closedir (dirp);
#endif

    snprintf (strbuf, sizeof (strbuf) - 1, "%d",
              no_tpage * pagesize + log_size);
    nv_add_nvp (res, "dbsize", strbuf);

    return ERR_NO_ERROR;
}

int
tsGetEnvironment (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char tmpfile[PATH_MAX];
    char strbuf[1024];
    FILE *infile;
    char cmd_name[CUBRID_CMD_NAME_LEN];
    const char *argv[5];

    nv_add_nvp (res, "CUBRID", sco.szCubrid);
    nv_add_nvp (res, "CUBRID_DATABASES", sco.szCubrid_databases);
    nv_add_nvp (res, "CUBRID_DBMT", sco.szCubrid);
    //  nv_add_nvp (res, "CUBRID_CHARSET", getenv ("CUBRID_CHARSET"));
    snprintf (tmpfile, PATH_MAX - 1, "%s/DBMT_task_015.%d", sco.dbmt_tmp_dir,
              (int) getpid ());

    cmd_name[0] = '\0';
    snprintf (cmd_name, sizeof (cmd_name) - 1, "%s/%s%s", sco.szCubrid,
              CUBRID_DIR_BIN, UTIL_CUBRID_REL_NAME);

    argv[0] = cmd_name;
    argv[1] = NULL;

    run_child (argv, 1, NULL, tmpfile, NULL, NULL);    /* cubrid_rel */

    if ((infile = fopen (tmpfile, "r")) != NULL)
    {
        fgets (strbuf, sizeof (strbuf), infile);
        fgets (strbuf, sizeof (strbuf), infile);
        uRemoveCRLF (strbuf);
        fclose (infile);
        unlink (tmpfile);
        nv_add_nvp (res, "CUBRIDVER", strbuf);
    }
    else
    {
        nv_add_nvp (res, "CUBRIDVER", "version information not available");
    }

    snprintf (tmpfile, PATH_MAX - 1, "%s/DBMT_task_015.%d", sco.dbmt_tmp_dir,
              (int) getpid ());
    snprintf (cmd_name, sizeof (cmd_name) - 1, "%s/bin/cubrid_broker%s",
              sco.szCubrid, DBMT_EXE_EXT);

    argv[0] = cmd_name;
    argv[1] = "--version";
    argv[2] = NULL;

    run_child (argv, 1, NULL, tmpfile, NULL, NULL);    /* cubrid_broker --version */

    if ((infile = fopen (tmpfile, "r")) != NULL)
    {
        fgets (strbuf, sizeof (strbuf), infile);
        fclose (infile);
        uRemoveCRLF (strbuf);
        unlink (tmpfile);
        nv_add_nvp (res, "BROKERVER", strbuf);
    }
    else
        nv_add_nvp (res, "BROKERVER", "version information not available");

    if (sco.hmtab1 == 1)
        nv_add_nvp (res, "HOSTMONTAB0", "ON");
    else
        nv_add_nvp (res, "HOSTMONTAB0", "OFF");
    if (sco.hmtab2 == 1)
        nv_add_nvp (res, "HOSTMONTAB1", "ON");
    else
        nv_add_nvp (res, "HOSTMONTAB1", "OFF");
    if (sco.hmtab3 == 1)
        nv_add_nvp (res, "HOSTMONTAB2", "ON");
    else
        nv_add_nvp (res, "HOSTMONTAB2", "OFF");
    if (sco.hmtab4 == 1)
        nv_add_nvp (res, "HOSTMONTAB3", "ON");
    else
        nv_add_nvp (res, "HOSTMONTAB3", "OFF");

#if defined(WINDOWS)
    nv_add_nvp (res, "osinfo", "NT");
#elif LINUX
    nv_add_nvp (res, "osinfo", "LINUX");
#elif AIX
    nv_add_nvp (res, "osinfo", "AIX");
#elif HPUX
    nv_add_nvp (res, "osinfo", "HPUX");
#elif UNIXWARE7
    nv_add_nvp (res, "osinfo", "UNIXWARE7");
#elif SOLARIS
    nv_add_nvp (res, "osinfo", "SOLARIS");
#else
    nv_add_nvp (res, "osinfo", "unknown");
#endif

    return ERR_NO_ERROR;
}

int
ts_startinfo (nvplist * req, nvplist * res, char *_dbmt_error)
{
    T_SERVER_STATUS_RESULT *cmd_res;
    int retval;

    /* add dblist */
    retval = ut_get_dblist (res, 1);
    if (retval != ERR_NO_ERROR)
        return retval;

    nv_add_nvp (res, "open", "activelist");
    cmd_res = cmd_server_status ();
    if (cmd_res != NULL)
    {
        T_SERVER_STATUS_INFO *info = (T_SERVER_STATUS_INFO *) cmd_res->result;
        int i;
        for (i = 0; i < cmd_res->num_result; i++)
        {
#ifdef JSON_SUPPORT
            nv_add_nvp (res, "open", "active");
#endif
            nv_add_nvp (res, "dbname", info[i].db_name);
#ifdef JSON_SUPPORT
            nv_add_nvp (res, "close", "active");
#endif
        }
    }
    nv_add_nvp (res, "close", "activelist");

    uWriteDBnfo2 (cmd_res);
    cmd_servstat_result_free (cmd_res);

    return ERR_NO_ERROR;
}

int
ts_kill_process (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char *pid_str;
    int pid;
    char *tgt_name;

    if ((pid_str = nv_get_val (req, "pid")) == NULL)
    {
        strcpy (_dbmt_error, "pid");
        return ERR_PARAM_MISSING;
    }
    tgt_name = nv_get_val (req, "name");

    pid = atoi (pid_str);
    if (pid > 0)
    {
        if (kill (pid, SIGTERM) < 0)
        {
            DBMT_ERR_MSG_SET (_dbmt_error, strerror (errno));
            return ERR_WITH_MSG;
        }
    }

    nv_add_nvp (res, "name", tgt_name);
    uWriteDBnfo ();
    return ERR_NO_ERROR;
}

static int
ts_check_backup_id (const char *backupid)
{
    FILE *infile;
    char strbuf[SIZE_BUFFER_MAX];
    char strbuf_tmp[SIZE_BUFFER_MAX];
    char *conf_item[AUTOBACKUP_CONF_ENTRY_NUM];

    strbuf[0] = '\0';
    strbuf_tmp[0] = '\0';

    infile =
        fopen (conf_get_dbmt_file (FID_AUTO_BACKUPDB_CONF, strbuf_tmp), "r");
    if (infile == NULL)
    {
        return 0;
    }

    while (fgets (strbuf, sizeof (strbuf), infile))
    {
        ut_trim (strbuf);
        if (strbuf[0] == '#')
        {
            continue;
        }
        if (string_tokenize (strbuf, conf_item, AUTOBACKUP_CONF_ENTRY_NUM) < 0)
        {
            continue;
        }
        if (strcmp (conf_item[1], backupid) == 0)
        {
            fclose (infile);
            return 1;
        }
    }
    fclose (infile);

    return 0;
}

static int
_check_backup_info (const char *conf_item[], int check_backupid,
                    char *_dbmt_error)
{
    char time_item[5];
    char dbname[NAME_MAX];
    char path_item[PATH_MAX];
    char conf_value_item[NAME_MAX];

    char *token = NULL;

    int i = 0;
    int period_type_exist = 0;
    int period_date_exist = 0;
    int period_date = 0;

    time_item[0] = '\0';
    dbname[0] = '\0';
    path_item[0] = '\0';
    conf_value_item[0] = '\0';

    /* check the validation of dbname */
    snprintf (dbname, NAME_MAX, "%s", conf_item[0]);
    if (_isRegisteredDB (dbname) == 0)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", conf_item[0]);
        return ERR_DB_NONEXISTANT;
    }
    /* check the validation of backupid */
    if (check_backupid == 1)
    {
        if (ts_check_backup_id (conf_item[1]) == 1)
        {
            snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE,
                      "backupid(%s) already exist.", conf_item[1]);
            return ERR_WITH_MSG;
        }
    }
    /* check the validation of path */
    snprintf (path_item, PATH_MAX, "%s", conf_item[2]);
    if (access (path_item, F_OK) < 0)
    {
        if (uCreateDir (path_item) == ERR_NO_ERROR)
        {
            uRemoveDir (path_item, REMOVE_DIR_FORCED);
        }
        else
        {
            snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "Error : %s : %s",
                      conf_item[2], strerror (errno));
            return ERR_WITH_MSG;
        }
    }
    else if (access (path_item, R_OK | W_OK) < 0)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "Error : %s : %s",
                  conf_item[2], strerror (errno));
        return ERR_WITH_MSG;
    }
    /* check the validation of period_type */
    for (i = 0; i < AUTOBACKUP_PERIOD_TYPE_NUM; i++)
    {
        if (strcmp (conf_item[3], autobackup_period_type[i]) == 0)
        {
            period_type_exist = 1;
            break;
        }
    }
    /* 0 is meaning period type is out of autobackup_period_type */
    if (period_type_exist == 0)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE,
                  "(%s) is not allowed for parameter(%s).", conf_item[3],
                  autobackup_conf_entry[3]);
        return ERR_WITH_MSG;
    }
    /* check the validation of period_date */
    /* period_date: Monthly */
    if ((strcmp (conf_item[3], AUTO_BACKUP_PERIOD_TYPE_MONTHLY) == 0))
    {
        snprintf (conf_value_item, NAME_MAX, "%s", conf_item[4]);
        token = strtok (conf_value_item, " ,");
        while (token != NULL)
        {
            period_date = atoi (token);
            if ((period_date <= 0) || (period_date > 31))
            {
                snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE,
                          "(%s) is not allowed for parameter(%s).", token,
                          autobackup_conf_entry[4]);
                return ERR_WITH_MSG;
            }

            token = strtok (NULL, " ,");
        }
    }
    /* period_date: Weekly */
    else if (strcmp (conf_item[3], AUTO_BACKUP_PERIOD_TYPE_WEEKLY) == 0)
    {
        snprintf (conf_value_item, NAME_MAX, "%s", conf_item[4]);
        token = strtok (conf_value_item, " ,");
        while (token != NULL)
        {
            for (i = 0; i < AUTOBACKUP_PERIOD_WEEK_NUM; i++)
            {
                if (strcmp (token, autobackup_period_week[i]) == 0)
                {
                    period_date_exist = 1;
                    break;
                }
            }
            /* 0 is meaning period type is out of autobackup_period_type */
            if (period_date_exist == 0)
            {
                snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE,
                          "(%s) is not allowed for parameter(%s).", token,
                          autobackup_conf_entry[4]);
                return ERR_WITH_MSG;
            }

            period_date_exist = 0;
            token = strtok (NULL, " ,");
        }
    }
    /* period_date: Daily */
    else if (strcmp (conf_item[3], AUTO_BACKUP_PERIOD_TYPE_DAILY) == 0)
    {
        /* do nothing */
    }
    /* period_date: Hourly */
    else if (strcmp (conf_item[3], AUTO_BACKUP_PERIOD_TYPE_HOURLY) == 0)
    {
        period_date = atoi (conf_item[4]);
        if ((period_date <= 0) || (period_date > 24))
        {
            snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE,
                      "(%s) is not allowed for parameter(%s).", conf_item[4],
                      autobackup_conf_entry[4]);
            return ERR_WITH_MSG;
        }
    }
    /* period_date: Special */
    else
    {
        snprintf (conf_value_item, NAME_MAX, "%s", conf_item[4]);
        token = strtok (conf_value_item, " ,");
        while (token != NULL)
        {
            /* convert period_date from YYYY-MM-DD into YYYYMMDD */
            period_date = atoi (token) * 10000;    /* convert year: YYYY0000 */
            period_date += atoi (token + 5) * 100;    /* convert month: YYYYMM00 */
            period_date += atoi (token + 8);    /* convert day: YYYYMMDD */

            if (((period_date / 10000 - 1900) < 0)
                || (((period_date % 10000) / 100) <= 0)
                || (((period_date % 10000) / 100) > 12)
                || ((period_date % 100) <= 0) || ((period_date % 100) > 31))
            {
                /* tm_year : True year - 1900 */
                /* tm_mon : [0, 11] */
                /* tm_mday : [1, 31] */
                snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE,
                          "(%s) is not allowed for parameter(%s).",
                          conf_item[4], autobackup_conf_entry[4]);
                return ERR_WITH_MSG;
            }
            token = strtok (NULL, " ,");
        }
    }
    /* check time */
    if (strlen (conf_item[5]) == 4)
    {
        snprintf (time_item, sizeof (time_item), "%s", conf_item[5]);
        if ((time_item[0] < '0') || (time_item[0] >= '3'))
        {
            snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE,
                      "(%s) is not valid time format for parameter(%s).",
                      conf_item[5], autobackup_conf_entry[5]);
            return ERR_WITH_MSG;
        }
        if ((time_item[1] < '0') || (time_item[1] > '9'))
        {
            snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE,
                      "(%s) is not valid time format for parameter(%s).",
                      conf_item[5], autobackup_conf_entry[5]);
            return ERR_WITH_MSG;
        }
        if ((time_item[0] == '2') && (time_item[1] >= '4'))
        {
            snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE,
                      "(%s) is not valid time format for parameter(%s).",
                      conf_item[5], autobackup_conf_entry[5]);
            return ERR_WITH_MSG;
        }
        if ((time_item[2] < '0') || (time_item[2] >= '6'))
        {
            snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE,
                      "(%s) is not valid time format for parameter(%s).",
                      conf_item[5], autobackup_conf_entry[5]);
            return ERR_WITH_MSG;
        }
        if ((time_item[3] < '0') || (time_item[3] > '9'))
        {
            snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE,
                      "(%s) is not valid time format for parameter(%s).",
                      conf_item[5], autobackup_conf_entry[5]);
            return ERR_WITH_MSG;
        }
    }
    else
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE,
                  "(%s) is not valid time format for parameter(%s).",
                  conf_item[5], autobackup_conf_entry[5]);
        return ERR_WITH_MSG;
    }
    /* check level: 0 (default ), 1, 2 */
    if ((conf_item[6][0] < '0') || (conf_item[6][0] >= '3'))
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE,
                  "(%c) is not allowed for parameter(%s).", conf_item[6][0],
                  autobackup_conf_entry[6]);
        return ERR_WITH_MSG;
    }
    return ERR_NO_ERROR;
}

int
ts_backupdb_info (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char db_dir[PATH_MAX], log_dir[PATH_MAX];
    char *tok[3], vinf[PATH_MAX], buf[LINE_MAX];
    char db_backup_dir[PATH_MAX];
    FILE *infile;
    struct stat statbuf;

    char *dbname = NULL;

    db_dir[0] = '\0';
    log_dir[0] = '\0';
    vinf[0] = '\0';
    buf[0] = '\0';
    tok[0] = '\0';
    db_backup_dir[0] = '\0';    /* Used for extension for backup path. */

    dbname = nv_get_val (req, "dbname");
    if (dbname == NULL)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", "dbname");
        return ERR_PARAM_MISSING;
    }

    if (uDatabaseMode (dbname, NULL) == DB_SERVICE_MODE_SA)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", dbname);
        return ERR_STANDALONE_MODE;
    }

    if (uRetrieveDBDirectory (dbname, db_dir) != ERR_NO_ERROR)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", dbname);
        return ERR_DBDIRNAME_NULL;
    }

    if (uRetrieveDBLogDirectory (dbname, log_dir) != ERR_NO_ERROR)
    {
        strcpy (_dbmt_error, dbname);
        return ERR_DBDIRNAME_NULL;
    }

    snprintf (vinf, sizeof (vinf), "%s/%s%s", log_dir, dbname,
              CUBRID_BACKUP_INFO_EXT);

    if (access (vinf, F_OK) < 0)
    {
        goto exit_success;
    }

    if ((infile = fopen (vinf, "rt")) != NULL)
    {
        while (fgets (buf, sizeof (buf), infile))
        {
            ut_trim (buf);
            if (string_tokenize (buf, tok, 3) < 0)
            {
                continue;
            }
            if (stat (tok[2], &statbuf) == 0)
            {
                snprintf (vinf, sizeof (vinf), "level%s", tok[0]);
                nv_add_nvp (res, "open", vinf);
                nv_add_nvp (res, "path", tok[2]);
                nv_add_nvp_int (res, "size", statbuf.st_size);
                _add_nvp_time (res, "data", statbuf.st_mtime,
                               "%04d.%02d.%02d.%02d.%02d", NV_ADD_DATE_TIME);
                nv_add_nvp (res, "close", vinf);
            }
        }
        fclose (infile);
    }
    else
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", vinf);
        return ERR_PERMISSION;
    }

exit_success:
    /* In CUBRID Manager, $db_dir/backup is default path. */
    snprintf (db_backup_dir, sizeof (db_backup_dir), "%s/backup", db_dir);
    nv_add_nvp (res, "dbdir", db_backup_dir);

    nv_add_nvp_int (res, "freespace", ut_disk_free_space (db_dir));

    return ERR_NO_ERROR;
}

int
ts_unloaddb_info (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char *n, *v, buf[1024];
    FILE *infile;
    int flag = 0;
    struct stat statbuf;

    snprintf (buf, sizeof (buf) - 1, "%s/unloaddb.info",
              sco.szCubrid_databases);
    if ((infile = fopen (buf, "rt")) == NULL)
    {
        return ERR_NO_ERROR;
    }

    while (fgets (buf, sizeof (buf), infile))
    {
        uRemoveCRLF (buf);

        if ((v = strchr (buf, ' ')) == NULL)
            continue;

        *v = '\0';
        n = buf;
        v++;

        while (*v == ' ')
            v++;

        if (!strcmp (n, "%"))
        {
            if (flag == 1)
            {
                nv_add_nvp (res, "close", "database");
            }
            else
            {
                flag = 1;
            }
            nv_add_nvp (res, "open", "database");
            nv_add_nvp (res, "dbname", v);
        }
        else
        {
            if (stat (v, &statbuf) == 0)
            {
                char timestr[64];
                char tmpbuf[1024];
                time_to_str (statbuf.st_mtime, "%04d.%02d.%02d %02d:%02d",
                             timestr, TIME_STR_FMT_DATE_TIME);
                snprintf (tmpbuf, sizeof (tmpbuf) - 1, "%s;%s", v, timestr);
                nv_add_nvp (res, n, tmpbuf);
            }
        }
    }
    if (flag == 1)
    {
        nv_add_nvp (res, "close", "database");
    }
    fclose (infile);

    return ERR_NO_ERROR;
}

/* backup automation */

int
ts_get_backup_info (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char *dbname;
    FILE *infile;
    char strbuf[1024];
    char *conf_item[AUTOBACKUP_CONF_ENTRY_NUM];
    int i;

    if ((dbname = nv_get_val (req, "_DBNAME")) == NULL)
    {
        strcpy (_dbmt_error, "database name");
        return ERR_PARAM_MISSING;
    }

    nv_add_nvp (res, "dbname", dbname);
    infile = fopen (conf_get_dbmt_file (FID_AUTO_BACKUPDB_CONF, strbuf), "r");
    if (infile == NULL)
    {
        return ERR_NO_ERROR;
    }

    while (fgets (strbuf, sizeof (strbuf), infile))
    {
        ut_trim (strbuf);
        if (strbuf[0] == '#')
        {
            continue;
        }
        if (string_tokenize (strbuf, conf_item, AUTOBACKUP_CONF_ENTRY_NUM) < 0)
        {
            continue;
        }
        if (strcmp (conf_item[0], dbname) == 0)
        {
#ifdef JSON_SUPPORT
            nv_add_nvp (res, "open", dbname);
#endif
            for (i = 0; i < AUTOBACKUP_CONF_ENTRY_NUM; i++)
            {
                nv_add_nvp (res, autobackup_conf_entry[i], conf_item[i]);
            }
#ifdef JSON_SUPPORT
            nv_add_nvp (res, "close", dbname);
#endif
        }
    }
    fclose (infile);

    return ERR_NO_ERROR;
}

int
ts_set_backup_info (nvplist * req, nvplist * res, char *_dbmt_error)
{
    FILE *infile, *outfile;
    char line[LINE_MAX], tmpfile[PATH_MAX];
    char autofilepath[PATH_MAX];
    const char *conf_item[AUTOBACKUP_CONF_ENTRY_NUM];

    int i = 0;
    int retval = 0;
    int no_auto_job = 1;        /* 1 means there is no valid auto job */
    int backupid_exist = 0;

    autofilepath[0] = '\0';
    line[0] = '\0';
    tmpfile[0] = '\0';

    for (i = 0; i < AUTOBACKUP_CONF_ENTRY_NUM - 1; i++)
    {
        conf_item[i] = nv_get_val (req, autobackup_conf_entry[i]);
        if (conf_item[i] == NULL)
        {
            snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s",
                      autobackup_conf_entry[i]);
            return ERR_PARAM_MISSING;
        }
    }

    conf_item[AUTOBACKUP_CONF_ENTRY_NUM - 1] =
        nv_get_val (req, autobackup_conf_entry[AUTOBACKUP_CONF_ENTRY_NUM - 1]);
    if (conf_item[AUTOBACKUP_CONF_ENTRY_NUM - 1] == NULL)
    {
        conf_item[AUTOBACKUP_CONF_ENTRY_NUM - 1] = "1";
    }

    retval = _check_backup_info (conf_item, 0, _dbmt_error);
    if (retval != ERR_NO_ERROR)
    {
        return retval;
    }

    conf_get_dbmt_file (FID_AUTO_BACKUPDB_CONF, autofilepath);
    if (access (autofilepath, F_OK) < 0)
    {
        outfile = fopen (autofilepath, "w");
        if (outfile == NULL)
        {
            strcpy (_dbmt_error, autofilepath);
            return ERR_FILE_OPEN_FAIL;
        }
        for (i = 0; i < AUTOBACKUP_CONF_ENTRY_NUM; i++)
        {
            fprintf (outfile, "%s ", conf_item[i]);
        }
        fprintf (outfile, "\n");
        fclose (outfile);
        return ERR_NO_ERROR;
    }

    if ((infile = fopen (autofilepath, "r")) == NULL)
    {
        strcpy (_dbmt_error, autofilepath);
        return ERR_FILE_OPEN_FAIL;
    }
    snprintf (tmpfile, PATH_MAX, "%s/DBMT_task_%d.%d", sco.dbmt_tmp_dir,
              TS_SETBACKUPINFO, (int) getpid ());
    if ((outfile = fopen (tmpfile, "w")) == NULL)
    {
        fclose (infile);
        return ERR_TMPFILE_OPEN_FAIL;
    }
    while (fgets (line, sizeof (line), infile))
    {
        char conf_dbname[128], conf_backupid[128];

        if (sscanf (line, "%127s %127s", conf_dbname, conf_backupid) < 2)
        {
            continue;
        }

        no_auto_job = 0;        /* 0 means there is some auto job in autobackupdb.conf */

        if ((strcmp (conf_dbname, conf_item[0]) == 0) &&
            (strcmp (conf_backupid, conf_item[1]) == 0))
        {
            for (i = 0; i < AUTOBACKUP_CONF_ENTRY_NUM; i++)
            {
                fprintf (outfile, "%s ", conf_item[i]);
            }
            fprintf (outfile, "\n");
            backupid_exist = 1;
        }
        else
        {
            fputs (line, outfile);
        }
    }
    fclose (infile);
    fclose (outfile);

    move_file (tmpfile, autofilepath);
    /* if config file is valid but no auto job plan, create it. */
    if (no_auto_job == 1)
    {
        outfile = fopen (autofilepath, "w");
        if (outfile == NULL)
        {
            strcpy (_dbmt_error, autofilepath);
            return ERR_FILE_OPEN_FAIL;
        }
        for (i = 0; i < AUTOBACKUP_CONF_ENTRY_NUM; i++)
        {
            fprintf (outfile, "%s ", conf_item[i]);
        }
        fprintf (outfile, "\n");
        fclose (outfile);
        return ERR_NO_ERROR;
    }
    /* if config file is valid and there is some auto job plan, but no special backupid, throw exception */
    if (backupid_exist == 0)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE,
                  "Backup plan does not exist. backupid is %s.", conf_item[1]);
        return ERR_WITH_MSG;
    }
    return ERR_NO_ERROR;
}

int
ts_add_backup_info (nvplist * req, nvplist * res, char *_dbmt_error)
{
    FILE *outfile;
    char autofilepath[PATH_MAX];
    const char *conf_item[AUTOBACKUP_CONF_ENTRY_NUM];

    int i = 0;
    int retval = 0;

    autofilepath[0] = '\0';

    for (i = 0; i < AUTOBACKUP_CONF_ENTRY_NUM - 1; i++)
    {
        conf_item[i] = nv_get_val (req, autobackup_conf_entry[i]);
        if (conf_item[i] == NULL)
        {
            snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s",
                      autobackup_conf_entry[i]);
            return ERR_PARAM_MISSING;
        }
    }

    conf_item[AUTOBACKUP_CONF_ENTRY_NUM - 1] =
    nv_get_val (req, autobackup_conf_entry[AUTOBACKUP_CONF_ENTRY_NUM - 1]);
    if (conf_item[AUTOBACKUP_CONF_ENTRY_NUM - 1] == NULL)
    {
        conf_item[AUTOBACKUP_CONF_ENTRY_NUM - 1] = "1";
    }

    retval = _check_backup_info (conf_item, 1, _dbmt_error);
    if (retval != ERR_NO_ERROR)
    {
        return retval;
    }

    conf_get_dbmt_file (FID_AUTO_BACKUPDB_CONF, autofilepath);
    if ((outfile = fopen (autofilepath, "a")) == NULL)
    {
        strcpy (_dbmt_error, autofilepath);
        return ERR_FILE_OPEN_FAIL;
    }
    for (i = 0; i < AUTOBACKUP_CONF_ENTRY_NUM; i++)
        fprintf (outfile, "%s ", conf_item[i]);
    fprintf (outfile, "\n");

    fclose (outfile);

    return ERR_NO_ERROR;
}

int
ts_delete_backup_info (nvplist * req, nvplist * res, char *_dbmt_error)
{
    FILE *infile, *outfile;
    char line[LINE_MAX], tmpfile[PATH_MAX];
    char autofilepath[PATH_MAX];

    char *dbname = NULL;
    char *backupid = NULL;

    line[0] = '\0';
    tmpfile[0] = '\0';
    autofilepath[0] = '\0';

    dbname = nv_get_val (req, "dbname");
    if (dbname == NULL)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "dbname");
        return ERR_PARAM_MISSING;
    }

    backupid = nv_get_val (req, "backupid");
    if (backupid == NULL)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "backupid");
        return ERR_PARAM_MISSING;
    }
    if (ts_check_backup_id (backupid) == 0)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE,
                  "Backup plan does not exist. backupid is %s.", backupid);
        return ERR_WITH_MSG;
    }

    conf_get_dbmt_file (FID_AUTO_BACKUPDB_CONF, autofilepath);
    if ((infile = fopen (autofilepath, "r")) == NULL)
    {
        strcpy (_dbmt_error, autofilepath);
        return ERR_FILE_OPEN_FAIL;
    }
    snprintf (tmpfile, PATH_MAX - 1, "%s/DBMT_task_%d.%d", sco.dbmt_tmp_dir,
              TS_DELETEBACKUPINFO, (int) getpid ());
    if ((outfile = fopen (tmpfile, "w")) == NULL)
    {
        fclose (infile);
        return ERR_TMPFILE_OPEN_FAIL;
    }

    while (fgets (line, sizeof (line), infile))
    {
        char conf_dbname[128], conf_backupid[128];

        if (sscanf (line, "%127s %127s", conf_dbname, conf_backupid) != 2)
            continue;
        if ((strcmp (conf_dbname, dbname) != 0) ||
            backupid == NULL || (strcmp (conf_backupid, backupid) != 0))
        {
            fputs (line, outfile);
        }
    }
    fclose (infile);
    fclose (outfile);
    move_file (tmpfile, autofilepath);
    return ERR_NO_ERROR;
}

int
ts_get_log_info (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char *dbname, log_dir[PATH_MAX], buf[PATH_MAX];
    char *error_log_param;
    struct stat statbuf;
    int fname_len = 0;
#if defined(WINDOWS)
    WIN32_FIND_DATA data;
    HANDLE handle;
    int found;
#else
    DIR *dirp = NULL;
    struct dirent *dp = NULL;
#endif
    char find_file[PATH_MAX];
    char *fname;

    dbname = nv_get_val (req, "_DBNAME");

    if ((dbname == NULL)
        || (uRetrieveDBDirectory (dbname, log_dir) != ERR_NO_ERROR))
    {
        if (dbname != NULL)
        {
            strcpy (_dbmt_error, dbname);
        }
        return ERR_DBDIRNAME_NULL;
    }

    nv_add_nvp (res, "dbname", dbname);
    nv_add_nvp (res, "open", "loginfo");

    if ((error_log_param = _ts_get_error_log_param (dbname)) == NULL)
    {
        snprintf (buf, sizeof (buf) - 1, "%s/%s.err", log_dir, dbname);
    }
    else if (error_log_param[0] == '/')
    {
        snprintf (buf, sizeof (buf) - 1, "%s", error_log_param);
    }
#if defined(WINDOWS)
    else if (error_log_param[2] == '/')
    {
        snprintf (buf, sizeof (buf) - 1, "%s", error_log_param);
    }
#endif
    else
    {
        snprintf (buf, sizeof (buf) - 1, "%s/%s", log_dir, error_log_param);
    }

    if (stat (buf, &statbuf) == 0)
    {
        nv_add_nvp (res, "open", "log");
        nv_add_nvp (res, "path", buf);
        nv_add_nvp (res, ENCRYPT_ARG ("owner"),
                    get_user_name (statbuf.st_uid, buf));
        nv_add_nvp_int (res, "size", statbuf.st_size);
        _add_nvp_time (res, "lastupdate", statbuf.st_mtime, "%04d.%02d.%02d",
                       NV_ADD_DATE);
        nv_add_nvp (res, "close", "log");
    }
    FREE_MEM (error_log_param);

    snprintf (buf, sizeof (buf) - 1, "%s/cub_server.err", log_dir);
    if (stat (buf, &statbuf) == 0)
    {
        nv_add_nvp (res, "open", "log");
        nv_add_nvp (res, "path", buf);
        nv_add_nvp (res, ENCRYPT_ARG ("owner"),
        get_user_name (statbuf.st_uid, buf));
        nv_add_nvp_int (res, "size", statbuf.st_size);
        _add_nvp_time (res, "lastupdate", statbuf.st_mtime, "%04d.%02d.%02d",
                       NV_ADD_DATE);
        nv_add_nvp (res, "close", "log");
    }

    snprintf (find_file, PATH_MAX - 1, "%s/%s", sco.szCubrid,
              CUBRID_ERROR_LOG_DIR);
#if defined(WINDOWS)
    snprintf (&find_file[strlen (find_file)], PATH_MAX - strlen (find_file) - 1,
              "/*");
    if ((handle = FindFirstFile (find_file, &data)) == INVALID_HANDLE_VALUE)
#else
    if ((dirp = opendir (find_file)) == NULL)
#endif
    {
        nv_add_nvp (res, "close", "loginfo");
        return ERR_NO_ERROR;
    }
#if defined(WINDOWS)
    for (found = 1; found; found = FindNextFile (handle, &data))
#else
    while ((dp = readdir (dirp)) != NULL)
#endif
    {
#if defined(WINDOWS)
        fname = data.cFileName;
#else
        fname = dp->d_name;
#endif
        fname_len = strlen (fname);
        /* the "4" is the size of ".err" */
        if (fname_len < 4 || (strcmp (fname + fname_len - 4, ".err") != 0))
        {
            continue;
        }
        if (memcmp (fname, dbname, strlen (dbname)))
        {
            continue;
        }
        if (isalnum (fname[strlen (dbname)]))
        {
            continue;
        }
        snprintf (buf, sizeof (buf) - 1, "%s/%s/%s", sco.szCubrid,
                  CUBRID_ERROR_LOG_DIR, fname);
        if (stat (buf, &statbuf) == 0)
        {
            nv_add_nvp (res, "open", "log");
            nv_add_nvp (res, "path", buf);
            nv_add_nvp (res, ENCRYPT_ARG ("owner"),
            get_user_name (statbuf.st_uid, buf));
            nv_add_nvp_int (res, "size", statbuf.st_size);
            _add_nvp_time (res, "lastupdate", statbuf.st_mtime,
                           "%04d.%02d.%02d", NV_ADD_DATE);
            nv_add_nvp (res, "close", "log");
        }
    }
#if defined(WINDOWS)
    FindClose (handle);
#else
    closedir (dirp);
#endif

    nv_add_nvp (res, "close", "loginfo");
    return ERR_NO_ERROR;
}

int
ts_view_log (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char *filepath, *startline, *endline, buf[1024];
    FILE *infile;
    int no_line = 0, start, end;

    filepath = nv_get_val (req, "path");
    if (filepath == NULL)
    {
        strcpy (_dbmt_error, "filepath");
        return ERR_PARAM_MISSING;
    }

    startline = nv_get_val (req, "start");
    endline = nv_get_val (req, "end");

    start = (startline == NULL ? -1 : atoi (startline));
    end = (endline == NULL ? -1 : atoi (endline));

    if ((infile = fopen (filepath, "rt")) == NULL)
    {
        sprintf (_dbmt_error, "%s", filepath);
        return ERR_FILE_OPEN_FAIL;
    }

    nv_add_nvp (res, "path", filepath);
    nv_add_nvp (res, "open", "log");
    while (fgets (buf, sizeof (buf), infile))
    {
        no_line++;
        if (start != -1 && end != -1)
        {
            if (start > no_line || end < no_line)
            {
                continue;
            }
        }

        uRemoveCRLF (buf);
        nv_add_nvp (res, "line", buf);
    }
    nv_add_nvp (res, "close", "log");
    fclose (infile);

    if (start != -1 && end != -1)
    {
        nv_add_nvp_int (res, "start", (start > no_line ? no_line : start));
        nv_add_nvp_int (res, "end", (end > no_line ? no_line : end));
    }

    nv_add_nvp_int (res, "total", no_line);

    return ERR_NO_ERROR;
}

int
ts_reset_log (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char *path;
    FILE *outfile;

    path = nv_get_val (req, "path");
    if (path == NULL)
    {
        strcpy (_dbmt_error, "filepath");
        return ERR_PARAM_MISSING;
    }

    outfile = fopen (path, "w");
    if (outfile == NULL)
    {
        strcpy (_dbmt_error, path);
        return ERR_FILE_OPEN_FAIL;
    }
    fclose (outfile);

    return ERR_NO_ERROR;
}

int
ts_get_auto_add_vol (nvplist * req, nvplist * res, char *_dbmt_error)
{
    FILE *infile = NULL;
    char *dbname;
    char strbuf[1024], file[PATH_MAX];
    char *conf_item[AUTOADDVOL_CONF_ENTRY_NUM];
    int i;

    if ((dbname = nv_get_val (req, "_DBNAME")) == NULL)
    {
        sprintf (_dbmt_error, "%s", "database name");
        return ERR_PARAM_MISSING;
    }

    nv_add_nvp (res, autoaddvol_conf_entry[1], "OFF");
    nv_add_nvp (res, autoaddvol_conf_entry[2], "0.0");
    nv_add_nvp (res, autoaddvol_conf_entry[3], "0");
    nv_add_nvp (res, autoaddvol_conf_entry[4], "OFF");
    nv_add_nvp (res, autoaddvol_conf_entry[5], "0.0");
    nv_add_nvp (res, autoaddvol_conf_entry[6], "0");

    infile = fopen (conf_get_dbmt_file (FID_AUTO_ADDVOLDB_CONF, file), "r");
    if (infile == NULL)
        return ERR_NO_ERROR;

    while (fgets (strbuf, sizeof (strbuf), infile))
    {
        ut_trim (strbuf);
        if (strbuf[0] == '#')
            continue;
        if (string_tokenize (strbuf, conf_item, AUTOADDVOL_CONF_ENTRY_NUM) < 0)
            continue;
        if (strcmp (conf_item[0], dbname) == 0)
        {
            for (i = 1; i < AUTOADDVOL_CONF_ENTRY_NUM; i++)
                nv_update_val (res, autoaddvol_conf_entry[i], conf_item[i]);
            break;
        }
    }
    fclose (infile);

    return ERR_NO_ERROR;
}

int
ts_set_auto_add_vol (nvplist * req, nvplist * res, char *_dbmt_error)
{
    FILE *infile, *outfile;
    char line[1024], tmpfile[PATH_MAX];
    char auto_addvol_conf_file[PATH_MAX];
    char *conf_item[AUTOADDVOL_CONF_ENTRY_NUM];
    int i;

    if ((conf_item[0] = nv_get_val (req, "_DBNAME")) == NULL)
    {
        sprintf (_dbmt_error, "%s", "database name");
        return ERR_PARAM_MISSING;
    }

    for (i = 1; i < AUTOADDVOL_CONF_ENTRY_NUM; i++)
    {
        conf_item[i] = nv_get_val (req, autoaddvol_conf_entry[i]);
        if (conf_item[i] == NULL)
        {
            strcpy (_dbmt_error, autoaddvol_conf_entry[i]);
            return ERR_PARAM_MISSING;
        }
    }

    conf_get_dbmt_file (FID_AUTO_ADDVOLDB_CONF, auto_addvol_conf_file);
    if (access (auto_addvol_conf_file, F_OK) < 0)
    {
        outfile = fopen (auto_addvol_conf_file, "w");
        if (outfile == NULL)
        {
            strcpy (_dbmt_error, auto_addvol_conf_file);
            return ERR_FILE_OPEN_FAIL;
        }
        for (i = 0; i < AUTOADDVOL_CONF_ENTRY_NUM; i++)
            fprintf (outfile, "%s ", conf_item[i]);
        fprintf (outfile, "\n");
        fclose (outfile);
        return ERR_NO_ERROR;
    }

    infile = fopen (auto_addvol_conf_file, "r");
    if (infile == NULL)
    {
        strcpy (_dbmt_error, auto_addvol_conf_file);
        return ERR_FILE_OPEN_FAIL;
    }
    snprintf (tmpfile, PATH_MAX - 1, "%s/DBMT_task_045.%d", sco.dbmt_tmp_dir,
              (int) getpid ());
    outfile = fopen (tmpfile, "w");
    if (outfile == NULL)
    {
        fclose (infile);
        return ERR_TMPFILE_OPEN_FAIL;
    }

    while (fgets (line, sizeof (line), infile))
    {
        char conf_dbname[128];

        if (sscanf (line, "%127s", conf_dbname) < 1)
            continue;

        if (strcmp (conf_dbname, conf_item[0]) != 0)
        {
            fputs (line, outfile);
        }
    }
    for (i = 0; i < AUTOADDVOL_CONF_ENTRY_NUM; i++)
        fprintf (outfile, "%s ", conf_item[i]);
    fprintf (outfile, "\n");
    fclose (infile);
    fclose (outfile);

    move_file (tmpfile, auto_addvol_conf_file);

    return ERR_NO_ERROR;
}

int
ts_get_addvol_status (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char *dbname = NULL;
    char dbdir[PATH_MAX];

    if ((dbname = nv_get_val (req, "_DBNAME")) == NULL)
    {
        sprintf (_dbmt_error, "%s", "database name");
        return ERR_PARAM_MISSING;
    }

    if (uRetrieveDBDirectory (dbname, dbdir) != ERR_NO_ERROR)
    {
        strcpy (_dbmt_error, dbname);
        return ERR_DBDIRNAME_NULL;
    }

    nv_add_nvp_int (res, "freespace", ut_disk_free_space (dbdir));
    nv_add_nvp (res, "volpath", dbdir);
    return ERR_NO_ERROR;
}

int
ts_get_tran_info (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char *dbname = NULL;
    char *dbpasswd = NULL;
    char *user = NULL;
    char dbname_at_hostname[MAXHOSTNAMELEN + DB_NAME_LEN];
    int ha_mode = 0;
    char buf[1024];
    char tmpfile[PATH_MAX];
    char errfile[PATH_MAX];
    FILE *infile = NULL;
    char *tok[9];
    char cmd_name[CUBRID_CMD_NAME_LEN];
    const char *argv[10];
    int argc = 0;
    int retval = 0;
    int tmp = 0;
    T_DB_SERVICE_MODE db_mode;

    cmd_name[0] = '\0';
    buf[0] = '\0';
    tmpfile[0] = '\0';
    errfile[0] = '\0';
    dbname_at_hostname[0] = '\0';

    if ((dbname = nv_get_val (req, "dbname")) == NULL)
    {
        strncpy (_dbmt_error, "dbname", DBMT_ERROR_MSG_SIZE);
        return ERR_PARAM_MISSING;
    }

    if ((user = nv_get_val (req, "dbuser")) == NULL)
    {
        strncpy (_dbmt_error, "dbuser", DBMT_ERROR_MSG_SIZE);
        return ERR_PARAM_MISSING;
    }

    dbpasswd = nv_get_val (req, "dbpasswd");

    /* get database mode. */
    db_mode = uDatabaseMode (dbname, &ha_mode);
    if (db_mode == DB_SERVICE_MODE_SA)
    {
        strncpy (_dbmt_error, dbname, DBMT_ERROR_MSG_SIZE);
        return ERR_STANDALONE_MODE;
    }

    snprintf (tmpfile, PATH_MAX - 1, "%s/DBMT_task_%d.%d", sco.dbmt_tmp_dir,
              TS_GETTRANINFO, (int) getpid ());
    snprintf (errfile, PATH_MAX - 1, "%s/DBMT_task_%d.stderr.%d",
              sco.dbmt_tmp_dir, TS_GETTRANINFO, (int) getpid ());

    cubrid_cmd_name (cmd_name);
    argv[argc++] = cmd_name;
    argv[argc++] = UTIL_OPTION_TRANLIST;

    argv[argc++] = "--" TRANLIST_USER_L;
    argv[argc++] = user;

    if (dbpasswd != NULL)
    {
        argv[argc++] = "--" TRANLIST_PASSWORD_L;
        argv[argc++] = dbpasswd;
    }

    if (ha_mode != 0)
    {
        append_host_to_dbname (dbname_at_hostname, dbname,
                               sizeof (dbname_at_hostname));
        argv[argc++] = dbname_at_hostname;
    }
    else
    {
        argv[argc++] = dbname;
    }

    argv[argc++] = NULL;

    retval = run_child (argv, 1, NULL, tmpfile, errfile, NULL);    /* tranlist */
    if (retval < 0)
    {
        strncpy (_dbmt_error, argv[0], DBMT_ERROR_MSG_SIZE);
        return ERR_SYSTEM_CALL;
    }

    if ((infile = fopen (errfile, "r")) == NULL)
    {
        return ERR_TMPFILE_OPEN_FAIL;
    }

    retval = ERR_NO_ERROR;
    tmp = 0;
    while (fgets (buf, sizeof (buf), infile))
    {
        ut_trim (buf);
        strncpy (_dbmt_error + tmp, buf, DBMT_ERROR_MSG_SIZE - tmp);
        tmp += strlen (buf);
        retval = ERR_WITH_MSG;
    }

    if (retval != ERR_NO_ERROR)
    {
        fclose (infile);
        unlink (tmpfile);
        unlink (errfile);
        return retval;
    }

    fclose (infile);

    if ((infile = fopen (tmpfile, "rt")) == NULL)
    {
        return ERR_TMPFILE_OPEN_FAIL;
    }
    nv_add_nvp (res, "dbname", dbname);
    nv_add_nvp (res, "open", "transactioninfo");
    while (fgets (buf, sizeof (buf), infile))
    {
        if (buf[0] == '-')
        {
            break;
        }
    }
    while (fgets (buf, sizeof (buf), infile))
    {
        ut_trim (buf);
        if (buf[0] == '-')
        {
            break;
        }
        if (string_tokenize (buf, tok, 9) < 0)
        {
            continue;
        }
        nv_add_nvp (res, "open", "transaction");
        nv_add_nvp (res, "tranindex", tok[0]);
        nv_add_nvp (res, ENCRYPT_ARG ("user"), tok[1]);
        nv_add_nvp (res, "host", tok[2]);
        nv_add_nvp (res, "pid", tok[3]);
        nv_add_nvp (res, "program", tok[4]);
        nv_add_nvp (res, "query_time", tok[5]);
        nv_add_nvp (res, "tran_time", tok[6]);
        nv_add_nvp (res, "wait_for_lock_holder", tok[7]);
        if (strncmp (tok[8], "***", 3) == 0)
        {
            nv_add_nvp (res, "SQL_ID", "empty");
        }
        else
        {
            nv_add_nvp (res, "SQL_ID", tok[8]);
        }
        nv_add_nvp (res, "close", "transaction");
    }
    nv_add_nvp (res, "close", "transactioninfo");
    fclose (infile);
    unlink (tmpfile);
    unlink (errfile);

    return ERR_NO_ERROR;
}

/*
 *  read stdout and stderr files as error message.
 *
 */
static void
read_stdout_stderr_as_err (char *stdout_file, char *stderr_file,
                           char *_dbmt_error)
{
    FILE *fp;
    int len = 0;
    int len_tmp = 0;
    char buf[1024];

    if (access (stderr_file, F_OK) == 0)
    {
        fp = fopen (stderr_file, "r");
        if (fp != NULL)
        {
            while (fgets (buf, sizeof (buf), fp) != NULL)
            {
                ut_trim (buf);
                len_tmp = strlen (buf);

                if (len_tmp < DBMT_ERROR_MSG_SIZE - len - 1)
                {
                    strcpy (_dbmt_error, buf);
                    _dbmt_error += len_tmp;
                    len += len_tmp;
                }
                else
                {
                    strcpy_limit (_dbmt_error, buf, DBMT_ERROR_MSG_SIZE - len);
                    strcpy_limit (_dbmt_error + DBMT_ERROR_MSG_SIZE - len - 4,
                                  "...", 4);
                    break;
                }
            }
        }
        fclose (fp);
    }

    if (access (stdout_file, F_OK) == 0)
    {
        fp = fopen (stdout_file, "r");
        if (fp != NULL)
        {
            while (fgets (buf, sizeof (buf), fp) != NULL)
            {
                ut_trim (buf);
                len_tmp = strlen (buf);

                if (len_tmp < DBMT_ERROR_MSG_SIZE - len - 1)
                {
                    strcpy (_dbmt_error, buf);
                    _dbmt_error += len_tmp;
                    len += len_tmp;
                }
                else
                {
                    strcpy_limit (_dbmt_error, buf, DBMT_ERROR_MSG_SIZE - len);
                    strcpy_limit (_dbmt_error + DBMT_ERROR_MSG_SIZE - len - 4,
                                  "...", 4);
                    break;
                }
            }
        }
        fclose (fp);
    }
}

int
ts_killtran (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char *dbname = NULL;
    char *dbpasswd = NULL;
    char *type = NULL;
    char *param = NULL;
    char dbname_at_hostname[MAXHOSTNAMELEN + DB_NAME_LEN];
    char cmd_name[CUBRID_CMD_NAME_LEN];
    char task_name[10];
    const char *argv[10];
    int ha_mode = 0;
    int argc = 0;
    int is_need_param = 1;
    int retval = 0;
    T_DB_SERVICE_MODE db_mode;

    task_name[0] = '\0';
    dbname_at_hostname[0] = '\0';
    cmd_name[0] = '\0';

    if ((dbname = nv_get_val (req, "dbname")) == NULL)
    {
        strcpy (_dbmt_error, "dbname");
        return ERR_PARAM_MISSING;
    }

    dbpasswd = nv_get_val (req, "_DBPASSWD");

    if ((type = nv_get_val (req, "type")) == NULL)
    {
        strcpy (_dbmt_error, "type");
        return ERR_PARAM_MISSING;
    }

    param = nv_get_val (req, "parameter");

    db_mode = uDatabaseMode (dbname, &ha_mode);
    if (db_mode == DB_SERVICE_MODE_SA)
    {
        sprintf (_dbmt_error, "%s", dbname);
        return ERR_STANDALONE_MODE;
    }

    cubrid_cmd_name (cmd_name);
    argv[argc++] = cmd_name;
    argv[argc++] = UTIL_OPTION_KILLTRAN;
    if (dbpasswd != NULL)
    {
        argv[argc++] = "--" KILLTRAN_DBA_PASSWORD_L;
        argv[argc++] = dbpasswd;
    }
    if (strcmp (type, "i") == 0)
    {
        /* remove (+) from formated string such as "1(+) | 1(-)" */
        /*char *p = strstr (param, "(");
        if (p != NULL)
        *p = '\0'; */

        argv[argc++] = "--" KILLTRAN_KILL_TRANSACTION_INDEX_L;
    }
    else if (strcmp (type, "u") == 0)
    {
        argv[argc++] = "--" KILLTRAN_KILL_USER_NAME_L;
    }
    else if (strcmp (type, "h") == 0)
    {
        argv[argc++] = "--" KILLTRAN_KILL_HOST_NAME_L;
    }
    else if (strcmp (type, "p") == 0)
    {
        argv[argc++] = "--" KILLTRAN_KILL_PROGRAM_NAME_L;
    }
    else if (strcmp (type, "s") == 0)
    {
        argv[argc++] = "--" KILLTRAN_KILL_SQL_ID_L;
    }
    else if (strcmp (type, "q") == 0)
    {
        argv[argc++] = "--" KILLTRAN_KILL_QUERY_INFO_L;
        is_need_param = 0;
    }
    else if (strcmp (type, "d") == 0)
    {
        argv[argc++] = "--" KILLTRAN_DISPLAY_INFORMATION_L;
        is_need_param = 0;
    }
    else
    {
        strcpy (_dbmt_error, "invalid value in type.");
        return ERR_WITH_MSG;
    }

    if (is_need_param)
    {
        if (param == NULL)
        {
            strcpy (_dbmt_error, "parameter");
            return ERR_PARAM_MISSING;
        }
        argv[argc++] = param;
        argv[argc++] = "--" KILLTRAN_FORCE_L;
    }
    if (ha_mode != 0)
    {
        append_host_to_dbname (dbname_at_hostname, dbname,
                               sizeof (dbname_at_hostname));
        argv[argc++] = dbname_at_hostname;
    }
    else
    {
        argv[argc++] = dbname;
    }

    argv[argc++] = NULL;

    snprintf (task_name, TASKNAME_LEN, "%s", "killtran");
    retval = _run_child (argv, 1, task_name, NULL, _dbmt_error);
    if (retval != ERR_NO_ERROR)
    {
        return retval;
    }

    ts_get_tran_info (req, res, _dbmt_error);
    return ERR_NO_ERROR;
}

int
ts_lockdb (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char buf[1024], tmpfile[PATH_MAX], tmpfile2[PATH_MAX], s[32];
    char dbname_at_hostname[MAXHOSTNAMELEN + DB_NAME_LEN];
    char cmd_name[CUBRID_CMD_NAME_LEN];
    char task_name[10];

    const char *argv[10];
    int argc = 0;
    int ha_mode = 0;
    int retval = 0;

    char *dbname = NULL;

    T_DB_SERVICE_MODE db_mode;
    FILE *infile, *outfile;

    buf[0] = '\0';
    tmpfile[0] = '\0';
    tmpfile2[0] = '\0';
    s[0] = '\0';
    dbname_at_hostname[0] = '\0';
    cmd_name[0] = '\0';
    task_name[0] = '\0';

    if ((dbname = nv_get_val (req, "dbname")) == NULL)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", "dbname");
        return ERR_PARAM_MISSING;
    }
    db_mode = uDatabaseMode (dbname, &ha_mode);
    if (db_mode == DB_SERVICE_MODE_SA)
    {
        sprintf (_dbmt_error, "%s", dbname);
        return ERR_STANDALONE_MODE;
    }

    snprintf (tmpfile, PATH_MAX, "%s/DBMT_task_%d_1.%d.tmp", sco.dbmt_tmp_dir,
              TS_LOCKDB, (int) getpid ());

    cubrid_cmd_name (cmd_name);
    argv[argc++] = cmd_name;
    argv[argc++] = UTIL_OPTION_LOCKDB;
    argv[argc++] = "--" LOCK_OUTPUT_FILE_L;
    argv[argc++] = tmpfile;

    if (ha_mode != 0)
    {
        append_host_to_dbname (dbname_at_hostname, dbname,
                               sizeof (dbname_at_hostname));
        argv[argc++] = dbname_at_hostname;
    }
    else
    {
        argv[argc++] = dbname;
    }

    argv[argc++] = NULL;

    snprintf (task_name, TASKNAME_LEN, "%s", "lockdb");

    retval = _run_child (argv, 1, task_name, NULL, _dbmt_error);
    if (retval != ERR_NO_ERROR)
    {
        return retval;
    }

    infile = fopen (tmpfile, "rt");
    if (infile == NULL)
    {
        return ERR_TMPFILE_OPEN_FAIL;
    }

    /* create file that remove line feed at existed outputfile */
    snprintf (tmpfile2, PATH_MAX, "%s/DBMT_task_%d_2.%d.tmp", sco.dbmt_tmp_dir,
              TS_LOCKDB, (int) getpid ());

    outfile = fopen (tmpfile2, "w");
    if (outfile == NULL)
    {
        fclose (infile);
        return ERR_TMPFILE_OPEN_FAIL;
    }

    while (fgets (buf, sizeof (buf), infile))
    {
        if (sscanf (buf, "%31s", s) == 1)
        {
            fputs (buf, outfile);
        }
    }
    fclose (infile);
    fclose (outfile);
    unlink (tmpfile);
    if ((infile = fopen (tmpfile2, "rt")) == NULL)
    {
        return ERR_TMPFILE_OPEN_FAIL;
    }

    if (_ts_lockdb_parse_us (res, infile) < 0)
    {
        /* parshing error */
        strcpy (_dbmt_error,
                "Lockdb operation has been failed(Unexpected state).");
        fclose (infile);
        unlink (tmpfile2);
        return ERR_WITH_MSG;
    }

    fclose (infile);
    unlink (tmpfile2);

    return ERR_NO_ERROR;
}

int
ts_get_backup_list (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char buf[1024], file[PATH_MAX], s1[256], s2[256], *dbname, log_dir[512];
    FILE *infile;
    int lv = -1;

    dbname = nv_get_val (req, "dbname");
    if (dbname == NULL)
    {
        strcpy (_dbmt_error, "database name");
        return ERR_PARAM_MISSING;
    }

    if (uRetrieveDBLogDirectory (dbname, log_dir) != ERR_NO_ERROR)
    {
        strcpy (_dbmt_error, dbname);
        return ERR_DBDIRNAME_NULL;
    }

    snprintf (file, PATH_MAX - 1, "%s/%s%s", log_dir, dbname,
              CUBRID_BACKUP_INFO_EXT);
    if ((infile = fopen (file, "rt")) != NULL)
    {
        while (fgets (buf, sizeof (buf), infile))
        {
            sscanf (buf, "%255s %*s %255s", s1, s2);
            lv = atoi (s1);
            snprintf (buf, sizeof (buf) - 1, "level%d", lv);
            nv_add_nvp (res, buf, s2);
        }
        fclose (infile);
    }
    for (lv++; lv <= 2; lv++)
    {
        snprintf (buf, sizeof (buf) - 1, "level%d", lv);
        nv_add_nvp (res, buf, "none");
    }

    return ERR_NO_ERROR;
}

static char *
remove_special_characters (char *str)
{
    char ret_old[MAX_LINE];
    char ret_new[MAX_LINE];
    unsigned int i = 0;
    unsigned int j = 0;

    ret_new[0] = '\0';
    snprintf(ret_old, sizeof(ret_old), "%s", str);

    for (i = 0; i < sizeof(ret_old); i ++)
    {
        if ((ret_old[i] == '[') || (ret_old[i] == ']'))
        {
            continue;
        }
        ret_new[j] = ret_old[i];
        j++;
    }

    snprintf(str, sizeof(ret_old), "%s", ret_new);

    return str;
}

#if defined(WINDOWS)
static int
_get_dir_list (list < string > &files_list, const char* roor_dir, string special_key)
{
    HANDLE handle;
    WIN32_FIND_DATA ffd;
    char find_path[PATH_MAX];
    string cms_log_name;

    snprintf (find_path, PATH_MAX, "%s/*", roor_dir);

    handle = FindFirstFile (find_path, &ffd);
    if (handle == INVALID_HANDLE_VALUE)
    {
        return -1;
    }
    while (FindNextFile (handle, &ffd))
    {
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN
            || ffd.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM)
        {
            continue;
        }
        else if (!(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
        {
            cms_log_name = ffd.cFileName;
            if (special_key.length() == 0)
            {
               files_list.push_back(cms_log_name);
            }
            else
            {
                if (cms_log_name.find(special_key) < cms_log_name.length())
                {
                    files_list.push_back(cms_log_name);
                }
            }
        }
    }
    FindClose (handle);
    
    return 0;
}

#else

static int
_get_dir_list (list < string > &files_list, const char* roor_dir, string special_key)
{
   DIR *dirptr = NULL;
   struct dirent *entry;
   string cms_log_name;
   
   if ((dirptr = opendir(roor_dir)) == NULL)
   {
      return -1;
   }
   while ((entry = readdir(dirptr)) != NULL)
   {
        if (strcmp (entry->d_name, ".") == 0 || strcmp (entry->d_name, "..") == 0)
        {
            continue;
        }
        
        cms_log_name = entry->d_name;
         
        if (special_key.length() == 0)
        {
           files_list.push_back(cms_log_name);
        }
        else
        {
            if (cms_log_name.find(special_key) < cms_log_name.length())
            {
                files_list.push_back(cms_log_name);
            }
        }
   }
   
   closedir(dirptr);
   return 0;
}
#endif

static list < string >
_get_filtered_files_list(list < string > &files_list, string file_exp)
{
    list < string >::iterator itor;
    list < string > ret_files_list;
    
    ret_files_list.clear();
    
    if (files_list.empty() == true)
    {
        return ret_files_list;
    }
    
    for (itor = files_list.begin(); itor != files_list.end(); itor++)
    {       
        if ((*itor).find(file_exp) < (*itor).length())
        {
            ret_files_list.push_back(*itor);
        }
    }
    return ret_files_list;
}

int
ts_load_access_log (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char buf[MAX_LINE], time[256];
    char root_dir[PATH_MAX];
    char log_full_dir[PATH_MAX];
    char err_full_dir[PATH_MAX];
    FILE *infile;
    char *tok[10];
    unsigned int message_line = 0;
    string log_exp = ".log";
    string err_exp = ".err";
    string cms_process_name = CMS_NAME;
    list < string > all_files_list;
    list < string > err_files_list;
    list < string > log_files_list;
    list < string >::iterator itor;
    
    buf[0] = '\0';
    time[0] = '\0';
    root_dir[0] = '\0';
    log_full_dir[0] = '\0';
    err_full_dir[0] = '\0';
    
    snprintf (root_dir, PATH_MAX, "%s/%s/", sco.szCubrid, DBMT_LOG_DIR);

    _get_dir_list (all_files_list, root_dir, cms_process_name);

    log_files_list = _get_filtered_files_list (all_files_list, log_exp);

#ifndef JSON_SUPPORT
    nv_add_nvp (res, "open", "accesslog");
#endif
    for (itor = log_files_list.begin(); itor != log_files_list.end(); itor++)
    {
        snprintf (log_full_dir, PATH_MAX, "%s%s", root_dir, (*itor).c_str());
        if ((infile = fopen (log_full_dir, "rt")) != NULL)
        {
            while (fgets (buf, sizeof (buf), infile) != NULL)
            {
                remove_special_characters (buf);
                ut_trim (buf);

                if (string_tokenize (buf, tok, 9) < 0)
                {
                    continue;
                }

                if (strcmp (tok[5], ACCESS_LOG) != 0)
                {
                    continue;
                }

                if (message_line > MAX_MSG_LINE)
                {
                    nv_add_nvp (res, "full_line", 
                                "The message is too much, please go to the log path and get the left.");
#ifndef JSON_SUPPORT
                    nv_add_nvp (res, "close", "errorlog");
#endif
                    fclose (infile);
                    return ERR_NO_ERROR;
                }
#ifdef JSON_SUPPORT
                nv_add_nvp (res, "open", "accesslog");
#endif
                nv_add_nvp (res, ENCRYPT_ARG ("user"), tok[6]);
                nv_add_nvp (res, "taskname", tok[8]);
                snprintf (time, sizeof (time) - 1, "%s %s", tok[0], tok[1]);
                nv_add_nvp (res, "time", time);

#ifdef JSON_SUPPORT
                nv_add_nvp (res, "close", "accesslog");
#endif
                
                message_line++;
            }
            fclose (infile);
        }
    }

#ifndef JSON_SUPPORT
    nv_add_nvp (res, "close", "accesslog");
#endif

    err_files_list = _get_filtered_files_list (all_files_list, err_exp);
#ifndef JSON_SUPPORT
    nv_add_nvp (res, "open", "errorlog");
#endif
    for (itor = err_files_list.begin(); itor != err_files_list.end(); itor++)
    {
        snprintf (err_full_dir, PATH_MAX, "%s%s", root_dir, (*itor).c_str());
        if ((infile = fopen (err_full_dir, "rt")) != NULL)
        {
            while (fgets (buf, sizeof (buf), infile) != NULL)
            {
                remove_special_characters (buf);
                ut_trim (buf);

                if (string_tokenize (buf, tok, 9) < 0)
                {
                    continue;
                }

                if (strcmp (tok[5], ACCESS_ERR) != 0)
                {
                    continue;
                } 
                
                if (message_line > MAX_MSG_LINE)
                {
                    nv_add_nvp (res, "full_line", 
                                "The message is too much, please go to the log path and get the left.");
#ifndef JSON_SUPPORT
                    nv_add_nvp (res, "close", "errorlog");
#endif
                    fclose (infile);
                    return ERR_NO_ERROR;
                }
                
#ifdef JSON_SUPPORT
                nv_add_nvp (res, "open", "errorlog");
#endif
                nv_add_nvp (res, ENCRYPT_ARG ("user"), tok[6]);
                nv_add_nvp (res, "taskname", tok[8]);
                snprintf (time, sizeof (time) - 1, "%s %s", tok[0], tok[1]);
                nv_add_nvp (res, "time", time);
                nv_add_nvp (res, "errornote", tok[8] + strlen (tok[8]) + 1);
#ifdef JSON_SUPPORT
                nv_add_nvp (res, "close", "errorlog");
#endif

                message_line++;
            }
            fclose (infile);
        }
    }
#ifndef JSON_SUPPORT
    nv_add_nvp (res, "close", "errorlog");
#endif
    return ERR_NO_ERROR;
}

static void
_get_error_access_log_files (nvplist * req, nvplist * res, bool is_access_log)
{
    char log_full_dir[PATH_MAX];
    char root_dir[PATH_MAX];
    list < string > log_files_list;
    list < string > all_files_list;
    list < string >::iterator itor;
    
    string cms_process_name = CMS_NAME;
    string log_exp = ".log";
    if (is_access_log == false)
    {
        log_exp = ".err";
    }

    log_full_dir[0] = '\0';
    
    snprintf (root_dir, PATH_MAX, "%s/%s/", sco.szCubrid, DBMT_LOG_DIR);
    
    _get_dir_list (all_files_list, root_dir, cms_process_name);
    log_files_list = _get_filtered_files_list (all_files_list, log_exp);
    
    if (log_files_list.empty() == true)
    {
        nv_add_nvp (res, "open", "logfileslist");
        
        snprintf (log_full_dir, PATH_MAX, "%s%s%s", root_dir, cms_process_name.c_str(), log_exp.c_str());
        nv_add_nvp (res, "logfile", log_full_dir);
        
        nv_add_nvp (res, "close", "logfileslist");
    }

    for (itor = log_files_list.begin(); itor != log_files_list.end(); itor++)
    {
        nv_add_nvp (res, "open", "logfileslist");

        snprintf (log_full_dir, PATH_MAX, "%s%s", root_dir, (*itor).c_str());
        nv_add_nvp (res, "logfile", log_full_dir);

        nv_add_nvp (res, "close", "logfileslist");
    }
}


int
ts_get_access_log_files (nvplist * req, nvplist * res, char *_dbmt_error)
{
    _get_error_access_log_files (req, res, true);

    return ERR_NO_ERROR;
}

int
ts_get_error_log_files (nvplist * req, nvplist * res, char *_dbmt_error)
{
    _get_error_access_log_files (req, res, false);

    return ERR_NO_ERROR;
}

int
tsGetAutoaddvolLog (nvplist * req, nvplist * res, char *_dbmt_error)
{
    FILE *infile;
    char strbuf[1024];
    char dbname[512];
    char volname[512];
    char purpose[512];
    char page[512];
    char time[512];
    char outcome[512];
    char file[PATH_MAX];
    char *start_time, *end_time;

    start_time = nv_get_val (req, "start_time");
    end_time = nv_get_val (req, "end_time");

    infile = fopen (conf_get_dbmt_file (FID_AUTO_ADDVOLDB_LOG, file), "r");
    if (infile != NULL)
    {
        while (fgets (strbuf, sizeof (strbuf), infile))
        {
            uRemoveCRLF (strbuf);
            /*testdb testdb_x002 data 1024 2012-11-16,10:4:57 success */
            sscanf (strbuf, "%511s %511s %511s %511s %511s %511s", dbname,
                    volname, purpose, page, time, outcome);
            if (start_time != NULL && strcmp (time, start_time) < 0)
                continue;
            if (end_time != NULL && strcmp (time, end_time) > 0)
                continue;
            nv_add_nvp (res, "open", "log");
            nv_add_nvp (res, "dbname", dbname);
            nv_add_nvp (res, "volname", volname);
            nv_add_nvp (res, "purpose", purpose);
            nv_add_nvp (res, "page", page);
            nv_add_nvp (res, "time", time);
            nv_add_nvp (res, "outcome", outcome);
            nv_add_nvp (res, "close", "log");
        }
        fclose (infile);
    }
    return ERR_NO_ERROR;
}

int
ts_check_dir (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char *n, *v;
    int i;
    for (i = 0; i < req->nvplist_leng; i++)
    {
        nv_lookup (req, i, &n, &v);
        if ((n != NULL) && (strcmp (n, "dir") == 0))
        {
            if ((v == NULL) || (access (v, F_OK) < 0))
                nv_add_nvp (res, "noexist", v);
        }
    }

    return ERR_NO_ERROR;
}

int
ts_check_file (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char *n, *v;
    int i;
    for (i = 0; i < req->nvplist_leng; i++)
    {
        nv_lookup (req, i, &n, &v);
        if ((n != NULL) && (strcmp (n, "file") == 0))
        {
            if ((v != NULL) && (access (v, F_OK) == 0))
                nv_add_nvp (res, "existfile", v);
        }
    }

    return ERR_NO_ERROR;
}

int
ts_get_autobackupdb_error_log (nvplist * req, nvplist * res,
                               char *_dbmt_error)
{
    char buf[1024], logfile[PATH_MAX], s1[256], s2[256], time[512], dbname[256],
    backupid[256];
    char *start_time, *end_time;
    FILE *infile;

    start_time = nv_get_val (req, "start_time");
    end_time = nv_get_val (req, "end_time");

    snprintf (logfile, PATH_MAX - 1, "%s/log/manager/auto_backupdb.log",
              sco.szCubrid);
    if ((infile = fopen (logfile, "r")) == NULL)
    {
        return ERR_NO_ERROR;
    }

    while (fgets (buf, sizeof (buf), infile))
    {
        if (sscanf (buf, "%255s %255s", s1, s2) != 2)
        {
            continue;
        }
        if (!strncmp (s1, "DATE:", 5))
        {
            snprintf (time, sizeof (time) - 1, "%s %s", s1 + 5, s2 + 5);
            if (start_time != NULL && strcmp (time, start_time) < 0)
                continue;
            if (end_time != NULL && strcmp (time, end_time) > 0)
                continue;
            if (fgets (buf, sizeof (buf), infile) == NULL)
            {
                break;
            }
            sscanf (buf, "%255s %255s", s1, s2);
            snprintf (dbname, sizeof (dbname) - 1, "%s", s1 + 7);
            snprintf (backupid, sizeof (backupid) - 1, "%s", s2 + 9);
            if (fgets (buf, sizeof (buf), infile) == NULL)
            {
                break;
            }
            uRemoveCRLF (buf);
            nv_add_nvp (res, "open", "error");
            nv_add_nvp (res, "dbname", dbname);
            nv_add_nvp (res, "backupid", backupid);
            nv_add_nvp (res, "error_time", time);
            nv_add_nvp (res, "error_desc", buf + 3);
            nv_add_nvp (res, "close", "error");
        }
    }
    fclose (infile);

    return ERR_NO_ERROR;
}

int
ts_get_autoexecquery_error_log (nvplist * req, nvplist * res,
                char *_dbmt_error)
{
    char buf[1024], logfile[PATH_MAX], s1[256], s2[256], s3[256], s4[256],
    time[512], dbname[256], username[256], query_id[256], error_code[256];
    char *start_time, *end_time;
    FILE *infile;

    start_time = nv_get_val (req, "start_time");
    end_time = nv_get_val (req, "end_time");

    snprintf (logfile, PATH_MAX - 1, "%s/log/manager/auto_execquery.log",
              sco.szCubrid);
    if ((infile = fopen (logfile, "r")) == NULL)
        return ERR_NO_ERROR;

    while (fgets (buf, sizeof (buf), infile))
    {
        if (sscanf (buf, "%255s %255s", s1, s2) != 2)
        {
            continue;
        }
        if (!strncmp (s1, "DATE:", 5))
        {
            snprintf (time, sizeof (time) - 1, "%s %s", s1 + 5, s2 + 5);    /* 5 = strlen("DATE:"); 5 = strlen("TIME:"); */
            if (start_time != NULL && strcmp (time, start_time) < 0)
                continue;
            if (end_time != NULL && strcmp (time, end_time) > 0)
                continue;
            if (fgets (buf, sizeof (buf), infile) == NULL)
            {
                break;
            }

            s3[0] = 0;
            sscanf (buf, "%255s %255s %255s %255s", s1, s2, s3, s4);
            snprintf (dbname, sizeof (dbname) - 1, "%s", s1 + 7);    /* 7 = strlen("DBNAME:") */
            snprintf (username, sizeof (username) - 1, "%s", s2 + 14);    /* 14 = strlen("EMGR-USERNAME:") */
            snprintf (query_id, sizeof (query_id) - 1, "%s", s3 + 9);    /* 9 = strlen("QUERY-ID:") */
            snprintf (error_code, sizeof (error_code) - 1, "%s", s4 + 11);    /* 11 = strlen("ERROR-CODE:") */
            if (fgets (buf, sizeof (buf), infile) == NULL)
            {
                break;
            }

            uRemoveCRLF (buf);
            nv_add_nvp (res, "open", "error");
            nv_add_nvp (res, "dbname", dbname);
            nv_add_nvp (res, ENCRYPT_ARG ("username"), username);
            nv_add_nvp (res, "query_id", query_id);
            nv_add_nvp (res, "error_time", time);
            nv_add_nvp (res, "error_code", error_code);
            nv_add_nvp (res, "error_desc", buf + 3);
            nv_add_nvp (res, "close", "error");
        }
    }
    fclose (infile);
    return ERR_NO_ERROR;
}

int
ts_trigger_operation (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char *task, *dbname, *dbuser, *dbpasswd;
    char dbname_at_hostname[MAXHOSTNAMELEN + DB_NAME_LEN];
    int ha_mode = 0;
    char cmd_name[CUBRID_CMD_NAME_LEN];
    const char *argv[11];
    char input_file[PATH_MAX];
    char cubrid_err_file[PATH_MAX];
    int retval, argc;
    T_DB_SERVICE_MODE db_mode;

    input_file[0] = '\0';
    cubrid_err_file[0] = '\0';

    task = nv_get_val (req, "task");
    if (task != NULL)
    {
        if (strcmp (task, "addtrigger") == 0)
        {
            snprintf (input_file, PATH_MAX - 1, "%s/dbmt_task_%d_%d",
                      sco.dbmt_tmp_dir, TS_ADDNEWTRIGGER, (int) getpid ());
        }
        else if (strcmp (task, "droptrigger") == 0)
        {
            snprintf (input_file, PATH_MAX - 1, "%s/dbmt_task_%d_%d",
                      sco.dbmt_tmp_dir, TS_DROPTRIGGER, (int) getpid ());
        }
        else if (strcmp (task, "altertrigger") == 0)
        {
            snprintf (input_file, PATH_MAX - 1, "%s/dbmt_task_%d_%d",
                      sco.dbmt_tmp_dir, TS_ALTERTRIGGER, (int) getpid ());
        }
    }

    dbname = nv_get_val (req, "_DBNAME");
    dbuser = nv_get_val (req, "_DBID");
    dbpasswd = nv_get_val (req, "_DBPASSWD");

    cmd_name[0] = '\0';
    snprintf (cmd_name, sizeof (cmd_name) - 1, "%s/%s%s", sco.szCubrid,
              CUBRID_DIR_BIN, UTIL_CSQL_NAME);
    argc = 0;
    argv[argc++] = cmd_name;

    db_mode = uDatabaseMode (dbname, &ha_mode);
    if (ha_mode != 0)
    {
        append_host_to_dbname (dbname_at_hostname, dbname,
                               sizeof (dbname_at_hostname));
        argv[argc++] = dbname_at_hostname;
    }
    else
    {
        argv[argc++] = dbname;
    }

    argv[argc++] = NULL;
    argv[argc++] = "--" CSQL_INPUT_FILE_L;
    argv[argc++] = input_file;
    if (dbuser)
    {
        argv[argc++] = "--" CSQL_USER_L;
        argv[argc++] = dbuser;
        if (dbpasswd)
        {
            argv[argc++] = "--" CSQL_PASSWORD_L;
            argv[argc++] = dbpasswd;
        }
    }

    argv[argc++] = "--" CSQL_NO_AUTO_COMMIT_L;

    for (; argc < 11; argc++)
    {
        argv[argc] = NULL;
    }

    if (!_isRegisteredDB (dbname))
    {
        return ERR_DB_NONEXISTANT;
    }

    if (db_mode == DB_SERVICE_MODE_SA)
    {
        sprintf (_dbmt_error, "%s", dbname);
        return ERR_STANDALONE_MODE;
    }

    if (db_mode == DB_SERVICE_MODE_CS)
    {
        /* run csql command with -cs option */
        argv[2] = "--" CSQL_CS_MODE_L;
    }

    if (db_mode == DB_SERVICE_MODE_NONE)
    {
        /* run csql command with -sa option */
        argv[2] = "--" CSQL_SA_MODE_L;
    }

    /* csql -sa -i input_file dbname  */
    if (task != NULL)
    {
        if (strcmp (task, "addtrigger") == 0)
        {
            if (op_make_triggerinput_file_add (req, input_file) == 0)
            {
                strcpy (_dbmt_error, argv[0]);
                return ERR_TMPFILE_OPEN_FAIL;
            }
        }
        else if (strcmp (task, "droptrigger") == 0)
        {
            if (op_make_triggerinput_file_drop (req, input_file) == 0)
            {
                strcpy (_dbmt_error, argv[0]);
                return ERR_TMPFILE_OPEN_FAIL;
            }
        }
        else if (strcmp (task, "altertrigger") == 0)
        {
            if (op_make_triggerinput_file_alter (req, input_file) == 0)
            {
                strcpy (_dbmt_error, argv[0]);
                return ERR_TMPFILE_OPEN_FAIL;
            }
        }
    }

    snprintf (cubrid_err_file, PATH_MAX, "%s/%s.%u.err.tmp",
              sco.dbmt_tmp_dir, "trigger_operation", getpid ());
    SET_TRANSACTION_NO_WAIT_MODE_ENV ();

    retval = run_child (argv, 1, NULL, NULL, cubrid_err_file, NULL);    /* csql - trigger */
    if (strlen (input_file) > 0)
    {
        unlink (input_file);
    }

    if (read_csql_error_file (cubrid_err_file, _dbmt_error, DBMT_ERROR_MSG_SIZE) < 0)
    {
        if (access (cubrid_err_file, F_OK) == 0)
        {
            unlink (cubrid_err_file);
        }
        return ERR_WITH_MSG;
    }
    if (access (cubrid_err_file, F_OK) == 0)
    {
        unlink (cubrid_err_file);
    }
    if (retval < 0)
    {
        strcpy (_dbmt_error, argv[0]);
        return ERR_SYSTEM_CALL;
    }

    nv_add_nvp (res, "dbname", dbname);

    return ERR_NO_ERROR;
}

int
ts_get_triggerinfo (nvplist * req, nvplist * res, char *_dbmt_error)
{
    return cm_ts_get_triggerinfo (req, res, _dbmt_error);
}

int
ts_set_autoexec_query (nvplist * req, nvplist * res, char *_dbmt_error)
{
    FILE *conf_file, *temp_file;
    char autoexecquery_conf_file[PATH_MAX];
    char tmpfile[PATH_MAX];
    char db_uid[64];
    char db_name[DB_NAME_LEN];
    char dbmt_uid[DBMT_USER_NAME_LEN];
    char enc_dbpasswd[PASSWD_ENC_LENGTH];
    nvplist *db_user_info;
    char line_buf[MAX_JOB_CONFIG_FILE_LINE_LENGTH];
    char *conf_item[AUTOEXECQUERY_CONF_ENTRY_NUM];
    int i, nvlist_index, nvlist_section_len;
    char *name, *value;

    if ((conf_item[0] = nv_get_val (req, "_DBNAME")) == NULL)
    {
        sprintf (_dbmt_error, "%s", "database name");
        return ERR_PARAM_MISSING;
    }

    if ((conf_item[4] = nv_get_val (req, "_ID")) == NULL)
    {
        sprintf (_dbmt_error, "%s", "database user");
        return ERR_PARAM_MISSING;
    }

    conf_get_dbmt_file (FID_AUTO_EXECQUERY_CONF, autoexecquery_conf_file);
    if (access (autoexecquery_conf_file, F_OK) == 0)
    {
        conf_file = fopen (autoexecquery_conf_file, "r");
    }
    else
    {
        conf_file = fopen (autoexecquery_conf_file, "w+");
    }
    if (conf_file == NULL)
    {
        return ERR_FILE_OPEN_FAIL;
    }

    snprintf (tmpfile, PATH_MAX - 1, "%s/DBMT_task_045.%d", sco.dbmt_tmp_dir,
              (int) getpid ());
    if ((temp_file = fopen (tmpfile, "w")) == NULL)
    {
        fclose (conf_file);
        return ERR_TMPFILE_OPEN_FAIL;
    }

    db_user_info = nv_create (5, NULL, "\n", ":", "\n");
    while (fgets (line_buf, sizeof (line_buf), conf_file) != NULL)
    {
        if (obsolete_version_autoexecquery_conf (line_buf))
        {
            if (sscanf (line_buf, "%64s %*s %64s", db_name, dbmt_uid) < 2)
            {
                continue;
            }

            if ((strcmp (dbmt_uid, conf_item[4]) != 0)
                || (strcmp (db_name, conf_item[0]) != 0))
            {
                /* configure item not set by current dbmt_user,
                * or it has no relation with current database */
                fputs (line_buf, temp_file);
            }
        }
        else
        {
            if (sscanf
                (line_buf, "%64s %*s %64s %80s %64s", db_name, db_uid,
                enc_dbpasswd, dbmt_uid) < 4)
            {
                continue;
            }

            if ((strcmp (dbmt_uid, conf_item[4]) != 0)
                || (strcmp (db_name, conf_item[0]) != 0))
            {
                fputs (line_buf, temp_file);
            }
            else
            {
                nv_add_nvp (db_user_info, db_uid, enc_dbpasswd);
            }
        }
    }
    fclose (conf_file);

    nv_locate (req, "planlist", &nvlist_index, &nvlist_section_len);
    if (nvlist_section_len == 0)
    {
        fclose (temp_file);
        move_file (tmpfile, autoexecquery_conf_file);

        return ERR_NO_ERROR;
    }

    name = value = NULL;
    for (i = nvlist_index + 1; i < nvlist_index + nvlist_section_len; i += 8)
    {
        /* open:queryplan */
        if (value != NULL && strcasecmp (value, "planlist") == 0)
        {
            fclose (temp_file);
            return ERR_NO_ERROR;
        }

        /* query_id */
        nv_lookup (req, i, &name, &value);
        conf_item[1] = value;

        /* db_uid */
        nv_lookup (req, i + 1, &name, &value);
        conf_item[2] = value;

        /* db_passwd */
        nv_lookup (req, i + 2, &name, &value);
        if (strcmp (value, "unknown") == 0)
        {
            if ((conf_item[3] =
                nv_get_val (db_user_info, conf_item[2])) == NULL)
            {
                uEncrypt (PASSWD_LENGTH, "", enc_dbpasswd);
                conf_item[3] = enc_dbpasswd;
            }
        }
        else if (strcmp (value, "none") == 0)
        {
            uEncrypt (PASSWD_LENGTH, "", enc_dbpasswd);
            conf_item[3] = enc_dbpasswd;
        }
        else
        {
            uEncrypt (PASSWD_LENGTH, value, enc_dbpasswd);
            conf_item[3] = enc_dbpasswd;
        }

        /* period */
        nv_lookup (req, i + 3, &name, &value);
        conf_item[5] = value;

        /* time detail */
        nv_lookup (req, i + 4, &name, &value);
        conf_item[6] = value;

        /* query string */
        nv_lookup (req, i + 5, &name, &value);
        if ((value != NULL) && (strlen (value) > MAX_AUTOQUERY_SCRIPT_SIZE))
        {
            sprintf (_dbmt_error,
                     "Query script too long. MAX_AUTOQUERY_SCRIPT_SIZE:%d.",
                     MAX_AUTOQUERY_SCRIPT_SIZE);
            fclose (temp_file);
            return ERR_WITH_MSG;
        }
        else
        {
            conf_item[7] = value;
        }

        fprintf (temp_file, "%s %s %s %s %s %s %s %s\n", conf_item[0],
                 conf_item[1], conf_item[2], conf_item[3], conf_item[4],
                 conf_item[5], conf_item[6], conf_item[7]);
        /* close:queryplan */
    }
    fclose (temp_file);
    move_file (tmpfile, autoexecquery_conf_file);

    nv_destroy (db_user_info);

    return ERR_NO_ERROR;
}

int
ts_get_autoexec_query (nvplist * req, nvplist * res, char *_dbmt_error)
{
    int retval = ERR_NO_ERROR;
    FILE *conf_file;
    char autoexecquery_conf_file[PATH_MAX];
    int conf_item_num;
    char *dbname, *dbmt_uid;
    char line_buf[MAX_JOB_CONFIG_FILE_LINE_LENGTH];
    char *conf_item[AUTOEXECQUERY_CONF_ENTRY_NUM];
    char exectime_detail[256];

    conf_get_dbmt_file (FID_AUTO_EXECQUERY_CONF, autoexecquery_conf_file);
    if (access (autoexecquery_conf_file, F_OK) == 0)
    {
        conf_file = fopen (autoexecquery_conf_file, "r");
        if (!conf_file)
        {
            return ERR_FILE_OPEN_FAIL;
        }
    }
    else
    {
        nv_add_nvp (res, "open", "planlist");
        nv_add_nvp (res, "close", "planlist");
        return ERR_NO_ERROR;
    }

    nv_add_nvp (res, "open", "planlist");
    dbname = nv_get_val (req, "_DBNAME");
    dbmt_uid = nv_get_val (req, "_ID");
    if (dbname == NULL || dbmt_uid == NULL)
    {
        goto err_ts_get_autoexec_query;
    }
    nv_add_nvp (res, "dbname", dbname);

    while (fgets (line_buf, sizeof (line_buf), conf_file) != NULL)
    {
        ut_trim (line_buf);

        if (obsolete_version_autoexecquery_conf (line_buf))
        {
            conf_item_num = AUTOEXECQUERY_CONF_ENTRY_NUM - 2;
        }
        else
        {
            conf_item_num = AUTOEXECQUERY_CONF_ENTRY_NUM;
        }

        if (string_tokenize_accept_laststring_space
                (line_buf, conf_item, conf_item_num) < 0)
        {
            strcpy_limit (_dbmt_error,
                          "autoexecquery.conf contains syntax error.",
                           DBMT_ERROR_MSG_SIZE);
            retval = ERR_WITH_MSG;
            goto err_ts_get_autoexec_query;
        }

        if (strcmp (dbname, conf_item[0]) != 0
            || strcmp (dbmt_uid, conf_item[conf_item_num - 5]) != 0)
        {
            continue;
        }

        nv_add_nvp (res, "open", "queryplan");
        nv_add_nvp (res, "query_id", conf_item[1]);

        if (conf_item_num == AUTOEXECQUERY_CONF_ENTRY_NUM)
        {
            nv_add_nvp (res, ENCRYPT_ARG ("username"), conf_item[2]);
        }
        else
        {
            nv_add_nvp (res, ENCRYPT_ARG ("username"), NULL);
        }

        nv_add_nvp (res, "period", conf_item[conf_item_num - 4]);
        snprintf (exectime_detail, sizeof (exectime_detail) - 1, "%s %s",
                  conf_item[conf_item_num - 3], conf_item[conf_item_num - 2]);
        nv_add_nvp (res, "detail", exectime_detail);
        nv_add_nvp (res, "query_string", conf_item[conf_item_num - 1]);
        nv_add_nvp (res, "close", "queryplan");
    }

err_ts_get_autoexec_query:
    nv_add_nvp (res, "close", "planlist");
    fclose (conf_file);

    return retval;
}

int
ts_addstatustemplate (nvplist * cli_request, nvplist * cli_response,
                      char *diag_error)
{
    FILE *templatefile, *tempfile;
    char templatefilepath[PATH_MAX], tempfilepath[PATH_MAX];
    char buf[1024];
    char *templatename, *desc, *sampling_term, *dbname;
    int ret_val = ERR_NO_ERROR;

    templatename = nv_get_val (cli_request, "name");
    desc = nv_get_val (cli_request, "desc");
    sampling_term = nv_get_val (cli_request, "sampling_term");
    dbname = nv_get_val (cli_request, "db_name");

    if (templatename == NULL)
    {
        snprintf (diag_error, DBMT_ERROR_MSG_SIZE, "%s", "name");
        return ERR_PARAM_MISSING;
    }

    /* write related information to template config file */
    conf_get_dbmt_file (FID_DIAG_STATUS_TEMPLATE, templatefilepath);
    if (access (templatefilepath, F_OK) < 0)
    {
        templatefile = fopen (templatefilepath, "w");
        if (templatefile == NULL)
        {
            if (diag_error)
            {
                strcpy (diag_error, templatefilepath);
            }
            return ERR_FILE_OPEN_FAIL;
        }
        fclose (templatefile);
    }

    if ((templatefile = fopen (templatefilepath, "r")) == NULL)
    {
        if (diag_error)
        {
            strcpy (diag_error, templatefilepath);
        }
        return ERR_FILE_OPEN_FAIL;
    }

    snprintf (tempfilepath, PATH_MAX - 1, "%s/statustemplate_add.tmp",
              sco.dbmt_tmp_dir);
    if ((tempfile = fopen (tempfilepath, "w+")) == NULL)
    {
        if (diag_error)
        {
            strcpy (diag_error, tempfilepath);
        }
        fclose (templatefile);
        return ERR_FILE_OPEN_FAIL;
    }

    while (fgets (buf, sizeof (buf), templatefile))
    {
        if (strncmp (buf, "<<<", 3) == 0)
        {
            fprintf (tempfile, "%s", buf);

            /* template name */
            if (!(fgets (buf, sizeof (buf), templatefile)))
            {
                break;
            }
            buf[strlen (buf) - 1] = '\0';
            if (strcmp (buf, templatename) == 0)
            {
                strcpy (diag_error, templatename);
                ret_val = ERR_TEMPLATE_ALREADY_EXIST;
                break;
            }

            fprintf (tempfile, "%s\n", buf);

            /* copy others */
            while (fgets (buf, sizeof (buf), templatefile))
            {
                fprintf (tempfile, "%s", buf);
                if (strncmp (buf, ">>>", 3) == 0)
                {
                    break;
                }
            }
        }
    }

    if (ret_val == ERR_NO_ERROR)
    {
        int i, config_index, config_length;
        char *target_name, *target_value;

        /* add new template config */
        fprintf (tempfile, "<<<\n");
        fprintf (tempfile, "%s\n", templatename);
        if (desc)
        {
            fprintf (tempfile, "%s\n", desc);
        }
        else
        {
            fprintf (tempfile, " \n");
        }

        if (dbname)
        {
            fprintf (tempfile, "%s\n", dbname);
        }
        else
        {
            fprintf (tempfile, " \n");
        }

        fprintf (tempfile, "%s\n", sampling_term);

        if (nv_locate
                (cli_request, "target_config", &config_index, &config_length) != 1)
        {
            ret_val = ERR_REQUEST_FORMAT;
        }
        else
        {
            for (i = config_index; i < config_index + config_length; i++)
            {
                if (nv_lookup (cli_request, i, &target_name, &target_value) == 1)
                {
                    fprintf (tempfile, "%s %s\n", target_name, target_value);
                }
                else
                {
                    ret_val = ERR_REQUEST_FORMAT;
                    break;
                }
            }
            fprintf (tempfile, ">>>\n");
        }
    }

    fclose (tempfile);
    fclose (templatefile);

    if (ret_val == ERR_NO_ERROR)
    {
        unlink (templatefilepath);
        rename (tempfilepath, templatefilepath);
    }
    else
    {
        unlink (tempfilepath);
    }

    return ret_val;
}

int
ts_removestatustemplate (nvplist * cli_request, nvplist * cli_response,
                         char *diag_error)
{
    FILE *templatefile, *tempfile;
    char templatefilepath[PATH_MAX], tempfilepath[PATH_MAX];
    char buf[1024];
    char *templatename;
    int ret_val = ERR_NO_ERROR;

    templatename = nv_get_val (cli_request, "name");

    if (templatename == NULL)
    {
        snprintf (diag_error, DBMT_ERROR_MSG_SIZE, "%s", "name");
        return ERR_PARAM_MISSING;
    }

    /* write related information to template config file */
    conf_get_dbmt_file (FID_DIAG_STATUS_TEMPLATE, templatefilepath);
    if ((templatefile = fopen (templatefilepath, "r")) == NULL)
    {
        if (diag_error)
        {
            strcpy (diag_error, templatefilepath);
        }
        return ERR_FILE_OPEN_FAIL;
    }

    snprintf (tempfilepath, PATH_MAX - 1, "%s/statustemplate_remove.tmp",
              sco.dbmt_tmp_dir);
    if ((tempfile = fopen (tempfilepath, "w+")) == NULL)
    {
        if (diag_error)
        {
            strcpy (diag_error, tempfilepath);
        }
        fclose (templatefile);
        return ERR_FILE_OPEN_FAIL;
    }

    while (fgets (buf, sizeof (buf), templatefile))
    {
        if (strncmp (buf, "<<<", 3) == 0)
        {
            /* template name */
            if (!(fgets (buf, sizeof (buf), templatefile)))
            {
                break;
            }
            buf[strlen (buf) - 1] = '\0';
            if (strcmp (buf, templatename) == 0)
            {
                continue;
            }

            fprintf (tempfile, "<<<\n");
            fprintf (tempfile, "%s\n", buf);

            /* copy others */
            while (fgets (buf, sizeof (buf), templatefile))
            {
                fprintf (tempfile, "%s", buf);
                if (strncmp (buf, ">>>", 3) == 0)
                {
                    break;
                }
            }
        }
    }

    fclose (tempfile);
    fclose (templatefile);

    if (ret_val == ERR_NO_ERROR)
    {
        unlink (templatefilepath);
        rename (tempfilepath, templatefilepath);
    }
    else
    {
        unlink (tempfilepath);
    }

    return ret_val;
}

int
ts_updatestatustemplate (nvplist * cli_request, nvplist * cli_response,
                         char *diag_error)
{
    FILE *templatefile, *tempfile;
    char templatefilepath[PATH_MAX], tempfilepath[PATH_MAX];
    char buf[1024];
    char *templatename, *desc, *sampling_term, *dbname;
    int ret_val = ERR_NO_ERROR;

    templatename = nv_get_val (cli_request, "name");
    desc = nv_get_val (cli_request, "desc");
    sampling_term = nv_get_val (cli_request, "sampling_term");
    dbname = nv_get_val (cli_request, "db_name");

    if (templatename == NULL)
    {
        snprintf (diag_error, DBMT_ERROR_MSG_SIZE, "%s", "name");
        return ERR_PARAM_MISSING;
    }

    /* write related information to template config file */
    conf_get_dbmt_file (FID_DIAG_STATUS_TEMPLATE, templatefilepath);
    if ((templatefile = fopen (templatefilepath, "r")) == NULL)
    {
        if (diag_error)
        {
            strcpy (diag_error, templatefilepath);
        }
        return ERR_FILE_OPEN_FAIL;
    }

    snprintf (tempfilepath, PATH_MAX - 1, "%s/statustemplate_update_%d.tmp",
              sco.dbmt_tmp_dir, getpid ());
    if ((tempfile = fopen (tempfilepath, "w+")) == NULL)
    {
        if (diag_error)
        {
            strcpy (diag_error, tempfilepath);
        }
        fclose (templatefile);
        return ERR_FILE_OPEN_FAIL;
    }

    while (fgets (buf, sizeof (buf), templatefile))
    {
        if (strncmp (buf, "<<<", 3) == 0)
        {
            fprintf (tempfile, "%s", buf);

            /* template name */
            if (!(fgets (buf, sizeof (buf), templatefile)))
            {
                break;
            }
            buf[strlen (buf) - 1] = '\0';
            if (strcmp (buf, templatename) == 0)
            {
                int i, config_index, config_length;
                char *target_name, *target_value;

                /* add new configuration */
                fprintf (tempfile, "%s\n", templatename);
                if (desc)
                {
                    fprintf (tempfile, "%s\n", desc);
                }
                else
                {
                    fprintf (tempfile, " \n");
                }

                if (dbname)
                {
                    fprintf (tempfile, "%s\n", dbname);
                }
                else
                {
                    fprintf (tempfile, " \n");
                }

                fprintf (tempfile, "%s\n", sampling_term);

                if (nv_locate
                        (cli_request, "target_config", &config_index,
                        &config_length) != 1)
                {
                    ret_val = ERR_REQUEST_FORMAT;
                    break;
                }
                else
                {
                    for (i = config_index; i < config_index + config_length; i++)
                    {
                        if (nv_lookup
                                (cli_request, i, &target_name, &target_value) == 1)
                        {
                            fprintf (tempfile, "%s %s\n", target_name, target_value);
                        }
                        else
                        {
                            ret_val = ERR_REQUEST_FORMAT;
                            break;
                        }
                    }
                    if (ret_val != ERR_NO_ERROR)
                    {
                        break;
                    }
                    fprintf (tempfile, ">>>\n");
                }

                continue;
            }

            fprintf (tempfile, "%s\n", buf);

            /* copy others */
            while (fgets (buf, sizeof (buf), templatefile))
            {
                fprintf (tempfile, "%s", buf);
                if (strncmp (buf, ">>>", 3) == 0)
                {
                    break;
                }
            }
        }
    }

    fclose (tempfile);
    fclose (templatefile);

    if (ret_val == ERR_NO_ERROR)
    {
        unlink (templatefilepath);
        rename (tempfilepath, templatefilepath);
    }
    else
    {
        unlink (tempfilepath);
    }

    return ret_val;
}

int
ts_getstatustemplate (nvplist * cli_request, nvplist * cli_response,
                      char *diag_error)
{
    FILE *templatefile;
    char templatefilepath[PATH_MAX];
    char buf[1024];
    char *templatename;
    char targetname[100], targetcolor[8], targetmag[32];
    int ret_val = ERR_NO_ERROR;

    templatename = nv_get_val (cli_request, "name");

    /* write related information to template config file */
    conf_get_dbmt_file (FID_DIAG_STATUS_TEMPLATE, templatefilepath);
    if ((templatefile = fopen (templatefilepath, "r")) == NULL)
    {
        return ERR_NO_ERROR;
    }
#ifdef JSON_SUPPORT
    nv_add_nvp (cli_response, "open", "templatelist");
#else
    nv_add_nvp (cli_response, "start", "templatelist");
#endif
    while (fgets (buf, sizeof (buf), templatefile))
    {
        if (strncmp (buf, "<<<", 3) == 0)
        {
            /* template name */
            if (!(fgets (buf, sizeof (buf), templatefile)))
            {
                break;
            }
            buf[strlen (buf) - 1] = '\0';
            if (templatename)
            {
                if (strcmp (buf, templatename) != 0)
                {
                    continue;
                }
            }
#ifdef JSON_SUPPORT
            nv_add_nvp (cli_response, "open", "template");
#else
            nv_add_nvp (cli_response, "start", "template");
#endif
            nv_add_nvp (cli_response, "name", buf);
            if (!fgets (buf, sizeof (buf), templatefile))
            {
                ret_val = ERR_WITH_MSG;
                if (diag_error)
                {
                    strcpy (diag_error, "Invalid file format\n");
                    strcat (diag_error, templatefilepath);
                }

                break;
            }
            buf[strlen (buf) - 1] = '\0';
            nv_add_nvp (cli_response, "desc", buf);

            if (!fgets (buf, sizeof (buf), templatefile))
            {
                ret_val = ERR_WITH_MSG;
                if (diag_error)
                {
                    strcpy (diag_error, "Invalid file format\n");
                    strcat (diag_error, templatefilepath);
                }

                break;
            }
            buf[strlen (buf) - 1] = '\0';
            nv_add_nvp (cli_response, "db_name", buf);

            if (!fgets (buf, sizeof (buf), templatefile))
            {
                ret_val = ERR_WITH_MSG;
                if (diag_error)
                {
                    strcpy (diag_error, "Invalid file format\n");
                    strcat (diag_error, templatefilepath);
                }

                break;
            }
            buf[strlen (buf) - 1] = '\0';
            nv_add_nvp (cli_response, "sampling_term", buf);
#ifdef JSON_SUPPORT
            nv_add_nvp (cli_response, "close", "target_config");
#else
            nv_add_nvp (cli_response, "start", "target_config");
#endif
            while (fgets (buf, sizeof (buf), templatefile))
            {
                int matched;
                if (strncmp (buf, ">>>", 3) == 0)
                {
                    break;
                }
                matched =
                    sscanf (buf, "%99s %7s %31s", targetname, targetcolor,
                            targetmag);
                if (matched != 3)
                {
                    continue;    /* error file format */
                }
                nv_add_nvp (cli_response, targetname, targetcolor);
                nv_add_nvp (cli_response, targetname, targetmag);
            }

#ifdef JSON_SUPPORT
            nv_add_nvp (cli_response, "close", "target_config");
            nv_add_nvp (cli_response, "close", "template");
#else
            nv_add_nvp (cli_response, "end", "target_config");
            nv_add_nvp (cli_response, "end", "template");
#endif

        }
    }
#ifdef JSON_SUPPORT
    nv_add_nvp (cli_response, "close", "templatelist");
#else
    nv_add_nvp (cli_response, "end", "templatelist");
#endif

    fclose (templatefile);

  return ret_val;
}


int
ts_analyzecaslog (nvplist * cli_request, nvplist * cli_response,
                  char *diag_error)
{
    int retval, i, arg_index;
    int matched, sect, sect_len;
    char tmpfileQ[PATH_MAX], tmpfileRes[PATH_MAX], tmpfileT[PATH_MAX],
        tmpfileanalyzeresult[PATH_MAX];
    char *logfile, *option_t;
    char cmd_name[CUBRID_CMD_NAME_LEN];
    char diag_err_file[PATH_MAX];
    const char *argv[256];
    char buf[1024], logbuf[2048];
    char qnum[16], max[32], min[32], avg[32], cnt[16], err[16];
    FILE *fdRes, *fdQ, *fdT, *fdAnalyzeResult;
#if defined(WINDOWS)
    DWORD th_id;
#else
    T_THREAD th_id;
#endif
    diag_err_file[0] = '\0';

    logfile = nv_get_val (cli_request, "logfile");
    option_t = nv_get_val (cli_request, "option_t");

    /* set prarameter with logfile and execute broker_log_top */
    /* execute at current directory and copy result to $CUBRID/tmp directory */
    snprintf (cmd_name, sizeof (cmd_name) - 1, "%s/bin/broker_log_top%s",
              sco.szCubrid, DBMT_EXE_EXT);
    arg_index = 0;
    argv[arg_index++] = cmd_name;
    if (option_t && !strcmp (option_t, "yes"))
    {
        argv[arg_index++] = "-t";
    }
    nv_locate (cli_request, "logfilelist", &sect, &sect_len);
    if (sect == -1)
    {
        snprintf (diag_error, DBMT_ERROR_MSG_SIZE, "%s", "logfilelist");
        return ERR_PARAM_MISSING;
    }
    for (i = 0; i < sect_len; i++)
    {
        nv_lookup (cli_request, sect + i, NULL, &logfile);
        if (logfile)
        {
            argv[arg_index++] = logfile;
        }
    }
    argv[arg_index++] = NULL;
    snprintf (diag_err_file, PATH_MAX, "%s/%s.%u.err.tmp",
              sco.dbmt_tmp_dir, "analyzecaslog", getpid ());

    retval = run_child (argv, 1, NULL, NULL, diag_err_file, NULL);    /* broker_log_top */
    if (read_error_file (diag_err_file, diag_error, DBMT_ERROR_MSG_SIZE) < 0)
    {
        if (access (diag_err_file, F_OK) == 0)
        {
            unlink (diag_err_file);
        }
        return ERR_WITH_MSG;
    }

    if (access (diag_err_file, F_OK) == 0)
    {
        unlink (diag_err_file);
    }

    if (retval < 0)
    {
        if (diag_error)
        {
            strcpy (diag_error, argv[0]);
        }
        return ERR_SYSTEM_CALL;
    }

    snprintf (tmpfileanalyzeresult, PATH_MAX - 1, "%s/analyzelog_%d.res",
              sco.dbmt_tmp_dir, (int) getpid ());
    fdAnalyzeResult = fopen (tmpfileanalyzeresult, "w+");
    if (fdAnalyzeResult == NULL)
    {
        if (diag_error)
        {
            strcpy (diag_error, "Tmpfile");
        }
        return ERR_FILE_OPEN_FAIL;
    }

    if ((option_t != NULL) && (strcmp (option_t, "yes") == 0))
    {
        int log_init_flag, log_index;

        snprintf (tmpfileT, PATH_MAX - 1, "%s/log_top_%d.t", sco.dbmt_tmp_dir,
                  (int) getpid ());
        rename ("./log_top.t", tmpfileT);

        fdT = fopen (tmpfileT, "r");
        if (fdT == NULL)
        {
            if (diag_error)
            {
                strcpy (diag_error, "log_top.t");
            }
            fclose (fdAnalyzeResult);
            return ERR_FILE_OPEN_FAIL;
        }

        log_index = 1;
        log_init_flag = 1;
#ifdef JSON_SUPPORT
        nv_add_nvp (cli_response, "open", "resultlist");
#else
        nv_add_nvp (cli_response, "resultlist", "start");
#endif
        while (fgets (buf, sizeof (buf), fdT))
        {
            char *time_str = NULL;
            const char *exec_time_tag = "*** elapsed time";

            if (strlen (buf) == 1)
            {
                continue;
            }

            if (log_init_flag == 1)
            {
#ifdef JSON_SUPPORT
                nv_add_nvp (cli_response, "open", "result");
#else
                nv_add_nvp (cli_response, "result", "start");
#endif
                snprintf (qnum, sizeof (qnum) - 1, "[Q%d]", log_index);
                fprintf (fdAnalyzeResult, "%s\n", qnum);
                nv_add_nvp (cli_response, "qindex", qnum);
                log_index++;
                log_init_flag = 0;
            }

            if ((time_str = strstr (buf, exec_time_tag)) != NULL)
            {
                time_str += strlen (exec_time_tag);
                ut_trim (time_str);

                nv_add_nvp (cli_response, "exec_time", time_str);
#ifdef JSON_SUPPORT
                nv_add_nvp (cli_response, "close", "result");
#else
                nv_add_nvp (cli_response, "result", "end");
#endif
                log_init_flag = 1;
            }
            else
            {
                fprintf (fdAnalyzeResult, "%s", buf);
            }
        }
#ifdef JSON_SUPPORT
        nv_add_nvp (cli_response, "close", "resultlist");
#else
        nv_add_nvp (cli_response, "resultlist", "end");
#endif

        fclose (fdT);
        unlink (tmpfileT);
    }
    else
    {
#if defined(WINDOWS)
        th_id = GetCurrentThreadId ();
#else
        th_id = getpid ();
#endif
        snprintf (tmpfileQ, PATH_MAX - 1, "%s/log_top_%lu.q", sco.dbmt_tmp_dir,
                  th_id);
        snprintf (tmpfileRes, PATH_MAX - 1, "%s/log_top_%lu.res",
                  sco.dbmt_tmp_dir, th_id);

        rename ("./log_top.q", tmpfileQ);
        rename ("./log_top.res", tmpfileRes);

        fdQ = fopen (tmpfileQ, "r");
        if (fdQ == NULL)
        {
            if (diag_error)
            {
                strcpy (diag_error, "log_top.q");
            }
            fclose (fdAnalyzeResult);
            return ERR_FILE_OPEN_FAIL;
        }

        fdRes = fopen (tmpfileRes, "r");
        if (fdRes == NULL)
        {
            if (diag_error)
            {
                strcpy (diag_error, "log_top.res");
            }
            fclose (fdAnalyzeResult);
            fclose (fdQ);
            return ERR_FILE_OPEN_FAIL;
        }

        memset (buf, '\0', sizeof (buf));
        memset (logbuf, '\0', sizeof (logbuf));
#ifdef JSON_SUPPORT
        nv_add_nvp (cli_response, "open", "resultlist");
#else
        nv_add_nvp (cli_response, "resultlist", "start");
#endif
        /* read result, log file and create msg with them */
        while (fgets (buf, sizeof (buf), fdRes))
        {
            if (strlen (buf) == 1)
            {
                continue;
            }

            if (!strncmp (buf, "[Q", 2))
            {
#ifdef JSON_SUPPORT
                nv_add_nvp (cli_response, "open", "result");
#else
                nv_add_nvp (cli_response, "result", "start");
#endif
                matched =
                    sscanf (buf, "%15s %31s %31s %31s %15s %15s", qnum, max, min,
                            avg, cnt, err);
                if (matched != 6)
                {
                    continue;
                }
                nv_add_nvp (cli_response, "qindex", qnum);
                nv_add_nvp (cli_response, "max", max);
                nv_add_nvp (cli_response, "min", min);
                nv_add_nvp (cli_response, "avg", avg);
                nv_add_nvp (cli_response, "cnt", cnt);
                if (strlen (err))
                {
                    err[strlen (err) - 1] = '\0';
                }
                nv_add_nvp (cli_response, "err", err + 1);

                fprintf (fdAnalyzeResult, "%s\n", qnum);

                while (strncmp (logbuf, qnum, 4) != 0)
                {
                    if (fgets (logbuf, sizeof (logbuf), fdQ) == NULL)
                    {
                        if (diag_error)
                        {
                            strcpy (diag_error,
                                    "log_top.q file format is not valid");
                        }
                        fclose (fdRes);
                        fclose (fdQ);
                        fclose (fdAnalyzeResult);
                        return ERR_WITH_MSG;
                    }
                }

                while (fgets (logbuf, sizeof (logbuf), fdQ))
                {
                    if (!strncmp (logbuf, "[Q", 2))
                    {
                        break;
                    }
                    fprintf (fdAnalyzeResult, "%s", logbuf);
                }
#ifdef JSON_SUPPORT
                nv_add_nvp (cli_response, "close", "result");
#else
                nv_add_nvp (cli_response, "result", "end");
#endif
            }
        }
#ifdef JSON_SUPPORT
        nv_add_nvp (cli_response, "close", "resultlist");
#else
        nv_add_nvp (cli_response, "resultlist", "end");
#endif

        fclose (fdRes);
        fclose (fdQ);

        unlink (tmpfileQ);
        unlink (tmpfileRes);
    }

    fclose (fdAnalyzeResult);
    nv_add_nvp (cli_response, "resultfile", tmpfileanalyzeresult);

    return ERR_NO_ERROR;
}

int
ts_executecasrunner (nvplist * cli_request, nvplist * cli_response,
                     char *diag_error)
{
    int i, sect, sect_len;
    char *log_string, *brokername, *username, *passwd;
    char *num_thread, *repeat_count, *show_queryresult;
    char *dbname, *casrunnerwithFile, *logfilename;
    char *show_queryplan;
    char bport[6], buf[1024];
    FILE *flogfile, *fresfile2;
    char tmplogfilename[PATH_MAX], resfile[PATH_MAX], resfile2[PATH_MAX];
    char log_converter_res[PATH_MAX];
    char cmd_name[CUBRID_CMD_NAME_LEN];
    const char *argv[25];
    T_CM_BROKER_CONF uc_conf;
    char out_msg_file_env[1024];
    T_CM_ERROR error;
#if defined(WINDOWS)
    DWORD th_id;
#else
    T_THREAD th_id;
#endif
    char use_tmplogfile = FALSE;

    brokername = nv_get_val (cli_request, "brokername");
    dbname = nv_get_val (cli_request, "dbname");
    username = nv_get_val (cli_request, "username");
    passwd = nv_get_val (cli_request, "passwd");
    num_thread = nv_get_val (cli_request, "num_thread");
    repeat_count = nv_get_val (cli_request, "repeat_count");
    show_queryresult = nv_get_val (cli_request, "show_queryresult");
    show_queryplan = nv_get_val (cli_request, "show_queryplan");
    casrunnerwithFile = nv_get_val (cli_request, "executelogfile");
    logfilename = nv_get_val (cli_request, "logfile");

    if (brokername == NULL)
    {
        snprintf (diag_error, DBMT_ERROR_MSG_SIZE, "%s", "brokername");
        return ERR_PARAM_MISSING;
    }

    if (dbname == NULL)
    {
        snprintf (diag_error, DBMT_ERROR_MSG_SIZE, "%s", "dbname");
        return ERR_PARAM_MISSING;
    }

    if (username == NULL)
    {
        snprintf (diag_error, DBMT_ERROR_MSG_SIZE, "%s", "username");
        return ERR_PARAM_MISSING;
    }

#if defined(WINDOWS)
    th_id = GetCurrentThreadId ();
#else
    th_id = getpid ();
#endif

    snprintf (resfile, PATH_MAX - 1, "%s/log_run_%lu.res", sco.dbmt_tmp_dir,
              th_id);
    snprintf (resfile2, PATH_MAX - 1, "%s/log_run_%lu.res2", sco.dbmt_tmp_dir,
              th_id);

    /* get right port number with broker name */
    if (cm_get_broker_conf (&uc_conf, NULL, &error) < 0)
    {
        strcpy (diag_error, error.err_msg);
        return ERR_WITH_MSG;
    }

    memset (bport, 0x0, sizeof (bport));
    for (i = 0; i < uc_conf.num_broker; i++)
    {
        char *confvalue = cm_br_conf_get_value (&(uc_conf.br_conf[i]), "%");

        if ((confvalue != NULL) && (strcmp (brokername, confvalue) == 0))
        {
            confvalue =
                cm_br_conf_get_value (&(uc_conf.br_conf[i]), "BROKER_PORT");
            if (confvalue != NULL)
            {
                snprintf (bport, sizeof (bport) - 1, "%s", confvalue);
            }
            break;
        }
    }

    cm_broker_conf_free (&uc_conf);

    if ((casrunnerwithFile != NULL) && (strcmp (casrunnerwithFile, "yes") == 0)
        && (logfilename != NULL))
    {
        snprintf (tmplogfilename, PATH_MAX - 1, "%s", logfilename);
    }
    else
    {
        use_tmplogfile = TRUE;
        /* create logfile */
        snprintf (tmplogfilename, PATH_MAX - 1, "%s/cas_log_tmp_%lu.q",
                  sco.dbmt_tmp_dir, th_id);

        flogfile = fopen (tmplogfilename, "w+");
        if (!flogfile)
        {
            return ERR_FILE_OPEN_FAIL;
        }

        nv_locate (cli_request, "logstring", &sect, &sect_len);
        if (sect >= 0)
        {
            for (i = 0; i < sect_len; ++i)
            {
                nv_lookup (cli_request, sect + i, NULL, &log_string);
                fprintf (flogfile, "%s\n",
                         (log_string == NULL) ? " " : log_string);
            }
        }
        fclose (flogfile);
    }

    /* execute broker_log_converter why logfile is created */
    snprintf (log_converter_res, PATH_MAX - 1, "%s/log_converted_%lu.q_res",
              sco.dbmt_tmp_dir, th_id);
    snprintf (cmd_name, sizeof (cmd_name) - 1, "%s/bin/broker_log_converter%s",
              sco.szCubrid, DBMT_EXE_EXT);

    i = 0;
    argv[i] = cmd_name;
    argv[++i] = tmplogfilename;
    argv[++i] = log_converter_res;
    argv[++i] = NULL;

    if (run_child (argv, 1, NULL, NULL, NULL, NULL) < 0)
    {                /* broker_log_converter */
        strcpy (diag_error, argv[0]);
        return ERR_SYSTEM_CALL;
    }

    /* execute broker_log_runner through logfile that converted */
    snprintf (cmd_name, sizeof (cmd_name) - 1, "%s/bin/broker_log_runner%s",
              sco.szCubrid, DBMT_EXE_EXT);
    i = 0;
    argv[i] = cmd_name;
    argv[++i] = "-I";
    argv[++i] = "localhost";
    argv[++i] = "-P";
    argv[++i] = bport;
    argv[++i] = "-d";
    argv[++i] = dbname;
    argv[++i] = "-u";
    argv[++i] = username;
    if (passwd)
    {
        argv[++i] = "-p";
        argv[++i] = passwd;
    }
    argv[++i] = "-t";
    argv[++i] = num_thread;
    argv[++i] = "-r";
    argv[++i] = repeat_count;
    if (show_queryplan && !strcmp (show_queryplan, "yes"))
    {
        argv[++i] = "-Q";
    }
    argv[++i] = "-o";
    argv[++i] = resfile;
    argv[++i] = log_converter_res;
    argv[++i] = NULL;

    snprintf (out_msg_file_env, sizeof (out_msg_file_env) - 1,
              "CUBRID_MANAGER_OUT_MSG_FILE=%s", resfile2);
    putenv (out_msg_file_env);

    if (run_child (argv, 1, NULL, NULL, NULL, NULL) < 0)
    {                /* broker_log_runner */
        return ERR_SYSTEM_CALL;
    }

  /* create message with read file's content */
#ifdef JSON_SUPPORT
    nv_add_nvp (cli_response, "open", "result_list");
#else
    nv_add_nvp (cli_response, "result_list", "start");
#endif

    fresfile2 = fopen (resfile2, "r");
    if (fresfile2)
    {
        while (fgets (buf, sizeof (buf), fresfile2))
        {
            if (!strncmp (buf, "cas_ip", 6))
                continue;
            if (!strncmp (buf, "cas_port", 8))
                continue;
            if (!strncmp (buf, "num_thread", 10))
                continue;
            if (!strncmp (buf, "repeat", 6))
                continue;
            if (!strncmp (buf, "dbname", 6))
                continue;
            if (!strncmp (buf, "dbuser", 6))
                continue;
            if (!strncmp (buf, "dbpasswd", 6))
                continue;
            if (!strncmp (buf, "result_file", 11))
                continue;

            buf[strlen (buf) - 1] = '\0';    /* remove new line ch */
            nv_add_nvp (cli_response, "result", buf);
        }
        fclose (fresfile2);
    }
#ifdef JSON_SUPPORT
    nv_add_nvp (cli_response, "close", "result_list");
#else
    nv_add_nvp (cli_response, "result_list", "end");
#endif
    nv_add_nvp (cli_response, "query_result_file", resfile);
    nv_add_nvp (cli_response, "query_result_file_num", num_thread);

    if ((show_queryresult != NULL) && !strcmp (show_queryresult, "no"))
    {
        /* remove query result file - resfile */
        int i, n = 0;
        char filename[PATH_MAX];
        if (num_thread != NULL)
        {
            n = atoi (num_thread);
        }

        for (i = 0; i < n && i < MAX_SERVER_THREAD_COUNT; i++)
        {
            snprintf (filename, PATH_MAX - 1, "%s.%d", resfile, i);
            unlink (filename);
        }
    }

    unlink (log_converter_res);    /* broker_log_converter execute result */
    unlink (resfile2);        /* cas log execute result */

    if (use_tmplogfile == TRUE)
    {
        unlink (tmplogfilename);    /* temp logfile */
    }
    return ERR_NO_ERROR;
}

int
ts_removecasrunnertmpfile (nvplist * cli_request, nvplist * cli_response,
                           char *diag_error)
{
    char command[PATH_MAX];
    char filename[PATH_MAX];
    char cubrid_tmp_path[PATH_MAX];
    char *fullpath_with_filename = NULL;

    const char *casrunnertmp_short[] =
        { "log_converted", "cas_log_tmp", "log_run" };
    unsigned int casrunnertmp_short_num =
        sizeof (casrunnertmp_short) / sizeof (casrunnertmp_short[0]);
    unsigned int i = 0;
    int valid_casrunnertmpfile = 0;

    command[0] = '\0';
    filename[0] = '\0';
    cubrid_tmp_path[0] = '\0';

    fullpath_with_filename = nv_get_val (cli_request, "filename");
    if (fullpath_with_filename == NULL)
    {
        snprintf (diag_error, DBMT_ERROR_MSG_SIZE, "%s", "filename");
        return ERR_PARAM_MISSING;
    }

    /* check permission : must under $CUBRID/tmp/ */
#if defined(WINDOWS)
    snprintf (cubrid_tmp_path, PATH_MAX, "%s\\", sco.dbmt_tmp_dir);
#else
    snprintf (cubrid_tmp_path, PATH_MAX, "%s/", sco.dbmt_tmp_dir);
#endif

    if (strstr (fullpath_with_filename, cubrid_tmp_path) == NULL)
    {
        snprintf (diag_error, DBMT_ERROR_MSG_SIZE, "%s",
                  fullpath_with_filename);
        return ERR_PERMISSION;
    }

    if (ut_get_filename (fullpath_with_filename, 1, filename) != 0)
    {
        snprintf (diag_error, DBMT_ERROR_MSG_SIZE, "%s",
                  fullpath_with_filename);
        return ERR_PERMISSION;
    }

    for (i = 0; i < casrunnertmp_short_num; i++)
    {
        if (strstr (filename, casrunnertmp_short[i]) != NULL)
        {
            valid_casrunnertmpfile = 1;
            break;
        }
    }

    if (valid_casrunnertmpfile == 0)
    {
        snprintf (diag_error, DBMT_ERROR_MSG_SIZE, "%s",
                  fullpath_with_filename);
        return ERR_PERMISSION;
    }

#if defined(WINDOWS)
    snprintf (command, sizeof (command), "%s %s %s", DEL_FILE,
              DEL_FILE_OPT, fullpath_with_filename);
#else
    snprintf (command, sizeof (command), "%s %s %s", DEL_DIR, DEL_DIR_OPT,
              fullpath_with_filename);
#endif

    if (system (command) == -1)
    {
        snprintf (diag_error, DBMT_ERROR_MSG_SIZE, "%s",
                  fullpath_with_filename);
        return ERR_DIR_REMOVE_FAIL;
    }
    return ERR_NO_ERROR;
}

int
ts_getcaslogtopresult (nvplist * cli_request, nvplist * cli_response,
                       char *diag_error)
{
    char *filename, *qindex;
    FILE *fd;
    char buf[1024];
    int find_flag;

    filename = nv_get_val (cli_request, "filename");
    if (filename == NULL)
    {
        snprintf (diag_error, DBMT_ERROR_MSG_SIZE, "%s", "filename");
        return ERR_PARAM_MISSING;
    }

    qindex = nv_get_val (cli_request, "qindex");
    if (qindex == NULL)
    {
        snprintf (diag_error, DBMT_ERROR_MSG_SIZE, "%s", "qindex");
        return ERR_PARAM_MISSING;
    }

    fd = fopen (filename, "r");
    if (!fd)
    {
        return ERR_FILE_OPEN_FAIL;
    }

    find_flag = 0;
#ifndef JSON_SUPPORT
    nv_add_nvp (cli_response, "logstringlist", "start");
#endif
    while (fgets (buf, sizeof (buf), fd))
    {
        if (!strncmp (buf, "[Q", 2))
        {
            if (find_flag == 1)
            {
                break;
            }
            if (!strncmp (buf, qindex, strlen (qindex)))
                {
                find_flag = 1;
                continue;
            }
        }

        if (find_flag == 1)
        {
            buf[strlen (buf) - 1] = '\0';
#ifdef JSON_SUPPORT
            nv_add_nvp (cli_response, "open", "logstringlist");
#endif
            nv_add_nvp (cli_response, "logstring", buf);
#ifdef JSON_SUPPORT
            nv_add_nvp (cli_response, "close", "logstringlist");
#endif
        }
    }
#ifndef JSON_SUPPORT
    nv_add_nvp (cli_response, "logstringlist", "end");
#endif
    fclose (fd);
    return ERR_NO_ERROR;
}

int
dbmt_user_is_dba (char *dbuser, const char *out_file)
{
    FILE *fp;
    char buf[1024];
    int res_flag = 0;
    int res = 0;

    buf[0] = '\0';

    if (out_file == NULL || dbuser == NULL)
    {
        return 0;
    }

    if (strcasecmp ("DBA", dbuser) == 0)
    {
        return 1;
    }

    fp = fopen (out_file, "r");
    if (fp == NULL)
    {
        return 0;
    }

    while (fgets (buf, sizeof (buf) - 1, fp))
    {
        ut_trim (buf);
        if (strncmp (buf, "=", 1) == 0)
        {
            continue;
        }

        if (strstr (buf, "count(*)"))
        {
            res_flag = 1;
            continue;
        }

        if (res_flag)
        {
            if (strstr (buf, "0"))
            {
                res = 0;
                break;
            }
            else
            {
                res = 1;
                break;
            }
        }
    }
    fclose (fp);

    return res;
}

int
cmd_dbmt_user_login (nvplist * in, nvplist * out, char *_dbmt_error)
{
    int errcode;
    char *targetid, *dbname, *dbuser, *dbpasswd;
    int isdba = 0;
    char outfile[PATH_MAX];
    static int cmdid = 0;
    const char *statement =
        "SELECT COUNT( * ) FROM db_user d WHERE {'DBA'} SUBSETEQ (SELECT SET{CURRENT_USER}+COALESCE(SUM(SET{t.g.name}), SET{}) from db_user u, TABLE(groups) AS t( g ) WHERE u.name = d.name) AND d.name=CURRENT_USER;";

    targetid = nv_get_val (in, "targetid");
    dbname = nv_get_val (in, "dbname");
    dbuser = nv_get_val (in, "dbuser");
    dbpasswd = nv_get_val (in, "dbpasswd");

    if (dbname == NULL)
    {
        strcpy (_dbmt_error, "dbname");
        return ERR_PARAM_MISSING;
    }

    if (dbuser == NULL)
    {
        strcpy (_dbmt_error, "dbuser");
        return ERR_PARAM_MISSING;
    }

    nv_add_nvp (out, "targetid", targetid);
    nv_add_nvp (out, "dbname", dbname);

    snprintf (outfile, sizeof (outfile) - 1, "%s/tmp/DBMT_user_login.%d",
              sco.szCubrid, cmdid++);
    errcode =
        run_csql_statement (statement, dbname, dbuser, dbpasswd, outfile, _dbmt_error);
    if (errcode != ERR_NO_ERROR)
        return errcode;

    isdba = dbmt_user_is_dba (dbuser, outfile);
    if (isdba)
    {
        nv_add_nvp (out, "authority", "isdba");
    }
    else
    {
        nv_add_nvp (out, "authority", "isnotdba");
    }
    _update_nvplist_name (out, "targetid", ENCRYPT_ARG ("targetid"));
    unlink (outfile);
    return ERR_NO_ERROR;
}



int
tsDBMTUserLogin (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char hexacoded[PASSWD_ENC_LENGTH];
    int ret;
    T_DBMT_CON_DBINFO con_dbinfo;
    char *dbname, *dbpasswd, *dbuser;
    char *ip, *port;

    ret = cmd_dbmt_user_login (req, res, _dbmt_error);
    if (ret != ERR_NO_ERROR)
    {
        return ret;
    }

    ip = nv_get_val (req, "_IP");
    port = nv_get_val (req, "_PORT");
    dbname = nv_get_val (req, "dbname");
    dbpasswd = nv_get_val (req, "dbpasswd");
    dbuser = nv_get_val (req, "dbuser");

    if (dbpasswd != NULL && strlen (dbpasswd) > PASSWD_LENGTH)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE,
                  "The input DB password is more than maximum password length %d.",
                  PASSWD_LENGTH);
        return ERR_WITH_MSG;
    }

    /* update dbinfo to conlist */
    uEncrypt (PASSWD_LENGTH, dbpasswd, hexacoded);
    memset (&con_dbinfo, 0, sizeof (T_DBMT_CON_DBINFO));
    dbmt_con_set_dbinfo (&con_dbinfo, dbname, dbuser, hexacoded);
    if (dbmt_con_write_dbinfo (&con_dbinfo, ip, port, dbname, 1, _dbmt_error) < 0)
    {
        return ERR_WITH_MSG;
    }

    _update_nvplist_name (res, "targetid", ENCRYPT_ARG ("targetid"));

    return ERR_NO_ERROR;
}


int
ts_remove_log (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char *path = NULL;
    FILE *output = NULL;
    int i = 0;
    int sect = -1;
    int sect_len = 0;
    int as_id = 0;
    char broker_name[PATH_MAX];
    char command[PATH_MAX];
    char full_path_buf[PATH_MAX];
    char buf[PATH_MAX];
    T_CM_ERROR error = { 0, {0} };

    broker_name[0] = '\0';
    command[0] = '\0';
    full_path_buf[0] = '\0';
    buf[0] = '\0';

    nv_locate (req, "files", &sect, &sect_len);
    if (sect < 0)
    {
        return ERR_REQUEST_FORMAT;
    }

    for (i = 0; i < sect_len; ++i)
    {
        nv_lookup (req, sect + i, NULL, &path);
#if defined(WINDOWS)
        path = nt_style_path (path, full_path_buf);
#endif
        if (access (path, F_OK) != 0)
        {
            snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "No such file: %s",
                      path);
            return ERR_WITH_MSG;
        }

        snprintf (command, sizeof (command), "%s %s %s", DEL_FILE,
                  DEL_FILE_OPT, path);

        output = popen (command, "r");
        memset (buf, '\0', sizeof (buf));
        if (output != NULL)
        {
            if (fgets (buf, PATH_MAX, output) != NULL)
            {
#if defined(WINDOWS)
                pclose (output);
                snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "Cannot remove %s",
                          full_path_buf);
                return ERR_WITH_MSG;
#endif
                if (get_broker_info_from_filename (path, broker_name, &as_id) < 0
                    || cm_del_cas_log (broker_name, as_id, &error) < 0)
                {
                    pclose (output);
                    snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s",
                              error.err_msg);
                    return ERR_WITH_MSG;
                }
            }
        }
        pclose (output);
    }                /* end of for */

    return ERR_NO_ERROR;
}

int
ts_get_host_stat (nvplist * req, nvplist * res, char *_dbmt_error)
{
    int retval = ERR_NO_ERROR;
    T_CMS_HOST_STAT stat;

    memset (&stat, 0, sizeof (T_CMS_HOST_STAT));

    retval = ut_get_host_stat (&stat, _dbmt_error);

    nv_add_nvp_int64 (res, "cpu_user", stat.cpu_user);
    nv_add_nvp_int64 (res, "cpu_kernel", stat.cpu_kernel);
    nv_add_nvp_int64 (res, "cpu_idle", stat.cpu_idle);
    nv_add_nvp_int64 (res, "cpu_iowait", stat.cpu_iowait);
    nv_add_nvp_int64 (res, "mem_phy_total", stat.mem_physical_total);
    nv_add_nvp_int64 (res, "mem_phy_free", stat.mem_physical_free);
    nv_add_nvp_int64 (res, "mem_swap_total", stat.mem_swap_total);
    nv_add_nvp_int64 (res, "mem_swap_free", stat.mem_swap_free);

    return retval;
}

int
ts_get_dbproc_stat (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char *dbname = NULL;
    T_CM_DB_PROC_STAT_ALL *db_stat_all = NULL;
    T_CM_DB_PROC_STAT db_stat;
    T_CM_ERROR error;
    int retval;
    int i = 0;

    memset (&db_stat, 0, sizeof (T_CM_DB_PROC_STAT));
    memset (&error, 0, sizeof (T_CM_ERROR));

    if ((dbname = nv_get_val (req, "dbname")) == NULL)
    {
        if ((db_stat_all = cm_get_db_proc_stat_all (&error)) == NULL)
        {
            strcpy_limit (_dbmt_error, error.err_msg, DBMT_ERROR_MSG_SIZE);
            retval = ERR_WITH_MSG;
            goto error_return;
        }

        for (i = 0; i < db_stat_all->num_stat; i++)
        {
            print_db_stat_to_res ((db_stat_all->db_stats + i), res);
        }

        cm_db_proc_stat_all_free (db_stat_all);
        retval = ERR_NO_ERROR;
    }
    else
    {
        if (cm_get_db_proc_stat (dbname, &db_stat, &error) < 0)
        {
            strcpy_limit (_dbmt_error, error.err_msg, DBMT_ERROR_MSG_SIZE);
            retval = ERR_WITH_MSG;
            goto error_return;
        }
        print_db_stat_to_res (&db_stat, res);
        retval = ERR_NO_ERROR;
    }

    return retval;

error_return:
    print_db_stat_to_res (&db_stat, res);
    return retval;
}

static int
analyze_heartbeat_cmd_outfile (FILE * infile, char *_dbmt_error)
{
    char buf[1024];
    const char *headtag = "++";
    const char *failtag = "not running";
    char *p;

    while (fgets (buf, sizeof (buf), infile))
    {
        if (strncmp (buf, headtag, strlen (headtag)) == 0)
        {
            if (strstr (buf, failtag) != NULL)
            {
                p = strchr (buf, '\n');
                if (p)
                {
                    *p = '\0';
                }
                /* copy begins with the 3rd charactor, ignore the "++" tag. */
                strcpy_limit (_dbmt_error, &buf[2], DBMT_ERROR_MSG_SIZE);
                return ERR_WITH_MSG;
            }
        }
    }

    return ERR_NO_ERROR;
}

static char *
cub_admin_cmd_name (char *cmd_name, int buf_len)
{
    cmd_name[0] = '\0';
#if !defined (DO_NOT_USE_CUBRIDENV)
    snprintf (cmd_name, buf_len, "%s/%s%s", sco.szCubrid, CUBRID_DIR_BIN,
              UTIL_ADMIN_NAME);
#else
    sprintf (cmd_name, buf_len, "%s/%s", CUBRID_BINDIR, UTIL_ADMIN_NAME);
#endif
    return cmd_name;
}

static int
cmd_heartbeat_deact (char *_dbmt_error)
{
    int retval = ERR_NO_ERROR;
    const char *argv[8];
    int argc = 0;
    char cmd_name[CUBRID_CMD_NAME_LEN];
    FILE *outputfile = NULL;
    char outputfilepath[PATH_MAX];
    char cubrid_err_file[PATH_MAX];

    cubrid_err_file[0] = '\0';
    outputfilepath[0] = '\0';

    snprintf (cubrid_err_file, PATH_MAX, "%s/%s.%u.err.tmp",
              sco.dbmt_tmp_dir, "heartbeat_deact", getpid ());

    cubrid_cmd_name (cmd_name);
    argv[argc++] = cmd_name;
    argv[argc++] = PRINT_CMD_HEARTBEAT;
    argv[argc++] = PRINT_CMD_DEACT;
    argv[argc++] = NULL;

    snprintf (outputfilepath, PATH_MAX - 1, "%s/DBMT_task_%d.%d",
              sco.dbmt_tmp_dir, TS_HEARTBEAT_DEACT, (int) getpid ());

    if (run_child (argv, 1, NULL, outputfilepath, cubrid_err_file, NULL) < 0)
    {                /* heartbeat deact */
        strcpy (_dbmt_error, argv[0]);
        retval = ERR_SYSTEM_CALL;
        goto rm_outputfile;
    }

    if (read_error_file (cubrid_err_file, _dbmt_error, DBMT_ERROR_MSG_SIZE) < 0)
    {
        retval = ERR_WITH_MSG;
        goto rm_outputfile;
    }

    /* open tmp file. */
    outputfile = fopen (outputfilepath, "r");
    if (outputfile == NULL)
    {
        retval = ERR_TMPFILE_OPEN_FAIL;
        goto rm_outputfile;
    }

    if ((retval =
        analyze_heartbeat_cmd_outfile (outputfile, _dbmt_error)) != ERR_NO_ERROR)
    {
        fclose (outputfile);
        goto rm_outputfile;
    }

    /* close tmp file. */
    fclose (outputfile);

rm_outputfile:
    unlink (outputfilepath);
    if (access (cubrid_err_file, F_OK) == 0)
    {
        unlink (cubrid_err_file);
    }
    return retval;
}

static int
cmd_heartbeat_act (char *_dbmt_error)
{
    int retval = ERR_NO_ERROR;
    const char *argv[8];
    int argc = 0;
    char cmd_name[CUBRID_CMD_NAME_LEN];
    FILE *outputfile = NULL;
    char outputfilepath[PATH_MAX];
    char cubrid_err_file[PATH_MAX];

    outputfilepath[0] = '\0';
    cubrid_err_file[0] = '\0';

    snprintf (cubrid_err_file, PATH_MAX, "%s/%s.%u.err.tmp",
              sco.dbmt_tmp_dir, "cmd_heartbeat_act", getpid ());

    cubrid_cmd_name (cmd_name);
    argv[argc++] = cmd_name;
    argv[argc++] = PRINT_CMD_HEARTBEAT;
    argv[argc++] = PRINT_CMD_ACT;
    argv[argc++] = NULL;

    snprintf (outputfilepath, PATH_MAX - 1, "%s/DBMT_task_%d.%d",
              sco.dbmt_tmp_dir, TS_HEARTBEAT_ACT, (int) getpid ());

    if (run_child (argv, 1, NULL, outputfilepath, cubrid_err_file, NULL) < 0)
    {                /* heartbeat act */
        strcpy (_dbmt_error, argv[0]);
        retval = ERR_SYSTEM_CALL;
        goto rm_outputfile;
    }

    if (read_error_file (cubrid_err_file, _dbmt_error, DBMT_ERROR_MSG_SIZE) < 0)
    {
        retval = ERR_WITH_MSG;
        goto rm_outputfile;
    }

    /* open tmp file. */
    outputfile = fopen (outputfilepath, "r");
    if (outputfile == NULL)
    {
        retval = ERR_TMPFILE_OPEN_FAIL;
        goto rm_outputfile;
    }

    if ((retval =
        analyze_heartbeat_cmd_outfile (outputfile, _dbmt_error)) != ERR_NO_ERROR)
    {
        fclose (outputfile);
        goto rm_outputfile;
    }

    /* close tmp file. */
    fclose (outputfile);

rm_outputfile:
    unlink (outputfilepath);
    if (access (cubrid_err_file, F_OK) == 0)
    {
        unlink (cubrid_err_file);
    }
    return retval;
}

static int
run_csql_statement (const char *sql_stat, char *dbname, char *dbuser,
                    char *dbpasswd, char *outfilepath, char *_dbmt_error)
{
    char dbname_at_hostname[MAXHOSTNAMELEN + DB_NAME_LEN];
    char cmd_name[CUBRID_CMD_NAME_LEN];
    char task_name[10];
    const char *argv[15];

    int argc = 0;
    int retval = 0;
    int ha_mode = 0;

    T_DB_SERVICE_MODE db_mode;

    task_name[0] = '\0';
    dbname_at_hostname[0] = '\0';
    cmd_name[0] = '\0';

    snprintf (cmd_name, sizeof (cmd_name) - 1, "%s/%s%s", sco.szCubrid,
              CUBRID_DIR_BIN, UTIL_CSQL_NAME);

    if (!_isRegisteredDB (dbname))
    {
        return ERR_DB_NONEXISTANT;
    }

    db_mode = uDatabaseMode (dbname, &ha_mode);

    if (db_mode == DB_SERVICE_MODE_SA)
    {
        sprintf (_dbmt_error, "%s", dbname);
        return ERR_STANDALONE_MODE;
    }

    argv[argc++] = cmd_name;

    if (db_mode == DB_SERVICE_MODE_NONE)
    {
        argv[argc++] = "--" CSQL_SA_MODE_L;
    }
    else
    {
        argv[argc++] = "--" CSQL_CS_MODE_L;
    }

    if (dbuser != NULL)
    {
        argv[argc++] = "--" CSQL_USER_L;
        argv[argc++] = dbuser;

        argv[argc++] = "--" CSQL_PASSWORD_L;
        if (dbpasswd != NULL)
        {
            argv[argc++] = dbpasswd;
        }
        else
        {
            argv[argc++] = "";
        }
    }
    else
    {
        strcpy (_dbmt_error, "dbuser");
        return ERR_PARAM_MISSING;
    }

    argv[argc++] = "--" CSQL_COMMAND_L;
    argv[argc++] = sql_stat;

    if (ha_mode != 0)
    {
        append_host_to_dbname (dbname_at_hostname, dbname,
                               sizeof (dbname_at_hostname));
        argv[argc++] = dbname_at_hostname;
    }
    else
    {
        argv[argc++] = dbname;
    }

    argv[argc++] = NULL;

    SET_TRANSACTION_NO_WAIT_MODE_ENV ();

    snprintf (task_name, TASKNAME_LEN, "%s", "csql");
    retval = _run_child (argv, 1, task_name, outfilepath, _dbmt_error);

    return retval;
}

int
ts_user_verify (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char *dbname, *dbuser, *dbpasswd;
    int retval = ERR_NO_ERROR;

    /* every user can access db_user table. */
    const char *sql_stat = "select 1 from db_root";

    if ((dbname = nv_get_val (req, "dbname")) == NULL)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", "dbname");
        return ERR_PARAM_MISSING;
    }

    if ((dbuser = nv_get_val (req, "dbuser")) != NULL)
    {
        dbpasswd = nv_get_val (req, "dbpasswd");
    }
    else
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", "dbuser");
        return ERR_PARAM_MISSING;
    }

    /*
    * using csql to verify the user's password.
    */
    retval = run_csql_statement (sql_stat, dbname, dbuser, dbpasswd, NULL, _dbmt_error);    /* csql */

    return retval;
}

int
ts_get_standby_server_stat (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char *dbname, *dbuser, *dbpasswd;
    char output_file[PATH_MAX] = { 0 };
    int retval;
    T_STANDBY_SERVER_STAT stat;
    FILE *outfile = NULL;

    /*
    * get the record which contains the insert/delete/update/commit/fail counter,
    * if there is more than one records, the one with largest last_access_time
    * in db_ha_apply_info table is chosen.
    */
    const char *sql_stat =
    "select "
    "insert_counter, update_counter, delete_counter, commit_counter, fail_counter, "
    "(last_access_time - log_record_time) "
    "from db_ha_apply_info "
    "where (last_access_time IN (select max (last_access_time) from db_ha_apply_info))";

    memset (&stat, 0, sizeof (stat));

    snprintf (output_file, PATH_MAX - 1, "%s/dbmt_task_%d_%d",
              sco.dbmt_tmp_dir, TS_GET_STANDBY_SERVER_STAT, (int) getpid ());

    if ((dbname = nv_get_val (req, "dbname")) == NULL)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", "dbname");
        retval = ERR_PARAM_MISSING;
        goto func_return;
    }

    nv_add_nvp (res, "dbname", dbname);

    if ((dbuser = nv_get_val (req, "dbid")) != NULL)
    {
        dbpasswd = nv_get_val (req, "dbpasswd");
    }
    else
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", "dbid");
        retval = ERR_PARAM_MISSING;
        goto func_return;
    }

    retval = run_csql_statement (sql_stat, dbname, dbuser, dbpasswd, output_file, _dbmt_error);    /* csql */

    if (retval != ERR_NO_ERROR)
    {
        goto func_return;
    }

    if ((outfile = fopen (output_file, "r")) == NULL)
    {
        retval = ERR_TMPFILE_OPEN_FAIL;
        goto func_return;
    }

    if ((retval =
        parse_standby_server_stat (&stat, outfile, _dbmt_error)) != ERR_NO_ERROR)
    {
        fclose (outfile);
        goto func_return;
    }

    fclose (outfile);
    retval = ERR_NO_ERROR;

func_return:
    nv_add_nvp_int64 (res, "delay_time", stat.delay_time);
    nv_add_nvp_int64 (res, "insert_counter", stat.insert_counter);
    nv_add_nvp_int64 (res, "update_counter", stat.update_counter);
    nv_add_nvp_int64 (res, "delete_counter", stat.delete_counter);
    nv_add_nvp_int64 (res, "commit_counter", stat.commit_counter);
    nv_add_nvp_int64 (res, "fail_counter", stat.fail_counter);

    unlink (output_file);
    return retval;
}

static int
parse_standby_server_stat (T_STANDBY_SERVER_STAT * stat, FILE * outfile,
                           char *_dbmt_error)
{
    char buf[1024];
    char prefix[64] = { 0 };
    long long delay_time = 0;
    long long insert_counter = 0;
    long long update_counter = 0;
    long long delete_counter = 0;
    long long commit_counter = 0;
    long long fail_counter = 0;

    while (fgets (buf, sizeof (buf), outfile))
    {
        sscanf (buf, "%63s", prefix);

        /* the first charactor is the num of insert_counter, it should be digit. */
        if (isdigit (prefix[0]))
        {
            /* break when found the result. */
            if (sscanf
                    (buf, "%lld %lld %lld %lld %lld %lld",
                    &insert_counter, &update_counter, &delete_counter,
                    &commit_counter, &fail_counter, &delay_time) == 6)
            {
                break;
            }
        }
    }

    stat->delay_time = delay_time;
    stat->insert_counter = insert_counter;
    stat->update_counter = update_counter;
    stat->delete_counter = delete_counter;
    stat->commit_counter = commit_counter;
    stat->fail_counter = fail_counter;

    return ERR_NO_ERROR;
}

static char *
get_mode_from_output_file (char *mode, int buf_len, FILE * outputfile,
                           char *_dbmt_error)
{
    char buf[1024];
    char server_mode[64] = { 0 };
    int scan_matched = 0;

    while (fgets (buf, sizeof (buf), outputfile))
    {
        if (strcmp (buf, "\n") == 0)
        {
            continue;
        }

        scan_matched =
            sscanf (buf, "%*s %*s %*s %*s %*s %*s %*s %*s %63s", server_mode);

        if (scan_matched != 1)
        {
            strcpy_limit (_dbmt_error, "error occur when parsing output file.",
                          DBMT_ERROR_MSG_SIZE);
            return NULL;
        }

        /* remove '.' */
        if (strlen (server_mode) != 0)
        {
            server_mode[strlen (server_mode) - 1] = '\0';
        }
        break;
    }
    strcpy_limit (mode, server_mode, buf_len);

    return mode;
}

static int
cmd_get_db_mode (T_DB_MODE_INFO * dbmodeinfo, char *dbname, char *_dbmt_error)
{
    int ha_mode = 0;
    T_DB_SERVICE_MODE dbmode;
    char server_mode[64] = "<unknown>";
    char server_msg[1024] = "none";
    int retval;

    strcpy_limit (dbmodeinfo->dbname, dbname, sizeof (dbmodeinfo->dbname));

    dbmode = uDatabaseMode (dbname, &ha_mode);

    if (ha_mode == 0)
    {
        /* To CUBRID Client, the SA and NONE mode all means the database is stopped. */
        if (dbmode == DB_SERVICE_MODE_SA || dbmode == DB_SERVICE_MODE_NONE)
        {
            strcpy_limit (server_mode, "stopped", sizeof (server_mode));
        }
        else
        {
            strcpy_limit (server_mode, "CS-mode", sizeof (server_mode));
        }

        retval = ERR_NO_ERROR;
    }
    else
    {
        /*
        * The task is used for monitoring, the retval of changemode command is
        * not checked. The error message will be appended to the server_msg.
        */
        retval =
            cmd_changemode (dbname, NULL, NULL, server_mode, sizeof (server_mode),
                            _dbmt_error);
        /* changemode */
    }

    /* record the error message to server_msg */
    if (retval != ERR_NO_ERROR)
    {
        strcpy_limit (server_msg, _dbmt_error, sizeof (server_msg));
    }

    strcpy_limit (dbmodeinfo->server_msg, server_msg,
                  sizeof (dbmodeinfo->server_msg));
    strcpy_limit (dbmodeinfo->server_mode, server_mode,
                  sizeof (dbmodeinfo->server_mode));

    return ERR_NO_ERROR;
}

int
ts_get_db_mode (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char *dblist, *dbname;
    char separator = ',';
    T_DB_MODE_INFO dbmode;

    if ((dblist = nv_get_val (req, "dblist")) == NULL)
    {
        strcpy_limit (_dbmt_error, "dblist", DBMT_ERROR_MSG_SIZE);
        return ERR_PARAM_MISSING;
    }

    while (dblist != NULL)
    {
        dbname = dblist;

        if ((dblist = strchr (dblist, separator)) != NULL)
        {
            dblist[0] = '\0';
            dblist++;
        }

        nv_add_nvp (res, "open", "dbserver");
        nv_add_nvp (res, "dbname", dbname);

        cmd_get_db_mode (&dbmode, dbname, _dbmt_error);
        nv_add_nvp (res, "server_mode", (&dbmode)->server_mode);
        nv_add_nvp (res, "server_msg", (&dbmode)->server_msg);

        nv_add_nvp (res, "close", "dbserver");
    }

    return ERR_NO_ERROR;
}

int
ts_changemode (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char *dbname, *modify, *force;
    char server_mode[64];
    int retval;

    if ((dbname = nv_get_val (req, "dbname")) == NULL)
    {
        strcpy_limit (_dbmt_error, "dbname", DBMT_ERROR_MSG_SIZE);
        return ERR_PARAM_MISSING;
    }
    modify = nv_get_val (req, "modify");
    force = nv_get_val (req, "force");

    /* changemode */
    retval =
    cmd_changemode (dbname, modify, force, server_mode, sizeof (server_mode),
                    _dbmt_error);

    if (retval != ERR_NO_ERROR)
    {
        return retval;
    }

    nv_add_nvp (res, "server_mode", server_mode);

    return ERR_NO_ERROR;
}

static int
cmd_changemode (char *dbname, char *modify, char *force,
                char *server_mode_out, int mode_len, char *_dbmt_error)
{
    char server_mode[64];
    const char *argv[10];
    int argc = 0;
    int ha_mode = 0;
    char dbname_at_hostname[MAXHOSTNAMELEN + DB_NAME_LEN];
    char cmd_name[CUBRID_CMD_NAME_LEN];
    T_DB_SERVICE_MODE dbmode;
    char cubrid_err_file[PATH_MAX];
    FILE *outputfile;
    char tmpfilepath[PATH_MAX];
    int retval = ERR_NO_ERROR;

    cubrid_err_file[0] = '\0';

    if (dbname == NULL)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", "dbname");
        return ERR_PARAM_MISSING;
    }

    dbmode = uDatabaseMode (dbname, &ha_mode);
    if (dbmode == DB_SERVICE_MODE_SA)
    {
        strcpy_limit (_dbmt_error, dbname, DBMT_ERROR_MSG_SIZE);
        return ERR_STANDALONE_MODE;
    }

    snprintf (cubrid_err_file, PATH_MAX, "%s/%s.%u.err.tmp",
              sco.dbmt_tmp_dir, "changemode", getpid ());
    snprintf (tmpfilepath, PATH_MAX - 1, "%s/DBMT_task_%d.%d",
              sco.dbmt_tmp_dir, TS_CHANGEMODE, (int) getpid ());

    cubrid_cmd_name (cmd_name);
    argv[argc++] = cmd_name;
    argv[argc++] = UTIL_OPTION_CHANGEMODE;

    if (modify != NULL)
    {
        argv[argc++] = "--" CHANGEMODE_MODE_L;
        argv[argc++] = modify;

        if (uStringEqual (force, "y"))
        {
            argv[argc++] = "--" CHANGEMODE_FORCE_L;
        }
    }

    if (ha_mode != 0)
    {
        append_host_to_dbname (dbname_at_hostname, dbname,
                               sizeof (dbname_at_hostname));
        argv[argc++] = dbname_at_hostname;
    }
    else
    {
        argv[argc++] = dbname;
    }

    argv[argc++] = NULL;

    if (run_child (argv, 1, NULL, tmpfilepath, cubrid_err_file, NULL) < 0)    /* changemode */
    {
        strcpy_limit (_dbmt_error, argv[0], DBMT_ERROR_MSG_SIZE);
        retval = ERR_SYSTEM_CALL;
        goto error_return;
    }

    if (read_error_file (cubrid_err_file, _dbmt_error, DBMT_ERROR_MSG_SIZE) < 0)
    {
        retval = ERR_WITH_MSG;
        goto error_return;
    }

    if ((outputfile = fopen (tmpfilepath, "r")) == NULL)
    {
        retval = ERR_TMPFILE_OPEN_FAIL;
        goto error_return;
    }

    if ((get_mode_from_output_file
        (server_mode, sizeof (server_mode), outputfile, _dbmt_error)) == NULL)
    {

        fclose (outputfile);
        strcpy_limit (server_mode_out, "<unknown>", mode_len);
        strcpy_limit (_dbmt_error, "unknown database mode.",
                      DBMT_ERROR_MSG_SIZE);
        retval = ERR_WITH_MSG;
        goto error_return;
    }

    strcpy_limit (server_mode_out, server_mode, mode_len);

    fclose (outputfile);
    unlink (tmpfilepath);
    if (access (cubrid_err_file, F_OK) == 0)
    {
        unlink (cubrid_err_file);
    }
    return ERR_NO_ERROR;

error_return:
    unlink (tmpfilepath);
    if (access (cubrid_err_file, F_OK) == 0)
    {
        unlink (cubrid_err_file);
    }
    return retval;
}

int
ts_role_change (nvplist * req, nvplist * res, char *_dbmt_error)
{
    int i;
    int retval = ERR_NO_ERROR;
    char cmdfile[PATH_MAX];
    FILE *infile = NULL;
    char *tok[8];
    const char *cmd_argv[8];
    char cub_admin_cmd[CUBRID_CMD_NAME_LEN];
    char buf[2048] = { 0 };

    const char *argv[] = {
        "/bin/ps",
        "xo",
        "cmd",
        NULL,
    };

    snprintf (cmdfile, PATH_MAX - 1, "%s/DBMT_task_%d.%d",
              sco.dbmt_tmp_dir, TS_ROLE_CHANGE, (int) getpid ());

    /* save the process info before heartbeat deact operation. */
    if (run_child (argv, 1, NULL, cmdfile, NULL, NULL) < 0)
    {
        strcpy_limit (_dbmt_error, argv[0], DBMT_ERROR_MSG_SIZE);
        return ERR_SYSTEM_CALL;
    }

    /*
    * use heartbeat deact command to deact the heartbeat in Master node,
    * so that the slave node can change into a master node.
    */
    if ((retval = cmd_heartbeat_deact (_dbmt_error)) != ERR_NO_ERROR)    /* heartbeat deact */
    {
        goto error_return;
    }

    /*
    * sleep 6s to wait for the slave node change into master node.
    * the slave node needs about 4s to change itself into master node.
    */
    SLEEP_SEC (6);

    /* restart the heartbeat after the slave node changed into master node. */
    if ((retval = cmd_heartbeat_act (_dbmt_error)) != ERR_NO_ERROR)    /* heartbeat act */
    {
        goto error_return;
    }

    if ((infile = fopen (cmdfile, "r")) == NULL)
    {
        retval = ERR_TMPFILE_OPEN_FAIL;
        goto error_return;
    }

    /* restart the HA related processes recorded in cmdfile. */
    while (fgets (buf, sizeof (buf), infile))
    {
        char buf_t[2048] = { 0 };

        ut_trim (buf);
        to_lower_str (buf, buf_t);

        for (i = 0; i < 8; i++)
        {
            tok[i] = NULL;
            cmd_argv[i] = NULL;
        }

        if ((strstr (buf_t, " copylogdb") != NULL) ||
            (strstr (buf_t, " applylogdb") != NULL))
        {
            /* restart applylogdb & copylogdb processes. */
            string_tokenize2 (buf, tok, 8, ' ');
            cub_admin_cmd_name (cub_admin_cmd, sizeof (cub_admin_cmd));

            cmd_argv[0] = cub_admin_cmd;

            for (i = 1; tok[i] != NULL; i++)
                cmd_argv[i] = tok[i];

            if (run_child (cmd_argv, 0, NULL, NULL, NULL, NULL) < 0)
            {
                retval = ERR_SYSTEM_CALL;
                goto error_return;
            }
        }
        else if (strstr (buf, "cub_server") != NULL)
        {
            /* restart database server processes. */
            string_tokenize2 (buf, tok, 3, ' ');

            if (cmd_start_server (tok[1], _dbmt_error, DBMT_ERROR_MSG_SIZE) < 0)
            {
                retval = ERR_WITH_MSG;
                goto error_return;
            }
        }
    }

    retval = ERR_NO_ERROR;

error_return:
    if (infile)
    {
        fclose (infile);
    }
    unlink (cmdfile);
    return retval;
}

static void
print_db_stat_to_res (T_CM_DB_PROC_STAT * db_stat, nvplist * res)
{
    nv_add_nvp (res, "open", "dbstat");
    nv_add_nvp (res, "dbname", db_stat->name);
    nv_add_nvp_int64 (res, "cpu_kernel", db_stat->stat.cpu_kernel);
    nv_add_nvp_int64 (res, "cpu_user", db_stat->stat.cpu_user);
    nv_add_nvp_int64 (res, "mem_physical", db_stat->stat.mem_physical);
    nv_add_nvp_int64 (res, "mem_virtual", db_stat->stat.mem_virtual);
    nv_add_nvp (res, "close", "dbstat");
}

int
ts_heartbeat_list (nvplist * req, nvplist * res, char *_dbmt_error)
{
    T_HA_SERVER_INFO_ALL *all_info = NULL;
    char *dbmodeall = NULL;
    char *dblist = NULL;
    int get_all_dbmode = 0;
    int retval = ERR_NO_ERROR;

    if ((dbmodeall = nv_get_val (req, "dbmodeall")) != NULL)
    {
        if (strcmp (dbmodeall, "y") == 0)
        {
            get_all_dbmode = 1;
        }
        else
        {
            get_all_dbmode = 0;
            dblist = nv_get_val (req, "dblist");
        }
    }
    else
    {
        retval = ERR_PARAM_MISSING;
        strcpy_limit (_dbmt_error, "dbmodeall", DBMT_ERROR_MSG_SIZE);
        goto error_return;
    }

    all_info = (T_HA_SERVER_INFO_ALL *) MALLOC (sizeof (T_HA_SERVER_INFO_ALL));
    if (all_info == NULL)
    {
        return ERR_MEM_ALLOC;
    }

    memset (all_info, 0, sizeof (T_HA_SERVER_INFO_ALL));

    if ((retval =
            cmd_heartbeat_list (&all_info, get_all_dbmode, dblist,
                                _dbmt_error)) != ERR_NO_ERROR)
    {
        goto error_return;
    }

    /*
    * get dbmode for every dbserver in the dbinfo list, the allocated space will be
    * freed in dbinfo_list_free function.
    */
    if ((retval =
            fill_dbmode_into_dbinfo_list (&all_info, _dbmt_error)) != ERR_NO_ERROR)
    {
        goto error_return;
    }

    print_dbinfo_list_to_res (all_info, res);

error_return:
    dbinfo_list_free (all_info);
    return retval;
}

int
ts_get_envvar_by_name (nvplist * req, nvplist * res, char *_dbmt_error)
{
    int i;
    char *n, *v;

    for (i = 0; i < req->nvplist_leng; i++)
    {
        nv_lookup (req, i, &n, &v);
        if ((n != NULL) && (strcmp (n, "envvar") == 0))
        {
            char *envvar_t = getenv (v);

            nv_add_nvp (res, v, (envvar_t == NULL ? "" : envvar_t));
        }
    }

    return ERR_NO_ERROR;
}

int
ts_copy_folder (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char *src_dir;
    char *dest_dir;

    if ((src_dir = nv_get_val (req, "srcdir")) == NULL)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", "srcdir");
        return ERR_PARAM_MISSING;
    }
    if ((dest_dir = nv_get_val (req, "destdir")) == NULL)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", "destdir");
        return ERR_PARAM_MISSING;
    }

    if (folder_copy (src_dir, dest_dir) < 0)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE - 1,
                  "Failed when copying %s to %s.", src_dir, dest_dir);
        return ERR_WITH_MSG;
    }

    return ERR_NO_ERROR;
}

int
ts_delete_folder (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char *src_dir;
    int force_flag;

    if ((src_dir = nv_get_val (req, "srcdir")) == NULL)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", "srcdir");
        return ERR_PARAM_MISSING;
    }

    force_flag = REMOVE_DIR_FORCED;

    if (uRemoveDir (src_dir, force_flag) != ERR_NO_ERROR)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE - 1,
                  "Can't' delete the folder: %s.", src_dir);
        return ERR_WITH_MSG;
    }

    return ERR_NO_ERROR;
}

int
ts_write_and_save_conf (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char *conf_path;
    char conf_backup_path[PATH_MAX];

    if ((conf_path = nv_get_val (req, "confpath")) == NULL)
    {
        strcpy_limit (_dbmt_error, "confpath", DBMT_ERROR_MSG_SIZE);
        return ERR_PARAM_MISSING;
    }

    /* if conf_path exsit, backup it at the current path. */
    if (access (conf_path, F_OK) == 0)
    {
        snprintf (conf_backup_path, sizeof (conf_backup_path) - 1,
                  "%s.bak", conf_path);

        if (file_copy (conf_path, conf_backup_path) != 0)
        {
            strcpy_limit (_dbmt_error, "backup file error.",
                          DBMT_ERROR_MSG_SIZE);
            return ERR_WITH_MSG;
        }
    }

    /* create a new conf file from request. */
    if (_write_conf_to_file (req, conf_path) < 0)
    {
        strcpy_limit (_dbmt_error, "write config file error.",
                      DBMT_ERROR_MSG_SIZE);
        return ERR_WITH_MSG;
    }

    return ERR_NO_ERROR;
}

int
ts_run_sql_statement (nvplist * req, nvplist * res, char *_dbmt_error)
{
    T_CUBRID_MODE mode;
    T_CSQL_RESULT *csql_res = NULL;
    int retval = ERR_NO_ERROR;
    char *dbname, *uid, *passwd;
    char *infile;
    char *command;
    char *error_continue;

    if ((dbname = nv_get_val (req, "dbname")) == NULL)
    {
        strcpy_limit (_dbmt_error, "dbname", DBMT_ERROR_MSG_SIZE);
        return ERR_PARAM_MISSING;
    }

    infile = nv_get_val (req, "infile");
    command = nv_get_val (req, "command");

    uid = nv_get_val (req, "uid");
    passwd = nv_get_val (req, "passwd");
    error_continue = nv_get_val (req, "error_continue");

    mode =
        (uDatabaseMode (dbname, NULL) ==
        DB_SERVICE_MODE_NONE ? CUBRID_MODE_SA : CUBRID_MODE_CS);

    csql_res = cmd_csql (dbname, uid, passwd, mode, infile, command, error_continue);    /* csql */

    if (csql_res == NULL)
    {
        strcpy_limit (_dbmt_error, "Error occur when execurating csql.",
                      DBMT_ERROR_MSG_SIZE);
        return ERR_WITH_MSG;
    }

    if (strlen (csql_res->err_msg) != 0)
    {
        strcpy_limit (_dbmt_error, csql_res->err_msg, DBMT_ERROR_MSG_SIZE);
        retval = ERR_WITH_MSG;
    }
    free (csql_res);
    return retval;
}

int
ts_get_folders_with_keyword (nvplist * req, nvplist * res, char *_dbmt_error)
{
    int retval;
    char *search_folder;
    char *keyword;

    if ((search_folder = nv_get_val (req, "search_folder")) == NULL)
    {
        strcpy_limit (_dbmt_error, "search_folder", DBMT_ERROR_MSG_SIZE);
        return ERR_PARAM_MISSING;
    }

    if ((keyword = nv_get_val (req, "keyword")) == NULL)
    {
        strcpy_limit (_dbmt_error, "keyword", DBMT_ERROR_MSG_SIZE);
        return ERR_PARAM_MISSING;
    }

    retval =
        _get_folders_with_keyword (search_folder, keyword, res, _dbmt_error);

    return retval;
}

int
ts_run_script (nvplist * req, nvplist * res, char *_dbmt_error)
{
    int argc = 0;
    const char *argv[5];
    char *script_path;
    char outfile[PATH_MAX];
    char errfile[PATH_MAX];
    char *n, *v;
    int retval = ERR_NO_ERROR;
    int i, pid;

    pid = (int) getpid ();
    snprintf (outfile, sizeof (outfile) - 1, "%s/DBMT_task_%d_out.%d",
              sco.dbmt_tmp_dir, TS_RUN_SCRIPT, pid);
    snprintf (errfile, sizeof (errfile) - 1, "%s/DBMT_task_%d_err.%d",
              sco.dbmt_tmp_dir, TS_RUN_SCRIPT, pid);

    /* set environment that the script need to run. */
    for (i = 0; i < req->nvplist_leng; i++)
    {
        nv_lookup (req, i, &n, &v);
        if ((n != NULL) && (strcmp (n, "envvar") == 0))
        {
            putenv (v);
        }
    }

    if ((script_path = nv_get_val (req, "script_path")) == NULL)
    {
        strcpy_limit (_dbmt_error, "script_path", DBMT_ERROR_MSG_SIZE);
        return ERR_PARAM_MISSING;
    }

    argv[argc++] = script_path;
    argv[argc++] = NULL;

    /* run *.bat or *.sh. */
    if (run_child (argv, 1, NULL, outfile, errfile, NULL) < 0)
    {
        strcpy_limit (_dbmt_error, argv[0], DBMT_ERROR_MSG_SIZE);
        retval = ERR_SYSTEM_CALL;
    }

    unlink (outfile);
    unlink (errfile);

    return retval;
}

int
ts_get_file_total_line_num (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char *filepath;
    FILE *fp = NULL;
    char buf[LINE_MAX];
    int total_num = 0;

    if ((filepath = nv_get_val (req, "filepath")) == NULL)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", "filepath");
        return ERR_PARAM_MISSING;
    }

    if ((fp = fopen (filepath, "r")) == NULL)
    {
        return ERR_TMPFILE_OPEN_FAIL;
    }

    while (fgets (buf, sizeof (buf), fp))
    {
        total_num++;
    }
    fclose (fp);

    nv_add_nvp_int (res, "totalnum", total_num);

    return ERR_NO_ERROR;
}

int
ts_error_trace (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char *err_log_path;
    char *eid;
    char *err_time;
    FILE *fp;
    char buf[10 * 1024];

    if ((err_log_path = nv_get_val (req, "logpath")) == NULL)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", "logpath");
        return ERR_PARAM_MISSING;
    }

    if ((eid = nv_get_val (req, "eid")) == NULL)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", "eid");
        return ERR_PARAM_MISSING;
    }

    if ((err_time = nv_get_val (req, "errtime")) == NULL)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", "errtime");
        return ERR_PARAM_MISSING;
    }

    memset (buf, 0, sizeof (buf));

    if ((fp = fopen (err_log_path, "r")) == NULL)
    {
        return ERR_FILE_OPEN_FAIL;
    }

    nv_add_nvp (res, "open", "errbloc");

    while (_get_block_from_log (fp, buf, sizeof (buf)) == 0)
    {
        char *line_start, *line_end;
        char eid_tok[64];
        char err_time_tok[64];

        snprintf (eid_tok, sizeof (eid_tok) - 1, "EID = %s", eid);
        snprintf (err_time_tok, sizeof (err_time_tok) - 1, "%s (", err_time);

        line_start = buf;
        if ((strstr (line_start, eid_tok) != NULL)
            && (strstr (line_start, err_time_tok) != NULL))
        {
            while ((line_end = strchr (line_start, '\n')) != NULL)
            {
                *line_end = '\0';
                nv_add_nvp (res, "line", line_start);
                line_end++;
                line_start = line_end;
            }
        }
    }

    nv_add_nvp (res, "close", "errbloc");
    fclose (fp);

    return ERR_NO_ERROR;
}

int
ts_remove_files (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char *path = NULL;
    char fullpath[PATH_MAX];
    int i = 0;
    int sect = -1;
    int sect_len = -1;
    int path_len = -1;
    int found = -1;

    fullpath[0] = '\0';

    nv_locate (req, "files", &sect, &sect_len);
    if (sect >= 0)
    {
        for (i = 0; i < sect_len; ++i)
        {
            found = nv_lookup (req, sect + i, NULL, &path);
            if (found == -1)
            {
                snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s",
                          "The key [path] is missing or its value is not valid.");
                return ERR_WITH_MSG;
            }
            if (path == NULL)
            {
                sprintf (_dbmt_error,
                         "Please inform file names to be deleted.");
                return ERR_WITH_MSG;
            }
            path_len = strlen (path);
            if (path_len <= 2 || strstr (path, "..") || strstr (path, "/")
                || strstr (path, "\\"))
            {
                sprintf (_dbmt_error, "Cannot be permitted to delete %s file",
                         path);
                return ERR_WITH_MSG;
            }
            if (*path == '+' && *(path + 1) == 'T')    // for CUBRID/tmp
            {
                snprintf (fullpath, sizeof (fullpath) - 1, "%s/tmp/%s",
                          sco.szCubrid, (path + 2));
            }
            else
            {
                sprintf (_dbmt_error, "Cannot be permitted to delete %s file",
                         path);
                return ERR_WITH_MSG;
            }
            if ((unlink (fullpath) != 0) && (errno != ENOENT))
            {
                sprintf (_dbmt_error, "Cannot remove file '%s' (%s)", path,
                         strerror (errno));
                return ERR_WITH_MSG;
            }
        }            /* end of for */
        return ERR_NO_ERROR;
    }
    else
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s",
                  "The key [files] is missing or its value is not valid.");
        return ERR_WITH_MSG;
    }
}


int
ts_login (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char *value = NULL;
    int ret_val = ERR_NO_ERROR;

    if ((ret_val = ts_validate_user (req, res, _dbmt_error)) != ERR_NO_ERROR)
    {
        /* Authentication failed. Drop connection */
        /* because function ts_validate_user already add the err msg to res */
        return ret_val;
    }

    if (ts_check_client_version (req, res) == 0)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", "Version-mismatched");

        /* because function ts_validate_user already add the err msg to res */
        return ERR_WITH_MSG;
    }

    /* generate token and record new connection to file */
    value = nv_get_val (req, "id");
    /* set _ID token for ut_error_log & ut_access_log.  */
    nv_add_nvp (req, "_ID", value);

    _accept_connection (req, res);

    ut_access_log (req, "connected");

    return ERR_NO_ERROR;
}

int
ts_logout (nvplist * req, nvplist * res, char *_dbmt_error)
{
    T_USER_TOKEN_INFO *removed_node = NULL;

    char *token = NULL;

    ut_access_log (req, "disconnected");

    nv_update_val (res, "status", "success");
    nv_update_val (res, "note", "");

    token = nv_get_val (req, "token");
    removed_node = dbmt_user_delete_token_info_by_token (token);

    if (removed_node == NULL)
    {
        return ERR_INVALID_TOKEN;
    }

    FREE_MEM (removed_node);

    return ERR_NO_ERROR;
}

int
ts_job_test (nvplist * req, nvplist * res, char *_dbmt_error)
{
    int i;
    nvplist *cli_response;
    const char *argvs[2];

    cli_response = nv_create (5, NULL, "\n", ":", "\n");
    for (i = ERR_NO_ERROR; i <= ERR_WARNING; i++)
    {
        uGenerateStatus (req, cli_response, i, "test error");
    }

    nv_destroy (cli_response);
    argvs[0] = "ping";
    argvs[1] = NULL;

    ut_run_child ("ping", argvs, 1, "infile.test", "outfile.test",
                  "errfile.test", &i);
    unlink ("outfile.test");
    unlink ("errfile.test");
    return ERR_NO_ERROR;
}

static const char *
get_processor_architecture ()
{
#ifdef WINDOWS
    SYSTEM_INFO siSysInfo;
    GetSystemInfo (&siSysInfo);
    switch (siSysInfo.wProcessorArchitecture)
    {
        case PROCESSOR_ARCHITECTURE_AMD64:
        case PROCESSOR_ARCHITECTURE_IA64:
            return "x64";
        case PROCESSOR_ARCHITECTURE_INTEL:
            return "x86";
        default:
            break;
    }
    return "unknown";
#else
    struct utsname u_name;
    if (uname (&u_name) < 0)
        return "unknown";

    if (!strcmp (u_name.machine, "x86_64"))
        return "x64";
    else
        return "x86";
#endif
}

int
ts_get_cms_env (nvplist * req, nvplist * res, char *_dbmt_error)
{
    int is_default_cert_file = 0;

    ts_get_server_version (req, res);
    nv_add_nvp (res, "PLATFORM", get_processor_architecture ());
    nv_add_nvp (res, "CMS_VER", makestring (BUILD_NUMBER));

    nv_add_nvp_int (res, "cm_port", sco.iCMS_port);

    is_default_cert_file = _is_default_cert (_dbmt_error);
    if (is_default_cert_file < 0)
    {
        return ERR_WITH_MSG;
    }
    if (is_default_cert_file == 0)
    {
        nv_add_nvp (res, "is_default_cert", "no");
    }
    else
    {
        nv_add_nvp (res, "is_default_cert", "yes");
    }

    return ERR_NO_ERROR;
}

int
ts_keepalive (nvplist * req, nvplist * res, char *_dbmt_error)
{
    SLEEP_SEC (10);
    nv_update_val (res, "status", "success");
    nv_update_val (res, "note", "");
    return ERR_NO_ERROR;
}

static int
_get_block_from_log (FILE * fp, char *block_buf, int len)
{
    int retval = -1;
    int space_left = len - 1;
    char buf[2048];
    char *buf_t = block_buf;

    while (fgets (buf, sizeof (buf), fp))
    {
        if (space_left <= 0)
            return 0;

        if (strcmp (buf, "\n") == 0)
            break;

        strcpy_limit (buf_t, buf, space_left);
        space_left -= strlen (buf);
        buf_t += strlen (buf);
        retval = 0;
    }

    if (strlen (block_buf))
    {
        block_buf[strlen (block_buf) - 1] = '\0';
    }
    return retval;
}

static int
cmd_heartbeat_list (T_HA_SERVER_INFO_ALL ** all_info, int get_all_dbmode,
                    char *dblist, char *_dbmt_error)
{
    char cmd_name[CUBRID_CMD_NAME_LEN];
    const char *argv[6];
    int argc = 0;
    char cubrid_err_file[PATH_MAX];
    char outputfilepath[PATH_MAX];
    int retval = ERR_NO_ERROR;
    FILE *tmpfile = NULL;

    cubrid_err_file[0] = '\0';

    cubrid_cmd_name (cmd_name);
    argv[argc++] = cmd_name;
    argv[argc++] = PRINT_CMD_HEARTBEAT;
    argv[argc++] = PRINT_CMD_LIST;
    argv[argc++] = NULL;

    snprintf (cubrid_err_file, PATH_MAX, "%s/%s.%u.err.tmp",
              sco.dbmt_tmp_dir, "heartbeat_list", getpid ());

    snprintf (outputfilepath, PATH_MAX - 1, "%s/DBMT_task_%d.%d",
              sco.dbmt_tmp_dir, TS_HEARTBEAT_LIST, (int) getpid ());

    if (run_child (argv, 1, NULL, outputfilepath, cubrid_err_file, NULL) < 0)
    {                /* heartbeat list */
        strcpy (_dbmt_error, argv[0]);
        retval = ERR_SYSTEM_CALL;
        goto rm_tmpfile;
    }

    if (read_error_file (cubrid_err_file, _dbmt_error, DBMT_ERROR_MSG_SIZE) < 0)
    {
        retval = ERR_WITH_MSG;
        goto rm_tmpfile;
    }

    /* open tmp file. */
    tmpfile = fopen (outputfilepath, "r");
    if (tmpfile == NULL)
    {
        retval = ERR_TMPFILE_OPEN_FAIL;
        goto rm_tmpfile;
    }

    if ((retval =
            record_ha_topology_to_struct (tmpfile, get_all_dbmode, dblist,
                                          _dbmt_error, all_info)) != ERR_NO_ERROR)
    {
        fclose (tmpfile);
        goto rm_tmpfile;
    }

    /* close tmp file. */
    fclose (tmpfile);

rm_tmpfile:
    unlink (outputfilepath);
    if (access (cubrid_err_file, F_OK) == 0)
    {
        unlink (cubrid_err_file);
    }
    return retval;
}

static int
dbname_exist_in_dbinfo_list (int nitem, char *dbname,
                             T_HA_SERVER_INFO_ALL * all_info)
{
    int i;
    T_HA_DBSERVER_INFO *db_info_t = NULL;

    for (i = 0; i < nitem; i++)
    {
        db_info_t = &(all_info->db_info[i]);
        if (strcmp (dbname, db_info_t->dbname) == 0)
        {
            return i;
        }
    }
    return -1;
}

static void
print_ha_proc_info (T_HA_LOG_PROC_INFO * ha_log_proc, int elem_num,
                    int is_copylogdb, nvplist * res)
{
    int i;

    for (i = 0; i < elem_num; i++)
    {
        nv_add_nvp (res, "open", "element");
        nv_add_nvp (res, "hostname", ha_log_proc[i].hostname);
        nv_add_nvp (res, "dbname", ha_log_proc[i].dbname);
        nv_add_nvp (res, "state", ha_log_proc[i].state);
        nv_add_nvp (res, "logpath", ha_log_proc[i].logpath);
        nv_add_nvp_int (res, "pid", ha_log_proc[i].pid);
        if (is_copylogdb != 0)
        {
            nv_add_nvp (res, "mode", ha_log_proc[i].mode);
        }
        nv_add_nvp (res, "close", "element");
    }
}

static void
print_dbinfo_list_to_res (T_HA_SERVER_INFO_ALL * all_info, nvplist * res)
{
    int i;
    T_DB_MODE_INFO *dbmode_info_t = NULL;
    T_HA_DB_PROC_INFO *dbproc_info_t = NULL;
    T_HA_LOG_PROC_INFO *applylogdb_info_t = NULL;
    T_HA_LOG_PROC_INFO *copylogdb_info_t = NULL;
    T_HA_NODE_INFO *node_info_t = NULL;

    nv_add_nvp (res, "currentnode", all_info->current_node);
    nv_add_nvp (res, "currentnodestate", all_info->current_node_state);

    nv_add_nvp (res, "open", "hanodelist");

    for (i = 0; i < all_info->num_nodeinfo; i++)
    {
        nv_add_nvp (res, "open", "node");
        if ((node_info_t = &(all_info->node_info[i])) != NULL)
        {
            nv_add_nvp (res, "hostname", node_info_t->hostname);
            nv_add_nvp (res, "ip", node_info_t->ip);
            nv_add_nvp_int (res, "priority", node_info_t->priority);
            nv_add_nvp (res, "state", node_info_t->state);
        }
        nv_add_nvp (res, "close", "node");
    }
    nv_add_nvp (res, "close", "hanodelist");

    nv_add_nvp (res, "open", "hadbinfolist");

    for (i = 0; i < all_info->num_dbinfo; i++)
    {
        nv_add_nvp (res, "open", "server");

        /* add db mode info */
        nv_add_nvp (res, "open", "dbmode");
        if ((dbmode_info_t = all_info->db_info[i].dbmode_info) != NULL)
        {
            nv_add_nvp (res, "dbname", dbmode_info_t->dbname);
            nv_add_nvp (res, "server_mode", dbmode_info_t->server_mode);
            nv_add_nvp (res, "server_msg", dbmode_info_t->server_msg);
        }
        nv_add_nvp (res, "close", "dbmode");

        nv_add_nvp (res, "open", "dbprocinfo");
        if ((dbproc_info_t = all_info->db_info[i].dbproc_info) != NULL)
        {
            nv_add_nvp (res, "dbname", dbproc_info_t->dbname);
            nv_add_nvp_int (res, "pid", dbproc_info_t->pid);
            nv_add_nvp (res, "state", dbproc_info_t->state);
        }
        nv_add_nvp (res, "close", "dbprocinfo");

        nv_add_nvp (res, "open", "applylogdb");
        if ((applylogdb_info_t = all_info->db_info[i].applylogdb_info) != NULL)
        {
            print_ha_proc_info (applylogdb_info_t, all_info->db_info[i].num_ap,
                0, res);
        }
        nv_add_nvp (res, "close", "applylogdb");

        nv_add_nvp (res, "open", "copylogdb");
        if ((copylogdb_info_t = all_info->db_info[i].copylogdb_info) != NULL)
        {
            print_ha_proc_info (copylogdb_info_t, all_info->db_info[i].num_cp,
                1, res);
        }
        nv_add_nvp (res, "close", "copylogdb");

        nv_add_nvp (res, "close", "server");
    }
    nv_add_nvp (res, "close", "hadbinfolist");
}

static void
dbinfo_list_free (T_HA_SERVER_INFO_ALL * all_info)
{
    int i;

    if (all_info == NULL)
        return;

    for (i = 0; i < all_info->num_dbinfo; i++)
    {
        if (&all_info->db_info[i] == NULL)
            continue;

        FREE_MEM ((&all_info->db_info[i])->dbmode_info);
        FREE_MEM ((&all_info->db_info[i])->dbproc_info);
        FREE_MEM ((&all_info->db_info[i])->applylogdb_info);
        FREE_MEM ((&all_info->db_info[i])->copylogdb_info);
    }

    FREE_MEM (all_info->db_info);
    FREE_MEM (all_info->node_info);
    FREE_MEM (all_info);
}

static char *
get_ip_from_hostname (char *hostname, char *ipaddr, int ip_len)
{
    char *ip = NULL;
    int i;
    struct hostent *hostent_p = NULL;

    hostent_p = gethostbyname (hostname);

    if (hostent_p == NULL)
    {
        ipaddr = NULL;
    }
    else
    {
        for (i = 0; hostent_p->h_addr_list[i] != NULL; i++)
        {
            ip = inet_ntoa (*((struct in_addr *) hostent_p->h_addr_list[i]));

            /* ignore the 127.0.0.1 */
            if (strcmp (ip, "127.0.0.1") == 0)
            {
                continue;
            }
            break;
        }
        if (ip)
        {
            strcpy_limit (ipaddr, ip, ip_len);
        }
    }

    return ipaddr;
}

static int
is_name_in_list (char *name, char *list)
{
    int first_name_len = 0;
    char *name_start_p = NULL;
    char *name_end_p = NULL;
    char name_t[1024] = { 0 };

    name_start_p = list;
    name_end_p = strchr (name_start_p, ',');

    while (name_end_p != NULL)
    {
        /* copy name from list and trim it. */
        first_name_len = (int) (name_end_p - name_start_p);

        if (first_name_len > (int) sizeof (name_t))
        {
            return -1;
        }

        strcpy_limit (name_t, name_start_p, first_name_len + 1);

        ut_trim (name_t);

        if (strcmp (name_t, name) == 0)
        {
            return 1;
        }

        name_start_p = name_end_p + 1;
        name_end_p = strchr (name_start_p, ',');
    }

    /*
    * when name_end_p is NULL, it indicates the end of list is met.
    * check the last name in the list.
    */

    strcpy_limit (name_t, name_start_p, sizeof (name_t));
    ut_trim (name_t);

    if (strcmp (name_t, name) == 0)
    {
        return 1;
    }

    return 0;
}

static void
set_copylogdb_mode (T_HA_LOG_PROC_INFO * copylogdb)
{
    FILE *cmd_fp = NULL;
    int cmd_len = 0;
    char buf[2048] = { 0 };
    char cmd_file[PATH_MAX];
    char *buf_t = NULL;

    memset (buf, 0, sizeof (buf));

    snprintf (cmd_file, PATH_MAX - 1, "/proc/%d/cmdline", copylogdb->pid);
    cmd_fp = fopen (cmd_file, "r");

    if (cmd_fp == NULL)
    {
        strcpy_limit (copylogdb->mode, "<unknown>", sizeof (copylogdb->mode));
        return;
    }

    cmd_len = (int) fread (buf, sizeof (char), sizeof (buf) - 1, cmd_fp);
    buf_t = buf;

    while (buf_t[0] != 0 && ((int) (buf_t - buf)) < cmd_len)
    {
        int s_len = 0;

        s_len = strlen (buf_t);

        if (uStringEqual (buf_t, "-m") || uStringEqual (buf_t, "--mode"))
        {
            /* if the arg is "-m" or "--mode", then the next arg is the mode. */
            buf_t = &buf_t[s_len + 1];
            break;
        }
        else if (strncmp (buf_t, "--mode=", strlen ("--mode=")) == 0)
        {
            /* if the arg is "--mode", the mode is right behind the '='. */
            buf_t += strlen ("--mode=");
            break;
        }

        buf_t = &buf_t[(s_len + 1)];
    }

    /* if the "-m" & "--mode" args are not exist, the default "sync" mode is used. */
    if (buf_t[0] == 0)
    {
        strcpy_limit (copylogdb->mode, "sync", sizeof (copylogdb->mode));
        goto func_return;
    }
    else
    {
        if (uStringEqual (buf_t, "3") || uStringEqualIgnoreCase (buf_t, "sync"))
        {
            strcpy_limit (copylogdb->mode, "sync", sizeof (copylogdb->mode));
        }
        else if (uStringEqual (buf_t, "2") ||
            uStringEqualIgnoreCase (buf_t, "semisync"))
        {
            strcpy_limit (copylogdb->mode, "semisync",
            sizeof (copylogdb->mode));
        }
        else if (uStringEqual (buf_t, "1") ||
            uStringEqualIgnoreCase (buf_t, "async"))
        {
            strcpy_limit (copylogdb->mode, "async", sizeof (copylogdb->mode));
        }
        else
        {
            strcpy_limit (copylogdb->mode, "<unknown>",
            sizeof (copylogdb->mode));
        }
        goto func_return;
    }

func_return:
    fclose (cmd_fp);
    return;
}

static int
parse_ha_proc_msg_to_all_info_array (char *buf, char *_dbmt_error,
                                     T_HA_SERVER_INFO_ALL ** all_info,
                                     int *nitem, int *nalloc,
                                     int *nproc_alloc, int get_all_dbmode,
                                     char *dblist)
{
    char tmpbuf[1280] = { 0 };
    char pid[32] = { 0 };
    char elem_name[64] = { 0 };
    char state[64] = { 0 };
    char dbname[DB_NAME_LEN] = { 0 };
    char logpath[PATH_MAX] = { 0 };
    char hostname[MAXHOSTNAMELEN] = { 0 };
    int dbinfo_index = 0;
    int retval = ERR_NO_ERROR;
    T_HA_LOG_PROC_INFO *applylogdb_info = NULL;
    T_HA_LOG_PROC_INFO *copylogdb_info = NULL;

    if (sscanf (buf, "%63s %1279s %*s %31[^,] , %*s %63[^)]",
                elem_name, tmpbuf, pid, state) != 4)
    {
        retval = ERR_NO_ERROR;
        goto func_return;
    }
    else
    {
        T_HA_DBSERVER_INFO *db_info_t = NULL;

        if (strcmp (elem_name, "Server") == 0)
        {
            T_HA_DB_PROC_INFO *dbproc_info = NULL;

            if ((get_all_dbmode == 0)
                && (is_name_in_list (tmpbuf, dblist) == 0))
            {
                retval = ERR_NO_ERROR;
                goto func_return;
            }

            dbproc_info =
                (T_HA_DB_PROC_INFO *) MALLOC (sizeof (T_HA_DB_PROC_INFO));

            if (dbproc_info == NULL)
            {
                retval = ERR_MEM_ALLOC;
                goto func_return;
            }

            /* create a T_HA_DB_PROC_INFO element */
            strcpy_limit (dbproc_info->dbname, tmpbuf,
                          sizeof (dbproc_info->dbname));
            strcpy_limit (dbproc_info->state, state,
                          sizeof (dbproc_info->state));
            dbproc_info->pid = atoi (pid);

            /*
            * if the dbname is already exist in dbinfo list, add the server proc
            * info to the node with the dbname.
            */
            if ((dbinfo_index =
                dbname_exist_in_dbinfo_list ((*nitem),
                                             dbproc_info->dbname,
                                             *all_info)) >= 0)
            {
                (*all_info)->db_info[dbinfo_index].dbproc_info = dbproc_info;
            }
            else
            {
                /*
                * Else add a new dbnode, and add the server proc info to the node.
                */
                if ((*nitem) >= (*nalloc))
                {
                    (*nalloc) *= 2;

                    (*all_info)->db_info =
                        (T_HA_DBSERVER_INFO *) realloc ((*all_info)->db_info,
                                                        (*nalloc) * sizeof (T_HA_DBSERVER_INFO));

                    if ((*all_info)->db_info == NULL)
                        {
                        retval = ERR_MEM_ALLOC;
                        goto func_return;
                    }
                }

                /* create two node list for applylogdb and copylogdb process of the server. */
                copylogdb_info =
                    (T_HA_LOG_PROC_INFO *) MALLOC ((*nproc_alloc) *
                                                    sizeof (T_HA_LOG_PROC_INFO));
                applylogdb_info =
                    (T_HA_LOG_PROC_INFO *) MALLOC ((*nproc_alloc) *
                                                    sizeof (T_HA_LOG_PROC_INFO));

                if (copylogdb_info == NULL || applylogdb_info == NULL)
                {
                    FREE_MEM (copylogdb_info);
                    FREE_MEM (applylogdb_info);
                    retval = ERR_MEM_ALLOC;
                    goto func_return;
                }

                db_info_t = &((*all_info)->db_info[(*nitem)]);

                strcpy_limit (db_info_t->dbname,
                              dbproc_info->dbname, sizeof (db_info_t->dbname));
                db_info_t->dbproc_info = dbproc_info;
                db_info_t->applylogdb_info = applylogdb_info;
                db_info_t->copylogdb_info = copylogdb_info;
                db_info_t->num_ap = 0;
                db_info_t->num_cp = 0;
                (*nitem)++;
            }
        }
        else
        {
            /*
            * if the elem_name is 'Applylogdb' or 'Copylogdb'.
            */

            /* create a tmp T_HA_LOG_PROC_INFO element for later copy. */
            T_HA_DBSERVER_INFO *db_info_t = NULL;
            T_HA_LOG_PROC_INFO p_proc_info;
            memset (&p_proc_info, 0, sizeof (T_HA_LOG_PROC_INFO));
            if (sscanf (tmpbuf, "%63[^@] @ %128[^:] : %1023s", dbname,
                        hostname, logpath) != 3)
            {
                retval = ERR_NO_ERROR;
                goto func_return;
            }

            if ((get_all_dbmode == 0)
                && (is_name_in_list (dbname, dblist) == 0))
            {
                retval = ERR_NO_ERROR;
                goto func_return;
            }

            strcpy_limit (p_proc_info.dbname, dbname,
                          sizeof (p_proc_info.dbname));
            strcpy_limit (p_proc_info.hostname, hostname,
                          sizeof (p_proc_info.hostname));
            strcpy_limit (p_proc_info.logpath, logpath,
                          sizeof (p_proc_info.logpath));
            strcpy_limit (p_proc_info.state, state, sizeof (p_proc_info.state));
            p_proc_info.pid = atoi (pid);

            /*
            * if the node already exist in the dbinfo list, then add
            * the Applylogdb or Copylogdb proc info to the node with the
            * dbname.
            */
            if ((dbinfo_index =
                dbname_exist_in_dbinfo_list ((*nitem),
                                             p_proc_info.dbname,
                                             *all_info)) >= 0)
            {
                db_info_t = &((*all_info)->db_info[dbinfo_index]);

                if (db_info_t->num_ap >= (*nproc_alloc))
                {
                    (*nproc_alloc) *= 2;
                    db_info_t->applylogdb_info =
                        (T_HA_LOG_PROC_INFO *) realloc (db_info_t->applylogdb_info,
                                                        (*nproc_alloc) * sizeof (T_HA_LOG_PROC_INFO));
                    db_info_t->copylogdb_info =
                        (T_HA_LOG_PROC_INFO *) realloc (db_info_t->copylogdb_info,
                                                        (*nproc_alloc) * sizeof (T_HA_LOG_PROC_INFO));

                    if ((db_info_t->applylogdb_info == NULL) ||
                        (db_info_t->copylogdb_info == NULL))
                    {
                        retval = ERR_MEM_ALLOC;
                        goto func_return;
                    }
                }

                if (strcmp (elem_name, "Applylogdb") == 0)
                {
                    memmove (&(db_info_t->applylogdb_info[db_info_t->num_ap]),
                             &p_proc_info, sizeof (T_HA_LOG_PROC_INFO));
                    db_info_t->num_ap++;
                }
                else
                {
                    /* set the copylogdb mode. */
                    set_copylogdb_mode (&p_proc_info);

                    memmove (&(db_info_t->copylogdb_info[db_info_t->num_cp]),
                             &p_proc_info, sizeof (T_HA_LOG_PROC_INFO));
                    db_info_t->num_cp++;
                }
            }
            else
            {
                /*
                * if the node does not exist in the dbinfo list,
                * add a new node with the dbname, and add Applylogdb and
                * Copylogdb to the node.
                */

                if ((*nitem) >= (*nalloc))
                {
                    (*nalloc) *= 2;

                    (*all_info)->db_info =
                        (T_HA_DBSERVER_INFO *) realloc ((*all_info)->db_info,
                                                        (*nalloc) * sizeof (T_HA_DBSERVER_INFO));
                    if ((*all_info)->db_info == NULL)
                    {
                        retval = ERR_MEM_ALLOC;
                        goto func_return;
                    }
                }

                /* create two node list for applylogdb and copylogdb process of the server. */
                copylogdb_info =
                    (T_HA_LOG_PROC_INFO *) MALLOC ((*nproc_alloc) *
                                                    sizeof (T_HA_LOG_PROC_INFO));
                applylogdb_info =
                    (T_HA_LOG_PROC_INFO *) MALLOC ((*nproc_alloc) *
                                                    sizeof (T_HA_LOG_PROC_INFO));

                if (copylogdb_info == NULL || applylogdb_info == NULL)
                {
                    FREE_MEM (copylogdb_info);
                    FREE_MEM (applylogdb_info);
                    retval = ERR_MEM_ALLOC;
                    goto func_return;
                }

                db_info_t = &((*all_info)->db_info[(*nitem)]);
                strcpy_limit (db_info_t->dbname,
                              p_proc_info.dbname, sizeof (db_info_t->dbname));
                db_info_t->dbproc_info = NULL;
                db_info_t->copylogdb_info = copylogdb_info;
                db_info_t->applylogdb_info = applylogdb_info;
                db_info_t->num_ap = 0;
                db_info_t->num_cp = 0;

                if (strcmp (elem_name, "Applylogdb") == 0)
                {
                    memmove (&(db_info_t->applylogdb_info[db_info_t->num_ap]),
                             &p_proc_info, sizeof (T_HA_LOG_PROC_INFO));
                    db_info_t->num_ap++;
                }
                if (strcmp (elem_name, "Copylogdb") == 0)
                {
                    /* set the copylogdb mode. */
                    set_copylogdb_mode (&p_proc_info);

                    memmove (&(db_info_t->copylogdb_info[db_info_t->num_cp]),
                             &p_proc_info, sizeof (T_HA_LOG_PROC_INFO));
                    db_info_t->num_cp++;
                }
                (*nitem)++;
            }
        }
    }

func_return:
    return retval;
}

static int
parse_ha_node_to_all_info_array (char *buf, T_HA_SERVER_INFO_ALL ** all_info,
                                 int *node_alloc, char *_dbmt_error)
{
    char tok[4][64] = { {0}, {0}, {0}, {0} };
    char ipaddr[64] = { 0 };
    T_HA_NODE_INFO *node_info_t = NULL;

    if (((*all_info)->num_nodeinfo) >= (*node_alloc))
    {
        (*node_alloc) *= 2;

        (*all_info)->node_info =
            (T_HA_NODE_INFO *) realloc ((*all_info)->node_info,
                                        (*node_alloc) * sizeof (T_HA_NODE_INFO));

        if ((*all_info)->node_info == NULL)
        {
            return ERR_MEM_ALLOC;
        }
    }

    node_info_t = &((*all_info)->node_info[(*all_info)->num_nodeinfo]);

    if (sscanf (buf, "%63s %63s %*s %63[^,] , %*s %63[^)]",
                tok[0], tok[1], tok[2], tok[3]) != 4)
    {
        return ERR_NO_ERROR;
    }

    strcpy_limit (node_info_t->hostname, tok[1],
                  sizeof (node_info_t->hostname));

    get_ip_from_hostname (tok[1], ipaddr, sizeof (ipaddr));

    if (ipaddr == NULL)
    {
        strcpy_limit (_dbmt_error, "can't get ip addr from hostname",
                      DBMT_ERROR_MSG_SIZE);
        return ERR_WITH_MSG;
    }

    strcpy_limit (node_info_t->ip, ipaddr, sizeof (node_info_t->ip));

    node_info_t->priority = atoi (tok[2]);

    strcpy_limit (node_info_t->state, tok[3], sizeof (node_info_t->state));

    (*all_info)->num_nodeinfo++;
    return ERR_NO_ERROR;
}

static int
record_ha_topology_to_struct (FILE * infile, int get_all_dbmode, char *dblist,
                              char *_dbmt_error,
                              T_HA_SERVER_INFO_ALL ** all_info)
{
    char buf[2048] = { 0 };
    char ha_elem_name[64] = { 0 };
    T_HA_DBSERVER_INFO *dbserver_p = NULL;
    T_HA_NODE_INFO *node_p = NULL;

    int nitem = 0;
    int nalloc = 15;
    int nproc_alloc = 20;
    int node_alloc = 10;
    int retval = ERR_NO_ERROR;

    /* Create a dbproc info list which contains all the info about the HA-Process. */
    dbserver_p =
        (T_HA_DBSERVER_INFO *) MALLOC (nalloc * sizeof (T_HA_DBSERVER_INFO));
    node_p = (T_HA_NODE_INFO *) MALLOC (node_alloc * sizeof (T_HA_NODE_INFO));

    if (dbserver_p == NULL || node_p == NULL)
    {
        FREE_MEM (dbserver_p);
        FREE_MEM (node_p);
        return ERR_MEM_ALLOC;
    }

    (*all_info)->db_info = dbserver_p;
    (*all_info)->node_info = node_p;
    (*all_info)->num_dbinfo = 0;
    (*all_info)->num_nodeinfo = 0;

    while (fgets (buf, sizeof (buf), infile))
    {
        sscanf (buf, "%63s", ha_elem_name);
        if (strcmp (ha_elem_name, "HA-Node") == 0)
        {
            char tok[4][64] = { {0}, {0}, {0}, {0} };

            if (sscanf (buf, "%63s %63s %*s %63[^,] , %*s %63[^)]",
                        tok[0], tok[1], tok[2], tok[3]) != 4)
            {
                continue;
            }
            if (strcmp (tok[0], "HA-Node") == 0)
            {
                strcpy_limit ((*all_info)->current_node, tok[2],
                               sizeof ((*all_info)->current_node));
                strcpy_limit ((*all_info)->current_node_state, tok[3],
                               sizeof ((*all_info)->current_node_state));
            }
        }
        else if (strcmp (ha_elem_name, "Node") == 0)
        {
            parse_ha_node_to_all_info_array (buf, all_info, &node_alloc,
                                             _dbmt_error);
        }
        else if (strcmp (ha_elem_name, "Applylogdb") == 0 ||
            strcmp (ha_elem_name, "Copylogdb") == 0 ||
            strcmp (ha_elem_name, "Server") == 0)
        {
            if (get_all_dbmode == 0 && dblist == NULL)
            {
                continue;
            }
            if ((retval =
                parse_ha_proc_msg_to_all_info_array
                    (buf, _dbmt_error, all_info, &nitem, &nalloc,
                     &nproc_alloc, get_all_dbmode, dblist)) != ERR_NO_ERROR)
            {
                goto func_return;
            }
        }
        else if ((strcmp (ha_elem_name, "++") == 0))
        {
            /* delete the '\n' at the end of buf. */
            ut_trim (buf);

            /* ignore the "++" tag. */
            strcpy_limit (_dbmt_error, &buf[2], DBMT_ERROR_MSG_SIZE);
            retval = ERR_WITH_MSG;
            goto func_return;
        }
    }

    retval = ERR_NO_ERROR;

func_return:
    (*all_info)->num_dbinfo = nitem;
    return retval;
}

static int
fill_dbmode_into_dbinfo_list (T_HA_SERVER_INFO_ALL ** all_info,
                              char *_dbmt_error)
{
    int i;
    T_HA_DBSERVER_INFO *dbserver_info_t = NULL;
    T_DB_MODE_INFO *dbmode_info_p = NULL;

    for (i = 0; i < (*all_info)->num_dbinfo; i++)
    {
        dbmode_info_p = (T_DB_MODE_INFO *) MALLOC (sizeof (T_DB_MODE_INFO));
        dbserver_info_t = &(*all_info)->db_info[i];

        if (dbmode_info_p == NULL)
        {
            return ERR_MEM_ALLOC;
        }

        cmd_get_db_mode (dbmode_info_p, dbserver_info_t->dbname, _dbmt_error);
        dbserver_info_t->dbmode_info = dbmode_info_p;
    }

    return ERR_NO_ERROR;
}

/*
 * get port info from brokers config, that located by <broker_name>
 */
static const char *
_op_get_port_from_config (T_CM_BROKER_CONF * uc_conf, char *broker_name)
{
    int pos;
    char *name;
    for (pos = 0; pos < uc_conf->num_broker; pos++)
    {
        name = cm_br_conf_get_value (&(uc_conf->br_conf[pos]), "%");
        if (name != NULL && strcasecmp (broker_name, name) == 0)
        {
            return cm_br_conf_get_value (&(uc_conf->br_conf[pos]),
                                         "BROKER_PORT");
        }
    }

    /* not found. in this case returns zero value, it is means unknown port. */
    return "0";
}

/* Read dbmt password file and append user information to nvplist */
static void
_tsAppendDBMTUserList (nvplist * res, T_DBMT_USER * dbmt_user,
                       int return_dbmt_pwd, char *_dbmt_error)
{
    const char *unicas_auth, *dbcreate = NULL;
    int i, j;

    nv_add_nvp (res, "open", "userlist");
    for (i = 0; i < dbmt_user->num_dbmt_user; i++)
    {
        if (dbmt_user->user_info[i].user_name[0] == '\0')
        {
            continue;
        }
        nv_add_nvp (res, "open", "user");
        nv_add_nvp (res, ENCRYPT_ARG ("id"), dbmt_user->user_info[i].user_name);
        if (return_dbmt_pwd)
        {
            char decrypted[PASSWD_LENGTH + 1];

            uDecrypt (PASSWD_LENGTH, dbmt_user->user_info[i].user_passwd,
                      decrypted);
            nv_add_nvp (res, ENCRYPT_ARG ("passwd"), decrypted);
        }

        nv_add_nvp (res, "open", "dbauth");
        unicas_auth = NULL;
        /* add dbinfo */
        for (j = 0; j < dbmt_user->user_info[i].num_dbinfo; j++)
        {
            if (dbmt_user->user_info[i].dbinfo[j].dbname[0] == '\0')
            {
                continue;
            }
#ifdef JSON_SUPPORT
            nv_add_nvp (res, "open", "auth_info");
#endif
            nv_add_nvp (res, "dbname",
                        dbmt_user->user_info[i].dbinfo[j].dbname);
            nv_add_nvp (res, ENCRYPT_ARG ("dbid"),
                        dbmt_user->user_info[i].dbinfo[j].uid);
            nv_add_nvp (res, "dbbrokeraddress",
                        dbmt_user->user_info[i].dbinfo[j].broker_address);
#ifdef JSON_SUPPORT
            nv_add_nvp (res, "close", "auth_info");
#endif
        }
        nv_add_nvp (res, "close", "dbauth");

        /* add auth info */
        for (j = 0; j < dbmt_user->user_info[i].num_authinfo; j++)
        {
            if (dbmt_user->user_info[i].authinfo[j].domain[0] == '\0')
            {
                continue;
            }
            if (strcmp (dbmt_user->user_info[i].authinfo[j].domain, "unicas") == 0)
            {
                unicas_auth = dbmt_user->user_info[i].authinfo[j].auth;
                nv_add_nvp (res, "casauth",
                            dbmt_user->user_info[i].authinfo[j].auth);
                continue;
            }
            else
            if (strcmp
                (dbmt_user->user_info[i].authinfo[j].domain, "dbcreate") == 0)
            {
                dbcreate = dbmt_user->user_info[i].authinfo[j].auth;
                nv_add_nvp (res, "dbcreate",
                            dbmt_user->user_info[i].authinfo[j].auth);
                continue;
            }
            else
            if (strcmp (dbmt_user->user_info[i].authinfo[j].domain,
                        "statusmonitorauth") == 0)
            {
                nv_add_nvp (res, "statusmonitorauth",
                            dbmt_user->user_info[i].authinfo[j].auth);
                continue;
            }
        }
        if (unicas_auth == NULL)
        {
            nv_add_nvp (res, "casauth", "none");
        }

        if (dbcreate == NULL)
        {
            nv_add_nvp (res, "dbcreate", "none");
        }
        nv_add_nvp (res, "close", "user");
    }
    nv_add_nvp (res, "close", "userlist");
}

static char *
get_user_name (int uid, char *name_buf)
{
#if defined(WINDOWS)
    strcpy (name_buf, "");
#else
    struct passwd *pwd;

    pwd = getpwuid (uid);
    if (pwd->pw_name)
    {
        strcpy (name_buf, pwd->pw_name);
    }
    else
    {
        name_buf[0] = '\0';
    }
#endif

    return name_buf;
}

static int
uca_conf_write (T_CM_BROKER_CONF * uc_conf, char *del_broker,
                char *_dbmt_error)
{
    char buf[512];
    FILE *fp;
    int i, j;
    struct stat statbuf;

    for (i = 0; i < uc_conf->num_header; i++)
    {
        if (uc_conf->header_conf[i].name == NULL ||
            uc_conf->header_conf[i].value == NULL)
        {
            return ERR_MEM_ALLOC;
        }
    }
    for (i = 0; i < uc_conf->num_broker; i++)
    {
        for (j = 0; j < uc_conf->br_conf[i].num; j++)
        {
            if (uc_conf->br_conf[i].item[j].name == NULL ||
                uc_conf->br_conf[i].item[j].value == NULL)
            {
                return ERR_MEM_ALLOC;
            }
        }
    }

    cm_get_broker_file (UC_FID_CUBRID_BROKER_CONF, buf);

    if (stat (buf, &statbuf) < 0)
    {
        cm_get_broker_file (UC_FID_CUBRID_CAS_CONF, buf);
        if (stat (buf, &statbuf) < 0)
        {
            cm_get_broker_file (UC_FID_UNICAS_CONF, buf);
            if (stat (buf, &statbuf) < 0)
            {
                cm_get_broker_file (UC_FID_CUBRID_BROKER_CONF, buf);
            }
        }
    }

    if ((fp = fopen (buf, "w")) == NULL)
    {
        strcpy (_dbmt_error, buf);
        return ERR_FILE_OPEN_FAIL;
    }
    fprintf (fp, "[broker]\n");
    for (i = 0; i < uc_conf->num_header; i++)
    {
        fprintf (fp, "%-25s =%s\n",
                 uc_conf->header_conf[i].name, uc_conf->header_conf[i].value);
    }
    fprintf (fp, "\n");
    for (i = 0; i < uc_conf->num_broker; i++)
    {
        if ((del_broker != NULL) &&
            (strcmp (uc_conf->br_conf[i].item[0].value, del_broker) == 0))
        {
            continue;
        }
        fprintf (fp, "[%s%s]\n", uc_conf->br_conf[i].item[0].name,
                 to_upper_str (uc_conf->br_conf[i].item[0].value, buf));
        for (j = 1; j < uc_conf->br_conf[i].num; j++)
        {
            if (uc_conf->br_conf[i].item[j].value[0] == '\0')
                continue;
            fprintf (fp, "%-25s =%s\n", uc_conf->br_conf[i].item[j].name,
                     uc_conf->br_conf[i].item[j].value);
        }
        fprintf (fp, "\n");
    }
    fclose (fp);
    return ERR_NO_ERROR;
}

static int
_tsParseSpacedb (nvplist * req, nvplist * res, char *dbname,
                 char *_dbmt_error, T_SPACEDB_RESULT * cmd_res)
{
    int pagesize, logpagesize, i;
    T_SPACEDB_INFO *vol_info;
    char dbdir[PATH_MAX];
#if defined(WINDOWS)
    WIN32_FIND_DATA data;
    char find_file[PATH_MAX];
    HANDLE handle;
    int found;
#else
    DIR *dirp = NULL;
    struct dirent *dp = NULL;
#endif

    pagesize = cmd_res->page_size;
    logpagesize = cmd_res->log_page_size;
    nv_update_val_int (res, "pagesize", pagesize);
    nv_update_val_int (res, "logpagesize", logpagesize);

    vol_info = cmd_res->vol_info;
    for (i = 0; i < cmd_res->num_vol; i++)
    {
        nv_add_nvp (res, "open", "spaceinfo");
        nv_add_nvp (res, "spacename", vol_info[i].vol_name);
        nv_add_nvp (res, "type", vol_info[i].purpose);
        nv_add_nvp (res, "location", vol_info[i].location);
        nv_add_nvp_int (res, "totalpage", vol_info[i].total_page);
        nv_add_nvp_int (res, "freepage", vol_info[i].free_page);
        _add_nvp_time (res, "date", vol_info[i].date, "%04d%02d%02d",
                       NV_ADD_DATE);
        nv_add_nvp (res, "close", "spaceinfo");
    }

    vol_info = cmd_res->tmp_vol_info;
    for (i = 0; i < cmd_res->num_tmp_vol; i++)
    {
        nv_add_nvp (res, "open", "spaceinfo");
        nv_add_nvp (res, "spacename", vol_info[i].vol_name);
        nv_add_nvp (res, "type", vol_info[i].purpose);
        nv_add_nvp (res, "location", vol_info[i].location);
        nv_add_nvp_int (res, "totalpage", vol_info[i].total_page);
        nv_add_nvp_int (res, "freepage", vol_info[i].free_page);
        _add_nvp_time (res, "date", vol_info[i].date, "%04d%02d%02d",
                       NV_ADD_DATE);
        nv_add_nvp (res, "close", "spaceinfo");
    }

    if (uRetrieveDBLogDirectory (dbname, dbdir) != ERR_NO_ERROR)
    {
        strcpy (_dbmt_error, dbname);
        return ERR_DBDIRNAME_NULL;
    }

    /* read entries in the directory and generate result */
#if defined(WINDOWS)
    snprintf (find_file, PATH_MAX - 1, "%s/*", dbdir);
    if ((handle = FindFirstFile (find_file, &data)) == INVALID_HANDLE_VALUE)
#else
    if ((dirp = opendir (dbdir)) == NULL)
#endif
    {
        sprintf (_dbmt_error, "%s", dbdir);
        return ERR_DIROPENFAIL;
    }

#if defined(WINDOWS)
    for (found = 1; found; found = FindNextFile (handle, &data))
#else
    while ((dp = readdir (dirp)) != NULL)
#endif
    {
        int baselen;
        char *fname;

#if defined(WINDOWS)
        fname = data.cFileName;
#else
        fname = dp->d_name;
#endif
        baselen = strlen (dbname);

        if (strncmp (fname, dbname, baselen) == 0)
        {
            if (!strcmp (fname + baselen, CUBRID_ACT_LOG_EXT))
            {
                _ts_gen_spaceinfo (res, fname, dbdir, "Active_log",
                                   logpagesize);
            }
            else if (!strncmp (fname + baselen, CUBRID_ARC_LOG_EXT,
                               CUBRID_ARC_LOG_EXT_LEN))
            {
                _ts_gen_spaceinfo (res, fname, dbdir, "Archive_log",
                                   logpagesize);
            }
#if 0
            else if (strncmp (fname + baselen, "_lginf", 6) == 0)
            {
                _ts_gen_spaceinfo (res, fname, dbdir, "Generic_log",
                                   logpagesize);
            }
#endif

        }
    }
#if defined(WINDOWS)
    FindClose (handle);
#else
    closedir (dirp);
#endif

    /* add last line */
    nv_add_nvp (res, "open", "spaceinfo");
    nv_add_nvp (res, "spacename", "Total");
    nv_add_nvp (res, "type", "");
    nv_add_nvp (res, "location", "");
    nv_add_nvp (res, "totlapage", "0");
    nv_add_nvp (res, "freepage", "0");
    nv_add_nvp (res, "date", "");
    nv_add_nvp (res, "close", "spaceinfo");

    if (uRetrieveDBDirectory (dbname, dbdir) == ERR_NO_ERROR)
    {
        nv_add_nvp_int (res, "freespace", ut_disk_free_space (dbdir));
    }
    else
    {
        nv_add_nvp_int (res, "freespace", -1);
    }
    return ERR_NO_ERROR;
}

static void
_ts_gen_spaceinfo (nvplist * res, const char *filename,
                   const char *dbinstalldir, const char *type, int pagesize)
{
    char volfile[PATH_MAX];
    struct stat statbuf;

    nv_add_nvp (res, "open", "spaceinfo");
    nv_add_nvp (res, "spacename", filename);
    nv_add_nvp (res, "type", type);
    nv_add_nvp (res, "location", dbinstalldir);

    snprintf (volfile, PATH_MAX - 1, "%s/%s", dbinstalldir, filename);
    stat (volfile, &statbuf);

    nv_add_nvp_int (res, "totalpage",
                    pagesize ? statbuf.st_size / pagesize : 0);
    nv_add_nvp (res, "freepage", " ");

    _add_nvp_time (res, "date", statbuf.st_mtime, "%04d%02d%02d", NV_ADD_DATE);

    nv_add_nvp (res, "close", "spaceinfo");
    return;
}

static int
_ts_lockdb_parse_us (nvplist * res, FILE * infile)
{
    char buf[1024], s[256], s1[256], s2[256], s3[256], s4[256];
    char *temp, *temp2;
    int scan_matched;
    int flag = 0;
    int flag_lot_tag = 0;
    int has_index_name = 0;

    nv_add_nvp (res, "open", "lockinfo");
    while (fgets (buf, sizeof (buf), infile))
    {
        sscanf (buf, "%255s", s);

        if (flag == 0 && !strcmp (s, "***"))
        {
            fgets (buf, sizeof (buf), infile);
            scan_matched =
                sscanf (buf, "%*s %*s %*s %*s %255s %*s %*s %*s %*s %255s", s1, s2);

            if (scan_matched != 2)
            {
                return -1;
            }
            if (strlen (s1) > 0)
            {
                s1[strlen (s1) - 1] = '\0';
            }
            nv_add_nvp (res, "esc", s1);
            nv_add_nvp (res, "dinterval", s2);
            flag = 1;
        }
        else if (flag == 1)
        {
            if (strcmp (s, "Transaction") == 0)
            {
                scan_matched =
                    sscanf (buf, "%*s %*s %255s %255s %255s", s1, s2, s3);

                if (scan_matched != 3)
                {
                    return -1;
                }

                s1[strlen (s1) - 1] = '\0';
                s2[strlen (s2) - 1] = '\0';
                s3[strlen (s3) - 1] = '\0';

                nv_add_nvp (res, "open", "transaction");
                nv_add_nvp (res, "index", s1);
                nv_add_nvp (res, "pname", s2);

                temp = strchr (s3, '@');
                if (temp != NULL)
                {
                    strncpy (buf, s3, (int) (temp - s3));
                    buf[(int) (temp - s3)] = '\0';
                    nv_add_nvp (res, ENCRYPT_ARG ("uid"), buf);
                }

                temp2 = strrchr (s3, '|');
                if (temp2 != NULL)
                {
                    strncpy (buf, temp + 1, (int) (temp2 - temp - 1));
                    buf[(int) (temp2 - temp) - 1] = '\0';
                    nv_add_nvp (res, "host", buf);
	
                    nv_add_nvp (res, "pid", temp2 + 1);    /* moved from below to avoid seg. fault */
                }

                fgets (buf, sizeof (buf), infile);
                buf[strlen (buf) - 1] = '\0';
                nv_add_nvp (res, "isolevel", buf + strlen ("Isolation "));

                fgets (buf, sizeof (buf), infile);
                if (strncmp (buf, "State", strlen ("State")) == 0)
                {
                    fgets (buf, sizeof (buf), infile);
                }

                scan_matched = sscanf (buf, "%*s %255s", s1);

                if (scan_matched != 1)
                {
                    return -1;
                }
                nv_add_nvp (res, "timeout", s1);
                nv_add_nvp (res, "close", "transaction");
            }
            else if (strcmp (s, "Object") == 0)
            {
                fgets (buf, sizeof (buf), infile);
                scan_matched =
                    sscanf (buf, "%*s %*s %*s %*s %*s %*s %*s %*s %255s", s1);
                if (scan_matched != 1)
                {
                    return -1;
                }
                nv_add_nvp (res, "open", "lot");
                flag_lot_tag = 1;
                nv_add_nvp (res, "numlocked", s1);

                fgets (buf, sizeof (buf), infile);
                scan_matched =
                    sscanf (buf, "%*s %*s %*s %*s %*s %*s %*s %*s %*s %255s", s2);
                if (scan_matched != 1)
                {
                    return -1;
                }
                nv_add_nvp (res, "maxnumlock", s2);
                flag = 2;
            }
        }            /* end of if (flag == 1) */
        else if (flag == 2)
        {
            char value[1024];

            while (!strcmp (s, "OID"))
            {
                int num_holders, num_b_holders, num_waiters, scan_matched;

                scan_matched =
                    sscanf (buf, "%*s %*s  %[^|] %*[|] %[^|] %*[|] %255s", s1, s2, s3);
                if (scan_matched != 3)
                {
                    return -1;
                }

                snprintf (value, sizeof (value) - 1, "%s|%s|%s", s1, s2, s3);

                nv_add_nvp (res, "open", "entry");
                nv_add_nvp (res, "oid", value);

                fgets (buf, sizeof (buf), infile);
                sscanf (buf, "%*s %*s %255s", s);

                s1[0] = s2[0] = s3[0] = '\0';
                scan_matched = 0;
                if ((strcmp (s, "Class") == 0) || (strcmp (s, "Instance") == 0)
                    || (strcmp (s, "Index") == 0))
                {
                    char *p;
                    p = strchr (buf, ':');
                    if (strlen (buf) > 1)
                    {
                        buf[strlen (buf) - 1] = '\0';
                        if (buf[strlen (buf) - 1] == '.')
                        {
                            buf[strlen (buf) - 1] = '\0';
                        }
                    }
                    nv_add_nvp (res, "ob_type", p + 2);
                    if (strcmp (s, "Index") == 0)
                    {
                        has_index_name = 1;
                    }
                    fgets (buf, sizeof (buf), infile);
                }
                else if (strcmp (s, "Root") == 0)
                {
                    nv_add_nvp (res, "ob_type", "Root class");
                    fgets (buf, sizeof (buf), infile);
                }
                else
                {
                    /* Current test is not 'OID = ...' and if 'Total mode of holders ...' then */
                    if (has_index_name == 1)
                    {
                        fgets (buf, sizeof (buf), infile);
                    }
                    scan_matched =
                        sscanf (buf,
                                "%*s %*s %255s %*s %*s %255s %*s %*s %255s", s1, s2, s3);
                    if ((strncmp (s1, "of", 2) == 0)
                        && (strncmp (s3, "of", 2) == 0))
                    {
                        nv_add_nvp (res, "ob_type", "None");
                    }
                    else
                    {
                        return -1;
                    }
                }

                if (has_index_name == 1)
                {
                    fgets (buf, sizeof (buf), infile);
                }
                /* already get  scan_matched value, don't sscanf */
                if (scan_matched == 0)
                    scan_matched =
                        sscanf (buf, "%*s %*s %255s %*s %*s %255s %*s %*s %255s", s1, s2, s3);

                if ((strncmp (s1, "of", 2) == 0)
                    && (strncmp (s3, "of", 2) == 0))
                {
                    /* ignore UnixWare's 'Total mode of ...' text */
                    fgets (buf, sizeof (buf), infile);
                    scan_matched =
                        sscanf (buf, "%*s %*s %255s %*s %*s %255s %*s %*s %255s", s1, s2, s3);
                }

                if (scan_matched != 3)
                {
                    return -1;
                }
                s1[strlen (s1) - 1] = '\0';
                s2[strlen (s2) - 1] = '\0';

                num_holders = atoi (s1);
                num_b_holders = atoi (s2);
                num_waiters = atoi (s3);

                if (num_waiters < 0 || num_waiters >= INT_MAX)
                {
                    return -1;
                }

                nv_add_nvp (res, "num_holders", s1);
                nv_add_nvp (res, "num_b_holders", s2);
                nv_add_nvp (res, "num_waiters", s3);

                while (fgets (buf, sizeof (buf), infile))
                {
                    sscanf (buf, "%255s", s);
                    if (strcmp (s, "NON_2PL_RELEASED:") == 0)
                    {
                        fgets (buf, sizeof (buf), infile);
                        while (sscanf (buf, "%255s", s))
                        {
                            if (strcmp (s, "Tran_index") != 0)
                            {
                                break;
                            }
                            else
                            {
                                if (fgets (buf, sizeof (buf), infile) == NULL)
                                {
                                    break;
                                }
                            }
                        }
                        break;
                    }        /* ignore NON_2PL_RELEASED information */

                    sscanf (buf, "%*s %255s", s);
                    if (strcmp (s, "HOLDERS:") == 0)
                    {
                        int index;

                        for (index = 0; index < num_holders; index++)
                        {
                            /* make lock holders information */

                            fgets (buf, sizeof (buf), infile);
                            scan_matched =
                                sscanf (buf,
                                        "%*s %*s %255s %*s %*s %255s %*s %*s %255s %*s %*s %255s",
                                        s1, s2, s3, s4);

                            /* parshing error */
                            if (scan_matched < 3)
                            {
                                return -1;
                            }
                            if (scan_matched == 4)
                            {
                                /* nsubgranules is existed */
                                s3[strlen (s3) - 1] = '\0';
                            }

                            s1[strlen (s1) - 1] = '\0';
                            s2[strlen (s2) - 1] = '\0';

                            nv_add_nvp (res, "open", "lock_holders");
                            nv_add_nvp (res, "tran_index", s1);
                            nv_add_nvp (res, "granted_mode", s2);
                            nv_add_nvp (res, "count", s3);
                            if (scan_matched == 4)
                            {
                                nv_add_nvp (res, "nsubgranules", s4);
                            }
                            nv_add_nvp (res, "close", "lock_holders");
                        }

                        if ((num_b_holders == 0) && (num_waiters == 0))
                        {
                            break;
                        }
                    }
                    else if (strcmp (s, "LOCK") == 0)
                    {
                        int index;
                        char *p;

                        for (index = 0; index < num_b_holders; index++)
                        {
                            /* make blocked lock holders */
                            int scan_matched;
                            fgets (buf, sizeof (buf), infile);
                            scan_matched =
                                sscanf (buf,
                                        "%*s %*s %255s %*s %*s %255s %*s %*s %255s %*s %*s %255s",
                                        s1, s2, s3, s4);

                            /* parshing error */
                            if (scan_matched < 3)
                            {
                                return -1;
                            }
                            if (scan_matched == 4)
                            {
                                /* nsubgranules is existed */
                                s3[strlen (s3) - 1] = '\0';
                            }

                            s1[strlen (s1) - 1] = '\0';
                            s2[strlen (s2) - 1] = '\0';

                            nv_add_nvp (res, "open", "b_holders");
                            nv_add_nvp (res, "tran_index", s1);
                            nv_add_nvp (res, "granted_mode", s2);
                            nv_add_nvp (res, "count", s3);

                            if (scan_matched == 4)
                            {
                                nv_add_nvp (res, "nsubgranules", s4);
                            }
                            fgets (buf, sizeof (buf), infile);
                            sscanf (buf, "%*s %*s %255s", s1);
                            nv_add_nvp (res, "b_mode", s1);

                            fgets (buf, sizeof (buf), infile);
                            p = strchr (buf, '=');
                            buf[strlen (buf) - 1] = '\0';
                            nv_add_nvp (res, "start_at", p + 2);

                            fgets (buf, sizeof (buf), infile);
                            sscanf (buf, "%*s %*s %255s", s1);
                            nv_add_nvp (res, "waitfornsec", s1);

                            nv_add_nvp (res, "close", "b_holders");
                        }

                        if (num_waiters == 0)
                        {
                            break;
                        }
                    }
                    else if (strcmp (s, "WAITERS:") == 0)
                    {
                        int index;

                        for (index = 0; index < num_waiters; index++)
                        {
                            /* make lock waiters */
                            char *p;

                            fgets (buf, sizeof (buf), infile);
                            sscanf (buf, "%*s %*s %255s %*s %*s %255s", s1, s2);
                            s1[strlen (s1) - 1] = '\0';

                            nv_add_nvp (res, "open", "waiters");
                            nv_add_nvp (res, "tran_index", s1);
                            nv_add_nvp (res, "b_mode", s2);

                            fgets (buf, sizeof (buf), infile);
                            p = strchr (buf, '=');
                            buf[strlen (buf) - 1] = '\0';
                            nv_add_nvp (res, "start_at", p + 2);

                            fgets (buf, sizeof (buf), infile);
                            sscanf (buf, "%*s %*s %255s", s1);
                            nv_add_nvp (res, "waitfornsec", s1);

                            nv_add_nvp (res, "close", "waiters");
                        }
                        break;
                    }
                }        /* end of while - for just one object */
                nv_add_nvp (res, "close", "entry");
            }            /* end of while(OID) */
        }
    }
    if (flag_lot_tag != 0)
    {
        nv_add_nvp (res, "close", "lot");
    }
    nv_add_nvp (res, "close", "lockinfo");
    return 0;
}

static char *
to_lower_str (char *str, char *buf)
{
    char *p;

    strcpy (buf, str);
    for (p = buf; *p; p++)
    {
        if (*p >= 'A' && *p <= 'Z')
        {
            *p = *p - 'A' + 'a';
        }
    }
    return buf;
}

static char *
to_upper_str (char *str, char *buf)
{
    char *p;

    strcpy (buf, str);
    for (p = buf; *p; p++)
    {
        if (*p >= 'a' && *p <= 'z')
        {
            *p = *p - 'a' + 'A';
        }
    }
    return buf;
}

static int
op_make_triggerinput_file_add (nvplist * req, char *input_filename)
{
    char *name, *status, *cond_source, *priority;
    char *event_target, *event_type, *event_time, *actiontime, *action;
    FILE *input_file;

    if (input_filename == NULL)
    {
        return 0;
    }

    input_file = fopen (input_filename, "w+");
    if (input_file == NULL)
    {
        return 0;
    }

    name = nv_get_val (req, "triggername");
    status = nv_get_val (req, "status");
    event_type = nv_get_val (req, "eventtype");
    event_target = nv_get_val (req, "eventtarget");
    event_time = nv_get_val (req, "conditiontime");
    cond_source = nv_get_val (req, "condition");
    actiontime = nv_get_val (req, "actiontime");
    action = nv_get_val (req, "action");
    priority = nv_get_val (req, "priority");
    /*            fprintf(input_file, ";autocommit off\n"); */
    fprintf (input_file, "create trigger\t%s\n", name);

    if (status)
    {
        fprintf (input_file, "status\t%s\n", status);
    }
    if (priority)
    {
        fprintf (input_file, "priority\t%s\n", priority);
    }
    fprintf (input_file, "%s\t%s\t", event_time, event_type);

    if (event_target)
    {
        fprintf (input_file, "ON\t%s\n", event_target);
    }
    if (cond_source)
    {
        fprintf (input_file, "if\t%s\n", cond_source);
    }
    fprintf (input_file, "execute\t");

    if (actiontime)
    {
        fprintf (input_file, "%s\t", actiontime);
    }
    fprintf (input_file, "%s\n", action);
    fprintf (input_file, "\n\ncommit;\n\n");

    fclose (input_file);

    return 1;
}

static int
op_make_triggerinput_file_drop (nvplist * req, char *input_filename)
{
    char *trigger_name;
    FILE *input_file;

    if (input_filename == NULL)
    {
        return 0;
    }

    input_file = fopen (input_filename, "w+");
    if (input_file == NULL)
    {
        return 0;
    }

    trigger_name = nv_get_val (req, "triggername");
    /*            fprintf(input_file, ";autocommit off\n"); */
    fprintf (input_file, "drop trigger\t%s\n", trigger_name);
    fprintf (input_file, "\n\n\ncommit;\n\n");

    fclose (input_file);

    return 1;
}

static int
op_make_triggerinput_file_alter (nvplist * req, char *input_filename)
{
    char *trigger_name, *status, *priority;
    FILE *input_file;

    if (input_filename == NULL)
    {
        return 0;
    }

    input_file = fopen (input_filename, "w+");
    if (input_file == NULL)
    {
        return 0;
    }

    trigger_name = nv_get_val (req, "triggername");
    status = nv_get_val (req, "status");
    priority = nv_get_val (req, "priority");
    /*            fprintf(input_file, ";autocommit off\n"); */
    if (status)
    {
        fprintf (input_file, "alter trigger\t%s\t", trigger_name);
        fprintf (input_file, "status %s\t", status);
    }

    if (priority)
    {
        fprintf (input_file, "alter trigger\t%s\t", trigger_name);
        fprintf (input_file, "priority %s\t", priority);
    }

    fprintf (input_file, "\n\n\ncommit;\n\n");
    fclose (input_file);

    return 1;
}

static int
get_broker_info_from_filename (char *path, char *br_name, int *as_id)
{
#if defined(WINDOWS)
    const char *sql_log_ext = ".sql.log";
    int sql_log_ext_len = strlen (sql_log_ext);
    int path_len;
    char *p;

    if (path == NULL)
    {
        return -1;
    }
    path_len = strlen (path);
    if (strncmp (path, sco.szCubrid, strlen (sco.szCubrid)) != 0 ||
        path_len <= sql_log_ext_len ||
        strcmp (path + (path_len - sql_log_ext_len), sql_log_ext) != 0)
    {
        return -1;
    }

    for (p = path + path_len - 1; p >= path; p--)
    {
        if (*p == '/' || *p == '\\')
        {
            break;
        }
    }
    path = p + 1;
    path_len = strlen (path);

    *(path + path_len - sql_log_ext_len) = '\0';
    p = strrchr (path, '_');

    *as_id = atoi (p + 1);
    if (*as_id <= 0)
    {
        return -1;
    }
    strncpy (br_name, path, p - path);
    *(br_name + (p - path)) = '\0';

    return 0;
#else
    return -1;
#endif
}

/*
 * check if dir path contains white space character,
 * and if path contains '\', substitute it with '/'
 */
static int
check_dbpath (char *dir, char *_dbmt_error)
{
    if (dir == NULL || *dir == '\0')
    {
        strcpy (_dbmt_error, "Path is NULL!");
        return ERR_WITH_MSG;
    }

    while (*dir != '\0')
    {
        if (isspace (*dir))
        {
            strcpy (_dbmt_error, "Path contains white space!");
            return ERR_WITH_MSG;
        }
        else if (*dir == '\\')
        {
            *dir = '/';
        }
        dir++;
    }

    return ERR_NO_ERROR;
}

static int
get_dbitemdir (char *item_dir, size_t item_dir_size, char *dbname,
               char *err_buf, int itemtype)
{
    FILE *databases_txt;
    char *envpath;
    char db_txt[PATH_MAX];
    char cbuf[2048];
    char itemname[1024];
    char scan_format[128];
    char pattern[64];
    const char *patternVol = "%%%lus %%%lus %%*s %%*s";
    const char *patternLog = "%%%lus %%*s %%*s %%%lus";

    if (item_dir == NULL || dbname == NULL)
    {
        return -1;
    }
#if !defined (DO_NOT_USE_CUBRIDENV)
    envpath = sco.szCubrid_databases;
#else
    envpath = CUBRID_VARDIR;
#endif
    if ((envpath == NULL) || (strlen (envpath) == 0))
    {
        return -1;
    }
    snprintf (db_txt, sizeof (db_txt) - 1, "%s/%s", envpath,
              CUBRID_DATABASE_TXT);
    databases_txt = fopen (db_txt, "r");

    /*set the patten to get dir from databases.txt. */
    if (databases_txt == NULL)
    {
        return -1;
    }

    if (itemtype == PATTERN_VOL)
    {
        strcpy_limit (pattern, patternVol, sizeof (pattern));
    }
    else if (itemtype == PATTERN_LOG)
    {
        strcpy_limit (pattern, patternLog, sizeof (pattern));
    }
    else
    {
        fclose (databases_txt);
        return -1;
    }

    snprintf (scan_format, sizeof (scan_format) - 1, pattern,
              (unsigned long) sizeof (itemname) - 1,
              (unsigned long) item_dir_size - 1);
    
    while (fgets (cbuf, sizeof (cbuf), databases_txt) != NULL)
    {
        if (sscanf (cbuf, scan_format, itemname, item_dir) < 2)
        {
            continue;
        }
        if (strcmp (itemname, dbname) == 0)
        {
            fclose (databases_txt);
            return 1;
        }
    }

    fclose (databases_txt);
    return 1;
}

static int
get_dblogdir (char *log_dir, size_t log_dir_size, char *dbname, char *err_buf)
{
    int retVal =
        get_dbitemdir (log_dir, log_dir_size, dbname, err_buf, PATTERN_LOG);
    return retVal;
}

static int
get_dbvoldir (char *vol_dir, size_t vol_dir_size, char *dbname, char *err_buf)
{
    int retVal =
        get_dbitemdir (vol_dir, vol_dir_size, dbname, err_buf, PATTERN_VOL);
    return retVal;
}

static char *
cm_get_abs_file_path (const char *filename, char *buf)
{
    strcpy (buf, filename);

    if (buf[0] == '/')
        return buf;
#if defined(WINDOWS)
    if (buf[2] == '/' || buf[2] == '\\')
        return buf;
#endif
    sprintf (buf, "%s/%s", getenv ("CUBRID"), filename);
    return buf;
}

static int
file_to_nvpairs (char *filepath, nvplist * res)
{
    FILE *infile;
    char buf[1024];

    /* return error if the input file is NULL. */
    if ((infile = fopen (filepath, "r")) == NULL)
    {
        return -1;
    }

    /* get all file content into response. */
    while (fgets (buf, sizeof (buf), infile))
    {
        uRemoveCRLF (buf);
        nv_add_nvp (res, "line", buf);
    }

    fclose (infile);
    return 0;
}

static int
file_to_nvp_by_separator (FILE * fp, nvplist * res, char separator)
{
    char buf[1024];
    char *p, *q, *next;
    int clientexist = 0;
    const char *comparestr = "System parameters";

    while (fgets (buf, sizeof (buf), fp) != NULL)
    {
        if (strncmp (buf, comparestr, strlen (comparestr)) == 0)
        {
            /* check if the sentences contains "client" or "server" or "standalone". */
            if (strstr (buf, "client") != NULL)
            {
                clientexist = 1;
                nv_add_nvp (res, "open", "client");
            }
            else if (strstr (buf, "server") != NULL)
            {
                /* if it is "server" then check if there is need to close "client". */
                if (clientexist != 0)
                    nv_add_nvp (res, "close", "client");
                nv_add_nvp (res, "open", "server");
            }
            else if (strstr (buf, "standalone") != NULL)
            {
                /* if it is "standalone" then there should return only server paramdump. */
                nv_add_nvp (res, "open", "server");
            }
            else
            {
                return -1;
            }
        }

        /*
        * ignore the lines that start with "#", empty lines,
        * and lines with out separator.
        */
        if ('#' == buf[0] || '\n' == buf[0] || strchr (buf, separator) == NULL)
        {
            continue;
        }
        p = buf;
        next = strchr (p, '\n');
        if (next != NULL)
        {
            *next = '\0';
        }
        q = strchr (p, '=');
        if (q != NULL)
        {
            *q = '\0';
            q++;
        }
        nv_add_nvp (res, p, q);
    }
    nv_add_nvp (res, "close", "server");
    return 0;
}

/* check if autoexecquery.conf version < 8.3.0 */
static int
obsolete_version_autoexecquery_conf (const char *conf_line)
{
    char conf_item_buf[80];

    if (conf_line == NULL)
    {
        return -1;
    }

    sscanf (conf_line, "%*s %*s %*s %80s", conf_item_buf);
    if (strcmp (conf_item_buf, "ONE") == 0
        || strcmp (conf_item_buf, "DAY") == 0
        || strcmp (conf_item_buf, "WEEK") == 0
        || strcmp (conf_item_buf, "MONTH") == 0)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

static int
alter_dblocation (const char *dbname, const char *new_dbpath)
{
    int retval = ERR_NO_ERROR;
    FILE *dblocation_info, *tmpfile;
    char dblocation_info_path[PATH_MAX];
    char tmpfile_path[PATH_MAX];
    char *strbuf;
    int buf_len, get_len;
    int db_existant = 0;
    char *tok[4];

    snprintf (dblocation_info_path, PATH_MAX - 1, "%s/%s",
              sco.szCubrid_databases, CUBRID_DATABASE_TXT);
    snprintf (tmpfile_path, PATH_MAX - 1, "%s/DBMT_util_dblocation.%d",
              sco.dbmt_tmp_dir, (int) getpid ());

    dblocation_info = fopen (dblocation_info_path, "r");
    tmpfile = fopen (tmpfile_path, "w");
    if (dblocation_info == NULL || tmpfile == NULL)
    {
        if (dblocation_info != NULL)
        {
            fclose (dblocation_info);
        }
        if (tmpfile != NULL)
        {
            fclose (tmpfile);
        }
        retval = ERR_FILE_OPEN_FAIL;
    }
    else
    {
        strbuf = NULL;
        buf_len = get_len = 0;
        while ((get_len =
            ut_getline (&strbuf, &buf_len, dblocation_info)) != -1)
        {
            ut_trim (strbuf);
            if (strbuf[0] == '#')
            {
                fprintf (tmpfile, "%s\n", strbuf);
                continue;
            }

            string_tokenize (strbuf, tok, 4);
            if (uStringEqual (dbname, tok[0]))
            {
                db_existant = 1;
                fprintf (tmpfile, "%s\t\t%s\t%s\t%s\n", tok[0], new_dbpath,
                         tok[2], new_dbpath);
            }
            else
            {
                fprintf (tmpfile, "%s\t\t%s\t%s\t%s\n", tok[0], tok[1],
                         tok[2], tok[3]);
            }
            FREE_MEM (strbuf);
            buf_len = 0;
        }

        if (strbuf != NULL)
        {
            FREE_MEM (strbuf);
        }

        fclose (dblocation_info);
        fclose (tmpfile);

        move_file (tmpfile_path, dblocation_info_path);
    }

    if (!db_existant)
    {
        retval = ERR_DB_NONEXISTANT;
    }

    return retval;
}

static int
_get_folders_with_keyword (char *search_folder_path, const char *keyword,
                           nvplist * res, char *_dbmt_error)
{
#if defined(WINDOWS)
    WIN32_FIND_DATA data;
    char find_file[512];
    HANDLE handle;
    int found;

    sprintf (find_file, "%s/%s", search_folder_path, keyword);
    handle = FindFirstFile (find_file, &data);
    if (handle == INVALID_HANDLE_VALUE)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE - 1,
                  "Folder with keyword: %s does not exist.", keyword);
        return ERR_WITH_MSG;
    }

    nv_add_nvp (res, "open", "folders");
    for (found = 1; found; found = FindNextFile (handle, &data))
    {
        if (strcmp (data.cFileName, ".") == 0
            || strcmp (data.cFileName, "..") == 0)
            continue;

        if (data.dwFileAttributes == FILE_ATTRIBUTE_DIRECTORY)
        {
            nv_add_nvp (res, "foldername", data.cFileName);
        }
    }                /* end of while and for */
    nv_add_nvp (res, "close", "folders");

    FindClose (handle);
#else
    struct dirent *dirp;
    struct stat statbuf;
    DIR *dp;

    dp = opendir (search_folder_path);
    if (dp == NULL)
    {
        strcpy_limit (_dbmt_error, "Could not open the search folder.",
                      DBMT_ERROR_MSG_SIZE);
        return ERR_WITH_MSG;
    }

    nv_add_nvp (res, "open", "folders");
    while ((dirp = readdir (dp)) != NULL)
    {
        char dir[PATH_MAX] = { 0 };

        snprintf (dir, sizeof (dir) - 1, "%s/%s", search_folder_path,
                  dirp->d_name);
        stat (dir, &statbuf);

        if (strcmp (dirp->d_name, ".") == 0 || strcmp (dirp->d_name, "..") == 0)
            continue;

        if (S_ISDIR (statbuf.st_mode) &&
            (fnmatch (keyword, dirp->d_name, 0) == 0))
        {
            nv_add_nvp (res, "foldername", dirp->d_name);
        }
    }                /* end of while and for */
    nv_add_nvp (res, "close", "folders");

    closedir (dp);
#endif

  return ERR_NO_ERROR;
}

static int
_update_nvplist_name (nvplist * ref, const char *name, const char *value)
{
    int i;
    char *name_buf;
    nvpair *nvp;

    if ((ref == NULL) || (name == NULL) || (value == NULL))
        return -1;

    for (i = 0; i < ref->nvplist_leng; i++)
    {
        if ((nvp = ref->nvpairs[i]) == NULL)
            return -1;

        name_buf = dst_buffer (nvp->name);
        if (uStringEqual (name_buf, name))
        {
            dst_reset (nvp->name);
            dst_append (nvp->name, value, strlen (value));
        }
    }

    return 0;
}

static int
read_shard_info_output (nvplist * res, char *stdout_file, char *stderr_file,
                        char *_dbmt_error)
{
    int num_shard = 0, rtn = ERR_NO_ERROR;
    int len = 0;
    char str_buf[512];
    char scan_buf[21][64];
    char *num[2] = { NULL, NULL };
    FILE *fp;

    if (access (stderr_file, F_OK) == 0)
    {
        fp = fopen (stderr_file, "r");
        if (fp != NULL)
        {
            while (fgets (str_buf, sizeof (str_buf), fp) != NULL)
            {
                ut_trim (str_buf);
                if (strncmp (str_buf, "++", 2) == 0)
                {
                    continue;
                }
                len += strlen (str_buf);
                if (len < (DBMT_ERROR_MSG_SIZE - 1))
                {
                    strcpy (_dbmt_error, str_buf);
                    _dbmt_error += len;
                }
                else
                {
                    strcpy_limit (_dbmt_error, str_buf, DBMT_ERROR_MSG_SIZE);
                    strcpy_limit (_dbmt_error + DBMT_ERROR_MSG_SIZE - 4, "...", 4);
                    break;
                }
            }
            fclose (fp);
            if (len != 0)
                return ERR_WITH_MSG;
        }
    }


    fp = fopen (stdout_file, "r");
    if (fp == NULL)
    {
        strcpy (_dbmt_error, stdout_file);
        return ERR_FILE_OPEN_FAIL;
    }

    while (fgets (str_buf, sizeof (str_buf), fp))
    {
        if (strstr (str_buf, "++") != NULL)
        {
            strcpy (_dbmt_error, str_buf);
            rtn = ERR_WITH_MSG;
            break;
        }

        if (strstr (str_buf, "*") == NULL)
            continue;

        /* *  NAME PID  PSIZE  PORT  Active-P  Active-C      REQ  TPS  QPS  K-QPS (H-KEY   H-ID H-ALL) NK-QPS    LONG-T    LONG-Q  ERR-Q  CANCELED  ACCESS_MODE  SQL_LOG */
        if (sscanf (str_buf,
                    "%63s %63s %63s %63s %63s %63s %63s %63s %63s %63s %63s %63s %63s %63s %63s %63s %63s %63s %63s %63s %63s ",
                    scan_buf[0], scan_buf[1], scan_buf[2], scan_buf[3],
                    scan_buf[4], scan_buf[5], scan_buf[6], scan_buf[7],
                    scan_buf[8], scan_buf[9], scan_buf[10], scan_buf[11],
                    scan_buf[12], scan_buf[13], scan_buf[14], scan_buf[15],
                    scan_buf[16], scan_buf[17], scan_buf[18], scan_buf[19],
                    scan_buf[20]) < 21)
            continue;

        num_shard++;
        nv_add_nvp (res, "open", "shard");
        nv_add_nvp (res, "name", scan_buf[1]);
        nv_add_nvp (res, "pid", scan_buf[2]);
        nv_add_nvp (res, "psize", scan_buf[3]);
        nv_add_nvp (res, "port", scan_buf[4]);
        nv_add_nvp (res, "active-p", scan_buf[5]);
        nv_add_nvp (res, "active-c", scan_buf[6]);
        nv_add_nvp (res, "req", scan_buf[7]);

        nv_add_nvp (res, "tps", scan_buf[8]);
        nv_add_nvp (res, "qps", scan_buf[9]);
        nv_add_nvp (res, "k-qps", scan_buf[10]);
        nv_add_nvp (res, "h-key", scan_buf[11]);
        nv_add_nvp (res, "h-id", scan_buf[12]);
        nv_add_nvp (res, "h-all", scan_buf[13]);
        nv_add_nvp (res, "nk-qps", scan_buf[14]);

        string_tokenize2 (scan_buf[15], num, 2, '/');
        nv_add_nvp (res, "long_tran", num[0]);
        nv_add_nvp (res, "long_tran_time", num[1]);

        string_tokenize2 (scan_buf[16], num, 2, '/');
        nv_add_nvp (res, "long_query", num[0]);
        nv_add_nvp (res, "long_query_time", num[1]);

        nv_add_nvp (res, "error_query", scan_buf[17]);
        nv_add_nvp (res, "canceled", scan_buf[18]);
        nv_add_nvp (res, "access_mode", scan_buf[19]);
        nv_add_nvp (res, "sqll", scan_buf[20]);
        nv_add_nvp (res, "state", "ON");
        nv_add_nvp (res, "close", "shard");
    }
    fclose (fp);
    return rtn;
}

int
ts_get_shard_info (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char stdout_log_file[512];
    char stderr_log_file[512];
    int pid, argc = 0;
    int ret_val;
    char cmd_name[CUBRID_CMD_NAME_LEN];
    const char *argv[6];
    static int reqid = 0;

    /* not thread safe :( */
    reqid++;
    sprintf (stdout_log_file, "%s/cmshardinfo.%d.err", sco.dbmt_tmp_dir, reqid);
    sprintf (stderr_log_file, "%s/cmshardinfo2.%d.err", sco.dbmt_tmp_dir, reqid);

    cmd_name[0] = '\0';
#if !defined (DO_NOT_USE_CUBRIDENV)
    sprintf (cmd_name, "%s/%s%s", sco.szCubrid, CUBRID_DIR_BIN, UTIL_CUBRID);
#else
    sprintf (cmd_name, "%s/%s", CUBRID_BINDIR, UTIL_CUBRID);
#endif

    argv[argc++] = cmd_name;
    argv[argc++] = PRINT_CMD_SHARD;
    argv[argc++] = PRINT_CMD_STATUS;
    argv[argc++] = "-b";
    argv[argc++] = "-f";
    argv[argc++] = NULL;

    pid = run_child (argv, 1, NULL, stdout_log_file, stderr_log_file, NULL);    /* start shard */

    if (pid < 0)
    {
        if (_dbmt_error)
        sprintf (_dbmt_error, "system error : %s shard status", cmd_name);
        unlink (stdout_log_file);
        unlink (stderr_log_file);
        return ERR_WITH_MSG;
    }

    ret_val =
        read_shard_info_output (res, stdout_log_file, stderr_log_file,
                                _dbmt_error);
    unlink (stdout_log_file);
    unlink (stderr_log_file);

    return ret_val;
}


static int
read_shard_status_output (nvplist * res, char *stdout_file, char *stderr_file,
                          char *_dbmt_error)
{
    int rtn = ERR_NO_ERROR;
    int len = 0;
    char str_buf[512];
    char scan_buf[8][64];
    FILE *fp;

    if (access (stderr_file, F_OK) == 0)
    {
        fp = fopen (stderr_file, "r");
        if (fp != NULL)
        {
            while (fgets (str_buf, sizeof (str_buf), fp) != NULL)
            {
                ut_trim (str_buf);
                if (strncmp (str_buf, "++", 2) == 0)
                {
                    continue;
                }
                len += strlen (str_buf);
                if (len < (DBMT_ERROR_MSG_SIZE - 1))
                {
                    strcpy (_dbmt_error, str_buf);
                    _dbmt_error += len;
                }
                else
                {
                    strcpy_limit (_dbmt_error, str_buf, DBMT_ERROR_MSG_SIZE);
                    strcpy_limit (_dbmt_error + DBMT_ERROR_MSG_SIZE - 4, "...", 4);
                    break;
                }
            }
            fclose (fp);
            if (len != 0)
            return ERR_WITH_MSG;
        }
    }


    fp = fopen (stdout_file, "r");
    if (fp == NULL)
    {
        strcpy (_dbmt_error, stdout_file);
        return ERR_FILE_OPEN_FAIL;
    }

    while (fgets (str_buf, sizeof (str_buf), fp))
    {
        if (strstr (str_buf, "++") != NULL)
        {
            strcpy (_dbmt_error, str_buf);
            rtn = ERR_WITH_MSG;
            break;
        }

        if (strstr (str_buf, "PROXY_ID") == NULL)
            continue;

        /*ingore ------------ */
        fgets (str_buf, sizeof (str_buf), fp);
        while (fgets (str_buf, sizeof (str_buf), fp))
        {
            /* PROXY_ID SHARD_ID   CAS_ID   PID   QPS   LQS PSIZE STATUS  */
            if (sscanf (str_buf, "%63s %63s %63s %63s %63s %63s %63s %63s",
                        scan_buf[0], scan_buf[1], scan_buf[2], scan_buf[3],
                        scan_buf[4], scan_buf[5], scan_buf[6], scan_buf[7]) < 8)
                continue;

            nv_add_nvp (res, "open", "shard");
            nv_add_nvp (res, "proxy_id", scan_buf[0]);
            nv_add_nvp (res, "shard_id", scan_buf[1]);
            nv_add_nvp (res, "cas_id", scan_buf[2]);
            nv_add_nvp (res, "pid", scan_buf[3]);
            nv_add_nvp (res, "qps", scan_buf[4]);
            nv_add_nvp (res, "lqs", scan_buf[5]);
            nv_add_nvp (res, "psize", scan_buf[6]);
            nv_add_nvp (res, "status", scan_buf[7]);
            nv_add_nvp (res, "close", "shard");
        }
    }
    fclose (fp);
    return rtn;
}


int
ts_get_shard_status (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char stdout_log_file[512];
    char stderr_log_file[512];
    int pid, argc = 0;
    int ret_val;
    char cmd_name[CUBRID_CMD_NAME_LEN];
    const char *argv[6];
    char *sname;
    static int reqid = 0;

    if ((sname = nv_get_val (req, "shardname")) == NULL)
    {
        strcpy (_dbmt_error, "shard name");
        return ERR_PARAM_MISSING;
    }
    /* not thread safe :( */
    reqid++;
    sprintf (stdout_log_file, "%s/cmshardstatus.%d.err", sco.dbmt_tmp_dir, reqid);
    sprintf (stderr_log_file, "%s/cmshardstatus2.%d.err", sco.dbmt_tmp_dir, reqid);

    cmd_name[0] = '\0';
#if !defined (DO_NOT_USE_CUBRIDENV)
    sprintf (cmd_name, "%s/%s%s", sco.szCubrid, CUBRID_DIR_BIN, UTIL_CUBRID);
#else
    sprintf (cmd_name, "%s/%s", CUBRID_BINDIR, UTIL_CUBRID);
#endif

    argv[argc++] = cmd_name;
    argv[argc++] = PRINT_CMD_SHARD;
    argv[argc++] = PRINT_CMD_STATUS;
    argv[argc++] = sname;
    argv[argc++] = NULL;

    pid = run_child (argv, 1, NULL, stdout_log_file, stderr_log_file, NULL);    /* start shard */

    if (pid < 0)
    {
        if (_dbmt_error)
            sprintf (_dbmt_error, "system error : %s shard status %s", cmd_name, sname);
        unlink (stdout_log_file);
        unlink (stderr_log_file);
        return ERR_WITH_MSG;
    }

    nv_add_nvp (res, "name", sname);
    ret_val =
        read_shard_status_output (res, stdout_log_file, stderr_log_file, _dbmt_error);
    unlink (stdout_log_file);
    unlink (stderr_log_file);

    return ret_val;
}


static int
read_start_shard_output (char *stdout_file, char *stderr_file,
                         char *_dbmt_error)
{
    FILE *fp, *fp2;
    char buf[1024];
    char *strp;
    int retval = 0;

    if (access (stdout_file, F_OK) == 0)
    {
        fp = fopen (stdout_file, "r");
        if (fp != NULL)
        {
            while (fgets (buf, sizeof (buf), fp) != NULL)
            {
                ut_trim (buf);
                if (strncmp (buf, "@", 1) == 0)
                    continue;
                if (strncmp (buf, "++", 2) == 0)
                {
                    if ((strp = strchr (buf, ':')) && strstr (strp, "fail"))
                    {
                        retval = -1;
                        break;
                    }
                }
                strcpy (_dbmt_error, buf);
                if (strstr (buf, "Cannot"))
                {
                    retval = -1;
                    break;
                }
            }
            fclose (fp);
        }
    }

    if (access (stderr_file, F_OK) == 0)
    {
    fp2 = fopen (stderr_file, "r");
    if (fp2 != NULL)
    {
        int len = 0;
        while (fgets (buf, sizeof (buf), fp2) != NULL)
        {
            ut_trim (buf);
            if (strncmp (buf, "++", 2) == 0 || strncmp (buf, "@", 1) == 0)
            {
                continue;
            }
            len += strlen (buf);
            if (len < (DBMT_ERROR_MSG_SIZE - 1))
            {
                strcpy (_dbmt_error, buf);
                _dbmt_error += len;
            }
            else
            {
                strcpy_limit (_dbmt_error, buf, DBMT_ERROR_MSG_SIZE);
                strcpy_limit (_dbmt_error + DBMT_ERROR_MSG_SIZE - 4, "...", 4);
                break;
            }
        }

        if (len != 0 && retval != -1)
        retval = 1;
        fclose (fp2);
        }
    }

    return retval;
}


int
ts_shard_start (nvplist * req, nvplist * res, char *err_buf)
{
    char stdout_log_file[512];
    char stderr_log_file[512];
    int pid, argc = 0;
    int ret_val;
    char cmd_name[CUBRID_CMD_NAME_LEN];
    const char *argv[5];
    char *sname = NULL;

    sname = nv_get_val (req, "shardname");

    sprintf (stdout_log_file, "%s/cmshardstart.%d.err", sco.dbmt_tmp_dir,
        (int) getpid ());
    sprintf (stderr_log_file, "%s/cmshardstart2.%d.err", sco.dbmt_tmp_dir,
        (int) getpid ());

    cmd_name[0] = '\0';
#if !defined (DO_NOT_USE_CUBRIDENV)
    sprintf (cmd_name, "%s/%s%s", sco.szCubrid, CUBRID_DIR_BIN, UTIL_CUBRID);
#else
    sprintf (cmd_name, "%s/%s", CUBRID_BINDIR, UTIL_CUBRID);
#endif

    argv[argc++] = cmd_name;
    argv[argc++] = PRINT_CMD_SHARD;
    if (sname == NULL)
    {
        argv[argc++] = PRINT_CMD_START;
    }
    else
    {
        argv[argc++] = PRINT_CMD_ON;
        argv[argc++] = sname;
    }

    argv[argc++] = NULL;

    pid = run_child (argv, 1, NULL, stdout_log_file, stderr_log_file, NULL);    /* start shard */

    if (pid < 0)
    {
        if (err_buf)
            sprintf (err_buf, "system error : %s start shard", cmd_name);
        unlink (stdout_log_file);
        unlink (stderr_log_file);
        return ERR_WITH_MSG;
    }

    ret_val =
        read_start_shard_output (stdout_log_file, stderr_log_file, err_buf);
    unlink (stdout_log_file);
    unlink (stderr_log_file);

    if (ret_val != 0)
        return ERR_WITH_MSG;

    return ERR_NO_ERROR;
}


int
ts_shard_stop (nvplist * req, nvplist * res, char *err_buf)
{
    char stdout_log_file[512];
    char stderr_log_file[512];
    int pid, argc = 0;
    int ret_val;
    char cmd_name[CUBRID_CMD_NAME_LEN];
    const char *argv[5];
    char *sname = NULL;

    sname = nv_get_val (req, "shardname");

    sprintf (stdout_log_file, "%s/cmshardstop.%d.err", sco.dbmt_tmp_dir,
             (int) getpid ());
    sprintf (stderr_log_file, "%s/cmshardstop2.%d.err", sco.dbmt_tmp_dir,
             (int) getpid ());

    cmd_name[0] = '\0';
#if !defined (DO_NOT_USE_CUBRIDENV)
    sprintf (cmd_name, "%s/%s%s", sco.szCubrid, CUBRID_DIR_BIN, UTIL_CUBRID);
#else
    sprintf (cmd_name, "%s/%s", CUBRID_BINDIR, UTIL_CUBRID);
#endif

    argv[argc++] = cmd_name;
    argv[argc++] = PRINT_CMD_SHARD;
    if (sname == NULL)
    {
        argv[argc++] = PRINT_CMD_STOP;
    }
    else
    {
        argv[argc++] = PRINT_CMD_OFF;
        argv[argc++] = sname;
    }

    argv[argc++] = NULL;

    pid = run_child (argv, 1, NULL, stdout_log_file, stderr_log_file, NULL);    /* start shard */

    if (pid < 0)
    {
        if (err_buf)
            sprintf (err_buf, "system error : %s stop shard", cmd_name);
        unlink (stdout_log_file);
        unlink (stderr_log_file);
        return -1;
    }

    ret_val =
        read_start_shard_output (stdout_log_file, stderr_log_file, err_buf);
    unlink (stdout_log_file);
    unlink (stderr_log_file);
    if (ret_val != 0)
        return ERR_WITH_MSG;

    return ERR_NO_ERROR;
}

static int
read_broker_changer_output (char *stdout_file, char *stderr_file,
                            char *_dbmt_error)
{
    FILE *fp;
    char buf[1024];
    int len = 0;

    strcpy (buf, "");

    if (access (stdout_file, F_OK) == 0)
    {
        fp = fopen (stdout_file, "r");
        if (fp != NULL)
        {
            while (fgets (buf, sizeof (buf), fp) != NULL)
            {
                if (strncmp (buf, "OK", 2) == 0)
                {
                    fclose (fp);
                    return ERR_NO_ERROR;
                }
                ut_trim (buf);
                len += strlen (buf);
                if (len < DBMT_ERROR_MSG_SIZE - len - 1)
                {
                    strcpy (_dbmt_error, buf);
                    _dbmt_error += len;
                }
                else
                {
                    strcpy_limit (_dbmt_error, buf, DBMT_ERROR_MSG_SIZE - len);
                    strcpy_limit (_dbmt_error + DBMT_ERROR_MSG_SIZE - len - 4,
                                  "...", 4);
                    break;
                }
            }
            fclose (fp);
        }
    }

    if (access (stderr_file, F_OK) == 0)
    {
        fp = fopen (stderr_file, "r");
        if (fp != NULL)
        {
            while (fgets (buf, sizeof (buf), fp) != NULL)
            {
                ut_trim (buf);
                len += strlen (buf);
                if (len < DBMT_ERROR_MSG_SIZE - len - 1)
                {
                    strcpy (_dbmt_error, buf);
                    _dbmt_error += len;
                }
                else
                {
                    strcpy_limit (_dbmt_error, buf, DBMT_ERROR_MSG_SIZE - len);
                    strcpy_limit (_dbmt_error + DBMT_ERROR_MSG_SIZE - len - 4,
                                  "...", 4);
                    break;
                }
            }

            fclose (fp);
        }
    }

    return ERR_SYSTEM_CALL;
}

int
ts_broker_changer (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char stdout_log_file[512];
    char stderr_log_file[512];

    char cmd_name[CUBRID_CMD_NAME_LEN];
    const char *argv[6];

    char *bname = NULL;
    char *casnum = NULL;
    char *confname = NULL;
    char *confvalue = NULL;

    int argc = 0;
    int pid;
    int ret_val;

    if ((bname = nv_get_val (req, "bname")) == NULL)
    {
        sprintf (_dbmt_error, "bname");
        return ERR_PARAM_MISSING;
    }

    // casnum is optional.
    casnum = nv_get_val (req, "casnum");

    if ((confname = nv_get_val (req, "confname")) == NULL)
    {
        sprintf (_dbmt_error, "confname");
        return ERR_PARAM_MISSING;
    }

    if ((confvalue = nv_get_val (req, "confvalue")) == NULL)
    {
        sprintf (_dbmt_error, "confvalue");
        return ERR_PARAM_MISSING;
    }

    sprintf (stdout_log_file, "%s/cmbrokerchanger.%d.out", sco.dbmt_tmp_dir,
             (int) getpid ());
    sprintf (stderr_log_file, "%s/cmbrokerchanger.%d.err", sco.dbmt_tmp_dir,
             (int) getpid ());

    cmd_name[0] = '\0';
#if !defined (DO_NOT_USE_CUBRIDENV)
    sprintf (cmd_name, "%s/%s%s", sco.szCubrid, CUBRID_DIR_BIN,
             UTIL_BROKER_CHANGER);
#else
    sprintf (cmd_name, "%s/%s", CUBRID_BINDIR, UTIL_BROKER_CHANGER);
#endif

    argv[argc++] = cmd_name;
    argv[argc++] = bname;

    // casnum is optional. 
    if (casnum != NULL)
    {
        argv[argc++] = casnum;
    }
    argv[argc++] = confname;
    argv[argc++] = confvalue;
    argv[argc] = NULL;

    // run "broker_changer"
    pid = run_child (argv, 1, NULL, stdout_log_file, stderr_log_file, NULL);

    if (pid < 0)
    {
        if (_dbmt_error)
            sprintf (_dbmt_error, "%s : system error, fork failed!", cmd_name);
        unlink (stdout_log_file);
        unlink (stderr_log_file);
        return ERR_SYSTEM_CALL;
    }

    ret_val =
        read_broker_changer_output (stdout_log_file, stderr_log_file,
                                    _dbmt_error);

    unlink (stdout_log_file);
    unlink (stderr_log_file);

    return ret_val;

}

static int
read_ha_cmd_output (char *stdout_file, char *stderr_file, char *_dbmt_error)
{
    FILE *fp;
    char buf[1024];
    int len = 0;
    int len_tmp = 0;
    int ret_val = ERR_NO_ERROR;

    if (access (stderr_file, F_OK) == 0)
    {
        fp = fopen (stderr_file, "r");
        if (fp != NULL)
        {
            while (fgets (buf, sizeof (buf), fp) != NULL)
            {
                ut_trim (buf);
                len_tmp = strlen (buf);

                if (len_tmp < DBMT_ERROR_MSG_SIZE - len - 1)
                {
                    strcpy (_dbmt_error, buf);
                    _dbmt_error += len_tmp;
                    len += len_tmp;
                }
                else
                {
                    strcpy_limit (_dbmt_error, buf, DBMT_ERROR_MSG_SIZE - len);
                    strcpy_limit (_dbmt_error + DBMT_ERROR_MSG_SIZE - len - 4,
                                  "...", 4);
                }

                ret_val = ERR_SYSTEM_CALL;
            }
        }
        fclose (fp);
    }

    if (access (stdout_file, F_OK) == 0 && ret_val == ERR_NO_ERROR)
    {
        fp = fopen (stdout_file, "r");
        if (fp != NULL)
        {
            while (fgets (buf, sizeof (buf), fp) != NULL)
            {
                ut_trim (buf);
                len_tmp = strlen (buf);

                if (len_tmp < DBMT_ERROR_MSG_SIZE - len - 1)
                {
                    strcpy (_dbmt_error, buf);
                    _dbmt_error += len_tmp;
                    len += len_tmp;
                }
                else
                {
                    strcpy_limit (_dbmt_error, buf, DBMT_ERROR_MSG_SIZE - len);
                    strcpy_limit (_dbmt_error + DBMT_ERROR_MSG_SIZE - len - 4,
                                  "...", 4);
                }
            }
        }
        fclose (fp);
    }

    return ret_val;
}

static int
handle_ha_status_output (nvplist * res, char *_dbmt_error)
{
    char *iter1 = NULL;
    char *iter2 = NULL;
    char *applydb_pos = NULL;
    char *copydb_pos = NULL;
    char *db_names[1000];
    char value[1024];
    int len_tmp;
    int num_dbs = 0;
    int i;

    // "current_node" 
    iter1 = strstr (_dbmt_error, "current");
    if (iter1 == NULL)
    {
        return ERR_WITH_MSG;
    }

    iter2 = strstr (iter1, "state");
    if (iter2 == NULL)
    {
        return ERR_WITH_MSG;
    }

    len_tmp = (int) (iter2 - iter1 - 10);

    strncpy (value, iter1 + 8, len_tmp);
    value[len_tmp] = '\0';
    nv_add_nvp (res, "current_node", value);

    // "current_node_state"
    iter1 = strstr (iter2, ")");
    if (iter1 == NULL)
    {
        return ERR_WITH_MSG;
    }

    len_tmp = (int) (iter1 - iter2 - 6);
    strncpy (value, iter2 + 6, len_tmp);
    value[len_tmp] = '\0';
    nv_add_nvp (res, "current_node_state", value);

    // "nodeA"
    iter1 = strstr (iter1, "Node");
    if (iter1 == NULL)
    {
        return ERR_WITH_MSG;
    }

    iter2 = strstr (iter1, "(");
    if (iter2 == NULL)
    {
        return ERR_WITH_MSG;
    }

    len_tmp = (int) (iter2 - iter1 - 6);
    strncpy (value, iter1 + 5, len_tmp);
    value[len_tmp] = '\0';
    nv_add_nvp (res, "nodeA", value);

    // "nodeA_state"
    iter1 = strstr (iter2, "state");
    if (iter1 == NULL)
    {
        return ERR_WITH_MSG;
    }

    iter2 = strstr (iter1, ")");
    if (iter2 == NULL)
    {
        return ERR_WITH_MSG;
    }

    len_tmp = (int) (iter2 - iter1 - 6);
    strncpy (value, iter1 + 6, len_tmp);
    value[len_tmp] = '\0';
    nv_add_nvp (res, "nodeA_state", value);

    // "nodeB"
    iter1 = strstr (iter2, "Node");
    if (iter1 == NULL)
    {
        return ERR_WITH_MSG;
    }

    iter2 = strstr (iter1, "(");
    if (iter2 == NULL)
    {
        return ERR_WITH_MSG;
    }

    len_tmp = (int) (iter2 - iter1 - 6);
    strncpy (value, iter1 + 5, len_tmp);
    value[len_tmp] = '\0';
    nv_add_nvp (res, "nodeB", value);

    // "nodeB_state"
    iter1 = strstr (iter2, "state");
    if (iter1 == NULL)
    {
        return ERR_WITH_MSG;
    }

    iter2 = strstr (iter1, ")");
    if (iter2 == NULL)
    {
        return ERR_WITH_MSG;
    }

    len_tmp = (int) (iter2 - iter1 - 6);
    strncpy (value, iter1 + 6, len_tmp);
    value[len_tmp] = '\0';
    nv_add_nvp (res, "nodeB_state", value);

    // count dbs

    iter1 = strstr (iter2, "Applylogdb");
    if (iter1 == NULL)
    {
        return ERR_WITH_MSG;
    }

    while (iter1 != NULL)
    {
        char *iter3 = NULL;

        iter3 = strstr (iter1, "@");
        if (iter3 == NULL)
        {
            return ERR_WITH_MSG;
        }

        strncpy (value, iter1 + 11, iter3 - iter1 - 11);
        value[iter3 - iter1 - 11] = '\0';

        db_names[num_dbs] = (char *) malloc (iter3 - iter1 - 10);
        strcpy (db_names[num_dbs], value);
        num_dbs++;

        iter1 = strstr (iter3, "Applylogdb");
    }

    applydb_pos = strstr (iter2, "Applylogdb");
    if (applydb_pos == NULL)
    {
        return ERR_WITH_MSG;
    }

    copydb_pos = strstr (iter2, "Copylogdb");
    if (copydb_pos == NULL)
    {
        return ERR_WITH_MSG;
    }

    i = 0;
    while (i < num_dbs)
    {
        // for each db, create an array to store "applylogdb" and "copylogdb"
        nv_add_nvp (res, "open", "ha_info");

        nv_add_nvp (res, "dbname", db_names[i]);

        if (applydb_pos != NULL)
        {
            // "applylogdb"
            iter1 = applydb_pos;
            iter2 = strstr (iter1, "(");
            if (iter2 == NULL)
            {
                return ERR_WITH_MSG;
            }

            len_tmp = (int) (iter2 - iter1 - 12);
            strncpy (value, iter1 + 11, len_tmp);
            value[len_tmp] = '\0';
            nv_add_nvp (res, "applylogdb", value);

            // "applylogdb_pid" 
            iter1 = strstr (iter2, "pid");
            if (iter1 == NULL)
            {
                return ERR_WITH_MSG;
            }

            iter2 = strstr (iter1, "state");
            if (iter2 == NULL)
            {
                return ERR_WITH_MSG;
            }

            len_tmp = (int) (iter2 - iter1 - 6);
            strncpy (value, iter1 + 4, len_tmp);
            value[len_tmp] = '\0';
            nv_add_nvp (res, "applylogdb_pid", value);

            // "applylogdb_state"
            iter1 = strstr (iter2, ")");
            if (iter1 == NULL)
            {
                return ERR_WITH_MSG;
            }

            len_tmp = (int) (iter1 - iter2 - 6);
            strncpy (value, iter2 + 6, len_tmp);
            value[len_tmp] = '\0';
            nv_add_nvp (res, "applylogdb_state", value);

            // for next loop
            applydb_pos = strstr (iter1, "Applylogdb");
        }

        if (copydb_pos != NULL)
        {
            // "copylogdb"
            iter1 = copydb_pos;
            iter2 = strstr (iter1, "(");
            if (iter2 == NULL)
            {
                return ERR_WITH_MSG;
            }

            len_tmp = (int) (iter2 - iter1 - 11);
            strncpy (value, iter1 + 10, len_tmp);
            value[len_tmp] = '\0';
            nv_add_nvp (res, "copylogdb", value);

            // "copylogdb_pid"
            iter1 = strstr (iter2, "pid");
            if (iter1 == NULL)
            {
                return ERR_WITH_MSG;
            }

            iter2 = strstr (iter1, "state");
            if (iter2 == NULL)
            {
                return ERR_WITH_MSG;
            }

            len_tmp = (int) (iter2 - iter1 - 6);
            strncpy (value, iter1 + 4, len_tmp);
            value[len_tmp] = '\0';
            nv_add_nvp (res, "copylogdb_pid", value);

            // "copylogdb_state"
            iter1 = strstr (iter2, ")");
            if (iter1 == NULL)
            {
                return ERR_WITH_MSG;
            }

            len_tmp = (int) (iter1 - iter2 - 6);
            strncpy (value, iter2 + 6, len_tmp);
            value[len_tmp] = '\0';
            nv_add_nvp (res, "copylogdb_state", value);

            // for next loop
            copydb_pos = strstr (iter1, "Copylogdb");
        }

        // finish filling array 
        nv_add_nvp (res, "close", "ha_info");

        // release the string after storing it to nvplist
        free (db_names[i]);

        i++;
    }

    return ERR_NO_ERROR;
}

int
ts_ha_start (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char stdout_log_file[512];
    char stderr_log_file[512];
    char cmd_name[CUBRID_CMD_NAME_LEN];
    const char *argv[6];
    char *dbname = NULL;

    int argc = 0;
    int pid;
    int ret_val;

    // dbname is optional.
    dbname = nv_get_val (req, "dbname");

    sprintf (stdout_log_file, "%s/cmhastart.%d.out", sco.dbmt_tmp_dir,
             (int) getpid ());
    sprintf (stderr_log_file, "%s/cmhastart.%d.err", sco.dbmt_tmp_dir,
             (int) getpid ());

    cmd_name[0] = '\0';
#if !defined (DO_NOT_USE_CUBRIDENV)
    sprintf (cmd_name, "%s/%s%s", sco.szCubrid, CUBRID_DIR_BIN, UTIL_CUBRID);
#else
    sprintf (cmd_name, "%s/%s", CUBRID_BINDIR, UTIL_CUBRID);
#endif

    argv[argc++] = cmd_name;
    argv[argc++] = PRINT_CMD_HEARTBEAT;
    argv[argc++] = PRINT_CMD_START;

    // casnum is optional. 
    if (dbname != NULL)
    {
        argv[argc++] = dbname;
    }
    argv[argc] = NULL;

    // run "cubrid heartbeat start [dbname]"
    pid = run_child (argv, 1, NULL, stdout_log_file, stderr_log_file, NULL);

    if (pid < 0)
    {
        if (_dbmt_error)
            sprintf (_dbmt_error, "%s : system error, fork failed!", cmd_name);
        unlink (stdout_log_file);
        unlink (stderr_log_file);
        return ERR_SYSTEM_CALL;
    }

    ret_val =
        read_ha_cmd_output (stdout_log_file, stderr_log_file, _dbmt_error);

    unlink (stdout_log_file);
    unlink (stderr_log_file);

    return ret_val;
}

int
ts_ha_stop (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char stdout_log_file[512];
    char stderr_log_file[512];
    char cmd_name[CUBRID_CMD_NAME_LEN];
    const char *argv[6];
    char *dbname = NULL;

    int argc = 0;
    int pid;
    int ret_val;


    // dbname is optional.
    dbname = nv_get_val (req, "dbname");

    sprintf (stdout_log_file, "%s/cmhastop.%d.out", sco.dbmt_tmp_dir,
             (int) getpid ());
    sprintf (stderr_log_file, "%s/cmhastop.%d.err", sco.dbmt_tmp_dir,
             (int) getpid ());

    cmd_name[0] = '\0';
#if !defined (DO_NOT_USE_CUBRIDENV)
    sprintf (cmd_name, "%s/%s%s", sco.szCubrid, CUBRID_DIR_BIN, UTIL_CUBRID);
#else
    sprintf (cmd_name, "%s/%s", CUBRID_BINDIR, UTIL_CUBRID);
#endif

    argv[argc++] = cmd_name;
    argv[argc++] = PRINT_CMD_HEARTBEAT;
    argv[argc++] = PRINT_CMD_STOP;

    // dbname is optional. 
    if (dbname != NULL)
    {
        argv[argc++] = dbname;
    }
    argv[argc] = NULL;

    // run "cubrid heartbeat stop [dbname]"
    pid = run_child (argv, 1, NULL, stdout_log_file, stderr_log_file, NULL);

    if (pid < 0)
    {
        if (_dbmt_error)
            sprintf (_dbmt_error, "%s : system error, fork failed!", cmd_name);
        unlink (stdout_log_file);
        unlink (stderr_log_file);
        return ERR_SYSTEM_CALL;
    }

    ret_val =
        read_ha_cmd_output (stdout_log_file, stderr_log_file, _dbmt_error);

    unlink (stdout_log_file);
    unlink (stderr_log_file);

    return ret_val;
}

int
ts_ha_status (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char stdout_log_file[512];
    char stderr_log_file[512];
    char cmd_name[CUBRID_CMD_NAME_LEN];
    const char *argv[6];
    int argc = 0;
    int pid;
    int ret_val;


    sprintf (stdout_log_file, "%s/cmhastatus.%d.out", sco.dbmt_tmp_dir,
             (int) getpid ());
    sprintf (stderr_log_file, "%s/cmhastatus.%d.err", sco.dbmt_tmp_dir,
             (int) getpid ());

    cmd_name[0] = '\0';
#if !defined (DO_NOT_USE_CUBRIDENV)
    sprintf (cmd_name, "%s/%s%s", sco.szCubrid, CUBRID_DIR_BIN, UTIL_CUBRID);
#else
    sprintf (cmd_name, "%s/%s", CUBRID_BINDIR, UTIL_CUBRID);
#endif

    argv[argc++] = cmd_name;
    argv[argc++] = PRINT_CMD_HEARTBEAT;
    argv[argc++] = PRINT_CMD_STATUS;
    argv[argc] = NULL;

    // run "cubrid heartbeat status"
    pid = run_child (argv, 1, NULL, stdout_log_file, stderr_log_file, NULL);

    if (pid < 0)
    {
        if (_dbmt_error)
            sprintf (_dbmt_error, "%s : system error, fork failed!", cmd_name);
        unlink (stdout_log_file);
        unlink (stderr_log_file);
        return ERR_SYSTEM_CALL;
    }

    if ((ret_val =
            read_ha_cmd_output (stdout_log_file, stderr_log_file,
                                _dbmt_error)) != ERR_NO_ERROR)
    {

        unlink (stdout_log_file);
        unlink (stderr_log_file);

        return ret_val;
    }

    unlink (stdout_log_file);
    unlink (stderr_log_file);

    // handle the response
    if ((ret_val = handle_ha_status_output (res, _dbmt_error)) != ERR_NO_ERROR)
    {
        return ret_val;
    }

    return ret_val;
}

int
ts_ha_reload (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char stdout_log_file[512];
    char stderr_log_file[512];

    char cmd_name[CUBRID_CMD_NAME_LEN];
    const char *argv[6];

    int argc = 0;
    int pid;
    int ret_val;


    sprintf (stdout_log_file, "%s/cmhareload.%d.out", sco.dbmt_tmp_dir,
             (int) getpid ());
    sprintf (stderr_log_file, "%s/cmhareload.%d.err", sco.dbmt_tmp_dir,
             (int) getpid ());

    cmd_name[0] = '\0';
#if !defined (DO_NOT_USE_CUBRIDENV)
    sprintf (cmd_name, "%s/%s%s", sco.szCubrid, CUBRID_DIR_BIN, UTIL_CUBRID);
#else
    sprintf (cmd_name, "%s/%s", CUBRID_BINDIR, UTIL_CUBRID);
#endif

    argv[argc++] = cmd_name;
    argv[argc++] = PRINT_CMD_HEARTBEAT;
    argv[argc++] = PRINT_CMD_RELOAD;
    argv[argc] = NULL;

    // run "cubrid heartbeat reload"
    pid = run_child (argv, 1, NULL, stdout_log_file, stderr_log_file, NULL);

    if (pid < 0)
    {
        if (_dbmt_error)
            sprintf (_dbmt_error, "%s : system error, fork failed!", cmd_name);
        unlink (stdout_log_file);
        unlink (stderr_log_file);
        return ERR_SYSTEM_CALL;
    }

    ret_val =
        read_ha_cmd_output (stdout_log_file, stderr_log_file, _dbmt_error);

    unlink (stdout_log_file);
    unlink (stderr_log_file);

    return ret_val;

}

int
ts_ha_copylogdb (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char stdout_log_file[512];
    char stderr_log_file[512];

    char cmd_name[CUBRID_CMD_NAME_LEN];
    const char *argv[7];

    char *dbname = NULL;
    char *on_off = NULL;
    char *peer_node = NULL;

    int argc = 0;
    int pid = -1;
    int ret_val = 0;


    if ((dbname = nv_get_val (req, "dbname")) == NULL)
    {
        sprintf (_dbmt_error, "dbname");
        return ERR_PARAM_MISSING;
    }

    // on_off should be "start" or "stop".
    if ((on_off = nv_get_val (req, "on_off")) == NULL)
    {
        sprintf (_dbmt_error, "on_off");
        return ERR_PARAM_MISSING;
    }
    else if (strcmp (on_off, "start") && strcmp (on_off, "stop"))
    {
        return ERR_REQUEST_FORMAT;
    }

    if ((peer_node = nv_get_val (req, "peer_node")) == NULL)
    {
        sprintf (_dbmt_error, "peer_node");
        return ERR_PARAM_MISSING;
    }

    sprintf (stdout_log_file, "%s/cmhacopylogdb.%d.out", sco.dbmt_tmp_dir,
             (int) getpid ());
    sprintf (stderr_log_file, "%s/cmhacopylogdb.%d.err", sco.dbmt_tmp_dir,
             (int) getpid ());

    cmd_name[0] = '\0';
#if !defined (DO_NOT_USE_CUBRIDENV)
    sprintf (cmd_name, "%s/%s%s", sco.szCubrid, CUBRID_DIR_BIN, UTIL_CUBRID);
#else
    sprintf (cmd_name, "%s/%s", CUBRID_BINDIR, UTIL_CUBRID);
#endif

    argv[argc++] = cmd_name;
    argv[argc++] = PRINT_CMD_HEARTBEAT;
    argv[argc++] = UTIL_OPTION_COPYLOGDB;
    argv[argc++] = on_off;
    argv[argc++] = dbname;
    argv[argc++] = peer_node;
    argv[argc] = NULL;

    // run "cubrid heartbeat copylogdb <start|stop> dbname peer_node"
    pid = run_child (argv, 1, NULL, stdout_log_file, stderr_log_file, NULL);

    if (pid < 0)
    {
        if (_dbmt_error)
            sprintf (_dbmt_error, "%s : system error, fork failed!", cmd_name);
        unlink (stdout_log_file);
        unlink (stderr_log_file);
        return ERR_SYSTEM_CALL;
    }

    //ret_val = read_broker_changer_output(stdout_log_file, stderr_log_file, _dbmt_error);

    unlink (stdout_log_file);
    unlink (stderr_log_file);

    return ret_val;

}

int
ts_ha_applylogdb (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char stdout_log_file[512];
    char stderr_log_file[512];

    char cmd_name[CUBRID_CMD_NAME_LEN];
    const char *argv[7];

    char *dbname = NULL;
    char *on_off = NULL;
    char *peer_node = NULL;

    int argc = 0;
    int pid = -1;
    int ret_val = 0;


    if ((dbname = nv_get_val (req, "dbname")) == NULL)
    {
        sprintf (_dbmt_error, "dbname");
        return ERR_PARAM_MISSING;
    }

    // on_off should be "start" or "stop".
    if ((on_off = nv_get_val (req, "on_off")) == NULL)
    {
        sprintf (_dbmt_error, "on_off");
        return ERR_PARAM_MISSING;
    }
    else if (strcmp (on_off, "start") && strcmp (on_off, "stop"))
    {
        return ERR_REQUEST_FORMAT;
    }

    if ((peer_node = nv_get_val (req, "peer_node")) == NULL)
    {
        sprintf (_dbmt_error, "peer_node");
        return ERR_PARAM_MISSING;
    }

    sprintf (stdout_log_file, "%s/cmhacopylogdb.%d.out", sco.dbmt_tmp_dir,
             (int) getpid ());
    sprintf (stderr_log_file, "%s/cmhacopylogdb.%d.err", sco.dbmt_tmp_dir,
             (int) getpid ());

    cmd_name[0] = '\0';
#if !defined (DO_NOT_USE_CUBRIDENV)
    sprintf (cmd_name, "%s/%s%s", sco.szCubrid, CUBRID_DIR_BIN, UTIL_CUBRID);
#else
    sprintf (cmd_name, "%s/%s", CUBRID_BINDIR, UTIL_CUBRID);
#endif

    argv[argc++] = cmd_name;
    argv[argc++] = PRINT_CMD_HEARTBEAT;
    argv[argc++] = UTIL_OPTION_APPLYLOGDB;
    argv[argc++] = on_off;
    argv[argc++] = dbname;
    argv[argc++] = peer_node;
    argv[argc] = NULL;

    // run "cubrid heartbeat applylogdb <start|stop> dbname peer_node"
    pid = run_child (argv, 1, NULL, stdout_log_file, stderr_log_file, NULL);

    if (pid < 0)
    {
        if (_dbmt_error)
            sprintf (_dbmt_error, "%s : system error, fork failed!", cmd_name);
        unlink (stdout_log_file);
        unlink (stderr_log_file);
        return ERR_SYSTEM_CALL;
    }

    //ret_val = read_broker_changer_output(stdout_log_file, stderr_log_file, _dbmt_error);

    unlink (stdout_log_file);
    unlink (stderr_log_file);

    return ret_val;

}

/*static int _get_update_url(char *url) 
{
    char cm_conf_file[PATH_MAX]; 
    char line_buf[MAX_JOB_CONFIG_FILE_LINE_LENGTH]; 

    char *iter = NULL; 

    FILE *fin;

#if !defined (DO_NOT_USE_CUBRIDENV)
    snprintf (cm_conf_file, PATH_MAX - 1, "%s/conf/%s", sco.szCubrid, CUBRID_DBMT_CONF);
#else
    snprintf (cm_conf_file, PATH_MAX - 1, "%s/%s", CUBRID_CONFDIR, CUBRID_DBMT_CONF);
#endif

    fin = fopen(cm_conf_file, "r"); 
    if (fin == NULL) 
    {
        return ERR_FILE_OPEN_FAIL; 
    }

    while (fgets(&line_buf, MAX_JOB_CONFIG_FILE_LINE_LENGTH, fin) != NULL) 
    {
       iter = strstr(line_buf, "patch_url");  
       if( iter == NULL) 
       {
           continue; 
       }

       iter = strstr(line_buf, "="); 
       strcpy (url, iter+2);  

       break; 
    }

    fclose(fin); 

    return ERR_NO_ERROR; 
}*/

static char *
_get_format_time ()
{
    char *buff = (char *) malloc (sizeof (char) * LINE_MAX);
#ifdef WINDOWS

#else
    time_t lt;

    time (&lt);
    struct tm *t = localtime (&lt);

    if (t)
        strftime (buff, LINE_MAX, "%Y%m%d %H:%M:%S", t);

#endif
    return buff;
}

static void
_write_auto_update_log (char *line_buf, int is_success)
{
    char *log_time;

    char log_path[PATH_MAX];

    FILE *fin = NULL;

    sprintf (log_path, "%s/log/manager/cms.update.log", sco.szCubrid);

    fin = fopen (log_path, "a");

    log_time = _get_format_time ();
    if (is_success)
    {
        fprintf (fin, "[%s] %s, update to %s.\n", log_time, line_buf,
                 sco.szCMSVersion);
    }
    else
    {
        fprintf (fin, "[%s] CMS update error: %s\n", log_time, line_buf);
    }

    free (log_time);
    fclose (fin);

}

int
ts_is_update_success (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char err_log[PATH_MAX];
    char output_log[PATH_MAX];
    char line_buf[LINE_MAX];

    FILE *fin = NULL;

    sprintf (err_log, "%s/cms_auto_update.err", sco.dbmt_tmp_dir);
    sprintf (output_log, "%s/cms_auto_update.log", sco.dbmt_tmp_dir);

    fin = fopen (output_log, "r");
    if (fin == NULL)
    {
        sprintf (_dbmt_error, "%s", output_log);
        return ERR_FILE_OPEN_FAIL;
    }

    while (fgets (line_buf, LINE_MAX, fin) != NULL)
    {
        if (strstr (line_buf, "CUBRID Manager Server is updated.") != NULL)
        {
            nv_add_nvp (res, "autoupdate_success", "success");

            _write_auto_update_log (line_buf, TRUE);
            fclose (fin);
            return ERR_NO_ERROR;
        }

    }
    fclose (fin);

    nv_add_nvp (res, "autoupdate_result", "failure");

    fin = fopen (err_log, "r");
    if (fin == NULL)
    {
        sprintf (_dbmt_error, "%s", err_log);
        return ERR_FILE_OPEN_FAIL;
    }

    while (fgets (line_buf, LINE_MAX, fin) != NULL)
    {
        _write_auto_update_log (line_buf, FALSE);
    }
    fclose (fin);


    return ERR_NO_ERROR;
}

int
ts_auto_update (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char *patch_name = NULL;

    char path[PATH_MAX];
    char shell_name[PATH_MAX];
    char err_log[PATH_MAX];
    char output_log[PATH_MAX];
#ifndef WINDOWS
    char cmd[PATH_MAX];
#endif
    char *argv[2];

    int ret_val = 0;

#ifndef WINDOWS
    pid_t pid = 0;
#endif

    patch_name = nv_get_val (req, "patch_name");
    if (patch_name == NULL)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", "patch_name");
        return ERR_PARAM_MISSING;
    }
#ifdef WINDOWS
    sprintf (path, "%s\\", sco.dbmt_tmp_dir);
#else
    sprintf (path, "%s/", sco.dbmt_tmp_dir);
#endif

    if ((ret_val =
        generate_update_script (patch_name, sco.szAutoUpdateURL, path,
                                _dbmt_error)) != ERR_NO_ERROR)
    {
        return ret_val;
    }

    sprintf (shell_name, "%s" SHELL_NAME, path);

    argv[0] = shell_name;
    argv[1] = NULL;

    sprintf (err_log, "%scms.autoupdate.err", path);
    sprintf (output_log, "%scms.autoupdate.log", path);

#ifdef WINDOWS
    ret_val = run_child (argv, 0, NULL, output_log, err_log, NULL);

#else
    sprintf (cmd, "%s >%s 2>%s", shell_name, output_log, err_log);

    // As "system" fucntion will wait for the command return in parent process, fork a new procee to execute it in order to avoid blocking. 
    if ((pid = fork ()) > 0)
    {
        return ERR_NO_ERROR;
    }
    else if (pid == 0)
    {
        system (cmd);
        exit (0);
    }
    else
    {
        sprintf (_dbmt_error, "fork()");
        return ERR_SYSTEM_CALL;
    }

#endif

    return ERR_NO_ERROR;
}

int
ts_list_dir (nvplist * req, nvplist * res, char *_dbmt_error)
{
    char *nvp_path = NULL;
    char path[PATH_MAX];
    char full_path[PATH_MAX];

    path[0] = 0;
    full_path[0] = 0;

    if (NULL == (nvp_path = nv_get_val (req, "path")))
    {
        strcpy (_dbmt_error, "missing path parameter");
        return ERR_PARAM_MISSING;
    }

    if (0 == strncmp (nvp_path, "../", strlen ("../")))
    {
        strcpy (_dbmt_error, "path parameter includes invalid dirctories!");
        return ERR_WITH_MSG;
    }
    if (NULL != strstr (nvp_path, "../"))
    {
        strcpy (_dbmt_error, "path parameter includes invalid dirctories!");
        return ERR_WITH_MSG;
    }
    if ('/' == nvp_path[strlen (nvp_path) - 3]
        && '.' == nvp_path[strlen (nvp_path) - 2]
        && '.' == nvp_path[strlen (nvp_path) - 1])
    {
        strcpy (_dbmt_error, "path parameter includes invalid dirctories!");
        return ERR_WITH_MSG;
    }

    snprintf (path, sizeof (path), "%s", nvp_path);
    if (path[strlen (path) - 1] != '/')
    {
        snprintf (path, sizeof (path), "%s/", nvp_path);
    }
    nv_add_nvp (res, "path", path);

#if !defined (DO_NOT_USE_CUBRIDENV)
    snprintf (full_path, PATH_MAX, "%s/%s/", sco.szCubrid, path);
#else
    sprintf (full_path, "%s/%s/", CUBRID, path);
#endif

#if defined(WINDOWS)
    {
        HANDLE handle;
        WIN32_FIND_DATA ffd;
        char find_path[PATH_MAX];
        snprintf (find_path, PATH_MAX - 1, "%s/*", full_path);

        nv_add_nvp (res, "open", "dir");
        handle = FindFirstFile (find_path, &ffd);
        if (handle == INVALID_HANDLE_VALUE)
        {
            sprintf (_dbmt_error, "open directory %s failed!", path);
            return ERR_WITH_MSG;
        }
        while (FindNextFile (handle, &ffd))
        {
            if (ffd.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN
                || ffd.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM)
            {
                continue;
            }
            else if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            {
                if (0 != strcmp (ffd.cFileName, ".")
                    && 0 != strcmp (ffd.cFileName, ".."))
                {
                    nv_add_nvp (res, "group", ffd.cFileName);
                }
            }
        }
        FindClose (handle);
        nv_add_nvp (res, "close", "dir");

        nv_add_nvp (res, "open", "file");
        handle = FindFirstFile (find_path, &ffd);
        if (handle == INVALID_HANDLE_VALUE)
        {
            sprintf (_dbmt_error, "open directory %s failed!", path);
            return ERR_WITH_MSG;
        }
        while (FindNextFile (handle, &ffd))
        {
            if (ffd.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN
                || ffd.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM)
            {
                continue;
            }
            else if (!(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            {
                if (0 == strcmp (ffd.cFileName, "cm.pass")
                    || 0 == strcmp (ffd.cFileName, "cmdb.pass"))
                {
                    continue;
                }
                nv_add_nvp (res, "group", ffd.cFileName);
            }
        }
        FindClose (handle);
        nv_add_nvp (res, "close", "file");
    }

#else
    {
        char name_temp[1024];
        DIR *dirptr = NULL;
        struct dirent *entry;

        nv_add_nvp (res, "open", "dir");
        if ((dirptr = opendir (full_path)) == NULL)
        {
            sprintf (_dbmt_error, "open directory %s failed!", path);
            return ERR_WITH_MSG;
        }
        else
        {
            while ((entry = readdir (dirptr)) != NULL)
            {
                struct stat stat_file;
                if (entry->d_name[0] == '.')
                {
                    continue;
                }
                strcpy (name_temp, full_path);
                strcat (name_temp, entry->d_name);

                stat (name_temp, &stat_file);
                if (S_ISDIR (stat_file.st_mode))
                {
                    nv_add_nvp (res, "group", entry->d_name);
                }
            }
        }
        closedir (dirptr);
        nv_add_nvp (res, "close", "dir");

        nv_add_nvp (res, "open", "file");
        if ((dirptr = opendir (full_path)) == NULL)
        {
            sprintf (_dbmt_error, "open directory %s failed!", path);
            return ERR_WITH_MSG;
        }
        else
        {
            while ((entry = readdir (dirptr)) != NULL)
            {
                struct stat stat_file;
                if (entry->d_name[0] == '.')
                {
                    continue;
                }
                strcpy (name_temp, full_path);
                strcat (name_temp, entry->d_name);

                stat (name_temp, &stat_file);
                if (!(S_ISDIR (stat_file.st_mode)))
                {
                    if (0 == strcmp (entry->d_name, "cm.pass")
                        || 0 == strcmp (entry->d_name, "cmdb.pass"))
                    {
                        continue;
                    }
                    nv_add_nvp (res, "group", entry->d_name);
                }
            }
        }
        closedir (dirptr);
        nv_add_nvp (res, "close", "file");
    }
#endif

  return ERR_NO_ERROR;
}

int
ts_monitor_process (nvplist * req, nvplist * res, char *_dbmt_error)
{
    // processes need monitoring
    const char process_name[][PATH_MAX] = {"cub_master", 0};
    char exist[15];
    int i = 0;

#ifdef WINDOWS

    PROCESSENTRY32 pe32;
    HANDLE process_snap = 0;
    pe32.dwSize = sizeof (pe32);

    process_snap = CreateToolhelp32Snapshot (TH32CS_SNAPPROCESS, 0);
    if (process_snap == INVALID_HANDLE_VALUE)
    {
        strcpy (_dbmt_error, "create process snapshot failed!");
        return ERR_SYSTEM_CALL;
    }

    i = 0;
    while (process_name[i][0] != 0)
    {
        strcpy (exist, "don't exist");
        if (!Process32First (process_snap, &pe32))
        {
            strcpy (_dbmt_error, "get process info failed!");
            return ERR_SYSTEM_CALL;
        }

        do
        {
            if (!strncmp
                (process_name[i], pe32.szExeFile, strlen (process_name[i])))
            {
                strcpy (exist, "exist");
                break;
            }

        }
        while (Process32Next (process_snap, &pe32));

        nv_add_nvp (res, process_name[i], exist);
        i++;
    }

#else
    char pid_file[PATH_MAX];
    char cmd_name[PATH_MAX];

    FILE *fin;
    int ch;

    sprintf (pid_file, "%s/monitor_process.%u.tmp", sco.dbmt_tmp_dir,
             getpid ());
    fin = fopen (pid_file, "w+");

    i = 0;
    while (process_name[i][0] != 0)
    {
        sprintf (cmd_name, "pgrep -u $(whoami) %s > %s", process_name[i],
                 pid_file);
        system (cmd_name);

        if ((ch = fgetc (fin)) == EOF)
        {
            strcpy (exist, "don't exist");
        }
        else if (ch > '1' && ch < '9')
        {
            strcpy (exist, "exist");
        }

        nv_add_nvp (res, process_name[i], exist);
        i++;
    }

    fclose (fin);
    unlink (pid_file);
#endif

    return ERR_NO_ERROR;
}

static int
_make_cert (nvplist * req, X509 ** x509p, EVP_PKEY ** pkeyp, int bits,
            char *_dbmt_error)
{
    char user_info[PATH_MAX];
    char nid_basic_constraints[PATH_MAX];
    char nid_key_usage[PATH_MAX];
    char nid_subject_key_identifier[PATH_MAX];
    char nid_netscape_cert_type[PATH_MAX];
    char nid_netscape_comment[PATH_MAX];

    X509 *x509_local = NULL;
    EVP_PKEY *pub_key = NULL;
    RSA *rsa = NULL;
    X509_NAME *name = NULL;
    BIGNUM *bignum = NULL;

    char *country_name = NULL;
    char *state_name = NULL;
    char *locality_name = NULL;
    char *organization_name = NULL;
    char *organizational_unit_name = NULL;
    char *common_name = NULL;
    char *email_addr = NULL;
    char *days = NULL;

    int day = 0;

    user_info[0] = '\0';
    nid_basic_constraints[0] = '\0';
    nid_key_usage[0] = '\0';
    nid_subject_key_identifier[0] = '\0';
    nid_netscape_cert_type[0] = '\0';
    nid_netscape_comment[0] = '\0';

    country_name = nv_get_val (req, "cname");
    state_name = nv_get_val (req, "stname");
    locality_name = nv_get_val (req, "loname");
    organization_name = nv_get_val (req, "orgname");
    organizational_unit_name = nv_get_val (req, "orgutname");
    common_name = nv_get_val (req, "comname");
    email_addr = nv_get_val (req, "email");
    days = nv_get_val (req, "days");

    if (days == NULL)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", "days");
        return ERR_PARAM_MISSING;
    }

    if ((pkeyp == NULL) || (*pkeyp == NULL))
    {
        if ((pub_key = EVP_PKEY_new ()) == NULL)
        {
            snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE,
                      "Cannot make a new private key.");
            return ERR_WITH_MSG;
        }
    }
    else
    {
        pub_key = *pkeyp;
    }

    if ((x509p == NULL) || (*x509p == NULL))
    {
        if ((x509_local = X509_new ()) == NULL)
        {
            snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE,
                      "Cannot make a new certification file.");
            return ERR_WITH_MSG;
        }
    }
    else
    {
        x509_local = *x509p;
    }

    /* Generate RSA key using RSA_generate_key_ex to replace RSA_generate_key
    *
    */
    if ((bignum = BN_new ()) == NULL)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE,
                  "Cannot make a new SSL private key file - create bignum failed.");
        return ERR_WITH_MSG;
    }
    if (BN_set_word (bignum, RSA_F4) == 0)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE,
                  "Cannot make a new SSL private key file - set bignum failed.");
        return ERR_WITH_MSG;
    }
    if ((rsa = RSA_new ()) == NULL)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE,
                  "Cannot make a new SSL private key file - create RSA failed.");
        return ERR_WITH_MSG;
    }
    if (RSA_generate_key_ex (rsa, bits, bignum, NULL) == 0)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE,
                  "Cannot make a new SSL private key file.");
        return ERR_WITH_MSG;
    }
    if (EVP_PKEY_assign_RSA (pub_key, rsa) == 0)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE,
                  "Failed to generate public key.");
        return ERR_WITH_MSG;
    }
    rsa = NULL;

    X509_set_version (x509_local, 2);
    ASN1_INTEGER_set (X509_get_serialNumber (x509_local), 0);
    X509_gmtime_adj (X509_get_notBefore (x509_local), 0);

    day = atoi (days);
    if (day <= 0)
    {
        day = 365;
    }
    X509_gmtime_adj (X509_get_notAfter (x509_local), (long) 60 * 60 * 24 * day);
    X509_set_pubkey (x509_local, pub_key);

    name = X509_get_subject_name (x509_local);

    /* This function creates and adds the entry, working out the
    * correct string type and performing checks on its length.
    * Normally we'd check the return value for errors...
    */
    if (country_name != NULL)
    {
        _add_issuer_info (name, "C", country_name);
    }
    if (state_name != NULL)
    {
        _add_issuer_info (name, "ST", state_name);
    }
    if (locality_name != NULL)
    {
        _add_issuer_info (name, "L", locality_name);
    }
    if (organization_name != NULL)
    {
        _add_issuer_info (name, "O", organization_name);
    }
    if (organizational_unit_name != NULL)
    {
        _add_issuer_info (name, "OU", organizational_unit_name);
    }
    if ((common_name != NULL) && (email_addr != NULL))
    {
        snprintf (user_info, PATH_MAX, "%s/%s", common_name, email_addr);
        _add_issuer_info (name, "CN", user_info);
    }
    else if ((common_name != NULL) && (email_addr == NULL))
    {
        snprintf (user_info, PATH_MAX, "%s", common_name);
        _add_issuer_info (name, "CN", user_info);
    }
    else if ((common_name == NULL) && (email_addr != NULL))
    {
        snprintf (user_info, PATH_MAX, "%s", email_addr);
        _add_issuer_info (name, "CN", user_info);
    }

    /* Issuer should not be null for all items,
    *  We have to set at least one issue as default,
    *  We decide to set organizational_unit_name as the last one.
    */
    if ((country_name == NULL) && (state_name == NULL)
        && (locality_name == NULL) && (organization_name == NULL)
        && (organizational_unit_name == NULL) && (common_name == NULL)
        && (email_addr == NULL))
    {
        snprintf (user_info, PATH_MAX, "CUBRID Manger Server Group.");
        _add_issuer_info (name, "OU", user_info);
    }
    /* Its self signed so set the issuer name to be the same as the
    * subject.
    */
    X509_set_issuer_name (x509_local, name);

    /* Add various extensions: standard extensions */
    snprintf (nid_basic_constraints, PATH_MAX, "critical,CA:TRUE");
    _add_extensions (x509_local, NID_basic_constraints, nid_basic_constraints);

    snprintf (nid_key_usage, PATH_MAX, "critical,keyCertSign,cRLSign");
    _add_extensions (x509_local, NID_key_usage, nid_key_usage);

    snprintf (nid_subject_key_identifier, PATH_MAX, "hash");
    _add_extensions (x509_local, NID_subject_key_identifier,
                     nid_subject_key_identifier);

    /* Some Netscape specific extensions */
    snprintf (nid_netscape_cert_type, PATH_MAX, "sslCA");
    _add_extensions (x509_local, NID_netscape_cert_type,
                     nid_netscape_cert_type);

    snprintf (nid_netscape_comment, PATH_MAX,
              "CUBRID Manager server comment extension");
    _add_extensions (x509_local, NID_netscape_comment, nid_netscape_comment);

    if (X509_sign (x509_local, pub_key, EVP_md5 ()) == 0)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE,
                  "Cannot sign with public key.");
        return ERR_WITH_MSG;
    }

    *x509p = x509_local;
    *pkeyp = pub_key;
    return ERR_NO_ERROR;
}

static void
_add_issuer_info (X509_NAME * name, const char *item_name, char *item_value)
{
    X509_NAME_add_entry_by_txt (name, item_name, MBSTRING_ASC, 
                                (const unsigned char *) item_value, -1, -1, 0);
}

static int
_add_extensions (X509 * cert, int nid, char *value)
{
    X509_EXTENSION *extension;
    X509V3_CTX ctx;
    /* This sets the 'context' of the extensions. */
    /* No configuration database */
    X509V3_set_ctx_nodb (&ctx);
    /* Issuer and subject certs: both the target since it is self signed,
    * no request and no CRL
    */
    X509V3_set_ctx (&ctx, cert, cert, NULL, NULL, 0);
    extension = X509V3_EXT_conf_nid (NULL, &ctx, nid, value);
    if (extension == 0)
    {
        return 1;
    }

    X509_add_ext (cert, extension, -1);
    X509_EXTENSION_free (extension);
    return 0;
}

static int
_backup_cert (char *_dbmt_error)
{
    char default_backup_cert_path[PATH_MAX];
    char default_cert_path[PATH_MAX];

    default_backup_cert_path[0] = '\0';
    default_cert_path[0] = '\0';

    snprintf (default_backup_cert_path, PATH_MAX, "%s.bak",
              sco.szSSLCertificate);
    if (access (default_backup_cert_path, F_OK) == 0)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE,
                  "Cannot backup SSL certification file: %s.",
                  sco.szSSLCertificate);
        return 1;
    }

    snprintf (default_cert_path, PATH_MAX, "%s", sco.szSSLCertificate);
    if (access (default_cert_path, F_OK) != 0)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE,
                  "Cannot find SSL certification file: %s.",
                  sco.szSSLCertificate);
        return 1;
    }
    /*No need to backup custom certification file */
    if (_is_default_cert (_dbmt_error) == 0)
    {
        return 1;
    }

    if (file_copy (default_cert_path, default_backup_cert_path) != 0)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE,
                  "Failed to backup SSL certification file: %s.",
                  sco.szSSLCertificate);
        return 1;
    }
    return 0;
}

static int
_recover_cert (char *_dbmt_error)
{
    char default_cert_path[PATH_MAX];
    char default_backup_cert_path[PATH_MAX];

    default_cert_path[0] = '\0';
    default_backup_cert_path[0] = '\0';

    /*Check the validation of backup certification file */
    if (_is_exist_default_backup_cert (_dbmt_error) != 1)
    {
        return 1;
    }

    snprintf (default_cert_path, PATH_MAX, "%s", sco.szSSLCertificate);
    if (access (default_cert_path, F_OK) == 0)
    {
        if (uRemoveDir (default_cert_path, REMOVE_DIR_FORCED) != ERR_NO_ERROR)
        {
            snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE,
                      "Cannot delete SSL certification file: %s.",
                      sco.szSSLCertificate);
            return 1;
        }
    }

    snprintf (default_backup_cert_path, PATH_MAX, "%s.bak",
              sco.szSSLCertificate);
    if (file_copy (default_backup_cert_path, default_cert_path) != 0)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE,
                  "Failed to recover SSL certification file: %s.",
                  sco.szSSLCertificate);
        return 1;
    }
    return 0;
}

int
ts_generate_cert (nvplist * req, nvplist * res, char *_dbmt_error)
{
    BIO *bio_err = NULL;
    X509 *x509 = NULL;
    EVP_PKEY *pub_key = NULL;
    FILE *keyfile = NULL;
    FILE *crtfile = NULL;
    char keyfilepath[PATH_MAX], crtfilepath[PATH_MAX];
    int ret_val = ERR_NO_ERROR;

    keyfilepath[0] = '\0';
    crtfilepath[0] = '\0';

    CRYPTO_mem_ctrl (CRYPTO_MEM_CHECK_ON);

    bio_err = BIO_new_fp (stderr, BIO_NOCLOSE);

    /*Backup default certification file. */

    if (_is_exist_default_backup_cert (_dbmt_error) != 1)
    {
        if (_backup_cert (_dbmt_error) != 0)
        {
            ret_val = ERR_WITH_MSG;
            goto release_src;
        }
    }

    ret_val = _make_cert (req, &x509, &pub_key, RSA_KEY_SIZE, _dbmt_error);
    if (ret_val != ERR_NO_ERROR)
    {
        goto release_src;
    }

    snprintf (keyfilepath, PATH_MAX, "%s", sco.szSSLKey);
    if ((keyfile = fopen (keyfilepath, "w")) == NULL)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", sco.szSSLKey);
        ret_val = ERR_FILE_OPEN_FAIL;
        goto release_src;
    }
    PEM_write_PrivateKey (keyfile, pub_key, NULL, NULL, 0, NULL, NULL);
    fclose (keyfile);

    snprintf (crtfilepath, PATH_MAX, "%s", sco.szSSLCertificate);
    if ((crtfile = fopen (crtfilepath, "w")) == NULL)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", sco.szSSLCertificate);
        ret_val = ERR_FILE_OPEN_FAIL;
        goto release_src;
    }
    if (PEM_write_X509 (crtfile, x509) != 1)
    {
        _recover_cert (_dbmt_error);
        ret_val = ERR_WITH_MSG;
        goto release_src;
    }

release_src:
    if (crtfile != NULL)
    {
        fclose (crtfile);
    }
    if (x509 != NULL)
    {
        X509_free (x509);
    }
    if (pub_key != NULL)
    {
        EVP_PKEY_free (pub_key);
    }

#ifndef OPENSSL_NO_ENGINE
    ENGINE_cleanup ();
#endif
    CRYPTO_cleanup_all_ex_data ();
    if (pub_key != NULL)
    {
        CRYPTO_mem_leaks (bio_err);
        BIO_free (bio_err);
    }
    return ret_val;
}

static int
_hash_cert (char *hash_value, char *file_path)
{
    MD5_CTX mdContext;
    unsigned char data[RSA_KEY_SIZE];
    unsigned char md5_final[MD5_DIGEST_LENGTH];
    char md5_final_hex[MD5_DIGEST_LENGTH];
    int bytes = 0;
    int i = 0;
    FILE *inFile = NULL;

    if ((inFile = fopen (file_path, "rb")) == NULL)
    {
        return 1;
    }

    MD5_Init (&mdContext);

    while ((bytes = (int) fread (data, 1, RSA_KEY_SIZE, inFile)) != 0)
    {
        MD5_Update (&mdContext, data, bytes);
    }
    MD5_Final (md5_final, &mdContext);
    fclose (inFile);

    for (i = 0; i < MD5_DIGEST_LENGTH; i++)
    {
        snprintf (md5_final_hex, 3, "%x", md5_final[i]);
        strncat (hash_value, md5_final_hex, 3);
    }
    return 0;
}

static int
_is_default_cert (char *_dbmt_error)
{
    char new_hash_value[33];
    char default_cert_path[PATH_MAX];
    const char *default_hash_file = "df6a39a5565f858e40b6a7a3b0dee779";
    int compare_ret = 0;

    new_hash_value[0] = '\0';
    default_cert_path[0] = '\0';

    snprintf (default_cert_path, PATH_MAX, "%s", sco.szSSLCertificate);

    if (_hash_cert (new_hash_value, default_cert_path) != 0)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE,
                  "Fail to get the value of SSL certification file.");
        return -1;
    }

    compare_ret =
        strncmp (default_hash_file, new_hash_value, strlen (new_hash_value));

    if (compare_ret == 0)
    {
        return 1;
    }
    return 0;
}

static int
_is_exist_default_backup_cert (char *_dbmt_error)
{
    char new_hash_value[33];
    char default_backup_cert_path[PATH_MAX];
    const char *default_hash_file = "df6a39a5565f858e40b6a7a3b0dee779";
    int compare_ret = 0;

    new_hash_value[0] = '\0';
    default_backup_cert_path[0] = '\0';

    snprintf (default_backup_cert_path, PATH_MAX, "%s.bak",
              sco.szSSLCertificate);

    if (access (default_backup_cert_path, F_OK) != 0)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE,
                  "Cannot find the backup SSL certification file: %s.",
                  default_backup_cert_path);
        return -1;
    }

    if (_hash_cert (new_hash_value, default_backup_cert_path) != 0)
    {
        snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE,
                  "Fail to get the value of backup SSL certification file.");
        return -1;
    }

    compare_ret =
        strncmp (default_hash_file, new_hash_value, strlen (new_hash_value));

    if (compare_ret == 0)
    {
        return 1;
    }
    snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE,
              "(%s) is not default backup SSL certification file.",
              default_backup_cert_path);
    return 0;
}
