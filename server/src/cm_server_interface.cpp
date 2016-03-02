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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <list>

#ifdef WINDOWS
#include <process.h>
#else
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/time.h>
#endif

#include "cm_server_interface.h"
#include "cm_server_extend_interface.h"
#include "cm_log.h"
#include "cm_mon_stat.h"

using namespace std;

#ifndef MAX_PATH
#define MAX_PATH 256
#endif

extern T_EMGR_VERSION CLIENT_VERSION;

typedef struct
{
    char cubrid[MAX_PATH];              /*cubrid home; CUBRID=/root/CUBRID */
    char cubrid_databases[MAX_PATH];    /*cubrid databases home,default $(cubrid home)/databases */
    char cubrid_err_log[MAX_PATH];      /*cubrid err log, use for save cmd log */
    // char cubrid_charset[MAX_PATH];
} cubrid_env_t;
mutex_t cm_mutex;
/*global cubrid env*/
cubrid_env_t cub_httpd_env;

/**
 * @brief initial monitoring stat information 
 *
 * @return -1: error, 1: ok 
 */
int
mon_stat_init (void)
{
#if !defined (DO_NOT_USE_CUBRIDENV)
    sprintf (sco.sMonStatDataPath, "%s/%s", sco.szCubrid, DBMT_MON_DATA_DIR);
#else
    sprintf (sco.sMonStatDataPath, "%s", CUBRID_MONDATADIR);
#endif

    if (access (sco.sMonStatDataPath, F_OK) < 0)
    {
        if (mkdir (sco.sMonStatDataPath, 0755) < 0)
        {
            fprintf (stderr, "Error while creating monitoring data path(%s)\n",
                     sco.sMonStatDataPath);
            return -1;
        }
    }

    if (!cm_mon_stat::get_instance ()->initial ())
    {
        fprintf (stderr, "Error while loading monitoring data information\n");
        return -1;
    }
    return 1;
}

void
cub_cm_init_env ()
{
    char conf_name[256];
    char tmpstrbuf[DBMT_ERROR_MSG_SIZE];
    char process_name[PATH_MAX];
    char default_cubrid_lang_type[PATH_MAX];
    char default_cubrid_lang_msg_type[PATH_MAX];

    tmpstrbuf[0]= '\0';
    //  char *charset = NULL;
    snprintf (process_name, PATH_MAX, "%s", CMS_NAME);
    snprintf (default_cubrid_lang_type, PATH_MAX, "CUBRID_LANG=en_US");
    snprintf (default_cubrid_lang_msg_type, PATH_MAX, "CUBRID_MSG_LANG=en_US");

    sys_config_init ();
    uReadEnvVariables (process_name);

    if (uReadSystemConfig () < 0)
    {
        snprintf (tmpstrbuf, DBMT_ERROR_MSG_SIZE, "CUBRID Manager Server : Cannot find the configuration file[%s].\n", 
                  conf_get_dbmt_file (FID_DBMT_CONF, conf_name));
        ut_record_cubrid_utility_log_stderr (tmpstrbuf);
        exit (1);
    }
    make_default_env ();

    /* check system configuration */
    if (uCheckSystemConfig (process_name) < 0)
    {
        ut_record_cubrid_utility_log_stderr ("CUBRID Manager Server : Error while checking system configuration file.\n");
        exit (1);
    }

    if (mon_stat_init () < 0)
    {
        ut_record_cubrid_utility_log_stderr ("CUBRID Manager Server : Error while checking monitoring data.\n");
        exit (1);
    }

    memset (&cub_httpd_env, 0, sizeof (cubrid_env_t));
    putenv (default_cubrid_lang_type);    /* set as default language type */
    putenv (default_cubrid_lang_msg_type);    /* set as default language type */
    //putenv ("CUBRID_CHARSET=en_US");    /* set as default language type */

    snprintf (cub_httpd_env.cubrid_err_log, MAX_PATH,
              "CUBRID_ERROR_LOG=%s/cmclt.%d.err", sco.dbmt_tmp_dir, (int) getpid ());
    putenv (cub_httpd_env.cubrid_err_log);

    snprintf (cub_httpd_env.cubrid, MAX_PATH, "CUBRID=%s", sco.szCubrid);
    putenv (cub_httpd_env.cubrid);

    snprintf (cub_httpd_env.cubrid_databases, MAX_PATH, "CUBRID_DATABASES=%s",
              sco.szCubrid_databases);
    putenv (cub_httpd_env.cubrid_databases);

    /*  charset = getenv ("CUBRID_CHARSET");
    if (charset != NULL)
    {
        snprintf (cub_httpd_env.cubrid_charset, MAX_PATH, "CUBRID_CHARSET=%s",
                  charset);
    }
    else
    {
        snprintf (cub_httpd_env.cubrid_charset, MAX_PATH,
                  "CUBRID_CHARSET=en_US");
        putenv (cub_httpd_env.cubrid_charset);
    }
    */
    mutex_init (cm_mutex);
    return;
}

void
cub_cm_destory_env ()
{
    mutex_destory (cm_mutex);
}

int
ch_build_request (Json::Value & req, nvplist * cli_request)
{
    static int i = 0;
    nv_add_nvp_int (cli_request, "_STAMP", i++);
    nv_add_nvp (cli_request, "_PROGNAME", CMS_NAME);

    return 1;
}

static int
is_no_token_cmd (int task_code)
{
    int no_token_cmd[] = { TS_LOGIN, TS_GET_CMS_ENV, -1 };
    int i;
    for (i = 0; no_token_cmd[i] != -1; i++)
    {
        if (task_code == no_token_cmd[i])
            return 1;
    }

    return 0;
}

/*
inherit for cm_job, find the task function, and exec;
*/
int
ch_process_request (nvplist * req, nvplist * res)
{
    int task_code;
    int retval = ERR_NO_ERROR;
    char *dbname, *task;
    // char *charset = NULL;
    // static char charsetenv[PATH_MAX] = "";
    char dbid[32];
    char dbpasswd[80];
    T_TASK_FUNC task_func;
    char access_log_flag;
    char _dbmt_error[DBMT_ERROR_MSG_SIZE];
    int major_ver, minor_ver;
    char *cli_ver;

    int elapsed_msec = 0;
    struct timeval task_begin, task_end;
    char elapsed_time_str[20];

    memset (_dbmt_error, 0, sizeof (_dbmt_error));

    task = nv_get_val (req, "task");
    dbname = nv_get_val (req, "dbname");
    //charset = nv_get_val (req, "charset");

    task_code = ut_get_task_info (task, &access_log_flag, &task_func, NULL);
    switch (task_code)
    {
        /* case TS_ANALYZECASLOG: */
        case TS_GET_DIAGDATA:
        nv_reset_nvp (res);
        nv_init (res, 5, NULL, "\n", ":DIAG_DEL:", "END__DIAGDATA\n");
        break;
    }

    /* insert task,status,note to the front of response */
    nv_add_nvp (res, "task", task);
    nv_add_nvp (res, "status", "none");
    nv_add_nvp (res, "note", "none");

    if (!is_no_token_cmd (task_code))
    {
        /*
        if (ut_validate_token (req) == 0)
        {
        retval = ERR_INVALID_TOKEN;
        uGenerateStatus (req, res, retval, _dbmt_error);
        return 0;
        }
        */

        /* if database name is specified */
        if (dbname)
        {
            memset (dbid, 0, 32);
            memset (dbpasswd, 0, 80);
            _ut_get_dbaccess (req, dbid, dbpasswd);
            nv_add_nvp (req, "_DBID", dbid);
            nv_add_nvp (req, "_DBPASSWD", dbpasswd);
            nv_add_nvp (req, "_DBNAME", dbname);
        }
    }

    /* set CLIENT_VERSION */
    cli_ver = nv_get_val (req, "_CLIENT_VERSION");
    make_version_info (cli_ver == NULL ? "1.0" : cli_ver, &major_ver,
                       &minor_ver);
    CLIENT_VERSION = EMGR_MAKE_VER (major_ver, minor_ver);    /* global variable */

    sprintf (_dbmt_error, "?");    /* prevent to have null string */
    if (task_code == TS_UNDEFINED)
    {
        if (task != NULL)
        {
            strcpy (_dbmt_error, task);
        }
        retval = ERR_UNDEFINED_TASK;
    }
    else
    {
        if (access_log_flag)
        {
            ut_access_log (req, NULL);
        }

        /*    if (charset != NULL)
        {
        snprintf (charsetenv, PATH_MAX, "CUBRID_CHARSET=%s", charset);
        putenv (charsetenv);
        }
        */
        /* record the start time of running cub_manager */
        gettimeofday (&task_begin, NULL);

        retval = (*task_func) (req, res, _dbmt_error);

        /* record the end time of running cub_manager */
        gettimeofday (&task_end, NULL);
        /*     if (charset != NULL)
        {
        putenv (cub_httpd_env.cubrid_charset);
        }
        */   
        /* caculate the running time of cub_manager. */
        _ut_timeval_diff (&task_begin, &task_end, &elapsed_msec);

        /* add cub_manager task running time to response. */
        snprintf (elapsed_time_str, sizeof (elapsed_time_str), "%d ms",
                  elapsed_msec);
        nv_add_nvp (res, "__EXEC_TIME", elapsed_time_str);
    }

    uGenerateStatus (req, res, retval, _dbmt_error);

    //      FREE_MEM (cli_ver);

    return 0;
}

int
json_to_nv (Json::Value & root, const char *name, nvplist * nv)
{
    switch (root.type ())
    {
        case Json::arrayValue:
            {
                int size = root.size ();

                for (int index = 0; index < size; ++index)
                {
                    if (!strcmp (name, "line") || !strcmp (name, "confdata")
                        || !strcmp (name, "group"))
                        json_to_nv (root[index], name, nv);
                    else
                    {
                        nv_add_nvp (nv, "open", name);
                        json_to_nv (root[index], name, nv);
                        nv_add_nvp (nv, "close", name);
                    }
                }
            }
            break;
        case Json::objectValue:
            {
                Json::Value::Members members (root.getMemberNames ());
                for (Json::Value::Members::iterator it = members.begin ();
                    it != members.end (); ++it)
                {
                    json_to_nv (root[*it], (*it).c_str (), nv);
                }
            }
            break;
        case Json::intValue:
            nv_add_nvp_int (nv, name, root.asInt ());
            break;
        default:
            nv_add_nvp (nv, name, root.asString ().c_str ());
            break;
    }

    return 0;
}

#define IS_SPECIAL_KEY  (!strcmp(pname, "line") || !strcmp(pname, "confdata")   \
                                                || !strcmp(pname, "group") || !strcmp(pname, "classattribute")  \
                                                || !strcmp(pname, "attribute"))
/*
transform struct nvplist to json.
*/
int
nv_to_json (nvplist * ref, char *value, int &index, Json::Value & root)
{
    Json::Value array;
    Json::StyledWriter writer;
    char *pvalue, *pname;
    for (; index < ref->nvplist_size; ++index)
    {
        if (ref->nvpairs[index] == NULL
            || dst_buffer (ref->nvpairs[index]->name) == NULL)
            continue;
        pname = dst_buffer (ref->nvpairs[index]->name);
        pvalue = dst_buffer (ref->nvpairs[index]->value);
        if (!strcmp (pname, "open"))
        {
            array.clear ();
            nv_to_json (ref, pvalue, ++index, array);
            if (!array.empty ())
                root[pvalue].append (array);
            else
                root[pvalue] = array;
        }
        else if (!strcmp (pname, "close") && !strcmp (pvalue, value))
        {
            break;
        }
        else if (IS_SPECIAL_KEY)
        {
            root[pname].append ((pvalue == NULL) ? "" : pvalue);
        }
        else
        {
            root[pname] = (pvalue == NULL) ? "" : pvalue;
        }
    }

    return 1;
}

void
dump_json (Json::Value & root)
{
    Json::StyledWriter writer;
    printf ("%s\n", writer.write (root).c_str ());
}

void
dump_nvplist (nvplist * root, char *dumpfile)
{
    nv_writeto (root, dumpfile);
}


int
cub_cm_extend_request (Json::Value & request, Json::Value & response)
{
    T_EXT_TASK_FUNC task_func = NULL;
    string task;
    try
    {
        task = request["task"].asString ();
        response["task"] = task;
        if (get_ext_task_info (task.c_str (), 0, &task_func, NULL))
        {
            (*task_func) (request, response);
            return 1;
        }
    }
    catch (exception & e)
    {
        response["status"] = STATUS_FAILURE;
        response["note"] = e.what ();
        return 1;
    }
    return 0;
}

class async_request
{
public:
    unsigned int uuid;
    Json::Value request;
    Json::Value response;
    int status;
#ifndef WINDOWS
    pthread_mutex_t *mutex;
    pthread_cond_t *cond;
#endif
};

list < async_request * >request_list;

#ifdef WINDOWS
DWORD WINAPI
cm_async_request_handler (LPVOID lpArg)
#else
void *
cm_async_request_handler (void *lpArg)
#endif
{
    int index = 0;
    nvplist *cli_request, *cli_response;
    async_request *async_param = (async_request *) lpArg;
    Json::Value & request = async_param->request;
    Json::Value & response = async_param->response;

    cli_request = nv_create (5, NULL, "\n", ":", "\n");
    cli_response = nv_create (5, NULL, "\n", ":", "\n");
    try
    {
        json_to_nv (request, NULL, cli_request);
        ch_build_request (request, cli_request);
        ch_process_request (cli_request, cli_response);
        nv_to_json (cli_response, NULL, index, response);
    }
    catch (exception & e)
    {
        response["status"] = ERR_REQUEST_FORMAT;
        response["note"] = e.what ();
    }

    async_param->status = 1;
    nv_destroy (cli_request);
    nv_destroy (cli_response);

#ifndef WINDOWS
    pthread_mutex_lock (async_param->mutex);
    pthread_cond_broadcast (async_param->cond);
    pthread_mutex_unlock (async_param->mutex);
#endif

    return NULL;
}

#ifdef WINDOWS
int
cm_execute_request_async (Json::Value & request, Json::Value & response,
                          unsigned long time_out = 600)
{
    HANDLE hHandles;
    DWORD ThreadID;
    DWORD dwWaitResult;
    static unsigned int req_id = 0;
    async_request *pstmt = (async_request *) new (async_request);
    if (pstmt == NULL)
        return ERR_MEM_ALLOC;

    pstmt->request = request;
    pstmt->status = 0;
    pstmt->uuid = req_id++;

    hHandles =
        CreateThread (NULL, 0, cm_async_request_handler, pstmt, 0, &ThreadID);
    if (hHandles == NULL)
    {
        free (pstmt);
        return build_server_header (response, ERR_WITH_MSG,
                                    "failed to execute task");
    }

    //dwWaitResult = WaitForSingleObject (hHandles, time_out * 1000);    //  time-out interval

    dwWaitResult = WaitForSingleObject (hHandles, INFINITE);    //no timeout. 

    if (dwWaitResult == WAIT_TIMEOUT)
    {
        CloseHandle (hHandles);
        request_list.push_back (pstmt);
        response["uuid"] = pstmt->uuid;
        return build_server_header (response, ERR_WITH_MSG, "timeout");
    }

    CloseHandle (hHandles);
    response = pstmt->response;
    free (pstmt);
    return ERR_NO_ERROR;
}
#else
int
cm_execute_request_async (Json::Value & request, Json::Value & response,
                          unsigned long time_out = 600)
{
    int err = 0;
    pthread_t async_thrd;
#if defined(AIX)
    pthread_attr_t thread_attr;
#endif
    pthread_cond_t cond;
    pthread_mutex_t mutex;
    timespec to;
    static unsigned int req_id = 0;
    async_request *pstmt = (async_request *) new (async_request);
    if (pstmt == NULL)
        return ERR_MEM_ALLOC;

    err = pthread_mutex_init (&mutex, NULL);
    if (err != 0)
    {
        LOG_ERROR("cm_execute_request_async : fail to set thread mutex.");
        return build_server_header (response, ERR_WITH_MSG,
                                    "failed to run task.");
    }

    err = pthread_cond_init (&cond, NULL);
    if (err != 0)
    {
        LOG_ERROR("cm_execute_request_async : fail to set thread condition.");
        return build_server_header (response, ERR_WITH_MSG,
                                    "failed to run task.");
    }

    pstmt->request = request;
    pstmt->status = 0;

    pstmt->uuid = req_id++;

    pstmt->mutex = &mutex;
    pstmt->cond = &cond;

#if defined(AIX)
    err = pthread_attr_init (&thread_attr);
    if (err != 0)
    {
        LOG_ERROR("cm_execute_request_async : fail to set thread attribute.");
        return build_server_header (response, ERR_WITH_MSG,
                                    "failed to run task.");
    }

    err = pthread_attr_setdetachstate (&thread_attr, PTHREAD_CREATE_DETACHED);
    if (err != 0)
    {
        LOG_ERROR("cm_execute_request_async : fail to set thread detach state.");
        return build_server_header (response, ERR_WITH_MSG,
                                    "failed to run task.");
    }

    /* AIX's pthread is slightly different from other systems.
    Its performance highly depends on the pthread's scope and it's related
    kernel parameters. */
    err = pthread_attr_setscope (&thread_attr, PTHREAD_SCOPE_PROCESS);
    if (err != 0)
    {
        LOG_ERROR("cm_execute_request_async : fail to set thread scope.");
        return build_server_header (response, ERR_WITH_MSG,
                                    "failed to run task.");
    }

    err = pthread_attr_setstacksize (&thread_attr, AIX_STACKSIZE_PER_THREAD);
    if (err != 0)
    {
        LOG_ERROR("cm_execute_request_async : fail to set thread stack size.");
        return build_server_header (response, ERR_WITH_MSG,
                                    "failed to run task.");
    }

    err = pthread_create (&async_thrd, &thread_attr, cm_async_request_handler, pstmt);
#else /* except AIX */
    err = pthread_create (&async_thrd, NULL, cm_async_request_handler, pstmt);
#endif

    if (err != 0)
    {
        free (pstmt);
        pthread_mutex_destroy (&mutex);
        pthread_cond_destroy (&cond);
        LOG_ERROR("cm_execute_request_async : fail to create thread.");
        return build_server_header (response, ERR_WITH_MSG,
                                    "failed to run task.");
    }
    pthread_mutex_lock (&mutex);
    to.tv_sec = time (NULL) + time_out;
    to.tv_nsec = 0;
    //err = pthread_cond_timedwait (&cond, &mutex, &to);
    err = pthread_cond_wait(&cond, &mutex); 
    pthread_mutex_unlock (&mutex);
    if (err == ETIMEDOUT)
    {
        request_list.push_back (pstmt);
        response["uuid"] = pstmt->uuid;
        LOG_ERROR("cm_execute_request_async : Timeout for running task.");
        return build_server_header (response, ERR_WITH_MSG, "timeout");
    }

    pthread_join (async_thrd, NULL);

    pthread_mutex_destroy (&mutex);
    pthread_cond_destroy (&cond);
    response = pstmt->response;
    free (pstmt);
    return ERR_NO_ERROR;
}
#endif

int
cub_check_async_status (Json::Value & request, Json::Value & response)
{
    string task;
    unsigned int uuid;
    list < async_request * >::iterator itor;
    task = request["task"].asString ();

    if (task != "gettaskstatus")
        return 0;
    if (request["uuid"] == Json::Value::null || !request["uuid"].isInt ())
        return build_server_header (response, ERR_WITH_MSG, "invalid uuid");
    uuid = request["uuid"].asInt ();
    for (itor = request_list.begin (); itor != request_list.end (); itor++)
    {
        if ((*itor)->uuid != uuid)
        {
            continue;
        }
        break;
    }
    if (itor == request_list.end ())
    {
        return build_server_header (response, ERR_WITH_MSG, "uuid not found");
    }

    if ((*itor)->status == 0)
    {
        return build_server_header (response, ERR_WITH_MSG, "task not return");
    }
    response = (*itor)->response;
    request_list.erase (itor);
    return ERR_NO_ERROR;
}

int
cub_cm_request_handler (Json::Value & request, Json::Value & response)
{

    mutex_lock (cm_mutex);


    // leave a back door for testing...
    if (ext_ut_validate_token (request, response) != ERR_NO_ERROR && request["token"].asString() != "test")
    {
        response["task"] = request["task"].asString(); 
        mutex_unlock (cm_mutex);
        return 1;
    }

    // leave a back door for testing...
    if (!ext_ut_validate_auth (request) && request["token"].asString() != "test")
    {
        response["status"] = STATUS_FAILURE;
        response["note"] = "The user don't have authority to execute the task: " + request["task"].asString();
        response["task"] = request["task"].asString(); 

        mutex_unlock (cm_mutex);
        return 1;
    }

    if (cub_check_async_status (request, response))
    {
        mutex_unlock (cm_mutex);
        return 1;
    }
    if (cub_cm_extend_request (request, response))
    {
        mutex_unlock (cm_mutex);
        return 1;
    } 
    cm_execute_request_async (request, response, sco.iHttpTimeout);

    mutex_unlock (cm_mutex);
    return 1;
}
