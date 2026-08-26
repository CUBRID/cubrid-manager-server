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
#include <map>

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
ch_build_request (Json::Value &req, nvplist *cli_request)
{
  static atomic_counter_t i = 0;
  nv_add_nvp_int (cli_request, "_STAMP", (int) ATOMIC_FETCH_ADD1 (i));
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
        {
          return 1;
        }
    }

  return 0;
}

/*
inherit for cm_job, find the task function, and exec;
*/
int
ch_process_request (nvplist *req, nvplist *res)
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

  return 0;
}

int
json_to_nv (Json::Value &root, const char *name, nvplist *nv)
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
            {
              json_to_nv (root[index], name, nv);
            }
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
nv_to_json (nvplist *ref, char *value, int &index, Json::Value &root)
{
  Json::Value array;
  Json::StyledWriter writer;
  char *pvalue, *pname;
  for (; index < ref->nvplist_size; ++index)
    {
      if (ref->nvpairs[index] == NULL
          || dst_buffer (ref->nvpairs[index]->name) == NULL)
        {
          continue;
        }
      pname = dst_buffer (ref->nvpairs[index]->name);
      pvalue = dst_buffer (ref->nvpairs[index]->value);
      if (!strcmp (pname, "open"))
        {
          array.clear ();
          nv_to_json (ref, pvalue, ++index, array);
          if (!array.empty ())
            {
              root[pvalue].append (array);
            }
          else
            {
              root[pvalue] = array;
            }
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
dump_json (Json::Value &root)
{
  Json::StyledWriter writer;
  printf ("%s\n", writer.write (root).c_str ());
}

void
dump_nvplist (nvplist *root, char *dumpfile)
{
  nv_writeto (root, dumpfile);
}


int
cub_cm_extend_request (Json::Value &request, Json::Value &response)
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
  catch (exception &e)
    {
      response["status"] = STATUS_FAILURE;
      response["note"] = e.what ();
      return 1;
    }
  return 0;
}

/*
 * task names that a client may run with "async":"yes". these are the
 * handful of utility-wrapping tasks that are known to run long enough
 * (compactdb, backupdb, ...) that blocking the caller for the whole
 * duration is undesirable. any other task ignores the "async" key and
 * runs the same way it always has.
 */
static const char *async_capable_tasks[] =
{
  "loaddb",
  "unloaddb",
  "createdb",
  "optimizedb",
  "checkdb",
  "copydb",
  "renamedb",
  "compactdb",
  "restoredb",
  "backupdb",
  "addvoldb",
  NULL
};

static bool
is_async_capable_task (const string &task_name)
{
  for (int i = 0; async_capable_tasks[i] != NULL; i++)
    {
      if (task_name == async_capable_tasks[i])
        {
          return true;
        }
    }

  return false;
}

static map <std::string, std::string> db_running_async;

/*
 * is_db_running_async () - pure query: is some async-capable task
 * currently running against dbname? caller must hold cm_mutex.
 */
static bool
is_db_running_async (const std::string &dbname)
{
  return !dbname.empty ()
         && db_running_async.find (dbname) != db_running_async.end ();
}

/*
 * db_running_async_start () - mark dbname as running task_name.
 * caller must hold cm_mutex.
 */
static bool
db_running_async_start (const std::string &dbname, const std::string &task_name)
{
  if (dbname.empty ())
    {
      return true;
    }
  if (is_db_running_async (dbname))
    {
      return false;
    }
  db_running_async[dbname] = task_name;
  return true;
}

/*
 * db_running_async_done () - clear dbname's running-task marker, if any.
 *   caller must hold cm_mutex.
 */
static void
db_running_async_done (const string &dbname)
{
  if (!dbname.empty ())
    {
      db_running_async.erase (dbname);
    }
}

static std::string
db_running_async_task (const std::string &dbname)
{
  map <std::string, std::string> ::iterator it = db_running_async.find (dbname);
  return (it != db_running_async.end ()) ? it->second : std::string ();
}

static int
build_db_busy_response (Json::Value &response, const std::string &dbname,
                        const std::string &running_task)
{
  string note = "database '" + dbname + "' is busy with another task";
  if (!running_task.empty ())
    {
      note += " ('" + running_task + "')";
    }
  response["job-status"] = "rejected";
  return build_server_header (response, ERR_WITH_MSG, note.c_str ());
}

static int num_running_async_tasks = 0;

/*
 * async_job_slot_try_acquire () - reserve one of the sco.iMaxNumAsyncTask
 *   slots for a new background job. caller must hold cm_mutex.
 */
static bool
async_job_slot_try_acquire (void)
{
  if (num_running_async_tasks >= sco.iMaxNumAsyncTask)
    {
      return false;
    }
  num_running_async_tasks++;
  return true;
}

/*
 * async_job_slot_release () - give back a slot reserved by
 *   async_job_slot_try_acquire (). caller must hold cm_mutex.
 */
static void
async_job_slot_release (void)
{
  if (num_running_async_tasks > 0)
    {
      num_running_async_tasks--;
    }
}

/*
 * build_async_task_limit_response () - reply used when a client's
 *   "async":"yes" request is rejected because sco.iMaxNumAsyncTask
 *   background jobs are already running.
 */
static int
build_async_task_limit_response (Json::Value &response)
{
  char note[128];

  snprintf (note, sizeof (note),
            "maximum number of concurrent async tasks (%d) reached; try again later",
            sco.iMaxNumAsyncTask);
  response["job-status"] = "rejected";
  return build_server_header (response, ERR_WITH_MSG, note);
}

/*
 * an async job is dropped sco.iAsyncJobTtlSec seconds after it was
 * created (default DEFAULT_ASYNC_JOB_TTL_SEC / 60 min, overridable via
 * "async_job_ttl_sec" in cm.conf) regardless of how many times a
 * client has polled gettaskstatus for it in the meantime, so
 * request_list can't grow without bound just because a client stopped
 * polling.
 */

class async_request
{
  public:
    INT64 uuid;
    Json::Value request;
    Json::Value response;
    int status;
    time_t created_at;
    time_t finished_at;
    std::string db_name;
    std::string requester_id;
    bool holds_async_slot;
    bool is_long_async_job;
#ifndef WINDOWS
    pthread_mutex_t *mutex;
    pthread_cond_t *cond;
#endif
};

std::map < INT64, async_request * > request_list;

/*
 * reap_stale_async_jobs () - drop finished jobs that have been sitting in
 *   request_list for longer than sco.iAsyncJobTtlSec because the client
 *   never called gettaskstatus / job_status to collect the result.
 *   a job still in progress (status == 0) is never removed here.
 *
 *   caller must already hold cm_mutex.
 */
static void
reap_stale_async_jobs (void)
{
  time_t now = time (NULL);
  map < INT64, async_request * > ::iterator itor = request_list.begin ();

  while (itor != request_list.end ())
    {
      async_request *cur = itor->second;

      if (cur->status != 0 && (now - cur->finished_at) > sco.iAsyncJobTtlSec)
        {
          itor = request_list.erase (itor);
#ifndef WINDOWS
          pthread_mutex_destroy (cur->mutex);
          pthread_cond_destroy (cur->cond);
          delete cur->mutex;
          delete cur->cond;
#endif
          delete cur;
          continue;
        }

      if (cur->status == 0 && !cur->is_long_async_job
          && (now - cur->created_at) > sco.iAsyncLongJobSec)
        {
          string task_name = cur->request.get ("task", "unknown").asString ();

          LOG_ERROR ("reap_stale_async_jobs : job %lld (task '%s', db '%s') has been "
                     "running for %d sec, past async_long_job_sec (%d sec); "
                     "its worker thread cannot be safely cancelled, so it is being "
                     "left in request_list until it actually finishes.",
                     (long long) cur->uuid, task_name.c_str (), cur->db_name.c_str (),
                     (int) (now - cur->created_at), sco.iAsyncLongJobSec);

          /* log this only once per job, not on every reap_stale_async_jobs () call */
          cur->is_long_async_job = true;
        }

      ++itor;
    }
}


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
  Json::Value &request = async_param->request;
  Json::Value &response = async_param->response;

  cli_request = nv_create (5, NULL, "\n", ":", "\n");
  cli_response = nv_create (5, NULL, "\n", ":", "\n");
  try
    {
      json_to_nv (request, NULL, cli_request);
      ch_build_request (request, cli_request);
      ch_process_request (cli_request, cli_response);
      nv_to_json (cli_response, NULL, index, response);
    }
  catch (exception &e)
    {
      response["status"] = STATUS_FAILURE;
      response["note"] = e.what ();
    }

  nv_destroy (cli_request);
  nv_destroy (cli_response);

#ifndef WINDOWS
  pthread_mutex_lock (async_param->mutex);
#endif
  mutex_lock (cm_mutex);
  async_param->finished_at = time (NULL);
  async_param->status = 1;

  db_running_async_done (async_param->db_name);

  if (async_param->holds_async_slot)
    {
      async_job_slot_release ();
    }
  mutex_unlock (cm_mutex);
#ifndef WINDOWS
  pthread_cond_broadcast (async_param->cond);
  pthread_mutex_unlock (async_param->mutex);
#endif

  return NULL;
}

/*
 * put_uuid () - write a job's uuid into a response as a JSON string.
 *   the vendored jsoncpp in this tree predates 64-bit JSON number
 *   support (Json::Value only has a 32-bit Int/UInt, no Int64/UInt64),
 *   so assigning an INT64 uuid straight into a Json::Value would
 *   silently truncate it once req_id grows past 2^32. encoding it as a
 *   string sidesteps that and round-trips losslessly through
 *   parse_uuid (), which already accepts numeric strings.
 */
static void
put_uuid (Json::Value &response, INT64 uuid)
{
  char buf[32];
  snprintf (buf, sizeof (buf), "%lld", (long long) uuid);
  response["uuid"] = buf;
}

#ifdef WINDOWS
int
cm_execute_request_async (Json::Value &request, Json::Value &response,
                          unsigned long time_out = 600, bool no_wait = false)
{
  HANDLE hHandles;
  DWORD ThreadID;
  DWORD dwWaitResult;
  static INT64 req_id = 0;
  string task_name = request.get ("task", "").asString ();
  string dbname = request.get ("dbname", "").asString ();
  bool is_db_task = is_async_capable_task (task_name);

  if (is_db_task)
    {
      mutex_lock (cm_mutex);
      bool started = db_running_async_start (dbname, task_name);
      string running_task = started ? "" : db_running_async_task (dbname);
      mutex_unlock (cm_mutex);
      if (!started)
        {
          return build_db_busy_response (response, dbname, running_task);
        }
    }

  if (no_wait)
    {
      mutex_lock (cm_mutex);
      bool acquired = async_job_slot_try_acquire ();
      mutex_unlock (cm_mutex);
      if (!acquired)
        {
          if (is_db_task)
            {
              mutex_lock (cm_mutex);
              db_running_async_done (dbname);
              mutex_unlock (cm_mutex);
            }
          return build_async_task_limit_response (response);
        }
    }

  async_request *pstmt = (async_request *) new (async_request);
  if (pstmt == NULL)
    {
      if (is_db_task || no_wait)
        {
          mutex_lock (cm_mutex);
          if (is_db_task)
            {
              db_running_async_done (dbname);
            }
          if (no_wait)
            {
              async_job_slot_release ();
            }
          mutex_unlock (cm_mutex);
        }
      return ERR_MEM_ALLOC;
    }

  pstmt->request = request;
  pstmt->status = 0;
  pstmt->created_at = time (NULL);
  pstmt->finished_at = 0;
  pstmt->db_name = is_db_task ? dbname : "";
  pstmt->requester_id = request.get ("_ID", "").asString ();
  pstmt->holds_async_slot = no_wait;
  pstmt->is_long_async_job = false;
  mutex_lock (cm_mutex);
  pstmt->uuid = req_id++;
  mutex_unlock (cm_mutex);

  hHandles =
    CreateThread (NULL, 0, cm_async_request_handler, pstmt, 0, &ThreadID);
  if (hHandles == NULL)
    {
      if (is_db_task || no_wait)
        {
          mutex_lock (cm_mutex);
          if (is_db_task)
            {
              db_running_async_done (dbname);
            }
          if (no_wait)
            {
              async_job_slot_release ();
            }
          mutex_unlock (cm_mutex);
        }
      delete (pstmt);
      return build_server_header (response, ERR_WITH_MSG,
                                  "failed to execute task");
    }

  if (no_wait)
    {
      /* caller asked for "async":"yes": hand the uuid back right away
       * and let the worker thread keep running in the background. */
      CloseHandle (hHandles);
      mutex_lock (cm_mutex);
      reap_stale_async_jobs ();
      request_list[pstmt->uuid] = pstmt;
      mutex_unlock (cm_mutex);

      put_uuid (response, pstmt->uuid);
      response["job-status"] = "running";
      return build_server_header (response, ERR_NO_ERROR, "none");
    }

  dwWaitResult = WaitForSingleObject (hHandles, time_out * 1000);    //  time-out interval

  if (dwWaitResult != WAIT_OBJECT_0)
    {
      CloseHandle (hHandles);
      mutex_lock (cm_mutex);
      reap_stale_async_jobs ();
      request_list[pstmt->uuid] = pstmt;
      mutex_unlock (cm_mutex);
      put_uuid (response, pstmt->uuid);
      response["job-status"] = "running";
      return build_server_header (response, ERR_WITH_MSG, "timeout");
    }

  CloseHandle (hHandles);
  response = pstmt->response;
  delete (pstmt);
  return ERR_NO_ERROR;
}
#else
int
cm_execute_request_async (Json::Value &request, Json::Value &response,
                          unsigned long time_out = 600, bool no_wait = false)
{
  int err = 0;
  pthread_t async_thrd;
  timespec to;
  static INT64 req_id = 0;
  string task_name = request.get ("task", "").asString ();
  string dbname = request.get ("dbname", "").asString ();
  bool is_db_task = is_async_capable_task (task_name);

  if (is_db_task)
    {
      /*
       * only one async-capable task may run against a given database
       * at a time (e.g. compactdb 'demodb' must not start while
       * backupdb 'demodb' is still running). fail fast here, before
       * spawning a worker thread at all, if dbname is already busy.
       */
      mutex_lock (cm_mutex);
      bool started = db_running_async_start (dbname, task_name);
      string running_task = started ? "" : db_running_async_task (dbname);
      mutex_unlock (cm_mutex);
      if (!started)
        {
          return build_db_busy_response (response, dbname, running_task);
        }
    }

  if (no_wait)
    {
      mutex_lock (cm_mutex);
      bool acquired = async_job_slot_try_acquire ();
      mutex_unlock (cm_mutex);
      if (!acquired)
        {
          if (is_db_task)
            {
              mutex_lock (cm_mutex);
              db_running_async_done (dbname);
              mutex_unlock (cm_mutex);
            }
          return build_async_task_limit_response (response);
        }
    }

  async_request *pstmt = (async_request *) new (async_request);
  if (pstmt == NULL)
    {
      if (is_db_task || no_wait)
        {
          mutex_lock (cm_mutex);
          if (is_db_task)
            {
              db_running_async_done (dbname);
            }
          if (no_wait)
            {
              async_job_slot_release ();
            }
          mutex_unlock (cm_mutex);
        }
      return ERR_MEM_ALLOC;
    }

  pstmt->mutex = new pthread_mutex_t;
  pstmt->cond = new pthread_cond_t;

  err = pthread_mutex_init (pstmt->mutex, NULL);
  if (err != 0)
    {
      LOG_ERROR ("cm_execute_request_async : fail to set thread mutex.");
      if (is_db_task || no_wait)
        {
          mutex_lock (cm_mutex);
          if (is_db_task)
            {
              db_running_async_done (dbname);
            }
          if (no_wait)
            {
              async_job_slot_release ();
            }
          mutex_unlock (cm_mutex);
        }
      delete pstmt->mutex;
      delete pstmt->cond;
      delete (pstmt);
      return build_server_header (response, ERR_WITH_MSG,
                                  "failed to run task.");
    }

  err = pthread_cond_init (pstmt->cond, NULL);
  if (err != 0)
    {
      LOG_ERROR ("cm_execute_request_async : fail to set thread condition.");
      if (is_db_task || no_wait)
        {
          mutex_lock (cm_mutex);
          if (is_db_task)
            {
              db_running_async_done (dbname);
            }
          if (no_wait)
            {
              async_job_slot_release ();
            }
          mutex_unlock (cm_mutex);
        }
      pthread_mutex_destroy (pstmt->mutex);
      delete pstmt->mutex;
      delete pstmt->cond;
      delete (pstmt);
      return build_server_header (response, ERR_WITH_MSG,
                                  "failed to run task.");
    }

  pstmt->request = request;
  pstmt->status = 0;
  pstmt->created_at = time (NULL);
  pstmt->finished_at = 0;
  pstmt->db_name = is_db_task ? dbname : "";
  pstmt->requester_id = request.get ("_ID", "").asString ();
  pstmt->holds_async_slot = no_wait;
  pstmt->is_long_async_job = false;

  mutex_lock (cm_mutex);
  pstmt->uuid = req_id++;
  mutex_unlock (cm_mutex);

  err = pthread_create (&async_thrd, NULL, cm_async_request_handler, pstmt);

  if (err != 0)
    {
      if (is_db_task || no_wait)
        {
          mutex_lock (cm_mutex);
          if (is_db_task)
            {
              db_running_async_done (dbname);
            }
          if (no_wait)
            {
              async_job_slot_release ();
            }
          mutex_unlock (cm_mutex);
        }
      pthread_mutex_destroy (pstmt->mutex);
      pthread_cond_destroy (pstmt->cond);
      delete pstmt->mutex;
      delete pstmt->cond;
      delete (pstmt);
      LOG_ERROR ("cm_execute_request_async : fail to create thread.");
      return build_server_header (response, ERR_WITH_MSG,
                                  "failed to run task.");
    }

  /* the thread is never pthread_join ()-ed (the no_wait and timeout
   * paths below return without waiting for it), so detach it up front;
   * otherwise it stays joinable forever and its resources are never
   * released. */
  pthread_detach (async_thrd);

  if (no_wait)
    {
      /* caller asked for "async":"yes": hand the uuid back right away
       * and let the worker thread keep running in the background. */
      mutex_lock (cm_mutex);
      reap_stale_async_jobs ();
      request_list[pstmt->uuid] = pstmt;
      mutex_unlock (cm_mutex);

      put_uuid (response, pstmt->uuid);
      response["job-status"] = "running";
      return build_server_header (response, ERR_NO_ERROR, "none");
    }

  pthread_mutex_lock (pstmt->mutex);
  to.tv_sec = time (NULL) + time_out;
  to.tv_nsec = 0;
  err = 0;
  while (pstmt->status == 0 && err == 0)
    {
      err = pthread_cond_timedwait (pstmt->cond, pstmt->mutex, &to);
    }
  bool finished = (pstmt->status != 0);
  pthread_mutex_unlock (pstmt->mutex);
  if (!finished)
    {
      string dbname, task_name;
      task_name = request.get ("task", "unknown").asString();
      dbname = request.get ("dbname", "").asString();
      /* register the still-running job so gettaskstatus can
       * find it later. the original code returned here without ever
       */
      mutex_lock (cm_mutex);
      reap_stale_async_jobs ();
      request_list[pstmt->uuid] = pstmt;
      mutex_unlock (cm_mutex);
      put_uuid (response, pstmt->uuid);
      response["job-status"] = "running";
      LOG_ERROR ("cm_execute_request_async : Timeout %ld secs: task '%s'. %s",
		time_out, task_name.c_str(), dbname.c_str ());
      return build_server_header (response, ERR_WITH_MSG, "timeout");
    }

  pthread_mutex_destroy (pstmt->mutex);
  pthread_cond_destroy (pstmt->cond);
  delete pstmt->mutex;
  delete pstmt->cond;
  response = pstmt->response;
  delete (pstmt);
  return ERR_NO_ERROR;
}
#endif

static bool
parse_uuid (const Json::Value &v, INT64 &out)
{
  if (v.isInt ())
    {
      out = v.asInt ();
      return true;
    }

  if (v.isUInt ())
    {
      out = v.asUInt ();
      return true;
    }

  if (v.isString ())
    {
      const string s = v.asString ();
      if (s.empty ())
        {
          return false;
        }

      char *endptr = NULL;
      /* strtoull (not strtoul): on Windows "unsigned long" is only 32
       * bits, which would silently truncate a uuid here even though
       * req_id/out are a full 64-bit INT64. */
#if defined (WINDOWS)
      unsigned long long parsed = _strtoui64 (s.c_str (), &endptr, 10);
#else
      unsigned long long parsed = strtoull (s.c_str (), &endptr, 10);
#endif
      if (endptr == s.c_str () || *endptr != '\0')
        {
          return false;
        }

      out = (INT64) parsed;
      return true;
    }

  return false;
}

/*
 * cub_check_async_status () - handle a "gettaskstatus"
 *   poll for a job previously started with "async":"yes" (or one that
 *   fell back to async because it ran past sco.iHttpTimeout).
 */
int
cub_check_async_status (Json::Value &request, Json::Value &response)
{
  string task;
  INT64 uuid;
  map < INT64, async_request * > ::iterator itor;
  task = request["task"].asString ();

  if (task != "gettaskstatus")
    {
      return 0;
    }

  reap_stale_async_jobs ();

  if (!parse_uuid (request["uuid"], uuid))
    {
      return build_server_header (response, ERR_WITH_MSG, "invalid uuid");
    }

  itor = request_list.find (uuid);
  if (itor == request_list.end ())
    {
      return build_server_header (response, ERR_WITH_MSG, "uuid not found");
    }

  if (request.get ("_ID", "").asString () != itor->second->requester_id)
    {
      return build_server_header (response, ERR_WITH_MSG, "invalid uuid");
    }

  if (itor->second->status == 0)
    {
      put_uuid (response, itor->second->uuid);
      response["job-status"] = "running";
      return build_server_header (response, ERR_NO_ERROR, "none");
    }

  /* NOTE: a finished job is intentionally left in request_list here,
   * not erased/deleted on this first successful poll - a client is
   * free to call gettaskstatus for the same uuid more than once (e.g.
   * a status-check retry, or more than one part of the client polling
   * independently) and should keep getting the same finished result
   * each time. the job is only ever reclaimed by reap_stale_async_jobs
   * (), once sco.iAsyncJobTtlSec seconds have passed since it was
   * created (see cm.conf's "async_job_ttl_sec"). */
  response = itor->second->response;
  put_uuid (response, itor->second->uuid);
  response["job-status"] = (response["status"].isString () &&
			    response["status"].asString () == STATUS_SUCCESS) ? "success" : "error";
  return ERR_NO_ERROR;
}

int
cub_cm_request_handler (Json::Value &request, Json::Value &response)
{

  mutex_lock (cm_mutex);


  if (ext_ut_validate_token (request, response) != ERR_NO_ERROR)
    {
      response["task"] = request["task"].asString();
      mutex_unlock (cm_mutex);
      return 1;
    }

  if (!ext_ut_validate_auth (request))
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

  /*
   * everything above this point is fast and bounded (token/auth lookup,
   * a request_list scan), so it is fine to run it under cm_mutex. what
   * follows is not: cm_execute_request_async () either runs the task
   * and waits for it (up to sco.iHttpTimeout, 30 sec by default) or, for
   * an explicit "async":"yes" request on a long-running task, does not
   * wait at all. cm_mutex used to stay held for that entire wait, which
   * meant one client's slow compactdb/backupdb/etc. blocked every other
   * client's requests - even unrelated, fast ones - for as long as the
   * first one took (or until it timed out). release the lock before
   * that call; cm_execute_request_async () re-takes cm_mutex itself,
   * briefly, only when it actually needs to touch request_list.
   */
  {
    const Json::Value &async_val = request.get ("async", "no");
    bool want_async = async_val.isString ()
                      && uStringEqual (async_val.asString ().c_str (), "yes")
                      && is_async_capable_task (request["task"].asString ());

    mutex_unlock (cm_mutex);
    cm_execute_request_async (request, response, sco.iHttpTimeout, want_async);
  }

  return 1;
}

