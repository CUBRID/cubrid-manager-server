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
*  cm_httpd.cpp
*/

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <string.h>
#include <event2/event.h>
#include <evhttp.h>
#include <event2/buffer.h>
#include <event2/http_struct.h>
#include <event2/http.h>
#include <event2/keyvalq_struct.h>
#include <event2/bufferevent_ssl.h>
#include <event2/listener.h>
#include <event2/thread.h>
#include <event2/event_compat.h>

#ifdef WINDOWS
#include <windows.h>
#include "cm_win_wsa.h"
#include <io.h>
#include <direct.h>
#include <process.h>
#else
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/timeb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <dirent.h>
#endif

#include "cm_log.h"
#include "cm_server_util.h"
#include "cm_config.h"
#include "cm_autojob.h"
#include "cm_auto_task.h"
#include "cm_cci_interface.h"
#include "cm_server_interface.h"
#include "cm_server_stat.h"
#include "cm_server_extend_interface.h"
#include "cm_mon_stat.h"
#include "cm_http_server.h"

//#include "cm_utf8.h"
using namespace std;

#define DEFAULT_THRD_NUM                      24
#define DEFAULT_HTTP_TIMEOUT                  6 * 60    //second
#define NUM_OF_FILES_IN_URL                   3
#define STAT_MONITOR_INTERVAL                 1        // seconds

static THREAD_FUNC automation_start (void *ud);
static THREAD_FUNC aj_thread_r (void *aj);
static void start_auto_thread (void);

T_EMGR_VERSION CLIENT_VERSION = EMGR_MAKE_VER (8, 4);

#ifdef WINDOWS
T_THREAD auto_task_tid = NULL;
#else
T_THREAD auto_task_tid = 0;
#endif

typedef struct aj_thread_info_t
{
  T_THREAD thread_id;
  time_t cur_time;
  time_t prev_check_time;
  ajob *ajob_list;
  time_t stime;
  int is_running;
} aj_thread_info;

aj_thread_info aj_tinfo;

MUTEX_T aj_thread_mutex;

struct worker_context
{
  struct event_base *base;
  struct evhttp *httpd;
  struct event *timer;
  bool first;
#ifdef WINDOWS
  HANDLE ths;
#else
  pthread_t ths;
#endif
};

int
bind_socket (int port)
{
  int r;
  int nfd;
  struct sockaddr_in addr;
  int one = 1;
  int flags = 1;
  nfd = (int) socket (AF_INET, SOCK_STREAM, 0);
  if (nfd < 0)
    {
      return -1;
    }

  setsockopt (nfd, SOL_SOCKET, SO_REUSEADDR, (char *) &one, sizeof (int));

  memset (&addr, 0, sizeof (addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons (port);
  r = bind (nfd, (struct sockaddr *) &addr, sizeof (addr));
  if (r < 0)
    {
      close (nfd);
      return -1;
    }
  r = listen (nfd, 10240);
  if (r < 0)
    {
      close (nfd);
      return -1;
    }
#ifdef WINDOWS
  ioctlsocket (nfd, FIONBIO, (unsigned long *) &flags);
#else
  if ((flags = fcntl (nfd, F_GETFL, 0)) != -1)
    {
      fcntl (nfd, F_SETFL, flags | O_NONBLOCK);
    }
#endif

  return nfd;
}

#ifdef WINDOWS
DWORD WINAPI
dispatch_thread (void *arg)
#else
void *
dispatch_thread (void *arg)
#endif
{
  struct worker_context *work_ctx = (struct worker_context *) arg;
  event_base_dispatch ((struct event_base *) work_ctx->base);

  if (work_ctx->timer)
    {
      event_free (work_ctx->timer);
    }
  if (work_ctx->httpd)
    {
      evhttp_free (work_ctx->httpd);
    }
  if (work_ctx->base)
    {
      event_base_free (work_ctx->base);
    }
#ifdef WINDOWS
  return 0;
#else
  return NULL;
#endif
}

void
cub_add_private_param (struct evhttp_request *req, Json::Value &root)
{
  root["_CLIENTIP"] = req->remote_host;
  root["_CLIENTPORT"] = req->remote_port;
  root["_STAMP"] = 1;
  root["_PROGNAME"] = CMS_NAME;
}

void
cub_generic_request_handler (struct evhttp_request *req, void *arg)
{
  struct evbuffer *input;
  struct evkeyvalq *headers;
  char *body;
  //    char *inustr, *outustr;
  string task_name;
  int len;
  struct evbuffer *evb;
  Json::Value root, response;
  Json::Reader reader;
  Json::StyledWriter writer;
  char *data = NULL;

  input = evhttp_request_get_input_buffer (req);
  if (input == NULL)
    {
      evhttp_send_reply (req, HTTP_BADREQUEST, "", NULL);
      return;
    }

  len = (int) evbuffer_get_length (input);
  if (len <= 0)
    {
      evhttp_send_reply (req, HTTP_BADREQUEST, "", NULL);
      return;
    }

  data = (char *) evbuffer_pullup(input, len);
  if (data == NULL)
    {
      evhttp_send_reply (req, HTTP_BADREQUEST, "", NULL);
      return;
    }


  body = (char *) malloc (len + 1);
  if (body == NULL)
    {
      evhttp_send_reply (req, HTTP_BADREQUEST, "", NULL);
      return;
    }

  memset (body, 0x00, len+1);
  memcpy (body, data, len);

  if (evbuffer_drain (input, len) < 0)
    {
      free (body);
      evhttp_send_reply (req, HTTP_BADREQUEST, "", NULL);
      return;
    }

  if (!reader.parse (body, root))
    {
      free (body);
      //utf8_clean(inustr);
      evhttp_send_reply (req, HTTP_BADREQUEST, "Error JSON format", NULL);
      return;
    }

  cub_add_private_param (req, root);

  if (!strcmp ((char *) arg, "cci"))
    {
      cub_cci_request_handler (root, response);
    }
  else if (!strcmp ((char *) arg, "cm_api"))
    {
      cub_cm_request_handler (root, response);
    }

  //outustr = utf8_encode(writer.write(response).c_str());
  //printf("---------------------\n%s\n", outustr);
  evb = evbuffer_new ();
  if (NULL == evb)
    {
      free (body);
      //utf8_clean(inustr);
      //utf8_clean(outustr);
      return evhttp_send_reply (req, HTTP_BADREQUEST, "", NULL);
    }

  headers = evhttp_request_get_output_headers (req);
  if (headers)
    {
      evhttp_add_header (headers, "Content-Type", "text/plain;charset=utf-8");
    }

  evbuffer_add_printf (evb, "%s", writer.write (response).c_str ());
  evhttp_send_reply (req, HTTP_OK, "OK", evb);
  evbuffer_free (evb);
  free (body);
  //utf8_clean(inustr);
  //utf8_clean(outustr);

  return;
}

static int cub_loop_flag = 1;

void
cub_ctrl_request_handler (struct evhttp_request *req, void *arg)
{
  evhttp_send_reply (req, HTTP_OK, "", NULL);
  cub_loop_flag = 0;
  return;
}

void
cub_post_request_handler (struct evhttp_request *req, void *arg)
{
  string post_msg = "{ \"success\" : true }";
  string req_uri (req->uri);
  char token[TOKEN_ENC_LENGTH];
  size_t token_pos;
  int code;
  string reason;
  size_t fname_pos = 0;
  size_t tmp_pos = 0;
  struct evbuffer *evb = evbuffer_new();

  code = HTTP_OK;
  reason = "OK";
  token[0] = '\0';
  token_pos = 0;

  string cookie (evhttp_find_header (req->input_headers, "COOKIE"));
  token_pos = cookie.find ("token=");
  if (token_pos == string::npos)
    {
      goto send_nok_reply;
    }

  cookie.copy (token, TOKEN_ENC_LENGTH - 1, token_pos + strlen ("token="));
  token[TOKEN_ENC_LENGTH - 1] = '\0';
  if (ext_ut_validate_token (token))
    {
      goto send_reply;
    }

  for (int index = 0; index < NUM_OF_FILES_IN_URL; ++index)
    {
      char fname[PATH_MAX];
      string fname_path = string (sco.dbmt_tmp_dir) + "/";
      fname[0] = '\0';
      fname_pos = req_uri.find ("fname=", tmp_pos);
      if (fname_pos == string::npos && index == 0)
        {
          goto send_nok_reply;
        }
      else if (fname_pos == string::npos)
        {
          goto send_reply;
        }

      fname_pos += strlen ("fname=");
      tmp_pos = req_uri.find ("&", fname_pos);
      if (tmp_pos == string::npos)
        {
          tmp_pos = req_uri.length();
        }
      req_uri.copy (fname, tmp_pos - fname_pos + 1, fname_pos);
      fname[tmp_pos - fname_pos] = '\0';
      if (strcmp (fname, "") != 0 || strcmp (fname, "&") != 0)
        {
          if (strstr (fname, "..") || strstr (fname, "\\") || strstr (fname, "/"))
            {
              continue;
            }
          fname_path += fname;
          unlink (fname_path.c_str());
        }
    }

send_nok_reply:
  post_msg = "{ \"failure\" : true }";
  code = HTTP_NOTFOUND;
  reason = "NOK";

send_reply:
  if (evb)
    {
      evbuffer_add_printf (evb, "%s", post_msg.c_str());
    }
  evhttp_send_reply (req, code, reason.c_str(), evb);
  if (evb)
    {
      evbuffer_free (evb);
    }
  return;
}

void
cub_timeout_cb (evutil_socket_t fd, short event, void *arg)
{
  struct worker_context *work_ctx = (struct worker_context *) arg;
  if (!cub_loop_flag)
    {
      event_base_loopexit (work_ctx->base, NULL);
    }
}


/**
 * @brief callback function to gather monitoring data
 */
void
start_monitor_stat_cb (evutil_socket_t fd, short event, void *arg)
{
  struct timeval stat_tv = { STAT_MONITOR_INTERVAL, 0 };

  struct worker_context *work_ctx = (struct worker_context *) arg;
  if (!cub_loop_flag)
    {
      event_base_loopexit (work_ctx->base, NULL);
      return;
    }

  // [CUBRIDSUS-11917]sleep the thread for a while when the CUBRID is starting
  if (work_ctx->first)
    {
      SLEEP_SEC (MIN_INTERVAL - 1);
      work_ctx->first = false;
    }

  if (sco.iSupportMonStat == TRUE)
    {
      (cm_mon_stat::get_instance())->gather_mon_data();
    }

  evtimer_add (work_ctx->timer, &stat_tv);
}

void
start_monitor_auto_jobs_cb (evutil_socket_t fd, short event, void *arg)
{
  struct timeval auto_task_tv = { sco.iMonitorInterval, 0 };
  struct worker_context *work_ctx = (struct worker_context *) arg;
  if (!cub_loop_flag)
    {
      event_base_loopexit (work_ctx->base, NULL);
      return;
    }
#ifdef WINDOWS
  unsigned long thread_status;
  GetExitCodeThread ((HANDLE) auto_task_tid, &thread_status);

  if (thread_status != STILL_ACTIVE)
    {
      auto_task_tid = NULL;
      LOG_WARN ("Restart auto jobs thread when exit abnormally.");
      start_auto_thread ();
    }
#else
  int pthread_kill_err = ESRCH;
  /* ESRCH   - Thread is not exist.
     EINVAL  - Signal is invalid.
  */
  pthread_kill_err = pthread_kill (auto_task_tid, 0);
  if (pthread_kill_err == ESRCH)
    {
      auto_task_tid = 0;
      LOG_WARN ("Restart auto jobs thread when exit abnormally.");
      start_auto_thread ();
    }
#endif

  evtimer_add (work_ctx->timer, &auto_task_tv);
}

int
start_service ()
{
  struct worker_context *start_ctx[DEFAULT_THRD_NUM];
  char tmpstrbuf[DBMT_ERROR_MSG_SIZE];
  struct timeval tv = { sco.iMonitorInterval, 0 };
  int nfd, err, i = 0;

  tmpstrbuf[0] = '\0';
#ifdef WINDOWS
  wsa_initialize ();
#endif

  thread_setup_SSL ();

  SSL_CTX *ctx = init_SSL (sco.szSSLCertificate, sco.szSSLKey);

  nfd = bind_socket (sco.iCMS_port);

  if (nfd < 0)
    {
      snprintf (tmpstrbuf, DBMT_ERROR_MSG_SIZE,
                "CUBRID Manager Server : The port %d is still used by other process.\n",
                sco.iCMS_port);
      ut_record_cubrid_utility_log_stderr (tmpstrbuf);
      return -1;
    }

  for (i = 0; i < DEFAULT_THRD_NUM; i++)
    {
      start_ctx[i] = (struct worker_context *) malloc (sizeof (struct worker_context));
      if (start_ctx[i] == NULL)
        {
          continue;
        }

      start_ctx[i]->base = event_base_new ();
      if (start_ctx[i]->base == NULL)
        {
          continue;
        }

      start_ctx[i]->first = true;
#ifndef WINDOWS
      start_ctx[i]->ths = 0;
#endif

      if (i > 1)        /* DEFAULT_THRD_NUM - 1 for request handler */
        {
          start_ctx[i]->timer = event_new (start_ctx[i]->base, -1, EV_PERSIST, cub_timeout_cb, (void *) start_ctx[i]);
          if (start_ctx[i]->timer == NULL)
            {
              continue;
            }

          start_ctx[i]->httpd = evhttp_new (start_ctx[i]->base);
          if (start_ctx[i]->httpd == NULL)
            {
              continue;
            }

          err = evhttp_accept_socket (start_ctx[i]->httpd, nfd);
          if (err != 0)
            {
              continue;
            }

          evhttp_set_timeout (start_ctx[i]->httpd, DEFAULT_HTTP_TIMEOUT);
          /* This is the magic that lets evhttp use SSL. */
          evhttp_set_bevcb (start_ctx[i]->httpd, create_sslconn_cb, ctx);
          evhttp_set_cb (start_ctx[i]->httpd, "/cci",
                         cub_generic_request_handler, (void *) "cci");
          evhttp_set_cb (start_ctx[i]->httpd, "/cm_api", cub_generic_request_handler, (void *) "cm_api");
          evhttp_set_cb (start_ctx[i]->httpd, "/ctrl", cub_ctrl_request_handler, NULL);
          evhttp_set_cb (start_ctx[i]->httpd, "/upload", cub_post_request_handler, NULL);
          /* Start web server*/
          evhttp_set_gencb (start_ctx[i]->httpd, load_webfiles_cb, (void *) sco.szCWMPath);
        }
      else if (i == 1)
        {
          /* index 1 for starting monitor of auto jobs */
          start_ctx[i]->timer = event_new (start_ctx[i]->base, -1, EV_TIMEOUT, start_monitor_auto_jobs_cb,
                                           (void *) start_ctx[i]);
          if (start_ctx[i]->timer == NULL)
            {
              ut_record_cubrid_utility_log_stderr ("CUBRID Manager Server : Failed to start monitor of auto job.\n");
              return -1;
            }
          start_ctx[i]->httpd = NULL;
        }
      else
        {
          /* index 0 for monitoring status job */
          start_ctx[i]->timer = event_new (start_ctx[i]->base, -1, EV_TIMEOUT, start_monitor_stat_cb,
                                           (void *) start_ctx[i]);
          if (start_ctx[i]->timer == NULL)
            {
              ut_record_cubrid_utility_log_stderr (
                "CUBRID Manager Server : Failed to start monitoring state job.\n");
              return -1; /* Start monitor status job failed */
            }
          start_ctx[i]->httpd = NULL;
        }
      if (i == 0)
        {
          struct timeval stat_tv = { 1, 0 };
          evtimer_add (start_ctx[i]->timer, &stat_tv);
        }
      else if (i == 1)
        {
          struct timeval auto_task_tv = { sco.iMonitorInterval, 0 };
          evtimer_add (start_ctx[i]->timer, &auto_task_tv);
        }
      else
        {
          evtimer_add (start_ctx[i]->timer, &tv);
        }
#ifdef WINDOWS
      start_ctx[i]->ths =
        CreateThread (NULL, 0, dispatch_thread, start_ctx[i], 0, NULL);
#else
      pthread_create (& (start_ctx[i]->ths), NULL, dispatch_thread,
                      (void *) start_ctx[i]);
#endif
    }

  for (i = 0; i < DEFAULT_THRD_NUM; i++)
    {
#ifdef WINDOWS
      if (start_ctx[i]->ths != INVALID_HANDLE_VALUE)
        {
          WaitForSingleObject (start_ctx[i]->ths, INFINITE);
        }
#else
      if (start_ctx[i]->ths != 0)
        {
          pthread_join (start_ctx[i]->ths, NULL);
        }
#endif
      if (start_ctx[i] != NULL)
        {
          free (start_ctx[i]);
        }
    }

  thread_cleanup_SSL ();

#ifdef WINDOWS
  WSACleanup ();
#endif

  return 0;
}

void
stop_service ()
{
  FILE *pidfile = NULL;
  int pidnum = -1;
  char cub_manager_pid_file[PATH_MAX];
  char connect_list_file[PATH_MAX];

  cub_manager_pid_file[0] = '\0';
  connect_list_file[0] = '\0';

  conf_get_dbmt_file (FID_CMSERVER_PID, cub_manager_pid_file);
  if (access (cub_manager_pid_file, F_OK) < 0)
    {
      ut_record_cubrid_utility_log_stderr ("CUBRID Manager Server : The server is not running.\n");
    }
  else
    {
      pidfile = fopen (cub_manager_pid_file, "rt");
      if (pidfile != NULL)
        {
          fscanf (pidfile, "%d", &pidnum);
          fclose (pidfile);
        }

      if ((pidfile == NULL) || ((kill (pidnum, SIGTERM)) < 0))
        {
          ut_record_cubrid_utility_log_stderr ("CUBRID Manager Server : Failed to stop the server.\n");
        }
      else
        {
          unlink (conf_get_dbmt_file (FID_CMSERVER_PID, cub_manager_pid_file));
          unlink (conf_get_dbmt_file (FID_CONN_LIST, connect_list_file));
        }
    }

  return;
}

static int
get_processid ()
{
  FILE *pidfile = NULL;
  int pidnum = -1;
  char pid_file_name[512];

  conf_get_dbmt_file (FID_CMSERVER_PID, pid_file_name);

  if (access (pid_file_name, F_OK) < 0)
    {
      return 0;
    }

  pidfile = fopen (pid_file_name, "rt");
  if (pidfile != NULL)
    {
      fscanf (pidfile, "%d", &pidnum);
      fclose (pidfile);
    }
  if (pidfile == NULL || ((kill (pidnum, 0) < 0) && (errno == ESRCH))
      || (is_cmserver_process (pidnum, UTIL_CM_SERVER) == 0))
    {
      unlink (pid_file_name);
      return 0;
    }

  return pidnum;
}

static void
print_usage (char *pname)
{
  printf ("Usage: %s [command]\n", pname);
  printf ("commands are :\n");
  printf ("   start      -  start the server.\n");
  printf ("   stop       -  stop the server.\n");
}

static void
init_files ()
{
  char strbuf[PATH_MAX];
  strbuf[0] = '\0';

  /* remove any temporary files from previous run */
  unlink (conf_get_dbmt_file (FID_CONN_LIST, strbuf));
  unlink (conf_get_dbmt_file (FID_PSVR_DBINFO_TEMP, strbuf));
  unlink (conf_get_dbmt_file (FID_CMSERVER_PID, strbuf));
}

static THREAD_FUNC
automation_start (void *ud)
{
  ajob ajob_list[AUTOJOB_SIZE];
  int i;
  time_t prev_check_time, cur_time;
  char strbuf[512];

  strbuf[0] = '\0';

  aj_tinfo.is_running = 0;
  MUTEX_INIT (aj_thread_mutex);

  /* set up automation list */
  aj_initialize (ajob_list, ud);
  for (i = 0; i < AUTOJOB_SIZE; ++i)
    {
      if (ajob_list[i].ajob_loader)
        {
          ajob_list[i].ajob_loader (& (ajob_list[i]));
        }
    }

  prev_check_time = time (NULL);
  for (;;)
    {
      SLEEP_SEC (sco.iMonitorInterval);
      cur_time = time (NULL);

      MUTEX_LOCK (aj_thread_mutex);
      if (0 != aj_tinfo.is_running)
        {
          if (cur_time - aj_tinfo.stime > sco.iAutoJobTimeout)
            {
              THREAD_CANCEL (aj_tinfo.thread_id);
              snprintf (strbuf, sizeof (strbuf), "%s - - -", ACCESS_LOG);
              write_manager_access_log (strbuf,
                                        "Auto jobs execute too long, Cancel the thread");
              aj_tinfo.is_running = 0;
            }
        }
      if (0 == aj_tinfo.is_running)
        {
          T_THREAD tid;
          aj_thread_info *ptr_aj_tinfo;
          aj_tinfo.ajob_list = ajob_list;
          aj_tinfo.cur_time = cur_time;
          aj_tinfo.prev_check_time = prev_check_time;
          ptr_aj_tinfo = &aj_tinfo;
          THREAD_BEGIN (tid, aj_thread_r, ptr_aj_tinfo);
          aj_tinfo.is_running = 1;
          aj_tinfo.thread_id = tid;
          aj_tinfo.stime = cur_time;
          prev_check_time = cur_time;
        }
      MUTEX_UNLOCK (aj_thread_mutex);
    }

#if defined(WINDOWS)
  return;
#else
  return NULL;
#endif
}

static THREAD_FUNC
aj_thread_r (void *aj)
{
  struct stat statbuf;
  aj_thread_info *aj_tinfo_local = (aj_thread_info *) aj;
  ajob *ajob_list = aj_tinfo_local->ajob_list;
  time_t cur_time = aj_tinfo_local->cur_time;
  time_t prev_check_time = aj_tinfo_local->prev_check_time;
  int i;

  for (i = 0; i < AUTOJOB_SIZE; ++i)
    {
      /* check automation configure file and see if it has changed since last access */
      stat (ajob_list[i].config_file, &statbuf);
      if (ajob_list[i].last_modi != statbuf.st_mtime)
        {
          ajob_list[i].last_modi = statbuf.st_mtime;
          if (ajob_list[i].ajob_loader)
            {
              ajob_list[i].ajob_loader (& (ajob_list[i]));
            }
        }

      /* if unchanged, go ahead and check value */
      if (ajob_list[i].is_on && ajob_list[i].ajob_handler)
        {
          ajob_list[i].ajob_handler (ajob_list[i].hd, prev_check_time, cur_time);
        }
    }

  MUTEX_LOCK (aj_thread_mutex);
  if (aj_tinfo_local->stime == cur_time)
    {
      aj_tinfo_local->is_running = 0;
    }
  MUTEX_UNLOCK (aj_thread_mutex);

#if defined(WINDOWS)
  return;
#else
  return NULL;
#endif
}

static void
start_auto_thread (void)
{
  int i = 0;
  userdata *ud = NULL;

  if ((ud = (userdata *) calloc (1, sizeof (userdata))) == NULL)
    {
      exit (1);
    }
  /* initialize memory for active databases information */
  for (i = 0; i < MAX_INSTALLED_DB; ++i)
    {
      ud->dbvect[i] = 0;
    }

  THREAD_BEGIN (auto_task_tid, automation_start, ud);
}

int
main (int argc, char **argv)
{
  char dbmt_file[PATH_MAX];
  char tmpstrbuf[DBMT_ERROR_MSG_SIZE];
  int pidnum = 0;

  tmpstrbuf[0] = '\0';

  cub_cm_init_env ();
  if (argc >= 2)
    {
      if (strcmp (argv[1], "stop") == 0)
        {
          stop_service ();
          exit (0);
        }
      else if (strcmp (argv[1], "--version") == 0)
        {
          fprintf (stdout, "CUBRID Manager Server ver : %s\n",
                   makestring (BUILD_NUMBER));
          exit (0);
        }
      else if (strcmp (argv[1], "getpid") == 0)
        {
          pidnum = get_processid ();
          if (pidnum > 0)
            {
              fprintf (stdout, "%d\n", pidnum);
            }
          exit (0);
        }
      else if (strcmp (argv[1], PRINT_CMD_START) != 0)
        {
          snprintf (tmpstrbuf, DBMT_ERROR_MSG_SIZE, "CUBRID Manager Server : Invalid command - %s\n", argv[1]);
          ut_record_cubrid_utility_log_stderr (tmpstrbuf);
          print_usage (argv[0]);
          exit (1);
        }
    }

  if ((pidnum = get_processid ()) > 0)
    {
      snprintf (tmpstrbuf, DBMT_ERROR_MSG_SIZE,
                "CUBRID Manager Server : The [pid=%d] process has been running.\n", pidnum);
      ut_record_cubrid_utility_log_stderr (tmpstrbuf);
      return 0;
    }

  ut_daemon_start ();

  init_files ();

#ifndef WINDOWS
  signal (SIGPIPE, SIG_IGN);
#endif

  if (ut_write_pid (conf_get_dbmt_file (FID_CMSERVER_PID, dbmt_file)) < 0)
    {
      snprintf (tmpstrbuf, DBMT_ERROR_MSG_SIZE,
                "CUBRID Manager Server : Fail to store the pid file in (%s).\n", dbmt_file);
      ut_record_cubrid_utility_log_stderr (tmpstrbuf);
      exit (1);
    }

  start_auto_thread ();

  start_service ();

  return 0;
}
