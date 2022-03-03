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
 * cm_config.cpp -
 */

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#if defined(WINDOWS)
#include <process.h>
#include <io.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "cm_porting.h"
#include "cm_config.h"
#include "cm_dep.h"
#include "cm_server_util.h"

#define DEFAULT_MONITOR_INTERVAL 5
#define DEFAULT_THREAD_NUM       8
#define DEFAULT_CMS_PORT         8001

#define DEFAULT_ALLOW_MULTI_CON  0    /* no */
#define DEFAULT_AUTOJOB_TIMEOUT  43200    /* timeout for all autojobs, 12 hours */
#define MIN_AUTOJOB_TIMEOUT      60    /* min timeout for all autojobs, 60 sec */

#define MAX_THREAD_NUM           64
#define MIN_THREAD_NUM           1
/* Reject multi connection with "ALL USER" */

#define NUM_DBMT_FILE            23

#define DEFAULT_CWM_PATH_SHORT            "/share/webmanager"
#define DEFAULT_SSL_CERTIFICATE           "cm_ssl_cert.crt"
#define DEFAULT_SSL_PRIVATEKEY            "cm_ssl_cert.key"

#define DEFAULT_LOG_FILE_COUNT            10
#define DEFAULT_LOG_FILE_SIZE             (4 * 1024 * 1024)

const char *autobackup_conf_entry[AUTOBACKUP_CONF_ENTRY_NUM] =
{
  "dbname", "backupid", "path", "period_type", "period_date", "time",
  "level", "archivedel", "updatestatus", "storeold", "onoff",
  "zip", "check", "mt", "bknum"
};

const char *autobackup_period_type[AUTOBACKUP_PERIOD_TYPE_NUM] =
{
  AUTO_BACKUP_PERIOD_TYPE_MONTHLY, AUTO_BACKUP_PERIOD_TYPE_WEEKLY,
  AUTO_BACKUP_PERIOD_TYPE_DAILY, AUTO_BACKUP_PERIOD_TYPE_HOURLY,
  AUTO_BACKUP_PERIOD_TYPE_SPECIAL
};

const char *autobackup_period_week[AUTOBACKUP_PERIOD_WEEK_NUM] =
{
  WEEK_SUNDAY_L, WEEK_MONDAY_L, WEEK_TUESDAY_L, WEEK_WEDNESDAY_L,
  WEEK_THURSDAY_L, WEEK_FRIDAY_L, WEEK_SATURDAY_L
};

const char *autoaddvol_conf_entry[AUTOADDVOL_CONF_ENTRY_NUM] =
{
  "dbname", "data", "data_warn_outofspace", "data_ext_page",
  "index", "index_warn_outofspace", "index_ext_page"
};

const char *autohistory_conf_entry[AUTOHISTORY_CONF_ENTRY_NUM] =
{
  "onoff",
  "startyear", "startmonth", "startday",
  "starthour", "startminute", "startsecond",
  "endyear", "endmonth", "endday",
  "endhour", "endminute", "endsecond",
  "memory", "cpu"
};

const char *autounicas_conf_entry[AUTOUNICAS_CONF_ENTRY_NUM] =
{
  "bname", "cpumonitor", "busymonitor", "logcpu", "logbusy",
  "cpurestart", "busyrestart", "cpulimit", "busytimelimit"
};

static T_DBMT_FILE_INFO dbmt_file[NUM_DBMT_FILE] =
{
  {FID_DBMT_CONF, DBMT_CONF_DIR, "cm.conf"},
  {FID_DBMT_PASS, DBMT_CONF_DIR, "cm.pass"},
  {FID_DBMT_CUBRID_PASS, DBMT_CONF_DIR, "cmdb.pass"},
  {FID_CONN_LIST, DBMT_LOG_DIR, "conlist"},
  {FID_AUTO_ADDVOLDB_CONF, DBMT_CONF_DIR, "autoaddvoldb.conf"},
  {FID_AUTO_ADDVOLDB_LOG, DBMT_LOG_DIR, "autoaddvoldb.log"},
  {FID_AUTO_BACKUPDB_CONF, DBMT_CONF_DIR, "autobackupdb.conf"},
  {FID_AUTO_HISTORY_CONF, DBMT_CONF_DIR, "autohistory.conf"},
  {FID_AUTO_EXECQUERY_CONF, DBMT_CONF_DIR, "autoexecquery.conf"},
  {FID_PSVR_DBINFO_TEMP, DBMT_LOG_DIR, "cmdbinfo.temp"},
  {FID_LOCK_CONN_LIST, DBMT_TMP_DIR, "conlist.lock"},
  {FID_LOCK_PSVR_DBINFO, DBMT_TMP_DIR, "cmdbinfo.lock"},
  {FID_LOCK_SVR_LOG, DBMT_TMP_DIR, "cmlog.lock"},
  {FID_LOCK_DBMT_PASS, DBMT_TMP_DIR, "cmpass.lock"},
  {FID_DIAG_ACTIVITY_LOG, DBMT_CONF_DIR, "diagactivitylog.conf"},
  {FID_DIAG_STATUS_TEMPLATE, DBMT_CONF_DIR, "diagstatustemplate.conf"},
  {FID_DIAG_ACTIVITY_TEMPLATE, DBMT_CONF_DIR, "diagactivitytemplate.conf"},
  {FID_DIAG_SERVER_PID, DBMT_LOG_DIR, "diag.pid"},
  {FID_CMSERVER_PID, DBMT_PID_DIR, DBMT_CUB_CMS_PID},
  {FID_CMS_LOG, DBMT_LOG_DIR, "cub_manager.log"},
  {FID_CMS_ERROR_LOG, DBMT_LOG_DIR, "cub_manager.err"},
  {FID_AUTO_JOBS_CONF, DBMT_CONF_DIR, "autojobs.conf"},
  {FID_SHARD_CONF, DBMT_CONF_DIR, "shard.conf"},
};

sys_config sco;

static int check_file (char *fname, char *pname);
static int check_path (char *path, char *pname);

void
sys_config_init (void)
{
  memset (&sco, 0, sizeof (sco));
}

int
uReadEnvVariables (char *progname)
{
  char tmpstrbuf[DBMT_ERROR_MSG_SIZE];
  tmpstrbuf[0] = '\0';

#if !defined (DO_NOT_USE_CUBRIDENV)
  sco.szCubrid = getenv ("CUBRID");
  sco.szCubrid_databases = getenv ("CUBRID_DATABASES");
#else
  sco.szCubrid = CUBRID_PREFIXDIR;
  sco.szCubrid_databases = CUBRID_VARDIR;
#endif
  sco.szProgname = strdup (progname);    /* not an env variable */
  if (sco.szCubrid == NULL)
    {
#if !defined (DO_NOT_USE_CUBRIDENV)
      snprintf (tmpstrbuf, DBMT_ERROR_MSG_SIZE,
                "CUBRID Manager Server : Environment variable CUBRID not set. - %s\n",
                sco.szProgname);
#else
      snprintf (tmpstrbuf, DBMT_ERROR_MSG_SIZE,
                "CUBRID Manager Server : CUBRID prefix directory was not set. - %s\n",
                sco.szProgname);
#endif
      ut_record_cubrid_utility_log_stderr (tmpstrbuf);
      return -1;
    }
  if (sco.szCubrid_databases == NULL)
    {
#if !defined (DO_NOT_USE_CUBRIDENV)
      snprintf (tmpstrbuf, DBMT_ERROR_MSG_SIZE,
                "CUBRID Manager Server : Environment variable CUBRID_DATABASES not set. - %s\n",
                sco.szProgname);
#else
      snprintf (tmpstrbuf, DBMT_ERROR_MSG_SIZE,
                "CUBRID Manager Server : CUBRID databases directory was not set. - %s\n",
                sco.szProgname);
#endif
      ut_record_cubrid_utility_log_stderr (tmpstrbuf);
      return -1;
    }

#if !defined (DO_NOT_USE_CUBRIDENV)
  sco.dbmt_tmp_dir =
    (char *) malloc (strlen (sco.szCubrid) + strlen (DBMT_TMP_DIR) + 2);
#else
  sco.dbmt_tmp_dir = (char *) malloc (strlen (CUBRID_TMPDIR) + 1);
#endif
  if (sco.dbmt_tmp_dir == NULL)
    {
      perror ("malloc");
      return -1;
    }
#if !defined (DO_NOT_USE_CUBRIDENV)
#ifdef WINDOWS
  sprintf (sco.dbmt_tmp_dir, "%s\\%s", sco.szCubrid, DBMT_TMP_DIR);
#else
  sprintf (sco.dbmt_tmp_dir, "%s/%s", sco.szCubrid, DBMT_TMP_DIR);
#endif
#else
  sprintf (sco.dbmt_tmp_dir, "%s", CUBRID_TMPDIR);
#endif

  return 1;
}

/* Read cm.conf and fill system configuration structure */
/* It fills the global variable 'sco' */
int
uReadSystemConfig (void)
{
  FILE *conf_file;
  char cbuf[1024];
  char ent_name[128], ent_val[128];
  const char *separator = " \t=";
  char *token;
  int cm_port = 0;
  int str_len = 0;
  char access_log_buf[PATH_MAX];
  char error_log_buf[PATH_MAX];

  conf_file = fopen (conf_get_dbmt_file (FID_DBMT_CONF, cbuf), "rt");
  if (conf_file == NULL)
    {
      return -1;
    }

  sco.iCMS_port = DEFAULT_CMS_PORT;
  sco.iMonitorInterval = DEFAULT_MONITOR_INTERVAL;
  sco.iAllow_AdminMultiCon = DEFAULT_ALLOW_MULTI_CON;
  sco.iSupportWebManager = FALSE;
  sco.iSupportMonStat = FALSE;
  sco.iHttpTimeout = 500;
  sco.iAutoJobTimeout = DEFAULT_AUTOJOB_TIMEOUT;
  sco.iMaxLogFiles = DEFAULT_LOG_FILE_COUNT;
  sco.iMaxLogFileSize = DEFAULT_LOG_FILE_SIZE;
  strcpy (sco.szAutoUpdateURL, "");
  strcpy (sco.szCMSVersion, "");
  strncpy (sco.szTokenActiveTime, "7200", PATH_MAX);
  snprintf (sco.szCWMPath, PATH_MAX, "%s%s", sco.szCubrid,
            DEFAULT_CWM_PATH_SHORT);

  conf_get_dbmt_file (FID_CMS_LOG, access_log_buf);
  conf_get_dbmt_file (FID_CMS_ERROR_LOG, error_log_buf);

  snprintf (sco.szAccessLog, PATH_MAX, "%s", access_log_buf);
  snprintf (sco.szErrorLog, PATH_MAX, "%s", error_log_buf);

  while (fgets (cbuf, sizeof (cbuf), conf_file))
    {
      ut_trim (cbuf);
      if (cbuf[0] == '\0' || cbuf[0] == '#')
        {
          continue;
        }

      /*
      * put the first token into var ent_name,
      * the separator is ' ', '\t', '='
      */
      if ((token = strtok (cbuf, separator)) == NULL)
        {
          continue;
        }
      ut_trim (token);
      strcpy_limit (ent_name, token, sizeof (ent_name));

      /*
      * put the rest of the string into var ent_val.
      */
      if ((token = strtok (NULL, "\0")) == NULL)
        {
          continue;
        }
      if (ut_trim (token) == NULL)
        {
          continue;
        }

      /*
      * if the first charactor is '=',
      * the token should move one more step.
      */
      if (token[0] == '=')
        {
          token++;
        }

      if (ut_trim (token) == NULL)
        {
          continue;
        }
      strcpy_limit (ent_val, token, sizeof (ent_val));

      if (strcasecmp (ent_name, "cm_port") == 0)
        {
          cm_port = atoi (ent_val);
          sco.iCMS_port = cm_port;
        }
      else if (strcasecmp (ent_name, "MonitorInterval") == 0 ||
               strcasecmp (ent_name, "cm_process_monitor_interval") == 0)
        {
          sco.iMonitorInterval = atoi (ent_val);

          /* check value range of system parameters */
          if (sco.iMonitorInterval < DEFAULT_MONITOR_INTERVAL)
            {
              sco.iMonitorInterval = DEFAULT_MONITOR_INTERVAL;
            }

        }
      else if (strcasecmp (ent_name, "Allow_UserMultiCon") == 0 ||
               strcasecmp (ent_name, "allow_user_multi_connection") == 0)
        {
          if (strcasecmp (ent_val, "yes") == 0)
            {
              sco.iAllow_AdminMultiCon = 1;
            }
          else
            {
              sco.iAllow_AdminMultiCon = 0;
            }
        }
      else if (strcasecmp (ent_name, "auto_job_timeout") == 0)
        {
          int timeout = atoi (ent_val);
          if (MIN_AUTOJOB_TIMEOUT <= timeout)
            {
              sco.iAutoJobTimeout = timeout;
            }
          else
            {
              sco.iAutoJobTimeout = DEFAULT_AUTOJOB_TIMEOUT;
            }
        }
      else if (strcasecmp (ent_name, "max_log_filesize") == 0)
        {
            str_len = (int) strlen(ent_val);
          if ((ent_val[str_len - 1] == 'M') || (ent_val[str_len - 1] == 'm'))
            {
              ent_val[str_len - 1] = '\0';
            }
          if (atoi (ent_val) > 0)
            {
              sco.iMaxLogFileSize = (atoi (ent_val) * 1024 * 1024);
            }
        }
      else if (strcasecmp (ent_name, "max_log_files") == 0)
        {
          if (atoi (ent_val) > 0)
            {
              sco.iMaxLogFiles = atoi (ent_val);
            }
        }
      else if (strcasecmp (ent_name, "support_web_manager") == 0)
        {
          if (strcasecmp (ent_val, "yes") == 0)
            {
              sco.iSupportWebManager = TRUE;
            }
          else
            {
              sco.iSupportWebManager = FALSE;
            }
        }
      else if (strcasecmp (ent_name, "web_manager_path") == 0)
        {
          /* The path validation will be checked in uCheckSystemConfig */
          snprintf (sco.szCWMPath, PATH_MAX, "%s", ent_val);
        }

      else if (strcasecmp (ent_name, "support_mon_statistic") == 0)
        {
          if (strcasecmp (ent_val, "yes") == 0)
            {
              sco.iSupportMonStat = TRUE;
            }
          else
            {
              sco.iSupportMonStat = FALSE;
            }
        }
      else if (strcasecmp (ent_name, "http_timeout") == 0 ||
               strcasecmp (ent_name, "HttpTimeout") == 0)
        {
          sco.iHttpTimeout = atoi (ent_val);
        }
      else if (strcasecmp (ent_name, "auto_update_url") == 0 ||
               strcasecmp (ent_name, "AutoUpdateURL") == 0)
        {
          snprintf (sco.szAutoUpdateURL, PATH_MAX, "%s", ent_val);
        }
      else if (strcasecmp (ent_name, "cubrid_server_ver") == 0 ||
               strcasecmp (ent_name, "CubridServerVer") == 0)
        {
          snprintf (sco.szCMSVersion, PATH_MAX, "%s", ent_val);
        }
      else if (strcasecmp (ent_name, "token_active_time") == 0 ||
               strcasecmp (ent_name, "TokenActiveTime") == 0)
        {
          ut_trim (ent_val);
          snprintf (sco.szTokenActiveTime, PATH_MAX, "%s", ent_val);
        }
    }
  fclose (conf_file);

#ifdef HOST_MONITOR_PROC
  sco.hmtab1 = 1;
  sco.hmtab2 = 1;
  sco.hmtab3 = 1;
#ifdef HOST_MONITOR_IO
  sco.hmtab4 = 1;
#else
  sco.hmtab4 = 0;
#endif /* HOST_MONITOR_IO */
#else
  sco.hmtab1 = 0;
  sco.hmtab2 = 0;
  sco.hmtab3 = 0;
  sco.hmtab4 = 0;
#endif /* HOST_MONITOR_PROC */

  return 1;
}

/* Check system configuration */
/* It is to be called after uReadSystemConfig() */
int
uCheckSystemConfig (char *progname)
{
  int retval;
  char filepath[PATH_MAX];
  char tmpstrbuf[DBMT_ERROR_MSG_SIZE];

  tmpstrbuf[0] = '\0';

  if (progname == NULL)
    {
      fprintf (stderr, "progname should not be NULL.\n");
      return -1;
    }

  /* create tmp directory */
  if (access (sco.dbmt_tmp_dir, F_OK) < 0)
    {
      mkdir (sco.dbmt_tmp_dir, 0755);
    }

  /* CUBRID databases.txt file check */
  sprintf (filepath, "%s/%s", sco.szCubrid_databases, CUBRID_DATABASE_TXT);
  if (access (filepath, F_OK) < 0)
    {
      FILE *fp;
      fp = fopen (filepath, "w");
      if (fp)
        {
          fclose (fp);
        }
    }
  retval = check_file (filepath, progname);
  if (retval < 0)
    {
      return -1;
    }

  if (check_file (conf_get_dbmt_file (FID_DBMT_PASS, filepath), progname) < 0)
    {
      return -1;
    }
  if (check_file (conf_get_dbmt_file (FID_DBMT_CUBRID_PASS, filepath), progname) < 0)
    {
      return -1;
    }
  /* cubrid manager only support https connections,
  * Thus private key and certificate must be checked before process starting.
  */
  snprintf (sco.szSSLKey, PATH_MAX, "%s/conf/%s", sco.szCubrid, DEFAULT_SSL_PRIVATEKEY);
  if (check_file (sco.szSSLKey, progname) < 0)
    {
      return -1;
    }
  snprintf (sco.szSSLCertificate, PATH_MAX, "%s/conf/%s", sco.szCubrid, DEFAULT_SSL_CERTIFICATE);
  if (check_file (sco.szSSLCertificate, progname) < 0)
    {
      return -1;
    }

#if !defined (DO_NOT_USE_CUBRIDENV)
  sprintf (filepath, "%s/%s", sco.szCubrid, DBMT_LOG_DIR);
#else
  sprintf (filepath, "%s", DBMT_LOG_DIR);
#endif
  if (check_path (filepath, progname) < 0)
    {
      return -1;
    }
#if !defined (DO_NOT_USE_CUBRIDENV)
  sprintf (filepath, "%s/%s", sco.szCubrid, DBMT_CONF_DIR);
#else
  sprintf (filepath, "%s", DBMT_CONF_DIR);
#endif
  if (check_path (filepath, progname) < 0)
    {
      return -1;
    }
#if !defined (DO_NOT_USE_CUBRIDENV)
  sprintf (filepath, "%s/%s", sco.szCubrid, DBMT_TMP_DIR);
#else
  sprintf (filepath, "%s", DBMT_TMP_DIR);
#endif
  if (check_path (filepath, progname) < 0)
    {
      return -1;
    }

  return 1;
}

char *
conf_get_dbmt_file (T_DBMT_FILE_ID dbmt_fid, char *buf)
{
  int i;

  buf[0] = '\0';
  for (i = 0; i < NUM_DBMT_FILE; i++)
    {
      if (dbmt_fid == dbmt_file[i].fid)
        {
#if !defined (DO_NOT_USE_CUBRIDENV)
          sprintf (buf, "%s/%s/%s", sco.szCubrid, dbmt_file[i].dir_name,
                   dbmt_file[i].file_name);
#else
          sprintf (buf, "%s/%s", dbmt_file[i].dir_name, dbmt_file[i].file_name);
#endif
          break;
        }
    }
  return buf;
}

char *
conf_get_dbmt_file2 (T_DBMT_FILE_ID dbmt_fid, char *buf)
{
  int i;

  buf[0] = '\0';
  for (i = 0; i < NUM_DBMT_FILE; i++)
    {
      if (dbmt_fid == dbmt_file[i].fid)
        {
          strcpy (buf, dbmt_file[i].file_name);
          break;
        }
    }
  return buf;
}

int
auto_conf_delete (T_DBMT_FILE_ID fid, char *dbname)
{
  char conf_file[PATH_MAX], tmpfile[PATH_MAX];
  char conf_dbname[128];
  char strbuf[MAX_JOB_CONFIG_FILE_LINE_LENGTH];
  FILE *infp, *outfp;

  conf_get_dbmt_file (fid, conf_file);
  if ((infp = fopen (conf_file, "r")) == NULL)
    {
      return -1;
    }
  make_temp_filepath (tmpfile, sco.dbmt_tmp_dir, "DBMT_task_ac_del", 208, PATH_MAX);
  if ((outfp = fopen (tmpfile, "w")) == NULL)
    {
      fclose (infp);
      return -1;
    }

  while (fgets (strbuf, sizeof (strbuf), infp))
    {
      if (sscanf (strbuf, "%127s", conf_dbname) < 1)
        {
          continue;
        }
      if (strcmp (dbname, conf_dbname) != 0)
        {
          fputs (strbuf, outfp);
        }
    }
  fclose (infp);
  fclose (outfp);

  if (move_file (tmpfile, conf_file) < 0)
    {
      return -1;
    }
  return 0;
}

int
auto_conf_rename (T_DBMT_FILE_ID fid, char *src_dbname, char *dest_dbname)
{
  char conf_file[PATH_MAX], tmpfile[PATH_MAX];
  char conf_dbname[128];
  char strbuf[1024], *p;
  FILE *infp, *outfp;

  conf_get_dbmt_file (fid, conf_file);
  if ((infp = fopen (conf_file, "r")) == NULL)
    {
      return -1;
    }
  make_temp_filepath (tmpfile, sco.dbmt_tmp_dir, "DBMT_task_ac_ren", 209, PATH_MAX);
  if ((outfp = fopen (tmpfile, "w")) == NULL)
    {
      fclose (infp);
      return -1;
    }

  while (fgets (strbuf, sizeof (strbuf), infp))
    {
      if (sscanf (strbuf, "%127s", conf_dbname) < 1)
        {
          continue;
        }
      if (strcmp (conf_dbname, src_dbname) == 0)
        {
          p = strstr (strbuf, src_dbname);
          p += strlen (src_dbname);
          fprintf (outfp, "%s%s", dest_dbname, p);
        }
      else
        {
          fputs (strbuf, outfp);
        }
    }
  fclose (infp);
  fclose (outfp);

  if (move_file (tmpfile, conf_file) < 0)
    {
      return -1;
    }
  return 0;
}

int
auto_conf_execquery_update_dbuser (const char *src_db_uid,
                                   const char *dest_db_uid,
                                   const char *dest_db_passwd)
{
  char conf_file_path[PATH_MAX], tmpfile_path[PATH_MAX];
  char dbname[64], query_id[64], db_uid[64], dbmt_uid[64];
  char *strbuf, *p;
  int buf_len, get_len;
  FILE *conf_file, *tmpfile;

  conf_get_dbmt_file (FID_AUTO_EXECQUERY_CONF, conf_file_path);
  if ((conf_file = fopen (conf_file_path, "r")) == NULL)
    {
      return -1;
    }
  make_temp_filepath (tmpfile_path, sco.dbmt_tmp_dir, "DBMT_task_ac_swit", 210, PATH_MAX);
  if ((tmpfile = fopen (tmpfile_path, "w")) == NULL)
    {
      fclose (conf_file);
      return -1;
    }

  strbuf = NULL;
  buf_len = get_len = 0;
  while ((get_len = ut_getline (&strbuf, &buf_len, conf_file)) != -1)
    {
      if (sscanf
          (strbuf, "%64s %64s %64s %*s %64s", dbname, query_id, db_uid, dbmt_uid) < 4)
        {
          continue;
        }

      if (uStringEqual (db_uid, src_db_uid))
        {
          p = strstr (strbuf, dbmt_uid);
          if (p)
            {
              p = strchr (p, ' ');
            }
          fprintf (tmpfile, "%s %s %s %s %s%s", dbname, query_id, dest_db_uid,
                   dest_db_passwd, dbmt_uid, p);
        }
      else
        {
          fputs (strbuf, tmpfile);
        }
      FREE_MEM (strbuf);
      buf_len = 0;
    }

  if (strbuf != NULL)
    {
      FREE_MEM (strbuf);
    }

  fclose (conf_file);
  fclose (tmpfile);

  if (move_file (tmpfile_path, conf_file_path) < 0)
    {
      return -1;
    }

  return 0;
}

int
auto_conf_execquery_delete_by_dbuser (const char *target_db_uid)
{
  char conf_file_path[PATH_MAX], tmpfile_path[PATH_MAX];
  char db_uid[64];
  char *strbuf;
  int buf_len, get_len;
  FILE *conf_file, *tmpfile;

  conf_get_dbmt_file (FID_AUTO_EXECQUERY_CONF, conf_file_path);
  if ((conf_file = fopen (conf_file_path, "r")) == NULL)
    {
      return -1;
    }
  make_temp_filepath (tmpfile_path, sco.dbmt_tmp_dir, "DBMT_task_ac_del_user", TS_DELETEDBMTUSER, PATH_MAX);
  if ((tmpfile = fopen (tmpfile_path, "w")) == NULL)
    {
      fclose (conf_file);
      return -1;
    }

  strbuf = NULL;
  buf_len = get_len = 0;
  while ((get_len = ut_getline (&strbuf, &buf_len, conf_file)) != -1)
    {
      if (sscanf (strbuf, "%*s %*s %64s", db_uid) < 1)
        {
          continue;
        }

      if (uStringEqual (db_uid, target_db_uid))
        {
          continue;
        }
      else
        {
          fputs (strbuf, tmpfile);
        }
      FREE_MEM (strbuf);
      buf_len = 0;
    }

  if (strbuf != NULL)
    {
      FREE_MEM (strbuf);
    }

  fclose (conf_file);
  fclose (tmpfile);

  if (move_file (tmpfile_path, conf_file_path) < 0)
    {
      return -1;
    }

  return 0;
}

static int
check_file (char *fname, char *pname)
{
  char tmpstrbuf[DBMT_ERROR_MSG_SIZE];

  tmpstrbuf[0] = '\0';

  if (access (fname, F_OK | R_OK | W_OK) < 0)
    {
      snprintf (tmpstrbuf, DBMT_ERROR_MSG_SIZE,
                "CUBRID Manager Server : %s - %s. - %s\n", fname, strerror (errno), pname);
      ut_record_cubrid_utility_log_stderr (tmpstrbuf);
      return -1;
    }
  return 1;
}

static int
check_path (char *dirname, char *pname)
{
  /* check if directory exists */
  char tmpstrbuf[DBMT_ERROR_MSG_SIZE];

  tmpstrbuf[0] = '\0';

  if (access (dirname, F_OK | W_OK | R_OK | X_OK) < 0)
    {
      snprintf (tmpstrbuf, DBMT_ERROR_MSG_SIZE,
                "CUBRID Manager Server :  %s - %s. - %s\n", dirname, strerror (errno), pname);
      ut_record_cubrid_utility_log_stderr (tmpstrbuf);
      return -1;
    }
  return 1;
}
