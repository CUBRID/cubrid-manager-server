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
 * cm_autojob.cpp -
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>

#if defined(WINDOWS)
#include <io.h>
#include <direct.h>
#include <process.h>
#else
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#endif

#include "cm_porting.h"
#include "cm_server_util.h"
#include "cm_autojob.h"
#include "cm_dep.h"
#include "cm_server_stat.h"
#include "cm_config.h"
#include "cm_cmd_exec.h"
#include "cm_text_encryption.h"
#include "cm_stat.h"

#ifdef _DEBUG_
#include "deb.h"
#include <assert.h>
#endif

#define MIN_AUTOBACKUPDB_DELAY         600
#define MAX_AUTOADD_FREE_SPACE_RATE    0.5


typedef struct backup_period_details_t
{
  int date;
  struct backup_period_details_t *next;
} backup_period_details;

typedef struct autobackupdb_node_t
{
  char *dbname;
  char *backup_id;
  char *path;
  int period_type;
  //int period_date;
  backup_period_details *period_date;
  int time;
  int level;
  int archivedel;
  int updatestatus;
  int storeold;
  int onoff;
  int zip;
  int check;
  int mt;
  int bk_num;
  time_t lbt;
  struct autobackupdb_node_t *next;
  int is_interval;        // 0 for specific time, 1 for interval
} autobackupdb_node;

typedef struct unicasm_node_t
{
  char *bname;
  short cpumonitor;
  short busymonitor;
  short logcpu;
  short logbusy;
  short cpurestart;
  short busyrestart;
  short cpulimit;
  int busylimit;
  time_t lrt;
  struct unicasm_node_t *next;
} unicasm_node;

/* This struct is for auto addvolume */

typedef enum
{
  AEQT_ONE,
  AEQT_DAY,
  AEQT_WEEK,
  AEQT_MONTH
} T_EXECQUERY_PERIOD_TYPE;

#define DETAIL_LEN 32

typedef struct query_period_details_t
{
  char detail[DETAIL_LEN];
  struct query_period_details_t *next;

} query_period_details;

typedef struct autoexecquery_t
{
  char dbname[64];
  char dbmt_uid[64];
  char query_id[64];
  char db_uid[64];
  char db_passwd[PASSWD_ENC_LENGTH];
  T_EXECQUERY_PERIOD_TYPE period;
  query_period_details *detail1;
  char detail2[16];
  char query_string[MAX_AUTOQUERY_SCRIPT_SIZE];
  int db_mode;
  struct autoexecquery_t *next;
} autoexecquery_node;

#ifdef HOST_MONITOR_PROC
/* This struct is for auto history logging */
typedef struct autohistory_t
{
  time_t start_time;
  time_t end_time;
  float memory_limit;
  float cpu_limit;
  char **dbname;
  int dbcount;
  FILE *hfile;
  void *mondata;
} autohistory_node;
#endif

typedef enum
{
  ABPT_MONTHLY,
  ABPT_WEEKLY,
  ABPT_DAILY,
  ABPT_HOURLY,
  ABPT_SPECIAL
} T_AUTOBACKUP_PERIOD_TYPE;

static void aj_load_execquery_conf (ajob *p_aj);
static void aj_execquery_handler (void *hd, time_t prev_check_time,
                                  time_t cur_time);
static void aj_execquery_get_exec_time (autoexecquery_node *c,
                                        query_period_details *d,
                                        struct tm *exec_tm,
                                        time_t prev_check_time);

static void aj_execquery (autoexecquery_node *c);
static void _aj_autoexecquery_error_log (autoexecquery_node *node,
    int err_code, const char *errmsg);
static void aj_load_autobackupdb_conf (ajob *ajp);
static void aj_load_autoaddvoldb_config (ajob *ajp);
static void aj_load_autohistory_conf (ajob *ajp);

static void aj_autobackupdb_handler (void *ajp, time_t prev_check_time,
                                     time_t cur_time);
static void aj_autoaddvoldb_handler (void *hd, time_t prev_check_time,
                                     time_t cur_time);
static void aj_autohistory_handler (void *ajp, time_t prev_check_time,
                                    time_t cur_time);

static void aj_backupdb (autobackupdb_node *n);
static void _aj_autobackupdb_error_log (autobackupdb_node *n, char *errmsg);

void
aj_initialize (ajob *ajlist, void *ud)
{
  struct stat statbuf;

  sprintf (ajlist[0].name, "autoaddvoldb");
  conf_get_dbmt_file (FID_AUTO_ADDVOLDB_CONF, ajlist[0].config_file);
  stat (ajlist[0].config_file, &statbuf);
  ajlist[0].last_modi = statbuf.st_mtime;
  ajlist[0].is_on = 0;        /* initially off */
  ajlist[0].ajob_handler = aj_autoaddvoldb_handler;
  ajlist[0].ajob_loader = aj_load_autoaddvoldb_config;
  ajlist[0].hd = NULL;
  ajlist[0].mondata = ud;

  sprintf (ajlist[1].name, "autohistory");
  conf_get_dbmt_file (FID_AUTO_HISTORY_CONF, ajlist[1].config_file);
  stat (ajlist[1].config_file, &statbuf);
  ajlist[1].last_modi = statbuf.st_mtime;
  ajlist[1].is_on = 0;
  ajlist[1].ajob_handler = aj_autohistory_handler;
  ajlist[1].ajob_loader = aj_load_autohistory_conf;
  ajlist[1].hd = NULL;
  ajlist[1].mondata = ud;

  sprintf (ajlist[2].name, "autobackupdb");
  conf_get_dbmt_file (FID_AUTO_BACKUPDB_CONF, ajlist[2].config_file);
  stat (ajlist[2].config_file, &statbuf);
  ajlist[2].last_modi = statbuf.st_mtime;
  ajlist[2].is_on = 0;
  ajlist[2].ajob_handler = aj_autobackupdb_handler;
  ajlist[2].ajob_loader = aj_load_autobackupdb_conf;
  ajlist[2].hd = NULL;
  ajlist[2].mondata = ud;

  sprintf (ajlist[3].name, "autoexecquery");
  conf_get_dbmt_file (FID_AUTO_EXECQUERY_CONF, ajlist[3].config_file);
  stat (ajlist[3].config_file, &statbuf);
  ajlist[3].last_modi = statbuf.st_mtime;
  ajlist[3].is_on = 0;
  ajlist[3].ajob_handler = aj_execquery_handler;
  ajlist[3].ajob_loader = aj_load_execquery_conf;
  ajlist[3].hd = NULL;
  ajlist[3].mondata = ud;
}

/* This function calculates the free space fraction of given type */
double
ajFreeSpace (GeneralSpacedbResult *cmd_res, const char *type)
{
  double total_page, free_page;

  total_page = free_page = 0.0;
  cmd_res->get_total_and_free_page (type, free_page, total_page);
  if (total_page > 0.0)
    {
      return (free_page / total_page);
    }

  return 1.0;
}

/* This function adds volume and write to file for fserver */
void
aj_add_volume (char *dbname, const char *type, int increase,
               int pagesize)
{
  char dbloca[512];
  char strbuf[1024];
  char volname[512] = { '\0' };
  FILE *outfile;
  time_t mytime;
  int retval;
  char log_file_name[512];
  char cmd_name[CUBRID_CMD_NAME_LEN];
  char inc_str[128];
  const char *argv[16];
  int argc = 0;
  GeneralSpacedbResult *all_volumes;
  char *pos = NULL;
  char tmp_dbname[DB_NAME_LEN + MAXHOSTNAMELEN];

  tmp_dbname[0] = '\0';
  pos = strchr (dbname, '@');
  if (pos != NULL)
    {
      strncpy (tmp_dbname, dbname, pos - dbname);
      tmp_dbname[pos - dbname] = '\0';
    }
  else
    {
      strncpy (tmp_dbname, dbname, strlen (dbname) + 1);
    }

  if (uRetrieveDBDirectory (tmp_dbname, dbloca) != ERR_NO_ERROR)
    {
      return;
    }

  if (access (dbloca, W_OK | X_OK | R_OK) < 0)
    {
      return;
    }

#if defined(WINDOWS)
  nt_style_path (dbloca, dbloca);
#endif

  cubrid_cmd_name (cmd_name);
  argv[argc++] = cmd_name;
  argv[argc++] = UTIL_OPTION_ADDVOLDB;
  argv[argc++] = "--" ADDVOL_FILE_PATH_L;
  argv[argc++] = dbloca;
  argv[argc++] = "--" ADDVOL_PURPOSE_L;
  argv[argc++] = type;
  argv[argc++] = "--" ADDVOL_DB_VOLUMN_SIZE_L;
  sprintf (inc_str, "%lldB", (long long) pagesize * increase);
  argv[argc++] = inc_str;
  argv[argc++] = dbname;
  argv[argc++] = NULL;
  retval = run_child (argv, 1, NULL, NULL, NULL, NULL);    /* addvoldb  */

  mytime = time (NULL);
  conf_get_dbmt_file (FID_AUTO_ADDVOLDB_LOG, log_file_name);
  if ((outfile = fopen (log_file_name, "a")) != NULL)
    {
      fprintf (outfile, "%s ", dbname);
      fprintf (outfile, "%s ", type);
      fprintf (outfile, "%d ", increase);
      time_to_str (mytime, "%d-%d-%d,%d:%d:%d", strbuf,
                   TIME_STR_FMT_DATE_TIME);
      fprintf (outfile, "%s ", strbuf);
      fprintf (outfile, "start\n");
      fclose (outfile);
    }

  mytime = 0;

  all_volumes = cmd_spacedb (dbname, CUBRID_MODE_CS);
  if (all_volumes == NULL)
    {
      return;
    }

  mytime = all_volumes->get_my_time (dbloca);
  mytime = time (&mytime);
  if ((outfile = fopen (log_file_name, "a")) != NULL)
    {
      fprintf (outfile, "%s ", dbname);
      if (retval == 0)
        {
          fprintf (outfile, "%s ", volname);
        }
      else
        {
          fprintf (outfile, "none ");
        }
      fprintf (outfile, "%s ", type);
      fprintf (outfile, "%d ", increase);
      time_to_str (mytime, "%d-%d-%d,%d:%d:%d", strbuf,
                   TIME_STR_FMT_DATE_TIME);
      fprintf (outfile, "%s ", strbuf);
      if (retval == 0)
        {
          fprintf (outfile, "success\n");
        }
      else
        {
          fprintf (outfile, "failure\n");
        }
      fclose (outfile);
    }
}

static void
aj_autohistory_handler (void *ajp, time_t prev_check_time, time_t cur_time)
{
#ifdef HOST_MONITOR_PROC
  time_t mytime, current_time;
  float current_cpu, current_mem;
  char strbuf[1024];
  autohistory_node *hsp;
  userdata *mondata;
  char timestr[64];

  hsp = (autohistory_node *) ajp;
  mondata = (userdata *) (hsp->mondata);

  current_time = time (&current_time);
  if ((current_time < hsp->start_time) || (current_time > hsp->end_time))
    {
      if (hsp->hfile != NULL)
        {
          fclose (hsp->hfile);
        }
      hsp->hfile = NULL;
      return;
    }

  /* auto histoy feature */
  current_cpu = (float) (1000 - mondata->ssbuf.cpu_states[0]);
  current_mem =
    (float) (mondata->ssbuf.memory_stats[1]) /
    (float) (mondata->ssbuf.memory_stats[0]) * 100.0;

  if ((current_cpu > hsp->cpu_limit) || (current_mem > hsp->memory_limit))
    {
      mytime = time (&mytime);

      if (hsp->hfile == NULL)
        {
          time_to_str (mytime, "%04d%02d%02d.%02d%02d%02d", timestr,
                       TIME_STR_FMT_DATE_TIME);
#if !defined (DO_NOT_USE_CUBRIDENV)
          sprintf (strbuf, "%s/logs/_dbmt_history.%s", sco.szCubrid, timestr);
#else
          sprintf (strbuf, "%s/_dbmt_history.%s", CUBRID_LOGDIR, timestr);
#endif
          hsp->hfile = fopen (strbuf, "w");
        }
      /* record system information */
      if (hsp->hfile != NULL)
        {
          time_to_str (mytime, "[%04d/%02d/%02d-%02d:%02d:%02d]", timestr,
                       TIME_STR_FMT_DATE_TIME);
          fprintf (hsp->hfile, "%s", timestr);
          fprintf (hsp->hfile, "load average 1min:%d 5min:%d 15min:%d\n",
                   mondata->ssbuf.load_avg[0],
                   mondata->ssbuf.load_avg[1], mondata->ssbuf.load_avg[2]);
          fprintf (hsp->hfile,
                   "cpu time idle:%d user:%d kernel%d iowait:%d swap:%d\n",
                   mondata->ssbuf.cpu_states[0],
                   mondata->ssbuf.cpu_states[1],
                   mondata->ssbuf.cpu_states[2],
                   mondata->ssbuf.cpu_states[3],
                   mondata->ssbuf.cpu_states[4]);
          fprintf (hsp->hfile,
                   "memory real:%dK active:%dK free:%dK swap:%dK swapfree:%dK\n",
                   mondata->ssbuf.memory_stats[0],
                   mondata->ssbuf.memory_stats[1],
                   mondata->ssbuf.memory_stats[2],
                   mondata->ssbuf.memory_stats[3],
                   mondata->ssbuf.memory_stats[4]);
          fflush (hsp->hfile);
        }
      /* record db information */

      if (hsp->hfile != NULL)
        {
          FILE *infile;
          int i;
          infile =
            fopen (conf_get_dbmt_file (FID_AUTO_HISTORY_CONF, strbuf), "r");
          if (infile != NULL)
            {
              while (fgets (strbuf, sizeof (strbuf), infile))
                {
                  ut_trim (strbuf);
                  for (i = 0; i < MAX_INSTALLED_DB; ++i)
                    {
                      if ((mondata->dbvect[i] == 1) &&
                          (uStringEqual (strbuf, mondata->dbbuf[i].db_name)))
                        {
                          fprintf (hsp->hfile, "database name:%s ",
                                   mondata->dbbuf[i].db_name);
                          fprintf (hsp->hfile, "pid:%d ",
                                   mondata->dbbuf[i].db_pid);
                          fprintf (hsp->hfile, "size:%ld ",
                                   mondata->dbbuf[i].db_size);
                          fprintf (hsp->hfile, "status:%c ",
                                   mondata->dbbuf[i].proc_stat[0]);
                          mytime = mondata->dbbuf[i].db_start_time;
                          time_to_str (mytime,
                                       "%04d/%02d/%02d-%02d:%02d:%02d",
                                       timestr, TIME_STR_FMT_DATE_TIME);
                          fprintf (hsp->hfile, "start_time:%s ", timestr);
                          fprintf (hsp->hfile, "cpu_usage:%f%% ",
                                   mondata->dbbuf[i].db_cpu_usage);
                          fprintf (hsp->hfile, "mem_usage:%f%%\n\n",
                                   mondata->dbbuf[i].db_mem_usage);
                          fflush (hsp->hfile);
                        }
                    }
                }
              fclose (infile);
            }
          fclose (hsp->hfile);
        }
    }
#endif
}

static void
aj_autoaddvoldb_handler (void *hd, time_t prev_check_time, time_t cur_time)
{
  char dbname_at_hostname[MAXHOSTNAMELEN + DB_NAME_LEN];
  autoaddvoldb_node *curr;
  GeneralSpacedbResult *spacedb_res;
  T_SERVER_STATUS_RESULT *server_status_res;
  int db_mode = 0;

  server_status_res = cmd_server_status ();
  if (server_status_res == NULL)
    {
      return;
    }

  for (curr = (autoaddvoldb_node *) hd; curr != NULL; curr = curr->next)
    {
      if (curr->dbname == NULL)
        {
          continue;
        }

      if ((db_mode =
             uIsDatabaseActive2 (server_status_res, curr->dbname)) == 0)
        {
          continue;
        }

      /* if the HA mode is on, the db_mode equals 2. */
      if (db_mode == HA_MODE)
        {
          append_host_to_dbname (dbname_at_hostname, curr->dbname,
                                 sizeof (dbname_at_hostname));
          spacedb_res = cmd_spacedb (dbname_at_hostname, CUBRID_MODE_CS);
        }
      else
        {
          spacedb_res = cmd_spacedb (curr->dbname, CUBRID_MODE_CS);
        }

      if (spacedb_res == NULL)
        {
          continue;
        }

      spacedb_res->auto_add_volume (curr, db_mode, dbname_at_hostname);
      delete spacedb_res;
    }
  cmd_servstat_result_free (server_status_res);
}

static void
aj_load_autoaddvoldb_config (ajob *ajp)
{
  FILE *infile = NULL;
  char strbuf[1024];
  char *conf_item[AUTOADDVOL_CONF_ENTRY_NUM];
  autoaddvoldb_node *next, *curr;

  /* turn off autoaddvoldb feature */
  ajp->is_on = 0;

  /* free existing structure */
  curr = (autoaddvoldb_node *) (ajp->hd);
  while (curr)
    {
      /* clear the linked list */
      next = curr->next;
      FREE_MEM (curr);
      curr = next;
    }
  ajp->hd = curr = NULL;

  infile = fopen (ajp->config_file, "r");
  if (infile == NULL)
    {
      return;
    }

  while (fgets (strbuf, sizeof (strbuf), infile))
    {
      ut_trim (strbuf);
      if (strbuf[0] == '#' || strbuf[0] == '\0')
        {
          continue;
        }

      if (string_tokenize (strbuf, conf_item, AUTOADDVOL_CONF_ENTRY_NUM) < 0)
        {
          continue;
        }

      if (curr == NULL)
        {
          curr = (autoaddvoldb_node *) malloc (sizeof (autoaddvoldb_node));
          ajp->hd = curr;
        }
      else
        {
          curr->next =
            (autoaddvoldb_node *) malloc (sizeof (autoaddvoldb_node));
          curr = curr->next;
        }
      if (curr == NULL)
        {
          break;
        }

      memset (curr, 0, sizeof (autoaddvoldb_node));
      strcpy (curr->dbname, conf_item[0]);

      if (strcmp (conf_item[1], "ON") == 0)
        {
          curr->data_vol = 1;
          ajp->is_on = 1;
        }

      curr->data_warn_outofspace = atof (conf_item[2]);
      if (curr->data_warn_outofspace > MAX_AUTOADD_FREE_SPACE_RATE)
        {
          curr->data_warn_outofspace = MAX_AUTOADD_FREE_SPACE_RATE;
        }

      curr->data_ext_page = atoi (conf_item[3]);

      if (strcmp (conf_item[4], "ON") == 0)
        {
          curr->index_vol = 1;
          ajp->is_on = 1;
        }

      curr->index_warn_outofspace = atof (conf_item[5]);
      if (curr->index_warn_outofspace > MAX_AUTOADD_FREE_SPACE_RATE)
        {
          curr->index_warn_outofspace = MAX_AUTOADD_FREE_SPACE_RATE;
        }

      curr->index_ext_page = atoi (conf_item[6]);
      curr->next = NULL;
    }
  fclose (infile);
}

/* parameter ud : autojob structure for autohistory */
/* parameter ud2 : data from collect_start() */
static void
aj_load_autohistory_conf (ajob *ajp)
{
#ifdef HOST_MONITOR_PROC
  int i;
  FILE *infile;
  struct tm timeptr;
  autohistory_node *ahist;
  char strbuf[1024];
  char *conf_item[AUTOHISTORY_CONF_ENTRY_NUM];

  ajp->is_on = 0;

  ahist = (autohistory_node *) (ajp->hd);
  /* free existing structure */
  if (ahist)
    {
      for (i = 0; i < ahist->dbcount; ++i)
        {
          FREE_MEM (ahist->dbname[i]);
        }
      FREE_MEM (ahist->dbname);
      FREE_MEM (ahist);
    }

  /* create new struct and initialize */
  ajp->hd = (void *) malloc (sizeof (autohistory_node));
  ahist = (autohistory_node *) (ajp->hd);
  ahist->memory_limit = 100.0;
  ahist->cpu_limit = 100.0;
  ahist->dbname = NULL;
  ahist->dbcount = 0;
  ahist->hfile = NULL;
  ahist->mondata = ajp->mondata;

  if ((infile = fopen (ajp->config_file, "r")) == NULL)
    {
      return;
    }

  memset (strbuf, 0, sizeof (strbuf));
  while (fgets (strbuf, sizeof (strbuf), infile))
    {
      ut_trim (strbuf);
      if (strbuf[0] == '#' || strbuf[0] == '\0')
        {
          memset (strbuf, 0, sizeof (strbuf));
          continue;
        }
      break;
    }
  if (string_tokenize (strbuf, conf_item, AUTOHISTORY_CONF_ENTRY_NUM) < 0)
    {
      fclose (infile);
      return;
    }

  if (strcmp (conf_item[0], "ON") == 0)
    {
      ajp->is_on = 1;
    }
  else
    {
      ajp->is_on = 0;
    }

  timeptr.tm_year = atoi (conf_item[1]) - 1900;
  timeptr.tm_mon = atoi (conf_item[2]) - 1;
  timeptr.tm_mday = atoi (conf_item[3]);
  timeptr.tm_hour = atoi (conf_item[4]);
  timeptr.tm_min = atoi (conf_item[5]);
  timeptr.tm_sec = atoi (conf_item[6]);
  ahist->start_time = mktime (&timeptr);

  timeptr.tm_year = atoi (conf_item[7]) - 1900;
  timeptr.tm_mon = atoi (conf_item[8]) - 1;
  timeptr.tm_mday = atoi (conf_item[9]);
  timeptr.tm_hour = atoi (conf_item[10]);
  timeptr.tm_min = atoi (conf_item[11]);
  timeptr.tm_sec = atoi (conf_item[12]);
  ahist->end_time = mktime (&timeptr);

  ahist->memory_limit = atof (conf_item[13]);
  ahist->cpu_limit = atof (conf_item[14]);

  while (fgets (strbuf, sizeof (strbuf), infile))
    {
      ut_trim (strbuf);
      ahist->dbcount++;
      ahist->dbname =
        REALLOC (ahist->dbname, sizeof (char *) * (ahist->dbcount));
      if (ahist->dbname == NULL)
        {
          break;
        }
      ahist->dbname[ahist->dbcount - 1] = strdup (strbuf);
    }

  fclose (infile);
#endif
}

static void
set_query_period_details (query_period_details **details, char *conf_item)
{
  char delim[] = " ,";
  char *token = NULL;
  query_period_details *head = NULL;

  token = strtok (conf_item, delim);
  while (token != NULL)
    {
      *details = (query_period_details *) malloc (sizeof (query_period_details));
      strncpy ((*details)->detail, token, DETAIL_LEN);
      (*details)->next = head;
      head = *details;
      token = strtok (NULL, delim);
    }
}

static void
set_backup_period_details (backup_period_details **details,
                           int period_type, char *conf_item)
{
  char delim[] = " ,";
  char *token;
  backup_period_details *head = NULL;

  token = strtok (conf_item, delim);
  while (token != NULL)
    {
      *details =
        (backup_period_details *) malloc (sizeof (backup_period_details));

      switch (period_type)
        {
        case ABPT_MONTHLY:
        case ABPT_HOURLY:
          (*details)->date = atoi (token);
          break;

        case ABPT_WEEKLY:
          if (!strcmp (token, WEEK_SUNDAY_L))
            {
              (*details)->date = 0;
            }
          else if (!strcmp (token, WEEK_MONDAY_L))
            {
              (*details)->date = 1;
            }
          else if (!strcmp (token, WEEK_TUESDAY_L))
            {
              (*details)->date = 2;
            }
          else if (!strcmp (token, WEEK_WEDNESDAY_L))
            {
              (*details)->date = 3;
            }
          else if (!strcmp (token, WEEK_THURSDAY_L))
            {
              (*details)->date = 4;
            }
          else if (!strcmp (token, WEEK_FRIDAY_L))
            {
              (*details)->date = 5;
            }
          else if (!strcmp (token, WEEK_SATURDAY_L))
            {
              (*details)->date = 6;
            }
          break;

        case ABPT_DAILY:
          (*details)->date = -1;
          break;

        case ABPT_SPECIAL:
          (*details)->date = atoi (token) * 10000;
          (*details)->date += atoi (token + 5) * 100;
          (*details)->date += atoi (token + 8);
          break;

        default:
          break;
        }

      (*details)->next = head;
      head = *details;
      token = strtok (NULL, delim);
    }
}

static void
aj_load_autobackupdb_conf (ajob *p_aj)
{
  char buf[1024];
  FILE *infile = NULL;
  autobackupdb_node *c;
  char *conf_item[AUTOBACKUP_CONF_ENTRY_NUM];
  int is_old_version_entry;

  p_aj->is_on = 0;

  c = (autobackupdb_node *) (p_aj->hd);
  while (c != NULL)
    {
      autobackupdb_node *t;
      backup_period_details *p;

      while (c->period_date != NULL)
        {
          p = c->period_date;
          c->period_date = c->period_date->next;
          FREE_MEM (p);
        }

      t = c;
      FREE_MEM (t->dbname);
      FREE_MEM (t->backup_id);
      FREE_MEM (t->path);
      c = c->next;
      FREE_MEM (t);
    }
  p_aj->hd = c = NULL;

  if ((infile = fopen (p_aj->config_file, "r")) == NULL)
    {
      return;
    }

  while (fgets (buf, sizeof (buf), infile))
    {
      is_old_version_entry = 0;
      ut_trim (buf);
      if (buf[0] == '#' || buf[0] == '\0')
        {
          continue;
        }

      if (string_tokenize (buf, conf_item, AUTOBACKUP_CONF_ENTRY_NUM) < 0)
        {
          if (string_tokenize (buf, conf_item, AUTOBACKUP_CONF_ENTRY_NUM - 3) < 0)
            {
              continue;
            }
          else
            {
              is_old_version_entry = 1;
            }
        }

      if (c == NULL)
        {
          c = (autobackupdb_node *) malloc (sizeof (autobackupdb_node));
          p_aj->hd = c;
        }
      else
        {
          c->next = (autobackupdb_node *) malloc (sizeof (autobackupdb_node));
          c = c->next;
        }
      if (c == NULL)
        {
          break;
        }

      c->lbt = -1;
      c->dbname = strdup (conf_item[0]);
      c->backup_id = strdup (conf_item[1]);
      c->path = strdup (conf_item[2]);

      if (!strcmp (conf_item[3], "Monthly"))
        {
          c->period_type = ABPT_MONTHLY;
        }
      else if (!strcmp (conf_item[3], "Weekly"))
        {
          c->period_type = ABPT_WEEKLY;
        }
      else if (!strcmp (conf_item[3], "Daily"))
        {
          c->period_type = ABPT_DAILY;
        }
      else if (!strcmp (conf_item[3], "Hourly"))
        {
          c->period_type = ABPT_HOURLY;
        }
      else if (!strcmp (conf_item[3], "Special"))
        {
          c->period_type = ABPT_SPECIAL;
        }
      else
        {
          if (c != NULL)
            {
              FREE_MEM (c->dbname);
              FREE_MEM (c->backup_id);
              FREE_MEM (c->path);
              FREE_MEM (c);
            }
          continue;
        }

      set_backup_period_details (& (c->period_date), c->period_type, conf_item[4]);

      if ('i' == conf_item[5][0])    // interval time is set
        {
          c->is_interval = 1;
          c->time = atoi (conf_item[5] + 1);
        }
      else            // sepcific time is set
        {
          c->time = atoi (conf_item[5]);
          c->is_interval = 0;
        }
      c->level = atoi (conf_item[6]);
      c->archivedel = !strcmp (conf_item[7], "ON") ? 1 : 0;
      c->updatestatus = !strcmp (conf_item[8], "ON") ? 1 : 0;
      c->storeold = !strcmp (conf_item[9], "ON") ? 1 : 0;
      c->onoff = !strcmp (conf_item[10], "ON") ? 1 : 0;

      if (is_old_version_entry)
        {
          c->zip = 0;
          c->check = 0;
          c->mt = 0;
          c->bk_num = 1;
        }
      else
        {
          c->zip = !strcmp (conf_item[11], "y") ? 1 : 0;
          c->check = !strcmp (conf_item[12], "y") ? 1 : 0;
          c->mt = atoi (conf_item[13]);
          c->bk_num = conf_item[14] ? atoi (conf_item[14]) : 1;
        }
      c->next = NULL;
    }                /* end of while */
  fclose (infile);
  p_aj->is_on = 1;
}

static void
aj_load_execquery_conf (ajob *p_aj)
{
  FILE *infile = NULL;
  char *conf_item[AUTOEXECQUERY_CONF_ENTRY_NUM];
  char buf[MAX_JOB_CONFIG_FILE_LINE_LENGTH];
  autoexecquery_node *c;

  p_aj->is_on = 0;

  /* NODE reset */
  c = (autoexecquery_node *) (p_aj->hd);
  while (c != NULL)
    {
      autoexecquery_node *t;
      query_period_details *p;

      while (c->detail1 != NULL)
        {
          p = c->detail1;
          c->detail1 = c->detail1->next;
          FREE_MEM (p);
        }

      t = c;
      c = c->next;
      FREE_MEM (t);
    }

  p_aj->hd = c = NULL;

  /* read NODE information from file */
  if ((infile = fopen (p_aj->config_file, "r")) == NULL)
    {
      return;
    }

  while (fgets (buf, sizeof (buf), infile))
    {
      ut_trim (buf);
      if (buf[0] == '#' || buf[0] == '\0')
        {
          continue;
        }

      if (string_tokenize_accept_laststring_space
          (buf, conf_item, AUTOEXECQUERY_CONF_ENTRY_NUM) < 0)
        {
          continue;
        }

      if (c == NULL)
        {
          c = (autoexecquery_node *) malloc (sizeof (autoexecquery_node));
          p_aj->hd = c;
        }
      else
        {
          c->next =
            (autoexecquery_node *) malloc (sizeof (autoexecquery_node));
          c = c->next;
        }
      if (c == NULL)
        {
          break;
        }

      snprintf (c->dbname, sizeof (c->dbname) - 1, "%s", conf_item[0]);
      snprintf (c->query_id, sizeof (c->query_id) - 1, "%s", conf_item[1]);
      snprintf (c->db_uid, sizeof (c->db_uid) - 1, "%s", conf_item[2]);
      snprintf (c->db_passwd, sizeof (c->db_passwd) - 1, "%s", conf_item[3]);
      c->db_passwd[sizeof (c->db_passwd) - 1] = '\0';
      snprintf (c->dbmt_uid, sizeof (c->dbmt_uid) - 1, "%s", conf_item[4]);

      if (strcmp (conf_item[5], "ONE") == 0)
        {
          c->period = AEQT_ONE;
        }
      else if (strcmp (conf_item[5], "DAY") == 0)
        {
          c->period = AEQT_DAY;
        }
      else if (strcmp (conf_item[5], "WEEK") == 0)
        {
          c->period = AEQT_WEEK;
        }
      else if (strcmp (conf_item[5], "MONTH") == 0)
        {
          c->period = AEQT_MONTH;
        }

      //      snprintf (c->detail1, sizeof (c->detail1) - 1, "%s", conf_item[6]);

      //Tools-822, use a link list to store period_details.
      set_query_period_details (& (c->detail1), conf_item[6]);

      snprintf (c->detail2, sizeof (c->detail2) - 1, "%s", conf_item[7]);
      snprintf (c->query_string, sizeof (c->query_string) - 1, "%s",
                conf_item[8]);
      c->db_mode = 2;
      c->next = NULL;
    }                /* end of while */
  fclose (infile);
  p_aj->is_on = 1;

}

static void
aj_execquery_handler (void *hd, time_t prev_check_time, time_t cur_time)
{
  time_t execquery_time;
  struct tm exec_tm, cur_tm, *tm_p;
  autoexecquery_node *c;
  query_period_details *detail1 = NULL;
  int tm_wday = 0;

  tm_p = localtime (&cur_time);
  if (tm_p == NULL)
    {
      return;
    }
  cur_tm = *tm_p;

  for (c = (autoexecquery_node *) (hd); c != NULL; c = c->next)
    {
      exec_tm = cur_tm;
      detail1 = c->detail1;

      while (detail1 != NULL)
        {
          aj_execquery_get_exec_time (c, detail1, &exec_tm, prev_check_time);

          // backup tm_wday, since mktime can change tm_wday field.
          tm_wday = exec_tm.tm_wday;
          execquery_time = mktime (&exec_tm);

          if (execquery_time <= prev_check_time || execquery_time > cur_time)
            {
              detail1 = detail1->next;
              continue;
            }

          if ((c->period == AEQT_ONE)
              || (c->period == AEQT_DAY)
              || ((c->period == AEQT_WEEK) && cur_tm.tm_wday == tm_wday)
              || ((c->period == AEQT_MONTH)
                  && cur_tm.tm_mday == exec_tm.tm_mday))
            {
              aj_execquery (c);
            }
          detail1 = detail1->next;
        }
    }

  return;
}

static void
aj_execquery_get_exec_time (autoexecquery_node *c,
                            query_period_details *d,
                            struct tm *exec_tm, time_t prev_check_time)
{
  switch (c->period)
    {
    case AEQT_ONE:
      sscanf (d->detail, "%d/%d/%d", & (exec_tm->tm_year), & (exec_tm->tm_mon),
              & (exec_tm->tm_mday));
      exec_tm->tm_year -= 1900;    /* year : since 1900 */
      exec_tm->tm_mon -= 1;    /* month : zero based month */
      break;

    case AEQT_DAY:
      /* sscanf(c->detail2, "%d:%d", &(exec_tm->tm_hour), &(exec_tm->tm_min)); */
      break;

    case AEQT_WEEK:
      if (strcmp (d->detail, WEEK_CAPITAL_SUNDAY_S) == 0)
        {
          exec_tm->tm_wday = 0;
        }
      else if (strcmp (d->detail, WEEK_CAPITAL_MONDAY_S) == 0)
        {
          exec_tm->tm_wday = 1;
        }
      else if (strcmp (d->detail, WEEK_CAPITAL_TUESDAY_S) == 0)
        {
          exec_tm->tm_wday = 2;
        }
      else if (strcmp (d->detail, WEEK_CAPITAL_WEDNESDAY_S) == 0)
        {
          exec_tm->tm_wday = 3;
        }
      else if (strcmp (d->detail, WEEK_CAPITAL_THURSDAY_S) == 0)
        {
          exec_tm->tm_wday = 4;
        }
      else if (strcmp (d->detail, WEEK_CAPITAL_FRIDAY_S) == 0)
        {
          exec_tm->tm_wday = 5;
        }
      else if (strcmp (d->detail, WEEK_CAPITAL_SATURDAY_S) == 0)
        {
          exec_tm->tm_wday = 6;
        }
      break;

    case AEQT_MONTH:
      sscanf (d->detail, "%d", & (exec_tm->tm_mday));
      break;
    }

  if ('i' == c->detail2[0])    // time interval for auto execute query
    {
      int interval;
      time_t prev_day_sec = 0;
      struct tm prev_tm, *tm_p;

      tm_p = localtime (&prev_check_time);
      if (tm_p == NULL)
        {
          return;
        }
      prev_tm = *tm_p;

      sscanf (c->detail2, "i%d", &interval);

      prev_day_sec =
        prev_tm.tm_hour * 3600 + prev_tm.tm_min * 60 + prev_tm.tm_sec;
      if ((prev_day_sec + interval * 60) >= (24 * 3600))    // if across a day, start at 00:00
        {
          exec_tm->tm_hour = 0;
          exec_tm->tm_min = 0;
        }
      else            // not across a day
        {
          time_t exec_sec =
            (prev_day_sec / (interval * 60) + 1) * interval * 60;
          exec_tm->tm_hour = (int) (exec_sec / 3600);
          exec_tm->tm_min = (exec_sec % 3600) / 60;
        }
    }
  else                // specific time for auto execute query
    {
      sscanf (c->detail2, "%d:%d", & (exec_tm->tm_hour), & (exec_tm->tm_min));
    }
  exec_tm->tm_sec = 0;
}

static void
aj_execquery (autoexecquery_node *c)
{
  int retval;
  int argc = 0;
  const char *argv[11];
  char cmd_name[CUBRID_CMD_NAME_LEN + 1];
  int ha_mode;
  T_DB_SERVICE_MODE db_mode;
  char dbname_at_hostname[MAXHOSTNAMELEN + DB_NAME_LEN];
  char dbpasswd[PASSWD_LENGTH + 1];
  int error_code;
  char error_buffer[1024];
  char cubrid_err_file[PATH_MAX];
  char input_filename[PATH_MAX];
  FILE *input_file;

  cubrid_err_file[0] = '\0';

  _aj_autoexecquery_error_log (c, 0, PRINT_CMD_START);

  memset (error_buffer, '\0', sizeof (error_buffer));

  cmd_name[0] = '\0';
#if !defined (DO_NOT_USE_CUBRIDENV)
  sprintf (cmd_name, "%s/%s%s", sco.szCubrid, CUBRID_DIR_BIN, UTIL_CSQL_NAME);
#else
  sprintf (cmd_name, "%s/%s", CUBRID_BINDIR, UTIL_CSQL_NAME);
#endif
  argv[argc++] = cmd_name;

  db_mode = uDatabaseMode (c->dbname, &ha_mode);
  if (ha_mode != 0)
    {
      append_host_to_dbname (dbname_at_hostname, c->dbname,
                             sizeof (dbname_at_hostname));
      argv[argc++] = dbname_at_hostname;
    }
  else
    {
      argv[argc++] = c->dbname;
    }

  switch (db_mode)
    {
    case DB_SERVICE_MODE_SA:
      sprintf (error_buffer, "Database(%s) is running in stand alone mode",
               c->dbname);
      _aj_autoexecquery_error_log (c, ERR_GENERAL_ERROR, error_buffer);
      return;
    case DB_SERVICE_MODE_CS:
      argv[argc++] = "--" CSQL_CS_MODE_L;
      break;
    case DB_SERVICE_MODE_NONE:
      argv[argc++] = "--" CSQL_SA_MODE_L;
      break;
    }

  make_temp_filepath (input_filename, sco.dbmt_tmp_dir, "dbmt_auto_execquery", TS_AUTOEXECQUERYERRLOG, PATH_MAX);
  argv[argc++] = "--" CSQL_INPUT_FILE_L;
  argv[argc++] = input_filename;

  argv[argc++] = "--" CSQL_USER_L;
  argv[argc++] = c->db_uid;

  uDecrypt (PASSWD_LENGTH, c->db_passwd, dbpasswd);
  argv[argc++] = "--" CSQL_PASSWORD_L;
  argv[argc++] = dbpasswd;

  argv[argc++] = "--" CSQL_NO_AUTO_COMMIT_L;

  for (; argc < 11; argc++)
    {
      argv[argc] = NULL;
    }

  input_file = fopen (input_filename, "w+");
  if (input_file != NULL)
    {
      fprintf (input_file, "%s\n", c->query_string);
      fprintf (input_file, ";commit");
      fclose (input_file);
    }
  else
    {
      sprintf (error_buffer, "Can't create temp file");
      _aj_autoexecquery_error_log (c, ERR_FILE_CREATE_FAIL, error_buffer);
      return;
    }

  make_temp_filepath (cubrid_err_file, sco.dbmt_tmp_dir, "aj_execquery", TS_AUTOEXECQUERYERRLOG, PATH_MAX);
  retval = run_child (argv, 1, NULL, NULL, cubrid_err_file, NULL);    /* csql auto-execute */
  unlink (input_filename);
  if (retval != 0)
    {
      sprintf (error_buffer, "Failed to execute Query with");
      _aj_autoexecquery_error_log (c, ERR_SYSTEM_CALL, error_buffer);
      if (access (cubrid_err_file, F_OK) == 0)
        {
          unlink (cubrid_err_file);
        }
      return;
    }
  else
    {
      if (read_error_file2 (cubrid_err_file, error_buffer, DBMT_ERROR_MSG_SIZE, &error_code) < 0)
        {
          if (error_code == 0)
            {
              error_code = ERR_GENERAL_ERROR;
            }
          _aj_autoexecquery_error_log (c, error_code, error_buffer);
          if (access (cubrid_err_file, F_OK) == 0)
            {
              unlink (cubrid_err_file);
            }
          return;
        }
      else
        {
          _aj_autoexecquery_error_log (c, 0, "success");
          if (access (cubrid_err_file, F_OK) == 0)
            {
              unlink (cubrid_err_file);
            }
        }
    }
}

static void
_aj_autoexecquery_error_log (autoexecquery_node *node, int error_code,
                             const char *errmsg)
{
  /* open error file and write errmsg */
  time_t tt;
  FILE *outfile;
  char logfile[256];
  char strbuf[128];

  tt = time (&tt);
#if !defined (DO_NOT_USE_CUBRIDENV)
  sprintf (logfile, "%s/log/manager/auto_execquery.log", sco.szCubrid);
#else
  sprintf (logfile, "%s/manager/auto_execquery.log", CUBRID_LOGDIR);
#endif

  outfile = fopen (logfile, "a");
  if (outfile == NULL)
    {
      return;
    }

  time_to_str (tt, "DATE:%04d/%02d/%02d TIME:%02d:%02d:%02d", strbuf,
               TIME_STR_FMT_DATE_TIME);
  fprintf (outfile, "%s\n", strbuf);
  fprintf (outfile, "DBNAME:%s EMGR-USERNAME:%s QUERY-ID:%s ERROR-CODE:%d\n",
           node->dbname, node->dbmt_uid, node->query_id, error_code);
  fprintf (outfile, "=> %s\n", errmsg);
  fflush (outfile);
  fclose (outfile);
}

static void
aj_autobackupdb_handler (void *hd, time_t prev_check_time, time_t cur_time)
{
  time_t backup_time;
  struct tm backup_tm, cur_tm, prev_tm, *tm_p;
  autobackupdb_node *c;

  backup_period_details *period_date = NULL;

  tm_p = localtime (&cur_time);
  if (tm_p == NULL)
    {
      return;
    }
  cur_tm = *tm_p;

  for (c = (autobackupdb_node *) (hd); c != NULL; c = c->next)
    {
      backup_tm = cur_tm;
      period_date = c->period_date;

      while (period_date != NULL)
        {
          if (c->period_type == ABPT_SPECIAL)
            {
              backup_tm.tm_year = period_date->date / 10000 - 1900;
              backup_tm.tm_mon = (period_date->date % 10000) / 100 - 1;
              backup_tm.tm_mday = period_date->date % 100;
            }
          if (1 == c->is_interval)    // interval time for auto backup
            {
              time_t prev_day_sec;
              tm_p = localtime (&prev_check_time);
              if (tm_p == NULL)
                {
                  return;
                }
              prev_tm = *tm_p;

              prev_day_sec =
                prev_tm.tm_hour * 3600 + prev_tm.tm_min * 60 + prev_tm.tm_sec;
              if ((prev_day_sec + c->time * 60) >= 24 * 3600)    // if across a day, start at 00:00
                {
                  backup_tm.tm_hour = 0;
                  backup_tm.tm_min = 0;
                }
              else        // not across a day
                {
                  time_t exec_sec =
                    (prev_day_sec / (c->time * 60) + 1) * c->time * 60;
                  backup_tm.tm_hour = (int) (exec_sec / 3600);
                  backup_tm.tm_min = (exec_sec % 3600) / 60;
                }
            }
          else            // specific time for auto backup
            {
              if (c->period_type != ABPT_HOURLY)
                {
                  backup_tm.tm_hour = c->time / 100;
                }
              backup_tm.tm_min = c->time % 100;
            }
          backup_tm.tm_sec = 0;

          backup_time = mktime (&backup_tm);
          if (backup_time <= prev_check_time || backup_time > cur_time)
            {
              period_date = period_date->next;
              continue;
            }

          if ((c->period_type == ABPT_MONTHLY
               && cur_tm.tm_mday == period_date->date)
              || (c->period_type == ABPT_WEEKLY
                  && cur_tm.tm_wday == period_date->date)
              || (c->period_type == ABPT_DAILY)
              || (c->period_type == ABPT_HOURLY)
              || (c->period_type == ABPT_SPECIAL))
            {
              aj_backupdb (c);
            }
          period_date = period_date->next;
        }            // while
    }                // for
}

static void
_aj_autobackupdb_error_log (autobackupdb_node *n, char *errmsg)
{
  time_t tt;
  FILE *outfile;
  char logfile[256];
  char strbuf[128];

  tt = time (&tt);
#if !defined (DO_NOT_USE_CUBRIDENV)
  sprintf (logfile, "%s/log/manager/auto_backupdb.log", sco.szCubrid);
#else
  sprintf (logfile, "%s/manager/auto_backupdb.log", CUBRID_LOGDIR);
#endif

  outfile = fopen (logfile, "a");
  if (outfile == NULL)
    {
      return;
    }
  time_to_str (tt, "DATE:%04d/%02d/%02d TIME:%02d:%02d:%02d", strbuf,
               TIME_STR_FMT_DATE_TIME);
  fprintf (outfile, "%s\n", strbuf);
  fprintf (outfile, "DBNAME:%s BACKUPID:%s\n", n->dbname, n->backup_id);
  fprintf (outfile, "=> %s\n", errmsg);
  fflush (outfile);
  fclose (outfile);
}

static void
aj_backupdb (autobackupdb_node *n)
{
  char dbname_at_hostname[MAXHOSTNAMELEN + DB_NAME_LEN];
  int ha_mode;
  char bkpath[512];
  char inputfilepath[512];
  char buf[2048], dbdir[512];
  char backup_vol_name[128];
  const char *opt_mode;
  char db_start_flag = 0;
  char cubrid_err_file[PATH_MAX];
  int retval;
  char cmd_name[CUBRID_CMD_NAME_LEN];
  char level_str[32];
  char strtime[32];
  char thread_num_str[16];
  const char *argv[16];
  int argc = 0;
  FILE *inputfile;
  T_DB_SERVICE_MODE db_mode;

  cubrid_err_file[0] = '\0';

  sprintf (buf, "backupdb(%s): auto job start", n->dbname);
  _aj_autobackupdb_error_log (n, buf);

  n->lbt = time (NULL);
  if (uRetrieveDBDirectory (n->dbname, dbdir) != ERR_NO_ERROR)
    {
      sprintf (buf, "DB directory not found");
      _aj_autobackupdb_error_log (n, buf);
      return;
    }
  time_to_str (n->lbt, "%04d%02d%02d_%02d%02d%02d", strtime,
               TIME_STR_FMT_DATE_TIME);
  sprintf (backup_vol_name, "%s_auto_backup_lv%d", n->dbname, n->level);
  sprintf (bkpath, "%s/%s_%s", n->path, strtime, backup_vol_name);

  db_mode = uDatabaseMode (n->dbname, &ha_mode);
  if (db_mode == DB_SERVICE_MODE_SA)
    {
      sprintf (buf, "Failed to execute backupdb: %s is in standalone mode", n->dbname);
      _aj_autobackupdb_error_log (n, buf);
      return;
    }
  if (n->onoff == 1 && db_mode == DB_SERVICE_MODE_NONE)
    {
      sprintf (buf, "Failed to execute backupdb: %s is offline", n->dbname);
      _aj_autobackupdb_error_log (n, buf);
      return;
    }

  if (access (n->path, F_OK) < 0)
    {
      if (uCreateDir (n->path) != ERR_NO_ERROR)
        {
          sprintf (buf, "Directory creation failed: %s", n->path);
          _aj_autobackupdb_error_log (n, buf);
          return;
        }
    }

  remove_extra_subdir (n->path, backup_vol_name, n->bk_num);

  if (access (bkpath, F_OK) < 0)
    {
      if (uCreateDir (bkpath) != ERR_NO_ERROR)
        {
          sprintf (buf, "Directory creation failed: %s", bkpath);
          _aj_autobackupdb_error_log (n, buf);
          return;
        }
    }

  /* if DB status is on then turn off */
  if (n->onoff == 0 && db_mode == DB_SERVICE_MODE_CS)
    {
      if (cmd_stop_server (n->dbname, NULL, 0) < 0)
        {
          sprintf (buf, "Failed to turn off DB");
          _aj_autobackupdb_error_log (n, buf);
          return;
        }
      db_start_flag = 1;
    }

  opt_mode = (n->onoff == 0) ? "--" CSQL_SA_MODE_L : "--" CSQL_CS_MODE_L;

  cubrid_cmd_name (cmd_name);
  sprintf (thread_num_str, "%d", n->mt);
  sprintf (level_str, "%d", n->level);
  argc = 0;
  argv[argc++] = cmd_name;
  argv[argc++] = UTIL_OPTION_BACKUPDB;
  argv[argc++] = opt_mode;
  argv[argc++] = "--" BACKUP_LEVEL_L;
  argv[argc++] = level_str;
  argv[argc++] = "--" BACKUP_DESTINATION_PATH_L;
  argv[argc++] = bkpath;
  if (n->archivedel)
    {
      argv[argc++] = "--" BACKUP_REMOVE_ARCHIVE_L;
    }

  if (n->mt > 0)
    {
      argv[argc++] = "--" BACKUP_THREAD_COUNT_L;
      argv[argc++] = thread_num_str;
    }

  if (n->zip)
    {
      argv[argc++] = "--" BACKUP_COMPRESS_L;
    }

  if (!n->check)
    {
      argv[argc++] = "--" BACKUP_NO_CHECK_L;
    }

  if (ha_mode != 0)
    {
      append_host_to_dbname (dbname_at_hostname, n->dbname,
                             sizeof (dbname_at_hostname));
      argv[argc++] = dbname_at_hostname;
    }
  else
    {
      argv[argc++] = n->dbname;
    }
  argv[argc++] = NULL;

  snprintf (cubrid_err_file, PATH_MAX, "%s/%s.%u.err.tmp",
            sco.dbmt_tmp_dir, "aj_backupdb", getpid ());

  sprintf (inputfilepath, "%s/DBMT_task_%d.%d", sco.dbmt_tmp_dir, TS_BACKUPDB,
           (int) getpid ());
  inputfile = fopen (inputfilepath, "w");
  if (inputfile)
    {
      fprintf (inputfile, "y");
      fclose (inputfile);
    }
  else
    {
      sprintf (buf, "Failed to write file: %s", inputfilepath);
      _aj_autobackupdb_error_log (n, buf);
      return;
    }

  retval = run_child (argv, 1, inputfilepath, NULL, cubrid_err_file, NULL);    /* backupdb */
  unlink (inputfilepath);

  if (read_error_file (cubrid_err_file, buf, sizeof (buf)) < 0)
    {
      _aj_autobackupdb_error_log (n, buf);
      if (access (cubrid_err_file, F_OK) == 0)
        {
          unlink (cubrid_err_file);
        }
      return;
    }
  if (access (cubrid_err_file, F_OK) == 0)
    {
      unlink (cubrid_err_file);
    }
  if (retval < 0)
    {
      /* backupdb */
      sprintf (buf, "Failed to execute backupdb: %s", argv[0]);
      _aj_autobackupdb_error_log (n, buf);
      return;
    }

  sprintf (buf, "backupdb(%s): success", n->dbname);
  _aj_autobackupdb_error_log (n, buf);    /* log success info to notify cubrid manager user */

  /* update statistics */
  if (n->onoff == 0 && n->updatestatus)
    {
      cubrid_cmd_name (cmd_name);
      argv[0] = cmd_name;
      argv[1] = UTIL_OPTION_OPTIMIZEDB;
      argv[2] = n->dbname;
      argv[3] = NULL;
      if (run_child (argv, 1, NULL, NULL, NULL, NULL) < 0)
        {
          /* optimizedb */
          sprintf (buf, "Failed to update statistics");
          _aj_autobackupdb_error_log (n, buf);
          return;
        }
    }

  if (db_start_flag)
    {
      char err_buf[ERR_MSG_SIZE];
      if (cmd_start_server (n->dbname, err_buf, sizeof (err_buf)) < 0)
        {
          int buf_len;
          memset (buf, 0, sizeof (buf));
          buf_len = sprintf (buf, "Failed to turn on DB : ");
          snprintf (buf + buf_len, sizeof (buf) - buf_len - 1, "%s", err_buf);
          _aj_autobackupdb_error_log (n, buf);
        }
    }
}
