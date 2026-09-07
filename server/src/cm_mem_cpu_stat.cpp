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
 * cm_mem_cpu_stat.cpp - CMS-native ports of CUBRID engine's
 * cm_common/cm_mem_cpu_stat.c cm_get_db_exec_stat ()/cm_get_host_disk_partition_stat ()
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>
#include <ctype.h>
#include <config.h>
#include <inttypes.h>

#if defined(WINDOWS)
#include <process.h>
#include <windows.h>
#else
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <unistd.h>
#include <sys/wait.h>
#endif

#include "cm_config.h"
#include "cm_cmd_util.h"
#include "cm_cmd_exec.h"
#include "cm_server_util.h"
#include "cm_stat.h"

#define NELEMS(x) ((sizeof (x))/(sizeof ((x)[0])))

#define CMS_FREE_MEM(PTR) \
  do { if (PTR) { free (PTR); (PTR) = NULL; } } while (0)

/*
 * "server"/"status" - same rationale as cm_server_status.cpp's
 * CMS_PRINT_CMD_SERVER/CMS_PRINT_CMD_STATUS
 */
#define CMS_PRINT_CMD_SERVER          "server"
#define CMS_PRINT_CMD_STATUS          "status"

typedef void *(*EXTRACT_FUNC) (FILE *fp, const char *arg1, T_CM_ERROR *arg2);

static void *extract_db_stat (FILE *fp, const char *tdbname, T_CM_ERROR *err_buf);
static void assign_db_stat (T_CM_DB_PROC_STAT *db_stat, char *db_name, T_CM_PROC_STAT *stat);
static void cm_db_proc_stat_free (T_CM_DB_PROC_STAT *stat);
static void *extract_host_partition_stat (FILE *fp, const char *arg1, T_CM_ERROR *err_buf);
static void *extract_db_exec_stat (FILE *fp, const char *dbname, T_CM_ERROR *err_buf);
static uint64_t *get_statdump_member_ptr (T_CM_DB_EXEC_STAT *stat, const char *prop_name);
static void *cms_get_command_result (const char *argv[], EXTRACT_FUNC func, const char *func_arg1,
                                     T_CM_ERROR *err_buf);
static void cms_err_buf_reset (T_CM_ERROR *err_buf);
static void cms_set_error_null_pointer (T_CM_ERROR *err_buf);
static void cms_set_error_oom (T_CM_ERROR *err_buf);
static char *cms_trim (char *str);

/*
 * cms_err_buf_reset () - CMS-native replacement for the engine's
 * cm_errmsg.h:cm_err_buf_reset (). see the NOTE near the top of this file.
 */
static void
cms_err_buf_reset (T_CM_ERROR *err_buf)
{
  err_buf->err_code = 0;
  err_buf->err_msg[0] = '\0';
}

/*
 * cms_set_error_null_pointer () / cms_set_error_oom () - CMS-native
 * replacements
 */
static void
cms_set_error_null_pointer (T_CM_ERROR *err_buf)
{
  err_buf->err_code = CM_ERR_NULL_POINTER;
  strcpy_limit (err_buf->err_msg, "NULL pointer parameter", sizeof (err_buf->err_msg));
}

static void
cms_set_error_oom (T_CM_ERROR *err_buf)
{
  err_buf->err_code = CM_OUT_OF_MEMORY;
  strcpy_limit (err_buf->err_msg, "out of memory", sizeof (err_buf->err_msg));
}

/*
 * cms_trim () - CMS-native replacement for the engine's cm_utils.h:ut_trim ()
 */
static char *
cms_trim (char *str)
{
  char *s, *p;

  if (str == NULL || *str == '\0')
    {
      return str;
    }

  for (s = str; isspace ((unsigned char) *s); s++)
    {
      ;
    }
  if (*s == '\0')
    {
      *str = '\0';
      return str;
    }

  for (p = s + strlen (s) - 1; p > s && isspace ((unsigned char) *p); p--)
    {
      ;
    }
  *(p + 1) = '\0';

  if (s != str)
    {
      memmove (str, s, (size_t) (p - s) + 2);
    }
  return str;
}

/*
 * cms_get_command_result () - CMS-native port of CUBRID engine
 */
static void *
cms_get_command_result (const char *argv[], EXTRACT_FUNC func, const char *func_arg1, T_CM_ERROR *err_buf)
{
  void *retval;
  FILE *fp = NULL;
  char outputfile[PATH_MAX];
  char errfile[PATH_MAX];
  int exit_code = 0;

  if (gen_tempfile_path (outputfile, sco.dbmt_tmp_dir, "DBMT_cms_stat_res", 0, PATH_MAX) < 0)
    {
      err_buf->err_code = CM_ERR_SYSTEM_CALL;
      snprintf (err_buf->err_msg, sizeof (err_buf->err_msg) - 1, "command execute failed: %s", "gen_tempfile_path ()");
      return NULL;
    }
  unlink (outputfile);

  if (gen_tempfile_path (errfile, sco.dbmt_tmp_dir, "DBMT_cms_stat_err", 0, PATH_MAX) < 0)
    {
      err_buf->err_code = CM_ERR_SYSTEM_CALL;
      snprintf (err_buf->err_msg, sizeof (err_buf->err_msg) - 1, "command execute failed: %s", "gen_tempfile_path ()");
      return NULL;
    }
  unlink (errfile);

  if (run_child_env (argv, RUN_FOREGROUND, NULL, outputfile, errfile, &exit_code) < 0)
    {
      err_buf->err_code = CM_ERR_SYSTEM_CALL;
      snprintf (err_buf->err_msg, sizeof (err_buf->err_msg) - 1, "command execute failed: %s", argv[0]);
      unlink (outputfile);
      unlink (errfile);
      return NULL;
    }

  if (!_child_exited_ok (exit_code))
    {
      err_buf->err_code = CM_ERR_SYSTEM_CALL;
      if (read_error_file (errfile, err_buf->err_msg, sizeof (err_buf->err_msg)) == 0
          || err_buf->err_msg[0] == '\0')
        {
          strcpy_limit (err_buf->err_msg, "unknown error", sizeof (err_buf->err_msg));
        }
      unlink (outputfile);
      unlink (errfile);
      return NULL;
    }

  fp = fopen (outputfile, "r");
  if (fp == NULL)
    {
      char errbuf[ERR_MSG_LEN];

      err_buf->err_code = CM_FILE_OPEN_FAILED;
      snprintf (err_buf->err_msg, sizeof (err_buf->err_msg) - 1, "file (%s) open failed: %s", outputfile,
               STRERROR_R (errno, errbuf, sizeof (errbuf)));
      unlink (outputfile);
      unlink (errfile);
      return NULL;
    }

  retval = func (fp, func_arg1, err_buf);	/* call extract function */

  fclose (fp);
  unlink (outputfile);
  unlink (errfile);
  return retval;
}

int
cms_get_db_proc_stat (const char *db_name, T_CM_DB_PROC_STAT *stat, T_CM_ERROR *err_buf)
{
  T_CM_DB_PROC_STAT *p = NULL;
  char cmd_name[PATH_MAX];

  /* cubrid server status */
  const char *argv[] = {
    cmd_name,
    CMS_PRINT_CMD_SERVER,
    CMS_PRINT_CMD_STATUS,
    NULL,
  };

  cms_err_buf_reset (err_buf);
  cubrid_cmd_name (cmd_name);

  if (db_name == NULL)
    {
      cms_set_error_null_pointer (err_buf);
      return -1;
    }

  p = (T_CM_DB_PROC_STAT *) cms_get_command_result (argv, extract_db_stat, db_name, err_buf);
  if (p != NULL)
    {
      *stat = *p;
      cm_db_proc_stat_free (p);
      return 0;
    }
  return -1;
}

static void
cm_db_proc_stat_free (T_CM_DB_PROC_STAT *stat)
{
  CMS_FREE_MEM (stat);
}

T_CM_DB_PROC_STAT_ALL *
cms_get_db_proc_stat_all (T_CM_ERROR *err_buf)
{
  char cmd_name[PATH_MAX];

  /* cubrid server status */
  const char *argv[] = {
    cmd_name,
    CMS_PRINT_CMD_SERVER,
    CMS_PRINT_CMD_STATUS,
    NULL,
  };

  cubrid_cmd_name (cmd_name);

  cms_err_buf_reset (err_buf);
  return (T_CM_DB_PROC_STAT_ALL *) cms_get_command_result (argv, extract_db_stat, NULL, err_buf);
}

/*
 * This function is not used, but it is code that has been ported for the future.
 */
#if defined (ENABLE_UNUSED_FUNCTION)
#if defined(WINDOWS)
T_CM_DISK_PARTITION_STAT_ALL *
cms_get_host_disk_partition_stat (T_CM_ERROR *err_buf)
{
  int i, len;
  char buf[160] = { 0 };
  ULONGLONG total_size[32], free_size[32];
  char names[32][4] = { 0 };
  char *token;
  T_CM_DISK_PARTITION_STAT_ALL *res;
  char *saveptr;

  len = GetLogicalDriveStringsA (sizeof (buf), buf);

  for (i = 0; i < len; i++)
    {
      if (buf[i] == 0)
        {
          buf[i] = ';';
        }
    }

  buf[len - 1] = 0;
  i = 0;

  for (token = STRTOK (buf, ";", &saveptr); token != NULL && i < 32; token = STRTOK (NULL, ";", &saveptr))
    {
      if (GetDriveTypeA (token) == DRIVE_FIXED)
        {
          ULARGE_INTEGER ul_total, ul_free;
          GetDiskFreeSpaceExA (token, &ul_free, &ul_total, NULL);
          total_size[i] = ul_total.QuadPart;
          free_size[i] = ul_free.QuadPart;
          strcpy_limit (names[i], token, sizeof (names[i]));
          i++;
        }
    }

  res = (T_CM_DISK_PARTITION_STAT_ALL *) malloc (sizeof (T_CM_DISK_PARTITION_STAT_ALL));

  if (res == NULL)
    {
      return NULL;
    }

  res->num_stat = i;
  res->partitions = (T_CM_DISK_PARTITION_STAT *) malloc (sizeof (T_CM_DISK_PARTITION_STAT) * i);

  if (res->partitions == NULL)
    {
      CMS_FREE_MEM (res);
      return NULL;
    }

  for (i = 0; i < res->num_stat; i++)
    {
      res->partitions[i].avail = free_size[i];
      res->partitions[i].size = total_size[i];
      res->partitions[i].used = total_size[i] - free_size[i];
      strcpy_limit (res->partitions[i].name, names[i], sizeof (res->partitions[i].name));
    }

  return res;
}
#else
T_CM_DISK_PARTITION_STAT_ALL *
cms_get_host_disk_partition_stat (T_CM_ERROR *err_buf)
{
  /* df -TB 1M */
  const char *argv[] = {
    "/bin/df",
    "-TB",
    "1M",
    NULL,
  };

  cms_err_buf_reset (err_buf);
  return (T_CM_DISK_PARTITION_STAT_ALL *) cms_get_command_result (argv, extract_host_partition_stat, NULL, err_buf);
}
#endif
#endif

int
cms_get_db_exec_stat (const char *db_name, T_CM_DB_EXEC_STAT *exec_stat, T_CM_ERROR *err_buf)
{
  T_CM_DB_EXEC_STAT *p = NULL;
  char cmd_name[PATH_MAX];

  /* cubrid statdump dbname */
  const char *argv[] = {
    cmd_name,
    "statdump",
    db_name,
    NULL,
  };

  cms_err_buf_reset (err_buf);
  if (db_name == NULL)
    {
      cms_set_error_null_pointer (err_buf);
      return -1;
    }

  cubrid_cmd_name (cmd_name);
  p = (T_CM_DB_EXEC_STAT *) cms_get_command_result (argv, extract_db_exec_stat, db_name, err_buf);
  if (p != NULL)
    {
      *exec_stat = *p;
      CMS_FREE_MEM (p);
      return 0;
    }
  return -1;
}

static void *
extract_db_stat (FILE *fp, const char *tdbname, T_CM_ERROR *err_buf)
{
  char linebuf[LINE_MAX];
  char db_name[512];
  char cmd_name[512];
  int pid;
  T_CM_PROC_STAT pstat;
  T_CM_DB_PROC_STAT_ALL *all_stat = NULL;
  T_CM_DB_PROC_STAT *db_stat = NULL;
  int nitem = 0;
  int nalloc = 10;

  if (tdbname != NULL)
    {
      db_stat = (T_CM_DB_PROC_STAT *) malloc (sizeof (T_CM_DB_PROC_STAT));
      if (!db_stat)
        {
          cms_set_error_oom (err_buf);
          return NULL;
        }
    }
  else
    {
      T_CM_DB_PROC_STAT *p = NULL;
      all_stat = (T_CM_DB_PROC_STAT_ALL *) malloc (sizeof (T_CM_DB_PROC_STAT_ALL));
      p = (T_CM_DB_PROC_STAT *) malloc (nalloc * sizeof (T_CM_DB_PROC_STAT));

      if (all_stat == NULL || p == NULL)
        {
          cms_set_error_oom (err_buf);
          CMS_FREE_MEM (all_stat);
          CMS_FREE_MEM (p);
          return NULL;
        }
      all_stat->db_stats = p;
    }

  while (fgets (linebuf, sizeof (linebuf), fp))
    {
      int tok_num = 0;
      char pid_t[20];

      cms_trim (linebuf);
      if (linebuf[0] == '@')
        continue;

      tok_num = sscanf (linebuf, "%511s %511s %*s %*s %*s %19s", cmd_name, db_name, pid_t);

      if (tok_num != 3 || (strcmp (cmd_name, "Server") != 0 && strcmp (cmd_name, "HA-Server") != 0))
        continue;

      /* remove the ")" at the end of the pid. */
      pid_t[strlen (pid_t) - 1] = '\0';
      pid = atoi (pid_t);

      if (pid == 0)
        continue;

      if (tdbname != NULL)
        {
          if (!strcmp ((char *) tdbname, db_name))
            {
              if (cm_get_proc_stat (&pstat, pid) == 0)
                {
                  assign_db_stat (db_stat, db_name, &pstat);
                  return db_stat;
                }
              goto not_found;
            }
        }
      else
        {
          if (nitem >= nalloc)
            {
              T_CM_DB_PROC_STAT *db_stats_newptr = NULL;
              int nalloc_new = nalloc * 2;
              db_stats_newptr =
                (T_CM_DB_PROC_STAT *) realloc (all_stat->db_stats, nalloc_new * sizeof (T_CM_DB_PROC_STAT));
              if (db_stats_newptr == NULL)
                {
                  cms_set_error_oom (err_buf);
                  return NULL;
                }
              all_stat->db_stats = db_stats_newptr;
              nalloc = nalloc_new;
            }
          if (cm_get_proc_stat (&pstat, pid) == 0)
            {
              assign_db_stat (&all_stat->db_stats[nitem++], db_name, &pstat);
            }
        }
    }

  if (tdbname == NULL)
    {
      all_stat->num_stat = nitem;
      return all_stat;
    }
  else
    {
      goto not_found;
    }

not_found:
  err_buf->err_code = CM_DB_STAT_NOT_FOUND;
  snprintf (err_buf->err_msg, sizeof (err_buf->err_msg) - 1, "stat of database (%s) not found", tdbname);
  cm_db_proc_stat_free (db_stat);
  return NULL;
}

static void
assign_db_stat (T_CM_DB_PROC_STAT *db_stat, char *db_name, T_CM_PROC_STAT *stat)
{
  strcpy_limit (db_stat->name, db_name, sizeof (db_stat->name));
  db_stat->stat = *stat;
}

static void *
extract_host_partition_stat (FILE *fp, const char *arg1, T_CM_ERROR *err_buf)
{
  char linebuf[LINE_MAX];
  char type[512];
  int nitem = 0;
  int nalloc = 10;
  T_CM_DISK_PARTITION_STAT *p = NULL;
  T_CM_DISK_PARTITION_STAT_ALL *stat = NULL;

  stat = (T_CM_DISK_PARTITION_STAT_ALL *) malloc (sizeof (T_CM_DISK_PARTITION_STAT_ALL));
  p = (T_CM_DISK_PARTITION_STAT *) malloc (nalloc * sizeof (T_CM_DISK_PARTITION_STAT));
  if (stat == NULL || p == NULL)
    {
      cms_set_error_oom (err_buf);
      CMS_FREE_MEM (stat);
      CMS_FREE_MEM (p);
      return NULL;
    }
  stat->partitions = p;

  while (fgets (linebuf, sizeof (linebuf), fp))
    {
      sscanf (linebuf, "%*s%511s", type);
      if (strstr (type, "ext") == NULL)
        continue;

      if (nitem >= nalloc)
        {
          nalloc *= 2;
          stat->partitions =
            (T_CM_DISK_PARTITION_STAT *) realloc (stat->partitions, nalloc * sizeof (T_CM_DISK_PARTITION_STAT));
        }
      if (stat->partitions)
        {
          p = stat->partitions + nitem;
          sscanf (linebuf, "%255s%*s%lu%lu%lu", p->name, &p->size, &p->used, &p->avail);
          nitem++;
        }
      else
        {
          cm_host_disk_partition_stat_free (stat);
          cms_set_error_oom (err_buf);
          return NULL;
        }
    }
  stat->num_stat = nitem;

  return stat;
}

typedef struct
{
  const char *prop_name;
  int prop_offset;
} STATDUMP_PROP;

/*
 * statdump_offset () - `cubrid statdump` output property name -> offsetof
 * (T_CM_DB_EXEC_STAT, ...) lookup table.
 */
static STATDUMP_PROP statdump_offset[] = {
  {"Num_file_creates", offsetof (T_CM_DB_EXEC_STAT, file_num_creates)},
  {"Num_file_removes", offsetof (T_CM_DB_EXEC_STAT, file_num_removes)},
  {"Num_file_ioreads", offsetof (T_CM_DB_EXEC_STAT, file_num_ioreads)},
  {"Num_file_iowrites", offsetof (T_CM_DB_EXEC_STAT, file_num_iowrites)},
  {"Num_file_iosynches", offsetof (T_CM_DB_EXEC_STAT, file_num_iosynches)},
  {"Num_file_page_allocs", offsetof (T_CM_DB_EXEC_STAT, file_num_page_allocs)},
  {"Num_file_page_deallocs", offsetof (T_CM_DB_EXEC_STAT, file_num_page_deallocs)},
  {"Num_data_page_fetches", offsetof (T_CM_DB_EXEC_STAT, pb_num_fetches)},
  {"Num_data_page_dirties", offsetof (T_CM_DB_EXEC_STAT, pb_num_dirties)},
  {"Num_data_page_ioreads", offsetof (T_CM_DB_EXEC_STAT, pb_num_ioreads)},
  {"Num_data_page_iowrites", offsetof (T_CM_DB_EXEC_STAT, pb_num_iowrites)},
  {"Num_data_page_hash_anchor_waits", offsetof (T_CM_DB_EXEC_STAT, pb_num_hash_anchor_waits)},
  {"Time_data_page_hash_anchor_wait", offsetof (T_CM_DB_EXEC_STAT, pb_time_hash_anchor_wait)},
  {"Num_data_page_fixed", offsetof (T_CM_DB_EXEC_STAT, pb_fixed_cnt)},
  {"Num_data_page_dirty", offsetof (T_CM_DB_EXEC_STAT, pb_dirty_cnt)},
  {"Num_data_page_lru1", offsetof (T_CM_DB_EXEC_STAT, pb_lru1_cnt)},
  {"Num_data_page_lru2", offsetof (T_CM_DB_EXEC_STAT, pb_lru2_cnt)},
  {"Num_data_page_lru3", offsetof (T_CM_DB_EXEC_STAT, pb_lru3_cnt)},
  {"Num_data_page_avoid_dealloc", offsetof (T_CM_DB_EXEC_STAT, pb_avoid_dealloc_cnt)},
  {"Num_data_page_avoid_victim", offsetof (T_CM_DB_EXEC_STAT, pb_avoid_victim_cnt)},
  {"Num_data_page_victim_candidate", offsetof (T_CM_DB_EXEC_STAT, pb_victim_cand_cnt)},
  {"Num_log_page_fetches", offsetof (T_CM_DB_EXEC_STAT, log_num_fetches)},
  {"Num_log_page_ioreads", offsetof (T_CM_DB_EXEC_STAT, log_num_ioreads)},
  {"Num_log_page_iowrites", offsetof (T_CM_DB_EXEC_STAT, log_num_iowrites)},
  {"Num_log_append_records", offsetof (T_CM_DB_EXEC_STAT, log_num_appendrecs)},
  {"Num_log_archives", offsetof (T_CM_DB_EXEC_STAT, log_num_archives)},
  {"Num_log_start_checkpoints", offsetof (T_CM_DB_EXEC_STAT, log_num_start_checkpoints)},
  {"Num_log_end_checkpoints", offsetof (T_CM_DB_EXEC_STAT, log_num_end_checkpoints)},
  {"Num_log_wals", offsetof (T_CM_DB_EXEC_STAT, log_num_wals)},
  {"Num_log_page_replacement", offsetof (T_CM_DB_EXEC_STAT, log_num_replacements)},
  {"Num_log_page_iowrites_for_replacement", offsetof (T_CM_DB_EXEC_STAT, log_num_iowrites_for_replacement)},
  {"Num_page_locks_acquired", offsetof (T_CM_DB_EXEC_STAT, lk_num_acquired_on_pages)},
  {"Num_object_locks_acquired", offsetof (T_CM_DB_EXEC_STAT, lk_num_acquired_on_objects)},
  {"Num_page_locks_converted", offsetof (T_CM_DB_EXEC_STAT, lk_num_converted_on_pages)},
  {"Num_object_locks_converted", offsetof (T_CM_DB_EXEC_STAT, lk_num_converted_on_objects)},
  {"Num_page_locks_re-requested", offsetof (T_CM_DB_EXEC_STAT, lk_num_re_requested_on_pages)},
  {"Num_object_locks_re-requested", offsetof (T_CM_DB_EXEC_STAT, lk_num_re_requested_on_objects)},
  {"Num_page_locks_waits", offsetof (T_CM_DB_EXEC_STAT, lk_num_waited_on_pages)},
  {"Num_object_locks_waits", offsetof (T_CM_DB_EXEC_STAT, lk_num_waited_on_objects)},
  {"Num_object_locks_time_waited_usec", offsetof (T_CM_DB_EXEC_STAT, lk_num_waited_time_on_objects)},
  {"Num_tran_commits", offsetof (T_CM_DB_EXEC_STAT, tran_num_commits)},
  {"Num_tran_rollbacks", offsetof (T_CM_DB_EXEC_STAT, tran_num_rollbacks)},
  {"Num_tran_savepoints", offsetof (T_CM_DB_EXEC_STAT, tran_num_savepoints)},
  {"Num_tran_start_topops", offsetof (T_CM_DB_EXEC_STAT, tran_num_start_topops)},
  {"Num_tran_end_topops", offsetof (T_CM_DB_EXEC_STAT, tran_num_end_topops)},
  {"Num_tran_interrupts", offsetof (T_CM_DB_EXEC_STAT, tran_num_interrupts)},
  {"Num_btree_inserts", offsetof (T_CM_DB_EXEC_STAT, bt_num_inserts)},
  {"Num_btree_deletes", offsetof (T_CM_DB_EXEC_STAT, bt_num_deletes)},
  {"Num_btree_updates", offsetof (T_CM_DB_EXEC_STAT, bt_num_updates)},
  {"Num_btree_covered", offsetof (T_CM_DB_EXEC_STAT, bt_num_covered)},
  {"Num_btree_noncovered", offsetof (T_CM_DB_EXEC_STAT, bt_num_noncovered)},
  {"Num_btree_resumes", offsetof (T_CM_DB_EXEC_STAT, bt_num_resumes)},
  {"Num_btree_multirange_optimization", offsetof (T_CM_DB_EXEC_STAT, bt_num_multi_range_opt)},
  {"Num_btree_splits", offsetof (T_CM_DB_EXEC_STAT, bt_num_splits)},
  {"Num_btree_merges", offsetof (T_CM_DB_EXEC_STAT, bt_num_merges)},
  {"Num_btree_get_stats", offsetof (T_CM_DB_EXEC_STAT, bt_num_get_stats)},
  {"Num_heap_stats_sync_bestspace", offsetof (T_CM_DB_EXEC_STAT, heap_num_stats_sync_bestspace)},
  {"Num_query_selects", offsetof (T_CM_DB_EXEC_STAT, qm_num_selects)},
  {"Num_query_inserts", offsetof (T_CM_DB_EXEC_STAT, qm_num_inserts)},
  {"Num_query_deletes", offsetof (T_CM_DB_EXEC_STAT, qm_num_deletes)},
  {"Num_query_updates", offsetof (T_CM_DB_EXEC_STAT, qm_num_updates)},
  {"Num_query_sscans", offsetof (T_CM_DB_EXEC_STAT, qm_num_sscans)},
  {"Num_query_iscans", offsetof (T_CM_DB_EXEC_STAT, qm_num_iscans)},
  {"Num_query_lscans", offsetof (T_CM_DB_EXEC_STAT, qm_num_lscans)},
  {"Num_query_setscans", offsetof (T_CM_DB_EXEC_STAT, qm_num_setscans)},
  {"Num_query_methscans", offsetof (T_CM_DB_EXEC_STAT, qm_num_methscans)},
  {"Num_query_nljoins", offsetof (T_CM_DB_EXEC_STAT, qm_num_nljoins)},
  {"Num_query_mjoins", offsetof (T_CM_DB_EXEC_STAT, qm_num_mjoins)},
  {"Num_query_objfetches", offsetof (T_CM_DB_EXEC_STAT, qm_num_objfetches)},
  {"Num_query_holdable_cursors", offsetof (T_CM_DB_EXEC_STAT, qm_num_holdable_cursors)},
  {"Num_sort_io_pages", offsetof (T_CM_DB_EXEC_STAT, sort_num_io_pages)},
  {"Num_sort_data_pages", offsetof (T_CM_DB_EXEC_STAT, sort_num_data_pages)},
  {"Num_network_requests", offsetof (T_CM_DB_EXEC_STAT, net_num_requests)},
  {"Num_adaptive_flush_pages", offsetof (T_CM_DB_EXEC_STAT, fc_num_pages)},
  {"Num_adaptive_flush_log_pages", offsetof (T_CM_DB_EXEC_STAT, fc_num_log_pages)},
  {"Num_adaptive_flush_max_pages", offsetof (T_CM_DB_EXEC_STAT, fc_tokens)},
  {"Num_prior_lsa_list_size", offsetof (T_CM_DB_EXEC_STAT, prior_lsa_list_size)},
  {"Num_prior_lsa_list_maxed", offsetof (T_CM_DB_EXEC_STAT, prior_lsa_list_maxed)},
  {"Num_prior_lsa_list_removed", offsetof (T_CM_DB_EXEC_STAT, prior_lsa_list_removed)},
  {"Num_heap_stats_bestspace_entries", offsetof (T_CM_DB_EXEC_STAT, hf_stats_bestspace_entries)},
  {"Num_heap_stats_bestspace_maxed", offsetof (T_CM_DB_EXEC_STAT, hf_stats_bestspace_maxed)},
  {"Time_ha_replication_delay", offsetof (T_CM_DB_EXEC_STAT, ha_repl_delay)},
  {"Num_plan_cache_add", offsetof (T_CM_DB_EXEC_STAT, pc_num_add)},
  {"Num_plan_cache_lookup", offsetof (T_CM_DB_EXEC_STAT, pc_num_lookup)},
  {"Num_plan_cache_hit", offsetof (T_CM_DB_EXEC_STAT, pc_num_hit)},
  {"Num_plan_cache_miss", offsetof (T_CM_DB_EXEC_STAT, pc_num_miss)},
  {"Num_plan_cache_full", offsetof (T_CM_DB_EXEC_STAT, pc_num_full)},
  {"Num_plan_cache_delete", offsetof (T_CM_DB_EXEC_STAT, pc_num_delete)},
  {"Num_plan_cache_invalid_xasl_id", offsetof (T_CM_DB_EXEC_STAT, pc_num_invalid_xasl_id)},
  {"Num_plan_cache_query_string_hash_entries", offsetof (T_CM_DB_EXEC_STAT, pc_num_query_string_hash_entries)},
  {"Num_plan_cache_xasl_id_hash_entries", offsetof (T_CM_DB_EXEC_STAT, pc_num_xasl_id_hash_entries)},
  {"Num_plan_cache_class_oid_hash_entries", offsetof (T_CM_DB_EXEC_STAT, pc_num_class_oid_hash_entries)},
  {"Num_vacuum_log_pages_vaccumed", offsetof (T_CM_DB_EXEC_STAT, vac_num_vacuumed_log_pages)},
  {"Num_vacuum_log_pages_to_vacuum", offsetof (T_CM_DB_EXEC_STAT, vac_num_to_vacuum_log_pages)},
  {"Num_vacuum_prefetch_requests_log_pages", offsetof (T_CM_DB_EXEC_STAT, vac_num_prefetch_requests_log_pages)},
  {"Num_vacuum_prefetch_hits_log_pages", offsetof (T_CM_DB_EXEC_STAT, vac_num_prefetch_hits_log_pages)},
  {"Num_heap_home_inserts", offsetof (T_CM_DB_EXEC_STAT, heap_home_inserts)},
  {"Num_heap_big_inserts", offsetof (T_CM_DB_EXEC_STAT, heap_big_inserts)},
  {"Num_heap_assign_inserts", offsetof (T_CM_DB_EXEC_STAT, heap_assign_inserts)},
  {"Num_heap_home_deletes", offsetof (T_CM_DB_EXEC_STAT, heap_home_deletes)},
  {"Num_heap_home_mvcc_deletes", offsetof (T_CM_DB_EXEC_STAT, heap_home_mvcc_deletes)},
  {"Num_heap_home_to_rel_deletes", offsetof (T_CM_DB_EXEC_STAT, heap_home_to_rel_deletes)},
  {"Num_heap_home_to_big_deletes", offsetof (T_CM_DB_EXEC_STAT, heap_home_to_big_deletes)},
  {"Num_heap_rel_deletes", offsetof (T_CM_DB_EXEC_STAT, heap_rel_deletes)},
  {"Num_heap_rel_mvcc_deletes", offsetof (T_CM_DB_EXEC_STAT, heap_rel_mvcc_deletes)},
  {"Num_heap_rel_to_home_deletes", offsetof (T_CM_DB_EXEC_STAT, heap_rel_to_home_deletes)},
  {"Num_heap_rel_to_big_deletes", offsetof (T_CM_DB_EXEC_STAT, heap_rel_to_big_deletes)},
  {"Num_heap_rel_to_rel_deletes", offsetof (T_CM_DB_EXEC_STAT, heap_rel_to_rel_deletes)},
  {"Num_heap_big_deletes", offsetof (T_CM_DB_EXEC_STAT, heap_big_deletes)},
  {"Num_heap_big_mvcc_deletes", offsetof (T_CM_DB_EXEC_STAT, heap_big_mvcc_deletes)},
  {"Num_heap_new_ver_inserts", offsetof (T_CM_DB_EXEC_STAT, heap_new_ver_inserts)},
  {"Num_heap_home_updates", offsetof (T_CM_DB_EXEC_STAT, heap_home_updates)},
  {"Num_heap_home_to_rel_updates", offsetof (T_CM_DB_EXEC_STAT, heap_home_to_rel_updates)},
  {"Num_heap_home_to_big_updates", offsetof (T_CM_DB_EXEC_STAT, heap_home_to_big_updates)},
  {"Num_heap_rel_updates", offsetof (T_CM_DB_EXEC_STAT, heap_rel_updates)},
  {"Num_heap_rel_to_home_updates", offsetof (T_CM_DB_EXEC_STAT, heap_rel_to_home_updates)},
  {"Num_heap_rel_to_rel_updates", offsetof (T_CM_DB_EXEC_STAT, heap_rel_to_rel_updates)},
  {"Num_heap_rel_to_big_updates", offsetof (T_CM_DB_EXEC_STAT, heap_rel_to_big_updates)},
  {"Num_heap_big_updates", offsetof (T_CM_DB_EXEC_STAT, heap_big_updates)},
  {"Num_heap_home_vacuums", offsetof (T_CM_DB_EXEC_STAT, heap_home_vacuums)},
  {"Num_heap_big_vacuums", offsetof (T_CM_DB_EXEC_STAT, heap_big_vacuums)},
  {"Num_heap_rel_vacuums", offsetof (T_CM_DB_EXEC_STAT, heap_rel_vacuums)},
  {"Num_heap_insid_vacuums", offsetof (T_CM_DB_EXEC_STAT, heap_insid_vacuums)},
  {"Num_heap_remove_vacuums", offsetof (T_CM_DB_EXEC_STAT, heap_remove_vacuums)},
  {"Num_heap_next_ver_vacuums", offsetof (T_CM_DB_EXEC_STAT, heap_next_ver_vacuums)},
  {"Time_heap_insert_prepare", offsetof (T_CM_DB_EXEC_STAT, heap_insert_prepare)},
  {"Time_heap_insert_execute", offsetof (T_CM_DB_EXEC_STAT, heap_insert_execute)},
  {"Time_heap_insert_log", offsetof (T_CM_DB_EXEC_STAT, heap_insert_log)},
  {"Time_heap_delete_prepare", offsetof (T_CM_DB_EXEC_STAT, heap_delete_prepare)},
  {"Time_heap_delete_execute", offsetof (T_CM_DB_EXEC_STAT, heap_delete_execute)},
  {"Time_heap_delete_log", offsetof (T_CM_DB_EXEC_STAT, heap_delete_log)},
  {"Time_heap_update_prepare", offsetof (T_CM_DB_EXEC_STAT, heap_update_prepare)},
  {"Time_heap_update_execute", offsetof (T_CM_DB_EXEC_STAT, heap_update_execute)},
  {"Time_heap_update_log", offsetof (T_CM_DB_EXEC_STAT, heap_update_log)},
  {"Time_heap_vacuum_prepare", offsetof (T_CM_DB_EXEC_STAT, heap_vacuum_prepare)},
  {"Time_heap_vacuum_execute", offsetof (T_CM_DB_EXEC_STAT, heap_vacuum_execute)},
  {"Time_heap_vacuum_log", offsetof (T_CM_DB_EXEC_STAT, heap_vacuum_log)},
  {"Num_bt_find_unique", offsetof (T_CM_DB_EXEC_STAT, bt_find_unique_cnt)},
  {"Num_bt_range_search", offsetof (T_CM_DB_EXEC_STAT, bt_range_search_cnt)},
  {"Num_bt_insert_obj", offsetof (T_CM_DB_EXEC_STAT, bt_insert_cnt)},
  {"Num_bt_delete_obj", offsetof (T_CM_DB_EXEC_STAT, bt_delete_cnt)},
  {"Num_bt_mvcc_delete", offsetof (T_CM_DB_EXEC_STAT, bt_mvcc_delete_cnt)},
  {"Num_bt_mark_delete", offsetof (T_CM_DB_EXEC_STAT, bt_mark_delete_cnt)},
  {"Num_bt_update_sk", offsetof (T_CM_DB_EXEC_STAT, bt_update_sk_cnt)},
  {"Num_bt_undo_insert", offsetof (T_CM_DB_EXEC_STAT, bt_undo_insert_cnt)},
  {"Num_bt_undo_delete", offsetof (T_CM_DB_EXEC_STAT, bt_undo_delete_cnt)},
  {"Num_bt_undo_mvcc_delete", offsetof (T_CM_DB_EXEC_STAT, bt_undo_mvcc_delete_cnt)},
  {"Num_bt_undo_update_sk", offsetof (T_CM_DB_EXEC_STAT, bt_undo_update_sk_cnt)},
  {"Num_bt_vacuum", offsetof (T_CM_DB_EXEC_STAT, bt_vacuum_cnt)},
  {"Num_bt_vacuum_insid", offsetof (T_CM_DB_EXEC_STAT, bt_vacuum_insid_cnt)},
  {"Num_bt_vacuum_update_sk", offsetof (T_CM_DB_EXEC_STAT, bt_vacuum_update_sk_cnt)},
  {"Num_bt_fix_ovf_oids", offsetof (T_CM_DB_EXEC_STAT, bt_fix_ovf_oids_cnt)},
  {"Num_bt_unique_rlocks", offsetof (T_CM_DB_EXEC_STAT, bt_unique_rlocks_cnt)},
  {"Num_bt_unique_wlocks", offsetof (T_CM_DB_EXEC_STAT, bt_unique_wlocks_cnt)},
  {"Time_bt_find_unique", offsetof (T_CM_DB_EXEC_STAT, bt_find_unique)},
  {"Time_bt_range_search", offsetof (T_CM_DB_EXEC_STAT, bt_range_search)},
  {"Time_bt_insert", offsetof (T_CM_DB_EXEC_STAT, bt_insert)},
  {"Time_bt_delete", offsetof (T_CM_DB_EXEC_STAT, bt_delete)},
  {"Time_bt_mvcc_delete", offsetof (T_CM_DB_EXEC_STAT, bt_mvcc_delete)},
  {"Time_bt_mark_delete", offsetof (T_CM_DB_EXEC_STAT, bt_mark_delete)},
  {"Time_bt_update_sk", offsetof (T_CM_DB_EXEC_STAT, bt_update_sk)},
  {"Time_bt_undo_insert", offsetof (T_CM_DB_EXEC_STAT, bt_undo_insert)},
  {"Time_bt_undo_delete", offsetof (T_CM_DB_EXEC_STAT, bt_undo_delete)},
  {"Time_bt_undo_mvcc_delete", offsetof (T_CM_DB_EXEC_STAT, bt_undo_mvcc_delete)},
  {"Time_bt_undo_update_sk", offsetof (T_CM_DB_EXEC_STAT, bt_undo_update_sk)},
  {"Time_bt_vacuum", offsetof (T_CM_DB_EXEC_STAT, bt_vacuum)},
  {"Time_bt_vacuum_insid", offsetof (T_CM_DB_EXEC_STAT, bt_vacuum_insid)},
  {"Time_bt_vacuum_update_sk", offsetof (T_CM_DB_EXEC_STAT, bt_vacuum_update_sk)},
  {"Time_bt_traverse", offsetof (T_CM_DB_EXEC_STAT, bt_traverse)},
  {"Time_bt_find_unique_traverse", offsetof (T_CM_DB_EXEC_STAT, bt_find_unique_traverse)},
  {"Time_bt_range_search_traverse", offsetof (T_CM_DB_EXEC_STAT, bt_range_search_traverse)},
  {"Time_bt_insert_traverse", offsetof (T_CM_DB_EXEC_STAT, bt_insert_traverse)},
  {"Time_bt_delete_traverse", offsetof (T_CM_DB_EXEC_STAT, bt_delete_traverse)},
  {"Time_bt_mvcc_delete_traverse", offsetof (T_CM_DB_EXEC_STAT, bt_mvcc_delete_traverse)},
  {"Time_bt_mark_delete_traverse", offsetof (T_CM_DB_EXEC_STAT, bt_mark_delete_traverse)},
  {"Time_bt_update_sk_traverse", offsetof (T_CM_DB_EXEC_STAT, bt_update_sk_traverse)},
  {"Time_bt_undo_insert_traverse", offsetof (T_CM_DB_EXEC_STAT, bt_undo_insert_traverse)},
  {"Time_bt_undo_delete_traverse", offsetof (T_CM_DB_EXEC_STAT, bt_undo_delete_traverse)},
  {"Time_bt_undo_mvcc_delete_traverse", offsetof (T_CM_DB_EXEC_STAT, bt_undo_mvcc_delete_traverse)},
  {"Time_bt_undo_update_sk_traverse", offsetof (T_CM_DB_EXEC_STAT, bt_undo_update_sk_traverse)},
  {"Time_bt_vacuum_traverse", offsetof (T_CM_DB_EXEC_STAT, bt_vacuum_traverse)},
  {"Time_bt_vacuum_insid_traverse", offsetof (T_CM_DB_EXEC_STAT, bt_vacuum_insid_traverse)},
  {"Time_bt_vacuum_update_sk_traverse", offsetof (T_CM_DB_EXEC_STAT, bt_vacuum_update_sk_traverse)},
  {"Time_bt_fix_ovf_oids", offsetof (T_CM_DB_EXEC_STAT, bt_fix_ovf_oids)},
  {"Time_bt_unique_rlocks", offsetof (T_CM_DB_EXEC_STAT, bt_unique_rlocks)},
  {"Time_bt_unique_wlocks", offsetof (T_CM_DB_EXEC_STAT, bt_unique_wlocks)},
  {"Time_vac_master", offsetof (T_CM_DB_EXEC_STAT, vac_master)},
  {"Time_vac_worker_process_log", offsetof (T_CM_DB_EXEC_STAT, vac_worker_process_log)},
  {"Time_vac_worker_execute", offsetof (T_CM_DB_EXEC_STAT, vac_worker_execute)},
  {"Data_page_buffer_hit_ratio", offsetof (T_CM_DB_EXEC_STAT, pb_hit_ratio)},
  {"Log_page_buffer_hit_ratio", offsetof (T_CM_DB_EXEC_STAT, log_hit_ratio)},
  {"Vacuum_data_page_buffer_hit_ratio", offsetof (T_CM_DB_EXEC_STAT, vacuum_data_hit_ratio)},
  {"Vacuum_page_efficiency_ratio", offsetof (T_CM_DB_EXEC_STAT, pb_vacuum_efficiency)},
  {"Vacuum_page_fetch_ratio", offsetof (T_CM_DB_EXEC_STAT, pb_vacuum_fetch_ratio)},
  {"Time_data_page_lock_acquire_time", offsetof (T_CM_DB_EXEC_STAT, pb_page_lock_acquire_time_msec)},
  {"Time_data_page_hold_acquire_time", offsetof (T_CM_DB_EXEC_STAT, pb_page_hold_acquire_time_msec)},
  {"Time_data_page_fix_acquire_time", offsetof (T_CM_DB_EXEC_STAT, pb_page_fix_acquire_time_msec)}
};

static uint64_t *
get_statdump_member_ptr (T_CM_DB_EXEC_STAT *stat, const char *prop_name)
{
  unsigned int i;
  for (i = 0; i < NELEMS (statdump_offset); i++)
    {
      if (strcmp (statdump_offset[i].prop_name, prop_name) == 0)
        {
          return (uint64_t *) ((char *) stat + statdump_offset[i].prop_offset);
        }
    }
  return NULL;
}

/*
 * extract_db_exec_stat () - EXTRACT_FUNC for cms_get_db_exec_stat (): parses
 * `cubrid statdump` output via the statdump_offset [] table above.
 */
static void *
extract_db_exec_stat (FILE *fp, const char *dbname, T_CM_ERROR *err_buf)
{
  char linebuf[LINE_MAX];
  char prop_name[100];
  T_CM_DB_EXEC_STAT *stat;
  stat = (T_CM_DB_EXEC_STAT *) calloc (1, sizeof (*stat));
  if (stat == NULL)
    {
      cms_set_error_oom (err_buf);
      return NULL;
    }
  while (fgets (linebuf, sizeof (linebuf), fp))
    {
      uint64_t *member_ptr;
      uint64_t prop_val;
      memset (prop_name, 0, sizeof (prop_name));
      sscanf (linebuf, "%99s%*s%" SCNu64, prop_name, &prop_val);
      member_ptr = get_statdump_member_ptr (stat, prop_name);
      if (!member_ptr)
        continue;
      *member_ptr = prop_val;
    }

  return stat;
}
