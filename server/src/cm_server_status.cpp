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
 * cm_server_status.cpp - cmd_cms_server_status () and the handful of
 * helpers it alone needs.
 *
 * all function which calls run_child () will be moved to CMS and will
 * be replaced by run_child_env (). This is because CMS will be built
 * so many CUBRID Engine versions, and we could remove Engine version
 * dependencies
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <config.h>

#if defined(WINDOWS)
#include <process.h>
#include <tlhelp32.h>
#else
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#endif

#include "cm_config.h"
#include "cm_cmd_exec.h"
#include "cm_server_util.h"
#include "cm_stat.h"

/*
 * "server"/"status" - the `cubrid` CLI subcommand and argument
 * cmd_cms_server_status () invokes (`cubrid server status`). the engine's
 * own cmd_server_status () gets these from PRINT_CMD_SERVER/PRINT_CMD_STATUS
 * in src/executables/utility.h, but that header is engine-internal and not
 * part of cm_common's public API, so they are just hardcoded here - same as
 * CMS's other cmd_* functions already hardcode their own CLI option strings
 * locally (e.g. CSQL_SA_MODE_L in cm_config.h) instead of pulling them from
 * the engine.
 */
#define CMS_PRINT_CMD_SERVER          "server"
#define CMS_PRINT_CMD_STATUS          "status"

static void read_server_status_output (T_SERVER_STATUS_RESULT *res,
                                       char *out_file);
#if defined(WINDOWS)
static int is_master_start (void);
#endif

/*
 * cubrid_cmd_name () - build the path to the `cubrid` CLI executable.
 * moved here (out of cm_cmd_exec.cpp) as-is: still used by cm_cmd_exec.cpp's
 * own cub_manager-only functions (cmd_csql (), cmd_spacedb (),
 * cmd_start_server (), ...) via the extern declaration in cm_cmd_exec.h,
 * exactly like before - only its defining translation unit changed, so it
 * gets compiled into (and is available to) both cm_admin and cub_manager.
 */
char *
cubrid_cmd_name (char *buf)
{
  buf[0] = '\0';
#if !defined (DO_NOT_USE_CUBRIDENV)
  snprintf (buf, PATH_MAX, "%s/%s%s", sco.szCubrid, CUBRID_DIR_BIN, UTIL_CUBRID);
#else
  snprintf (buf, PATH_MAX, "%s/%s", CUBRID_BINDIR, UTIL_CUBRID);
#endif
  return buf;
}

/*
 * is_master_start () - ported as-is from CUBRID engine's
 * cm_common/cm_utils.c of the same name. walks a process snapshot for
 * cub_master; returns 0 if it's running, -1 if not (or on error). used
 * only on Windows - see the comment where it's called below for why.
 */
#if defined(WINDOWS)
static int
is_master_start (void)
{
  HANDLE h_proc_snap;
  PROCESSENTRY32 pe32;
  int retval = -1;

  h_proc_snap = CreateToolhelp32Snapshot (TH32CS_SNAPPROCESS, 0);
  if (h_proc_snap == INVALID_HANDLE_VALUE)
    {
      return -1;
    }

  pe32.dwSize = sizeof (PROCESSENTRY32);

  if (Process32First (h_proc_snap, &pe32) == 0)
    {
      retval = -1;
      goto func_clean_return;
    }

  do
    {
      if (strcasecmp (pe32.szExeFile, UTIL_MASTER_NAME) == 0)
        {
          retval = 0;
          break;
        }
    }
  while (Process32Next (h_proc_snap, &pe32));

func_clean_return:
  CloseHandle (h_proc_snap);
  return retval;
}
#endif

/*
 * cmd_cms_server_status () - see the declaration comment in cm_cmd_exec.h.
 *
 * process-spawn goes through * run_child_env ()/gen_tempfile_path ()
 */
T_SERVER_STATUS_RESULT *
cmd_cms_server_status (void)
{
  T_SERVER_STATUS_RESULT *res;
  char out_file[PATH_MAX];
  char cmd_name[PATH_MAX];
  const char *argv[4];
  int exit_code = 0;

  res = (T_SERVER_STATUS_RESULT *) malloc (sizeof (T_SERVER_STATUS_RESULT));
  if (res == NULL)
    {
      return NULL;
    }
  memset (res, 0, sizeof (T_SERVER_STATUS_RESULT));

#if defined(WINDOWS)
  /*
   * ported as-is from the engine: on Windows, skip spawning `cubrid
   * server status` entirely when cub_master isn't running, and just
   * return the (empty) result.
   */
  if (is_master_start () != 0)
    {
      return res;
    }
#endif

  /*
   * task_code 0: this isn't tied to any single CMS TS_* task (it's called
   * from 4 different places), so there's no one TS_*
   * gen_tempfile_path () only uses task_code as part of the filename for
   * uniqueness/traceability, and thread-id/sequence/time already make
   * the name unique regardless of what's passed here.
   */
  if (gen_tempfile_path (out_file, sco.dbmt_tmp_dir, "DBMT_util_001", 0, PATH_MAX) < 0)
    {
      cmd_result_free (res);
      return NULL;
    }

  cubrid_cmd_name (cmd_name);

  argv[0] = cmd_name;
  argv[1] = CMS_PRINT_CMD_SERVER;
  argv[2] = CMS_PRINT_CMD_STATUS;
  argv[3] = NULL;

  /*
   * unlike cub_jobsa above, the `cubrid` CLI just writes to its own
   * stdout - run_child_env () redirects that to out_file itself (the
   * stdout_file parameter), rather than out_file being passed in argv[].
   */
  if (run_child_env (argv, RUN_FOREGROUND, NULL, out_file, NULL, &exit_code) < 0    /* cubrid server status */
      || !ut_child_exited_ok (exit_code))
    {
      unlink (out_file);
      cmd_result_free (res);
      return NULL;
    }

  read_server_status_output (res, out_file);

  unlink (out_file);
  return res;
}

/*
 * cms_is_database_active () - CMS-native port of CUBRID engine's
 * cm_common/cm_utils.c:uIsDatabaseActive ().
 *
 * returns 0 if dbn is not currently active,
 *         1 if active (non-HA),
 *         2 if active in HA mode
 */
int
cms_is_database_active (char *dbn)
{
  T_SERVER_STATUS_RESULT *cmd_res;
  int retval = 0;

  if (dbn == NULL)
    {
      return 0;
    }

  cmd_res = cmd_cms_server_status ();
  if (cmd_res != NULL)
    {
      retval = uIsDatabaseActive2 (cmd_res, dbn);
      cmd_servstat_result_free (cmd_res);
    }
  return retval;
}

/*
 * cms_database_mode () - CMS-native port of CUBRID engine's
 * cm_common/cm_utils.c:uDatabaseMode ().
 */
T_DB_SERVICE_MODE
cms_database_mode (char *dbname, int *ha_mode)
{
  int pid, retval;

  retval = cms_is_database_active (dbname);
  if (retval != 0)
    {
      if (ha_mode != NULL)
        {
          *ha_mode = (retval == 2) ? 1 : 0;
        }
      return DB_SERVICE_MODE_CS;
    }

  pid = get_db_server_pid (dbname);
  if (pid > 0)
    {
      if (kill (pid, 0) >= 0)
        {
          return DB_SERVICE_MODE_SA;
        }
    }
  return DB_SERVICE_MODE_NONE;
}

/*
 * read_server_status_output () - parse `cubrid server status` output into
 * ported as-is from CUBRID engine's cm_common
 */
static void
read_server_status_output (T_SERVER_STATUS_RESULT *res, char *out_file)
{
  T_SERVER_STATUS_INFO *info;
  int num_info, num_alloc;
  char str_buf[512];
  char tmp_str[64], db_name[64];
  FILE *fp;

  fp = fopen (out_file, "r");
  if (fp == NULL)
    {
      return;
    }

  num_info = 0;
  num_alloc = 5;
  info = (T_SERVER_STATUS_INFO *) malloc (sizeof (T_SERVER_STATUS_INFO) * num_alloc);
  if (info == NULL)
    {
      fclose (fp);
      return;
    }

  while (fgets (str_buf, sizeof (str_buf), fp))
    {
      char *tmp_p;

      if (sscanf (str_buf, "%63s %63s", tmp_str, db_name) < 2)
        {
          continue;
        }
      if (strcmp (tmp_str, "@") == 0 || (strcmp (tmp_str, "Server") != 0 && strcmp (tmp_str, "HA-Server") != 0))
        {
          continue;
        }

      tmp_p = strchr (db_name, ',');
      if (tmp_p != NULL)
        {
          *tmp_p = '\0';
        }

      num_info++;
      if (num_info > num_alloc)
        {
          num_alloc += 5;
          T_SERVER_STATUS_INFO *const new_info
            = (T_SERVER_STATUS_INFO *) realloc (info, sizeof (T_SERVER_STATUS_INFO) * num_alloc);
          if (new_info == NULL)
            {
              /*
               * realloc () failure doesn't touch the original block
               * so, everything parsed before realloc fail is valid
               */
              num_info--;
              break;
            }
          else
            {
              info = new_info;
            }
        }
      strcpy_limit (info[num_info - 1].db_name, db_name, sizeof (info[num_info - 1].db_name));
      info[num_info - 1].ha_mode = (strcmp (tmp_str, "HA-Server") == 0) ? 1 : 0;
    }
  fclose (fp);

  res->num_result = num_info;
  res->result = info;
}
