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
 * cm_cmd_exec.cpp -
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <config.h>

#if defined(WINDOWS)
#include <process.h>
#else
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "cm_config.h"
#include "cm_cmd_exec.h"
#include "cm_server_util.h"
#include "cm_stat.h"
#include "cm_autojob.h"
#include "cm_log.h"

#ifdef    _DEBUG_
#include "deb.h"
#endif

#define new_servstat_result()        (T_SERVER_STATUS_RESULT*) new_cmd_result()
#define new_csql_result()            (T_CSQL_RESULT*) new_cmd_result()

static T_CMD_RESULT *new_cmd_result (void);
static const char *get_cubrid_mode_opt (T_CUBRID_MODE mode);
static void read_spacedb_output (GeneralSpacedbResult *res, char *out_file);

static int read_start_server_output (char *stdout_log_file,
                                     char *stderr_log_file,
                                     char *_dbmt_error);

static int _size_to_byte_by_unit (double orgin_num, char unit);

static bool _child_exited_ok (int exit_code);
static void _fill_dbmt_error_from_errfile (const char *err_file, char *_dbmt_error);

/*
 * cubrid_cmd_name () - now defined in cm_server_status.cpp (still declared
 * in cm_cmd_exec.h, used here by cmd_csql ()/cmd_spacedb ()/
 * cmd_start_server () below exactly as before). moved out along with
 * cmd_cms_server_status ()
 */

T_CSQL_RESULT *
cmd_csql (char *dbname, char *uid, char *passwd, T_CUBRID_MODE mode,
          char *infile, char *command, char *error_continue)
{
  char cubrid_err_file[PATH_MAX];
  char out_file[PATH_MAX];
  T_CSQL_RESULT *res;
  char cmd_name[CUBRID_CMD_NAME_LEN];
  const char *argv[15];
  int argc = 0;

  cmd_name[0] = '\0';
  cubrid_err_file[0] = '\0';
#if !defined (DO_NOT_USE_CUBRIDENV)
  sprintf (cmd_name, "%s/%s%s", sco.szCubrid, CUBRID_DIR_BIN, UTIL_CSQL_NAME);
#else
  sprintf (cmd_name, "%s/%s", CUBRID_BINDIR, UTIL_CSQL_NAME);
#endif
  argv[argc++] = cmd_name;
  argv[argc++] = get_cubrid_mode_opt (mode);
  if (uid)
    {
      argv[argc++] = "--" CSQL_USER_L;
      argv[argc++] = uid;

      if (passwd)
        {
          argv[argc++] = "--" CSQL_PASSWORD_L;
          argv[argc++] = passwd;
        }
    }
  if (infile)
    {
      argv[argc++] = "--" CSQL_INPUT_FILE_L;
      argv[argc++] = infile;
    }
  else if (command)
    {
      argv[argc++] = "--" CSQL_COMMAND_L;
      argv[argc++] = command;
    }
  else
    {
      return NULL;
    }

  if (uStringEqualIgnoreCase (error_continue, "y"))
    {
      argv[argc++] = "--" CSQL_ERROR_CONTINUE_L;
    }

  argv[argc++] = dbname;
  argv[argc++] = NULL;

#if !defined (DO_NOT_USE_CUBRIDENV)
  gen_tempfile_path (out_file, sco.szCubrid, "DBMT_util", TS_CSQL_CMD, PATH_MAX);
#else
  gen_tempfile_path (out_file, CUBRID_TMPDIR, "DBMT_util", TS_CSQL_CMD, PATH_MAX);
#endif
  gen_tempfile_path (cubrid_err_file, sco.dbmt_tmp_dir, "cmd_csql_err", TS_CSQL_CMD, PATH_MAX);

  {
    const char *extra_envp[] = TRANSACTION_NO_WAIT_MODE_ENVP;

    run_child_env (argv, RUN_FOREGROUND, NULL, NULL, out_file, NULL, extra_envp);    /* csql */
  }

  res = new_csql_result ();
  if (res == NULL)
    {
      return NULL;
    }

  read_error_file (out_file, res->err_msg, ERR_MSG_SIZE);

  unlink (out_file);
  return res;
}

void find_and_parse_cub_admin_version (int &major_version, int &minor_version, char *build_version, size_t build_version_size)
{
  const char *argv[3];
  char tmpfile[PATH_MAX], strbuf[BUFFER_MAX_LEN];
  FILE *infile;
  char cmd_name[CUBRID_CMD_NAME_LEN];
  char *saveptr;
  int local_major = -1, local_minor = -1;
  char version[BUFFER_MAX_LEN];

  if (build_version != NULL && build_version_size > 0)
    {
      build_version[0] = '\0';
    }

  cubrid_cmd_name (cmd_name);
  if (gen_tempfile_path (tmpfile, sco.dbmt_tmp_dir, "cub_admin_version", TS_GET_SERVER_VERSION, PATH_MAX) < 0)
    {
      LOG_ERROR ("Unable to determine cubrid version due to a system error. Set version to %d.%d defined by default.",
                 cubrid_version_major, cubrid_version_minor);
      return;
    }
  argv[0] = cmd_name;
  argv[1] = "--version";
  argv[2] = NULL;

  if (run_child_env (argv, RUN_FOREGROUND, NULL, tmpfile, NULL, NULL) < 0)
    {
      LOG_ERROR ("Unable to determine cubrid version due to a system error. Set version to %d.%d defined by default.",
                 cubrid_version_major, cubrid_version_minor);
      unlink (tmpfile);
      return;
    }
  if ((infile = fopen (tmpfile, "r")) == NULL)
    {
      LOG_ERROR ("Unable to determine cubrid version due to a system error. Set version to %d.%d defined by default.",
                 cubrid_version_major, cubrid_version_minor);
      unlink (tmpfile);
      return;
    }

  if (!fgets (strbuf, sizeof (strbuf), infile) || ! fgets (strbuf, sizeof (strbuf), infile))
    {
      LOG_ERROR ("Unable to determine cubrid version due to a system error. Set version to %d.%d defined by default.",
                 cubrid_version_major, cubrid_version_minor);
      fclose (infile);
      unlink (tmpfile);
      return;
    }

  if (sscanf (strbuf, "%*s %64s", version) != 1)
    {
      LOG_ERROR ("Unable to parse cubrid version from '%s'. Set version to %d.%d defined by default.",
                 strbuf, cubrid_version_major, cubrid_version_minor);
      fclose (infile);
      unlink (tmpfile);
      return;
    }

  char *p = STRTOK (version, ".", &saveptr);
  if (p != NULL && is_positive_number (p))
    {
      local_major = atoi (p);
    }
  else
    {
      LOG_ERROR ("Unable to parse cubrid major version from '%s'. Set version to %d.%d defined by default.",
                 version, cubrid_version_major, cubrid_version_minor);
    }

  p = STRTOK (NULL, ".", &saveptr);
  if (p != NULL && is_positive_number (p))
    {
      local_minor = atoi (p);
    }
  else
    {
      LOG_ERROR ("Unable to parse cubrid minor version from '%s'. Set version to %d.%d defined by default.",
                 version, cubrid_version_major, cubrid_version_minor);
    }

  if (local_major > 0 && local_minor >= 0)
    {
      major_version = local_major;
      minor_version = local_minor;
    }

  if (build_version != NULL && build_version_size > 0)
    {
      char *lparen = strchr (strbuf, '(');
      if (lparen != NULL)
        {
          char *rparen = strchr (lparen + 1, ')');
          if (rparen != NULL && rparen > lparen + 1)
            {
              size_t len = (size_t) (rparen - (lparen + 1));
              if (len >= build_version_size)
                {
                  len = build_version_size - 1;
                }
              strncpy (build_version, lparen + 1, len);
              build_version[len] = '\0';
            }
        }
    }

  fclose (infile);
  unlink (tmpfile);
}

GeneralSpacedbResult *
cmd_spacedb (const char *dbname, T_CUBRID_MODE mode)
{
  GeneralSpacedbResult *res = NULL;
  char out_file[PATH_MAX];
  char cubrid_err_file[PATH_MAX];
  char cmd_name[CUBRID_CMD_NAME_LEN];
  char err_message[ERR_MSG_SIZE];
  const char *argv[10];
  int argc = 0;
  cubrid_err_file[0] = '\0';

  /*
   * To ensure thread safety, the running cubrid engine version is attempted only once.
   * If the cubrid engine version fails to be determined at startup,
   * the default version (currently 11.4) is assumed.
   */
  if (cubrid_version_major < 10 || (cubrid_version_major == 10 && cubrid_version_minor == 0))
    {
      res = new SpaceDbResultOldFormat();
    }
  else
    {
      res = new SpaceDbResultNewFormat();
    }

  gen_tempfile_path (out_file, sco.dbmt_tmp_dir, "DBMT_util", TS_DB_SPACE_INFO, PATH_MAX);
  cubrid_cmd_name (cmd_name);
  argv[argc++] = cmd_name;
  argv[argc++] = UTIL_OPTION_SPACEDB;
  argv[argc++] = get_cubrid_mode_opt (mode);
  argv[argc++] = "--" SPACE_SIZE_UNIT_L;
  argv[argc++] = "PAGE";
  argv[argc++] = "--" SPACE_OUTPUT_FILE_L;
  argv[argc++] = out_file;
  argv[argc++] = dbname;
  argv[argc++] = "-p";
  argv[argc++] = NULL;

  gen_tempfile_path (cubrid_err_file, sco.dbmt_tmp_dir, "cmd_spacedb_err", TS_DB_SPACE_INFO, PATH_MAX);
  run_child_env (argv, RUN_FOREGROUND, NULL, NULL, cubrid_err_file, NULL);    /* spacedb */
  read_error_file (cubrid_err_file, err_message, ERR_MSG_SIZE);
  res->set_err_msg (err_message);
  read_spacedb_output (res, out_file);
  if (access (cubrid_err_file, F_OK) == 0)
    {
      unlink (cubrid_err_file);
    }
  unlink (out_file);
  return res;
}


int
cmd_start_server (char *dbname, char *err_buf, int err_buf_size)
{
  char stdout_log_file[PATH_MAX];
  char stderr_log_file[PATH_MAX];
  int pid;
  int ret_val;
  char cmd_name[CUBRID_CMD_NAME_LEN];
  const char *argv[5];
  const char *extra_envp[3];
  int envc = 0;

#ifdef HPUX
  char jvm_env_string[32];
#endif

  cmd_start_master ();
  gen_tempfile_path (stdout_log_file, sco.dbmt_tmp_dir, "cmserverstart", TS_CMSERVERSTART, PATH_MAX);
  gen_tempfile_path (stderr_log_file, sco.dbmt_tmp_dir, "cmserverstart2", TS_CMSERVERSTART, PATH_MAX);

  cmd_name[0] = '\0';
#if !defined (DO_NOT_USE_CUBRIDENV)
  sprintf (cmd_name, "%s/%s%s", sco.szCubrid, CUBRID_DIR_BIN, UTIL_CUBRID);
#else
  sprintf (cmd_name, "%s/%s", CUBRID_BINDIR, UTIL_CUBRID);
#endif

  argv[0] = cmd_name;
  argv[1] = PRINT_CMD_SERVER;
  argv[2] = PRINT_CMD_START;
  argv[3] = dbname;
  argv[4] = NULL;

  extra_envp[envc++] = "CUBRID_ERROR_LOG=";    /* removing env variable CUBRID_ERROR_LOG if exists */

#ifdef HPUX
#ifdef HPUX_IA64
  strcpy (jvm_env_string, "LD_PRELOAD=libjvm.so");
#else /* pa-risc */
  strcpy (jvm_env_string, "LD_PRELOAD=libjvm.sl");
#endif
  extra_envp[envc++] = jvm_env_string;
#endif

  extra_envp[envc] = NULL;

  pid = run_child_env (argv, RUN_FOREGROUND, NULL, stdout_log_file, stderr_log_file, NULL, extra_envp);    /* start server */

  if (pid < 0)
    {
      if (err_buf)
        {
          sprintf (err_buf, "system error : %s %s %s %s", cmd_name, PRINT_CMD_SERVER, PRINT_CMD_START, dbname);
        }
      unlink (stdout_log_file);
      unlink (stderr_log_file);
      return -1;
    }

  ret_val =
    read_start_server_output (stdout_log_file, stderr_log_file, err_buf);
  unlink (stdout_log_file);
  unlink (stderr_log_file);

  return ret_val;
}

int
cmd_stop_server (char *dbname, char *err_buf, int err_buf_size)
{
  char strbuf[1024];
  int t, timeout = 30, interval = 3;    /* sec */
  char cmd_name[CUBRID_CMD_NAME_LEN];
  const char *argv[5];

  if (err_buf)
    {
      memset (err_buf, 0, err_buf_size);
    }

  cmd_name[0] = '\0';
#if !defined (DO_NOT_USE_CUBRIDENV)
  sprintf (cmd_name, "%s/%s%s", sco.szCubrid, CUBRID_DIR_BIN, UTIL_CUBRID);
#else
  sprintf (cmd_name, "%s/%s", CUBRID_BINDIR, UTIL_CUBRID);
#endif

  argv[0] = cmd_name;
  argv[1] = PRINT_CMD_SERVER;
  argv[2] = PRINT_CMD_STOP;
  argv[3] = dbname;
  argv[4] = NULL;
  if (run_child_env (argv, RUN_FOREGROUND, NULL, NULL, NULL, NULL) < 0)
    {
      /* stop_server */
      if (err_buf)
        {
          sprintf (strbuf, "Command returned error : %s %s %s %s", cmd_name,
                   PRINT_CMD_SERVER, PRINT_CMD_STOP, dbname);
          strncpy (err_buf, strbuf, err_buf_size - 1);
        }
      return -1;
    }

  for (t = timeout; t > 0; t -= interval)
    {
      SLEEP_MILISEC (interval, 0);
      if (!cms_is_database_active (dbname))
        {
          return 0;
        }
    }
  if (err_buf)
    {
      sprintf (strbuf, "%s server hasn't shut down after %d seconds", dbname, timeout);
      strncpy (err_buf, strbuf, err_buf_size - 1);
    }
  return -1;
}

void
cmd_start_master (void)
{
  int pid;
  char cmd_name[CUBRID_CMD_NAME_LEN];
  const char *argv[2];

  cmd_name[0] = '\0';
#if !defined (DO_NOT_USE_CUBRIDENV)
  sprintf (cmd_name, "%s/%s%s", sco.szCubrid,
           CUBRID_DIR_BIN, UTIL_MASTER_NAME);
#else
  sprintf (cmd_name, "%s/%s", CUBRID_BINDIR, UTIL_MASTER_NAME);
#endif
  argv[0] = cmd_name;
  argv[1] = NULL;

  pid = run_child_env (argv, RUN_BACKGROUND, NULL, NULL, NULL, NULL);    /* cub_master */
  SLEEP_MILISEC (0, 500);
}

/*
 * cub_jobsa_cmd_name () / cub_sainfo_cmd_name () - build the path to the
 * SA-mode helper executables
 */
static char *
cub_jobsa_cmd_name (char *buf)
{
  buf[0] = '\0';
#if !defined (DO_NOT_USE_CUBRIDENV)
  snprintf (buf, PATH_MAX, "%s/%scub_jobsa%s", sco.szCubrid, CUBRID_DIR_BIN, DBMT_EXE_EXT);
#else
  snprintf (buf, PATH_MAX, "%s/cub_jobsa%s", CUBRID_BINDIR, DBMT_EXE_EXT);
#endif
  return buf;
}

static char *
cub_sainfo_cmd_name (char *buf)
{
  buf[0] = '\0';
#if !defined (DO_NOT_USE_CUBRIDENV)
  snprintf (buf, PATH_MAX, "%s/%scub_sainfo%s", sco.szCubrid, CUBRID_DIR_BIN, DBMT_EXE_EXT);
#else
  snprintf (buf, PATH_MAX, "%s/cub_sainfo%s", CUBRID_BINDIR, DBMT_EXE_EXT);
#endif
  return buf;
}

/*
 * _child_exited_ok () - true if a run_child_env () (wait_flag ==
 * RUN_FOREGROUND) child both ran to completion and exited with status 0.
 *
 */
static bool
_child_exited_ok (int exit_code)
{
#if defined(WINDOWS)
  return (exit_code == 0);
#else
  return (WIFEXITED (exit_code) != 0 && WEXITSTATUS (exit_code) == 0);
#endif
}

/*
 * _fill_dbmt_error_from_errfile () -
 * fill _dbmt_error with err_file's content via read_error_file (),
 * or "unknown error" when err_file doesn't exist, or * empty
 */
static void
_fill_dbmt_error_from_errfile (const char *err_file, char *_dbmt_error)
{
  if (read_error_file (err_file, _dbmt_error, DBMT_ERROR_MSG_SIZE) == 0
      || _dbmt_error[0] == '\0')
    {
      strcpy_limit (_dbmt_error, "unknown error", DBMT_ERROR_MSG_SIZE);
    }
}

int
cmd_class_info_sa (const char *dbname, const char *uid, const char *passwd,
                   const char *cli_ver_val, nvplist *out, char *_dbmt_error)
{
  char strbuf[1024];
  char outfile[PATH_MAX], errfile[PATH_MAX];
  FILE *fp;
  int ret_val = ERR_NO_ERROR;
  char cmd_name[PATH_MAX];
  const char *argv[10];
  char cli_ver[10];
  char opcode[10];
  int major_ver, minor_ver;
  int exit_code = 0;
  const char *ver_str = (cli_ver_val != NULL) ? cli_ver_val : "1.0";
  const char *dot;

  if (uid == NULL)
    {
      uid = "";
    }
  if (passwd == NULL)
    {
      passwd = "";
    }

  if (gen_tempfile_path (outfile, sco.dbmt_tmp_dir, "DBMT_class_info", TS_CLASSINFO, PATH_MAX) < 0)
    {
      return ERR_GENERAL_ERROR;
    }
  if (snprintf (errfile, PATH_MAX - 1, "%s.err", outfile) < 0)
    {
      return ERR_GENERAL_ERROR;
    }
  unlink (outfile);
  unlink (errfile);

  major_ver = atoi (ver_str);
  dot = strchr (ver_str, '.');
  minor_ver = (dot != NULL) ? atoi (dot + 1) : 0;
  snprintf (cli_ver, sizeof (cli_ver), "%d", EMGR_MAKE_VER (major_ver, minor_ver));

  cub_jobsa_cmd_name (cmd_name);
  snprintf (opcode, sizeof (opcode), "%d", CMS_EMS_SA_CLASS_INFO);

  argv[0] = cmd_name;
  argv[1] = opcode;
  argv[2] = dbname;
  argv[3] = uid;
  argv[4] = passwd;
  argv[5] = outfile;
  argv[6] = errfile;
  argv[7] = cli_ver;
  argv[8] = NULL;

  if (run_child_env (argv, RUN_FOREGROUND, NULL, NULL, NULL, &exit_code) < 0)
    {
      strcpy_limit (_dbmt_error, argv[0], DBMT_ERROR_MSG_SIZE);
      unlink (outfile);
      unlink (errfile);
      return ERR_SYSTEM_CALL;
    }

  if (!_child_exited_ok (exit_code))
    {
      _fill_dbmt_error_from_errfile (errfile, _dbmt_error);
      ret_val = ERR_WITH_MSG;
      goto class_info_sa_finale;
    }

  fp = fopen (outfile, "r");
  if (fp == NULL)
    {
      strcpy_limit (_dbmt_error, "class_info", DBMT_ERROR_MSG_SIZE);
      ret_val = ERR_SYSTEM_CALL;
      goto class_info_sa_finale;
    }

  nv_add_nvp (out, "dbname", dbname);
  while (fgets (strbuf, sizeof (strbuf), fp))
    {
      char name[32], value[128];

      if (sscanf (strbuf, "%31s %127s", name, value) < 2)
        {
          continue;
        }
      nv_add_nvp (out, name, value);
    }
  fclose (fp);

class_info_sa_finale:
  unlink (outfile);
  unlink (errfile);
  return ret_val;
}

int
cmd_get_triggerinfo_sa (const char *dbname, const char *uid, const char *passwd,
                        nvplist *res, char *_dbmt_error)
{
  char outfile[PATH_MAX], errfile[PATH_MAX];
  int ret_val = ERR_NO_ERROR;
  char cmd_name[PATH_MAX];
  const char *argv[10];
  int exit_code = 0;

  if (uid == NULL)
    {
      uid = "";
    }
  if (passwd == NULL)
    {
      passwd = "";
    }

  if (gen_tempfile_path (outfile, sco.dbmt_tmp_dir, "DBMT_trigger_info", TS_GETTRIGGERINFO, PATH_MAX) < 0)
    {
      return ERR_GENERAL_ERROR;
    }
  if (snprintf (errfile, PATH_MAX - 1, "%s.err", outfile) < 0)
    {
      return ERR_GENERAL_ERROR;
    }
  unlink (outfile);
  unlink (errfile);

  cub_sainfo_cmd_name (cmd_name);

  argv[0] = cmd_name;
  argv[1] = dbname;
  argv[2] = uid;
  argv[3] = passwd;
  argv[4] = outfile;
  argv[5] = errfile;
  argv[6] = NULL;

  if (run_child_env (argv, RUN_FOREGROUND, NULL, NULL, NULL, &exit_code) < 0)
    {
      strcpy_limit (_dbmt_error, argv[0], DBMT_ERROR_MSG_SIZE);
      unlink (outfile);
      unlink (errfile);
      return ERR_SYSTEM_CALL;
    }

  if (!_child_exited_ok (exit_code))
    {
      _fill_dbmt_error_from_errfile (errfile, _dbmt_error);
      ret_val = ERR_WITH_MSG;
      goto trigger_info_sa_finale;
    }

  nv_add_nvp (res, "dbname", dbname);
  ret_val = nv_readfrom (res, outfile);

trigger_info_sa_finale:
  unlink (outfile);
  unlink (errfile);
  return ret_val;
}

int
cmd_optimizedb_sa (const char *dbname, const char *classname, char *_dbmt_error)
{
  char cmd_name[PATH_MAX];
  const char *argv[6];
  int argc = 0;
  int exit_code = 0;
  char cubrid_err_file[PATH_MAX];

  cubrid_cmd_name (cmd_name);

  if (gen_tempfile_path (cubrid_err_file, sco.dbmt_tmp_dir, "optimizedb", TS_OPTIMIZEDB, PATH_MAX) < 0)
    {
      strcpy_limit (_dbmt_error, "optimizedb", DBMT_ERROR_MSG_SIZE);
      return ERR_GENERAL_ERROR;
    }

  argv[argc++] = cmd_name;
  argv[argc++] = UTIL_OPTION_OPTIMIZEDB;
  if (classname != NULL)
    {
      argv[argc++] = "--" OPTIMIZE_CLASS_NAME_L;
      argv[argc++] = classname;
    }
  argv[argc++] = dbname;
  argv[argc++] = NULL;

  if (run_child_env (argv, RUN_FOREGROUND, NULL, NULL, cubrid_err_file, &exit_code) < 0)
    {
      strcpy_limit (_dbmt_error, argv[0], DBMT_ERROR_MSG_SIZE);
      unlink (cubrid_err_file);
      return ERR_SYSTEM_CALL;
    }

  if (!_child_exited_ok (exit_code))
    {
      _fill_dbmt_error_from_errfile (cubrid_err_file, _dbmt_error);
      unlink (cubrid_err_file);
      return ERR_WITH_MSG;
    }

  unlink (cubrid_err_file);
  return ERR_NO_ERROR;
}

int
read_csql_error_file (char *err_file, char *err_buf, int err_buf_size)
{
  FILE *fp;
  char buf[1024];
  int msg_size = 0;

  if (err_buf)
    {
      memset (err_buf, 0, err_buf_size);
    }

  if (err_file == NULL || err_file[0] == '\0')
    {
      return 0;
    }

  fp = fopen (err_file, "r");
  if (fp == NULL)
    {
      return 0;
    }

  while (1)
    {
      memset (buf, 0, sizeof (buf));
      if (fgets (buf, sizeof (buf) - 1, fp) == NULL)
        {
          break;
        }

      ut_trim (buf);

      if ((strncasecmp (buf, "ERROR", 5) == 0))
        {
          if (err_buf != NULL)
            {
              snprintf (err_buf, err_buf_size - 1, "%s", buf + 6);
            }
            msg_size = (int) strlen (buf + 6);
          break;
        }
      else if (strstr (buf, "*** ERROR") != NULL)
        {
          memset (buf, 0, sizeof (buf));
          if (fgets (buf, sizeof (buf) - 1, fp) == NULL)
            {
              break;
            }
          if (err_buf != NULL)
            {
              snprintf (err_buf, err_buf_size - 1, "%s", buf);
            }
            msg_size = (int) strlen (buf);
          break;
        }
    }

  fclose (fp);

  return (msg_size > 0 ? -1 : 0);
}

int
read_error_file (const char *err_file, char *err_buf, int err_buf_size)
{
  FILE *fp;
  char buf[1024];
  int msg_size = 0;
  char rm_prev_flag = 0;
  char is_debug = 0;
  size_t i;
  int append_end = 1;

  if (err_buf == NULL || err_file == NULL || err_file[0] == '\0'
      || err_buf_size == 0)
    {
      return 0;
    }

  if (err_buf_size < 0)
    {
      err_buf_size = DBMT_ERROR_MSG_SIZE;
      append_end = 0;
    }

  memset (err_buf, 0, err_buf_size);

  fp = fopen (err_file, "r");
  if (fp == NULL)
    {
      return 0;
    }

  while (1)
    {
      memset (buf, 0, sizeof (buf));
      if (fgets (buf, sizeof (buf) - 1, fp) == NULL)
        {
          break;
        }
      for (i = 0; i < sizeof (buf) - 2; i++)
        {
          if (buf[i] == '\0')
            {
              if (buf[i + 1] == '\0')
                {
                  break;
                }

              buf[i] = ' ';
            }
        }
      ut_trim (buf);
      if (buf[0] == '\0')
        {
          continue;
        }
      if (strncmp (buf, "---", 3) == 0 ||
          strncmp (buf, "***", 3) == 0 ||
          strncmp (buf, "<<<", 3) == 0 || strncmp (buf, "Time:", 5) == 0)
        {
          if (strstr (buf, "- DEBUG") != NULL)
            {
              is_debug = 1;
            }
          else
            {
              is_debug = 0;
              rm_prev_flag = 1;
            }
          continue;
        }
      /* ignore all the debug information, until find new line start with "---"|"***"|"<<<"|"Time:". */
      if (is_debug != 0)
        {
          continue;
        }

      if (rm_prev_flag != 0)
        {
          msg_size = 0;
        }

      if (append_end)
        {
          strcat (buf, "<end>");
        }

      if ((err_buf_size - msg_size - 1) > 0)
        {
          strncpy (err_buf + msg_size, buf, err_buf_size - msg_size - 1);
        }
      else
        {
          break;
        }
        msg_size += (int) strlen (buf);
      rm_prev_flag = 0;
    }
  err_buf[err_buf_size - 1] = '\0';
  fclose (fp);
  return (msg_size > 0 ? -1 : 0);
}

int
read_error_file2 (char *err_file, char *err_buf, int err_buf_size,
                  int *err_code)
{
  FILE *fp;
  char buf[1024];
  int found = 0;
  int success = 1;

  if (err_buf == NULL || err_file == NULL)
    {
      return 0;
    }

  err_buf[0] = 0;

  fp = fopen (err_file, "r");
  if (fp == NULL)
    {
      *err_code = 0;
      return 0;            /* not found error file */
    }

  while (1)
    {
      char *p = NULL;
      size_t len;
      if (fgets (buf, sizeof (buf), fp) == NULL)
        {
          break;
        }

      /* start with "ERROR: " */
      len = strlen (buf);
      if (len > 7 && memcmp (buf, "ERROR: ", 7) == 0)
        {
          /* ignore a newline character if it exists */
          if (buf[len - 1] == '\n')
            {
              len--;
            }
          len -= 7;

          if (len >= (size_t) err_buf_size)
            {
              len = (size_t) err_buf_size - 1;
            }

          memcpy (err_buf, buf + 7, len);
          err_buf[len] = 0;

          success = 0;
          continue;
        }

      /* find "CODE = " */
      p = strstr (buf, "CODE = ");
      if (p != NULL)
        {
          if (sscanf (p, "CODE = %d", err_code) != 1)
            {
              continue;
            }

          success = 0;
          found = 1;

          /* read error description */
          if (fgets (buf, sizeof (buf), fp) == NULL)
            {
              break;
            }

          len = strlen (buf);
          if (len > 0 && buf[len - 1] == '\n')
            {
              len--;
            }

          if (len >= (size_t) err_buf_size)
            {
              len = (size_t) err_buf_size - 1;
            }

          memcpy (err_buf, buf, len);
          err_buf[len] = 0;
        }
    }

  fclose (fp);

  if (success != 0)
    {
      *err_code = 0;
      return 0;
    }
  else if (found == 0)
    {
      *err_code = -1;
    }

  return -1;
}

static T_CMD_RESULT *
new_cmd_result (void)
{
  T_CMD_RESULT *res;

  res = (T_CMD_RESULT *) malloc (sizeof (T_CMD_RESULT));
  if (res == NULL)
    {
      return NULL;
    }
  memset (res, 0, sizeof (T_CMD_RESULT));
  return res;
}

static const char *
get_cubrid_mode_opt (T_CUBRID_MODE mode)
{
  if (mode == CUBRID_MODE_SA)
    {
      return ("--" CSQL_SA_MODE_L);
    }

  return ("--" CSQL_CS_MODE_L);
}

static bool is_valid_database_description (char *str)
{
  if (strncmp (str, "PERMANENT", 9) != 0 && strncmp (str, "TEMPORARY", 9) != 0)
    {
      return false;
    }

  return true;
}

static bool is_valid_volume_description (char *str)
{
  if (strstr (str, "PERMANENT") == NULL && strstr (str, "TEMPORARY") == NULL)
    {
      return false;
    }

  return true;
}

static bool is_valid_file_description (char *str)
{
  if (strncmp (str, "INDEX", 5) != 0 && strncmp (str, "HEAP", 4) != 0 &&
      strncmp (str, "SYSTEM", 6) != 0 && strncmp (str, "TEMP", 4) != 0)
    {
      return false;
    }

  return true;
}

static void
read_spacedb_output (GeneralSpacedbResult *res, char *out_file)
{
  FILE *fp;

  fp = fopen (out_file, "r");
  if (fp == NULL)
    {
      return;
    }

  res->read_spacedb_output (fp);
}

static int
read_start_server_output (char *stdout_file, char *stderr_file,
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
              if (strncmp (buf, "++", 2) == 0)
                {
                  if ((strp = strchr (buf, ':')) && strstr (strp, "fail"))
                    {
                      retval = -1;
                      break;
                    }
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
                len += (int) strlen (buf);
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
            {
              retval = 1;
            }
          fclose (fp2);
        }
    }

  return retval;
}

static int
_size_to_byte_by_unit (double orgin_num, char unit)
{
  switch (unit)
    {
    case 'B':
    case 'b':
      break;
    case 'K':
    case 'k':
      orgin_num *= BYTES_IN_K;
      break;
    case 'M':
    case 'm':
      orgin_num *= BYTES_IN_M;
      break;
    case 'G':
    case 'g':
      orgin_num *= BYTES_IN_G;
      break;
    default:
      /* if none of the above occur, return -1 to indicate error. */
      orgin_num = -1;
      break;
    }

  return (int) (orgin_num);
}

void SpaceDbResultNewFormat::add_volume (char *str_buf)
{
  char purpose[128], volume_name[PATH_MAX], type[32];
  struct stat statbuf;

  SpaceDbVolumeInfoNewFormat volume;
  sscanf (str_buf, "%d %s %s DATA %d %d %d %s", &volume.volid, type, purpose,
          &volume.used_size,
          &volume.free_size,
          &volume.total_size,
          volume_name);
  strcpy (volume.purpose, purpose);
  strcpy (volume.type, type);
  strcpy (volume.volume_name, volume_name);

  stat (volume_name, &statbuf);
  volume.date = statbuf.st_mtime;

  volumes.push_back (volume);
}

int SpaceDbResultOldFormat::get_volume_info (char *str_buf, SpaceDbVolumeInfoOldFormat &volume)
{
  int volid, total_page, free_page;
  char purpose[COLUMN_VALUE_MAX_SIZE], vol_name[PATH_MAX];
  char *token = NULL, *p;
  char *saveptr;
  struct stat statbuf;

  volid = total_page = free_page = 0;
  purpose[0] = vol_name[0] = '\0';

  token = STRTOK (str_buf, " ", &saveptr);
  if (token == NULL)
    {
      return FALSE;
    }
  volid = atoi (token);

  token = STRTOK (NULL, " ", &saveptr);
  if (token == NULL)
    {
      return FALSE;
    }
  strcpy (purpose, token);

  if (strcmp (purpose, "GENERIC") != 0 && strcmp (purpose, "DATA") != 0
      && strcmp (purpose, "INDEX") != 0 && strcmp (purpose, "TEMP") != 0)
    {
      return FALSE;
    }

  token = STRTOK (NULL, " ", &saveptr);
  if (token == NULL)
    {
      return FALSE;
    }

  if (strcmp (token, "TEMP") == 0)
    {
      if (strcmp (purpose, "TEMP") != 0)
        {
          return FALSE;
        }
      else
        {
          strcat (purpose, " ");
          strcat (purpose, token);
        }

      token = STRTOK (NULL, " ", &saveptr);
      if (token == NULL)
        {
          return FALSE;
        }
    }
  total_page = atoi (token);

  token = STRTOK (NULL, " ", &saveptr);
  if (token == NULL)
    {
      return FALSE;
    }
  free_page = atoi (token);

  token = STRTOK (NULL, "\n", &saveptr);
  if (token == NULL)
    {
      return FALSE;
    }
  strcpy (vol_name, token + 1);

  volume.volid = volid;
  volume.total_size = total_page;
  volume.free_size = free_page;
  strcpy (volume.purpose, purpose);

  stat (vol_name, &statbuf);
  volume.date = statbuf.st_mtime;

#if defined(WINDOWS)
  unix_style_path (vol_name);
#endif

  p = strrchr (vol_name, '/');
  if (p == NULL)
    {
      volume.location[0] = '\0';
      volume.vol_name[0] = '\0';
    }
  else
    {
      *p = '\0';
      snprintf (volume.location, sizeof (volume.location) - 1, "%s", vol_name);
      snprintf (volume.vol_name, sizeof (volume.vol_name) - 1, "%s", p + 1);
      *p = '/';
    }

  return TRUE;

}

void SpaceDbResultOldFormat::create_result (nvplist *res)
{
  nv_update_val_int (res, "pagesize", page_size);
  nv_update_val_int (res, "logpagesize", log_page_size);

  for (int i = 0; i < volumes.size(); i++)
    {
      nv_add_nvp (res, "open", "spaceinfo");
      nv_add_nvp (res, "spacename", volumes[i].vol_name);
      nv_add_nvp (res, "type", volumes[i].purpose);
      nv_add_nvp (res, "location", volumes[i].location);
      nv_add_nvp_int (res, "totalpage", volumes[i].total_size);
      nv_add_nvp_int (res, "freepage", volumes[i].free_size);
      ts_add_nvp_time (res, "date", volumes[i].date, "%04d%02d%02d",
                       NV_ADD_DATE);
      nv_add_nvp (res, "close", "spaceinfo");
    }

  for (int i = 0; i < temporary_volumes.size(); i++)
    {
      nv_add_nvp (res, "open", "spaceinfo");
      nv_add_nvp (res, "spacename", temporary_volumes[i].vol_name);
      nv_add_nvp (res, "type", temporary_volumes[i].purpose);
      nv_add_nvp (res, "location", temporary_volumes[i].location);
      nv_add_nvp_int (res, "totalpage", temporary_volumes[i].total_size);
      nv_add_nvp_int (res, "freepage", temporary_volumes[i].free_size);
      ts_add_nvp_time (res, "date", temporary_volumes[i].date, "%04d%02d%02d",
                       NV_ADD_DATE);
      nv_add_nvp (res, "close", "spaceinfo");
    }
}

void SpaceDbResultNewFormat::create_result (nvplist *res)
{
  nv_update_val_int (res, "pagesize", page_size);
  nv_update_val_int (res, "logpagesize", log_page_size);

  for (int i = 0; i < DATABASE_DESCRIPTION_NUM_LINES; i++)
    {
      nv_add_nvp (res, "open", "dbinfo");
      nv_add_nvp (res, "type", databaseSpaceDescriptions[i].type);
      nv_add_nvp (res, "purpose", databaseSpaceDescriptions[i].purpose);
      nv_add_nvp_int (res, "volume_count", databaseSpaceDescriptions[i].volume_count);
      nv_add_nvp_int (res, "used_size", databaseSpaceDescriptions[i].used_size);
      nv_add_nvp_int (res, "free_size", databaseSpaceDescriptions[i].free_size);
      nv_add_nvp_int (res, "total_size", databaseSpaceDescriptions[i].total_size);
      nv_add_nvp (res, "close", "dbinfo");
    }

  for (int i = 0; i < volumes.size(); i++)
    {
      nv_add_nvp (res, "open", "spaceinfo");
      nv_add_nvp (res, "type", volumes[i].type);
      nv_add_nvp (res, "purpose", volumes[i].purpose);
      nv_add_nvp (res, "location", volumes[i].volume_name);
      nv_add_nvp (res, "spacename", volumes[i].volume_name);
      nv_add_nvp_int (res, "volid", volumes[i].volid);
      nv_add_nvp_int (res, "usedpage", volumes[i].used_size);
      nv_add_nvp_int (res, "freepage", volumes[i].free_size);
      nv_add_nvp_int (res, "totalpage", volumes[i].total_size);
      ts_add_nvp_time (res, "date", volumes[i].date, "%04d%02d%02d",
                       NV_ADD_DATE);
      nv_add_nvp (res, "close", "spaceinfo");
    }

  for (int i = 0; i < FILES_DESCRIPTION_NUM_LINES; i++)
    {
      nv_add_nvp (res, "open", "fileinfo");
      nv_add_nvp (res, "data_type", fileSpaceDescriptions[i].data_type);
      nv_add_nvp_int (res, "file_count", fileSpaceDescriptions[i].file_count);
      nv_add_nvp_int (res, "used_size", fileSpaceDescriptions[i].used_size);
      nv_add_nvp_int (res, "file_table_size", fileSpaceDescriptions[i].file_table_size);
      nv_add_nvp_int (res, "reserved_size", fileSpaceDescriptions[i].reserved_size);
      nv_add_nvp_int (res, "total_size", fileSpaceDescriptions[i].total_size);
      nv_add_nvp (res, "close", "fileinfo");
    }
}

int SpaceDbResultOldFormat::get_cnt_tpage()
{
  int cnt_tpage = 0, i;

  for (i = 0; i < volumes.size(); i++)
    {
      cnt_tpage += volumes[i].total_size;
    }
  for (i = 0; i < temporary_volumes.size(); i++)
    {
      cnt_tpage += temporary_volumes[i].total_size;
    }

  return cnt_tpage;
}

int SpaceDbResultNewFormat::get_cnt_tpage()
{
  int cnt_tpage = 0;

  for (int i = 0; i < volumes.size(); i++)
    {
      cnt_tpage += volumes[i].total_size;
    }

  return cnt_tpage;
}

time_t SpaceDbResultOldFormat::get_my_time (char *dbloca)
{
  char strbuf[BUFFER_MAX_LEN];
  char volname[PATH_MAX] = { '\0' };
  time_t mytime = time (NULL);;
  struct stat statbuf;

  for (int i = 0; i < volumes.size(); i++)
    {
      if (uStringEqual (volumes[i].purpose, "DATA")
          || uStringEqual (volumes[i].purpose, "INDEX"))
        {
          strcpy (volname, volumes[i].vol_name);
          snprintf (strbuf, BUFFER_MAX_LEN, "%s/%s", dbloca, volname);
          if (!stat (strbuf, &statbuf))
            {
              mytime = statbuf.st_mtime;
            }
        }
    }

  return mytime;
}

time_t SpaceDbResultNewFormat::get_my_time (char *dbloca)
{
  char strbuf[BUFFER_MAX_LEN];
  char volname[PATH_MAX] = { '\0' };
  time_t mytime = time (NULL);;
  struct stat statbuf;

  for (int i = 0; i < volumes.size(); i++)
    {
      if (uStringEqual (volumes[i].purpose, "PERMANENT"))
        {
          strcpy (volname, volumes[i].volume_name);
          snprintf (strbuf, BUFFER_MAX_LEN, "%s/%s", dbloca, volname);
          if (!stat (strbuf, &statbuf))
            {
              mytime = statbuf.st_mtime;
            }
        }
    }

  return mytime;
}

void SpaceDbResultOldFormat::auto_add_volume (autoaddvoldb_node *curr, int db_mode, char *dbname_at_hostname)
{
  double frate;
  int page_add = curr->data_ext_page;
  if ((curr->data_vol) && (page_add > 0))
    {
      frate = ajFreeSpace (this, "DATA");
      if (page_add < MIN_AUTO_ADDVOL_PAGE_SIZE)
        {
          page_add = MIN_AUTO_ADDVOL_PAGE_SIZE;
        }
      if (curr->data_warn_outofspace >= frate)
        {
          if (db_mode == HA_MODE)
            {
              append_host_to_dbname (dbname_at_hostname, curr->dbname,
                                     sizeof (dbname_at_hostname));
              aj_add_volume (dbname_at_hostname, "data", page_add, page_size);
            }
          else
            {
              aj_add_volume (curr->dbname, "data", page_add, page_size);
            }
        }
    }

  page_add = curr->index_ext_page;
  if ((curr->index_vol) && (page_add > 0))
    {
      frate = ajFreeSpace (this, "INDEX");
      if (page_add < MIN_AUTO_ADDVOL_PAGE_SIZE)
        {
          page_add = MIN_AUTO_ADDVOL_PAGE_SIZE;
        }
      if (curr->index_warn_outofspace >= frate)
        {
          if (db_mode == HA_MODE)
            {
              append_host_to_dbname (dbname_at_hostname, curr->dbname,
                                     sizeof (dbname_at_hostname));
              aj_add_volume (dbname_at_hostname, "index", page_add, page_size);
            }
          else
            {
              aj_add_volume (curr->dbname, "index", page_add, page_size);
            }
        }
    }
}

void SpaceDbResultNewFormat::auto_add_volume (autoaddvoldb_node *curr, int db_mode, char *dbname_at_hostname)
{
  double frate;
  int page_add = curr->data_ext_page;
  if ((curr->data_vol) && (page_add > 0))
    {
      frate = ajFreeSpace (this, "PERMANENT");
      if (page_add < MIN_AUTO_ADDVOL_PAGE_SIZE)
        {
          page_add = MIN_AUTO_ADDVOL_PAGE_SIZE;
        }
      if (curr->data_warn_outofspace >= frate)
        {
          if (db_mode == 2)
            {
              append_host_to_dbname (dbname_at_hostname, curr->dbname,
                                     sizeof (dbname_at_hostname));
              aj_add_volume (dbname_at_hostname, "data", page_add, page_size);
            }
          else
            {
              aj_add_volume (curr->dbname, "data", page_add, page_size);
            }
        }
    }
}

void SpaceDbResultOldFormat::read_spacedb_output (FILE *fp)
{
  char str_buf[1024];
  int db_page_size = 0, log_page_size = 0;

  while (fgets (str_buf, sizeof (str_buf), fp))
    {
      char *tmp_p;

      ut_trim (str_buf);

      if (strncmp (str_buf, "Space", 5) == 0)
        {
          int matchs = 0;
          double page_size = 0.0;
          char page_unit = 'H';

          /*
          * The log format looks like the following:
          * Space description for database 'demodb' with pagesize 16.0K. (log pagesize: 16.0K)
          */
          tmp_p = strstr (str_buf, "pagesize");
          if (tmp_p == NULL)
            {
              goto spacedb_error;
            }

          if ((matchs =
                 sscanf (tmp_p, "pagesize %lf%c", &page_size, &page_unit)) != 2)
            {
              goto spacedb_error;
            }

          if ((db_page_size =
                 _size_to_byte_by_unit (page_size, page_unit)) < 0)
            {
              goto spacedb_error;
            }

          tmp_p = strstr (str_buf, "log pagesize:");
          if (tmp_p != NULL)
            {
              if ((matchs =
                     sscanf (tmp_p, "log pagesize: %lf%c", &page_size,
                             &page_unit)) != 2)
                {
                  goto spacedb_error;
                }

              if ((log_page_size =
                     _size_to_byte_by_unit (page_size, page_unit)) < 0)
                {
                  goto spacedb_error;
                }
            }
          else
            {
              /* log pagesize default value */
              log_page_size = 4096;
            }
        }

      else if (strncmp (str_buf, "Volid", 5) == 0)
        {
          break;
        }
    }

  while (fgets (str_buf, sizeof (str_buf), fp))
    {
      ut_trim (str_buf);
      if (str_buf[0] == '\0' || str_buf[0] == '-')
        {
          continue;
        }
      if (strncmp (str_buf, "Volid", 5) == 0)
        {
          break;
        }

      if (strncmp (str_buf, "Space", 5) == 0)
        {
          continue;
        }

      if (add_volume (str_buf))
        {
          continue;
        }
    }

  while (fgets (str_buf, sizeof (str_buf), fp))
    {
      ut_trim (str_buf);
      if (str_buf[0] == '\0' || str_buf[0] == '-')
        {
          continue;
        }
      if (strncmp (str_buf, "Volid", 5) == 0)
        {
          break;
        }

      if (add_temporary_volume (str_buf))
        {
          continue;
        }
    }
  set_page_size (db_page_size);
  set_log_page_size (log_page_size);

  fclose (fp);
  return;

spacedb_error:
  fclose (fp);
}

void SpaceDbResultNewFormat::read_spacedb_output (FILE *fp)
{
  char page_unit, log_page_unit, *p;
  double page_size, log_page_size_double;
  char str_buf[1024];
  int db_page_size = 0, log_page_size = 0;
  int index = 0;

  while (fgets (str_buf, sizeof (str_buf), fp))
    {
      ut_trim (str_buf);

      if (strncmp (str_buf, "Space", 5) == 0)
        {
          p = strstr (str_buf, "pagesize");
          if (p)
            {
              sscanf (p, "pagesize %lf%c", &page_size, &page_unit);
              if ((db_page_size =
                     _size_to_byte_by_unit (page_size, page_unit)) < 0)
                {
                  goto spacedb_error;
                }
              set_page_size (db_page_size);
            }
          p = strstr (str_buf, "log pagesize:");
          if (p)
            {
              sscanf (p, "log pagesize: %lf%c", &log_page_size_double, &log_page_unit);
              if ((log_page_size =
                     _size_to_byte_by_unit (log_page_size_double, log_page_unit)) < 0)
                {
                  goto spacedb_error;
                }
              set_log_page_size (log_page_size);
            }
        }
      if (strncmp (str_buf, "type", 4) == 0)
        {
          break;
        }
    }

  while (fgets (str_buf, sizeof (str_buf), fp))
    {
      ut_trim (str_buf);

      if (strncmp (str_buf, "Space", 5) == 0)
        {
          break;
        }
      if (!is_valid_database_description (str_buf))
        {
          break;
        }
      sscanf (str_buf, "%s %s DATA %d %d %d %d", databaseSpaceDescriptions[index].type,
              databaseSpaceDescriptions[index].purpose, &databaseSpaceDescriptions[index].volume_count,
              &databaseSpaceDescriptions[index].used_size,
              &databaseSpaceDescriptions[index].free_size,
              &databaseSpaceDescriptions[index].total_size);
      index++;
    }

  while (fgets (str_buf, sizeof (str_buf), fp))
    {
      ut_trim (str_buf);

      if (strncmp (str_buf, "Detailed", 8) == 0)
        {
          break;
        }

      if (!is_valid_volume_description (str_buf))
        {
          continue;
        }

      add_volume (str_buf);
    }

  while (fgets (str_buf, sizeof (str_buf), fp))
    {
      ut_trim (str_buf);

      if (strncmp (str_buf, "data_type", 9) == 0)
        {
          break;
        }
    }

  index = 0;

  while (fgets (str_buf, sizeof (str_buf), fp))
    {
      ut_trim (str_buf);

      if (!is_valid_file_description (str_buf))
        {
          continue;
        }

      sscanf (str_buf, "%s %d %d %d %d %d\n", fileSpaceDescriptions[index].data_type,
              &fileSpaceDescriptions[index].file_count,
              &fileSpaceDescriptions[index].used_size,
              &fileSpaceDescriptions[index].file_table_size,
              &fileSpaceDescriptions[index].reserved_size,
              &fileSpaceDescriptions[index].total_size);
      index++;
    }

  fclose (fp);
  return;

spacedb_error:
  fclose (fp);
}

