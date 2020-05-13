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
static void read_server_status_output (T_SERVER_STATUS_RESULT *res,
                                       char *out_file);
static void read_spacedb_output (GeneralSpacedbResult *res, char *out_file);

static int read_start_server_output (char *stdout_log_file,
                                     char *stderr_log_file,
                                     char *_dbmt_error);

static int _size_to_byte_by_unit (double orgin_num, char unit);

char *
cubrid_cmd_name (char *buf)
{
  buf[0] = '\0';
#if !defined (DO_NOT_USE_CUBRIDENV)
  sprintf (buf, "%s/%s%s", sco.szCubrid, CUBRID_DIR_BIN, UTIL_CUBRID);
#else
  sprintf (buf, "%s/%s", CUBRID_BINDIR, UTIL_CUBRID);
#endif
  return buf;
}

T_CSQL_RESULT *
cmd_csql (char *dbname, char *uid, char *passwd, T_CUBRID_MODE mode,
          char *infile, char *command, char *error_continue)
{
  char cubrid_err_file[PATH_MAX];
  char out_file[512];
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
  sprintf (out_file, "%s/tmp/DBMT_util_003.%d", sco.szCubrid,
           (int) getpid ());
#else
  sprintf (out_file, "%s/DBMT_util_003.%d", CUBRID_TMPDIR, (int) getpid ());
#endif
  snprintf (cubrid_err_file, PATH_MAX, "%s/%s.%u.err.tmp",
            sco.dbmt_tmp_dir, "cmd_csql", getpid ());
  SET_TRANSACTION_NO_WAIT_MODE_ENV ();

  run_child (argv, 1, NULL, NULL, out_file, NULL);    /* csql */

  res = new_csql_result ();
  if (res == NULL)
    {
      return NULL;
    }

  read_error_file (out_file, res->err_msg, ERR_MSG_SIZE);

  unlink (out_file);
  return res;
}

void find_and_parse_cub_admin_version (int &major_version, int &minor_version)
{
  const char *argv[3];
  char tmpfile[PATH_MAX], strbuf[BUFFER_MAX_LEN];
  FILE *infile;
  char cmd_name[CUBRID_CMD_NAME_LEN];

  cubrid_cmd_name (cmd_name);
  snprintf (tmpfile, PATH_MAX - 1, "%s/cub_admin_version", sco.dbmt_tmp_dir);
  argv[0] = cmd_name;
  argv[1] = "--version";
  argv[2] = NULL;

  run_child (argv, 1, NULL, tmpfile, NULL, NULL);
  if ((infile = fopen (tmpfile, "r")) != NULL)
    {
      if (!fgets (strbuf, sizeof (strbuf), infile) || ! fgets (strbuf, sizeof (strbuf), infile))
        {
           LOG_ERROR ("Spacedb is skipped due to temporalily insufficient resources");
           major_version = minor_version = -1;
           return;
        }
      char version[10];
      sscanf (strbuf, "%*s %s", version);

      char *p = strtok (version, ".");
      major_version = atoi (p);
      p = strtok (NULL, ".");
      minor_version = atoi (p);

      fclose (infile);
      unlink (tmpfile);
    }
  else
    {
      major_version = minor_version = -1;
    }
}

GeneralSpacedbResult *
cmd_spacedb (const char *dbname, T_CUBRID_MODE mode)
{
  GeneralSpacedbResult *res = NULL;
  int minor_version, major_version;
  char out_file[PATH_MAX];
  char cubrid_err_file[PATH_MAX];
  char cmd_name[CUBRID_CMD_NAME_LEN];
  char err_message[ERR_MSG_SIZE];
  const char *argv[10];
  int argc = 0;
  cubrid_err_file[0] = '\0';

  find_and_parse_cub_admin_version (major_version, minor_version);

  if (major_version < 10 || (major_version == 10 && minor_version == 0))
    {
      res = new SpaceDbResultOldFormat();
    }
  else
    {
      res = new SpaceDbResultNewFormat();
    }

  sprintf (out_file, "%s/DBMT_util_002.%d", sco.dbmt_tmp_dir,
           (int) getpid ());
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

  snprintf (cubrid_err_file, PATH_MAX, "%s/%s.%u.err.tmp",
            sco.dbmt_tmp_dir, "cmd_spacedb", getpid ());
  run_child (argv, 1, NULL, NULL, cubrid_err_file, NULL);    /* spacedb */
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
  char stdout_log_file[512];
  char stderr_log_file[512];
  int pid;
  int ret_val;
  char cmd_name[CUBRID_CMD_NAME_LEN];
  const char *argv[5];

#ifdef HPUX
  char jvm_env_string[32];
#endif

  cmd_start_master ();
  sprintf (stdout_log_file, "%s/cmserverstart.%d.err", sco.dbmt_tmp_dir,
           (int) getpid ());
  sprintf (stderr_log_file, "%s/cmserverstart2.%d.err", sco.dbmt_tmp_dir,
           (int) getpid ());


  /* unset CUBRID_ERROR_LOG environment variable, using default value */
#if defined(WINDOWS)
  _putenv ("CUBRID_ERROR_LOG=");
#else
  unsetenv ("CUBRID_ERROR_LOG");
#endif

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

#ifdef HPUX
#ifdef HPUX_IA64
  strcpy (jvm_env_string, "LD_PRELOAD=libjvm.so");
#else /* pa-risc */
  strcpy (jvm_env_string, "LD_PRELOAD=libjvm.sl");
#endif
  putenv (jvm_env_string);
#endif

  pid = run_child (argv, 1, NULL, stdout_log_file, stderr_log_file, NULL);    /* start server */

#ifdef HPUX
  putenv ("LD_PRELOAD=");
#endif

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
  if (run_child (argv, 1, NULL, NULL, NULL, NULL) < 0)
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
      if (!uIsDatabaseActive (dbname))
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

  pid = run_child (argv, 0, NULL, NULL, NULL, NULL);    /* cub_master */
  SLEEP_MILISEC (0, 500);
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

  if (err_buf == NULL || err_file == NULL || err_file[0] == '\0'
      || err_buf_size == 0)
    {
      return 0;
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
      strcat (buf, "<end>");
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
  struct stat statbuf;

  volid = total_page = free_page = 0;
  purpose[0] = vol_name[0] = '\0';

  token = strtok (str_buf, " ");
  if (token == NULL)
    {
      return FALSE;
    }
  volid = atoi (token);

  token = strtok (NULL, " ");
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

  token = strtok (NULL, " ");
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

      token = strtok (NULL, " ");
      if (token == NULL)
        {
          return FALSE;
        }
    }
  total_page = atoi (token);

  token = strtok (NULL, " ");
  if (token == NULL)
    {
      return FALSE;
    }
  free_page = atoi (token);

  token = strtok (NULL, "\n");
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

