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
 * cm_auto_task.cpp -
 */

#include <stdio.h>
#include <string.h>

#include "cm_auto_task.h"
#include "cm_porting.h"
#include "cm_dep.h"
#include "cm_server_util.h"
#include "cm_config.h"
#include "cm_user.h"
#include "cm_text_encryption.h"
#include "string.h"
#include "stdlib.h"

#if defined(WINDOWS)
#include <windows.h>
#else
#include <unistd.h>
#endif

#ifdef  _DEBUG_
#include "deb.h"
#endif

int
ts_validate_user (nvplist *req, nvplist *res, char *_dbmt_error)
{
  char *id, *passwd;
  char strbuf[1024];
  int retval, i;
  T_DBMT_USER dbmt_user;

  id = nv_get_val (req, "id");
  passwd = nv_get_val (req, "password");

  nv_update_val (res, "task", "authenticate");
  /* id, passwd checking */
  if (id == NULL)
    {
      sprintf (_dbmt_error, "%s", "parameter(id) is missing in request.");
      ut_error_log (req, "ID not specified in the request");
      return ERR_PARAM_MISSING;
    }

  if (passwd == NULL)
    {
      sprintf (_dbmt_error, "%s",
               "parameter(password) is missing in request.");
      ut_error_log (req, "password not specified in the request.");
      return ERR_PARAM_MISSING;
    }

  if (dbmt_user_read (&dbmt_user, strbuf) != ERR_NO_ERROR)
    {
      sprintf (_dbmt_error, "%s", "password file open error");
      ut_error_log (req, "Failed to read user info");
      return ERR_WITH_MSG;
    }

  retval = -1;
  for (i = 0; i < dbmt_user.num_dbmt_user; i++)
    {
      if (strcmp (dbmt_user.user_info[i].user_name, id) == 0)
        {
          char decrypted[PASSWD_LENGTH + 1];

          uDecrypt (PASSWD_LENGTH, dbmt_user.user_info[i].user_passwd,
                    decrypted);
          if (uStringEqual (passwd, decrypted))
            {
              nv_update_val (res, "status", "success");
              retval = ERR_NO_ERROR;
            }
          else
            {
              ut_error_log (req, "Incorrect password");
              sprintf (_dbmt_error, "Incorrect password");
              retval = ERR_WITH_MSG;
            }
          break;
        }
    }
  dbmt_user_free (&dbmt_user);

  if (retval < 0)
    {
      sprintf (_dbmt_error, "%s", "user not found.");
      ut_error_log (req, "User not found.");
      return ERR_WITH_MSG;
    }

  return retval;
}

int
ts_check_client_version (nvplist *req, nvplist *res)
{
  char *p;
  int major_ver, minor_ver;
  T_EMGR_VERSION clt_ver;

  major_ver = minor_ver = 0;
  p = nv_get_val (req, "clientver");
  if (p != NULL)
    {
      major_ver = atoi (p);
      p = strchr (p, '.');
      if (p != NULL)
        {
          minor_ver = atoi (p + 1);
        }
    }
  clt_ver = EMGR_MAKE_VER (major_ver, minor_ver);

  if (clt_ver < EMGR_MAKE_VER (1, 0))
    {
      nv_update_val (res, "status", "failure");
      nv_update_val (res, "note",
                     "Can not connect to the server due to version mismatch.");
      return 0;
    }

  return 1;
}

int
ts_check_already_connected (nvplist *cli_response, int max_index,
                            int current_index, T_CLIENT_INFO *client_info)
{
  int index = 0;
  for (index = 0; index <= max_index; index++)
    {
      if (IS_INVALID_SOCKET (client_info[index].sock_fd)
          || (index == current_index))
        {
          continue;
        }

      if (!strcmp (client_info[current_index].user_id, client_info[index].user_id))
        {
          char message[1024];
          sprintf (message,
                   "User %s was already connected from another client(%s)",
                   client_info[index].user_id, client_info[index].ip_address);

          nv_update_val (cli_response, "status", "failure");
          nv_update_val (cli_response, "note", message);
          return index;
        }
    }

  return -1;
}

int
ts_get_server_version (nvplist *req, nvplist *res)
{
  char tmpfile[PATH_MAX];
  char strbuf[1024];
  FILE *infile;
  char cmd_name[CUBRID_CMD_NAME_LEN];
  const char *argv[5];

  nv_update_val (res, "task", "getversion");
  snprintf (tmpfile, PATH_MAX - 1, "%s/DBMT_task_015", sco.dbmt_tmp_dir);

  cmd_name[0] = '\0';
  snprintf (cmd_name, sizeof (cmd_name) - 1, "%s/%s%s", sco.szCubrid,
            CUBRID_DIR_BIN, UTIL_CUBRID_REL_NAME);

  argv[0] = cmd_name;
  argv[1] = NULL;

  run_child (argv, 1, NULL, tmpfile, NULL, NULL);	/* cubrid_rel */

  if ((infile = fopen (tmpfile, "r")) != NULL)
    {
      fgets (strbuf, sizeof (strbuf), infile);
      fgets (strbuf, sizeof (strbuf), infile);
      uRemoveCRLF (strbuf);
      fclose (infile);
      unlink (tmpfile);
      nv_add_nvp (res, "CUBRIDVER", strbuf);
      nv_update_val (res, "status", "success");
    }
  else
    {
      nv_add_nvp (res, "CUBRIDVER", "none");
      nv_update_val (res, "status", "failure");
      nv_update_val (res, "note", "version information not available");
      return 0;
    }

  return 1;
}
