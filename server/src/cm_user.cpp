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
 * cm_user.cpp -
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#if defined(WINDOWS)
#include <process.h>
#else
#include <unistd.h>
#endif

#include "cm_porting.h"
#include "cm_config.h"
#include "cm_server_util.h"
#include "cm_user.h"

#define CUBRID_PASS_OPEN_TAG         "<<<:"
#define CUBRID_PASS_OPEN_TAG_LEN     strlen(CUBRID_PASS_OPEN_TAG)
#define CUBRID_PASS_CLOSE_TAG        ">>>:"
#define CUBRID_PASS_CLOSE_TAG_LEN    strlen(CUBRID_PASS_CLOSE_TAG)


T_USER_TOKEN_INFO *user_token_info = NULL;

int
dbmt_user_read (T_DBMT_USER *dbmt_user, char *_dbmt_error)
{
  file_resource_guard guard (*cm_cmdb_pass_mutex (), FID_LOCK_DBMT_PASS);
  if (!guard.ok ())
    {
      return ERR_TMPFILE_OPEN_FAIL;
    }

  return dbmt_user_read_locked (dbmt_user, _dbmt_error);
}

/* see the usage note on the declaration in cm_user.h */
int
dbmt_user_read_locked (T_DBMT_USER *dbmt_user, char *_dbmt_error)
{
  T_DBMT_USER_INFO *user_info = NULL;
  T_DBMT_USER_DBINFO *user_dbinfo = NULL;
  T_DBMT_USER_AUTHINFO *user_authinfo = NULL;
  int num_dbmt_user = 0;
  int num_dbinfo = 0;
  int num_authinfo = 0;
  char *authinfo[2];
  char *dbinfo[4];
  FILE *fp = NULL;
  char strbuf[1024];
  char cur_user[DBMT_USER_NAME_LEN];
  int retval = ERR_NO_ERROR;

  memset (dbmt_user, 0, sizeof (T_DBMT_USER));

  fp = fopen (conf_get_dbmt_file (FID_DBMT_CUBRID_PASS, strbuf), "r");
  if (fp == NULL)
    {
      strcpy (_dbmt_error,
	      conf_get_dbmt_file2 (FID_DBMT_CUBRID_PASS, strbuf));
      retval = ERR_FILE_OPEN_FAIL;
      goto read_dbmt_user_error;
    }

  memset (cur_user, 0, sizeof (cur_user));
  while (fgets (strbuf, sizeof (strbuf), fp))
    {
      ut_trim (strbuf);
      if (strncmp (strbuf, CUBRID_PASS_OPEN_TAG, CUBRID_PASS_OPEN_TAG_LEN) == 0)
	{
	  snprintf (cur_user, sizeof (cur_user) - 1, "%s", strbuf + CUBRID_PASS_OPEN_TAG_LEN);
	  if (cur_user[0] == '\0')
	    {
	      continue;
	    }

	  user_info =
		  (T_DBMT_USER_INFO *) increase_capacity (user_info,
		      sizeof (T_DBMT_USER_INFO), num_dbmt_user,
		      num_dbmt_user + 1);
	  if (user_info == NULL)
	    {
	      retval = ERR_MEM_ALLOC;
	      goto read_dbmt_user_error;
	    }
	  num_dbmt_user++;

	  /* user name set */
	  strcpy_limit (user_info[num_dbmt_user - 1].user_name, cur_user,
			DBMT_USER_NAME_LEN);
	  if (user_dbinfo != NULL)
	    {
	      free (user_dbinfo);
	      user_dbinfo = NULL;
	    }
	  num_dbinfo = 0;
	  num_authinfo = 0;
	  continue;
	}

      if (cur_user[0] == '\0')
	{
	  continue;
	}

      if (strncmp (strbuf, CUBRID_PASS_CLOSE_TAG, CUBRID_PASS_CLOSE_TAG_LEN) == 0)
	{
	  if (strcmp (strbuf + CUBRID_PASS_CLOSE_TAG_LEN, cur_user) != 0)
	    {
	      strcpy (_dbmt_error, conf_get_dbmt_file2 (FID_DBMT_CUBRID_PASS,
		      strbuf));
	      retval = ERR_FILE_INTEGRITY;
	      goto read_dbmt_user_error;
	    }
	  if (user_info != NULL)
	    {
	      user_info[num_dbmt_user - 1].dbinfo = user_dbinfo;
	      user_dbinfo = NULL;
	      user_info[num_dbmt_user - 1].num_dbinfo = num_dbinfo;

	      user_info[num_dbmt_user - 1].authinfo = user_authinfo;
	      user_authinfo = NULL;
	      user_info[num_dbmt_user - 1].num_authinfo = num_authinfo;
	    }
	  cur_user[0] = '\0';
	}
      else
	{
	  /* get authority info and database info */
	  if (string_tokenize2 (strbuf, authinfo, 2, ':') < 0)
	    {
	      continue;
	    }
	  else
	    {
	      if ((strcmp (authinfo[0], "dbc") == 0)
		  || (strcmp (authinfo[0], "dbo") == 0)
		  || (strcmp (authinfo[0], "brk") == 0)
		  || (strcmp (authinfo[0], "mon") == 0)
		  || (strcmp (authinfo[0], "job") == 0)
		  || (strcmp (authinfo[0], "var") == 0)
		  || (strcmp (authinfo[0], "user_auth") == 0)
		  || (strcmp (authinfo[0], "admin") == 0) ||
		  // for old cmdb.pass file.
		  (strcmp (authinfo[0], "unicas") == 0)
		  || (strcmp (authinfo[0], "dbcreate") == 0)
		  || (strcmp (authinfo[0], "statusmonitorauth") == 0))
		{
		  T_DBMT_USER_AUTHINFO tmp_authinfo;
		  memset (&tmp_authinfo, 0, sizeof (T_DBMT_USER_AUTHINFO));

		  dbmt_user_set_authinfo (&tmp_authinfo, authinfo[0], authinfo[1]);

		  user_authinfo =
			  (T_DBMT_USER_AUTHINFO *) increase_capacity (user_authinfo,
			      sizeof (T_DBMT_USER_AUTHINFO),
			      num_authinfo, num_authinfo + 1);
		  if (user_authinfo == NULL)
		    {
		      retval = ERR_MEM_ALLOC;
		      goto read_dbmt_user_error;
		    }
		  num_authinfo++;
		  user_authinfo[num_authinfo - 1] = tmp_authinfo;
		}
	      else
		{
		  T_DBMT_USER_DBINFO tmp_dbinfo;
		  memset (&tmp_dbinfo, 0, sizeof (T_DBMT_USER_DBINFO));

		  if (string_tokenize2 (authinfo[1], dbinfo, 3, ';') < 0)
		    {
		      continue;
		    }

		  /* 8.3.0 cmdb.pass not store dbpasswd. For compatibility,
		  * check if use older version cmdb.pass */
		  char *separator;
		  separator = dbinfo[3] = strchr (dbinfo[2], ';');
		  if (separator != NULL)
		    {
		      *separator = '\0';
		      dbinfo[3] = separator + 1;
		      dbmt_user_set_dbinfo (&tmp_dbinfo, authinfo[0],
					    dbinfo[0], dbinfo[1], dbinfo[3]);
		    }
		  else
		    {
		      dbmt_user_set_dbinfo (&tmp_dbinfo, authinfo[0],
					    dbinfo[0], dbinfo[1], dbinfo[2]);
		    }

		  user_dbinfo =
			  (T_DBMT_USER_DBINFO *) increase_capacity (user_dbinfo,
			      sizeof (T_DBMT_USER_DBINFO),
			      num_dbinfo, num_dbinfo + 1);
		  if (user_dbinfo == NULL)
		    {
		      retval = ERR_MEM_ALLOC;
		      goto read_dbmt_user_error;
		    }
		  num_dbinfo++;
		  user_dbinfo[num_dbinfo - 1] = tmp_dbinfo;
		}
	    }
	}
    }
  fclose (fp);
  fp = NULL;

  if (user_dbinfo != NULL)
    {
      free (user_dbinfo);
      user_dbinfo = NULL;
    }
  if (user_authinfo != NULL)
    {
      free (user_authinfo);
      user_authinfo = NULL;
    }

  if (num_dbmt_user < 1)
    {
      strcpy (_dbmt_error,
	      conf_get_dbmt_file2 (FID_DBMT_CUBRID_PASS, strbuf));
      retval = ERR_FILE_INTEGRITY;
      goto read_dbmt_user_error;
    }

  dbmt_user->num_dbmt_user = num_dbmt_user;
  dbmt_user->user_info = user_info;

  fp = fopen (conf_get_dbmt_file (FID_DBMT_PASS, strbuf), "r");
  if (fp == NULL)
    {
      strcpy (_dbmt_error, conf_get_dbmt_file2 (FID_DBMT_PASS, strbuf));
      retval = ERR_FILE_OPEN_FAIL;
      goto read_dbmt_user_error;
    }

  while (fgets (strbuf, sizeof (strbuf), fp))
    {
      char *tok[2];
      int i;

      ut_trim (strbuf);
      if (string_tokenize2 (strbuf, tok, 2, ':') < 0)
	{
	  continue;
	}
      for (i = 0; i < dbmt_user->num_dbmt_user; i++)
	{
	  if (strcmp (tok[0], dbmt_user->user_info[i].user_name) == 0)
	    {
	      snprintf (dbmt_user->user_info[i].user_passwd,
			sizeof (dbmt_user->user_info[i].user_passwd) - 1,
			"%s", tok[1]);
	      break;
	    }
	}
    }
  fclose (fp);

  return ERR_NO_ERROR;

read_dbmt_user_error:
  if (fp != NULL)
    {
      fclose (fp);
    }
  if (user_info != NULL)
    {
      free (user_info);
    }
  if (user_authinfo != NULL)
    {
      free (user_authinfo);
    }
  if (user_dbinfo != NULL)
    {
      free (user_dbinfo);
    }
  dbmt_user_free (dbmt_user);

  return retval;
}

void
dbmt_user_free (T_DBMT_USER *dbmt_user)
{
  int i;

  if (dbmt_user->user_info)
    {
      for (i = 0; i < dbmt_user->num_dbmt_user; i++)
	{
	  if (dbmt_user->user_info[i].dbinfo)
	    {
	      free (dbmt_user->user_info[i].dbinfo);
	    }
	  if (dbmt_user->user_info[i].authinfo)
	    {
	      free (dbmt_user->user_info[i].authinfo);
	    }
	}
      free (dbmt_user->user_info);
    }
}

int
dbmt_user_write_auth (T_DBMT_USER *dbmt_user, char *_dbmt_error)
{
  file_resource_guard guard (*cm_cmdb_pass_mutex (), FID_LOCK_DBMT_PASS);
  if (!guard.ok ())
    {
      return ERR_TMPFILE_OPEN_FAIL;
    }

  return dbmt_user_write_auth_locked (dbmt_user, _dbmt_error);
}

/* see the usage note on the declaration in cm_user.h */
int
dbmt_user_write_auth_locked (T_DBMT_USER *dbmt_user, char *_dbmt_error)
{
  FILE *fp;
  char tmpfile[PATH_MAX];
  int i, j;
  char strbuf[1024];

#if !defined (DO_NOT_USE_CUBRIDENV)
  gen_tempfile_path (tmpfile, sco.szCubrid, "DBMT_util_pass", TS_USER_WRITE_AUTH, PATH_MAX);
#else
  gen_tempfile_path (tmpfile, CUBRID_TMPDIR, "DBMT_util_pass", TS_USER_WRITE_AUTH, PATH_MAX);
#endif
  fp = fopen (tmpfile, "w");
  if (fp == NULL)
    {
      return ERR_TMPFILE_OPEN_FAIL;
    }
  for (i = 0; i < dbmt_user->num_dbmt_user; i++)
    {
      if (dbmt_user->user_info[i].user_name[0] == '\0')
	{
	  continue;
	}

      fprintf (fp, "%s%s\n", CUBRID_PASS_OPEN_TAG,
	       dbmt_user->user_info[i].user_name);
      for (j = 0; j < dbmt_user->user_info[i].num_authinfo; j++)
	{
	  if (dbmt_user->user_info[i].authinfo[j].domain[0] == '\0')
	    {
	      continue;
	    }
	  fprintf (fp, "%s:%s\n", dbmt_user->user_info[i].authinfo[j].domain,
		   dbmt_user->user_info[i].authinfo[j].auth);
	}
      for (j = 0; j < dbmt_user->user_info[i].num_dbinfo; j++)
	{
	  if (dbmt_user->user_info[i].dbinfo[j].dbname[0] == '\0')
	    {
	      continue;
	    }
	  fprintf (fp, "%s:%s;%s;%s\n",
		   dbmt_user->user_info[i].dbinfo[j].dbname,
		   dbmt_user->user_info[i].dbinfo[j].auth,
		   dbmt_user->user_info[i].dbinfo[j].uid,
		   dbmt_user->user_info[i].dbinfo[j].broker_address);
	}
      fprintf (fp, "%s%s\n", CUBRID_PASS_CLOSE_TAG,
	       dbmt_user->user_info[i].user_name);
    }
  fclose (fp);

  move_file (tmpfile, conf_get_dbmt_file (FID_DBMT_CUBRID_PASS, strbuf));

  return ERR_NO_ERROR;
}

void
dbmt_user_set_dbinfo (T_DBMT_USER_DBINFO *dbinfo, const char *dbname,
		      const char *auth, const char *uid,
		      const char *broker_address)
{
  strcpy_limit (dbinfo->dbname, dbname, sizeof (dbinfo->dbname));
  strcpy_limit (dbinfo->auth, auth, sizeof (dbinfo->auth));
  strcpy_limit (dbinfo->uid, uid, sizeof (dbinfo->uid));
  if (broker_address == NULL)
    {
      dbinfo->broker_address[0] = '\0';
    }
  else
    {
      strcpy_limit (dbinfo->broker_address, broker_address,
		    sizeof (dbinfo->broker_address));
    }
}

void
dbmt_user_set_authinfo (T_DBMT_USER_AUTHINFO *authinfo, const char *domain,
			const char *auth)
{
  strcpy_limit (authinfo->domain, domain, sizeof (authinfo->domain));
  strcpy_limit (authinfo->auth, auth, sizeof (authinfo->auth));
}

void
dbmt_user_set_userinfo (T_DBMT_USER_INFO *usrinfo, const char *user_name,
			const char *user_passwd, int num_authinfo,
			T_DBMT_USER_AUTHINFO *authinfo, int num_dbinfo,
			T_DBMT_USER_DBINFO *dbinfo)
{
  strcpy_limit (usrinfo->user_name, user_name, sizeof (usrinfo->user_name));
  strcpy_limit (usrinfo->user_passwd, user_passwd, sizeof (usrinfo->user_passwd));
  usrinfo->num_authinfo = num_authinfo;
  usrinfo->authinfo = authinfo;
  usrinfo->num_dbinfo = num_dbinfo;
  usrinfo->dbinfo = dbinfo;
}

int
dbmt_user_search (T_DBMT_USER_INFO *user_info, const char *dbname)
{
  int i;

  for (i = 0; i < user_info->num_dbinfo; i++)
    {
      if (strcmp (user_info->dbinfo[i].dbname, dbname) == 0)
	{
	  return i;
	}
    }

  return -1;
}

int
dbmt_user_write_pass (T_DBMT_USER *dbmt_user, char *_dbmt_error)
{
  file_resource_guard guard (*cm_cmdb_pass_mutex (), FID_LOCK_DBMT_PASS);
  if (!guard.ok ())
    {
      return ERR_TMPFILE_OPEN_FAIL;
    }

  return dbmt_user_write_pass_locked (dbmt_user, _dbmt_error);
}

/* see the usage note on the declaration in cm_user.h */
int
dbmt_user_write_pass_locked (T_DBMT_USER *dbmt_user, char *_dbmt_error)
{
  char tmpfile[PATH_MAX], strbuf[1024];
  FILE *fp;
  int i;

#if !defined (DO_NOT_USE_CUBRIDENV)
  gen_tempfile_path (tmpfile, sco.szCubrid, "DBMT_util_pass", TS_USER_WRITE_PASS, PATH_MAX);
#else
  gen_tempfile_path (tmpfile, CUBRID_TMPDIR, "DBMT_util_pass", TS_USER_WRITE_PASS, PATH_MAX);
#endif

  fp = fopen (tmpfile, "w");
  if (fp == NULL)
    {
      return ERR_TMPFILE_OPEN_FAIL;
    }
  for (i = 0; i < dbmt_user->num_dbmt_user; i++)
    {
      if (dbmt_user->user_info[i].user_name[0] == '\0')
	{
	  continue;
	}
      fprintf (fp, "%s:%s\n", dbmt_user->user_info[i].user_name,
	       dbmt_user->user_info[i].user_passwd);
    }
  fclose (fp);

  move_file (tmpfile, conf_get_dbmt_file (FID_DBMT_PASS, strbuf));

  return ERR_NO_ERROR;
}

void
dbmt_user_db_delete (T_DBMT_USER *dbmt_user, char *dbname)
{
  int i, j;

  for (i = 0; i < dbmt_user->num_dbmt_user; i++)
    {
      for (j = 0; j < dbmt_user->user_info[i].num_dbinfo; j++)
	{
	  if (strcmp (dbmt_user->user_info[i].dbinfo[j].dbname, dbname) == 0)
	    {
	      dbmt_user->user_info[i].dbinfo[j].dbname[0] = '\0';
	    }
	}
    }
}

int
dbmt_user_add_dbinfo (T_DBMT_USER_INFO *usrinfo, T_DBMT_USER_DBINFO *dbinfo)
{
  int i = usrinfo->num_dbinfo;

  usrinfo->dbinfo =
	  (T_DBMT_USER_DBINFO *) increase_capacity (usrinfo->dbinfo,
	      sizeof (T_DBMT_USER_DBINFO),
	      i, i + 1);
  if (usrinfo->dbinfo == NULL)
    {
      return ERR_MEM_ALLOC;
    }
  i++;
  usrinfo->num_dbinfo = i;
  for (i--; i >= 1; i--)
    {
      usrinfo->dbinfo[i] = usrinfo->dbinfo[i - 1];
    }
  usrinfo->dbinfo[0] = *dbinfo;

  return ERR_NO_ERROR;
}

/*
 * token_list_mutex ()/token_list_guard - guard user_token_info (the
 * in-memory circular linked list of active login tokens) against
 * concurrent access. It has two very different callers:
 *   - HTTP request threads read it (dbmt_user_search_token_info () and
 *     friends, via ext_ut_validate_token ()/ut_validate_token ()) while
 *     holding cm_mutex (cm_lock_guard in cm_server_interface.cpp).
 *   - "login"/"logout" run in their OWN per-request worker thread
 *     (registered in task_info [], not ext_task_info [] - see
 *     cm_execute_request_async () in cm_server_interface.cpp),
 *     completely outside cm_mutex, and insert/delete nodes.
 */
static mutex_t *
token_list_mutex (void)
{
  struct holder
  {
    mutex_t m;
    holder (void)
    {
      mutex_init (m);
    }
    ~holder (void)
    {
      mutex_destory (m);
    }
  };
  static holder h;

  return &h.m;
}

/*
 * token_list_guard - minimal RAII wrapper around token_list_mutex ().
 */
class token_list_guard
{
  public:
    token_list_guard (void)
    {
      mutex_lock (*token_list_mutex ());
    }

    ~token_list_guard (void)
    {
      mutex_unlock (*token_list_mutex ());
    }

  private:
    token_list_guard (const token_list_guard &);
    token_list_guard &operator= (const token_list_guard &);
};

/*
 * find_token_node_unlocked ()/find_token_node_by_token_unlocked () -
 * the actual list traversal, verbatim from before.
 */
static T_USER_TOKEN_INFO *
find_token_node_unlocked (const char *user_id)
{
  T_USER_TOKEN_INFO *head = user_token_info;

  if (user_id == NULL || head == NULL)
    {
      return NULL;
    }

  do
    {
      if (!strcmp (head->user_id, user_id))
	{
	  return head;
	}

      head = head->next;

    }
  while (head != user_token_info);

  return NULL;
}

static T_USER_TOKEN_INFO *
find_token_node_by_token_unlocked (const char *token)
{
  T_USER_TOKEN_INFO *head = user_token_info;

  if (token == NULL || head == NULL)
    {
      return NULL;
    }

  do
    {
      if (!strcmp (head->token, token))
	{
	  return head;
	}

      head = head->next;

    }
  while (head != user_token_info);

  return NULL;
}

/*
 * unlink_and_free_token_node_unlocked () - detach `node` from the
 * circular list.
 */
static void
unlink_and_free_token_node_unlocked (T_USER_TOKEN_INFO *node)
{
  if (node == user_token_info)
    {
      if (user_token_info->next != user_token_info)
	{
	  user_token_info = user_token_info->next;
	}
      else
	{
	  user_token_info = NULL;
	}
    }

  node->prev->next = node->next;
  node->next->prev = node->prev;

  free (node);
}

int
dbmt_user_new_token_info (const char *user_id,
			  const char *user_ip,
			  const char *user_port, const char *token_enc,
#ifdef WINDOWS
			  HANDLE proc_id,
#else
			  pid_t proc_id,
#endif
			  time_t login_time)
{
  T_USER_TOKEN_INFO *end_node;
  T_USER_TOKEN_INFO *new_node;

  token_list_guard guard;

  if (! (new_node = find_token_node_unlocked (user_id)))
    {
      new_node = (T_USER_TOKEN_INFO *) malloc (sizeof (T_USER_TOKEN_INFO));
      if (new_node == NULL)
	{
	  return ERR_MEM_ALLOC;
	}

      if (user_token_info == NULL)
	{
	  end_node = user_token_info = new_node;
	}
      else
	{
	  end_node = user_token_info->prev;
	}
      end_node->next = new_node;
      new_node->next = user_token_info;
      new_node->prev = end_node;
      user_token_info->prev = new_node;
    }

  strncpy (new_node->user_id, user_id, DBMT_USER_NAME_LEN);
  strncpy (new_node->user_ip, user_ip, 20);
  strncpy (new_node->user_port, user_port, 10);
  strncpy (new_node->token, token_enc, TOKEN_ENC_LENGTH);
  new_node->proc_id = proc_id;
  new_node->login_time = login_time;

  return ERR_NO_ERROR;
}

bool
dbmt_user_search_token_info (const char *user_id, T_USER_TOKEN_INFO *out)
{
  T_USER_TOKEN_INFO *node;

  if (user_id == NULL || out == NULL)
    {
      return false;
    }

  token_list_guard guard;

  node = find_token_node_unlocked (user_id);
  if (node == NULL)
    {
      if (user_token_info == NULL)
	{
	  ut_access_log (NULL, "user_token_info is null.");
	}
      return false;
    }

  *out = *node;
  return true;
}

bool
dbmt_user_search_token_info_by_token (const char *token, T_USER_TOKEN_INFO *out)
{
  T_USER_TOKEN_INFO *node;

  if (token == NULL || out == NULL)
    {
      return false;
    }

  token_list_guard guard;

  node = find_token_node_by_token_unlocked (token);
  if (node == NULL)
    {
      if (user_token_info == NULL)
	{
	  ut_access_log (NULL, "user_token_info is null.");
	}
      return false;
    }

  *out = *node;
  return true;
}

bool
dbmt_user_touch_token_login_time (const char *user_id, const char *token, time_t now_time)
{
  T_USER_TOKEN_INFO *node;

  if (user_id == NULL || token == NULL)
    {
      return false;
    }

  token_list_guard guard;

  node = find_token_node_unlocked (user_id);
  if (node == NULL || strcmp (node->token, token) != 0)
    {
      return false;
    }

  node->login_time = now_time;
  return true;
}

bool
dbmt_user_delete_token_info (const char *user_id)
{
  T_USER_TOKEN_INFO *removed_node = NULL;

  if (user_id == NULL)
    {
      return false;
    }

  token_list_guard guard;

  removed_node = find_token_node_unlocked (user_id);
  if (removed_node == NULL)
    {
      return false;
    }

  unlink_and_free_token_node_unlocked (removed_node);

  return true;
}

bool
dbmt_user_delete_token_info_by_token (const char *token)
{
  T_USER_TOKEN_INFO *removed_node = NULL;

  if (token == NULL)
    {
      return false;
    }

  token_list_guard guard;

  removed_node = find_token_node_by_token_unlocked (token);
  if (removed_node == NULL)
    {
      return false;
    }

  unlink_and_free_token_node_unlocked (removed_node);

  return true;
}
