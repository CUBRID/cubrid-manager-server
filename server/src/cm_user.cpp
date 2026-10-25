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

#include <map>
#include <string>
#include <utility>
#include <new>

#include "cm_porting.h"
#include "cm_config.h"
#include "cm_server_util.h"
#include "cm_user.h"

#define CUBRID_PASS_OPEN_TAG         "<<<:"
#define CUBRID_PASS_OPEN_TAG_LEN     strlen(CUBRID_PASS_OPEN_TAG)
#define CUBRID_PASS_CLOSE_TAG        ">>>:"
#define CUBRID_PASS_CLOSE_TAG_LEN    strlen(CUBRID_PASS_CLOSE_TAG)


int
dbmt_user_read (T_DBMT_USER *dbmt_user, char *_dbmt_error)
{
  /*
   * zero dbmt_user up front, before even trying the lock
   */
  memset (dbmt_user, 0, sizeof (T_DBMT_USER));

  file_resource_guard guard (*cm_cmdb_pass_mutex (), FID_LOCK_DBMT_PASS);
  if (!guard.ok ())
    {
      strcpy (_dbmt_error, "internal lock error");
      return ERR_WITH_MSG;
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

	  {
	    size_t new_size = sizeof (T_DBMT_USER_INFO) * (num_dbmt_user + 1);
	    T_DBMT_USER_INFO *tmp = (T_DBMT_USER_INFO *)
				    (user_info == NULL ? malloc (new_size) : realloc (user_info, new_size));

	    if (tmp == NULL)
	      {
		retval = ERR_MEM_ALLOC;
		goto read_dbmt_user_error;
	      }
	    memset (tmp + num_dbmt_user, 0, sizeof (T_DBMT_USER_INFO));
	    user_info = tmp;
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

  user_info = NULL;

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
      T_DBMT_USER tmp_user;
      tmp_user.num_dbmt_user = num_dbmt_user;
      tmp_user.user_info = user_info;
      dbmt_user_free (&tmp_user);
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
      strcpy (_dbmt_error, "internal lock error");
      return ERR_WITH_MSG;
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
      snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "%s", tmpfile);
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

  /*
   * a short write (e.g. a full disk) must not replace cmdb.pass with a
   * truncated copy, and a failed replace must reach the caller: tasks that
   * change a database report it as a warning that cmdb.pass needs a manual
   * check.
   */
  bool write_failed = (ferror (fp) != 0);
  if (fclose (fp) != 0)
    {
      write_failed = true;
    }
  if (write_failed)
    {
      unlink (tmpfile);
      snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "cannot write the new cmdb.pass to %s", tmpfile);
      LOG_ERROR ("dbmt_user_write_auth_locked : %s", _dbmt_error);
      return ERR_WITH_MSG;
    }

  if (move_file (tmpfile, conf_get_dbmt_file (FID_DBMT_CUBRID_PASS, strbuf)) != 0)
    {
      /* keep tmpfile: a failed copy fallback may have truncated cmdb.pass */
      /* the precisions keep the message within DBMT_ERROR_MSG_SIZE (-Wformat-truncation) */
      snprintf (_dbmt_error, DBMT_ERROR_MSG_SIZE, "cannot replace %.1000s; the new content is kept in %.3900s",
		strbuf, tmpfile);
      /*
       * callers such as createdb and copydb replace _dbmt_error with their own
       * warning, so the error log is where the kept file can be found
       */
      LOG_ERROR ("dbmt_user_write_auth_locked : %s", _dbmt_error);
      return ERR_WITH_MSG;
    }

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

static T_DBMT_USER_AUTHINFO *
find_authinfo (const T_DBMT_USER_INFO *usrinfo, const char *domain)
{
  for (int i = 0; i < usrinfo->num_authinfo; i++)
    {
      if (strcmp (usrinfo->authinfo[i].domain, domain) == 0)
	{
	  return &usrinfo->authinfo[i];
	}
    }
  return NULL;
}

static bool
authinfo_is (const T_DBMT_USER_INFO *usrinfo, const char *domain,
	     const char *value)
{
  T_DBMT_USER_AUTHINFO *ai = find_authinfo (usrinfo, domain);

  return ai != NULL && strcmp (ai->auth, value) == 0;
}

bool
dbmt_user_get_user_auth (const T_DBMT_USER_INFO *usrinfo, unsigned int *auth)
{
  T_DBMT_USER_AUTHINFO *ai;

  if (usrinfo == NULL)
    {
      return false;
    }

  ai = find_authinfo (usrinfo, "user_auth");
  if (ai == NULL)
    {
      return false;
    }

  if (auth != NULL)
    {
      *auth = (unsigned int) strtoul (ai->auth, NULL, 10);
    }
  return true;
}

unsigned int
dbmt_user_legacy_auth_bits (const T_DBMT_USER_INFO *usrinfo)
{
  unsigned int auth = 0;

  if (usrinfo == NULL)
    {
      return 0;
    }

  if (authinfo_is (usrinfo, "dbcreate", "admin"))
    {
      auth |= AU_DBC;
    }
  if (authinfo_is (usrinfo, "unicas", "admin"))
    {
      auth |= AU_BRK;
    }
  if (authinfo_is (usrinfo, "statusmonitorauth", "admin"))
    {
      auth |= AU_MON;
    }

  return auth;
}

unsigned int
dbmt_user_effective_auth (const T_DBMT_USER_INFO *usrinfo)
{
  unsigned int auth = 0;

  if (usrinfo == NULL)
    {
      return 0;
    }

  if (!dbmt_user_get_user_auth (usrinfo, &auth))
    {
      /* legacy account: no user_auth entry */
      auth = dbmt_user_legacy_auth_bits (usrinfo) | AU_DBO | AU_JOB;
    }

  if (strcmp (usrinfo->user_name, "admin") == 0)
    {
      auth |= AU_ADMIN;
    }

  return auth;
}

void
dbmt_user_sync_user_auth (T_DBMT_USER_INFO *usrinfo, unsigned int changed_mask)
{
  static const struct
  {
    unsigned int bit;
    const char *domain;
  } bit_domains[] =
  {
    {AU_DBC, "dbc"},
    {AU_BRK, "brk"},
    {AU_MON, "mon"}
  };
  T_DBMT_USER_AUTHINFO *ai;
  unsigned int auth, legacy;

  changed_mask &= (AU_DBC | AU_BRK | AU_MON);
  if (usrinfo == NULL || changed_mask == 0)
    {
      return;
    }

  ai = find_authinfo (usrinfo, "user_auth");
  if (ai == NULL)
    {
      return;
    }

  legacy = dbmt_user_legacy_auth_bits (usrinfo);
  auth = (unsigned int) strtoul (ai->auth, NULL, 10);
  auth = (auth & ~changed_mask) | (legacy & changed_mask);
  snprintf (ai->auth, sizeof (ai->auth), "%u", auth);

  for (size_t i = 0; i < sizeof (bit_domains) / sizeof (bit_domains[0]); i++)
    {
      if ((changed_mask & bit_domains[i].bit) == 0)
	{
	  continue;
	}
      ai = find_authinfo (usrinfo, bit_domains[i].domain);
      if (ai != NULL)
	{
	  strcpy_limit (ai->auth, (auth & bit_domains[i].bit) ? "yes" : "no",
			sizeof (ai->auth));
	}
    }
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
      strcpy (_dbmt_error, "internal lock error");
      return ERR_WITH_MSG;
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
 * Session store.
 *
 * Sessions live only here, in an in-memory map keyed by the (opaque) token.
 * Keying by token - not by user id - lets one user hold several sessions at
 * once. Each session also carries the DB-login information saved through
 * dbmtuserlogin, which is wiped when the session is removed.
 *
 * session_map_mutex ()/session_map_guard guard the map against concurrent
 * access. It has two very different callers:
 *   - HTTP request threads read it (dbmt_user_search_token_info_by_token ()
 *     and friends, via ext_ut_validate_token ()) while holding cm_mutex
 *     (cm_lock_guard in cm_server_interface.cpp).
 *   - "login"/"logout" run in their OWN per-request worker thread (registered
 *     in task_info [], not ext_task_info [] - see cm_execute_request_async ()
 *     in cm_server_interface.cpp), completely outside cm_mutex, and
 *     insert/delete entries.
 */

struct cm_session
{
  T_USER_TOKEN_INFO info;
  time_t last_access;
  /* dbname -> (db user, db password) saved by dbmtuserlogin */
  std::map<std::string, std::pair<std::string, std::string> > db_logins;
};

/* token -> session */
static std::map<std::string, cm_session> g_sessions;

static mutex_t *
session_map_mutex (void)
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
      /*
       * deliberately empty
       */
    }
  };
  static holder h;

  return &h.m;
}

/*
 * session_map_guard - minimal RAII wrapper around session_map_mutex ().
 */
class session_map_guard
{
  public:
    session_map_guard (void)
    {
      mutex_lock (*session_map_mutex ());
    }

    ~session_map_guard (void)
    {
      mutex_unlock (*session_map_mutex ());
    }

  private:
    session_map_guard (const session_map_guard &);
    session_map_guard &operator= (const session_map_guard &);
};

/*
 * wipe_string () - overwrite a string's contents before it is dropped, so a
 *   DB password does not linger in freed memory.
 */
static void
wipe_string (std::string &s)
{
  if (!s.empty ())
    {
      volatile char *p = const_cast<volatile char *> (s.data ());
      for (size_t i = 0; i < s.size (); ++i)
	{
	  p[i] = '\0';
	}
    }
  s.clear ();
}

static void
wipe_session_dblogins (cm_session &sess)
{
  std::map<std::string, std::pair<std::string, std::string> >::iterator it;
  for (it = sess.db_logins.begin (); it != sess.db_logins.end (); ++it)
    {
      wipe_string (it->second.first);
      wipe_string (it->second.second);
    }
  sess.db_logins.clear ();
}

/*
 * session_active_time_unlocked () - the configured token_active_time
 *   (seconds), or the 7200 default when it is unset/invalid.
 */
static time_t
session_active_time_unlocked (void)
{
  const char *v = sco.szTokenActiveTime;
  time_t t = 0;

  if (v != NULL)
    {
      t = (time_t) atol (v);
    }
  if (t <= 0)
    {
      t = 7200;
    }
  return t;
}

/*
 * session_max_per_user_unlocked () - the configured max_sessions_per_user
 *   (1 for one session per user).
 *   An invalid value stops CMS at startup (uCheckSystemConfig ()), so the
 *   clamp to [1, 64] here is only a safeguard.
 */
#define SESSION_MIN_PER_USER MIN_MAX_SESSIONS_PER_USER
#define SESSION_MAX_PER_USER MAX_MAX_SESSIONS_PER_USER
#define SESSION_DEFAULT_PER_USER DEFAULT_MAX_SESSIONS_PER_USER

static int
session_max_per_user_unlocked (void)
{
  int n = SESSION_DEFAULT_PER_USER;

  if (sco.szMaxSessionsPerUser[0] != '\0')
    {
      n = atoi (sco.szMaxSessionsPerUser);
    }
  if (n < SESSION_MIN_PER_USER)
    {
      n = SESSION_MIN_PER_USER;
    }
  if (n > SESSION_MAX_PER_USER)
    {
      n = SESSION_MAX_PER_USER;
    }
  return n;
}

/*
 * purge_expired_unlocked () - drop every session whose last_access is older
 *   than the active-time window.
 */
static void
purge_expired_unlocked (time_t now_time)
{
  time_t active_time = session_active_time_unlocked ();
  std::map<std::string, cm_session>::iterator it = g_sessions.begin ();

  while (it != g_sessions.end ())
    {
      if (now_time - it->second.last_access > active_time)
	{
	  wipe_session_dblogins (it->second);
	  g_sessions.erase (it++);
	}
      else
	{
	  ++it;
	}
    }
}

/*
 * evict_lru_if_over_limit_unlocked () - if user_id already holds the maximum
 *   number of sessions, remove that user's least-recently-used one so a new
 *   session can be added.
 */
static void
evict_lru_if_over_limit_unlocked (const char *user_id)
{
  int limit = session_max_per_user_unlocked ();
  int count = 0;
  std::map<std::string, cm_session>::iterator it;
  std::map<std::string, cm_session>::iterator lru = g_sessions.end ();

  for (it = g_sessions.begin (); it != g_sessions.end (); ++it)
    {
      if (strcmp (it->second.info.user_id, user_id) == 0)
	{
	  ++count;
	  if (lru == g_sessions.end ()
	      || it->second.last_access < lru->second.last_access)
	    {
	      lru = it;
	    }
	}
    }

  if (count >= limit && lru != g_sessions.end ())
    {
      wipe_session_dblogins (lru->second);
      g_sessions.erase (lru);
    }
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
  if (user_id == NULL || user_ip == NULL || user_port == NULL
      || token_enc == NULL)
    {
      return ERR_MEM_ALLOC;
    }

  session_map_guard guard;

  purge_expired_unlocked (login_time);
  evict_lru_if_over_limit_unlocked (user_id);

  std::map<std::string, cm_session>::iterator it;
  try
    {
      it = g_sessions.insert (std::make_pair (std::string (token_enc), cm_session ())).first;
    }
  catch (const std::bad_alloc &)
    {
      return ERR_MEM_ALLOC;
    }
  cm_session &sess = it->second;

  memset (&sess.info, 0, sizeof (sess.info));
  strncpy (sess.info.user_id, user_id, sizeof (sess.info.user_id) - 1);
  strncpy (sess.info.user_ip, user_ip, sizeof (sess.info.user_ip) - 1);
  strncpy (sess.info.user_port, user_port, sizeof (sess.info.user_port) - 1);
  strncpy (sess.info.token, token_enc, sizeof (sess.info.token) - 1);
  sess.info.proc_id = proc_id;
  sess.info.login_time = login_time;
  sess.last_access = login_time;

  return ERR_NO_ERROR;
}

bool
dbmt_user_search_token_info_by_token (const char *token, T_USER_TOKEN_INFO *out)
{
  if (token == NULL || out == NULL)
    {
      return false;
    }

  session_map_guard guard;

  std::map<std::string, cm_session>::iterator it = g_sessions.find (token);
  if (it == g_sessions.end ())
    {
      return false;
    }

  *out = it->second.info;
  return true;
}

bool
dbmt_user_touch_token_login_time_by_token (const char *token, time_t now_time)
{
  if (token == NULL)
    {
      return false;
    }

  session_map_guard guard;

  std::map<std::string, cm_session>::iterator it = g_sessions.find (token);
  if (it == g_sessions.end ())
    {
      return false;
    }

  it->second.info.login_time = now_time;
  it->second.last_access = now_time;
  return true;
}

bool
dbmt_user_delete_token_info_by_token (const char *token)
{
  if (token == NULL)
    {
      return false;
    }

  session_map_guard guard;

  std::map<std::string, cm_session>::iterator it = g_sessions.find (token);
  if (it == g_sessions.end ())
    {
      return false;
    }

  wipe_session_dblogins (it->second);
  g_sessions.erase (it);
  return true;
}

int
dbmt_user_delete_all_sessions_of_user (const char *user_id)
{
  int removed = 0;

  if (user_id == NULL)
    {
      return 0;
    }

  session_map_guard guard;

  std::map<std::string, cm_session>::iterator it = g_sessions.begin ();
  while (it != g_sessions.end ())
    {
      if (strcmp (it->second.info.user_id, user_id) == 0)
	{
	  wipe_session_dblogins (it->second);
	  g_sessions.erase (it++);
	  ++removed;
	}
      else
	{
	  ++it;
	}
    }

  return removed;
}

bool
dbmt_user_session_set_dblogin (const char *token, const char *dbname,
			       const char *dbuser, const char *dbpasswd)
{
  if (token == NULL || dbname == NULL || dbuser == NULL || dbpasswd == NULL)
    {
      return false;
    }

  session_map_guard guard;

  std::map<std::string, cm_session>::iterator it = g_sessions.find (token);
  if (it == g_sessions.end ())
    {
      return false;
    }

  std::pair<std::string, std::string> &cred = it->second.db_logins[dbname];
  wipe_string (cred.first);
  wipe_string (cred.second);
  cred.first = dbuser;
  cred.second = dbpasswd;
  return true;
}

bool
dbmt_user_session_get_dblogin (const char *token, const char *dbname,
			       char *dbuser, size_t dbuser_size,
			       char *dbpasswd, size_t dbpasswd_size)
{
  if (token == NULL || dbname == NULL
      || dbuser == NULL || dbpasswd == NULL
      || dbuser_size == 0 || dbpasswd_size == 0)
    {
      return false;
    }

  session_map_guard guard;

  std::map<std::string, cm_session>::iterator it = g_sessions.find (token);
  if (it == g_sessions.end ())
    {
      return false;
    }

  std::map<std::string, std::pair<std::string, std::string> >::iterator dit =
	  it->second.db_logins.find (dbname);
  if (dit == it->second.db_logins.end ())
    {
      return false;
    }

  strncpy (dbuser, dit->second.first.c_str (), dbuser_size - 1);
  dbuser[dbuser_size - 1] = '\0';
  strncpy (dbpasswd, dit->second.second.c_str (), dbpasswd_size - 1);
  dbpasswd[dbpasswd_size - 1] = '\0';
  return true;
}
