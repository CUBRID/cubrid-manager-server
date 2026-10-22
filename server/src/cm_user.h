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
 * cm_user.h -
 */

#ifndef _CM_USER_H_
#define _CM_USER_H_

#define DBMT_USER_NAME_LEN 64

typedef struct
{
  char dbname[DBMT_USER_NAME_LEN];
  char auth[16];
  char uid[32];
  char broker_address[64];
} T_DBMT_USER_DBINFO;

typedef struct
{
  char domain[DBMT_USER_NAME_LEN];
  char auth[16];
} T_DBMT_USER_AUTHINFO;

typedef struct
{
  char user_name[DBMT_USER_NAME_LEN];
  char user_passwd[80];
  int num_authinfo;
  int num_dbinfo;
  T_DBMT_USER_AUTHINFO *authinfo;
  T_DBMT_USER_DBINFO *dbinfo;
} T_DBMT_USER_INFO;

typedef struct
{
  int num_dbmt_user;
  T_DBMT_USER_INFO *user_info;
} T_DBMT_USER;

typedef struct T_USER_TOKEN_INFO T_USER_TOKEN_INFO;

/*
 * T_USER_TOKEN_INFO - one CMS session.
 *
 * Sessions live only in the in-memory session map keyed by token (see
 * cm_user.cpp); the same user may hold several sessions at once. DB-login
 * information supplied through dbmtuserlogin is kept per session in the C++
 * session object (not in this plain struct), which callers reach through the
 * dbmt_user_session_* helpers below. This struct is the value copied out to
 * callers that only need the connection fields.
 */
struct T_USER_TOKEN_INFO
{
  char user_id[DBMT_USER_NAME_LEN];
  char user_ip[20];
  char user_port[10];
#ifdef WINDOWS
  HANDLE proc_id;
#else
  pid_t proc_id;
#endif
  time_t login_time;

  char token[TOKEN_ENC_LENGTH];
};

int dbmt_user_read (T_DBMT_USER *dbmt_user, char *_dbmt_error);
void dbmt_user_free (T_DBMT_USER *dbmt_user);
int dbmt_user_write_auth (T_DBMT_USER *dbmt_user, char *_dbmt_error);
int dbmt_user_write_pass (T_DBMT_USER *dbmt_user, char *_dbmt_error);

/*
 * dbmt_user_read_locked ()/dbmt_user_write_auth_locked ()/
 * dbmt_user_write_pass_locked () - the caller must already hold
 *   a file_resource_guard on cm_cmdb_pass_mutex () (FID_LOCK_DBMT_PASS) for
 *   the whole read-modify-write sequence, not just for each individual call.
 *   usage:
 *     file_resource_guard guard (*cm_cmdb_pass_mutex (), FID_LOCK_DBMT_PASS);
 *     if (guard.ok () && dbmt_user_read_locked (&dbmt_user, _dbmt_error) == ERR_NO_ERROR)
 *       {
 *         ... modify dbmt_user in memory ...
 *         dbmt_user_write_auth_locked (&dbmt_user, _dbmt_error);
 *       }
 */
int dbmt_user_read_locked (T_DBMT_USER *dbmt_user, char *_dbmt_error);
int dbmt_user_write_auth_locked (T_DBMT_USER *dbmt_user, char *_dbmt_error);
int dbmt_user_write_pass_locked (T_DBMT_USER *dbmt_user, char *_dbmt_error);
void dbmt_user_set_dbinfo (T_DBMT_USER_DBINFO *dbinfo, const char *dbname,
			   const char *auth, const char *uid, const char *broker_address);
void dbmt_user_set_authinfo (T_DBMT_USER_AUTHINFO *authinfo,
			     const char *domain, const char *auth);
void dbmt_user_set_userinfo (T_DBMT_USER_INFO *usrinfo,
			     const char *user_name, const char *user_passwd,
			     int num_authinfo, T_DBMT_USER_AUTHINFO *authinfo,
			     int num_dbinfo, T_DBMT_USER_DBINFO *dbinfo);
int dbmt_user_search (T_DBMT_USER_INFO *user_info, const char *dbname);
void dbmt_user_db_delete (T_DBMT_USER *dbmt_user, char *dbname);
int dbmt_user_add_dbinfo (T_DBMT_USER_INFO *usrinfo,
			  T_DBMT_USER_DBINFO *dbinfo);

/*
 * dbmt_user_new_token_info () - add a new session keyed by token_enc.
 *   Several sessions may exist for the same user_id. Expired sessions are
 *   purged first; if the user is already at the per-user limit the
 *   least-recently-used session of that user is evicted to make room.
 *   return: ERR_NO_ERROR, or ERR_MEM_ALLOC on failure.
 */
int dbmt_user_new_token_info (const char *user_id,
			      const char *user_ip, const char *user_port,
			      const char *token_enc,
#ifdef WINDOWS
			      HANDLE proc_id,
#else
			      pid_t proc_id,
#endif
			      time_t login_time);

/* Look a session up by its token (the only unambiguous key now that a user
 * may have many sessions). Copies the connection fields into *out. */
bool dbmt_user_search_token_info_by_token (const char *token, T_USER_TOKEN_INFO *out);

/* Update last-access time of the session identified by token. */
bool dbmt_user_touch_token_login_time_by_token (const char *token, time_t now_time);

/* Delete one session by its token (e.g. logout). */
bool dbmt_user_delete_token_info_by_token (const char *token);

/* Delete every session of a user (e.g. the user is deleted). Returns the
 * number of sessions removed. */
int dbmt_user_delete_all_sessions_of_user (const char *user_id);

/*
 * Per-session DB-login store. dbmtuserlogin saves the DB user/password for a
 * dbname into the caller's own session; request handling later reads it back
 * for that same session only. Values are held in the C++ session object and
 * wiped when the session is removed.
 */
bool dbmt_user_session_set_dblogin (const char *token, const char *dbname,
				    const char *dbuser, const char *dbpasswd);
bool dbmt_user_session_get_dblogin (const char *token, const char *dbname,
				    char *dbuser, size_t dbuser_size,
				    char *dbpasswd, size_t dbpasswd_size);

#endif                /* _CM_USER_H_ */
