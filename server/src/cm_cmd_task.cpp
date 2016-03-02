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
 * cm_cmd_task.cpp -
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(WINDOWS)
#include <direct.h>
#include <io.h>
#include <process.h>
#include <winsock2.h>
#include "cm_win_wsa.h"
#else
#include <unistd.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netdb.h>
#endif

#include "cm_dep.h"
#include "cm_text_encryption.h"
#include "cm_server_util.h"
#include "cm_user.h"
#include "cm_cmd_task.h"
#include "cm_cmd_util.h"
#include "cm_config.h"

static struct option adddbinfo_opt[] = {
    {ARG_AUTH, 1, 0, 'a'},
    {ARG_UID, 1, 0, 'u'},
    {ARG_HOST, 1, 0, 'h'},
    {ARG_PORT, 1, 0, 'p'},
    {0, 0, 0, 0}
};

static struct option adduser_opt[] = {
    {ARG_UNICAS, 1, 0, 'b'},
    {ARG_DBCREATE, 1, 0, 'c'},
    {ARG_MONITOR, 1, 0, 'm'},
    {ARG_DB_INFO, 1, 0, 'd'},
    {0, 0, 0, 0}
};

static struct option chguserpwd_opt[] = {
    {ARG_NEW_PASS, 1, 0, 'n'},
    {ARG_OLD_PASS, 1, 0, 'o'},
    {ARG_ADMIN_PASS, 1, 0, ADMIN_FLAG},
    {0, 0, 0, 0}
};

static struct option chguserauth_opt[] = {
    {ARG_UNICAS, 1, 0, 'b'},
    {ARG_DBCREATE, 1, 0, 'c'},
    {ARG_MONITOR, 1, 0, 'm'},
    {0, 0, 0, 0}
};

static struct option chgdbinfo_opt[] = {
    {ARG_AUTH, 1, 0, 'a'},
    {ARG_UID, 1, 0, 'u'},
    {ARG_HOST, 1, 0, 'h'},
    {ARG_PORT, 1, 0, 'p'},
    {0, 0, 0, 0}
};

static const char *auth_list[] = {
    "none",
    "admin",
    "monitor",
    NULL
};

static const char *createdb_auth_list[] = {
    "none",
    "admin",
    NULL
};

static int _get_dbmt_user_index (T_DBMT_USER * dbmt_user, const char *username);
static T_DBMT_USER *_dbmt_user_get (char *error_msg);
static void _dbmt_user_free (T_DBMT_USER * dbmt_user);
static void _errmsg_output (int cmd_id, const char *error_msg);
static void _print_dbmtuser_info (T_DBMT_USER_INFO * dbmtuser_info);
static int _add_dbinfo_to_dbinfo_array (const char *dbinfo_str,
                                        T_DBMT_USER_DBINFO ** dbmt_dbinfo, 
                                        int *num_db, char *error_msg);
static int _check_str_in_list (const char *str, const char *str_list[]);
static int _check_dbmt_user_passwd (T_DBMT_USER * dbmt_user,
                                    const char *username, const char *passwd,
                                    char *error_msg);

static int
_get_cmd_nvplist (nvplist * arg_list, const char *argv[], int argc,
                  struct option opt[], const char *need_arg_list[],
                  char *error_msg);

static int
_get_longname_by_shortname (struct option opt[], int shortname,
                            char *longname, int buflen);

static int
_set_nvplist_by_arglist (nvplist * arg_list, const char *argnamearray[],
                         const char *argvalarray[]);

static int
_dbmtuser_auth_arg_check (const char *unicas_auth, const char *dbcreate_auth,
                          const char *monitor_auth, char *error_msg);
static int _get_localhost_ip (char *ipaddr, int ipaddr_len);


/* ***************************************
 *
 *       Command Task Interface
 *
 * ***************************************/

int
cmd_listdb (int argc, const char *in_argv[])
{
    int i = 0;
    int cmd_id = CMD_LISTDB;
    char *tok[2];
    char buf[LINE_MAX];
    char db_txt_path[PATH_MAX];

    FILE *fp = NULL;

    snprintf (db_txt_path, sizeof (db_txt_path) - 1, "%s/%s",
              sco.szCubrid_databases, CUBRID_DATABASE_TXT);

    if ((fp = fopen (db_txt_path, "r")) == NULL)
    {
        _errmsg_output (cmd_id, "The databases.txt file does not exist.\n");
        return E_FAILURE;
    }

    while (fgets (buf, sizeof (buf), fp))
    {
        ut_trim (buf);

        if (buf[0] == '#')
            continue;

        if (string_tokenize (buf, tok, 2) < 0)
            continue;

        printf ("  %d.  %s\n", ++i, ut_trim (tok[0]));
    }

    fclose (fp);

    return E_SUCCESS;
}

int
cmd_deluser (int argc, const char *in_argv[])
{
    int retval = E_SUCCESS;
    int cmd_id = CMD_DELUSER;
    int dbmt_user_index = -1;
    char error_msg[DBMT_ERROR_MSG_SIZE];
    char dbmt_user_name[DBMT_USER_NAME_LEN];
    T_DBMT_USER *dbmt_user = NULL;

    if (argc == 1)
    {
        print_help_msg (cmd_id);
        return E_SUCCESS;
    }

    if (argc != 2)
    {
        strcpy_limit (error_msg, get_msg_by_id (PTN_ARG_NUM_ERR),
                      DBMT_ERROR_MSG_SIZE);
        retval = E_ARG_ERR;
        goto error_clean_return;
    }

    if ((dbmt_user = _dbmt_user_get (error_msg)) == NULL)
    {
        retval = E_FAILURE;
        goto error_clean_return;
    }

    strcpy_limit (dbmt_user_name, in_argv[1], sizeof (dbmt_user_name));

    if (uStringEqual (DBMT_USER_ADMIN_NAME, dbmt_user_name))
    {
        snprintf (error_msg, DBMT_ERROR_MSG_SIZE - 1,
                  get_msg_by_id (PTN_DBMT_USER_NOT_DEL), DBMT_USER_ADMIN_NAME);
        retval = E_FAILURE;
        goto error_clean_return;
    }

    dbmt_user_index = _get_dbmt_user_index (dbmt_user, dbmt_user_name);

    if (dbmt_user_index < 0)
    {
        snprintf (error_msg, DBMT_ERROR_MSG_SIZE - 1,
                  get_msg_by_id (PTN_DBMT_USER_NOT_EXIST), dbmt_user_name);
        retval = E_FAILURE;
        goto error_clean_return;
    }

    dbmt_user->user_info[dbmt_user_index].user_name[0] = '\0';

    if (dbmt_user_write_auth (dbmt_user, error_msg) != ERR_NO_ERROR)
    {
        retval = E_FAILURE;
        goto error_clean_return;
    }

    retval = E_SUCCESS;
    goto clean_return;

error_clean_return:
    _errmsg_output (cmd_id, error_msg);
    if (retval == E_ARG_ERR)
    {
        print_help_msg (cmd_id);
    }

clean_return:
    _dbmt_user_free (dbmt_user);
    return retval;
}

int
cmd_adduser (int argc, const char *in_argv[])
{
    int i;
    int num_dbmt_user;
    int num_db = 0;
    int retval = E_SUCCESS;
    int cmd_id = CMD_ADDUSER;
    char dbmt_pass[PASSWD_ENC_LENGTH];
    char error_msg[DBMT_ERROR_MSG_SIZE] = { '\0' };
    T_DBMT_USER *dbmt_user;
    T_DBMT_USER_AUTHINFO *auth_info = NULL;
    T_DBMT_USER_DBINFO *db_info = NULL;

    const char *username, *userpass, *unicas, *dbcreate, *monitor, *tmp;
    const char *need_arg_list[] = {
        ARG_DBMT_USER_NAME,
        ARG_DBMT_USER_PWD,
        NULL
    };

    nvplist *arg_list;

    if (argc == 1)
    {
        print_help_msg (cmd_id);
        return E_SUCCESS;
    }

    arg_list = nv_create (5, NULL, "\n", ":", "\n");
    if ((retval =
        _get_cmd_nvplist (arg_list, in_argv, argc, adduser_opt,
                          need_arg_list, error_msg)) != E_SUCCESS)
    {
        goto error_return;
    }

    tmp = nv_get_val (arg_list, ARG_UNICAS);
    unicas = (tmp == NULL ? "none" : tmp);

    tmp = nv_get_val (arg_list, ARG_DBCREATE);
    dbcreate = (tmp == NULL ? "none" : tmp);

    tmp = nv_get_val (arg_list, ARG_MONITOR);
    monitor = (tmp == NULL ? "none" : tmp);

    username = nv_get_val (arg_list, ARG_DBMT_USER_NAME);
    userpass = nv_get_val (arg_list, ARG_DBMT_USER_PWD);

    if ((retval =
        _dbmtuser_auth_arg_check (unicas, dbcreate, monitor, error_msg)) != E_SUCCESS)
    {
        goto error_return;
    }

    for (i = 0; i < arg_list->nvplist_leng; i++)
    {
        char *n, *v;
        nv_lookup (arg_list, i, &n, &v);
        if (n != NULL && (uStringEqual (n, ARG_DB_INFO)))
        {
            if ((_add_dbinfo_to_dbinfo_array (v, &db_info,
                                              &num_db, error_msg)) != E_SUCCESS)
            {
                retval = E_ARG_ERR;
                goto error_return;
            }
        }
    }

    if ((dbmt_user = _dbmt_user_get (error_msg)) == NULL)
    {
        retval = E_FAILURE;
        goto error_return;
    }

    if (_get_dbmt_user_index (dbmt_user, username) >= 0)
    {
        snprintf (error_msg, DBMT_ERROR_MSG_SIZE - 1,
                  get_msg_by_id (PTN_DBMT_USER_EXIST), username);
        retval = E_FAILURE;
        goto error_clean_return;
    }

    /* set dbmt user auth info. */
    if ((auth_info =
        (T_DBMT_USER_AUTHINFO *) malloc (AUTH_NUM_TOTAL * sizeof (T_DBMT_USER_AUTHINFO))) == NULL)
        goto error_mem_alloc_return;

    dbmt_user_set_authinfo (&auth_info[0], "unicas", unicas);
    dbmt_user_set_authinfo (&auth_info[1], "dbcreate", dbcreate);
    dbmt_user_set_authinfo (&auth_info[2], "statusmonitorauth", monitor);

    /* encrypt the password. */
    uEncrypt (PASSWD_LENGTH, userpass, dbmt_pass);

    num_dbmt_user = dbmt_user->num_dbmt_user;

    /* set dbmt user info struct. */
    dbmt_user->user_info =
        (T_DBMT_USER_INFO *) increase_capacity (dbmt_user->user_info, sizeof (T_DBMT_USER_INFO),
                                                num_dbmt_user, num_dbmt_user + 1);

    if (dbmt_user->user_info == NULL)
        goto error_mem_alloc_return;

    dbmt_user_set_userinfo (&(dbmt_user->user_info[num_dbmt_user]),
                            (char *) username, (char *) dbmt_pass,
                            AUTH_NUM_TOTAL, auth_info, num_db, db_info);
    dbmt_user->num_dbmt_user++;

    /* update the cmdbpass & cm.pass conf file. */
    if (dbmt_user_write_pass (dbmt_user, error_msg) != ERR_NO_ERROR)
    {
        retval = E_FAILURE;
        goto error_clean_return;
    }

    if (dbmt_user_write_auth (dbmt_user, error_msg) != ERR_NO_ERROR)
    {
        retval = E_FAILURE;
        goto error_clean_return;
    }

    _dbmt_user_free (dbmt_user);
    nv_destroy (arg_list);

    return E_SUCCESS;

error_mem_alloc_return:
    retval = E_FAILURE;
    strcpy_limit (error_msg, get_msg_by_id (PTN_MEM_ALLOC_ERR), DBMT_ERROR_MSG_SIZE);

error_clean_return:
    _dbmt_user_free (dbmt_user);

error_return:
    nv_destroy (arg_list);
    _errmsg_output (cmd_id, error_msg);
    if (db_info)
    {
        free (db_info);
    }
    if (auth_info)
    {
        free (auth_info);
    }
    if (retval == E_ARG_ERR)
    {
        print_help_msg (cmd_id);
    }

    return retval;
}

int
cmd_viewuser (int argc, const char *in_argv[])
{
    int i;
    int retval = E_SUCCESS;
    int cmd_id = CMD_VIEWUSER;
    char error_msg[DBMT_ERROR_MSG_SIZE] = { '\0' };
    T_DBMT_USER *dbmt_user = NULL;

    if ((dbmt_user = _dbmt_user_get (error_msg)) == NULL)
    {
        retval = E_FAILURE;
        goto error_return;
    }

    if (argc == 1)
    {
        /* show all the dbmtuser info. */
        for (i = 0; i < dbmt_user->num_dbmt_user; i++)
            _print_dbmtuser_info (&dbmt_user->user_info[i]);
    }
    else if (argc == 2)
    {
        int index = -1;
        /* user specified a dbmtuser name. */
        index = _get_dbmt_user_index (dbmt_user, (char *) in_argv[1]);

        if (index < 0)
        {
            snprintf (error_msg, DBMT_ERROR_MSG_SIZE - 1,
                      get_msg_by_id (PTN_DBMT_USER_NOT_EXIST), in_argv[1]);
            retval = E_FAILURE;
            goto error_return;
        }

        _print_dbmtuser_info (&dbmt_user->user_info[index]);
    }
    else
    {
        snprintf (error_msg, DBMT_ERROR_MSG_SIZE - 1,
                  get_msg_by_id (PTN_ARG_NUM_ERR));
        retval = E_ARG_ERR;
        goto error_return;
    }

    goto clean_return;

error_return:
    _errmsg_output (cmd_id, error_msg);
    if (retval == E_ARG_ERR)
    {
        print_help_msg (cmd_id);
    }

clean_return:
    _dbmt_user_free (dbmt_user);
    return retval;
}

int
cmd_chguser_pwd (int argc, const char *in_argv[])
{
    int retval = E_SUCCESS;
    int dbmt_user_index = -1;
    int cmd_id = CMD_CHGUSER_PWD;
    char pwd_tmp[PASSWD_ENC_LENGTH];
    char error_msg[DBMT_ERROR_MSG_SIZE];
    const char *dbmtusername, *oldpass, *newpass, *adminpass;
    T_DBMT_USER *dbmt_user = NULL;

    nvplist *arg_list = NULL;
    const char *need_arg_list[] = {
        ARG_DBMT_USER_NAME,
        NULL
    };

    arg_list = nv_create (5, NULL, "\n", ":", "\n");

    if (argc == 1)
    {
        print_help_msg (cmd_id);
        return E_SUCCESS;
    }

    if ((retval =
        _get_cmd_nvplist (arg_list, in_argv, argc, chguserpwd_opt, need_arg_list, error_msg)) != E_SUCCESS)
        goto error_clean_return;

    dbmtusername = nv_get_val (arg_list, ARG_DBMT_USER_NAME);
    oldpass = nv_get_val (arg_list, ARG_OLD_PASS);
    newpass = nv_get_val (arg_list, ARG_NEW_PASS);
    adminpass = nv_get_val (arg_list, ARG_ADMIN_PASS);

    /* get dbmt user. */
    if ((dbmt_user = _dbmt_user_get (error_msg)) == NULL)
    {
        retval = E_FAILURE;
        goto error_clean_return;
    }

    if ((dbmt_user_index = _get_dbmt_user_index (dbmt_user, dbmtusername)) < 0)
    {
        snprintf (error_msg, DBMT_ERROR_MSG_SIZE - 1,
                  get_msg_by_id (PTN_DBMT_USER_NOT_EXIST), dbmtusername);
        retval = E_FAILURE;
        goto error_clean_return;
    }

    if (oldpass != NULL)
    {
        /* check old password. */
        if (_check_dbmt_user_passwd
            (dbmt_user, dbmtusername, oldpass, error_msg) < 0)
        {
            retval = E_FAILURE;
            goto error_clean_return;
        }
    }
    else if (adminpass != NULL)
    {
        /* check admin password. */
        if (_check_dbmt_user_passwd
            (dbmt_user, DBMT_USER_ADMIN_NAME, adminpass, error_msg) < 0)
        {
            retval = E_FAILURE;
            goto error_clean_return;
        }
    }
    else
    {
        snprintf (error_msg, DBMT_ERROR_MSG_SIZE - 1,
                  get_msg_by_id (PTN_ARG_MUST_APPEAR_ERR),
                  ARG_OLD_PASS ", " ARG_ADMIN_PASS);
        retval = E_FAILURE;
        goto error_clean_return;
    }

    /* reset the new password. */
    uEncrypt (PASSWD_LENGTH, newpass, pwd_tmp);
    strcpy_limit (dbmt_user->user_info[dbmt_user_index].user_passwd, pwd_tmp,
                  PASSWD_ENC_LENGTH);

    if (dbmt_user_write_pass (dbmt_user, error_msg) != ERR_NO_ERROR)
    {
        retval = E_FAILURE;
        goto error_clean_return;
    }

    nv_destroy (arg_list);
    _dbmt_user_free (dbmt_user);
    return E_SUCCESS;

error_clean_return:
    nv_destroy (arg_list);
    _dbmt_user_free (dbmt_user);
    _errmsg_output (cmd_id, error_msg);

    if (retval == E_ARG_ERR)
    {
        print_help_msg (cmd_id);
    }

    return retval;
}

int
cmd_chguser_auth (int argc, const char *in_argv[])
{
    int i = 0;
    int retval = E_SUCCESS;
    int dbmt_user_index = -1;
    int cmd_id = CMD_CHGUSER_AUTH;
    char error_msg[DBMT_ERROR_MSG_SIZE];
    const char *unicas, *dbcreate, *monitor, *username;
    T_DBMT_USER *dbmt_user = NULL;
    T_DBMT_USER_INFO *dbmt_user_info_t = NULL;

    nvplist *arg_list = NULL;
    const char *need_arg_list[] = {
        ARG_DBMT_USER_NAME,
        NULL
    };

    arg_list = nv_create (5, NULL, "\n", ":", "\n");

    if (argc == 1)
    {
        print_help_msg (cmd_id);
        return E_SUCCESS;
    }

    if ((retval =
        _get_cmd_nvplist (arg_list, in_argv, argc, chguserauth_opt, need_arg_list, error_msg)) != E_SUCCESS)
        goto error_clean_return;

    unicas = nv_get_val (arg_list, ARG_UNICAS);
    dbcreate = nv_get_val (arg_list, ARG_DBCREATE);
    monitor = nv_get_val (arg_list, ARG_MONITOR);
    username = nv_get_val (arg_list, ARG_DBMT_USER_NAME);

    if ((retval =
        _dbmtuser_auth_arg_check (unicas, dbcreate, monitor, error_msg)) != E_SUCCESS)
    {
        goto error_clean_return;
    }

    if (unicas == NULL && dbcreate == NULL && monitor == NULL)
    {
        snprintf (error_msg, sizeof (error_msg) - 1,
                  get_msg_by_id (PTN_ARG_MUST_APPEAR_ERR),
                  ARG_UNICAS ", " ARG_DBCREATE ", " ARG_MONITOR);
        retval = E_ARG_ERR;
        goto error_clean_return;
    }

    /* get dbmt user. */
    if ((dbmt_user = _dbmt_user_get (error_msg)) == NULL)
    {
        _errmsg_output (cmd_id, error_msg);
        return E_FAILURE;
    }

    if ((dbmt_user_index = _get_dbmt_user_index (dbmt_user, username)) < 0)
    {
        snprintf (error_msg, DBMT_ERROR_MSG_SIZE - 1,
                  get_msg_by_id (PTN_DBMT_USER_NOT_EXIST), username);
        retval = E_FAILURE;
        goto error_clean_return;
    }

    dbmt_user_info_t = &(dbmt_user->user_info[dbmt_user_index]);

    for (i = 0; i < dbmt_user_info_t->num_authinfo; i++)
    {
        T_DBMT_USER_AUTHINFO *auth_t;

        auth_t = &(dbmt_user_info_t->authinfo[i]);

        if (uStringEqual (auth_t->domain, "unicas") && unicas != NULL)
        {
            strcpy_limit (auth_t->auth, unicas, sizeof (auth_t->auth));
        }
        else if (uStringEqual (auth_t->domain, "dbcreate") && dbcreate != NULL)
        {
            strcpy_limit (auth_t->auth, dbcreate, sizeof (auth_t->auth));
        }
        else if (uStringEqual (auth_t->domain, "statusmonitorauth")
                 && monitor != NULL)
        {
            strcpy_limit (auth_t->auth, monitor, sizeof (auth_t->auth));
        }
    }

    if (dbmt_user_write_auth (dbmt_user, error_msg) != ERR_NO_ERROR)
    {
        retval = E_FAILURE;
        goto error_clean_return;
    }

    nv_destroy (arg_list);
    _dbmt_user_free (dbmt_user);
    return E_SUCCESS;

error_clean_return:
    nv_destroy (arg_list);
    _dbmt_user_free (dbmt_user);
    _errmsg_output (cmd_id, error_msg);

    if (retval == E_ARG_ERR)
    {
        print_help_msg (cmd_id);
    }

    return retval;
}

int
cmd_adddbinfo (int argc, const char *in_argv[])
{
    int i;
    int num_db;
    int dbmt_user_index;
    int retval = E_SUCCESS;
    int cmd_id = CMD_ADDDBINFO;
    char error_msg[DBMT_ERROR_MSG_SIZE];
    char local_ip[64];
    char broker_addr[BROKER_ADDR_LEN];
    const char *username, *dbname, *auth, *uid, *host, *port, *tmp;
    int flag = 0;
    char *n, *v;
    int dbexist = 0;

    T_DBMT_USER *dbmt_user = NULL;
    T_DBMT_USER_INFO *t_info = NULL;

    nvplist *arg_list = NULL;
    nvplist *db_list = NULL;
    const char *need_arg_list[] = {
        ARG_DBMT_USER_NAME,
        ARG_DB_NAME,
        NULL
    };

    local_ip[0] = '\0';

    if (argc == 1)
    {
        print_help_msg (cmd_id);
        return E_SUCCESS;
    }

    if (_get_localhost_ip (local_ip, sizeof (local_ip)) != 0)
    {
        snprintf (error_msg, DBMT_ERROR_MSG_SIZE - 1,
                  "failed to get localhost ip");
        retval = E_FAILURE;
        goto error_clean_return;
    }

    arg_list = nv_create (5, NULL, "\n", ":", "\n");
    db_list = nv_create (5, NULL, "\n", ":", "\n");

    if ((retval =
        _get_cmd_nvplist (arg_list, in_argv, argc, adddbinfo_opt, need_arg_list, error_msg)) != E_SUCCESS)
        goto error_clean_return;

    /* set default value of auth, uid, host & port. */
    tmp = nv_get_val (arg_list, ARG_AUTH);
    auth = ((tmp == NULL) ? "admin" : tmp);

    tmp = nv_get_val (arg_list, ARG_UID);
    uid = ((tmp == NULL) ? "dba" : tmp);

    tmp = nv_get_val (arg_list, ARG_HOST);
    host = ((tmp == NULL) ? local_ip : tmp);

    tmp = nv_get_val (arg_list, ARG_PORT);
    port = ((tmp == NULL) ? "30000" : tmp);

    username = nv_get_val (arg_list, ARG_DBMT_USER_NAME);
    dbname = nv_get_val (arg_list, ARG_DB_NAME);

    /* does this database exist in database.txt? */

    if (ut_get_dblist (db_list, 0) != ERR_NO_ERROR)
    {
        snprintf (error_msg, DBMT_ERROR_MSG_SIZE - 1,
                  "failed to get database lists.");
        retval = E_FAILURE;
        goto error_clean_return;
    }
    for (i = 0; i < db_list->nvplist_leng; i++)
    {
        nv_lookup (db_list, i, &n, &v);
        if (n == NULL || v == NULL)
        {
            snprintf (error_msg, DBMT_ERROR_MSG_SIZE - 1, "malformed database lists.");
            retval = E_FAILURE;
            goto error_clean_return;
        }

        if (!strcmp (n, "open") && !strcmp (v, "dblist"))
        {
            flag = 1;
        }
        else if (!strcmp (n, "close") && !strcmp (v, "dblist"))
        {
            flag = 0;
            break;
        }
        else if (flag == 1)
        {
            if (!strcmp (n, "dbname") && !strcmp (v, dbname))
                dbexist = 1;
        }            /* close "else if (flag == 1)" */
    }
    if (!dbexist)
    {
        snprintf (error_msg, DBMT_ERROR_MSG_SIZE - 1,
                  get_msg_by_id (PTN_DB_NOT_EXIST), dbname);
        retval = E_FAILURE;
        goto error_clean_return;
    }

    if ((dbmt_user = _dbmt_user_get (error_msg)) == NULL)
    {
        _errmsg_output (cmd_id, error_msg);
        return E_FAILURE;
    }

    if ((dbmt_user_index = _get_dbmt_user_index (dbmt_user, username)) < 0)
    {
        snprintf (error_msg, DBMT_ERROR_MSG_SIZE - 1,
            get_msg_by_id (PTN_DBMT_USER_NOT_EXIST), username);
        retval = E_FAILURE;
        goto error_clean_return;
    }

    snprintf (broker_addr, sizeof (broker_addr), "%s,%s", host, port);

    t_info = &(dbmt_user->user_info[dbmt_user_index]);

    /* check whether this user has been authorized to this DB. */
    if (dbmt_user_search (t_info, dbname) >= 0)
    {
        snprintf (error_msg, DBMT_ERROR_MSG_SIZE - 1,
                  get_msg_by_id (PTN_DB_ALREADY_AUTH), dbname, username);
        retval = E_FAILURE;
        goto error_clean_return;
    }

    num_db = t_info->num_dbinfo;
    t_info->dbinfo = (T_DBMT_USER_DBINFO *) increase_capacity (t_info->dbinfo,
                                                               sizeof(T_DBMT_USER_DBINFO),
                                                               num_db, num_db + 1);
    if (t_info->dbinfo == NULL)
    {
        strcpy_limit (error_msg, get_msg_by_id (PTN_MEM_ALLOC_ERR), DBMT_ERROR_MSG_SIZE);
        retval = E_FAILURE;
        goto error_clean_return;
    }

    /* add dbinfo to dbmt user. */
    dbmt_user_set_dbinfo (&(t_info->dbinfo[num_db]), dbname, auth, uid, broker_addr);

    t_info->num_dbinfo++;

    if (dbmt_user_write_auth (dbmt_user, error_msg) != ERR_NO_ERROR)
    {
        retval = E_FAILURE;
        goto error_clean_return;
    }

    retval = E_SUCCESS;
    goto memory_clean_return;

error_clean_return:
    _errmsg_output (cmd_id, error_msg);

    if (retval == E_ARG_ERR)
    {
        print_help_msg (cmd_id);
    }

memory_clean_return:
    if (db_list)
        nv_destroy (db_list);
    if (arg_list)
        nv_destroy (arg_list);
    if (dbmt_user)
        _dbmt_user_free (dbmt_user);
    return retval;
}

int
cmd_deldbinfo (int argc, const char *in_argv[])
{
    int db_index;
    int dbmt_user_index;
    int retval = E_SUCCESS;
    int cmd_id = CMD_DELDBINFO;
    char dbname[DBNAME_LEN];
    char error_msg[DBMT_ERROR_MSG_SIZE];
    char dbmt_user_name[DBMT_USER_NAME_LEN];

    T_DBMT_USER *dbmt_user = NULL;

    if (argc == 1)
    {
        print_help_msg (cmd_id);
        return E_SUCCESS;
    }

    if (argc != 3)
    {
        snprintf (error_msg, DBMT_USER_NAME_LEN - 1, get_msg_by_id (PTN_ARG_NUM_ERR));
        retval = E_ARG_ERR;
        goto error_clean_return;
    }

    if ((dbmt_user = _dbmt_user_get (error_msg)) == NULL)
    {
        retval = E_FAILURE;
        goto error_clean_return;
    }

    strcpy_limit (dbmt_user_name, in_argv[1], sizeof (dbmt_user_name));
    strcpy_limit (dbname, in_argv[2], sizeof (dbname));

    dbmt_user_index = _get_dbmt_user_index (dbmt_user, dbmt_user_name);
    if (dbmt_user_index < 0)
    {
        snprintf (error_msg, DBMT_ERROR_MSG_SIZE - 1,
                  get_msg_by_id (PTN_DBMT_USER_NOT_EXIST), dbmt_user_name);

        retval = E_FAILURE;
        goto error_clean_return;
    }

    if ((db_index =
        dbmt_user_search (&dbmt_user->user_info[dbmt_user_index], dbname)) < 0)
    {
        snprintf (error_msg, DBMT_ERROR_MSG_SIZE - 1,
                  get_msg_by_id (PTN_DB_NOT_AUTH), dbname, dbmt_user_name);
        retval = E_FAILURE;
        goto error_clean_return;
    }

    dbmt_user->user_info[dbmt_user_index].dbinfo[db_index].dbname[0] = '\0';

    if (dbmt_user_write_auth (dbmt_user, error_msg) != ERR_NO_ERROR)
    {
        retval = E_FAILURE;
        goto error_clean_return;
    }

    retval = E_SUCCESS;
    goto clean_return;

error_clean_return:
    _errmsg_output (cmd_id, error_msg);

    if (retval == E_ARG_ERR)
    {
        print_help_msg (cmd_id);
    }

clean_return:
    _dbmt_user_free (dbmt_user);
    return retval;
}

int
cmd_chgdbinfo (int argc, const char *in_argv[])
{
    int dbinfo_index;
    int dbmt_user_index;
    int retval = E_SUCCESS;
    int cmd_id = CMD_CHGDBINFO;
    char *broker_tok[2];
    char broker_addr[BROKER_ADDR_LEN];
    char broker_addr_t[BROKER_ADDR_LEN];
    char error_msg[DBMT_ERROR_MSG_SIZE];
    char *auth, *uid, *host, *port, *username, *dbname;
    const char *need_arg_list[] = {
        ARG_DBMT_USER_NAME,
        ARG_DB_NAME,
        NULL
    };

    T_DBMT_USER *dbmt_user = NULL;
    T_DBMT_USER_INFO *userinfo_t = NULL;
    T_DBMT_USER_DBINFO *dbinfo_t = NULL;

    nvplist *arg_list = NULL;

    arg_list = nv_create (5, NULL, "\n", ":", "\n");

    if (argc == 1)
    {
        print_help_msg (cmd_id);
        return E_SUCCESS;
    }

    if ((retval =
        _get_cmd_nvplist (arg_list, in_argv, argc, chgdbinfo_opt,need_arg_list, error_msg)) != E_SUCCESS)
        goto error_clean_return;

    auth = nv_get_val (arg_list, ARG_AUTH);
    uid = nv_get_val (arg_list, ARG_UID);
    host = nv_get_val (arg_list, ARG_HOST);
    port = nv_get_val (arg_list, ARG_PORT);
    username = nv_get_val (arg_list, ARG_DBMT_USER_NAME);
    dbname = nv_get_val (arg_list, ARG_DB_NAME);

    if ((dbmt_user = _dbmt_user_get (error_msg)) == NULL)
    {
        _errmsg_output (cmd_id, error_msg);
        return E_FAILURE;
    }

    if ((dbmt_user_index = _get_dbmt_user_index (dbmt_user, username)) < 0)
    {
        snprintf (error_msg, DBMT_ERROR_MSG_SIZE - 1,
                  get_msg_by_id (PTN_DBMT_USER_NOT_EXIST), username);
        retval = E_FAILURE;
        goto error_clean_return;
    }

    userinfo_t = &(dbmt_user->user_info[dbmt_user_index]);

    if ((dbinfo_index = dbmt_user_search (userinfo_t, dbname)) < 0)
    {
        snprintf (error_msg, DBMT_ERROR_MSG_SIZE - 1,
                  get_msg_by_id (PTN_DB_NOT_EXIST), dbname, username);
        retval = E_FAILURE;
        goto error_clean_return;
    }

    dbinfo_t = &(userinfo_t->dbinfo[dbinfo_index]);

    strcpy_limit (broker_addr_t, dbinfo_t->broker_address,
                  sizeof (broker_addr_t));
    if (string_tokenize2 (broker_addr_t, broker_tok, 2, ',') < 0)
    {
        snprintf (error_msg, DBMT_ERROR_MSG_SIZE - 1,
                  get_msg_by_id (PTN_BROKER_ADDR_ERR), dbinfo_t->broker_address);
        retval = E_FAILURE;
        goto error_clean_return;
    }

    snprintf (broker_addr, sizeof (broker_addr) - 1, "%s,%s",
              ((host == NULL) ? broker_tok[0] : host),
              ((port == NULL) ? broker_tok[1] : port));

    strcpy_limit (dbinfo_t->broker_address, broker_addr,
                  sizeof (dbinfo_t->broker_address));

    if (auth != NULL)
    {
        strcpy_limit (dbinfo_t->auth, auth, sizeof (dbinfo_t->auth));
    }

    if (uid != NULL)
    {
        strcpy_limit (dbinfo_t->uid, uid, sizeof (dbinfo_t->uid));
    }

    if (dbmt_user_write_auth (dbmt_user, error_msg) != ERR_NO_ERROR)
    {
        retval = E_FAILURE;
        goto error_clean_return;
    }

    retval = E_SUCCESS;
    goto memory_clean_return;

error_clean_return:
    _errmsg_output (cmd_id, error_msg);

    if (retval == E_ARG_ERR)
    {
        print_help_msg (cmd_id);
    }

memory_clean_return:
    nv_destroy (arg_list);
    _dbmt_user_free (dbmt_user);
    return retval;
}

/* ***************************************
 *
 *       Command Task Tools
 *
 * ***************************************/

static int
_check_dbmt_user_passwd (T_DBMT_USER * dbmt_user, const char *username,
                         const char *passwd, char *error_msg)
{
    int dbmt_user_index = -1;
    char pwd_tmp[PASSWD_ENC_LENGTH];
    T_DBMT_USER_INFO *dbmt_user_info_t = NULL;

    /* check admin password. */
    if ((dbmt_user_index = _get_dbmt_user_index (dbmt_user, username)) < 0)
    {
        snprintf (error_msg, DBMT_ERROR_MSG_SIZE - 1,
                  get_msg_by_id (PTN_DBMT_USER_NOT_EXIST), username);
        return -1;
    }

    dbmt_user_info_t = &(dbmt_user->user_info[dbmt_user_index]);
    uDecrypt (PASSWD_LENGTH, dbmt_user_info_t->user_passwd, pwd_tmp);

    if (!uStringEqual (pwd_tmp, passwd))
    {
        snprintf (error_msg, DBMT_ERROR_MSG_SIZE - 1,
                  get_msg_by_id (PTN_DBMT_USER_PWD_ERR), passwd);
        return -1;
    }

    return 0;
}

static T_DBMT_USER *
_dbmt_user_get (char *error_msg)
{
    T_DBMT_USER *dbmt_user = NULL;

    if ((dbmt_user = (T_DBMT_USER *) malloc (sizeof (T_DBMT_USER))) == NULL)
        return NULL;

    if (dbmt_user_read (dbmt_user, error_msg) < 0)
        return NULL;

    return dbmt_user;
}

static void
_dbmt_user_free (T_DBMT_USER * dbmt_user)
{
    if (dbmt_user != NULL)
    {
        dbmt_user_free (dbmt_user);
    }

    free (dbmt_user);
    return;
}

static int
_get_dbmt_user_index (T_DBMT_USER * dbmt_user, const char *username)
{
    int i;

    for (i = 0; i < dbmt_user->num_dbmt_user; i++)
    {
        if (uStringEqual (username, dbmt_user->user_info[i].user_name))
        {
            return i;
        }
    }

    return -1;
}

static void
_errmsg_output (int cmd_id, const char *error_msg)
{
    char cmd_name[OPT_STR_LEN];

    if (get_cmdname_by_id (cmd_id, cmd_name, sizeof (cmd_name)) < 0)
    {
        fprintf (stderr, "ERROR: Command id (%d) is not exist.\n", cmd_id);
        return;
    }

    fprintf (stderr, "ERROR: %s: %s\n", cmd_name, error_msg);
    return;
}

static int
_get_cmd_nvplist (nvplist * arg_list, const char *argv[], int argc,
                  struct option opt[], const char *need_arg_list[],
                  char *error_msg)
{
    int retval = E_SUCCESS;
    int i, need_arg_num;
    char opt_str[OPT_STR_LEN];
    char *l_opt_arg;

    for (i = 0; need_arg_list[i] != NULL; i++)
    ;
    need_arg_num = i;
    if (0 == need_arg_num)
    {
        return E_ARG_ERR;
    }
    utility_make_getopt_optstring (opt, opt_str);

    while (1)
    {
        int opt_key = 0;
        int opt_index = 0;
        char longname[OPT_STR_LEN];

        opt_key =
        getopt_long (argc, (char **const) argv, opt_str, opt, &opt_index);

        /* end of args */
        if (opt_key == -1)
            break;
        if (_get_longname_by_shortname
            (opt, opt_key, longname, sizeof (longname)) < 0)
            return E_ARG_ERR;
        l_opt_arg = optarg;

        nv_add_nvp (arg_list, longname, l_opt_arg);
    }

    if (argc - optind == need_arg_num)
    {
        _set_nvplist_by_arglist (arg_list, need_arg_list, &(argv[optind]));
    }
    else if (argc - optind < need_arg_num)
    {
        snprintf (error_msg, DBMT_ERROR_MSG_SIZE - 1,
                  get_msg_by_id (PTN_ARG_MISS), need_arg_list[need_arg_num - 1]);
        retval = E_ARG_ERR;
    }
    else
    {
        snprintf (error_msg, DBMT_ERROR_MSG_SIZE - 1,
                  get_msg_by_id (PTN_ARG_MORE), argv[optind + 1]);
        retval = E_ARG_ERR;
    }

    return retval;
}

static int
_get_longname_by_shortname (struct option opt[], int shortname,
                            char *longname, int buflen)
{
    int i;

    for (i = 0; opt[i].val != 0; i++)
    {
        if (shortname == opt[i].val)
        {
            strcpy_limit (longname, opt[i].name, buflen);
            return 0;
        }
    }

    return -1;
}

static int
_set_nvplist_by_arglist (nvplist * arg_list, const char *argnamelist[],
                         const char *argvalarray[])
{
    int i;

    for (i = 0; argnamelist[i] != NULL; i++)
    {
        nv_add_nvp (arg_list, argnamelist[i], argvalarray[i]);
    }

    return 0;
}

/* the str_list should be end with NULL. */
static int
_check_str_in_list (const char *str, const char *str_list[])
{
    int i;

    if (str == NULL)
        return -1;

    for (i = 0; str_list[i] != NULL; i++)
    {
        if (uStringEqual (str, str_list[i]))
            return i;
    }

    return -1;
}

static int
_add_dbinfo_to_dbinfo_array (const char *dbinfo_str,
                             T_DBMT_USER_DBINFO ** dbmt_dbinfo, int *num_db,
                             char *error_msg)
{
    char *tok[3];
    char str_t[1024];
    char *broker_tok[3];
    char broker_str[BROKER_ADDR_LEN];
    int i;

    strcpy_limit (str_t, dbinfo_str, sizeof (str_t));

    if (string_tokenize2 (str_t, tok, 3, ';') < 0)
    {
        snprintf (error_msg, DBMT_ERROR_MSG_SIZE - 1, get_msg_by_id (PTN_ARG_FORMAT_ERR), str_t);
        return E_FAILURE;
    }

    /* check broker ip & broker port. */
    if (string_tokenize2 (tok[2], broker_tok, 2, ',') < 0)
    {
        snprintf (error_msg, DBMT_ERROR_MSG_SIZE - 1, get_msg_by_id (PTN_BROKER_ADDR_ERR), tok[2]);
        return E_FAILURE;
    }

    if ((*num_db) > 0)
    {
        for (i = 0; i < (*num_db); i++)
        {
            if (uStringEqual (tok[0], (*dbmt_dbinfo)[i].dbname))
            {
                snprintf (error_msg, DBMT_ERROR_MSG_SIZE - 1, get_msg_by_id (PTN_DB_ADD_TWICE), tok[0]);
                return E_FAILURE;
            }
        }
    }

    snprintf (broker_str, sizeof (broker_str) - 1, "%s,%s", ut_trim (broker_tok[0]), ut_trim (broker_tok[1]));

    *dbmt_dbinfo = (T_DBMT_USER_DBINFO *) increase_capacity (*dbmt_dbinfo,
                                                             sizeof(T_DBMT_USER_DBINFO), 
                                                             (*num_db), (*num_db) + 1);

    if (*dbmt_dbinfo == NULL)
    {
        snprintf (error_msg, DBMT_ERROR_MSG_SIZE - 1, get_msg_by_id (PTN_MEM_ALLOC_ERR));
        return E_FAILURE;
    }

    dbmt_user_set_dbinfo (&(*dbmt_dbinfo)[(*num_db)], ut_trim (tok[0]),
                          DBMT_USER_ADMIN_NAME, ut_trim (tok[1]), broker_str);
    (*num_db)++;

    return E_SUCCESS;
}

static void
_print_dbmtuser_info (T_DBMT_USER_INFO * dbmtuser_info)
{
    int i;
    const char *dbinfo_pattern = "     %-48s %-17s %-23s \n";
    char split[17 + 23 + 48 + 3];
    int len = 17 + 23 + 48 + 3;

    memset (split, '=', len - 1);
    split[len - 1] = '\0';

    printf ("DBMT USER: %s\n", dbmtuser_info->user_name);
    printf ("  Auth info: \n");

    for (i = 0; i < dbmtuser_info->num_authinfo; i++)
    {
        T_DBMT_USER_AUTHINFO *t_authinfo = &dbmtuser_info->authinfo[i];
        if (strcmp (t_authinfo->domain, "unicas") == 0)
            printf ("    broker: %s\n", t_authinfo->auth);
        else
            printf ("    %s: %s\n", t_authinfo->domain, t_authinfo->auth);
    }

    printf ("  DB info: \n");
    printf ("    %s\n", split);
    printf (dbinfo_pattern, "DBNAME", "UID", "BROKER INFO");
    printf ("    %s\n", split);

    for (i = 0; i < dbmtuser_info->num_dbinfo; i++)
    {
        T_DBMT_USER_DBINFO *t_dbinfo = &dbmtuser_info->dbinfo[i];
        printf (dbinfo_pattern,
                t_dbinfo->dbname, t_dbinfo->uid, t_dbinfo->broker_address);
    }
    printf ("\n");

    return;
}

static int
_dbmtuser_auth_arg_check (const char *unicas_auth, const char *dbcreate_auth,
                          const char *monitor_auth, char *error_msg)
{
    if (unicas_auth != NULL && _check_str_in_list (unicas_auth, auth_list) < 0)
    {
        snprintf (error_msg, DBMT_ERROR_MSG_SIZE - 1,
                  get_msg_by_id (PTN_ARG_FORMAT_ERR), ARG_UNICAS);
        return E_ARG_ERR;
    }
    if (dbcreate_auth != NULL
        && _check_str_in_list (dbcreate_auth, createdb_auth_list) < 0)
    {
        snprintf (error_msg, DBMT_ERROR_MSG_SIZE - 1,
                  get_msg_by_id (PTN_ARG_FORMAT_ERR), ARG_DBCREATE);
        return E_ARG_ERR;
    }
    if (monitor_auth != NULL && _check_str_in_list (monitor_auth, auth_list) < 0)
    {
        snprintf (error_msg, DBMT_ERROR_MSG_SIZE - 1,
                  get_msg_by_id (PTN_ARG_FORMAT_ERR), ARG_MONITOR);
        return E_ARG_ERR;
    }

    return E_SUCCESS;
}

static int
_get_localhost_ip (char *ipaddr, int ipaddr_len)
{
    char hostname[64];
    char *ip = NULL;
    int i = 0;
    struct hostent *hostent_p = NULL;

#if defined(WINDOWS)
    WSADATA wsaData;
    WSAStartup (MAKEWORD (2, 2), &wsaData);
#endif

    hostname[0] = '\0';

    if (gethostname (hostname, sizeof (hostname)) < 0)
    {
        goto exit_err;
    }

    hostent_p = gethostbyname (hostname);

    if (hostent_p == NULL)
    {
        ipaddr = NULL;
        goto exit_err;
    }
    else
    {
        for (i = 0; hostent_p->h_addr_list[i] != NULL; i++)
        {
            ip = inet_ntoa (*((struct in_addr *) hostent_p->h_addr_list[i]));
            /* ignore the 127.0.0.1 */
            if (strcmp (ip, "127.0.0.1") == 0)
            {
                continue;
            }
            break;
        }
        if (ip)
        {
            strcpy_limit (ipaddr, ip, ipaddr_len);
            return 0;
        }

        goto exit_err;
    }
exit_err:
#if defined(WINDOWS)
    WSACleanup ();
#endif
    return -1;
}
