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
 * cm_cmd_util.h -
 */

#ifndef _CM_CMD_UTIL_H_
#define _CM_CMD_UTIL_H_

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#else
#include "getopt.h"
#endif


/* typedef struct option GETOPT_LONG; */

/*
 * CM_ADMIN COMMON MACRO.
 */
#define CM_ADMIN_NAME           "cm_admin"
#define CM_ADMIN_VERSION        "0.1"

#define OPT_STR_LEN             128
#define DBNAME_LEN              128
#define UID_LEN                 18
#define PORT_LEN                8
#define BROKER_ADDR_LEN         MAXHOSTNAMELEN + PORT_LEN + 1

#define ADMIN_FLAG              1

#ifndef PATH_MAX
#define PATH_MAX                1024
#endif

#ifndef LINE_MAX
#define LINE_MAX                1024
#endif

#define SQL_STAT_LEN            1024
#define DBMT_USER_ADMIN_NAME    "admin"
#define AUTH_NUM_TOTAL          3


/*
 * CM_ADMIN ARG NAME DEFINITION.
 */

#define ARG_DBMT_USER_NAME      "dbmtuser-name"
#define ARG_DBMT_USER_PWD       "dbmtuser-password"
#define ARG_DB_NAME             "dbname"

#define ARG_UNICAS              "broker"
#define ARG_DBCREATE            "dbcreate"
#define ARG_MONITOR             "monitor"

#define ARG_AUTH                "auth"
#define ARG_UID                 "uid"
#define ARG_HOST                "host"
#define ARG_PORT                "port"

#define ARG_OLD_PASS            "old"
#define ARG_NEW_PASS            "new"
#define ARG_ADMIN_PASS          "adminpass"

#define ARG_DB_INFO             "dbinfo"


/*
 * CM_ADMIN ERROR ID DEFINITION.
 */
#define E_SUCCESS               2000
#define E_FAILURE               2001
#define E_CMD_NOT_EXIST         2002
#define E_ARG_ERR               2003

typedef enum
{
  PTN_ARG_MISS,
  PTN_ARG_MORE,
  PTN_ARG_NUM_ERR,
  PTN_ARG_FORMAT_ERR,
  PTN_ARG_MUST_APPEAR_ERR,
  PTN_DBMT_USER_NOT_EXIST,
  PTN_DBMT_USER_EXIST,
  PTN_DBMT_USER_NOT_DEL,
  PTN_DBMT_USER_PWD_ERR,
  PTN_DB_NOT_AUTH,
  PTN_DB_ALREADY_AUTH,
  PTN_DB_NOT_EXIST,
  PTN_DB_ADD_TWICE,
  PTN_BROKER_ADDR_ERR,
  PTN_MEM_ALLOC_ERR,
  PTN_UNDEFINE,
} PTN_ID;

void print_cmd (void);
void print_help_msg (int cmd_id);

int run_task (const char *task_name, int argc, const char *argv[]);
int get_cmdname_by_id (int cmd_id, char *cmd_name, int buf_size);
const char *get_msg_by_id (int ptn_id);
char *utility_make_getopt_optstring (struct option *opt_array, char *buf);
#endif /* !_CM_CMD_UTIL_H_ */
