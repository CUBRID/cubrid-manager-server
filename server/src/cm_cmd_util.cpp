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
 * cm_cmd_util.cpp -
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "cm_porting.h"
#include "cm_dep.h"
#include "cm_cmd_util.h"
#include "cm_cmd_task.h"

typedef int (*CMD_FUNC) (int argc, const char *argv[]);

#define DEF_CMD_FUNC(CMD_FUNC) CMD_FUNC;

typedef struct
{
    const char *cmd_name;
    CMD_FUNC cmd_func;
    CMD_ID cmd_id;
} CMD_INFO;

static CMD_INFO cmd_info[] = {
    {"adduser", cmd_adduser, CMD_ADDUSER},
    {"deluser", cmd_deluser, CMD_DELUSER},
    {"viewuser", cmd_viewuser, CMD_VIEWUSER},
    {"changeuserauth", cmd_chguser_auth, CMD_CHGUSER_AUTH},
    {"changeuserpwd", cmd_chguser_pwd, CMD_CHGUSER_PWD},
    {"adddbinfo", cmd_adddbinfo, CMD_ADDDBINFO},
    {"deldbinfo", cmd_deldbinfo, CMD_DELDBINFO},
    {"changedbinfo", cmd_chgdbinfo, CMD_CHGDBINFO},
    {"listdb", cmd_listdb, CMD_LISTDB},
    {NULL, NULL, CMD_UNDEFINED},
};

typedef struct
{
    PTN_ID ptn_id;
    const char *ptn_msg;
} PTN_INFO;

static PTN_INFO msg_str_ptn[] = {
    {PTN_ARG_MISS, "Argument (%s) is missing."},
    {PTN_ARG_MORE, "Argument (%s) is not needed."},
    {PTN_ARG_NUM_ERR, "Argument number is not correct."},
    {PTN_ARG_FORMAT_ERR, "Argument (%s) not correct!"},
    {PTN_ARG_MUST_APPEAR_ERR, "Arg %s should appear at least one."},
    {PTN_DBMT_USER_NOT_EXIST, "DBMT user (%s) not exist."},
    {PTN_DBMT_USER_EXIST, "DBMT user (%s) already exist."},
    {PTN_DBMT_USER_NOT_DEL, "DBMT user (%s) is not allowed to be deleted."},
    {PTN_DBMT_USER_PWD_ERR, "Password (%s) is not correct."},
    {PTN_DB_NOT_AUTH, "Database (%s) is not authorized to DBMT user (%s)."},
    {PTN_DB_ALREADY_AUTH,
        "Database (%s) is already authorized to DBMT user (%s)."},
    {PTN_DB_NOT_EXIST, "Database (%s) does not exist."},
    {PTN_DB_ADD_TWICE, "Database (%s) has been add twice."},
    {PTN_BROKER_ADDR_ERR, "Broker address (%s) format is wrong."},
    {PTN_MEM_ALLOC_ERR, "Memory Allocate Error!"},
    {PTN_UNDEFINE, NULL}
};

const char *
get_msg_by_id (int ptn_id)
{
    int i;

    for (i = 0; msg_str_ptn[i].ptn_id != PTN_UNDEFINE; i++)
    {
        if ((int) msg_str_ptn[i].ptn_id == ptn_id)
        {
            return msg_str_ptn[i].ptn_msg;
        }
    }

    return NULL;
}

int
run_task (const char *task_name, int argc, const char *argv[])
{
    int i;
    int retval = E_FAILURE;

    for (i = 0; cmd_info[i].cmd_name != NULL; i++)
    {
        if (task_name != NULL && strcmp (task_name, cmd_info[i].cmd_name) == 0)
        {
            retval = (*cmd_info[i].cmd_func) (argc, argv);
            return retval;
        }
    }

    return E_CMD_NOT_EXIST;
}

char *
utility_make_getopt_optstring (struct option *opt_array, char *buf)
{
    int i;
    char *p = buf;

    for (i = 0; opt_array[i].name; i++)
    {
        if (opt_array[i].val < 255)
        {
            *p++ = (char) opt_array[i].val;
            if (opt_array[i].has_arg)
            {
                *p++ = ':';
            }
        }
    }
    *p = '\0';
    return buf;
}

void
print_cmd (void)
{
    int i;

    printf ("Available Utilities:\n");

    for (i = 0; cmd_info[i].cmd_name != NULL; i++)
    {
        printf ("    %s\n", cmd_info[i].cmd_name);
    }

    printf ("\n");

    return;
}

int
get_cmdname_by_id (int cmd_id, char *cmd_name, int buf_size)
{
    int i;

    for (i = 0; cmd_info[i].cmd_name != NULL; i++)
    {
        if (cmd_id == (int) cmd_info[i].cmd_id)
        {
            snprintf (cmd_name, buf_size - 1, cmd_info[i].cmd_name);
            return 0;
        }
    }

    return -1;
}

void
print_help_msg (int cmd_id)
{
    const char *pattern = "  %s, %-30s%s\n";
    const char *pattern2 = "%-36s%s\n";
    const char *pattern_long_only = "      %-30s%s\n";
    const char *pattern_usage = "usage: " CM_ADMIN_NAME " %s\n\n";

    switch (cmd_id)
    {
        case CMD_ADDUSER:
            printf ("adduser: Add a DBMT user to the cmserver.\n");
            printf (pattern_usage,
                    "adduser [OPTIONS] <" ARG_DBMT_USER_NAME "> <" ARG_DBMT_USER_PWD
                    ">");
            printf ("valid options:\n");
            printf (pattern, "-b", "--broker",
                    "Authority of broker, default: none; allowed:");
            printf (pattern2, " ", "none, admin, monitor");
            printf (pattern, "-c", "--dbcreate",
                    "Authority of creating a database, only admin user has the auth to create a database;");
            printf (pattern2, " ", "default: none;  allowed: none, admin");
            printf (pattern, "-m", "--monitor",
                    "Authority of monitoring host & database, default: none; allowed:");
            printf (pattern2, " ", "none, admin, monitor");
            printf (pattern, "-d", "--dbinfo",
                    "DBINFO should be formatted as follows:");
            printf (pattern2, " ", "\"<dbname>;<uid>;<broker_ip>,<broker_port>\"");
            break;

        case CMD_DELUSER:
            printf ("deluser: Delete a DBMT user from the cmserver.\n");
            printf (pattern_usage, "deluser <" ARG_DBMT_USER_NAME ">");
            break;

        case CMD_VIEWUSER:
            printf ("viewuser: View DBMT user info.\n");
            printf (pattern_usage, "viewuser [" ARG_DBMT_USER_NAME "]");
            break;

        case CMD_DELDBINFO:
            printf ("deldbinfo: Delete a dbinfo of the specified DBMT user.\n");
            printf (pattern_usage,
                    "deldbinfo <" ARG_DBMT_USER_NAME "> <" ARG_DB_NAME ">");
            break;

        case CMD_ADDDBINFO:
            printf ("adddbinfo: Add a dbinfo to a DBMT user.\n");
            printf (pattern_usage,
                    "adddbinfo [OPTIONS] <" ARG_DBMT_USER_NAME "> <" ARG_DB_NAME
                    ">");
            printf ("valid options:\n");
            printf (pattern, "-u", "--uid",
                    "Uid is the dbuser of the database; default: dba");
            printf (pattern, "-h", "--host",
                    "Host is the ipaddr of the broker; default: localhost");
            printf (pattern, "-p", "--port",
                    "Port is the port of broker; default: 30000");
            break;

        case CMD_CHGDBINFO:
            printf ("changedbinfo: Add a dbinfo to a DBMT user.\n");
            printf (pattern_usage,
                    "changedbinfo [OPTIONS] <" ARG_DBMT_USER_NAME "> <" ARG_DB_NAME
                    ">");
            printf ("valid options:\n");
            printf (pattern, "-u", "--uid  ", "Uid is the dbuser of the database");
            printf (pattern, "-h", "--host", "Host is the ipaddr of the broker");
            printf (pattern, "-p", "--port", "Port is the port of broker");
            break;

        case CMD_CHGUSER_PWD:
            printf
                ("changeuserpwd: Change the password of the specified DBMT user.\n");
            printf (pattern_usage,
                    "changeuserpwd [OPTIONS] <" ARG_DBMT_USER_NAME ">");
            printf ("valid options:\n");
            printf (pattern, "-o", "--oldpass", "Old password of the DBMT user.");
            printf (pattern, "-n", "--newpass", "New password of the DBMT user.");
            printf (pattern_long_only, "--adminpass",
                    "Admin password should be set when old password is not offered.");
            break;

        case CMD_CHGUSER_AUTH:
            printf
                ("changeuserauth: Change the authority info of the DBMT user.\n");
            printf (pattern_usage,
                    "changeuserauth [OPTIONS] <" ARG_DBMT_USER_NAME ">");
            printf ("valid options:\n");
            printf (pattern, "-b", "--broker", "Authority of broker; allowed:");
            printf (pattern2, " ", "none, admin, monitor");
            printf (pattern, "-c", "--dbcreate",
                    "Authority of creating a database, only admin user has the authority to create database;");
            printf (pattern2, " ", "allowed: none, admin");
            printf (pattern, "-m", "--monitor",
                    "Authority of monitoring host and database; allowed:");
            printf (pattern2, " ", "none, admin, monitor");
            break;

        default:
            break;
    }

    return;
}
