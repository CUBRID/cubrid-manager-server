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
 * cm_cmd_task.h -
 */

#ifndef _CM_CMD_TASK_H_
#define _CM_CMD_TASK_H_

#include <stdio.h>
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#else
#include "getopt.h"
#endif

typedef enum
{
  CMD_CHANGEDBPWD,
  CMD_LISTDB,
  CMD_ADDUSER,
  CMD_DELUSER,
  CMD_VIEWUSER,
  CMD_CHGUSER_AUTH,
  CMD_CHGUSER_PWD,
  CMD_ADDDBINFO,
  CMD_DELDBINFO,
  CMD_CHGDBINFO,
  CMD_UNDEFINED,
} CMD_ID;


int cmd_listdb (int argc, const char *in_argv[]);
int cmd_adduser (int argc, const char *in_argv[]);
int cmd_deluser (int argc, const char *in_argv[]);
int cmd_viewuser (int argc, const char *in_argv[]);
int cmd_chguser_pwd (int argc, const char *in_argv[]);
int cmd_chguser_auth (int argc, const char *in_argv[]);
int cmd_adddbinfo (int argc, const char *in_argv[]);
int cmd_deldbinfo (int argc, const char *in_argv[]);
int cmd_chgdbinfo (int argc, const char *in_argv[]);

#endif /* ! _CM_CMD_TASK_H_ */
