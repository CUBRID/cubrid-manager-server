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
 * cm_auto_task.h -
 */

#ifndef _CM_AUTO_TASK_H_
#define _CM_AUTO_TASK_H_

#include "cm_porting.h"
#include "cm_dep.h"

typedef struct
{
  SOCKET sock_fd;
  int state;
  char *user_id;
  char *ip_address;
  short port;
} T_CLIENT_INFO;

int ts_validate_user (nvplist *req, nvplist *res, char *_dbmt_error);
int ts_get_server_version (nvplist *req, nvplist *res);
int ts_check_client_version (nvplist *req, nvplist *res);
int ts_check_already_connected (nvplist *cli_response, int max_index,
                                int current_index,
                                T_CLIENT_INFO *client_info);

#endif /* _CM_AUTO_TASK_H_ */
