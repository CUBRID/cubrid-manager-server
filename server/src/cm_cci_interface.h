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

#ifndef __CM_CCI_H__
#define __CM_CII_H__
#include <json/json.h>

typedef int (*T_HTTP_TASK_FUNC) (Json::Value &request,
                                 Json::Value &response);

typedef struct
{
  const char *task_str;
  int task_code;
  T_HTTP_TASK_FUNC task_func;
} T_HTTP_TASK_INFO;

typedef union tagUNI_CCI_A_TYPE
{
  char *str;
  int i;
  short s;
  float f;
  double d;
} UNI_CCI_A_TYPE;

#define JSON_FIND_V(root, key, err)     \
    if (Json::Value::null == root[key]) \
        return err;

int http_cubrid_exportdb (Json::Value &request, Json::Value &response);
int http_cubrid_importdb (Json::Value &request, Json::Value &response);
int http_cubrid_sql (Json::Value &request, Json::Value &response);
int get_cci_task_info (const char *task, T_HTTP_TASK_FUNC *task_func);
int cub_cci_request_handler (Json::Value &request, Json::Value &response);

#endif
