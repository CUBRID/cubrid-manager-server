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

#ifndef __CM_SERVER_EXTEND_INFERFACE_H_
#define __CM_SERVER_EXTEND_INFERFACE_H_

#include "cm_user.h"

#include <time.h>
#include <string.h>
#include <json/json.h>

#define STATUS_SUCCESS      "success"
#define STATUS_FAILURE      "failure"
#define STATUS_NONE         "none"

#define MIN_INTERVAL 10
#define MAX_INTERVAL 3600

#define JSON_FIND_V(root, key, err)     \
    if (Json::Value::null == root[key]) \
        return err;

typedef int (*T_EXT_TASK_FUNC) (Json::Value &request,
                                Json::Value &response);

typedef struct
{
  const char *task_str;
  int access_level;
  T_EXT_TASK_FUNC task_func;
  T_USER_AUTH user_auth;
} T_EXTEND_TASK_INFO;

int build_server_header (Json::Value &response, const int status,
                         const char *note);
int get_ext_task_info (const char *task, int access_flag,
                       T_EXT_TASK_FUNC *task_func, T_USER_AUTH *auth);
int ext_get_sys_diskinfo (Json::Value &request, Json::Value &response);
int ext_get_proc_info (Json::Value &request, Json::Value &response);
int ext_set_log_level (Json::Value &request, Json::Value &response);
int ext_set_auto_start (Json::Value &request, Json::Value &response);
int ext_get_auto_start (Json::Value &request, Json::Value &response);
int ext_exec_auto_start (Json::Value &request, Json::Value &response);
int ext_exec_auto_jobs (Json::Value &request, Json::Value &response);
int ext_cub_broker_start (Json::Value &request, Json::Value &response);
int ext_get_db_err_log (Json::Value &request, Json::Value &response);
int ext_get_broker_start_log (Json::Value &request, Json::Value &response);
int ext_send_mail (Json::Value &request, Json::Value &response);
int ext_exec_auto_mail (Json::Value &request, Json::Value &response);
int ext_get_autojob_conf (Json::Value &request, Json::Value &response);
int ext_set_autojob_conf (Json::Value &request, Json::Value &response);
int ext_read_private_data (Json::Value &request, Json::Value &response);
int ext_write_private_data (Json::Value &request, Json::Value &response);
int ext_set_autoexec_query (Json::Value &request, Json::Value &response);
int ext_get_ha_apply_info (Json::Value &request, Json::Value &response);
int ext_get_mon_interval (Json::Value &request, Json::Value &reponse);
int ext_set_mon_interval (Json::Value &request, Json::Value &reponse);
int ext_get_mon_statistic (Json::Value &request, Json::Value &reponse);
int ext_add_dbmt_user_new (Json::Value &request, Json::Value &response);
int ext_update_dbmt_user_new (Json::Value &request, Json::Value &response);
int ext_get_dbmt_user_info_new (Json::Value &request,
                                Json::Value &response);

#define EXT_JOBS_AUTO_START      "auto_start"
#define EXT_JOBS_MAIL_CONF       "mail_config"
#define EXT_JOBS_MAIL_REPORT     "mail_report"

/* utility */
bool ext_set_auto_jobs (const std::string jobkey, Json::Value &jobvalue);
bool ext_get_auto_jobs (const std::string jobkey, Json::Value &jobvalue);
bool ext_ut_validate_userid (const std::string userid);
int ext_ut_add_dblist_to_response (Json::Value &res, bool is_add_dbpath =
                                     false);
int ext_ut_add_userlist_to_response (Json::Value &response,
                                     const T_DBMT_USER &dbmt_user,
                                     bool is_add_pwd = false);
std::string ext_ut_generate_token (const std::string &client_ip,
                                   const std::string &client_id, int proc_id,
                                   time_t login_time);
int ext_ut_validate_token (Json::Value &resquest, Json::Value &response);
bool ext_ut_validate_token (const char *token);
bool ext_ut_validate_auth (Json::Value &request);

#endif
