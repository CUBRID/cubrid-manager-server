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
*  cm_cci_interface.cpp
*/

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <list>

#if defined(WINDOWS)
#include <winsock2.h>
#else
#include <sys/time.h>
#endif

#include <cas_cci.h>
#include <cm_dep.h>

#include "cm_log.h"
#include "cm_cci_interface.h"
#include "cm_server_util.h"
#include "cm_cmd_exec.h"
#include "cm_config.h"

#define SQL_FILE_SUFFIX ".sql"
#define CSV_FILE_SUFFIX ".csv"

using namespace std;

static T_HTTP_TASK_INFO http_task_info[] =
{
  {"exportdb", 0, http_cubrid_exportdb},
  {"importdb", 0, http_cubrid_importdb},
  {"sql", 0, http_cubrid_sql},
  {NULL, 0, NULL}
};

int
get_cci_task_info (const char *task, T_HTTP_TASK_FUNC *task_func)
{
  int i;

  for (i = 0; http_task_info[i].task_str != NULL; i++)
    {
      if (!strcmp (task, http_task_info[i].task_str))
        {
          if (task_func)
            {
              *task_func = http_task_info[i].task_func;
            }
          return http_task_info[i].task_code;
        }
    }

  *task_func = NULL;

  return -1;
}

int
build_common_header (Json::Value &response, int status, const char *note)
{
  response["status"] = status;
  response["note"] = string (note);

  return status;
}

int
_get_col_info (int req, T_CCI_SQLX_CMD &cmd_type, Json::Value &response)
{
  int i, col_count;
  char *temp;
  T_CCI_COL_INFO *res_col_info;
  Json::Value attribute, col;

  res_col_info = cci_get_result_info (req, &cmd_type, &col_count);
  if (cmd_type == CUBRID_STMT_SELECT && !res_col_info)
    {
      return -1;
    }
  response["stmt_type"] = cmd_type;

  for (i = 1; i <= col_count; i++)
    {
      temp = CCI_GET_RESULT_INFO_NAME (res_col_info, i);
      col["name"] = (temp == NULL) ? "" : temp;
      temp = CCI_GET_RESULT_INFO_ATTR_NAME (res_col_info, i);
      col["attr_name"] = (temp == NULL) ? "" : temp;
      temp = CCI_GET_RESULT_INFO_CLASS_NAME (res_col_info, i);
      col["class_name"] = (temp == NULL) ? "" : temp;
      temp = CCI_GET_RESULT_INFO_DEFAULT_VALUE (res_col_info, i);
      col["default"] = (temp == NULL) ? "" : temp;

      col["type"] = CCI_GET_RESULT_INFO_TYPE (res_col_info, i);
      col["precision"] = CCI_GET_RESULT_INFO_PRECISION (res_col_info, i);
      col["scale"] = CCI_GET_RESULT_INFO_SCALE (res_col_info, i);
      col["is_not_null"] = CCI_GET_RESULT_INFO_IS_NON_NULL (res_col_info, i);
      col["is_auto_inc"] =
        CCI_GET_RESULT_INFO_IS_AUTO_INCREMENT (res_col_info, i);
      col["is_unique_key"] =
        CCI_GET_RESULT_INFO_IS_UNIQUE_KEY (res_col_info, i);
      col["is_primary_key"] =
        CCI_GET_RESULT_INFO_IS_PRIMARY_KEY (res_col_info, i);
      col["is_foreign_key"] =
        CCI_GET_RESULT_INFO_IS_FOREIGN_KEY (res_col_info, i);
      col["is_reverse_index"] =
        CCI_GET_RESULT_INFO_IS_REVERSE_INDEX (res_col_info, i);
      col["is_reverse_unique"] =
        CCI_GET_RESULT_INFO_IS_REVERSE_UNIQUE (res_col_info, i);
      col["is_shared"] = CCI_GET_RESULT_INFO_IS_SHARED (res_col_info, i);
      attribute.append (col);
    }
  response["attribute"] = attribute;
  return col_count;
}

typedef struct
{
  int con_id;
  int fetch_size;
  int fetch_offset;
  int dump_plan;
  const char *stmt;
  Json::Value *response;
#ifndef WINDOWS
  pthread_mutex_t *mutex;
  pthread_cond_t *cond;
#endif
} async_stmt_st;

int
_execute_async_stmt (int con_id, const char *stmt, int fetch_size,
                     int fetch_offset, int dump_plan, Json::Value &response)
{
  int req = 0, col_count = 0, res, ind, i, flag = 0;
  char *buffer, oidbuf[1024], *plan = NULL;
  Json::Value values, col, oid;
  T_CCI_ERROR error;
  int elapsed_msec = 0;
  T_CCI_SQLX_CMD cmd_type;
  struct timeval task_begin, task_end;

  response["stmt"] = stmt;
  /* record the start time of running stmt */
  gettimeofday (&task_begin, NULL);

  if ((req = cci_prepare (con_id, (char *) stmt, CCI_PREPARE_INCLUDE_OID, &error)) < 0)
    {
      response["status"] = error.err_code;
      response["note"] = error.err_msg;
      res = req;
      goto handle_error;
    }

  if ((col_count = _get_col_info (req, cmd_type, response)) < 0)
    {
      response["status"] = -1;
      response["note"] = "get col info error";
      res = col_count;
      goto handle_error;
    }

  if (dump_plan)
    {
      flag |= CCI_EXEC_QUERY_INFO;
    }
  if ((res = cci_execute (req, flag, 0, &error)) < 0)
    {
      response["status"] = error.err_code;
      response["note"] = error.err_msg;
      goto handle_error;
    }
  response["exec_retval"] = res;

  if (dump_plan && cmd_type == CUBRID_STMT_SELECT)
    {
      if (cci_get_query_plan (req, &plan) >= 0)
        {
          response["query_plan"] = plan ? plan : "";
          cci_query_info_free (plan);
        }
    }

  if (fetch_size == 0)
    {
      fetch_size = res;
    }

  while (fetch_size--)
    {
      res = cci_cursor (req, fetch_offset, CCI_CURSOR_CURRENT, &error);
      if (res < 0)
        {
          break;
        }

      fetch_offset = 1;
      if ((res = cci_fetch (req, &error)) < 0)
        {
          break;
        }

      col.clear ();
      for (i = 1; i <= col_count; i++)
        {
          buffer = NULL;
          if ((res =
                 cci_get_data (req, i, CCI_A_TYPE_STR, &buffer, &ind)) < 0)
            {
              break;
            }
          if (buffer == NULL)
            {
              col.append (Json::Value::null);
            }
          else
            {
              col.append (buffer);
            }
        }
      values.append (col);

      if (!cci_get_cur_oid (req, oidbuf))
        {
          oid.append (oidbuf);
        }
      else
        {
          oid.append ("");
        }
    }
  response["values"] = values;
  response["oid"] = oid;

  response["status"] = CCI_ER_NO_ERROR;
  response["note"] = "note";
  res = CCI_ER_NO_ERROR;
handle_error:
  if (req > 0)
    {
      cci_close_req_handle (req);
    }

  gettimeofday (&task_end, NULL);
  _ut_timeval_diff (&task_begin, &task_end, &elapsed_msec);
  response["__EXEC_TIME"] = elapsed_msec;
  return res;
}

#ifdef WINDOWS
DWORD WINAPI
_async_stmt (LPVOID lpArg)
#else
void *
_async_stmt (void *lpArg)
#endif
{
  async_stmt_st *pstmt = (async_stmt_st *) lpArg;
  _execute_async_stmt (pstmt->con_id, pstmt->stmt, pstmt->fetch_size,
                       pstmt->fetch_offset, pstmt->dump_plan,
                       * (pstmt->response));

#ifndef WINDOWS
  pthread_mutex_lock (pstmt->mutex);
  pthread_cond_broadcast (pstmt->cond);
  pthread_mutex_unlock (pstmt->mutex);
#endif
  return NULL;
}

#ifdef WINDOWS
int
_execute_stmt (int con_id, const char *stmt, int fetch_size, int fetch_offset,
               int dump_plan, Json::Value &response, unsigned long time_out = 120)
{
  HANDLE hHandles;
  DWORD ThreadID;
  DWORD dwCount = 0, dwWaitResult;
  async_stmt_st *pstmt = (async_stmt_st *) malloc (sizeof (async_stmt_st));
  if (pstmt == NULL)
    {
      return CCI_ER_NO_MORE_MEMORY;
    }

  pstmt->con_id = con_id;
  pstmt->stmt = stmt;
  pstmt->fetch_size = fetch_size;
  pstmt->fetch_offset = fetch_offset;
  pstmt->dump_plan = dump_plan;
  pstmt->response = &response;

  hHandles = CreateThread (NULL, 0, _async_stmt, pstmt, 0, &ThreadID);
  if (hHandles == NULL)
    {
      free (pstmt);
      return build_common_header (response, CCI_ER_DBMS,
                                  "failed to execute stmt");
    }

  dwWaitResult = WaitForSingleObject (hHandles,    // handle to mutex
                                      time_out * 1000);    // no time-out interval

  if (dwWaitResult == WAIT_TIMEOUT)
    {
      TerminateThread (hHandles, 1);
      CloseHandle (hHandles);
      free (pstmt);
      return build_common_header (response, CCI_ER_DBMS,
                                  "execute stmt timeout");
    }

  CloseHandle (hHandles);
  free (pstmt);
  return CCI_ER_NO_ERROR;
}
#else
int
_execute_stmt (int con_id, const char *stmt, int fetch_size, int fetch_offset,
               int dump_plan, Json::Value &response, unsigned long time_out = 120)
{
  int err = 0;
  pthread_t async_thrd;
#if defined(AIX)
  pthread_attr_t thread_attr;
#endif
  pthread_cond_t cond;
  pthread_mutex_t mutex;
  timespec to;
  async_stmt_st *pstmt = (async_stmt_st *) malloc (sizeof (async_stmt_st));
  if (pstmt == NULL)
    {
      return CCI_ER_NO_MORE_MEMORY;
    }

  err = pthread_mutex_init (&mutex, NULL);
  if (err != 0)
    {
      LOG_ERROR ("_execute_stmt : fail to set thread mutex.");
      return build_common_header (response, CCI_ER_DBMS,
                                  "failed to execute stmt");
    }

  err = pthread_cond_init (&cond, NULL);
  if (err != 0)
    {
      LOG_ERROR ("_execute_stmt : fail to set thread condition.");
      return build_common_header (response, CCI_ER_DBMS,
                                  "failed to execute stmt");
    }

  pstmt->con_id = con_id;
  pstmt->stmt = stmt;
  pstmt->fetch_size = fetch_size;
  pstmt->fetch_offset = fetch_offset;
  pstmt->dump_plan = dump_plan;
  pstmt->response = &response;

  pstmt->mutex = &mutex;
  pstmt->cond = &cond;

#if defined(AIX)
  err = pthread_attr_init (&thread_attr);
  if (err != 0)
    {
      LOG_ERROR ("_execute_stmt : fail to set thread attribute.");
      return build_common_header (response, CCI_ER_DBMS,
                                  "failed to execute stmt");
    }

  err = pthread_attr_setdetachstate (&thread_attr, PTHREAD_CREATE_DETACHED);
  if (err != 0)
    {
      LOG_ERROR ("_execute_stmt : fail to set thread detach state.");
      return build_common_header (response, CCI_ER_DBMS,
                                  "failed to execute stmt");
    }

  /* AIX's pthread is slightly different from other systems.
  Its performance highly depends on the pthread's scope and it's related
  kernel parameters. */
  err = pthread_attr_setscope (&thread_attr, PTHREAD_SCOPE_PROCESS);
  if (err != 0)
    {
      LOG_ERROR ("cm_execute_request_async : fail to set thread scope.");
      return build_common_header (response, CCI_ER_DBMS,
                                  "failed to execute stmt");
    }

  err = pthread_attr_setstacksize (&thread_attr, AIX_STACKSIZE_PER_THREAD);
  if (err != 0)
    {
      LOG_ERROR ("cm_execute_request_async : fail to set thread stack size.");
      return build_common_header (response, CCI_ER_DBMS,
                                  "failed to execute stmt");
    }

  err = pthread_create (&async_thrd, &thread_attr, _async_stmt, pstmt);
#else /* except AIX */
  err = pthread_create (&async_thrd, NULL, _async_stmt, pstmt);
#endif

  if (err != 0)
    {
      free (pstmt);
      pthread_mutex_destroy (&mutex);
      pthread_cond_destroy (&cond);
      return build_common_header (response, CCI_ER_DBMS,
                                  "failed to execute stmt");
    }
  pthread_mutex_lock (&mutex);
  to.tv_sec = time (NULL) + time_out;
  to.tv_nsec = 0;
  err = pthread_cond_timedwait (&cond, &mutex, &to);
  pthread_mutex_unlock (&mutex);
  if (err == ETIMEDOUT)
    {
      pthread_cancel (async_thrd);
    }
  else
    {
      pthread_join (async_thrd, NULL);
    }

  pthread_mutex_destroy (&mutex);
  pthread_cond_destroy (&cond);

  free (pstmt);

  if (err == ETIMEDOUT)
    return build_common_header (response, CCI_ER_QUERY_TIMEOUT,
                                "execute stmt timeout");

  return CCI_ER_NO_ERROR;
}
#endif

int
_saveto (string file_name, string info, string flag)
{
  FILE *fp = fopen (file_name.c_str (), flag.c_str ());
  if (fp == NULL)
    {
      return -1;
    }

  fwrite (info.c_str (), 1, info.size (), fp);
  fclose (fp);
  return 0;
}

string
_get_auto_increment ()
{
  //" AUTO_INCREMENT(1,1)"
  return "";
}

string
str_replace (const string &orign, const string &oldstr,
             const string &newstr)
{
  size_t pos = 0;
  string tempstr = orign;
  string::size_type newlen = newstr.length ();
  string::size_type oldlen = oldstr.length ();
  while (true)
    {
      pos = tempstr.find (oldstr, pos);
      if (pos == string::npos)
        {
          break;
        }

      tempstr.replace (pos, oldlen, newstr);
      pos += newlen;
    }

  return tempstr;
}


string
_fix_cci_get_attr_type_str (const char *buf)
{
  int flag = 0;
  const char *p = buf;
  string fix_str = buf;
  if (!strstr (buf, "float") && strstr (buf, "floa"))
    {
      fix_str = str_replace (fix_str, "floa", "float");
    }
  if (!strstr (buf, "blob") && strstr (buf, "blo"))
    {
      fix_str = str_replace (fix_str, "blo", "blob");
    }
  if (!strstr (buf, "clob") && strstr (buf, "clo"))
    {
      fix_str = str_replace (fix_str, "clo", "clob");
    }
  if (!strstr (buf, "datetime") && strstr (buf, "datetim"))
    {
      fix_str = str_replace (fix_str, "datetim", "datetime");
    }
  else if (!strstr (buf, "date") && strstr (buf, "dat"))
    {
      fix_str = str_replace (fix_str, "dat", "date");
    }
  else if (!strstr (buf, "timestamp") && strstr (buf, "timestam"))
    {
      fix_str = str_replace (fix_str, "timestam", "timestamp");
    }
  else if (!strstr (buf, "time") && strstr (buf, "tim"))
    {
      fix_str = str_replace (fix_str, "tim", "time");
    }
  if (!strstr (buf, "monetary") && strstr (buf, "monetar"))
    {
      fix_str = str_replace (fix_str, "monetar", "monetary");
    }
  if (!strstr (buf, "integer") && strstr (buf, "intege"))
    {
      fix_str = str_replace (fix_str, "intege", "integer");
    }
  if (!strstr (buf, "double") && strstr (buf, "doubl"))
    {
      fix_str = str_replace (fix_str, "doubl", "double");
    }
  if (!strstr (buf, "smallint") && strstr (buf, "smallin"))
    {
      fix_str = str_replace (fix_str, "smallin", "smallint");
    }
  if (!strstr (buf, "string") && strstr (buf, "strin"))
    {
      fix_str = str_replace (fix_str, "strin", "string");
    }
  if (!strstr (buf, "bigint") && strstr (buf, "bigin"))
    {
      fix_str = str_replace (fix_str, "bigin", "bigint");
    }

  while (*p != 0)
    {
      if (*p == '(')
        {
          flag++;
        }
      if (*p == ')')
        {
          flag--;
        }
      p++;
    }
  if (flag > 0)
    {
      fix_str.append (")");
    }
  return fix_str;
}

int
_get_attribute_type (int con_id, string db_name, string class_name,
                     Json::Value &attribute, list < string > &result_list)
{
  string schema;
  char buf[256];
  T_CCI_ERROR err_buf;
  string st_default =
    attribute["default"].asString () ==
    "" ? "" : " DEFAULT '" + attribute["default"].asString () + "'";

  schema += "\"" + attribute["name"].asString () + "\" ";

  /*cci_get_attr_type_str has bug, so before fix ,we use _fix_cci_get_attr_type_str */
  cci_get_attr_type_str (con_id, (char *) class_name.c_str (),
                         (char *) attribute["name"].asString ().c_str (), buf,
                         256, &err_buf);
  /* schema += buf; */
  schema += _fix_cci_get_attr_type_str (buf);
  schema += st_default;
  if (attribute["is_auto_inc"].asInt ())
    {
      schema += _get_auto_increment ();
    }

  if (attribute["is_not_null"].asInt ())
    {
      schema += " NOT NULL";
    }

  if (!attribute["is_primary_key"].asInt ())
    {
      if (attribute["is_unique_key"].asInt ())
        {
          schema += " UNIQUE";
        }
    }
  attribute["type_str"] = buf;

  result_list.push_back (schema);

  return 0;
}

int
_get_class_primary_key (string &pk, int has_pk, Json::Value &attribute)
{
  if (!attribute["is_primary_key"].asInt ())
    {
      return 0;
    }

  if (has_pk)
    {
      pk += ",";
    }
  pk += "\"" + attribute["name"].asString () + "\"";
  return 1;
}

int
_get_class_constraint (int con_id, string class_name, Json::Value &result)
{
  int cci_request = 0, cci_retval, cci_ind;
  T_CCI_ERROR cci_error;
  UNI_CCI_A_TYPE cci_value;
  Json::Value constraint;
  string index_name;

  if ((cci_request = cci_schema_info (con_id, CCI_SCH_CONSTRAINT,
                                      (char *) class_name.c_str (), NULL, 0,
                                      &cci_error)) < 0)
    {
      return -1;
    }

  while (1)
    {
      cci_retval = cci_cursor (cci_request, 1, CCI_CURSOR_CURRENT, &cci_error);
      if (cci_retval < 0)
        {
          break;
        }

      if ((cci_retval = cci_fetch (cci_request, &cci_error)) < 0)
        {
          break;
        }

      constraint.clear ();
      /* type */
      if ((cci_retval = cci_get_data (cci_request, 1, CCI_A_TYPE_INT, &cci_value, &cci_ind)) < 0)
        {
          break;
        }
      constraint["type"] = cci_value.i;

      /* asc_or_desc */
      if ((cci_retval = cci_get_data (cci_request, 8, CCI_A_TYPE_STR, &cci_value, &cci_ind)) < 0)
        {
          break;
        }
      constraint["asc_or_desc"] = cci_value.str;

      /* index name */
      if ((cci_retval = cci_get_data (cci_request, 2, CCI_A_TYPE_STR, &cci_value, &cci_ind)) < 0)
        {
          break;
        }
      index_name = cci_value.str;
      constraint["index_name"] = cci_value.str;

      /* column name */
      if ((cci_retval = cci_get_data (cci_request, 3, CCI_A_TYPE_STR, &cci_value, &cci_ind)) < 0)
        {
          break;
        }
      constraint["attr_name"] = cci_value.str;

      /* num pages */
      if ((cci_retval = cci_get_data (cci_request, 4, CCI_A_TYPE_INT, &cci_value, &cci_ind)) < 0)
        {
          break;
        }
      constraint["num_pages"] = cci_value.i;

      /* num keys */
      if ((cci_retval = cci_get_data (cci_request, 5, CCI_A_TYPE_INT, &cci_value, &cci_ind)) < 0)
        {
          break;
        }
      constraint["num_keys"] = cci_value.i;

      /* primary key */
      if ((cci_retval = cci_get_data (cci_request, 6, CCI_A_TYPE_INT, &cci_value, &cci_ind)) < 0)
        {
          break;
        }
      constraint["primary_key"] = cci_value.i;

      /* key order */
      if ((cci_retval = cci_get_data (cci_request, 7, CCI_A_TYPE_INT, &cci_value, &cci_ind)) < 0)
        {
          break;
        }
      constraint["key_order"] = cci_value.i;

      result[index_name].append (constraint);
    }
  cci_close_req_handle (cci_request);
  return 0;
}

int
_get_class_foreign_key (int con_id, string class_name, Json::Value &result)
{
  int cci_request = 0, cci_retval, cci_ind;
  T_CCI_ERROR cci_error;
  UNI_CCI_A_TYPE cci_value;
  Json::Value constraint;
  string fk_name;
  if ((cci_request =
         cci_schema_info (con_id, CCI_SCH_IMPORTED_KEYS, (char *) class_name.c_str (), NULL, 0, &cci_error)) < 0)
    {
      return -1;
    }

  while (1)
    {
      cci_retval = cci_cursor (cci_request, 1, CCI_CURSOR_CURRENT, &cci_error);
      if (cci_retval < 0)
        {
          break;
        }

      if ((cci_retval = cci_fetch (cci_request, &cci_error)) < 0)
        {
          break;
        }

      constraint.clear ();

      /* pk class name */
      if ((cci_retval = cci_get_data (cci_request, 1, CCI_A_TYPE_STR, &cci_value, &cci_ind)) < 0)
        {
          break;
        }
      constraint["pk_table_name"] = cci_value.str;

      /* pk column name */
      if ((cci_retval = cci_get_data (cci_request, 2, CCI_A_TYPE_STR, &cci_value, &cci_ind)) < 0)
        {
          break;
        }
      constraint["pk_column_name"] = cci_value.str;

      /* fk class name */
      if ((cci_retval = cci_get_data (cci_request, 3, CCI_A_TYPE_STR, &cci_value, &cci_ind)) < 0)
        {
          break;
        }
      constraint["fk_table_name"] = cci_value.str;

      /* fk column name */
      if ((cci_retval = cci_get_data (cci_request, 4, CCI_A_TYPE_STR, &cci_value, &cci_ind)) < 0)
        {
          break;
        }
      constraint["fk_column_name"] = cci_value.str;

      /* key sequence number */
      if ((cci_retval = cci_get_data (cci_request, 5, CCI_A_TYPE_INT, &cci_value, &cci_ind)) < 0)
        {
          break;
        }
      constraint["key_seq"] = cci_value.i;

      /* update rule */
      if ((cci_retval = cci_get_data (cci_request, 6, CCI_A_TYPE_INT, &cci_value, &cci_ind)) < 0)
        {
          break;
        }
      constraint["update_action"] = cci_value.i;

      /* delete rule */
      if ((cci_retval = cci_get_data (cci_request, 7, CCI_A_TYPE_INT, &cci_value, &cci_ind)) < 0)
        {
          break;
        }
      constraint["delete_action"] = cci_value.i;

      /* foreign key name */
      if ((cci_retval = cci_get_data (cci_request, 8, CCI_A_TYPE_STR, &cci_value, &cci_ind)) < 0)
        {
          break;
        }
      fk_name = cci_value.str;
      constraint["fk_name"] = cci_value.str;

      /* primary key name */
      if ((cci_retval = cci_get_data (cci_request, 9, CCI_A_TYPE_STR, &cci_value, &cci_ind)) < 0)
        {
          break;
        }
      constraint["fk_name"] = cci_value.str;

      result[fk_name].append (constraint);
    }
  cci_close_req_handle (cci_request);
  return 0;
}

string
_get_action_type_str (int action)
{
  switch (action)
    {
    case 0:
      return "CASCADE";
    case 1:
      return "RESTRICT";
    case 2:
      return "NO ACTION";
    case 3:
      return "SET NULL";
    default:
      break;
    }
  return "";
}

string
_get_index_type_str (int type)
{
  switch (type)
    {
    case 0:
      return "UNIQUE INDEX";
    case 1:
      return "INDEX";
    case 2:
      return "REVERSE UNIQUE INDEX";
    case 3:
      return "REVERSE INDEX";
    default:
      break;
    }
  return "";
}

int
_build_foreign_key_str (Json::Value &f_key, list < string > &schema)
{
  int i = 0, size, on_delete = -1, on_update = -1;
  string f_key_str = "";
  string fk_col_name, pk_col_name, pk_tab_name;
  Json::Value::Members members (f_key.getMemberNames ());

  for (Json::Value::Members::iterator it = members.begin ();
       it != members.end (); ++it)
    {
      size = f_key[*it].size ();
      fk_col_name = "";
      pk_col_name = "";
      for (i = 0; i < size; i++)
        {
          fk_col_name +=
            "\"" + f_key[*it][i]["fk_column_name"].asString () + "\"";
          pk_col_name +=
            "\"" + f_key[*it][i]["pk_column_name"].asString () + "\"";
          pk_tab_name =
            "\"" + f_key[*it][i]["pk_table_name"].asString () + "\"";
          on_delete = f_key[*it][i]["delete_action"].asInt ();
          on_update = f_key[*it][i]["update_action"].asInt ();
          if (i != (size - 1))
            {
              fk_col_name += ",";
              pk_col_name += ",";
            }
        }
      f_key_str = "FOREIGN KEY (" + fk_col_name + ") REFERENCES "
                  + pk_tab_name + "(" + pk_col_name + ") ON DELETE "
                  + _get_action_type_str (on_delete) + " ON UPDATE "
                  + _get_action_type_str (on_update);

      schema.push_back (f_key_str);
    }
  return 0;
}


int
_build_index_str (Json::Value &index, string class_name,
                  list < string > &schema)
{
  int i = 0, size, type = 0;
  string index_str = "", asc = "";
  string attr_name, pk_col_name, pk_tab_name;
  Json::Value::Members members (index.getMemberNames ());

  for (Json::Value::Members::iterator it = members.begin ();
       it != members.end (); ++it)
    {
      size = index[*it].size ();
      attr_name = "";
      for (i = 0; i < size; i++)
        {
          attr_name += "\"" + index[*it][i]["attr_name"].asString () + "\"";
          asc = index[*it][i]["asc_or_desc"].asString ();
          type = index[*it][i]["type"].asInt ();

          if (asc == "D")
            {
              attr_name += " DESC";
            }

          if (i != (size - 1))
            {
              attr_name += ",";
            }
        }

      /* exclude ASC UNIQUE */
      if (type == 0 && asc == "A")
        {
          continue;
        }

      index_str =
        "CREATE " + _get_index_type_str (type) + " ON \"" + class_name +
        "\"(" + attr_name + ");";

      schema.push_back (index_str);
    }
  return 0;
}

string
_dump_constraint_list (list < string > &schema_list, const string quote = ",")
{
  list < string >::iterator itor;
  string schema = "";
  int flag = 0;
  for (itor = schema_list.begin (); itor != schema_list.end ();
       itor++, flag++)
    {
      if (flag)
        {
          schema += quote + "\n";
        }
      schema += *itor;
    }
  schema += "\n";
  return schema;
}

int
_export_class_schema (int con_id, string db_name, string class_name,
                      Json::Value &result, string export_path)
{
  int i, has_primary_key = 0;
  int attr_size = result["attribute"].size ();
  Json::Value fkey, index;
  string schema = "CREATE TABLE \"" + class_name + "\" (\n";
  string pk = "CONSTRAINT PRIMARY KEY(";
  list < string > schema_list, index_list;

  for (i = 0; i < attr_size; i++)
    {
      _get_attribute_type (con_id, db_name, class_name, result["attribute"][i], schema_list);
    }

  for (i = 0; i < attr_size; i++)
    {
      has_primary_key += _get_class_primary_key (pk, has_primary_key, result["attribute"][i]);
    }

  if (has_primary_key)
    {
      schema_list.push_back (pk + ")");
    }

  if (_get_class_foreign_key (con_id, class_name, fkey) == 0)
    {
      _build_foreign_key_str (fkey, schema_list);
    }

  schema += _dump_constraint_list (schema_list) + ");\n";

  if (_get_class_constraint (con_id, class_name, index) == 0)
    {
      _build_index_str (index, class_name, index_list);
    }

  schema += _dump_constraint_list (index_list, "") + "\n";

  return _saveto (export_path, schema, "a+");
}

string
_quota_mark (string &col)
{
  size_t it, size = col.size ();
  string result;
  for (it = 0; it != size; it++)
    {
      if (col[it] == '\'')
        {
          result.append (1, '\'');
        }

      result.append (1, col[it]);
    }

  return result;
}

int
_export_class_object_sql (string class_name, Json::Value &result,
                          string export_path)
{
  unsigned int i, j;
  string header = "insert into \"" + class_name + "\" ";
  string values, col, type_str, prefix;
  header = header + " values ";
  for (i = 0; i < result["values"].size (); i++)
    {
      values = "(";
      for (j = 0; j < result["values"][i].size (); j++)
        {
          type_str = result["attribute"][j]["type_str"].asString ();
          if (type_str == "date")
            {
              prefix = "DATE";
            }
          else
            {
              prefix = "";
            }

          col = result["values"][i][j].asString ();

          values += prefix + "'" + _quota_mark (col) + "'";
          if (j != (result["values"][i].size () - 1))
            {
              values += ", ";
            }
        }
      values += ");\n";
      _saveto (export_path, header + values, "a+");
    }
  return 0;
}

int
_export_class_object_csv (string class_name, Json::Value &result,
                          string export_path)
{
  unsigned int i, j;
  string values, col;

  for (i = 0; i < result["values"].size (); i++)
    {
      values = "";
      for (j = 0; j < result["values"][i].size (); j++)
        {
          col = result["values"][i][j].asString ();
          values += "\"" + _quota_mark (col) + "\"";
          if (j != (result["values"][i].size () - 1))
            {
              values += ",";
            }
        }
      values += "\n";
      _saveto (export_path, values, "a+");
    }
  return 0;
}

typedef enum
{
  DUMP_TYPE_SQL = 0,
  DUMP_TYPE_CSV
} E_DUMP_TYPE;

typedef enum
{
  DUMP_FLAG_DATA = 1,
  DUMP_FLAG_SCHEMA = 2,
  DUMP_FLAG_DATA_SCHEMA = 3
} E_DUMP_FLAG;

void
_export_class (int con_id, string db_name, string class_name,
               string export_path, int export_type, int export_flag,
               Json::Value &result)
{
  switch (export_type)
    {
    case DUMP_TYPE_SQL:
      if (export_flag & DUMP_FLAG_SCHEMA)
        {
          _export_class_schema (con_id, db_name, class_name, result, export_path);
        }
      if (export_flag & DUMP_FLAG_DATA)
        {
          _export_class_object_sql (class_name, result, export_path);
        }
      break;
    case DUMP_TYPE_CSV:
      _export_class_object_csv (class_name, result, export_path);
      break;
    default:
      break;
    }
}

static bool
_get_export_path (string &export_path, string &export_filename,
                  int export_type, const string &db_name)
{
  time_t time_now;
  struct tm *tm_now = NULL;
  char file_name_dt[PATH_MAX];

  file_name_dt[0] = '\0';

  export_filename = "";
  export_path = string (sco.szCWMPath) + "/files/";
  if (access ((char *) export_path.c_str (), F_OK | R_OK | W_OK | X_OK) < 0)
    {
      return false;
    }

  time_now = time (NULL);
  if (time_now == -1)
    {
      return false;
    }

#ifndef WINDOWS
  tm_now = new struct tm ();
  if (localtime_r (&time_now, tm_now) == NULL)
    {
      delete tm_now;
      tm_now = NULL;
      return false;
    }
#else
  tm_now = localtime (&time_now);
  if (tm_now == NULL)
    {
      return false;
    }
#endif

  if (strftime (file_name_dt, PATH_MAX, "_%Y%m%d_%H%M%S", tm_now) == 0)
    {
#ifndef WINDOWS
      delete tm_now;
#endif
      tm_now = NULL;
      return false;
    }

  bool success = true;
  switch (export_type)
    {
    case DUMP_TYPE_SQL:
      export_filename = db_name + file_name_dt + SQL_FILE_SUFFIX;
      break;

    case DUMP_TYPE_CSV:
      export_filename = db_name + file_name_dt + CSV_FILE_SUFFIX;
      break;

    default:
      export_filename = "";
      export_path = "";
      success = false;
      break;
    }

#ifndef WINDOWS
  delete tm_now;
#endif
  tm_now = NULL;

  if (success)
    {
      export_path += export_filename;
    }
  return success;
}

int
http_cubrid_exportdb (Json::Value &request, Json::Value &response)
{
  int con_handle, port, export_size, export_type, export_flag, res;
  unsigned int i;
  int time_out;
  string ip, db_name, db_user, dbpasswd;
  string export_path, export_filename, stmt, classname;
  Json::Value result;
  T_CCI_ERROR error;

  ip = request.get ("bip", "localhost").asString ();
  port = request.get ("bport", sco.iCMS_port).asInt ();
  export_size = request.get ("export_size", 0).asInt ();
  export_type = request.get ("export_type", DUMP_TYPE_SQL).asInt ();
  export_flag = request.get ("export_flag", DUMP_FLAG_DATA_SCHEMA).asInt ();
  time_out = request.get ("time_out", 120).asInt ();

  JSON_FIND_V (request, "dbname",
               build_common_header (response, ERR_PARAM_MISSING, "dbname"));
  db_name = request["dbname"].asString ();

  JSON_FIND_V (request, "dbid",
               build_common_header (response, ERR_PARAM_MISSING, "dbid"));
  db_user = request["dbid"].asString ();

  JSON_FIND_V (request, "dbpasswd",
               build_common_header (response, ERR_PARAM_MISSING, "dbpasswd"));
  dbpasswd = request["dbpasswd"].asString ();

  if (!_get_export_path (export_path, export_filename, export_type, db_name))
    {
      return build_common_header (response, ERR_WITH_MSG, "Can not generate the export file name.");
    }

  con_handle =
    cci_connect ((char *) ip.c_str (), port, (char *) db_name.c_str (),
                 (char *) db_user.c_str (), (char *) dbpasswd.c_str ());
  if (con_handle < 0)
    {
      cci_get_err_msg (con_handle, error.err_msg, 1024);
      return build_common_header (response, con_handle, error.err_msg);
    }

  if (Json::Value::null != request["charset"])
    {
      cci_set_charset (con_handle, (char *) request["charset"].asString ().c_str ());
    }

  _saveto (export_path, "", "w");
  JSON_FIND_V (request, "class",
               build_common_header (response, ERR_PARAM_MISSING, "stmt"));
  for (i = 0; i < request["class"].size (); i++)
    {
      result.clear ();
      classname = request["class"][i].asString ();
      stmt = "select * from \"" + classname + "\"";
      res = _execute_stmt (con_handle, stmt.c_str (), export_size, 1, 0, result, time_out);
      if (res < 0)
        {
          result["class"] = classname;
          response["result"].append (result);
          continue;
        }
      _export_class (con_handle, db_name, request["class"][i].asString (),
                     export_path, export_type, export_flag, result);
    }

  cci_disconnect (con_handle, &error);
  build_common_header (response, ERR_NO_ERROR, "none");
  response["export_filename"] = export_filename;

  return ERR_NO_ERROR;
}

int
_import_class_sql (Json::Value &request, Json::Value &response)
{
  string ip, db_name, db_user, dbpasswd;
  string import_filename;
  string import_path;
  string error_continue_option = "y";
  T_CSQL_RESULT *csql_result;
  T_CUBRID_MODE mode;

  JSON_FIND_V (request, "dbname",
               build_common_header (response, ERR_PARAM_MISSING, "dbname"));
  db_name = request["dbname"].asString ();

  JSON_FIND_V (request, "dbid",
               build_common_header (response, ERR_PARAM_MISSING, "dbid"));
  db_user = request["dbid"].asString ();

  JSON_FIND_V (request, "dbpasswd",
               build_common_header (response, ERR_PARAM_MISSING, "dbpasswd"));
  dbpasswd = request["dbpasswd"].asString ();

  JSON_FIND_V (request, "import_filename",
               build_common_header (response, ERR_PARAM_MISSING,
                                    "Parameter(import_filename) missing in the request."));

  import_filename = request["import_filename"].asString ();
  import_path = string (sco.dbmt_tmp_dir) + "/" + import_filename;

  mode = (uDatabaseMode ((char *) db_name.c_str (), NULL) ==
          DB_SERVICE_MODE_NONE ? CUBRID_MODE_SA : CUBRID_MODE_CS);
  csql_result =
    cmd_csql ((char *) db_name.c_str (), (char *) db_user.c_str (),
              (char *) dbpasswd.c_str (), mode, (char *) import_path.c_str (),
              NULL, (char *) error_continue_option.c_str ());
  if (csql_result == NULL)
    {
      return build_common_header (response, ERR_WITH_MSG,
                                  "Error occur when execurating csql.");
    }
  else if (strlen (csql_result->err_msg) != 0)
    {
      build_common_header (response, ERR_WITH_MSG, csql_result->err_msg);
      free (csql_result);
      return ERR_WITH_MSG;
    }
  free (csql_result);
  return build_common_header (response, ERR_NO_ERROR, "none");
}

char *
_char_replace (char *str, char src, char dst)
{
  char *p = str;
  while (*p != 0)
    {
      if (*p == src)
        {
          *p = dst;
        }
      p++;
    }

  return str;
}

string
_build_with_double_quotes (char *str, const char delimiter)
{
  char *pos = str;
  char *begin = NULL, *end = NULL;
  int quotes = 0;
  string value;
  while (*pos != 0)
    {
      if (*pos == '"')
        {
          if (quotes++)
            {
              end = pos;
            }
          else
            {
              begin = pos;
            }
        }
      if (*pos == delimiter && 0 == (quotes % 2))
        {
          if (begin)
            {
              *begin = '\'';
            }
          if (end)
            {
              *end = '\'';
            }
          *pos = 0;
          value += begin;
          value += ",";
          quotes = 0;
        }
      pos++;
    }
  if (begin)
    {
      *begin = '\'';
    }
  if (end)
    {
      *end = '\'';
    }
  value += begin;
  return value;
}

string
_build_without_quotes (char *str, const char delimiter)
{
  char *pos = str;
  char *begin = str;
  string value;
  while ((pos = strchr (begin, delimiter)) != NULL)
    {
      *pos = 0;
      value += "'";
      value += begin;
      value += "',";
      begin = pos + 1;
    }
  value += "'";
  value += begin;
  value += "'";
  return value;
}

string
_build_quotes (char *str, const char delimiter)
{
  if (str == NULL)
    {
      return "";
    }
  if (*str == '"')
    {
      return _build_with_double_quotes (str, delimiter);
    }
  return _build_without_quotes (str, delimiter);
}

int
_import_class_csv (Json::Value &request, Json::Value &response)
{
  string ip, db_name, db_user, dbpasswd, stmt, classname;
  string import_path;
  string import_filename;
  FILE *fp;
  char buf[1024];
  int con_handle, port, time_out, success = 0, fail = 0;
  Json::Value result;
  T_CCI_ERROR error;

  ip = request.get ("bip", "localhost").asString ();
  port = request.get ("bport", sco.iCMS_port).asInt ();
  time_out = request.get ("time_out", 120).asInt ();

  JSON_FIND_V (request, "dbname",
               build_common_header (response, ERR_PARAM_MISSING, "dbname"));
  db_name = request["dbname"].asString ();

  JSON_FIND_V (request, "dbid",
               build_common_header (response, ERR_PARAM_MISSING, "dbid"));
  db_user = request["dbid"].asString ();

  JSON_FIND_V (request, "dbpasswd",
               build_common_header (response, ERR_PARAM_MISSING, "dbpasswd"));
  dbpasswd = request["dbpasswd"].asString ();

  JSON_FIND_V (request, "classname",
               build_common_header (response, ERR_PARAM_MISSING, "classname"));
  classname = request["classname"].asString ();

  JSON_FIND_V (request, "import_filename",
               build_common_header (response, ERR_PARAM_MISSING,
                                    "Parameter(import_filename) missing in the request"));
  import_filename = request["import_filename"].asString ();
  import_path = string (sco.dbmt_tmp_dir) + "/" + import_filename;

  fp = fopen (import_path.c_str (), "r");
  if (NULL == fp)
    {
      return build_common_header (response, ERR_GENERAL_ERROR, "failed to open import file!");
    }

  con_handle =
    cci_connect ((char *) ip.c_str (), port, (char *) db_name.c_str (),
                 (char *) db_user.c_str (), (char *) dbpasswd.c_str ());
  if (con_handle < 0)
    {
      cci_get_err_msg (con_handle, error.err_msg, 1024);
      fclose (fp);
      return build_common_header (response, con_handle, error.err_msg);
    }

  while (fgets (buf, 1024, fp))
    {
      ut_trim (buf);
      stmt =
        "insert into \"" + classname + "\" values (" + _build_quotes (buf, ',') + string (")");
      _execute_stmt (con_handle, stmt.c_str (), 0, 1, 0, result, time_out);
      if (result["status"].asInt () != CCI_ER_NO_ERROR)
        {
          response["result"].append (stmt + " error");
          fail++;
        }
      else
        {
          success++;
        }

    }

  fclose (fp);
  response["fail_cnt"] = fail;
  response["success_cnt"] = success;
  cci_end_tran (con_handle, CCI_TRAN_COMMIT, &error);
  cci_disconnect (con_handle, &error);
  build_common_header (response, ERR_NO_ERROR, "none");
  return ERR_NO_ERROR;
}

int
http_cubrid_importdb (Json::Value &request, Json::Value &response)
{
  int import_type, result = ERR_NO_ERROR;
  string ip, db_name, db_user, dbpasswd;
  string import_path, stmt;

  import_type = request.get ("import_type", DUMP_TYPE_SQL).asInt ();
  switch (import_type)
    {
    case DUMP_TYPE_SQL:
      result = _import_class_sql (request, response);
      break;
    case DUMP_TYPE_CSV:
      result = _import_class_csv (request, response);
      break;
    default:
      break;
    }
  return result;
}

int
http_cubrid_sql (Json::Value &request, Json::Value &response)
{
  int con_handle, port, fetch_size, fetch_offset, dump_plan, time_out;
  unsigned int i;
  int return_err = 0, err_continue = 0;
  int autocommit = 1;
  string ip, db_name, db_user, dbpasswd;
  Json::Value result;
  T_CCI_ERROR error;

  ip = request.get ("bip", "localhost").asString ();
  port = request.get ("bport", sco.iCMS_port).asInt ();
  err_continue = request.get ("error_continue", 0).asInt ();
  fetch_size = request.get ("fetch_size", 5000).asInt ();
  fetch_offset = request.get ("fetch_offset", 1).asInt ();
  dump_plan = request.get ("dump_plan", 0).asInt ();
  time_out = request.get ("time_out", 120).asInt ();
  autocommit = request.get ("autocommit", 1).asInt ();

  JSON_FIND_V (request, "dbname",
               build_common_header (response, ERR_PARAM_MISSING, "dbname"));
  db_name = request["dbname"].asString ();

  JSON_FIND_V (request, "dbid",
               build_common_header (response, ERR_PARAM_MISSING, "dbid"));
  db_user = request["dbid"].asString ();

  JSON_FIND_V (request, "dbpasswd",
               build_common_header (response, ERR_PARAM_MISSING, "dbpasswd"));
  dbpasswd = request["dbpasswd"].asString ();

  con_handle =
    cci_connect ((char *) ip.c_str (), port, (char *) db_name.c_str (),
                 (char *) db_user.c_str (), (char *) dbpasswd.c_str ());
  if (con_handle < 0)
    {
      cci_get_err_msg (con_handle, error.err_msg, 1024);
      return build_common_header (response, con_handle, error.err_msg);
    }

  cci_set_autocommit (con_handle, (CCI_AUTOCOMMIT_MODE) autocommit);

  if (Json::Value::null != request["charset"])
    {
      cci_set_charset (con_handle, (char *) request["charset"].asString ().c_str ());
    }

  JSON_FIND_V (request, "stmt",
               build_common_header (response, ERR_PARAM_MISSING, "stmt"));
  for (i = 0; i < request["stmt"].size (); i++)
    {
      result.clear ();

      if (_execute_stmt (con_handle, request["stmt"][i].asString ().c_str (), fetch_size,
                         fetch_offset, dump_plan, result, time_out) < 0
          && 0 == err_continue)
        {
          return_err = 1;
          response["result"].append (result);
          break;
        }

      response["result"].append (result);
    }

  cci_end_tran (con_handle, CCI_TRAN_COMMIT, &error);
  cci_disconnect (con_handle, &error);
  build_common_header (response, ERR_NO_ERROR, "none");
  return ERR_NO_ERROR;
}

int
cub_cci_request_handler (Json::Value &request, Json::Value &response)
{
  int res;
  int elapsed_msec = 0;
  struct timeval task_begin, task_end;
  string task_name;
  T_HTTP_TASK_FUNC task_func = NULL;

  JSON_FIND_V (request, "task",
               build_common_header (response, ERR_PARAM_MISSING, "task"));
  task_name = request["task"].asString ();

  /* record the start time of running cub_manager task. */
  gettimeofday (&task_begin, NULL);

  get_cci_task_info (task_name.c_str (), &task_func);
  if (task_func)
    {
      try
        {
          res = (*task_func) (request, response);
        }
      catch (exception &e)
        {
          res = build_common_header (response, ERR_REQUEST_FORMAT, e.what ());
        }
    }
  else
    {
      res = build_common_header (response, ERR_UNDEFINED_TASK, task_name.c_str ());
    }

  /* record the end time of running cub_manager task. */
  gettimeofday (&task_end, NULL);

  /* caculate the running time of cub_manager task. */
  _ut_timeval_diff (&task_begin, &task_end, &elapsed_msec);
  response["__EXEC_TIME"] = elapsed_msec;

  return res;
}
