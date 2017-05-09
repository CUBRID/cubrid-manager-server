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

#include "cm_log.h"

#include <string.h>
#ifdef WINDOWS
#include <Psapi.h>
#else
#include <sys/statvfs.h>
#include <dirent.h>
#include <sys/stat.h>
#endif

#include "cm_dep.h"
#include "cm_stat.h"
#include "cm_cmd_exec.h"
#include "cm_server_util.h"
#include "cm_text_encryption.h"
#include "cm_server_extend_interface.h"
#include "cm_mailer.h"
#include "cm_mon_stat.h"
#include "cm_user.h"

#include <fstream>
#include <sstream>

using namespace std;

#ifndef MAX_PATH
#define MAX_PATH   260
#endif

#if defined(WINDOWS)
#define snprintf _snprintf
#ifndef strncasecmp
#define strncasecmp _strnicmp
#endif
#endif

#define MIN_PASSWD_LENGTH 4
#define MAX_TIME_LENGTH 10


extern T_USER_TOKEN_INFO *user_token_info;
static T_EXTEND_TASK_INFO ext_task_info[] =
{
  {"getsysdiskinfo", 0, ext_get_sys_diskinfo, ALL_AUTHORITY},
  {"getprocstat", 0, ext_get_proc_info, ALL_AUTHORITY},
  {"setloglevel", 0, ext_set_log_level, AU_DBC | AU_DBO | AU_MON},
  {"setautostart", 0, ext_set_auto_start, AU_DBC | AU_DBO | AU_JOB},
  {"getautostart", 0, ext_get_auto_start, ALL_AUTHORITY},
  {"getautojobconf", 0, ext_get_autojob_conf, ALL_AUTHORITY},
  {"setautojobconf", 0, ext_set_autojob_conf, AU_DBC | AU_DBO | AU_JOB},
  {"execautostart", 0, ext_exec_auto_start, ALL_AUTHORITY},
  {"getdberrorlog", 0, ext_get_db_err_log, ALL_AUTHORITY},
  {"getbrokerlog", 0, ext_get_broker_start_log, ALL_AUTHORITY},
  {"sendmail", 0, ext_send_mail, ALL_AUTHORITY},
  {"automail", 0, ext_exec_auto_mail, AU_DBC | AU_DBO | AU_MON},
  {"readprivatedata", 0, ext_read_private_data, ALL_AUTHORITY},
  {"writeprivatedata", 0, ext_write_private_data, AU_DBC | AU_DBO | AU_BRK},
  {"setautoexecquery", 0, ext_set_autoexec_query, AU_DBC | AU_DBO | AU_JOB},
  {"gethaapplyinfo", 0, ext_get_ha_apply_info, ALL_AUTHORITY},
  {"adddbmtuser_new", 0, ext_add_dbmt_user_new, AU_DBC},
  {"updatedbmtuser_new", 0, ext_update_dbmt_user_new, AU_DBC | AU_DBO},
  {"getdbmtuserinfo_new", 0, ext_get_dbmt_user_info_new, AU_DBC | AU_DBO},
  {"get_mon_interval", 0, ext_get_mon_interval, AU_MON},
  {"set_mon_interval", 0, ext_set_mon_interval, AU_ADMIN},
  {"get_mon_statistic", 0, ext_get_mon_statistic, AU_MON},
  {NULL, 0, NULL, 0}
};

static bool
ext_get_id_from_token (const char *token, char token_content[][TOKEN_LENGTH+1])
{
  char tmp_token[TOKEN_LENGTH+1];
  char *tmp_token_content[3];

  uDecrypt (TOKEN_LENGTH, token, tmp_token);

  if (string_tokenize2 (tmp_token, tmp_token_content, 3, ':') < 0)
    {
      return false;
    }

  // ip
  strcpy (token_content[0], tmp_token_content[0]);
  // port
  strcpy (token_content[1], tmp_token_content[1]);
  // id
  strcpy (token_content[2], tmp_token_content[2]);

  return true;
}

int
build_server_header (Json::Value &response, const int status,
                     const char *note)
{
  response["status"] =
    (status == ERR_NO_ERROR) ? STATUS_SUCCESS : STATUS_FAILURE;
  response["note"] = string (note);
  return status;
}

int
get_ext_task_info (const char *task, int access_flag,
                   T_EXT_TASK_FUNC *task_func, T_USER_AUTH *auth)
{
  int i;

  for (i = 0; ext_task_info[i].task_str != NULL; i++)
    {
      if (!strcmp (task, ext_task_info[i].task_str))
        {
          if (access_flag < ext_task_info[i].access_level)
            {
              return 0;
            }
          if (task_func)
            {
              *task_func = ext_task_info[i].task_func;
            }

          if (auth)
            {
              *auth = ext_task_info[i].user_auth;
            }

          return 1;
        }
    }

  return 0;
}

string
ull_to_str (const unsigned long long num)
{
  char buf[MAX_PATH];
  snprintf (buf, MAX_PATH, "%llu", num);
  return string (buf);
}

#ifdef WINDOWS
int
ext_get_sys_diskinfo (Json::Value &request, Json::Value &response)
{
  int flag = 0;
  DWORD drives = GetLogicalDrives ();
  ULARGE_INTEGER total_size;
  ULARGE_INTEGER free_size;
  Json::Value drive;
  string drivename;

  while (drives)
    {
      if (drives & 1)
        {
          drivename = 'A' + flag;
          drivename += ":";
          if (GetDriveType (drivename.c_str ()) == DRIVE_FIXED)
            {
              drive.clear ();
              GetDiskFreeSpaceEx (drivename.c_str (), NULL, &total_size,
                                  &free_size);
              drive["name"] = drivename;
              drive["total_size"] = ull_to_str (total_size.QuadPart);
              drive["free_size"] = ull_to_str (free_size.QuadPart);

              response["disk_info"].append (drive);
            }
        }
      drives >>= 1;
      flag++;
    }

  return build_server_header (response, ERR_NO_ERROR, STATUS_NONE);
}
#else
int
ext_get_sys_diskinfo (Json::Value &request, Json::Value &response)
{
  struct statvfs buf;
  int error;
  Json::Value drive;
  error = statvfs ("/", &buf);

  if (error < 0)
    {
      return build_server_header (response, ERR_WITH_MSG,
                                  "get file system info error!");
    }

  drive["name"] = "/";
  drive["total_size"] = ull_to_str (buf.f_bsize * buf.f_blocks);
  drive["free_size"] = ull_to_str (buf.f_bsize * buf.f_bfree);

  response["disk_info"].append (drive);

  return build_server_header (response, ERR_NO_ERROR, STATUS_NONE);
}
#endif

int
ext_get_proc_info (Json::Value &request, Json::Value &response)
{
  T_CMS_PROC_STAT stat;
  int pid;

  pid = request.get ("pid", getpid ()).asInt ();
  ut_get_proc_stat (&stat, pid);

  response["pid"] = stat.pid;
  response["cpu_kernel"] = (unsigned int) stat.cpu_kernel;
  response["cpu_user"] = (unsigned int) stat.cpu_user;
  response["mem_physical"] = (unsigned int) stat.mem_physical;
  response["mem_virtual"] = (unsigned int) stat.mem_virtual;

  return build_server_header (response, ERR_NO_ERROR, STATUS_NONE);
}

int
ext_set_log_level (Json::Value &request, Json::Value &response)
{
  unsigned int loglevel;

  loglevel = request.get ("log_level", CLog::xINFO).asUInt ();

  if (loglevel > CLog::xDEBUG)
    {
      return build_server_header (response, ERR_WITH_MSG, "invalid log level!");
    }
  CLog::GetInstance (loglevel)->setLogLevel (loglevel);
  response["log_level"] = loglevel;
  return build_server_header (response, ERR_NO_ERROR, STATUS_NONE);
}

bool load_json_from_file (string filepath, Json::Value &root)
{
  bool rtn = FALSE;
  Json::Reader reader;
  ifstream ifs (filepath.c_str());
  if (!ifs.bad())
    {
      rtn = reader.parse (ifs, root);
      ifs.close();
    }
  return rtn;
}

bool write_json_to_file (string filepath, Json::Value &root)
{
  Json::StyledWriter writer;
  ofstream ofs (filepath.c_str());
  if (!ofs.bad())
    {
      ofs << writer.write (root) << endl;
      ofs.close();
      return TRUE;
    }

  return FALSE;
}

int ext_cub_broker_start (Json::Value &request, Json::Value &response)
{
  string task =  request["task"].asString();
  nvplist *cli_request, *cli_response;
  char _dbmt_error[DBMT_ERROR_MSG_SIZE];
  int ret = ERR_NO_ERROR;

  memset (_dbmt_error, 0, sizeof (_dbmt_error));

  cli_request = nv_create (5, NULL, "\n", ":", "\n");
  cli_response = nv_create (5, NULL, "\n", ":", "\n");

  nv_add_nvp (cli_request, "task", task.c_str());

  if (request["bname"] != Json::Value::null)
    {
      nv_add_nvp (cli_request, "bname", request["bname"].asString().c_str());
      ret = ts2_start_broker (cli_request, cli_response, _dbmt_error);
    }
  else
    {
      ret = ts2_start_unicas (cli_request, cli_response, _dbmt_error);
    }

  if (ret == ERR_NO_ERROR)
    {
      response["status"] = STATUS_SUCCESS;
      response["note"] = STATUS_NONE;
    }
  else
    {
      response["status"] = STATUS_FAILURE;
      response["note"] = _dbmt_error;
    }
  nv_destroy (cli_request);
  nv_destroy (cli_response);
  return 0;
}

bool ext_get_auto_jobs (const string jobkey, Json::Value &jobvalue)
{
  char conf_path[MAX_PATH];
  Json::Value   root_jobs;

  if (load_json_from_file ( conf_get_dbmt_file (FID_AUTO_JOBS_CONF, conf_path), root_jobs) == FALSE)
    {
      LOG_DEBUG ("load json from %s error.", conf_path);
      return FALSE;
    }
  if (jobkey == "")
    {
      jobvalue = root_jobs;
    }
  else
    {
      jobvalue = root_jobs[jobkey];
    }
  return TRUE;
}

bool ext_set_auto_jobs (const string jobkey, Json::Value &jobvalue)
{
  char conf_path[MAX_PATH];
  Json::Value   root_jobs;

  if (load_json_from_file ( conf_get_dbmt_file (FID_AUTO_JOBS_CONF, conf_path), root_jobs) == FALSE)
    {
      LOG_WARN ("%s is not exist!", conf_path);
    }
  root_jobs[jobkey] = jobvalue;
  return write_json_to_file (conf_path, root_jobs);
}


int
ext_get_auto_start (Json::Value &request, Json::Value &response)
{
  Json::Value   root_jobs;

  if (ext_get_auto_jobs (EXT_JOBS_AUTO_START, root_jobs) == FALSE)
    {
      response[EXT_JOBS_AUTO_START] = Json::Value::null;
      return build_server_header (response, ERR_NO_ERROR, STATUS_NONE);
    }
  response[EXT_JOBS_AUTO_START] = root_jobs;

  return build_server_header (response, ERR_NO_ERROR, STATUS_NONE);
}

int
ext_set_auto_start (Json::Value &request, Json::Value &response)
{
  Json::Value   root_jobs;
  JSON_FIND_V (request, EXT_JOBS_AUTO_START,
               build_server_header (response, ERR_PARAM_MISSING, "Parameter(auto_start) missing in the request"));

  JSON_FIND_V (request, "service",
               build_server_header (response, ERR_PARAM_MISSING, "Parameter(service) missing in the request"));

  if (ext_get_auto_jobs (EXT_JOBS_AUTO_START, root_jobs) == FALSE)
    {
      LOG_WARN ("autojob configure file is not exist or error format!");
    }

  root_jobs[request["service"].asString()] = request[EXT_JOBS_AUTO_START];

  if (ext_set_auto_jobs ( EXT_JOBS_AUTO_START, root_jobs) == FALSE)
    {
      LOG_WARN ("set auto_start jobs fail!");
      return build_server_header (response, ERR_WITH_MSG, "set auto_start jobs fail!");
    }

  return build_server_header (response, ERR_NO_ERROR, STATUS_NONE);
}

int
ext_get_autojob_conf (Json::Value &request, Json::Value &response)
{
  Json::Value root_jobs;
  char decrypted[PASSWD_LENGTH + 1];
  string userpasswd;
  string key = request.get ("service", "").asString();

  if (ext_get_auto_jobs (key, root_jobs) == FALSE)
    {
      return build_server_header (response, ERR_WITH_MSG, "failed to get autojob conf");
    }
  if (key == "mail_config")
    {
      userpasswd = root_jobs.get ("password", "").asString();
      uDecrypt (PASSWD_LENGTH, userpasswd.c_str(), decrypted);
      root_jobs["password"] = decrypted;
    }

  response["jobconf"] = root_jobs;

  return build_server_header (response, ERR_NO_ERROR, STATUS_NONE);
}

int
ext_set_autojob_conf (Json::Value &request, Json::Value &response)
{
  Json::Value   root_jobs;
  string keyvalue, password;
  char encrypted[PASSWD_ENC_LENGTH];

  JSON_FIND_V (request, "service",
               build_server_header (response, ERR_PARAM_MISSING, "Parameter(service) missing in the request"));

  keyvalue = request["service"].asString();
  if (keyvalue == "mail_config")
    {
      if (request["jobconf"] != Json::Value::null
          && request["jobconf"].type() == Json::objectValue
          && request["jobconf"]["password"] != Json::Value::null)
        {
          password = request["jobconf"]["password"].asString();
          uEncrypt (PASSWD_LENGTH, password.c_str(), encrypted);
          request["jobconf"]["password"] = encrypted;
        }
      else
        {
          return build_server_header (response, ERR_WITH_MSG, "error mail_config format!");
        }
    }
  if (ext_set_auto_jobs ( keyvalue, request["jobconf"]) == FALSE)
    {
      LOG_WARN ("set %s fail!", keyvalue.c_str());
      return build_server_header (response, ERR_WITH_MSG, "set autojob conf fail!");
    }

  return build_server_header (response, ERR_NO_ERROR, STATUS_NONE);
}

int ext_get_active_dbs (Json::Value &activedbs)
{
  T_SERVER_STATUS_RESULT *cmd_res;
  int i;
  cmd_res = cmd_server_status ();
  if (cmd_res == NULL)
    {
      return 1;
    }
  T_SERVER_STATUS_INFO *info = (T_SERVER_STATUS_INFO *) cmd_res->result;
  for (i = 0; i < cmd_res->num_result; i++)
    {
      activedbs .append (info[i].db_name);
    }
  cmd_servstat_result_free (cmd_res);
  return 0;
}

int ext_get_active_brokers (Json::Value &activebrokers)
{
  T_CM_BROKER_INFO_ALL uc_info;
  T_CM_BROKER_CONF uc_conf;
  T_CM_ERROR error;
  Json::Value  broker;
  int i;

  if (cm_get_broker_conf (&uc_conf, NULL, &error) < 0)
    {
      return 1;
    }
  if (cm_get_broker_info (&uc_info, &error) < 0)
    {
      activebrokers["brokerstatus"] = "OFF";
    }
  else
    {
      for (i = 0; i < uc_info.num_info; i++)
        {
          broker["name"] = uc_info.br_info[i].name;
          broker["state"] = uc_info.br_info[i].status;
          activebrokers["brokers"].append (broker);
        }
      activebrokers["brokerstatus"] = "ON";
      cm_broker_info_free (&uc_info);
    }

  cm_broker_conf_free (&uc_conf);
  return 0;
}


static void
ext_autojobs_log (const char *service, const char *serv_name, const char *errmsg)
{
  time_t tt;
  tm *t;
  FILE *outfile;
  char logfile[MAX_PATH];
  char strbuf[MAX_PATH] = "unknown";

  tt = time (&tt);

  snprintf (logfile, MAX_PATH, "%s/%s/autojobs.log", sco.szCubrid, DBMT_LOG_DIR);

  outfile = fopen (logfile, "a");
  if (outfile == NULL)
    {
      return;
    }
  t = localtime (&tt);
  if (t)
    {
      strftime ( strbuf, MAX_PATH, "%Y%m%d_%H:%M:%S", t);
    }
  fprintf (outfile, "%s %s %s : %s\n",strbuf, service, serv_name, errmsg);
  fclose (outfile);
}


int ext_exec_dbs_auto_start (const Json::Value &autodbs,  Json::Value &response)
{
  unsigned int i, j, found;
  char err_buf[ERR_MSG_SIZE];
  Json::Value activedbs;
  string dbname;

  if (autodbs == Json::Value::null)
    {
      return build_server_header (response, ERR_NO_ERROR, STATUS_NONE);
    }

  if (ext_get_active_dbs (activedbs))
    {
      LOG_ERROR ("get active db list failed!");
      return build_server_header (response, ERR_WITH_MSG, "get active db list failed!");
    }

  for (i = 0; i < autodbs.size(); i++)
    {
      found = 0;
      dbname = autodbs[i].asString();
      for (j = 0; j < activedbs.size(); j++)
        {
          if (activedbs[j].asString() == dbname)
            {
              found = 1;
              break;
            }
        }

      if (found == 0)
        {
          if (cmd_start_server ((char *)dbname.c_str(), err_buf, sizeof (err_buf)) < 0)
            {
              ext_autojobs_log ("databases", dbname.c_str(), err_buf);
              response[EXT_JOBS_AUTO_START]["databases"][dbname] = err_buf;
            }
          else
            {
              ext_autojobs_log ("databases", dbname.c_str(), STATUS_SUCCESS);
              response[EXT_JOBS_AUTO_START]["databases"][dbname] = STATUS_SUCCESS;
            }
        }
    }

  return build_server_header (response, ERR_NO_ERROR, STATUS_NONE);
}

int ext_exec_brokers_auto_start (const Json::Value &autobrokers,  Json::Value &response)
{
  unsigned int i,t;
  Json::Value activebrokers, request;
  string bname;

  if (autobrokers == Json::Value::null || autobrokers.size() == 0)
    {
      return build_server_header (response, ERR_NO_ERROR, STATUS_NONE);
    }

  if (ext_get_active_brokers (activebrokers))
    {
      LOG_ERROR ("get active db list failed!");
      return build_server_header (response, ERR_WITH_MSG, "get active db list failed!");
    }

  if (activebrokers["brokerstatus"].asString() == "OFF")
    {
      request["task"] = "startbroker";
      ext_cub_broker_start (request, response);

      if (response["status"] != "success")
        {
          ext_autojobs_log ("brokers", "unicas", response["note"].asString().c_str());
          response[EXT_JOBS_AUTO_START]["brokers"]["@unicas"] = response["note"].asString();
        }
      else
        {
          ext_autojobs_log ("brokers", "unicas", STATUS_SUCCESS);
          response[EXT_JOBS_AUTO_START]["brokers"]["@unicas"] = STATUS_SUCCESS;
        }
    }

  for (t = 0; t < autobrokers.size(); t++)
    {
      for (i = 0; i < activebrokers["brokers"].size(); i++)
        {
          bname = activebrokers["brokers"][i]["name"].asString();
          if (bname == autobrokers[t].asString() &&
              activebrokers["brokers"][i]["state"].asString() == "OFF")
            {
              request["task"] = "broker_start";
              request["bname"] = bname;
              ext_cub_broker_start (request, response);

              if (response["status"] != "success")
                {
                  ext_autojobs_log ("brokers", bname.c_str(), response["note"].asString().c_str());
                  response[EXT_JOBS_AUTO_START]["brokers"][bname] = response["note"].asString();
                }
              else
                {
                  ext_autojobs_log ("brokers", bname.c_str(), STATUS_SUCCESS);
                  response[EXT_JOBS_AUTO_START]["brokers"][bname] = STATUS_SUCCESS;
                }
            }
        }
    }
  return build_server_header (response, ERR_NO_ERROR, STATUS_NONE);
}

string format_time (string str_time)
{
  string::iterator itor;
  itor = str_time.begin();
  while ( itor != str_time.end())
    {
      if (*itor == ' ' || *itor == '/' || *itor == ':')
        {
          itor = str_time.erase (itor);
        }
      else
        {
          itor++;
        }
    }
  return str_time;
}

string build_report_log (Json::Value &report)
{
  unsigned int i, j;
  int log_type;
  string report_log, url_prefix, db_name, tmp_str;
  string start_time, end_time;
  Json::Value logdata;

  start_time = report.get ("start_time", "").asString();
  end_time = report.get ("end_time", "").asString();
  url_prefix = report.get ("url_prefix", "").asString();
  db_name= report.get ("dbname", "").asString();
  log_type= report.get ("log_type", 0).asInt();

  report_log = "<br>Hi, This is timed log report.";
  report_log += "<br>";
  report_log += "<br>start time : " + start_time;
  report_log += "<br> end time : " + end_time;
  report_log += "<br>";
  switch (log_type)
    {
    case 0:
      logdata = report["db"];
      if (logdata != Json::Value::null)
        {
          if (logdata["result"] != Json::Value::null)
            {
              report_log += "<table><tr><th>Databases Log Message</th></tr>";
              for (i = 0; i < logdata["result"].size(); i++)
                {
                  //report_log += "<td>" + logdata["result"][i]["file"].asString() + "</td>";
                  tmp_str = "<tr><td>";
                  for (j = 0; j < logdata["result"][i]["logs"].size(); j++)
                    {
                      tmp_str += "<br>" + logdata["result"][i]["logs"][j].asString();
                      if (tmp_str.size() > 256)
                        {
                          tmp_str += "<br>more logs in " + logdata["result"][i]["file"].asString();
                          break;
                        }
                    }
                  report_log += tmp_str + "</td></tr>";
                  if (report_log.size() > 1024)
                    {
                      report_log += "<tr><td>......</td></tr>";
                      break;
                    }
                }
              report_log += "</table>";
            }
          else
            {
              report_log += "<br>*** No record ***";
            }
        }
      else
        {
          report_log += "<br>*** No record ***";
        }
      break;
    case 1:
      logdata = report["broker"];
      report_log += "<br>Log type : Broker start/stop log";
      if (logdata != Json::Value::null)
        {
          if (logdata["log"] != Json::Value::null)
            {
              report_log += "<table><tr bgcolor=rgb(227,227,227)><th>Broker Log Description</th></tr>";
              for (i = 0; i < logdata["log"].size(); i++)
                {
                  report_log += "<tr><td>" + logdata["log"][i].asString() + "</td></tr>";
                }
              report_log += "</table>";
            }
          else
            {
              report_log += "<br>*** No record ***";
            }
        }
      else
        {
          report_log += "<br>*** No record ***";
        }
      break;
    default:
      break;
    }
  report_log += "<br>See More Detail Log: <a href=\"" + url_prefix + "\">CUBRID Web Manager</a>";
  return report_log;
}

int update_next_report_time (Json::Value &mailreport)
{
  return 0;
}

int ext_exec_mail_report (Json::Value &mailreport,  Json::Value &response)
{
  unsigned int i, period_type, save_flag = 0;
  Json::Value log_request, log_response, mail_conf;
  time_t cur_time, next_time;
  char format_time[PATH_MAX], next_exec_time[PATH_MAX];
  string next_exec, prev_exec, mailhead, mailbody, userpasswd;
  char decrypted[PASSWD_LENGTH + 1];

  if (mailreport == Json::Value::null || mailreport.size() == 0)
    {
      return build_server_header (response, ERR_NO_ERROR, STATUS_NONE);
    }

  if (ext_get_auto_jobs (EXT_JOBS_MAIL_CONF, mail_conf) == FALSE)
    {
      LOG_ERROR ("get mail config failed!");
      return build_server_header (response, ERR_WITH_MSG, "get mail config failed!");
    }

  if (mail_conf == Json::Value::null || mail_conf["onoff"].asInt() == 0)
    {
      return build_server_header (response, ERR_NO_ERROR, STATUS_NONE);
    }

  userpasswd = mail_conf.get ("password", "").asString();
  uDecrypt (PASSWD_LENGTH, userpasswd.c_str(), decrypted);
  mail_conf["password"] = decrypted;

  cur_time = time (NULL);
  time_to_str (cur_time, "%4d/%02d/%02d %02d:%02d:%02d", format_time, TIME_STR_FMT_DATE_TIME);
  for (i = 0; i < mailreport.size(); i++)
    {
      if (mailreport[i]["receiver"] == Json::Value::null)
        {
          continue;
        }
      if (mailreport[i]["dbname"]  == Json::Value::null)
        {
          continue;
        }
      if (mailreport[i]["url_prefix"]  == Json::Value::null)
        {
          continue;
        }

      next_exec = "";
      prev_exec = "";
      mailbody = "";
      if (mailreport[i]["prev_exec"] != Json::Value::null)
        {
          prev_exec = mailreport[i]["prev_exec"].asString();
        }
      if (mailreport[i]["next_exec"] != Json::Value::null)
        {
          next_exec = mailreport[i]["next_exec"].asString();
        }
      if ( strcmp (format_time, next_exec.c_str()) < 0)
        {
          continue;
        }

      log_request["dbname"] = mailreport[i]["dbname"].asString();
      log_request["start_time"] = prev_exec;
      log_request["end_time"] = format_time;

      mailhead = "Log Report for CUBRID";

      log_response["dbname"] = mailreport[i]["dbname"].asString();
      log_response["url_prefix"] = mailreport[i]["url_prefix"].asString();
      log_response["start_time"] = prev_exec;
      log_response["end_time"] = format_time;
      log_response["log_type"] = mailreport[i].get ("log_type", 0).asInt();

      ext_get_db_err_log (log_request, log_response["db"]);
      ext_get_broker_start_log (log_request, log_response["broker"]);
      mailbody += build_report_log (log_response);

      mail_conf["receiver"] = mailreport[i]["receiver"];
      mail_conf["msg_header"] = mailhead;
      mail_conf["msg_body"] =  mailbody;
      mail_conf["body_type"] =  1;
      ext_send_mail (mail_conf, response);

      period_type = mailreport[i].get ("period_type", 2).asInt();
      switch (period_type)
        {
        case 0: /* daily */
          next_time = cur_time + 24 * 60 * 60;
          break;
        case 1: /* weekly */
          next_time = cur_time + 7 * 24 * 60 * 60;
          break;
        default: /* monthly */
          next_time = cur_time + 30 * 24 * 60 * 60;
          break;
        }
      time_to_str (next_time, "%4d/%02d/%02d %02d:%02d:%02d", next_exec_time, TIME_STR_FMT_DATE_TIME);
      mailreport[i]["next_exec"] = next_exec_time;
      mailreport[i]["prev_exec"] = format_time;
      save_flag = 1;
    }

  if (save_flag)
    {
      ext_set_auto_jobs ("mail_report", mailreport);
    }

  return build_server_header (response, ERR_NO_ERROR, STATUS_NONE);
}

int ext_exec_auto_mail (Json::Value &request,  Json::Value &response)
{
  Json::Value mail_report;
  if (ext_get_auto_jobs (EXT_JOBS_MAIL_REPORT, mail_report) == FALSE)
    {
      LOG_WARN ("get mail report config failed!");
      return build_server_header (response, ERR_WITH_MSG, "get mail report config failed!");
    }
  return ext_exec_mail_report (mail_report, response);
}

int ext_exec_auto_start (Json::Value &request, Json::Value &response)
{
  Json::Value autojobs;
  string dbname;

  if (ext_get_auto_jobs (EXT_JOBS_AUTO_START, autojobs) == FALSE)
    {
      LOG_DEBUG ("get auto start jobs failed.");
      return build_server_header (response, ERR_WITH_MSG, "get auto start jobs failed.");
    }

  if (autojobs == Json::Value::null)
    {
      return build_server_header (response, ERR_NO_ERROR, STATUS_NONE);
    }

  ext_exec_brokers_auto_start (autojobs["brokers"], response);
  ext_exec_dbs_auto_start (autojobs["databases"], response);

  return build_server_header (response, ERR_NO_ERROR, STATUS_NONE);
}

int ext_exec_auto_jobs (Json::Value &request, Json::Value &response)
{
  ext_exec_auto_start (request, response);
  // Fix for TOOLS-3452
  // Delivery this fuctionality next version Aug/3/2013
  //ext_exec_auto_mail(request, response);
  return build_server_header (response, ERR_NO_ERROR, STATUS_NONE);
}


int ext_get_db_err_log (Json::Value &request, Json::Value &response)
{
  string start_d, end_d;
  string dbname;
  char log_dir[PATH_MAX],  find_file[PATH_MAX], format_time[PATH_MAX];
  char buf[1024], logbuf[1024];
#if defined(WINDOWS)
  WIN32_FIND_DATA data;
  HANDLE handle;
  int found;
#else
  DIR *dirp = NULL;
  struct dirent *dp = NULL;
#endif
  struct stat statbuf;
  char *fname;
  int fname_len = 0, logsize = 0;
  Json::Value logitem;
  FILE *fd;
  JSON_FIND_V (request, "dbname",
               build_server_header (response, ERR_PARAM_MISSING, "Parameter(dbname) missing in the request"));

  dbname = request["dbname"].asString();
  if (request["start_time"] != Json::Value::null)
    {
      start_d = request["start_time"].asString();
    }
  if (request["end_time"] != Json::Value::null)
    {
      end_d = request["end_time"].asString();
    }
  response["start_time"] = start_d;
  response["end_time"] = end_d;
  response["dbname"] = dbname;

  if (uRetrieveDBDirectory (dbname.c_str(), log_dir) != ERR_NO_ERROR)
    {
      return build_server_header (response, ERR_DBDIRNAME_NULL, "Can not find the directory!");
    }

  snprintf (find_file, PATH_MAX - 1, "%s/%s", sco.szCubrid, CUBRID_ERROR_LOG_DIR);
#if defined(WINDOWS)
  snprintf (&find_file[strlen (find_file)], PATH_MAX - strlen (find_file) - 1, "/*");
  if ((handle = FindFirstFile (find_file, &data)) == INVALID_HANDLE_VALUE)
#else
  if ((dirp = opendir (find_file)) == NULL)
#endif
    {
      return build_server_header (response, ERR_NO_ERROR, STATUS_NONE);
    }
#if defined(WINDOWS)
  for (found = 1; found; found = FindNextFile (handle, &data))
#else
  while ((dp = readdir (dirp)) != NULL)
#endif
    {
#if defined(WINDOWS)
      fname = data.cFileName;
#else
      fname = dp->d_name;
#endif
        fname_len = (int) strlen (fname);
      /* the "4" is the size of ".err" */
      if (fname_len < 4 || (strcmp (fname + fname_len - 4, ".err") != 0))
        {
          continue;
        }
      if (memcmp (fname, dbname.c_str(), dbname.size()))
        {
          continue;
        }
      snprintf (buf, sizeof (buf) - 1, "%s/%s/%s", sco.szCubrid,    CUBRID_ERROR_LOG_DIR, fname);
      if (stat (buf, &statbuf) == 0)
        {
          time_to_str (statbuf.st_mtime, "%4d/%02d/%02d %02d:%02d:%02d", format_time, TIME_STR_FMT_DATE_TIME);
          if (!start_d.empty() && strcmp (start_d.c_str(), format_time) > 0)
            {
              continue;
            }
          if (!end_d.empty() && strcmp (end_d.c_str(), format_time) < 0)
            {
              continue;
            }
          logitem.clear();
          logitem["file"] = buf;
          fd = fopen (buf, "r");
          if (fd == NULL)
            {
              continue;
            }
          while (fgets (logbuf, sizeof (logbuf), fd) != NULL)
            {
              ut_trim (logbuf);
              logitem["logs"].append (logbuf);
              logsize++;
              if (logsize > 2000)
                {
                  break;
                }
            }
          fclose (fd);
          response["result"].append (logitem);
          if (logsize > 2000)
            {
              response["overflow"] = 1;
              break;
            }
        }
    }
#if defined(WINDOWS)
  FindClose (handle);
#else
  closedir (dirp);
#endif

  return build_server_header (response, ERR_NO_ERROR, STATUS_NONE);
}


int ext_get_broker_start_log (Json::Value &request, Json::Value &response)
{
  char log_file[PATH_MAX];
  char logbuf[1024];
  FILE *fd;
  string start_d, end_d;
  char *tok[2];
  string format_time, strlog;
  int logsize = 0;

  snprintf (log_file, PATH_MAX - 1, "%s/%s/cubrid_broker.log", sco.szCubrid, CUBRID_BROKER_LOG_DIR);
  fd = fopen (log_file, "r");
  if (fd == NULL)
    {
      return build_server_header (response, ERR_WITH_MSG, "Can't find cubrid_broker.log");
    }

  if (request["start_time"] != Json::Value::null)
    {
      start_d = request["start_time"].asString();
    }
  if (request["end_time"] != Json::Value::null)
    {
      end_d = request["end_time"].asString();
    }
  response["start_time"] = start_d;
  response["end_time"] = end_d;
  response["file"] = log_file;

  while (fgets (logbuf, sizeof (logbuf), fd) != NULL)
    {
      ut_trim (logbuf);
      strlog = logbuf;
      if (string_tokenize (logbuf, tok, 2) < 0)
        {
          continue;
        }
      format_time = string (tok[0]) + " " + string (tok[1]);
      if (!start_d.empty() && strcmp (start_d.c_str(), format_time.c_str()) > 0)
        {
          continue;
        }
      if (!end_d.empty() && strcmp (end_d.c_str(), format_time.c_str()) < 0)
        {
          continue;
        }
      response["log"].append (strlog);
      logsize++;
      if (logsize > 2000)
        {
          response["overflow"] = 1;
          break;
        }
    }
  fclose (fd);
  return build_server_header (response, ERR_NO_ERROR, STATUS_NONE);
}

int ext_send_mail (Json::Value &request, Json::Value &response)
{
  string sender, receiver;
  string smtp_server, uname, passwd;
  string msg_body, msg_header;
  jwsmtp::mailer mail;
  int auth_type, body_type;
  Json::Value result;

  JSON_FIND_V (request, "sender",
               build_server_header (response, ERR_PARAM_MISSING, "Parameter(sender) missing in the request"));
  JSON_FIND_V (request, "receiver",
               build_server_header (response, ERR_PARAM_MISSING, "Parameter(receiver) missing in the request"));
  JSON_FIND_V (request, "smtp_server",
               build_server_header (response, ERR_PARAM_MISSING, "Parameter(smtp_server) missing in the request"));
  JSON_FIND_V (request, "username",
               build_server_header (response, ERR_PARAM_MISSING, "Parameter(username) missing in the request"));
  JSON_FIND_V (request, "password",
               build_server_header (response, ERR_PARAM_MISSING, "Parameter(password) missing in the request"));

  sender = request["sender"].asString();
  mail.setsender (sender);

  receiver = request["receiver"].asString();
  mail.addrecipient (receiver);

  smtp_server = request["smtp_server"].asString();
  mail.setserver (smtp_server);

  auth_type = request.get ("authtype", 2).asInt();
  mail.authtype ((enum jwsmtp::mailer::authtype)auth_type);

  uname = request["username"].asString();
  mail.username (uname);

  passwd = request["password"].asString();
  mail.password (passwd);

  msg_header = request.get ("msg_header", "").asString();
  mail.setsubject (msg_header);

  msg_body = request.get ("msg_body", "").asString();
  body_type = request.get ("body_type", 0).asInt();
  if (body_type == 1)
    {
      mail.setmessageHTML (msg_body);
    }
  else
    {
      mail.setmessage (msg_body);
    }

  mail.send();
  result["receiver"] = receiver;
  result["message"] = mail.response();
  response["response"].append (result);
  return build_server_header (response, ERR_NO_ERROR, STATUS_NONE);
}

int ext_write_private_data (Json::Value &request, Json::Value &response)
{
  FILE *outfile;
  unsigned int i;
  string confname;
  Json::Value confdata;
  char conf_path[PATH_MAX];

  JSON_FIND_V (request, "confname",
               build_server_header (response, ERR_PARAM_MISSING, "Parameter(confname) missing in the request"));

  confname= request["confname"].asString();
  snprintf (conf_path, PATH_MAX, "%s/%s/%s", sco.szCubrid, DBMT_LOG_DIR, confname.c_str());

  outfile = fopen (conf_path, "w");
  if (outfile == NULL)
    {
      return build_server_header (response, ERR_FILE_OPEN_FAIL, string ("open " + string (conf_path) + " failed!").c_str());
    }
  confdata = request["confdata"];
  for (i = 0; i < confdata.size(); i++)
    {
      fprintf (outfile, "%s\n", confdata[i].asString().c_str());
    }
  fclose (outfile);

  return build_server_header (response, ERR_NO_ERROR, STATUS_NONE);
}

int ext_read_private_data (Json::Value &request, Json::Value &response)
{
  FILE *infile;
  string confname;
  char conf_path[PATH_MAX], strbuf[1024 * 200];

  JSON_FIND_V (request, "confname",
               build_server_header (response, ERR_PARAM_MISSING, "Parameter(confname) missing in the request"));

  confname= request["confname"].asString();
  snprintf (conf_path, PATH_MAX, "%s/%s/%s", sco.szCubrid, DBMT_LOG_DIR, confname.c_str());

  infile = fopen (conf_path, "r");
  if (infile == NULL)
    {
      return build_server_header (response, ERR_FILE_OPEN_FAIL, string ("open " + confname + " failed!").c_str());
    }
  while (fgets (strbuf, sizeof (strbuf), infile) != NULL)
    {
      uRemoveCRLF (strbuf);
      response["confdata"].append (strbuf);
    }
  fclose (infile);

  return build_server_header (response, ERR_NO_ERROR, STATUS_NONE);
}

static int _find_dba_password (const string &dbname, const string &query_id, char *userpass, char *_dbmt_error)
{
  char autoexecquery_conf_file[PATH_MAX];
  ifstream conf_file;
  char line_buf[LINE_MAX];
  bool is_find = false;

  autoexecquery_conf_file[0] = '\0';
  line_buf[0] = '\0';

  conf_get_dbmt_file (FID_AUTO_EXECQUERY_CONF, autoexecquery_conf_file);
  conf_file.open (autoexecquery_conf_file, ios::in);
  if (!conf_file.good())
    {
      strncpy (_dbmt_error, autoexecquery_conf_file, DBMT_ERROR_MSG_SIZE);
      return ERR_FILE_OPEN_FAIL;
    }

  strncpy (userpass, "", PASSWD_ENC_LENGTH);

  while (conf_file.getline (line_buf, LINE_MAX))
    {
      istringstream stream_buf (line_buf);
      string tmp_dbname;
      string tmp_queryid;
      string tmp_id;
      string tmp_password;

      stream_buf >> tmp_dbname >> tmp_queryid >> tmp_id >> tmp_password;

      if (tmp_dbname == dbname || tmp_queryid == query_id)
        {
          strncpy (userpass, tmp_password.c_str(), PASSWD_ENC_LENGTH);
          is_find = true;
          break;
        }
    }
  conf_file.close();

  if (!is_find)
    {
      strncpy (_dbmt_error, autoexecquery_conf_file, DBMT_ERROR_MSG_SIZE);
      return ERR_FILE_INTEGRITY;
    }

  return ERR_NO_ERROR;
}

int ext_set_autoexec_query (Json::Value &request, Json::Value &response)
{
  char autoexecquery_conf_file[PATH_MAX];
  char tmp_conf_file[PATH_MAX];
  char token_content[3][TOKEN_LENGTH+1];
  char userpass[PASSWD_ENC_LENGTH];
  char line_buf[MAX_JOB_CONFIG_FILE_LINE_LENGTH];
  char _dbmt_error[DBMT_ERROR_MSG_SIZE];
  unsigned int index = 0;  // for json operator [](UInt).
  int ret_val = 0;
  Json::Value planlist;
  Json::Value queryplan;
  string sql_script;
  string conf_item[AUTOEXECQUERY_CONF_ENTRY_NUM];
  fstream conf_file;
  ofstream tmp_file;


  autoexecquery_conf_file[0] = '\0';
  tmp_conf_file[0] = '\0';
  token_content[0][0] = '\0';
  token_content[1][0] = '\0';
  token_content[2][0] = '\0';
  userpass[0] = '\0';
  line_buf[0] = '\0';
  _dbmt_error[0] = '\0';

  conf_get_dbmt_file (FID_AUTO_EXECQUERY_CONF, autoexecquery_conf_file);
  if (access (autoexecquery_conf_file, F_OK) == 0)
    {
      conf_file.open (autoexecquery_conf_file, ios::in);
    }
  else
    {
      conf_file.open (autoexecquery_conf_file, ios::in | ios::out);
    }
  if (!conf_file.good())
    {
      char tmp[DBMT_ERROR_MSG_SIZE];
      snprintf (tmp, DBMT_ERROR_MSG_SIZE-1, "File(%s) open error", autoexecquery_conf_file);
      return build_server_header (response, ERR_FILE_OPEN_FAIL, tmp);
    }

  // open a temp file for new auto query config.
  snprintf (tmp_conf_file, PATH_MAX-1, "%s/DBMT_task_045.%d", sco.dbmt_tmp_dir, static_cast<int> (getpid()));
  tmp_file.open (tmp_conf_file, ios::out);
  if (!tmp_file.good())
    {
      return build_server_header (response, ERR_FILE_OPEN_FAIL, "Temporal file open error.");
    }

  // dbname
  conf_item[0] = request["dbname"].asString();

  // get manager id from token
  if (!ext_get_id_from_token (request["token"].asString().c_str(), token_content))
    {
      return build_server_header (response, ERR_INVALID_TOKEN,
                                  "Request is rejected due to invalid token. Please reconnect.");
    }
  conf_item[4] = token_content[2];

  while (conf_file.getline (line_buf, sizeof (line_buf)))
    {
      istringstream stream_buf (line_buf);
      string ignored_info, db_name, db_uid;

      stream_buf >> db_name >> ignored_info >> ignored_info >> ignored_info >>  db_uid;

      if (db_name != conf_item[0] || db_uid != conf_item[4])
        {
          tmp_file << line_buf << endl;
        }

    }
  conf_file.close();
  tmp_file.close();

  index = 0;

  JSON_FIND_V (request, "dbname",
               build_server_header (response, ERR_PARAM_MISSING, "Parameter(dbname) missing in the request"));
  JSON_FIND_V (request, "token",
               build_server_header (response, ERR_PARAM_MISSING, "Parameter(token) missing in the request"));
  JSON_FIND_V (request, "planlist",
               build_server_header (response, ERR_PARAM_MISSING, "Parameter(planlist) missing in the request"));
  planlist = request["planlist"];

  JSON_FIND_V (planlist[index], "queryplan",
               build_server_header (response, ERR_PARAM_MISSING, "Parameter(planquery) missing in the request"));
  queryplan = planlist[index]["queryplan"];



  for (index = 0; index < queryplan.size(); ++index)
    {

      JSON_FIND_V (queryplan[index], "username",
                   build_server_header (response, ERR_PARAM_MISSING, "Parameter(username) missing in the request"));
      JSON_FIND_V (queryplan[index], "userpass",
                   build_server_header (response, ERR_PARAM_MISSING, "Parameter(userpass) missing in the request"));
      JSON_FIND_V (queryplan[index], "period",
                   build_server_header (response, ERR_PARAM_MISSING, "Parameter(period) missing in the request"));
      JSON_FIND_V (queryplan[index], "detail",
                   build_server_header (response, ERR_PARAM_MISSING, "Parameter(detail) missing in the request"));
      JSON_FIND_V (queryplan[index], "query_string",
                   build_server_header (response, ERR_PARAM_MISSING, "Parameter(query_string) missing in the request"));
      JSON_FIND_V (queryplan[index], "query_id",
                   build_server_header (response, ERR_PARAM_MISSING, "Parameter(query_id) missing in the request"));

      tmp_file.open (tmp_conf_file, ios::out | ios::app);
      if (!tmp_file.good())
        {
          return build_server_header (response, ERR_FILE_OPEN_FAIL, "Temporal file open error.");
        }


      // query_id
      conf_item[1] = queryplan[index]["query_id"].asString();

      // the name of dba
      conf_item[2] = queryplan[index]["username"].asString();

      // get password after encrpition.
      // if password equals to "none" or "<<AUTO_QUERY_EMPTY_PASSWD>>",
      // that means this query plan just use empty password.
      // if password equals to "unknown" or "<<AUTO_QUERY_PASSWD_NO_CHANGES>>",
      // that means this query plan just use previous password.
      // for more details, see tools-3464.
      if (queryplan[index]["userpass"].asString() == "none" ||
          queryplan[index]["userpass"].asString() == "<<AUTO_QUERY_EMPTY_PASSWD>>")
        {
          uEncrypt (PASSWD_LENGTH, "", userpass);
        }
      else if (queryplan[index]["userpass"].asString() == "unknown" ||
               queryplan[index]["userpass"].asString() == "<<AUTO_QUERY_PASSWD_NO_CHANGES>>")
        {
          if ((ret_val = _find_dba_password (conf_item[0], conf_item[1], userpass, _dbmt_error)) != ERR_NO_ERROR)
            {
              return build_server_header (response, ret_val, _dbmt_error);
            }
        }
      else
        {
          uEncrypt (PASSWD_LENGTH, queryplan[index]["userpass"].asString().c_str(), userpass);
        }
      conf_item[3] = userpass;

      // period
      conf_item[5] = queryplan[index]["period"].asString();

      // details of period
      conf_item[6] = queryplan[index]["detail"].asString();

      // get sql script, checking its length
      sql_script = queryplan[index]["query_string"].asString();
      if (sql_script.length() == 0 || sql_script.length() > MAX_AUTOQUERY_SCRIPT_SIZE)
        {
          char tmp[DBMT_ERROR_MSG_SIZE];
          snprintf (tmp, DBMT_ERROR_MSG_SIZE-1, "Query script too long. MAX_AUTOQUERY_SCRIPT_SIZE:%d.",
                    MAX_AUTOQUERY_SCRIPT_SIZE);
          tmp_file.close();

          return build_server_header (response, ERR_WITH_MSG, tmp);
        }
      conf_item[7] = sql_script;

      for (int i = 0; i < 7; ++i)
        {
          tmp_file << conf_item[i] << ' ';
        }
      tmp_file << conf_item[7] << endl;

      tmp_file.close();

    }

  move_file (tmp_conf_file, autoexecquery_conf_file);

  return build_server_header (response, ERR_NO_ERROR, STATUS_NONE);

}

static int _read_apply_info_cmd_output (const string &stdout_file, const string &stderr_file, string (& str_result)[4])
{
  ifstream in_file;
  string line_buf;
  unsigned found;

  in_file.open (stderr_file.c_str(), ios::in);

  if (getline (in_file, line_buf))
    {
      in_file.close();
      return ERR_GENERAL_ERROR;
    }

  in_file.close();

  in_file.open (stdout_file.c_str(), ios::in);

  int i = 0;
  while (getline (in_file, line_buf))
    {
      if (line_buf.find ("Delay in Applying Copied Log") != string::npos)
        {
          i = 2;
          continue;
        }

      if (line_buf.find ("Delayed log page count") != string::npos)
        {
          found = (unsigned int) line_buf.find (":");

          str_result[i++] = line_buf.substr (found+2);
          continue;
        }

      if (line_buf.find ("Estimated Delay") != string::npos)
        {

          unsigned int tmp_pos = (unsigned int) line_buf.find ("second(s)");
          found = (unsigned int) line_buf.find (":");

          str_result[i++] = line_buf.substr (found+2, tmp_pos-found-3);
          if (str_result[i-1] == "-")
            {
              str_result[i-1] = "";
            }
          continue;
        }
    }

  return ERR_NO_ERROR;
}

int ext_get_ha_apply_info (Json::Value &request, Json::Value &response)
{

  string opt_applyinfo = "applyinfo";
  string opt_L = "-L";
  string opt_r = "-r";
  string opt_a = "-a";
  string copy_log_path;
  string remote_host_name;
  string dbname;
  string str_result[4];

  char cmd_name[CUBRID_CMD_NAME_LEN];
  const char *argv[9];
  char stdout_log_file[512];
  char stderr_log_file[512];

  int retval;

  JSON_FIND_V (request, "copylogpath",
               build_server_header (response, ERR_PARAM_MISSING, "Parameter(copylogpath) missing in the request"));
  JSON_FIND_V (request, "remotehostname",
               build_server_header (response, ERR_PARAM_MISSING, "Parameter(remotehostname) missing in the request"));
  JSON_FIND_V (request, "dbname",
               build_server_header (response, ERR_PARAM_MISSING, "Parameter(remotehostname) missing in the request"));

  sprintf (stdout_log_file, "%s/cmhastop.%d.out", sco.dbmt_tmp_dir,  (int)getpid());
  sprintf (stderr_log_file, "%s/cmhastop.%d.err", sco.dbmt_tmp_dir,  (int)getpid());

  copy_log_path = request["copylogpath"].asString();
  remote_host_name = request["remotehostname"].asString();
  dbname = request["dbname"].asString();

  cubrid_cmd_name (cmd_name);

  argv[0] = cmd_name;
  argv[1] = opt_applyinfo.c_str();
  argv[2] = opt_L.c_str();
  argv[3] = copy_log_path.c_str();
  argv[4] = opt_r.c_str();
  argv[5] = remote_host_name.c_str();
  argv[6] = opt_a.c_str();
  argv[7] = dbname.c_str();
  argv[8] = NULL;

  run_child (argv, 1, NULL, stdout_log_file, stderr_log_file, NULL);

  if ((retval=_read_apply_info_cmd_output (stdout_log_file, stderr_log_file, str_result)) != ERR_NO_ERROR)
    {
      return build_server_header (response, retval, "Invalid options or command format!");
    }

  response["copyinglog_count"] = str_result[0];
  response["copyinglog_estimated_time"] = str_result[1];
  response["applyinglog_count"] = str_result[2];
  response["applyinglog_estimated_time"] = str_result[3];

  return build_server_header (response, ERR_NO_ERROR, STATUS_NONE);
}

int ext_add_dbmt_user_new (Json::Value &request, Json::Value &response)
{
  T_DBMT_USER dbmt_user;
  T_DBMT_USER_AUTHINFO *authinfo = NULL;
  T_DBMT_USER_DBINFO *dbinfo = NULL;

  char dbmt_error[DBMT_ERROR_MSG_SIZE];
  char dbmt_password[PASSWD_ENC_LENGTH];
  char str_auth[12]; // the length of number 2^32

  T_USER_AUTH  auth = 0;
  int num_authinfo = 0;
  int num_dbmt_user = 0;
  int num_dbinfo = 0;
  int retval;

  string user_id, password;

  Json::Value authoritylist;
  Json::Value dbauthlist;


  JSON_FIND_V (request, "targetid",
               build_server_header (response, ERR_PARAM_MISSING, "Parameter(targetid) missing in the request"));
  JSON_FIND_V (request, "password",
               build_server_header (response, ERR_PARAM_MISSING, "Parameter(password) missing in the request"));

  user_id = request["targetid"].asString();
  password = request["password"].asString();

  if (0 != IsValidUserName (user_id.c_str()))
    {
      return build_server_header (response, ERR_WITH_MSG,
                                  "Invalid user name! User name should begin with a letter, and can only contain letters, digits or underscore. The length should be between 4 and 32.");
    }

  if (password.length() > PASSWD_LENGTH || password.length() < MIN_PASSWD_LENGTH)
    {
      return build_server_header (response, ERR_WITH_MSG, "Invalid password! The length should be between 4 and 32.");
    }

  if ((retval = dbmt_user_read (&dbmt_user, dbmt_error) != ERR_NO_ERROR))
    {
      return build_server_header (response, retval, dbmt_error);
    }

  uEncrypt (PASSWD_LENGTH, password.c_str(), dbmt_password);

  num_dbmt_user = dbmt_user.num_dbmt_user;
  for (int i = 0; i < dbmt_user.num_dbmt_user; ++i)
    {
      if (strcmp (dbmt_user.user_info[i].user_name, user_id.c_str()) == 0)
        {
          dbmt_user_free (&dbmt_user);
          sprintf (dbmt_error, "CUBRID Manager user(%s) already exist.", user_id.c_str());
          return build_server_header (response, ERR_DBMTUSER_EXIST, dbmt_error);
        }
    }

  // set user authority info
  JSON_FIND_V (request, "authoritylist", build_server_header (response, ERR_PARAM_MISSING,
               "Parameter(authoritylist) missing in the request"));
  authoritylist = request["authoritylist"];
  Json::Value json_value = authoritylist;

  if (json_value["admin"] != Json::Value::null)
    {
      if (json_value["admin"].asString() != "yes")
        {
          dbmt_user_free (&dbmt_user);
          return build_server_header (response, ERR_WITH_MSG, "The value of 'admin' should be 'yes'!");
        }
      auth |= AU_ADMIN;

      authinfo = (T_DBMT_USER_AUTHINFO *) increase_capacity (authinfo, sizeof (T_DBMT_USER_AUTHINFO), num_authinfo,
                 num_authinfo + 2);
      if (authinfo == NULL)
        {
          dbmt_user_free (&dbmt_user);
          return build_server_header (response, ERR_MEM_ALLOC, "Memory Allocation error.");
        }

      dbmt_user_set_authinfo (& (authinfo[1]), "admin", "yes");
      num_authinfo += 2;
    }
  else
    {
      JSON_FIND_V (json_value, "dbc", build_server_header (response, ERR_PARAM_MISSING,
                   "Parameter(dbc or admin) missing in the authoritylist"));
      JSON_FIND_V (json_value, "dbo", build_server_header (response, ERR_PARAM_MISSING,
                   "Parameter(dbo or admin) missing in the authoritylist"));
      JSON_FIND_V (json_value, "brk", build_server_header (response, ERR_PARAM_MISSING,
                   "Parameter(brk or admin) missing in the authoritylist"));
      JSON_FIND_V (json_value, "mon", build_server_header (response, ERR_PARAM_MISSING,
                   "Parameter(mon or admin) missing in the authoritylist"));
      JSON_FIND_V (json_value, "job", build_server_header (response, ERR_PARAM_MISSING,
                   "Parameter(job or admin) missing in the authoritylist"));
      JSON_FIND_V (json_value, "var", build_server_header (response, ERR_PARAM_MISSING,
                   "Parameter(var or admin) missing in the authoritylist"));

      if (json_value["dbc"].asString() == "yes")
        {
          auth |= AU_DBC;
        }
      else if (json_value["dbc"].asString() != "no")
        {
          return build_server_header (response, ERR_WITH_MSG, "invalid value in 'dbc', it can only accept either 'yes' or 'no'.");
        }

      if (json_value["dbo"].asString() == "yes")
        {
          auth |= AU_DBO;
        }
      else if (json_value["dbo"].asString() != "no")
        {
          return build_server_header (response, ERR_WITH_MSG, "invalid value in 'dbo', it can only accept either 'yes' or 'no'.");
        }

      if (json_value["brk"].asString() == "yes")
        {
          auth |= AU_BRK;
        }
      else if (json_value["brk"].asString() != "no")
        {
          return build_server_header (response, ERR_WITH_MSG, "invalid value in 'brk', it can only accept either 'yes' or 'no'.");
        }

      if (json_value["mon"].asString() == "yes")
        {
          auth |= AU_MON;
        }
      else if (json_value["mon"].asString() != "no")
        {
          return build_server_header (response, ERR_WITH_MSG, "invalid value in 'mon', it can only accept either 'yes' or 'no'.");
        }

      if (json_value["job"].asString() == "yes")
        {
          auth |= AU_JOB;
        }
      else if (json_value["job"].asString() != "no")
        {
          return build_server_header (response, ERR_WITH_MSG, "invalid value in 'job', it can only accept either 'yes' or 'no'.");
        }

      if (json_value["var"].asString() == "yes")
        {
          auth |= AU_VAR;
        }
      else if (json_value["var"].asString() != "no")
        {
          return build_server_header (response, ERR_WITH_MSG, "invalid value in 'var', it can only accept either 'yes' or 'no'.");
        }

      // all authorites are set as 'no'
      if (auth == 0)
        {
          return build_server_header (response, ERR_WITH_MSG, "It can't be allowed to set all authorities as \"no\".");
        }

      authinfo = (T_DBMT_USER_AUTHINFO *) increase_capacity (authinfo, sizeof (T_DBMT_USER_AUTHINFO), num_authinfo,
                 num_authinfo + 7);
      if (authinfo == NULL)
        {
          dbmt_user_free (&dbmt_user);
          return build_server_header (response, ERR_MEM_ALLOC, "Memory Allocation error.");
        }
      num_authinfo += 7;

      // maybe only for debug
      dbmt_user_set_authinfo (& (authinfo[1]), "dbc", ((AU_DBC & auth)? "yes" : "no"));
      dbmt_user_set_authinfo (& (authinfo[2]), "dbo", ((AU_DBO & auth)? "yes" : "no"));
      dbmt_user_set_authinfo (& (authinfo[3]), "brk", ((AU_BRK & auth)? "yes" : "no"));
      dbmt_user_set_authinfo (& (authinfo[4]), "mon", ((AU_MON & auth)? "yes" : "no"));
      dbmt_user_set_authinfo (& (authinfo[5]), "job", ((AU_JOB & auth)? "yes" : "no"));
      dbmt_user_set_authinfo (& (authinfo[6]), "var", ((AU_VAR & auth)? "yes" : "no"));
    }

  sprintf (str_auth, "%u", auth);
  dbmt_user_set_authinfo (& (authinfo[0]), "user_auth", str_auth);

  LOG_DEBUG ("set user authority info successfully.");

  // set db authority info
  JSON_FIND_V (request, "dbauth", build_server_header (response, ERR_PARAM_MISSING,
               "Parameter(dbauth) missing in the request"));

  dbauthlist = request["dbauth"];

  for (unsigned int i = 0; i < dbauthlist.size(); ++i)
    {
      string dbname, dbid, dbpassword, broker_address;

      JSON_FIND_V (dbauthlist[i], "dbname", build_server_header (response, ERR_PARAM_MISSING,
                   "Parameter(dbname) missing in the authoritylist"));
      JSON_FIND_V (dbauthlist[i], "dbid", build_server_header (response, ERR_PARAM_MISSING,
                   "Parameter(dbid) missing in the authoritylist"));
      JSON_FIND_V (dbauthlist[i], "dbpassword", build_server_header (response, ERR_PARAM_MISSING,
                   "Parameter(dbpassword) missing in the authoritylist"));
      JSON_FIND_V (dbauthlist[i], "dbbrokeraddress", build_server_header (response, ERR_PARAM_MISSING,
                   "Parameter(dbbrokeraddress) missing in the authoritylist"));

      dbname = dbauthlist[i]["dbname"].asString();
      dbid = dbauthlist[i]["dbid"].asString();
      dbpassword = dbauthlist[i]["dbpassword"].asString();
      broker_address = dbauthlist[i]["dbbrokeraddress"].asString();

      dbinfo = (T_DBMT_USER_DBINFO *) increase_capacity (dbinfo, sizeof (T_DBMT_USER_DBINFO),
               num_dbinfo, num_dbinfo + 1);
      if (dbinfo == NULL)
        {
          FREE_MEM (authinfo);
          dbmt_user_free (&dbmt_user);

          return build_server_header (response, ERR_MEM_ALLOC, "Memory Allocation error.");
        }
      num_dbinfo++;

      dbmt_user_set_dbinfo (& (dbinfo[num_dbinfo-1]), dbname.c_str(), "admin", dbid.c_str(), broker_address.c_str());
    }

  LOG_DEBUG ("set db authority info successfully.");

  // store user authority info & db authority info into dbmt_user
  dbmt_user.user_info = (T_DBMT_USER_INFO *) increase_capacity (dbmt_user.user_info, sizeof (T_DBMT_USER_INFO),
                        num_dbmt_user, num_dbmt_user + 1);


  if (dbmt_user.user_info == NULL)
    {
      FREE_MEM (authinfo);
      FREE_MEM (dbinfo);
      return build_server_header (response, ERR_MEM_ALLOC, "Memory Allocation error.") ;
    }

  num_dbmt_user++;
  dbmt_user_set_userinfo (& (dbmt_user.user_info[num_dbmt_user-1]), user_id.c_str(), dbmt_password, num_authinfo,
                          authinfo, num_dbinfo, dbinfo);
  dbmt_user.num_dbmt_user = num_dbmt_user;


  LOG_DEBUG ("store to dbmt_user successfully.");

  if ((retval = dbmt_user_write_auth (&dbmt_user, dbmt_error)) != ERR_NO_ERROR)
    {
      dbmt_user_free (&dbmt_user);

      return build_server_header (response, retval, dbmt_error);
    }
  if ((retval = dbmt_user_write_pass (&dbmt_user, dbmt_error)) != ERR_NO_ERROR)
    {
      dbmt_user_free (&dbmt_user);

      return build_server_header (response, retval, dbmt_error);
    }

  if ((retval = ext_ut_add_dblist_to_response (response)) != ERR_NO_ERROR)
    {
      dbmt_user_free (&dbmt_user);

      return build_server_header (response, retval, "database.txt open error");
    }

  if ((retval = ext_ut_add_userlist_to_response (response, dbmt_user)) != ERR_NO_ERROR)
    {
      dbmt_user_free (&dbmt_user);

      return build_server_header (response, retval, "add userlist to response error!");
    }

  dbmt_user_free (&dbmt_user);

  return build_server_header (response, ERR_NO_ERROR, STATUS_NONE);
}

int ext_update_dbmt_user_new (Json::Value &request, Json::Value &response)
{

  T_DBMT_USER_AUTHINFO *authinfo = NULL;
  T_DBMT_USER_DBINFO *dbinfo = NULL;
  T_DBMT_USER dbmt_user;

  T_USER_AUTH auth = 0;

  char dbmt_error[DBMT_ERROR_MSG_SIZE];

  string user_id;

  Json::Value json_value;
  Json::Value dbauthlist;

  int num_authinfo = 0;
  int num_dbinfo = 0;
  int pos = 0;
  int retval;


  char str_auth[12]; // the length of number 2^32

  JSON_FIND_V (request, "targetid",
               build_server_header (response, ERR_PARAM_MISSING, "Parameter(targetid) missing in the request."));

  user_id = request["targetid"].asString();

  if ((json_value = request["authoritylist"]) != Json::Value::null)
    {

      if (json_value["admin"] != Json::Value::null)
        {
          if (json_value["admin"].asString() != "yes")
            {
              return build_server_header (response, ERR_WITH_MSG, "The value of 'admin' should be 'yes'!");
            }

          auth |= AU_ADMIN;

          authinfo = (T_DBMT_USER_AUTHINFO *) increase_capacity (authinfo, sizeof (T_DBMT_USER_AUTHINFO), num_authinfo,
                     num_authinfo + 2);
          if (authinfo == NULL)
            {
              return build_server_header (response, ERR_MEM_ALLOC, "Memory Allocation error.");
            }

          dbmt_user_set_authinfo (& (authinfo[1]), "admin", "yes");
          num_authinfo += 2;
        }
      else
        {
          JSON_FIND_V (json_value, "dbc", build_server_header (response, ERR_PARAM_MISSING,
                       "Parameter(dbc or admin) missing in the authoritylist"));
          JSON_FIND_V (json_value, "dbo", build_server_header (response, ERR_PARAM_MISSING,
                       "Parameter(dbo or admin) missing in the authoritylist"));
          JSON_FIND_V (json_value, "brk", build_server_header (response, ERR_PARAM_MISSING,
                       "Parameter(brk or admin) missing in the authoritylist"));
          JSON_FIND_V (json_value, "mon", build_server_header (response, ERR_PARAM_MISSING,
                       "Parameter(mon or admin) missing in the authoritylist"));
          JSON_FIND_V (json_value, "job", build_server_header (response, ERR_PARAM_MISSING,
                       "Parameter(job or admin) missing in the authoritylist"));
          JSON_FIND_V (json_value, "var", build_server_header (response, ERR_PARAM_MISSING,
                       "Parameter(var or admin) missing in the authoritylist"));


          if (json_value["dbc"].asString() == "yes")
            {
              auth |= AU_DBC;
            }
          else if (json_value["dbc"].asString() != "no")
            {
              return build_server_header (response, ERR_WITH_MSG, "invalid value in 'dbc', it can only accept either 'yes' or 'no'.");
            }

          if (json_value["dbo"].asString() == "yes")
            {
              auth |= AU_DBO;
            }
          else if (json_value["dbo"].asString() != "no")
            {
              return build_server_header (response, ERR_WITH_MSG, "invalid value in 'dbo', it can only accept either 'yes' or 'no'.");
            }

          if (json_value["brk"].asString() == "yes")
            {
              auth |= AU_BRK;
            }
          else if (json_value["brk"].asString() != "no")
            {
              return build_server_header (response, ERR_WITH_MSG, "invalid value in 'brk', it can only accept either 'yes' or 'no'.");
            }

          if (json_value["mon"].asString() == "yes")
            {
              auth |= AU_MON;
            }
          else if (json_value["mon"].asString() != "no")
            {
              return build_server_header (response, ERR_WITH_MSG, "invalid value in 'mon', it can only accept either 'yes' or 'no'.");
            }

          if (json_value["job"].asString() == "yes")
            {
              auth |= AU_JOB;
            }
          else if (json_value["job"].asString() != "no")
            {
              return build_server_header (response, ERR_WITH_MSG, "invalid value in 'job', it can only accept either 'yes' or 'no'.");
            }

          if (json_value["var"].asString() == "yes")
            {
              auth |= AU_VAR;
            }
          else if (json_value["var"].asString() != "no")
            {
              return build_server_header (response, ERR_WITH_MSG, "invalid value in 'var', it can only accept either 'yes' or 'no'.");
            }

          // all authorites are set as 'no'
          if (auth == 0)
            {
              return build_server_header (response, ERR_WITH_MSG, "It can't be allowed to set all authorities as \"no\".");
            }

          authinfo = (T_DBMT_USER_AUTHINFO *) increase_capacity (authinfo, sizeof (T_DBMT_USER_AUTHINFO), num_authinfo,
                     num_authinfo + 7);
          if (authinfo == NULL)
            {
              return build_server_header (response, ERR_MEM_ALLOC, "Memory Allocation error.");
            }
          num_authinfo += 7;

          // maybe only for debug
          dbmt_user_set_authinfo (& (authinfo[1]), "dbc", ((AU_DBC & auth)? "yes" : "no"));
          dbmt_user_set_authinfo (& (authinfo[2]), "dbo", ((AU_DBO & auth)? "yes" : "no"));
          dbmt_user_set_authinfo (& (authinfo[3]), "brk", ((AU_BRK & auth)? "yes" : "no"));
          dbmt_user_set_authinfo (& (authinfo[4]), "mon", ((AU_MON & auth)? "yes" : "no"));
          dbmt_user_set_authinfo (& (authinfo[5]), "job", ((AU_JOB & auth)? "yes" : "no"));
          dbmt_user_set_authinfo (& (authinfo[6]), "var", ((AU_VAR & auth)? "yes" : "no"));

        }

      sprintf (str_auth, "%u", auth);
      dbmt_user_set_authinfo (& (authinfo[0]), "user_auth", str_auth);

    }

  // set db authority info
  //JSON_FIND_V(request, "dbauth", build_server_header(response, ERR_PARAM_MISSING, "Parameter(dbauth) missing in the request"));

  if ((dbauthlist = request["dbauth"]) != Json::Value::null)
    {

      for (unsigned int i = 0; i < dbauthlist.size(); ++i)
        {

          string dbname, dbid, dbpassword, broker_address;

          JSON_FIND_V (dbauthlist[i], "dbname", build_server_header (response, ERR_PARAM_MISSING,
                       "Parameter(dbname) missing in the authoritylist"));
          JSON_FIND_V (dbauthlist[i], "dbid", build_server_header (response, ERR_PARAM_MISSING,
                       "Parameter(dbid) missing in the authoritylist"));
          JSON_FIND_V (dbauthlist[i], "dbpassword", build_server_header (response, ERR_PARAM_MISSING,
                       "Parameter(dbpassword) missing in the authoritylist"));
          JSON_FIND_V (dbauthlist[i], "dbbrokeraddress", build_server_header (response, ERR_PARAM_MISSING,
                       "Parameter(dbbrokeraddress) missing in the authoritylist"));

          dbname = dbauthlist[i]["dbname"].asString();
          dbid = dbauthlist[i]["dbid"].asString();
          dbpassword = dbauthlist[i]["dbpassword"].asString();
          broker_address = dbauthlist[i]["dbbrokeraddress"].asString();

          dbinfo = (T_DBMT_USER_DBINFO *) increase_capacity (dbinfo, sizeof (T_DBMT_USER_DBINFO),
                   num_dbinfo, num_dbinfo + 1);
          if (dbinfo == NULL)
            {
              FREE_MEM (authinfo);

              return build_server_header (response, ERR_MEM_ALLOC, "Memory Allocation error.");
            }
          num_dbinfo++;

          dbmt_user_set_dbinfo (& (dbinfo[num_dbinfo-1]), dbname.c_str(), "admin", dbid.c_str(), broker_address.c_str());

        }
    }

  if ((retval = dbmt_user_read (&dbmt_user, dbmt_error)) != ERR_NO_ERROR)
    {
      FREE_MEM (authinfo);
      FREE_MEM (dbinfo);
      return build_server_header (response, retval, dbmt_error);
    }

  pos = -1;
  for (int i = 0;  i < dbmt_user.num_dbmt_user; ++i)
    {
      if (!strcmp (dbmt_user.user_info[i].user_name, user_id.c_str()))
        {
          pos = i;
          break;
        }
    }

  if (pos < 0)
    {
      FREE_MEM (authinfo);
      FREE_MEM (dbinfo);
      dbmt_user_free (&dbmt_user);

      return build_server_header (response, ERR_GENERAL_ERROR, "the user doesn't exist!");
    }

  if (authinfo != NULL)
    {
      free (dbmt_user.user_info[pos].authinfo);
      dbmt_user.user_info[pos].authinfo = authinfo;
      dbmt_user.user_info[pos].num_authinfo = num_authinfo;

    }

  if (dbinfo != NULL)
    {
      if (dbmt_user.user_info[pos].dbinfo == NULL)
        {
          dbmt_user.user_info[pos].dbinfo = dbinfo;
          dbmt_user.user_info[pos].num_dbinfo = num_dbinfo;
        }
      else
        {
          T_DBMT_USER_INFO *current_user = dbmt_user.user_info+pos;
          for (int i = 0; i < num_dbinfo; ++i )
            {
              int tmp_pos = -1;
              for (int j = 0; j < current_user->num_dbinfo; ++j)
                {
                  if (!strcmp (current_user->dbinfo[j].dbname, dbinfo[i].dbname))
                    {
                      tmp_pos = j;
                    }
                }

              if (tmp_pos < 0)
                {
                  current_user->dbinfo = (T_DBMT_USER_DBINFO *)increase_capacity (current_user->dbinfo,
                                         sizeof (T_DBMT_USER_DBINFO),
                                         current_user->num_dbinfo,
                                         current_user->num_dbinfo+1);

                  if (current_user->dbinfo == NULL)
                    {
                      FREE_MEM (dbinfo);
                      dbmt_user_free (&dbmt_user);

                      return build_server_header (response, ERR_MEM_ALLOC, "Memory allocation error.");
                    }
                  tmp_pos = current_user->num_dbinfo;
                  current_user->num_dbinfo++;
                }

              dbmt_user_set_dbinfo (& (current_user->dbinfo[tmp_pos]),
                                    dbinfo[i].dbname,
                                    dbinfo[i].auth,
                                    dbinfo[i].uid,
                                    dbinfo[i].broker_address);
            }
        }
    }

  if ((retval = dbmt_user_write_auth (&dbmt_user, dbmt_error)) != ERR_NO_ERROR)
    {
      FREE_MEM (dbinfo);
      dbmt_user_free (&dbmt_user);

      return build_server_header (response, retval, dbmt_error);
    }


  if ((retval = ext_ut_add_dblist_to_response (response)) != ERR_NO_ERROR)
    {
      FREE_MEM (dbinfo);
      dbmt_user_free (&dbmt_user);

      return build_server_header (response, retval, "database.txt open error");
    }

  if ((retval = ext_ut_add_userlist_to_response (response, dbmt_user)) != ERR_NO_ERROR)
    {
      FREE_MEM (dbinfo);
      dbmt_user_free (&dbmt_user);

      return build_server_header (response, retval, "add userlist to response error!");
    }


  FREE_MEM (dbinfo);
  dbmt_user_free (&dbmt_user);

  return build_server_header (response, ERR_NO_ERROR, STATUS_NONE);
}

int ext_get_dbmt_user_info_new (Json::Value &request, Json::Value &response)
{

  T_DBMT_USER dbmt_user;
  char dbmt_error[DBMT_ERROR_MSG_SIZE];
  int retval;

  if ((retval = dbmt_user_read (&dbmt_user, dbmt_error)) != ERR_NO_ERROR)
    {
      dbmt_user_free (&dbmt_user);
      return build_server_header (response, retval, dbmt_error);
    }


  if ((retval = ext_ut_add_dblist_to_response (response)) != ERR_NO_ERROR)
    {
      dbmt_user_free (&dbmt_user);
      return build_server_header (response, retval, "database.txt open error");
    }

  if ((retval = ext_ut_add_userlist_to_response (response, dbmt_user)) != ERR_NO_ERROR)
    {
      dbmt_user_free (&dbmt_user);
      return build_server_header (response, retval, "add userlist to response error!");
    }

  dbmt_user_free (&dbmt_user);
  return build_server_header (response, ERR_NO_ERROR, STATUS_NONE);
}

// utility fucntions.
//
// -ext_ut_validate_userid
// -ext_ut_add_dblist_to_response
// -ext_ut_add_userlist_to_response
// -ext_ut_validate_token
// -ext_ut_generate_token

int ext_ut_add_dblist_to_response (Json::Value &response, bool is_add_dbpath)
{

  char dbtxt_file[PATH_MAX];
  char hostname[128];
  ifstream in_file;
  string line_buf;
  Json::Value dblist;
  Json::Value dbs;

  snprintf (dbtxt_file, PATH_MAX-1, "%s/%s", sco.szCubrid_databases, CUBRID_DATABASE_TXT);
  if (access (dbtxt_file, F_OK) == 0)
    {
      in_file.open (dbtxt_file, ios::in);
    }
  else
    {
      return ERR_DATABASETXT_OPEN;
    }
  if (!in_file.good())
    {
      return ERR_DATABASETXT_OPEN;
    }

  memset (hostname, 0, sizeof (hostname));
  gethostname (hostname, sizeof (hostname));

  string str_hostname = hostname;

  while (getline (in_file, line_buf))
    {
      istringstream in_str (line_buf);
      istringstream in_hname;
      string dbname, dbpath, hname_list, hname[2];
      Json::Value db;

      in_str >> dbname >> dbpath >> hname_list;
      in_hname.str (hname_list);

      int i = 0;
      while (getline (in_hname, hname[i], ':'))
        {
          if (hname[i] == "127.0.0.1" || hname[i] == str_hostname || hname[i] == "localhost")
            {
              db["dbname"] = dbname;
              if (is_add_dbpath)
                {
                  db["dbdir"] = dbpath;
                }
              dbs.append (db);
              break;
            }
          i++;
        }
    }

  dblist["dbs"] = dbs;
  response["dblist"].append (dblist);

  return ERR_NO_ERROR;
}

int ext_ut_add_userlist_to_response (Json::Value &response, const T_DBMT_USER &dbmt_user, bool is_add_pwd)
{
  Json::Value userlist;

  for (int i = 0; i < dbmt_user.num_dbmt_user; ++i)
    {
      Json::Value user;
      Json::Value authority_list;
      Json::Value dbauth;
      Json::Value json_value;
      string user_auth;
      ostringstream tmp_oss;

      if (dbmt_user.user_info[i].user_name[0] == '\0')
        {
          continue;
        }

      user[ENCRYPT_ARG ("id")] = dbmt_user.user_info[i].user_name;
      if (is_add_pwd)
        {
          user["passwd"] = dbmt_user.user_info[i].user_passwd;
        }

      json_value.clear();

      // add user authority info
      for (int j = 0; j < dbmt_user.user_info[i].num_authinfo; ++j)
        {
          if (dbmt_user.user_info[i].authinfo[j].domain[0] == '\0')
            {
              continue;
            }

          if (!strcmp (dbmt_user.user_info[i].authinfo[j].domain, "dbo"))
            {
              json_value["dbo"] = dbmt_user.user_info[i].authinfo[j].auth;
              continue;
            }

          if (!strcmp (dbmt_user.user_info[i].authinfo[j].domain, "dbc"))
            {
              json_value["dbc"] = dbmt_user.user_info[i].authinfo[j].auth;
              continue;
            }

          if (!strcmp (dbmt_user.user_info[i].authinfo[j].domain, "brk"))
            {
              json_value["brk"] = dbmt_user.user_info[i].authinfo[j].auth;
              continue;
            }

          if (!strcmp (dbmt_user.user_info[i].authinfo[j].domain, "mon"))
            {
              json_value["mon"] = dbmt_user.user_info[i].authinfo[j].auth;
              continue;
            }

          if (!strcmp (dbmt_user.user_info[i].authinfo[j].domain, "job"))
            {
              json_value["job"] = dbmt_user.user_info[i].authinfo[j].auth;
              continue;
            }

          if (!strcmp (dbmt_user.user_info[i].authinfo[j].domain, "var"))
            {
              json_value["var"] = dbmt_user.user_info[i].authinfo[j].auth;
              continue;
            }

          if (!strcmp (dbmt_user.user_info[i].authinfo[j].domain, "all"))
            {
              json_value["all"] = dbmt_user.user_info[i].authinfo[j].auth;
              continue;
            }

          if (!strcmp (dbmt_user.user_info[i].authinfo[j].domain, "user_auth"))
            {
              user_auth = dbmt_user.user_info[i].authinfo[j].auth;
              continue;
            }
        }

      authority_list.append (json_value);

      tmp_oss << AU_ADMIN;
      if (!strcasecmp (dbmt_user.user_info[i].user_name, "admin") ||
          user_auth == tmp_oss.str())
        {
          user["user_auth"] = "admin";
        }
      else
        {
          user["user_auth"] = user_auth;
        }
      user["authority_list"] = authority_list;

      json_value.clear();
      // add user db info
      for (int j = 0; j < dbmt_user.user_info[i].num_dbinfo; ++j)
        {
          json_value[ENCRYPT_ARG ("dbid")] = dbmt_user.user_info[i].dbinfo[j].uid;
          json_value["dbname"] = dbmt_user.user_info[i].dbinfo[j].dbname;
          json_value["dbbrokeraddress"] = dbmt_user.user_info[i].dbinfo[j].broker_address;

          dbauth["auth_info"].append (json_value);
        }

      user["dbauth"].append (dbauth);
      userlist["user"].append (user);
    }
  response["userlist"].append (userlist);

  return ERR_NO_ERROR;
}

static bool _validate_token_active_time (time_t &active_time)
{
    size_t len = 0;

  active_time = 0;
  len = strlen (sco.szTokenActiveTime);

  if (len > MAX_TIME_LENGTH)
    {
      return false;
    }

  for (int i = 0; i < len; ++i)
    {
      if (!isdigit (sco.szTokenActiveTime[i]))
        {
          return false;
        }
    }

  active_time = atol (sco.szTokenActiveTime);

  if (active_time == 0)
    {
      return false;
    }

  if (active_time == LONG_MAX)
    {
      LOG_WARN ("token_active_time in cm.conf maybe more than 2147483647, correct it to 2147483647.");
    }

  return true;
}

bool ext_ut_validate_token (const char *token)
{
  T_USER_TOKEN_INFO *token_info;
  string token_enc;
  string token_content[5]; // client_ip, client_port, client_id, proc_id, login_time
  istringstream tmp_iss;
  time_t now_time = time (0);
  time_t active_time;
  char token_dec[TOKEN_LENGTH + 1];

  if (strlen (token) > TOKEN_ENC_LENGTH)
    {
      return false;
    }

  uDecrypt (TOKEN_LENGTH, token, token_dec);
  tmp_iss.str (string (token_dec));

  int i = 0;
  while (getline (tmp_iss, token_content[i++], ':'));

  token_info = dbmt_user_search_token_info (token_content[2].c_str());
  if (token_info == NULL)
    {
      return false;
    }

  if (strcmp (token_info->token, token) != 0)
    {
      return false;
    }

  if (!_validate_token_active_time (active_time))
    {
      active_time = 7200;
    }

  if (now_time - token_info->login_time > active_time)
    {
      return false;
    }

  token_info->login_time = now_time;

  return true;
}

int ext_ut_validate_token (Json::Value &request, Json::Value &response)
{

  T_USER_TOKEN_INFO *token_info;
  string task;
  string token;
  string token_content[5]; // client_ip, client_port, client_id, proc_id, login_time
  istringstream tmp_iss;
  time_t now_time = time (0);
  time_t active_time;
  char token_dec[TOKEN_LENGTH+1];

  if (request["task"].asString() == "login" || request["task"].asString() == "getcmsenv")
    {
      return build_server_header (response, ERR_NO_ERROR, "none");
    }


  if (request["task"] == Json::Value::null)
    {
      return build_server_header (response, ERR_PARAM_MISSING, "Parameter(task) missing in the request.");
    }

  if (request["token"] == Json::Value::null)
    {
      return build_server_header (response, ERR_PARAM_MISSING, "Parameter(token) missing in the request.");
    }

  if (request["task"].asString() == "")
    {
      return build_server_header (response, ERR_WITH_MSG, "Task can't be null.");
    }

  if (request["token"].asString() == "")
    {
      return build_server_header (response, ERR_INVALID_TOKEN, "Request is rejected due to invalid token. Please reconnect.");
    }

  task = request["task"].asString();
  token = request["token"].asString();
  if (token.length() > TOKEN_ENC_LENGTH)
    {
      return build_server_header (response, ERR_INVALID_TOKEN, "Request is rejected due to invalid token. Please reconnect.");
    }

  uDecrypt (TOKEN_LENGTH, token.c_str(), token_dec);
  tmp_iss.str (string (token_dec));

  int i = 0;
  while (getline (tmp_iss, token_content[i++], ':'));

  token_info = dbmt_user_search_token_info (token_content[2].c_str());
  if (token_info == NULL)
    {
      return build_server_header (response, ERR_INVALID_TOKEN, "Request is rejected due to invalid token. Please reconnect.");
    }


  if (strcmp (token_info->token, token.c_str()))
    {
      return build_server_header (response, ERR_INVALID_TOKEN, "Request is rejected due to invalid token. Please reconnect.");
    }


  if (!_validate_token_active_time (active_time))
    {
      active_time = 7200;
    }

  if (now_time-token_info->login_time > active_time)
    {
      return build_server_header (response, ERR_INVALID_TOKEN, "Request is rejected due to invalid token. Please reconnect.");
    }

  token_info->login_time = now_time;

  request["_IP"] = token_content[0];
  request["_PORT"] = token_content[1];
  request["_ID"] = token_content[2];

  return build_server_header (response, ERR_NO_ERROR, "none");
}

bool ext_ut_validate_auth (Json::Value &request)
{
  T_USER_AUTH auth_task = 0;
  T_USER_AUTH auth_user = 0;
  T_DBMT_USER dbmt_user;
  T_DBMT_USER_AUTHINFO *auth_info = NULL;

  string task;
  string user_id;

  char dbmt_error[DBMT_ERROR_MSG_SIZE];
  int num_authinfo = 0;

  if (request["task"].asString() == "login" || request["task"].asString() == "getcmsenv")
    {
      return true;
    }

  if (request["task"] == Json::Value::null || request["_ID"] == Json::Value::null)
    {
      return false;
    }

  task = request["task"].asString();
  user_id = request["_ID"].asString();

  if (ut_get_task_info (task.c_str(), NULL, NULL, &auth_task) == 0 &&
      get_ext_task_info (task.c_str(), 0, NULL, &auth_task) == 0)
    {
      // As the task doesn't exist, this failure will be checked in next step.
      return true;
    }

  if (dbmt_user_read (&dbmt_user, dbmt_error) != ERR_NO_ERROR)
    {
      return false;
    }

  bool matches = false;
  for (int index = 0; index < dbmt_user.num_dbmt_user; ++index)
    {
      if (strcmp (dbmt_user.user_info[index].user_name, user_id.c_str()) == 0)
        {
          auth_info = dbmt_user.user_info[index].authinfo;
          num_authinfo = dbmt_user.user_info[index].num_authinfo;
          matches = true;
          break;
        }
    }

  // the user doesn't exist
  if (!matches)
    {
      return false;
    }

  for (int index = 0; index < num_authinfo; ++index)
    {
      if (!strcmp (auth_info[index].domain, "user_auth"))
        {
          istringstream (string (auth_info[index].auth)) >> auth_user;
          break;
        }
    }

  // assign default authority to old users.
  if (auth_user == 0)
    {
      if (user_id == "admin")
        {
          auth_user = AU_ADMIN;
        }
      else
        {
          auth_user = ALL_AUTHORITY;
        }
    }

  if (auth_user == AU_ADMIN)
    {
      return true;
    }

  return (auth_user & auth_task) ? true : false;
}

int ext_get_mon_interval (Json::Value &request, Json::Value &response)
{
  response["task"] = request["task"];
  time_t interval;
  if (false == (cm_mon_stat::get_instance())->get_mon_interval (interval))
    {
      return build_server_header (response, ERR_WITH_MSG,
                                  "Get interval failed, because the monitoring module is not initialized!");
    }
  response["interval"] = int (interval);
  return build_server_header (response, ERR_NO_ERROR, STATUS_NONE);
}

int ext_set_mon_interval (Json::Value &request, Json::Value &response)
{
  int interval = 0;
  response["task"] = request["task"];
  JSON_FIND_V (request, "interval",
               build_server_header (response, ERR_PARAM_MISSING, "Parameter(interval) missing in the request"));
  interval = request["interval"].asInt();
  if (interval < MIN_INTERVAL)
    {
      stringstream sstr;
      sstr << "The interval " << interval << " seconds is less than the minimum interval " << MIN_INTERVAL << " seconds";
      return build_server_header (response, ERR_WITH_MSG, sstr.str().c_str());
    }
  if (interval >= MAX_INTERVAL)
    {
      stringstream sstr;
      sstr << "The interval " << interval << " seconds is bigger than or equal to the maximum interval " << MAX_INTERVAL <<
           " seconds";
      return build_server_header (response, ERR_WITH_MSG, sstr.str().c_str());
    }
  if (true == (cm_mon_stat::get_instance())->set_mon_interval (interval))
    {
      return build_server_header (response, ERR_NO_ERROR, STATUS_NONE);
    }
  else
    {
      return build_server_header (response, ERR_WITH_MSG,
                                  "Set monitoring interval for monitoring statistic failed!");
    }
}

int ext_get_mon_statistic (Json::Value &request, Json::Value &response)
{
  response["task"] = request["task"];
  string errmsg = "";
  JSON_FIND_V (request, "metric",
               build_server_header (response, ERR_PARAM_MISSING, "Parameter(metric) missing in the request"));
  JSON_FIND_V (request, "dtype",
               build_server_header (response, ERR_PARAM_MISSING, "Parameter(dtype) missing in the request"));
  if (0 == strncmp ("db_", request["metric"].asString().c_str(), strlen ("db_")))
    {
      JSON_FIND_V (request, "dbname",
                   build_server_header (response, ERR_PARAM_MISSING, "Parameter(dbname) missing in the request"));
    }
  if (0 == strncmp ("vol_", request["metric"].asString().c_str(), strlen ("vol_")))
    {
      JSON_FIND_V (request, "dbname",
                   build_server_header (response, ERR_PARAM_MISSING, "Parameter(dbname) missing in the request"));
      JSON_FIND_V (request, "volname",
                   build_server_header (response, ERR_PARAM_MISSING, "Parameter(volname) missing in the request"));
    }
  if (0 == strncmp ("broker_", request["metric"].asString().c_str(), strlen ("broker_")))
    {
      JSON_FIND_V (request, "bname",
                   build_server_header (response, ERR_PARAM_MISSING, "Parameter(bname) missing in the request"));
    }
  if (true == (cm_mon_stat::get_instance())->get_mon_statistic (request, response, errmsg))
    {
      return build_server_header (response, ERR_NO_ERROR, STATUS_NONE);
    }
  else
    {
      return build_server_header (response, ERR_WITH_MSG, errmsg.c_str());
    }
}
