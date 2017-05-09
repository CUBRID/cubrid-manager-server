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

#include <string.h>

#include "cm_log.h"
#include "json/json.h"
#include "cm_config.h"
#include "cm_job_task.h"
#include "cm_server_interface.h"
#include "cm_mon_stat.h"
#include "cm_server_extend_interface.h"

#include <iostream>
#include <fstream>
#include <sstream>

using namespace std;

#define DEFAULT_MON_STAT_INTERVAL   60

#define MON_DATA_BLOCK      ((24 * 60 * 60) / _meta[K_INTERVAL].asInt() + 30 * 24 + 365)
/* MB_SIZE = 1024 * 1024 */
#define MB_SIZE             (1048576)

// Initial metric value
#define INIT_METRIC_VALUE         -1

/* monitoring data file names */
#define META_NAME           "meta.json"
#define BROKER_MON          "broker_mon"
#define DB_MON              "db_mon"
#define VOL_MON             "vol_mon"
#define HA_MON              "ha_mon"
#define OS_MON              "os_mon"
/* end of monitoring data file names */

typedef struct
{
  const char *metric;
  int pfactor;
  bool ddiff;
} T_METRIC;

/* broker metrics */
/* two unused metrics*/
#define BROKER_METRICS_LEN      10

#define BROKER_TPS          "broker_tps"
#define BROKER_QPS          "broker_qps"
#define BROKER_LONG_T       "broker_long_t"
#define BROKER_LONG_Q       "broker_long_q"
#define BROKER_REQ          "broker_req"
#define BROKER_ERR_Q        "broker_err_q"
#define BROKER_JQ           "broker_jq"

const T_METRIC BROKER_METRICS[BROKER_METRICS_LEN] =
{
  {BROKER_TPS, 1, true},
  {BROKER_QPS, 1, true},
  {BROKER_LONG_T, 1, true},
  {BROKER_LONG_Q, 1, true},
  {BROKER_REQ, 1, true},
  {BROKER_ERR_Q, 1, true},
  {BROKER_JQ, 1, false},
  {"none1", 1, false},
  {"none2", 1, false},
  {"uptime", 1, false}       // uptime must be the last one
};

/* DB metrics */
/* two unused metrics */
#define DB_METRICS_LEN                  19

#define DB_CPU_KERNEL                   "db_cpu_kernel"
#define DB_CPU_USER                     "db_cpu_user"
#define DB_MEM_PHY                      "db_mem_phy"
#define DB_MEM_VIR                      "db_mem_vir"
#define DB_QPS                          "db_qps"
#define DB_TPS                          "db_tps"
#define DB_HIT_RATIO                    "db_hit_ratio"
#define DB_FETCH_PAGES                  "db_fetch_pages"
#define DB_DIRTY_PAGES                  "db_dirty_pages"
#define DB_IO_READ                      "db_io_read"
#define DB_IO_WRITE                     "db_io_write"
/* HA metrics for DB */
#define DB_HA_COPY_DELAY_PAGE           "db_ha_copy_delay_page"
#define DB_HA_COPY_DELAY_ESTIMATED      "db_ha_copy_delay_estimated"
#define DB_HA_APPLY_DELAY_PAGE          "db_ha_apply_delay_page"
#define DB_HA_APPLY_DELAY_ESTIMATED     "db_ha_apply_delay_estimated"

#define DB_FREESPACE                    "db_freespace"

const T_METRIC DB_METRICS[DB_METRICS_LEN] =
{
  {DB_CPU_KERNEL, 1, true},
  {DB_CPU_USER, 1, true},
  {DB_MEM_PHY, 100, false},
  {DB_MEM_VIR, 100, false},
  {DB_QPS, 1, true},
  {DB_TPS, 1, true},
  {DB_HIT_RATIO, 1, false},
  {DB_FETCH_PAGES, 1, true},
  {DB_DIRTY_PAGES, 1, true},
  {DB_IO_READ, 1, true},
  {DB_IO_WRITE, 1, true},
  {DB_HA_COPY_DELAY_PAGE, 1, true},
  {DB_HA_COPY_DELAY_ESTIMATED, 1, false},
  {DB_HA_APPLY_DELAY_PAGE, 1, true},
  {DB_HA_APPLY_DELAY_ESTIMATED, 1, false},
  {DB_FREESPACE, 100, false},
  {"none1", 1, false},
  {"none2", 1, false},
  {"uptime", 1, false}       // uptime must be the last one
};

// volume free sapce is a special metrics for DB
#define VOL_FREESPACE           "vol_freespace"
#define VOL_METRICS_LEN         2

/* OS metrics */
/* two unused metrics */
#define OS_METRICS_LEN          10

#define OS_CPU_IDLE             "os_cpu_idle"
#define OS_CPU_IOWAIT           "os_cpu_iowait"
#define OS_CPU_KERNEL           "os_cpu_kernel"
#define OS_CPU_USER             "os_cpu_user"
#define OS_MEM_PHY_FREE         "os_mem_phy_free"
#define OS_MEM_SWAP_FREE        "os_mem_swap_free"
#define OS_DISK_FREE            "os_disk_free"

const T_METRIC OS_METRICS[OS_METRICS_LEN] =
{
  {OS_CPU_IDLE, 1, true},
  {OS_CPU_IOWAIT, 1, true},
  {OS_CPU_KERNEL, 1, true},
  {OS_CPU_USER, 1, true},
  {OS_MEM_PHY_FREE, 100, false},
  {OS_MEM_SWAP_FREE, 100, false},
  {OS_DISK_FREE, 100, false},
  {"none1", 1, false},
  {"none2", 1, false},
  {"uptime", 1, false}           // uptime must be the last one
};

/* end metrics define */

/* meta key word */
#define K_INTERVAL              "k_interval"
#define K_TOTAL_VOL_NUM         "k_total_vol_num"

#define K_BROKER_METRICS        "k_broker_metrics"
#define K_BROKER_NUM            "k_broker_num"
#define K_BROKER_RRD            "k_broker_rrd"

#define K_DB_METRICS            "k_db_metrics"
#define K_DB_NUM                "k_db_num"
#define K_DB_RRD                "k_db_rrd"

#define K_OS_METRICS            "k_os_metrics"
#define K_OS_RRD                "k_os_rrd"

#define K_BROKER_HOUR_AGG_TIME  "k_broker_hour_agg_time"
#define K_DB_HOUR_AGG_TIME      "k_db_hour_agg_time"
#define K_OS_HOUR_AGG_TIME      "k_os_hour_agg_time"

#define K_BROKER_DAILY_AGG_TIME  "k_broker_daily_agg_time"
#define K_DB_DAILY_AGG_TIME      "k_db_daily_agg_time"
#define K_OS_DAILY_AGG_TIME      "k_os_daily_agg_time"
/* end meta key word */

#define JSON_ATOI(x) (atoi((x).asString().c_str()))
#if defined(WINDOWS)
#define JSON_ATOL(x) (_atoi64((x).asString().c_str()))
#define CPU_BASE_FEQ_WIN 1000000
#else
#define JSON_ATOL(x) (atoll((x).asString().c_str()))
#endif

static bool init_rrdfile (string filename, int rrdsize, int metrics_len);
static bool get_rrdfile (string filename, int rrdpos, int *buf, int bufsize, int metrics_len);
static bool append_rrdfile (string filename, int rrdsize, int metrics_len);
static bool update_rrdfile (string filename, int rrdpos, int *buf, int bufsize, int mlen);
static bool call_task (Json::Value &req, Json::Value &res, T_TASK_FUNC func, string &errmsg);
static bool get_dbs_list (Json::Value &db_list);
static bool get_active_dbs_list (Json::Value &db_list);
static bool get_brokers_list (Json::Value &brokers_list);
static bool get_volume_list (string dbname, Json::Value &vol_list);
static void mon_last (int *buf, int bufsize, int *agg_data, int idx, int mlen, int pfactor = 1);
static void mon_avg (int *buf, int bufsize, int *agg_data, int idx, int mlen, int pfactor = 1);
static void mon_diff_avg (int *buf, int bufsize, int *agg_data, int idx, int mlen, int interval, int pfactor = 1);
static bool call_task_ext (Json::Value &req, Json::Value &res, T_EXT_TASK_FUNC func);
static bool mdtype_from_str (const string &dtype, MDTYPE &mdtype);

class scope_lock
{
  public:
    scope_lock (MUTEX_T &mutex):_mutex (mutex)
    {
      MUTEX_LOCK (_mutex);
    }
    ~scope_lock()
    {
      MUTEX_UNLOCK (_mutex);
    }
  private:
    MUTEX_T _mutex;
};

cm_mon_stat *cm_mon_stat::_instance = NULL;

cm_mon_stat::cm_mon_stat (string data_path):
  _data_path (data_path + "/"),
  _meta_file (_data_path + META_NAME)
{
  _daily_idx = -1;
  _monthly_idx = -1;
  _yearly_idx = -1;
  _prev_gather = 0;
  _init = false;
  MUTEX_INIT (_data_mutex);
}

cm_mon_stat *cm_mon_stat::get_instance()
{
  if (NULL == _instance)
    {
      _instance = new cm_mon_stat (sco.sMonStatDataPath);
    }
  return _instance;
}

bool cm_mon_stat::get_mon_interval (time_t &interval) const
{
  if (true == _init)
    {
      interval = _meta[K_INTERVAL].asInt();
      return true;
    }
  else
    {
      return false;
    }
}

bool cm_mon_stat::set_mon_interval (time_t interval)
{
  if (false == _init)
    {
      return false;
    }
  if (_meta[K_INTERVAL].asInt() == interval)
    {
      return true;
    }
  try
    {
      return reset_meta ((int) interval);
    }
  catch (exception &)
    {
      return false;
    }
}

bool cm_mon_stat::initial()
{
  try
    {
      if (access (_meta_file.c_str(), F_OK) < 0)   /* file not exist */
        {
          _init = init_meta (DEFAULT_MON_STAT_INTERVAL);
        }
      else
        {
          _init = load_meta_file();
        }
    }
  catch (exception &)
    {
      _init = false;
    }
  return _init;
}

void cm_mon_stat::gather_mon_data (void)
{

  time_t gather_time = time (NULL);
  //try {
  if ((0 != _prev_gather)
      && (gather_time - _prev_gather < _meta[K_INTERVAL].asInt()))
    {
      return;
    }
  if (false == _init)
    {
      LOG_WARN ("monitoring statistic module is not initialized");
      return;
    }
  scope_lock slocker (_data_mutex);

  if (false == get_dbs_list (_dbs))
    {
      LOG_WARN ("get dbs list failed, time=[%d]", gather_time);
      return;
    }

  if (false == get_brokers_list (_brokers))
    {
      LOG_WARN ("get brokers list failed, time=[%d]", gather_time);
      return;
    }


  gather_daily_brokers_mon (gather_time);
  gather_daily_dbs_mon (gather_time);
  gather_daily_os_mon (gather_time);
  _daily_idx = (gather_time % (60 * 60 * 24)) / _meta[K_INTERVAL].asInt();

  aggregate_2_hour (gather_time);
  _monthly_idx = (gather_time % ( 30 * 60 * 60 * 24)) / 3600;

  aggregate_2_day (gather_time);
  _yearly_idx = (gather_time % ( 365 * 60 * 60 * 24)) / (3600 * 24);

  _prev_gather = gather_time;
  //}
  //catch (...) {
  //    LOG_WARN("gather_mon_data end with exception, time=[%d]", gather_time);
  //}
}

void cm_mon_stat::aggregate_2_hour (time_t gather_time)
{
  int monthly_idx = (gather_time % ( 30 * 60 * 60 * 24)) / 3600;
  int buf_base = 3600/_meta[K_INTERVAL].asInt();
  int read_offset = 0;

  if (0 == _daily_idx)
    {
      read_offset += (23 * 3600) / _meta[K_INTERVAL].asInt();
    }
  else
    {
      read_offset += _daily_idx - (3600 / _meta[K_INTERVAL].asInt());
    }

  int write_offset = 24 * 3600 / _meta[K_INTERVAL].asInt() + monthly_idx;

  aggregate_brokers (read_offset, buf_base, write_offset, HOUR, gather_time);
  aggregate_dbs (read_offset, buf_base, write_offset, HOUR, gather_time);
  aggregate_os (read_offset, buf_base, write_offset, HOUR, gather_time);
}

void cm_mon_stat::aggregate_2_day (time_t gather_time)
{
  int yearly_idx = (gather_time % ( 365 * 60 * 60 * 24)) / (3600 * 24);
  int buf_base = 24;
  int read_offset = 24 * 3600 /_meta[K_INTERVAL].asInt();

  if (0 == _monthly_idx)
    {
      read_offset += 29 * 24;
    }
  else
    {
      read_offset += _monthly_idx - 24;
    }

  int write_offset = 24 * 3600 / _meta[K_INTERVAL].asInt() + 30 * 24 + yearly_idx;

  aggregate_brokers (read_offset, buf_base, write_offset, DAY, gather_time);
  aggregate_dbs (read_offset, buf_base, write_offset, DAY, gather_time);
  aggregate_os (read_offset, buf_base, write_offset, DAY, gather_time);
}

void cm_mon_stat::aggregate_os (int read_offset,
                                int buf_base,
                                int write_offset,
                                AGG_TYPE atype,
                                time_t gather_time)
{
  string key;
  int mod = 0;
  if (HOUR == atype)
    {
      key = K_OS_HOUR_AGG_TIME;
      mod = 3600;
    }
  else
    {
      key = K_OS_DAILY_AGG_TIME;
      mod = 3600 * 24;
    }

  if (Json::Value::null != _meta[key])
    {
      time_t last_time = _meta[key].asInt();
      if (last_time / mod >= gather_time / mod)
        {
          return;
        }
    }
  int bufsize = buf_base * OS_METRICS_LEN;
  int *buf = new (int[bufsize]);
  if (false == get_rrdfile (_data_path + OS_MON, read_offset, buf, bufsize, OS_METRICS_LEN))
    {
      LOG_WARN ("read os rrd file failed");
      delete [] buf;
      return;
    }

  int agg_data[OS_METRICS_LEN];
  memset (agg_data, 0, OS_METRICS_LEN * sizeof (int));
  for (int i = 0; i < 4; i++)
    {
      if (HOUR == atype)
        {
          mon_diff_avg (buf, bufsize, agg_data, i, OS_METRICS_LEN, _meta[K_INTERVAL].asInt());
        }
      else
        {
          mon_avg (buf, bufsize, agg_data, i, OS_METRICS_LEN);
        }
    }
  mon_avg (buf, bufsize, agg_data, 4, OS_METRICS_LEN, 100);
  mon_avg (buf, bufsize, agg_data, 5, OS_METRICS_LEN, 100);
  mon_last (buf, bufsize, agg_data, 6, OS_METRICS_LEN, 100);
  agg_data[7] = 0;
  agg_data[8] = 0;
  agg_data[9] = int (gather_time);

  update_rrdfile (_data_path + OS_MON, write_offset, agg_data, OS_METRICS_LEN, OS_METRICS_LEN);
  _meta[key] = int (gather_time);
  flush_meta_file();
  delete [] buf;
}

void cm_mon_stat::aggregate_dbs (int read_offset,
                                 int buf_base,
                                 int write_offset,
                                 AGG_TYPE atype,
                                 time_t gather_time)
{
  string key;
  int mod = 0;
  if (HOUR == atype)
    {
      key = K_DB_HOUR_AGG_TIME;
      mod = 3600;
    }
  else
    {
      key = K_DB_DAILY_AGG_TIME;
      mod = 3600 * 24;
    }
  if (Json::Value::null != _meta[key])
    {
      time_t last_time = _meta[key].asInt();
      if (last_time / mod >= gather_time / mod)
        {
          return;
        }
    }

  // Fix for CUBRIDSUS-11976
  Json::Value active_dbs;
  if (false == get_active_dbs_list (active_dbs))
    {
      LOG_WARN ("get active dbs list failed, time=[%d]", gather_time);
      return;
    }

  for (unsigned int i = 0; i < active_dbs.size(); i++)
    {
      string dbname = active_dbs[i].asString();
      if (false == _meta[K_DB_RRD].isMember (dbname + "_idx"))
        {
          LOG_WARN ("can't find db [%s] index in meta file", dbname.c_str());
          continue;
        }
      int db_idx = _meta[K_DB_RRD][dbname + "_idx"].asInt();
      int read_idx = db_idx * MON_DATA_BLOCK + read_offset;

      int bufsize = buf_base * DB_METRICS_LEN;
      int *buf = new (int[bufsize]);

      if (false == get_rrdfile (_data_path + DB_MON, read_idx, buf, bufsize, DB_METRICS_LEN))
        {
          LOG_WARN ("read db rrd file failed");
          delete [] buf;
          return;
        }

      int agg_data[DB_METRICS_LEN];
      memset (agg_data, 0, DB_METRICS_LEN * sizeof (int));

      if (HOUR == atype)
        {
          mon_diff_avg (buf, bufsize, agg_data, 0, DB_METRICS_LEN, _meta[K_INTERVAL].asInt());
          agg_data[0] = agg_data[0] / _meta[K_INTERVAL].asInt();
          mon_diff_avg (buf, bufsize, agg_data, 1, DB_METRICS_LEN, _meta[K_INTERVAL].asInt());
          agg_data[1] = agg_data[1] / _meta[K_INTERVAL].asInt();
        }
      else
        {
          mon_avg (buf, bufsize, agg_data, 0, DB_METRICS_LEN);
          mon_avg (buf, bufsize, agg_data, 1, DB_METRICS_LEN);
        }
      mon_avg (buf,bufsize, agg_data, 2, DB_METRICS_LEN, 100);
      mon_avg (buf,bufsize, agg_data, 3, DB_METRICS_LEN, 100);
      if (HOUR == atype)
        {
          mon_diff_avg (buf, bufsize, agg_data, 4, DB_METRICS_LEN, _meta[K_INTERVAL].asInt());
          agg_data[4] = agg_data[4] / _meta[K_INTERVAL].asInt();
          mon_diff_avg (buf, bufsize, agg_data, 5, DB_METRICS_LEN, _meta[K_INTERVAL].asInt());
          agg_data[5] = agg_data[5] / _meta[K_INTERVAL].asInt();
        }
      else
        {
          mon_avg (buf, bufsize, agg_data, 4, DB_METRICS_LEN);
          mon_avg (buf, bufsize, agg_data, 5, DB_METRICS_LEN);
        }
      mon_avg (buf,bufsize, agg_data, 6, DB_METRICS_LEN);
      for (unsigned int i = 7; i < 11; i++)
        {
          if (HOUR == atype)
            {
              mon_diff_avg (buf,bufsize, agg_data, i, DB_METRICS_LEN, _meta[K_INTERVAL].asInt());
              agg_data[i] /= _meta[K_INTERVAL].asInt();
            }
          else
            {
              mon_avg (buf,bufsize, agg_data, i, DB_METRICS_LEN);
            }
        }
      // HA metrics
      if (HOUR == atype)
        {
          mon_diff_avg (buf,bufsize, agg_data, 11, DB_METRICS_LEN, _meta[K_INTERVAL].asInt());
          agg_data[11] /= _meta[K_INTERVAL].asInt();
        }
      else
        {
          mon_avg (buf,bufsize, agg_data, 11, DB_METRICS_LEN);
        }
      mon_avg (buf,bufsize, agg_data, 12, DB_METRICS_LEN);
      if (HOUR == atype)
        {
          mon_diff_avg (buf,bufsize, agg_data, 13, DB_METRICS_LEN, _meta[K_INTERVAL].asInt());
          agg_data[13] /= _meta[K_INTERVAL].asInt();
        }
      else
        {
          mon_avg (buf,bufsize, agg_data, 13, DB_METRICS_LEN);
        }
      mon_avg (buf,bufsize, agg_data, 14, DB_METRICS_LEN);
      mon_last (buf,bufsize, agg_data, 15, DB_METRICS_LEN, 100);
      agg_data[16] = 0;
      agg_data[17] = 0;
      agg_data[18] = int (gather_time);

      int rrdpos = db_idx * MON_DATA_BLOCK + write_offset;
      update_rrdfile (_data_path + DB_MON, rrdpos, agg_data, DB_METRICS_LEN, DB_METRICS_LEN);

      // volume
      Json::Value vols;
      if (false == get_volume_list (dbname, vols))
        {
          continue;
        }

      for (unsigned int i = 0; i < vols.size(); i++)
        {
          string vol_name = vols[i].asString();
          if (false == _meta[K_DB_RRD][dbname + "_vol"].isMember (vol_name))
            {
              LOG_WARN ("can't find db [%s] vol[%s] index in meta file", dbname.c_str(), vol_name.c_str());
              continue;
            }
          int vol_idx = _meta[K_DB_RRD][dbname + "_vol"][vol_name].asInt();
          int read_idx = vol_idx * MON_DATA_BLOCK + read_offset;
          int bufsize_vol = buf_base * VOL_METRICS_LEN;
          int *buf_vol = new (int[bufsize_vol]);
          if (false == get_rrdfile (_data_path + VOL_MON, read_idx, buf_vol, bufsize_vol, VOL_METRICS_LEN))
            {
              LOG_WARN ("read volume rrd file failed");
              delete [] buf;
              delete [] buf_vol;
              return;
            }
          int agg_data[VOL_METRICS_LEN];
          memset (agg_data, 0, VOL_METRICS_LEN * sizeof (int));
          mon_last (buf_vol,bufsize_vol,agg_data,0,VOL_METRICS_LEN, 100);
          agg_data[1] = int (gather_time);

          int rrdpos = vol_idx * MON_DATA_BLOCK + write_offset;
          update_rrdfile (_data_path + VOL_MON, rrdpos, agg_data, VOL_METRICS_LEN, VOL_METRICS_LEN);
          delete [] buf_vol;
        }
      delete [] buf;
    }
  _meta[key] = int (gather_time);
  flush_meta_file();
}

static bool mdtype_from_str (const string &dtype, MDTYPE &mdtype)
{
  if ("daily" == dtype)
    {
      mdtype = DAILY;
    }
  else if ("weekly" == dtype)
    {
      mdtype = WEEKLY;
    }
  else if ("monthly" == dtype)
    {
      mdtype = MONTHLY;
    }
  else if ("yearly" == dtype)
    {
      mdtype = YEARLY;
    }
  else
    {
      return false;
    }
  return true;
}

bool cm_mon_stat::get_mon_statistic (const Json::Value req, Json::Value &res, string &errmsg) const
{
  if (false == _init)
    {
      errmsg = "monitoring staticstic module is not initialized";
      LOG_WARN (errmsg.c_str());
      return false;
    }
  string metric = req["metric"].asString();
  if (OS_CPU_IDLE == metric
      || OS_CPU_IOWAIT == metric
      || OS_CPU_KERNEL == metric
      || OS_CPU_USER == metric
      || DB_CPU_KERNEL == metric
      || DB_CPU_USER == metric)
    {
      if (false == m_get_mon_statistic (req, res, errmsg))
        {
          return false;
        }

      Json::Value os_idle_req, os_idle_res;
      os_idle_req = req;
      os_idle_req["metric"] = OS_CPU_IDLE;
      if (false == m_get_mon_statistic (os_idle_req, os_idle_res, errmsg))
        {
          res.removeMember ("data");
          return false;
        }

      Json::Value os_iowait_req, os_iowait_res;
      os_iowait_req = req;
      os_iowait_req["metric"] = OS_CPU_IOWAIT;
      if (false == m_get_mon_statistic (os_iowait_req, os_iowait_res, errmsg))
        {
          res.removeMember ("data");
          return false;
        }

      Json::Value os_kernel_req, os_kernel_res;
      os_kernel_req = req;
      os_kernel_req["metric"] = OS_CPU_KERNEL;
      if (false == m_get_mon_statistic (os_kernel_req, os_kernel_res, errmsg))
        {
          res.removeMember ("data");
          return false;
        }

      Json::Value os_user_req, os_user_res;
      os_user_req = req;
      os_user_req["metric"] = OS_CPU_USER;
      if (false == m_get_mon_statistic (os_user_req, os_user_res, errmsg))
        {
          res.removeMember ("data");
          return false;
        }

      for (unsigned int i = 0; i < res["data"].size(); i++)
        {
          if (res["data"][i].asInt() == INIT_METRIC_VALUE)
            {
              continue;
            }
          else if (os_idle_res["data"][i].asInt() != INIT_METRIC_VALUE
                   && os_iowait_req["data"][i].asInt() != INIT_METRIC_VALUE
                   && os_kernel_res["data"][i].asInt() != INIT_METRIC_VALUE
                   && os_user_res["data"][i].asInt() != INIT_METRIC_VALUE)
            {
              int total = os_idle_res["data"][i].asInt() + os_iowait_req["data"][i].asInt()
                          + os_kernel_res["data"][i].asInt() + os_user_res["data"][i].asInt();
              if (total <= 0)
                {
                  res["data"][i] = 0;
                }
              else
                {
                  // Because of percentage and accurating to the second decimal places,
                  // so it should be multiply by 10000.
                  res["data"][i] = int (float (res["data"][i].asInt()) * 10000 / total);
                }
            }
          else
            {
              res["data"][i] = INIT_METRIC_VALUE;
            }
        }
      return true;
    }
  else
    {
      return m_get_mon_statistic (req, res, errmsg);
    }
}

// the data maybe wrong for the begin of the return data array
bool cm_mon_stat::m_get_mon_statistic (const Json::Value req, Json::Value &res, string &errmsg) const
{
  res["metric"] = req["metric"];
  res["dtype"] = req["dtype"];

  string metric = req["metric"].asString();

  MDTYPE mdtype = DAILY;
  if (false == mdtype_from_str (req["dtype"].asString(), mdtype))
    {
      errmsg = string ("Error format of dtype [") + req["dtype"].asString() + "] in request";
      LOG_WARN (errmsg.c_str());
      return false;
    }

  int m_idx = 0;
  int i = 0;
  int pfactor = 1;
  bool d_diff = false;

  if (0 == strncmp ("db_", metric.c_str(), strlen ("db_")))
    {
      string dbname = req["dbname"].asString();
      res["dbname"] = dbname;
      if (false == _meta[K_DB_RRD].isMember (dbname + "_idx"))
        {
          errmsg = string ("Can't find dbname[") + dbname + "] in meta[k_db_rrd]";
          LOG_WARN (errmsg.c_str());
          return false;
        }
      int db_idx = _meta[K_DB_RRD][dbname + "_idx"].asInt();
      for (i = 0; i < DB_METRICS_LEN; i++)
        {
          if (DB_METRICS[i].metric == metric)
            {
              m_idx = i;
              pfactor = DB_METRICS[i].pfactor;
              d_diff = DB_METRICS[i].ddiff;
              break;
            }
        }
      if (i == DB_METRICS_LEN)
        {
          errmsg = string ("Can't find DB metric[") + metric + "] from request";
          LOG_WARN (errmsg.c_str());
          return false;
        }
      string data_path = _data_path + DB_MON;
      return get_rrd_data (mdtype, data_path, db_idx, m_idx, pfactor, d_diff, DB_METRICS_LEN, res, errmsg);
    }

  if (0 == strncmp ("vol_", metric.c_str(), strlen ("vol_")))
    {
      string dbname = req["dbname"].asString();
      string volname = req["volname"].asString();
      res["dbname"] = dbname;
      res["volname"] = volname;
      if (false == _meta[K_DB_RRD].isMember (dbname + "_vol"))
        {
          errmsg = string ("Can't find dbname_vol[") + dbname + "] in meta[k_db_rrd]";
          LOG_WARN (errmsg.c_str());
          return false;
        }
      if (false == _meta[K_DB_RRD][dbname + "_vol"].isMember (volname))
        {
          errmsg = string ("Can't find volname[") + volname + "] in DB [" + dbname + "] meta[k_db_rrd]";
          LOG_WARN (errmsg.c_str());
          return false;
        }
      int vol_idx = _meta[K_DB_RRD][dbname + "_vol"][volname].asInt();
      if (VOL_FREESPACE != metric)
        {
          errmsg = string ("Can't find volume metric[") + metric + "] from request";
          LOG_WARN (errmsg.c_str());
          return false;
        }
      string data_path = _data_path + VOL_MON;
      return get_rrd_data (mdtype, data_path, vol_idx, m_idx, 100, d_diff, VOL_METRICS_LEN, res, errmsg);
    }

  if (0 == strncmp ("broker_", metric.c_str(), strlen ("broker_")))
    {
      string bname = req["bname"].asString();
      res["bname"] = bname;
      if (false == _meta[K_BROKER_RRD].isMember (bname + "_idx"))
        {
          errmsg = string ("Can't find broker [") + bname + "] in meta[k_db_rrd]";
          LOG_WARN (errmsg.c_str());
          return false;
        }
      int b_idx = _meta[K_BROKER_RRD][bname + "_idx"].asInt();
      for (i = 0; i < BROKER_METRICS_LEN; i++)
        {
          if (BROKER_METRICS[i].metric == metric)
            {
              m_idx = i;
              pfactor = BROKER_METRICS[i].pfactor;
              d_diff = BROKER_METRICS[i].ddiff;
              break;
            }
        }
      if (i == BROKER_METRICS_LEN)
        {
          errmsg = string ("Can't find broker metric[") + metric + "] from request";
          LOG_WARN (errmsg.c_str());
          return false;
        }
      string data_path = _data_path + BROKER_MON;
      return get_rrd_data (mdtype, data_path, b_idx, m_idx, pfactor, d_diff, BROKER_METRICS_LEN, res, errmsg);
    }

  if (0 == strncmp ("os_", metric.c_str(), strlen ("os_")))
    {
      for (i = 0; i < OS_METRICS_LEN; i++)
        {
          if (OS_METRICS[i].metric == metric)
            {
              m_idx = i;
              pfactor = OS_METRICS[i].pfactor;
              d_diff = OS_METRICS[i].ddiff;
              break;
            }
        }
      if (i == OS_METRICS_LEN)
        {
          errmsg = string ("Can't find os metric[") + metric + "] from request";
          LOG_WARN (errmsg.c_str());
          return false;
        }
      string data_path = _data_path + OS_MON;
      return get_rrd_data (mdtype, data_path, 0, m_idx, pfactor, d_diff, OS_METRICS_LEN, res, errmsg);
    }

  return false;
}

bool cm_mon_stat::get_rrd_data (MDTYPE mdtype, string dpath, int didx,
                                int midx, int pfactor, bool ddiff, int mlen,
                                Json::Value &res, string &errmsg) const
{
  int read_rrd_idx = didx * MON_DATA_BLOCK;
  int bufsize = 0;
  switch (mdtype)
    {
    case DAILY:
      bufsize = mlen * (24 * 60 * 60 / _meta[K_INTERVAL].asInt());
      break;
    case WEEKLY:
    case MONTHLY:
      bufsize = mlen * 30 * 24;
      read_rrd_idx += 24 * 60 * 60 / _meta[K_INTERVAL].asInt();
      break;
    case YEARLY:
      bufsize = mlen * 365;
      read_rrd_idx += 24 * 60 * 60 / _meta[K_INTERVAL].asInt() + 24 * 30;
      break;
    }
  int *buf = new (int[bufsize]);
  if (false == get_rrdfile (dpath, read_rrd_idx, buf, bufsize, mlen))
    {
      errmsg = string ("read rrd file failed [") + dpath + "]";
      LOG_WARN (errmsg.c_str());
      delete [] buf;
      return false;
    }

  time_t cur_time = time (NULL);
  int read_buf_idx = 0;
  int daily_mod = (3600 * 24) / _meta[K_INTERVAL].asInt();
  switch (mdtype)
    {
    case DAILY:
      read_buf_idx = _daily_idx < 0 ?
                     (cur_time % (60 * 60 * 24)) / _meta[K_INTERVAL].asInt():_daily_idx + 1;
      if (true == ddiff)
        {
          // Smoothing data functionality is added
          int value = INIT_METRIC_VALUE;
          int start = 0;      // for count the num if the it's not updated from the beginning
          for (int i = 1; i < daily_mod; i++)
            {
              int cur = buf[ ((read_buf_idx + i) % daily_mod) * mlen + midx];
              int cur_up = buf[ ((read_buf_idx + i) % daily_mod) * mlen + mlen - 1];
              int pre = buf[ ((read_buf_idx + i - 1) % daily_mod) * mlen + midx];
              int pre_up = buf[ ((read_buf_idx + i - 1) % daily_mod) * mlen + mlen - 1];
              if ((cur_up < pre_up) || (cur_up - pre_up > 2 * _meta[K_INTERVAL].asInt()))
                {
                  if (-1 != start)
                    {
                      start++;
                    }
                  else
                    {
                      res["data"].append (value); // using last value
                    }
                }
              else
                {
                  if (cur == INIT_METRIC_VALUE)
                    {
                      value = INIT_METRIC_VALUE;
                    }
                  else  if (pre == INIT_METRIC_VALUE)
                    {
                      value = int ((float (cur) * (100/pfactor)) / _meta[K_INTERVAL].asInt());
                    }
                  else
                    {
                      value = int ((float (cur >= pre ? cur - pre: cur) * (100/pfactor)) / _meta[K_INTERVAL].asInt());
                    }
                  res["data"].append (value);
                  if (-1 != start)         // If from the start, add extra value
                    {
                      while (start >= 0)
                        {
                          res["data"].append (value);
                          start--;
                        }
                    }
                }
            }
          if (Json::Value::null == res["data"])
            {
              for (int i = 0; i < daily_mod; i++)
                {
                  res["data"].append (0);
                }
            }
        }
      else
        {
          for (int i = read_buf_idx; i < read_buf_idx + daily_mod; i++)
            {
              res["data"].append (buf[ (i % daily_mod) * mlen + midx] * (100/pfactor));
            }
        }
      break;
    case WEEKLY:
      read_buf_idx = _monthly_idx < 0 ? (cur_time % (30 * 60 * 60 * 24)) / 3600 :_monthly_idx + 1;
      read_buf_idx += 30 * 24;
      for (int i = read_buf_idx - 24*7; i <  read_buf_idx; i++)
        {
          res["data"].append (buf[ (i% (30*24)) * mlen + midx]);
        }
      break;
    case MONTHLY:
      read_buf_idx = _monthly_idx < 0 ? (cur_time % (30 * 60 * 60 * 24)) / 3600 :_monthly_idx + 1;
      for (int i = read_buf_idx; i <  30 * 24 + read_buf_idx; i++)
        {
          res["data"].append (buf[ (i% (30*24)) * mlen + midx]);
        }
      break;
    case YEARLY:
      read_buf_idx = _yearly_idx < 0 ? (cur_time % (365 * 3600 * 24)) / (3600*24) :_yearly_idx + 1;
      for (int i = read_buf_idx; i <  365; i++)
        {
          res["data"].append (buf[i * mlen + midx]);
        }
      for (int i = 0; i < read_buf_idx; i++)
        {
          res["data"].append (buf[i * mlen + midx]);
        }
      break;
    }
  delete [] buf;
  return true;
}

static bool get_volume_list (string dbname, Json::Value &vol_list)
{
  Json::Value req, res;
  req["dbname"] = dbname;
  req["_DBNAME"] = dbname;
  string errmsg;
  if (false == call_task (req, res, tsDbspaceInfo, errmsg))
    {
      LOG_WARN ("call getdbspaceinfo failed, error code[%d], error message [%s]",
                res["retval"].asInt(), errmsg.c_str());
      return false;
    }
  for (unsigned int i = 0; i < res["spaceinfo"].size(); i++)
    {
      vol_list.append (res["spaceinfo"][i]["spacename"].asString());
    }
  return true;
}

void cm_mon_stat::aggregate_brokers (int read_offset,
                                     int buf_base,
                                     int write_offset,
                                     AGG_TYPE atype,
                                     time_t gather_time)
{
  string key;
  int mod = 0;
  if (HOUR == atype)
    {
      key = K_BROKER_HOUR_AGG_TIME;
      mod = 3600;
    }
  else
    {
      key = K_BROKER_DAILY_AGG_TIME;
      mod = 3600 * 24;
    }
  if (Json::Value::null != _meta[key])
    {
      time_t last_time = _meta[key].asInt();
      if (last_time / mod >= gather_time / mod)
        {
          return;
        }
    }

  for (unsigned int i = 0; i < _brokers.size(); i++)
    {
      string bname = _brokers[i].asString();
      if (false == _meta[K_BROKER_RRD].isMember (bname + "_idx"))
        {
          LOG_WARN ("can't find broker [%s] index in meta file", bname.c_str());
          continue;
        }
      int broker_idx = _meta[K_BROKER_RRD][bname + "_idx"].asInt();

      int read_idx = broker_idx * MON_DATA_BLOCK + read_offset;

      int bufsize = buf_base * BROKER_METRICS_LEN;
      int *buf = new (int[bufsize]);

      if (false == get_rrdfile (_data_path + BROKER_MON, read_idx, buf, bufsize, BROKER_METRICS_LEN))
        {
          LOG_WARN ("read broker rrd file failed");
          delete [] buf;
          return;
        }

      int agg_data[BROKER_METRICS_LEN];
      memset (agg_data, 0, BROKER_METRICS_LEN * sizeof (int));
      for (int i = 0; i < 6; i ++)
        {
          if (HOUR == atype)
            {
              mon_diff_avg (buf, bufsize, agg_data, i, BROKER_METRICS_LEN, _meta[K_INTERVAL].asInt());
              agg_data[i] = agg_data[i] / _meta[K_INTERVAL].asInt();
            }
          else
            {
              mon_avg (buf, bufsize, agg_data, i, BROKER_METRICS_LEN);
            }
        }
      mon_avg (buf, bufsize, agg_data, 6, BROKER_METRICS_LEN);
      agg_data[7] = 0;
      agg_data[8] = 0;
      agg_data[9] = int (gather_time);

      int rrdpos = broker_idx * MON_DATA_BLOCK + write_offset;
      update_rrdfile (_data_path + BROKER_MON, rrdpos, agg_data, BROKER_METRICS_LEN, BROKER_METRICS_LEN);
      delete [] buf;
    }
  _meta[key] = int (gather_time);
  flush_meta_file();
}

static void mon_last (int *buf, int bufsize, int *agg_data, int idx, int mlen, int pfactor)
{
  if (buf[bufsize - mlen + idx] != INIT_METRIC_VALUE)
    {
      agg_data[idx] = buf[bufsize - mlen + idx] * (100 / pfactor);
    }
  else
    {
      agg_data[idx] = 0;
    }
}

// pfactor is used to control the precision, the default is accurating to 2 decimal places

static void mon_avg (int *buf, int bufsize, int *agg_data, int idx, int mlen, int pfactor)
{
  int count = 0;
  for (int i = 0; i < bufsize/mlen; i++)
    {
      if (buf[i * mlen + idx] != INIT_METRIC_VALUE)
        {
          agg_data[idx] += buf[i * mlen + idx];
          count++;
        }
    }
  if (count != 0)
    {
      agg_data[idx] = agg_data[idx] * (100/pfactor) / count;
    }
  else
    {
      agg_data[idx] = 0;
    }
}

// pfactor is used to control the precision, the default is accurating to 2 decimal places

static void mon_diff_avg (int *buf, int bufsize, int *agg_data, int idx, int mlen, int interval, int pfactor)
{
  int count = 0;
  for (int i = 0; i < bufsize/mlen - 1; i++)
    {
      int pre = buf[i * mlen + idx];
      int pre_up = buf[i * mlen + mlen - 1];
      int next = buf[ (i + 1) * mlen + idx];
      int next_up = buf[ (i + 1) * mlen + mlen - 1];
      if (next == INIT_METRIC_VALUE)
        {
          continue;
        }
      if (pre == INIT_METRIC_VALUE)
        {
          agg_data[idx] += next;
          count++;
          continue;
        }
      if ((pre <= next) && (next_up > pre_up) && (next_up - pre_up < 2*interval))
        {
          agg_data[idx] += (next - pre);
          count++;
        }
    }
  if (0 != count)
    {
      agg_data[idx] = agg_data[idx] * (100/pfactor) / count;
    }
  else
    {
      agg_data[idx] = 0;
    }
}

void cm_mon_stat::gather_daily_brokers_mon (time_t gather_time)
{
  int broker_data[BROKER_METRICS_LEN];
  memset (broker_data, 0, BROKER_METRICS_LEN * sizeof (int));

  int daily_idx = (gather_time % (60 * 60 * 24)) / _meta[K_INTERVAL].asInt();

  Json::Value req, brokers_info;
  string errmsg;
  if (false == call_task (req, brokers_info, ts2_get_unicas_info, errmsg))
    {
      LOG_ERROR ("failed to get brokers infomation, time=[%d], error code[%d], error message [%s]",
                 gather_time, brokers_info["retval"].asInt(), errmsg.c_str());
      return;
    }
  if (brokers_info.isMember ("brokersinfo"))
    {
      for (unsigned int i = 0; i < brokers_info["brokersinfo"][0u]["broker"].size(); i++)
        {
          Json::Value &bdata = brokers_info["brokersinfo"][0u]["broker"][i];
          string bname = bdata["name"].asString();

          // resize broker rrdfile
          if (false == _meta[K_BROKER_RRD].isMember (bname + "_idx"))
            {
              if (false == append_rrdfile (_data_path + BROKER_MON, MON_DATA_BLOCK, BROKER_METRICS_LEN))
                {
                  continue;
                }
              _meta[K_BROKER_RRD][bname + "_idx"] = _meta[K_BROKER_NUM].asInt();
              _meta[K_BROKER_NUM] = _meta[K_BROKER_NUM].asInt() + 1;
              if (false == flush_meta_file())
                {
                  continue;
                }
            }

          broker_data[0] = JSON_ATOI (bdata["tran"]);
          broker_data[1] = JSON_ATOI (bdata["query"]);
          broker_data[2] = JSON_ATOI (bdata["long_tran"]);
          broker_data[3] = JSON_ATOI (bdata["long_query"]);
          broker_data[4] = JSON_ATOI (bdata["req"]);
          broker_data[5] = JSON_ATOI (bdata["error_query"]);
          broker_data[6] = JSON_ATOI (bdata["jq"]);
          broker_data[7] = 0;
          broker_data[8] = 0;
          broker_data[9] = int (gather_time);

          int broker_idx = _meta[K_BROKER_RRD][bname+"_idx"].asInt();
          int rrdpos = broker_idx * MON_DATA_BLOCK + daily_idx;
          update_rrdfile (_data_path + BROKER_MON, rrdpos, broker_data, BROKER_METRICS_LEN, BROKER_METRICS_LEN);
        }
    }
  else
    {
      LOG_ERROR ("error format of brokers infomation, time=[%d]", gather_time);
    }
}

bool cm_mon_stat::gather_dbs_tran_query (time_t gather_time, Json::Value &db_tq)
{
  string bstr = _brokers[0u].asString();

  for (unsigned int i = 1; i < _brokers.size(); i ++)
    {
      bstr += "," + _brokers[i].asString();
    }

  Json::Value as_req, as_res;
  as_req["bname"] = bstr;
  string errmsg;
  if (false != call_task (as_req, as_res, ts2_get_broker_status, errmsg))
    {
      Json::Value b_as;
      // more than one broker
      if (as_res.isMember ("broker"))
        {
          b_as = as_res["broker"];
        }
      else if (as_res.isMember ("asinfo"))  // one broker
        {
          b_as.append (as_res);
        }
      else
        {
          LOG_WARN ("get broker status failed, time=[%d]", gather_time);
          return false;
        }

      for (unsigned int i = 0; i < b_as.size(); i++)
        {
          for (unsigned int j = 0; j < b_as[i]["asinfo"].size(); j++)
            {
              string dbname = b_as[i]["asinfo"][j]["as_dbname"].asString();
              if (0 != dbname.length())
                {
                  if (db_tq.isMember (dbname))
                    {
                      db_tq[dbname]["query"] = db_tq[dbname]["query"].asInt() + JSON_ATOI (b_as[i]["asinfo"][j]["as_num_query"]);
                      db_tq[dbname]["tran"] = db_tq[dbname]["tran"].asInt() + JSON_ATOI (b_as[i]["asinfo"][j]["as_num_tran"]);
                    }
                  else
                    {
                      db_tq[dbname]["query"] = JSON_ATOI (b_as[i]["asinfo"][j]["as_num_query"]);
                      db_tq[dbname]["tran"] = JSON_ATOI (b_as[i]["asinfo"][j]["as_num_tran"]);
                    }
                }
            }
        }
    }
  else
    {
      LOG_WARN ("get brokers status failed, time=[%d], error code [%d], error message [%s]",
                gather_time, as_res["retval"].asInt(), errmsg.c_str());
      return false;
    }
  return true;
}

void cm_mon_stat::gather_daily_dbs_mon (time_t gather_time)
{
  int db_data[DB_METRICS_LEN];
  Json::Value db_tq;
  if (false == gather_dbs_tran_query (gather_time, db_tq))
    {
      return;
    }

  int daily_idx = (gather_time % (60 * 60 * 24)) / _meta[K_INTERVAL].asInt();

  Json::Value active_dbs;
  if (false == get_active_dbs_list (active_dbs))
    {
      LOG_WARN ("get active dbs list failed, time=[%d]", gather_time);
      return;
    }

  Json::Value ha_req, ha_res;
  ha_req["task"] = "ha_status";
  bool has_ha_info = false;
  string errmsg;
  string ha_rmt_hostname;
  if (true == call_task (ha_req, ha_res, ts_ha_status, errmsg))
    {
      has_ha_info = true;
      if ("master" == ha_res["current_node_state"].asString())
        {
          ha_rmt_hostname = ha_res["nodeA"].asString();
        }
      else
        {
          ha_rmt_hostname = ha_res["nodeB"].asString();
        }
    }
  else if (ERR_SYSTEM_CALL != ha_res["retval"].asInt())
    {
      LOG_WARN ("Get HA status failed, time=[%d], error code [%d], error message [%s]",
                gather_time, ha_res["retval"].asInt(), errmsg.c_str());
    }

  for (unsigned int i = 0; i < active_dbs.size(); i++)
    {
      memset (db_data, 0, DB_METRICS_LEN * sizeof (int));
      string dbname = active_dbs[i].asString();
      // resize db rrdfile
      if (false == _meta[K_DB_RRD].isMember (dbname + "_idx"))
        {
          if (false == append_rrdfile (_data_path + DB_MON, MON_DATA_BLOCK, DB_METRICS_LEN))
            {
              LOG_WARN ("append rrd file for new db failed, time=[%d]", gather_time);
              continue;
            }
          _meta[K_DB_RRD][dbname + "_idx"] = _meta[K_DB_NUM].asInt();
          _meta[K_DB_NUM] = _meta[K_DB_NUM].asInt() + 1;
          if (false == flush_meta_file())
            {
              LOG_WARN ("flush meta file failed, time=[%d]", gather_time);
              continue;
            }
        }

      Json::Value req, res;
      req["dbname"] = dbname;
      req["_DBNAME"] = dbname;
      errmsg = "";
      if (false == call_task (req, res, ts_get_dbproc_stat, errmsg))
        {
          LOG_WARN ("call getdbprocstatus failed, time=[%d], error code[%d], error message [%s]",
                    gather_time, res["retval"].asInt(), errmsg.c_str());
          continue;
        }
#if defined(WINDOWS)
      db_data[0] = JSON_ATOI (res["dbstat"][0u]["cpu_kernel"]) / CPU_BASE_FEQ_WIN;
      db_data[1] = JSON_ATOI (res["dbstat"][0u]["cpu_user"]) / CPU_BASE_FEQ_WIN;
#else
      db_data[0] = JSON_ATOI (res["dbstat"][0u]["cpu_kernel"]);
      db_data[1] = JSON_ATOI (res["dbstat"][0u]["cpu_user"]);
#endif
      db_data[2] = int (JSON_ATOL (res["dbstat"][0u]["mem_physical"]) * 100 / MB_SIZE);
      db_data[3] = int (JSON_ATOL (res["dbstat"][0u]["mem_virtual"]) * 100 / MB_SIZE);
      if (db_tq.isMember (dbname))
        {
          db_data[4] = db_tq[dbname]["query"].asInt();
          db_data[5] = db_tq[dbname]["tran"].asInt();
        }
      else
        {
          db_data[4] = 0;
          db_data[5] = 0;
        }

      //statdump
      res.clear();
      errmsg = "";
      if (false == call_task (req, res, ts_statdump, errmsg))
        {
          LOG_WARN ("call statdump failed, time=[%d], error code[%d], error message [%s]",
                    gather_time, res["retval"].asInt(), errmsg.c_str());
          continue;
        }
      db_data[6] = JSON_ATOI (res["data_page_buffer_hit_ratio"]);
      db_data[7] = JSON_ATOI (res["num_data_page_fetches"]);
      db_data[8] = JSON_ATOI (res["num_data_page_dirties"]);
      db_data[9] = JSON_ATOI (res["num_file_ioreads"]);
      db_data[10] = JSON_ATOI (res["num_file_iowrites"]);

      // HA monitoring
      if (true == has_ha_info)
        {
          // TODO: HA monitoring
          for (unsigned int i = 0; i < ha_res["ha_info"].size(); i++)
            {
              if (dbname == ha_res["ha_info"][i]["dbname"].asString())
                {
                  Json::Value req, res;
                  req["task"] = "gethaapplyinfo";
                  req["dbname"] = dbname;
                  req["remotehostname"] = ha_rmt_hostname;
                  string copylog = ha_res["ha_info"][i]["copylogdb"].asString();
                  unsigned int colon_idx = (unsigned int) copylog.find (':');
                  if (string::npos == colon_idx)
                    {
                      LOG_WARN ("Error format of copylogdb, time=[%d], copylogdb=[%s]",
                                gather_time, req["copylogdb"].asString().c_str());
                      break;
                    }
                  req["copylogpath"] = copylog.substr (colon_idx + 1);
                  if (false == call_task_ext (req, res, ext_get_ha_apply_info))
                    {
                      LOG_WARN ("Get HA apply info failed, time=[%d], dbname=[%s]",
                                gather_time, req["dbname"].asString().c_str());
                      break;
                    }
                  db_data[11] = JSON_ATOI (res["copyinglog_coun"]);
                  db_data[12] = JSON_ATOI (res["copyinglog_estimated_time"]);
                  db_data[13] = JSON_ATOI (res["applyinglog_count"]);
                  db_data[14] = JSON_ATOI (res["applyinglog_estimated_time"]);
                }
            }
        }

      // dbspaceinfo
      res.clear();
      req["_DBNAME"] = dbname;
      errmsg = "";
      if (false == call_task (req, res, tsDbspaceInfo, errmsg))
        {
          LOG_WARN ("call getdbspaceinfo failed, time=[%d], error code[%d], error message [%s]",
                    gather_time, res["retval"].asInt(), errmsg.c_str());
          continue;
        }
      db_data[15] = int (JSON_ATOL (res["freespace"]) * JSON_ATOL (res["pagesize"]) * 100 / MB_SIZE);
      db_data[16] = 0;
      db_data[17] = 0;
      db_data[18] = int (gather_time);

      // update rrdfile
      int rrdpos = _meta[K_DB_RRD][dbname + "_idx"].asInt() * MON_DATA_BLOCK + daily_idx;
      update_rrdfile (_data_path +"/"+ DB_MON, rrdpos, db_data, DB_METRICS_LEN, DB_METRICS_LEN);
      // volume
      for (unsigned int i = 0; i < res["spaceinfo"].size(); i++)
        {
          string vol_name = res["spaceinfo"][i]["spacename"].asString();
          if (false == _meta[K_DB_RRD][dbname + "_vol"].isMember (vol_name))
            {
              if (0 == _meta[K_TOTAL_VOL_NUM].asInt())
                {
                  init_rrdfile (_data_path + VOL_MON, MON_DATA_BLOCK, VOL_METRICS_LEN);
                }
              else
                {
                  append_rrdfile (_data_path + VOL_MON, MON_DATA_BLOCK, VOL_METRICS_LEN);
                }
              _meta[K_DB_RRD][dbname + "_vol"][vol_name] = _meta[K_TOTAL_VOL_NUM].asInt();
              _meta[K_TOTAL_VOL_NUM] = _meta[K_TOTAL_VOL_NUM].asInt() + 1;
              if (false == flush_meta_file())
                {
                  LOG_WARN ("flush meta file failed, time=[%d]", gather_time);
                  continue;
                }
            }

          // in MB
          int vol_data[VOL_METRICS_LEN];
          vol_data[0] = int (JSON_ATOL (res["spaceinfo"][i]["freepage"])
                             * JSON_ATOL (res["pagesize"]) * 100 / MB_SIZE);
          vol_data[1] = int (gather_time);
          int vol_idx = _meta[K_DB_RRD][dbname + "_vol"][vol_name].asInt();
          int rrdpos = vol_idx * MON_DATA_BLOCK + daily_idx;
          update_rrdfile (_data_path +"/"+ VOL_MON, rrdpos, vol_data, VOL_METRICS_LEN, VOL_METRICS_LEN);
        }
    }
}

void cm_mon_stat::gather_daily_os_mon (time_t gather_time)
{
  int os_data[OS_METRICS_LEN];
  memset (os_data, 0, OS_METRICS_LEN * sizeof (int));
  int daily_idx = (gather_time % (60 * 60 * 24)) / _meta[K_INTERVAL].asInt();

  Json::Value req, res;
  string errmsg;
  if (false != call_task (req, res, ts_get_host_stat, errmsg))
    {
#if defined(WINDOWS)
      // Fix for TOOLS-3417
      // using reducer to make the number doesn't excced MAX_INT
      os_data[0] = int (JSON_ATOL (res["cpu_idle"])/CPU_BASE_FEQ_WIN);
      os_data[1] = int (JSON_ATOL (res["cpu_iowait"])/CPU_BASE_FEQ_WIN);
      os_data[2] = int (JSON_ATOL (res["cpu_kernel"])/CPU_BASE_FEQ_WIN);
      os_data[3] = int (JSON_ATOL (res["cpu_user"])/CPU_BASE_FEQ_WIN);
#else
      os_data[0] = int (JSON_ATOI (res["cpu_idle"]));
      os_data[1] = int (JSON_ATOI (res["cpu_iowait"]));
      os_data[2] = int (JSON_ATOI (res["cpu_kernel"]));
      os_data[3] = int (JSON_ATOI (res["cpu_user"]));
#endif
      os_data[4] = int (JSON_ATOL (res["mem_phy_free"]) * 100 / MB_SIZE);
      os_data[5] = int (JSON_ATOL (res["mem_swap_free"]) * 100 / MB_SIZE);
    }
  else
    {
      LOG_WARN ("get host statu failed, time=[%d], error code[%d], error message [%s]",
                gather_time, res["retval"].asInt(), errmsg.c_str());
      return;
    }
  res.clear();
  if (false != call_task_ext (req, res, ext_get_sys_diskinfo))
    {
      int total_free = 0;
      for (unsigned int i = 0; i < res["disk_info"].size(); i++)
        {
          total_free += int (JSON_ATOL (res["disk_info"][i]["free_size"]) * 100 / MB_SIZE);
        }
      os_data[6] = total_free;
    }
  else
    {
      LOG_WARN ("get system disk info failed, time=[%d], error message [%s]",
                gather_time, res["note"].asString().c_str());
      return;
    }
  os_data[7] = 0;
  os_data[8] = 0;
  os_data[9] = int (gather_time);
  update_rrdfile (_data_path + OS_MON, daily_idx, os_data, OS_METRICS_LEN, OS_METRICS_LEN);
}

bool cm_mon_stat::init_meta (int interval)
{
  _meta[K_INTERVAL] = interval;
  _meta[K_TOTAL_VOL_NUM] = 0;

  // init broker
  Json::Value req, brokers_info;
  string errmsg;
  if (false == call_task (req, brokers_info, ts2_get_unicas_info, errmsg))
    {
      LOG_ERROR ("failed to get brokers infomation, error code[%d], error message [%s]",
                 brokers_info["retval"].asInt(), errmsg.c_str());
      throw exception();
    }
  for (int i = 0; i < BROKER_METRICS_LEN; i++)
    {
      _meta[K_BROKER_METRICS][BROKER_METRICS[i].metric] = i;
    }
  if (brokers_info.isMember ("brokersinfo"))
    {
      _meta[K_BROKER_NUM] = brokers_info["brokersinfo"][0u]["broker"].size();
      for (int i = 0; i < _meta[K_BROKER_NUM].asInt(); i++)
        {
          string bname = brokers_info["brokersinfo"][0u]["broker"][i]["name"].asString();
          _meta[K_BROKER_RRD][bname + "_idx"] = i;

        }
      int rrdsize = MON_DATA_BLOCK * _meta[K_BROKER_NUM].asInt();
      init_rrdfile (_data_path + BROKER_MON, rrdsize, BROKER_METRICS_LEN);
    }
  else
    {
      throw exception();
    }

  // init db
  Json::Value dbs_info;
  if (false == call_task (req, dbs_info, ts_startinfo, errmsg))
    {
      LOG_ERROR ("failed to get DBs infomation, error code[%d], error message [%s]",
                 dbs_info["retval"].asInt(), errmsg.c_str());
      throw exception();
    }

  for (int i = 0; i < DB_METRICS_LEN; i++)
    {
      _meta[K_DB_METRICS][DB_METRICS[i].metric] = i;
    }
  if (dbs_info.isMember ("dblist"))
    {
      Json::Value &dbs = dbs_info["dblist"][0u]["dbs"];
      _meta[K_DB_NUM] = dbs.size();
      for (int i = 0; i < _meta[K_DB_NUM].asInt(); i++)
        {
          string dbname = dbs[i]["dbname"].asString();
          _meta[K_DB_RRD][dbname + "_idx"] = i;
        }
      int rrdsize = MON_DATA_BLOCK * _meta[K_DB_NUM].asInt();
      init_rrdfile (_data_path + DB_MON, rrdsize, DB_METRICS_LEN);
    }
  else
    {
      _meta[K_DB_NUM] = 0;
      init_rrdfile (_data_path + VOL_MON, 0, 0);
      init_rrdfile (_data_path + DB_MON, 0, 0);
      LOG_WARN ("no dblist for DBs info");
    }

  // init OS
  for (int i = 0; i < OS_METRICS_LEN; i++)
    {
      _meta[K_OS_METRICS][OS_METRICS[i].metric] = i;
    }
  _meta[K_OS_RRD]["os_idx"] = 0;
  init_rrdfile (_data_path + OS_MON, MON_DATA_BLOCK, OS_METRICS_LEN);

  return flush_meta_file();
}

bool cm_mon_stat::reset_meta (int new_interval)
{
  scope_lock slocker (_data_mutex);

  // reset broker
  if (false == reset_mon_file (_data_path + BROKER_MON, _meta[K_BROKER_NUM].asInt(), BROKER_METRICS_LEN, new_interval))
    {
      LOG_ERROR ("reset broker monitoring file failed");
      return false;
    }
  // reset DBs
  if (false == reset_mon_file (_data_path + DB_MON, _meta[K_DB_NUM].asInt(), DB_METRICS_LEN, new_interval))
    {
      LOG_ERROR ("reset DB monitoring file failed");
      return false;
    }
  // reset volume
  if (false == reset_mon_file (_data_path + VOL_MON, _meta[K_TOTAL_VOL_NUM].asInt(), VOL_METRICS_LEN, new_interval))
    {
      LOG_ERROR ("reset volume monitoring file failed");
      return false;
    }
  // reset os
  if (false == reset_mon_file (_data_path + OS_MON, 1, OS_METRICS_LEN, new_interval))
    {
      LOG_ERROR ("reset os monitoring file failed");
      return false;
    }
  _meta[K_INTERVAL] = new_interval;
  return flush_meta_file();
}

bool cm_mon_stat::reset_mon_file (string fpath, int block_num, int mlen, int new_interval)
{
  int ori_bufsize = MON_DATA_BLOCK * block_num * mlen;
  int *ori_buf = new (int[ori_bufsize]);
  if (false == get_rrdfile (fpath, 0, ori_buf, ori_bufsize, mlen))
    {
      LOG_ERROR ("get_rrdfile failed, file name[%s]", fpath.c_str());
      delete [] ori_buf;
      return false;
    }

  int old_daily_data_block = (24 * 60 * 60) / _meta[K_INTERVAL].asInt();
  int new_mon_data_block = (24 * 60 * 60) / new_interval + 30 * 24 + 365;
  int new_rrdsize = new_mon_data_block * block_num;
  if (false == init_rrdfile (fpath, new_rrdsize, mlen))
    {
      LOG_ERROR ("init_rrdfile failed, file name[%s]", fpath.c_str());
      delete [] ori_buf;
      return false;
    }

  for (int i = 0; i < block_num; i++)
    {
      int *ptr = ori_buf + i * MON_DATA_BLOCK + old_daily_data_block;
      int rrdpos = i * new_mon_data_block + (24 * 60 * 60) / new_interval;
      if (false == update_rrdfile (fpath, rrdpos, ptr, (30 * 24 + 365) * mlen, mlen))
        {
          LOG_ERROR ("update_rrdfile failed, file name[%s], block number[%d]", fpath.c_str(), i);
          delete [] ori_buf;
          return false;
        }
    }
  delete [] ori_buf;
  return true;
}

bool cm_mon_stat::flush_meta_file (void)
{
  Json::StyledWriter writer;
  ofstream ofs (_meta_file.c_str());
  if (!ofs.bad())
    {
      ofs << writer.write (_meta) << endl;
      ofs.close();
      return true;
    }

  return false;
}

bool cm_mon_stat::load_meta_file (void)
{
  Json::Reader reader;
  ifstream ifs (_meta_file.c_str());
  if (!ifs.bad())
    {
      bool rtn = reader.parse (ifs, _meta);
      if (false == rtn)
        {
          LOG_ERROR ("failed to load monitoring meta file [%s]", _meta_file.c_str());
        }
      ifs.close();
      return rtn;
    }
  else
    {
      LOG_ERROR ("failed to load monitoring meta file [%s]", _meta_file.c_str());
      return false;
    }
}

int json_to_nv (Json::Value &root, const char *name, nvplist *nv);
int nv_to_json (nvplist *ref, char *value, int &index, Json::Value &root);

static bool init_rrdfile (string filename, int rrdsize, int metrics_len)
{
  int bufsize = rrdsize * metrics_len;
  int *buf = new (int[bufsize]);
  memset ((void *)buf, INIT_METRIC_VALUE, bufsize * sizeof (int));
  ofstream ofs (filename.c_str(), ios_base::out | ios_base::binary | ios_base::trunc);
  if (ofs.fail())
    {
      LOG_ERROR ("failed to open monitoring data file [%s]", filename.c_str());
      delete [] buf;
      throw exception();
    }
  ofs.write ((char *)buf, bufsize * sizeof (int));
  ofs.close();
  delete [] buf;
  return true;
}

static bool update_rrdfile (string filename, int rrdpos, int *buf, int bufsize, int mlen)
{
  fstream fs (filename.c_str(), ios_base::in | ios_base::out | ios_base::binary);
  if (fs.fail())
    {
      LOG_ERROR ("failed to open monitoring data file [%s]", filename.c_str());
      return false;
    }
  fs.seekp (rrdpos * sizeof (int) * mlen);
  fs.write ((char *) buf, bufsize * sizeof (int));
  fs.close();
  return true;
}

static bool get_rrdfile (string filename, int rrdpos, int *buf, int bufsize, int metrics_len)
{
  fstream fs (filename.c_str(), ios_base::in | ios_base::binary);
  if (fs.fail())
    {
      LOG_ERROR ("failed to open monitoring data file [%s]", filename.c_str());
      return false;
    }
  fs.seekp (rrdpos * sizeof (int) * metrics_len);
  fs.read ((char *) buf, bufsize * sizeof (int));
  if (fs.eof())
    {
      LOG_ERROR ("failed to read monitoring data, rrdpos:[%d], bufsize:[%d], file:[%s]", rrdpos, bufsize, filename.c_str());
      return false;
    }
  fs.close();
  return true;
}

static bool append_rrdfile (string filename, int rrdsize, int metrics_len )
{
  int bufsize = rrdsize * metrics_len;
  int *buf = new (int[bufsize]);
  memset (buf, 0, bufsize * sizeof (int));
  ofstream ofs (filename.c_str(), ios_base::out | ios_base::binary | ios_base::app);
  if (ofs.fail())
    {
      LOG_ERROR ("failed to open monitoring data file [%s]", filename.c_str());
      delete [] buf;
      return false;
    }
  ofs.write ((char *)buf, bufsize * sizeof (int));
  ofs.close();
  delete [] buf;
  return true;
}

static bool get_dbs_list (Json::Value &db_list)
{
  Json::Value req, dbs_info;
  db_list.clear();
  string errmsg;
  if (false == call_task (req, dbs_info, ts_startinfo, errmsg))
    {
      LOG_ERROR ("failed to get DBs infomation, error code[%d], error message [%s]",
                 dbs_info["retval"].asInt(), errmsg.c_str());
      return false;
    }
  if (dbs_info.isMember ("dblist"))
    {
      Json::Value &dbs = dbs_info["dblist"][0u]["dbs"];
      for (unsigned int i = 0; i < dbs.size(); i++)
        {
          db_list.append (dbs[i]["dbname"].asString());
        }
    }
  else
    {
      LOG_ERROR ("no dblist for DBs info");
      return false;
    }
  return true;
}

static bool get_active_dbs_list (Json::Value &db_list)
{
  Json::Value req, dbs_info;
  db_list.clear();
  string errmsg;
  if (false == call_task (req, dbs_info, ts_startinfo, errmsg))
    {
      LOG_ERROR ("failed to get active DBs infomation, error code[%d], error message [%s]",
                 dbs_info["retval"].asInt(), errmsg.c_str());
      return false;
    }
  if (dbs_info.isMember ("activelist"))
    {
      if (0 == dbs_info["activelist"].size()
          || false == dbs_info["activelist"][0u].isMember ("active"))
        {
          return true;
        }
      Json::Value &dbs = dbs_info["activelist"][0u]["active"];

      for (unsigned int i = 0; i < dbs.size(); i++)
        {
          db_list.append (dbs[i]["dbname"].asString());
        }
    }
  else
    {
      LOG_ERROR ("no active dblist for DBs info");
      return false;
    }
  return true;
}

static bool get_brokers_list (Json::Value &brokers_list)
{
  Json::Value req, brokers_info;
  brokers_list.clear();
  string errmsg;
  if (false == call_task (req, brokers_info, ts2_get_unicas_info, errmsg))
    {
      LOG_ERROR ("failed to get brokers infomation, error code[%d], error message [%s]",
                 brokers_info["retval"].asInt(), errmsg.c_str());
      return false;
    }
  if (brokers_info.isMember ("brokersinfo"))
    {
      Json::Value &brokers = brokers_info["brokersinfo"][0u]["broker"];

      for (unsigned int i = 0; i < brokers.size(); i++)
        {
          brokers_list.append (brokers[i]["name"].asString());
        }
    }
  else
    {
      LOG_ERROR ("no key brokersinfo for getbrokerstatus");
      return false;
    }
  return true;
}

static bool call_task (Json::Value &req, Json::Value &res, T_TASK_FUNC func, string &errmsg)
{
  bool ret = false;
  nvplist  *cli_request, *cli_response;
  cli_request = nv_create (5, NULL, "\n", ":", "\n");
  cli_response = nv_create (5, NULL, "\n", ":", "\n");
  try
    {
      int index = 0;
      char dbmt_error[DBMT_ERROR_MSG_SIZE];
      dbmt_error[0] = 0;

      json_to_nv (req, NULL, cli_request);
      int retval = (*func) (cli_request, cli_response, dbmt_error);
      nv_to_json (cli_response, NULL, index, res);
      res["retval"] = retval;
      errmsg = dbmt_error;
      if ((1 == retval) || (ERR_NO_ERROR == retval))
        {
          ret = true;
        }
      else
        {
          //LOG_WARN("Failed with return value %d, error message is [%s]", retval, dbmt_error);
          ret = false;
        }
    }
  catch (exception &)
    {
      ret = false;
    }
  nv_destroy (cli_request);
  nv_destroy (cli_response);
  return ret;
}

static bool call_task_ext (Json::Value &req, Json::Value &res, T_EXT_TASK_FUNC func)
{
  try
    {
      (*func) (req, res);
      if (STATUS_SUCCESS != res["status"].asString())
        {
          return false;
        }
      return true;
    }
  catch (exception &e)
    {
      res["status"] = STATUS_FAILURE;
      res["note"] = e.what ();
      return false;
    }
}
