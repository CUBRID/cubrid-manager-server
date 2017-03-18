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

/**
* @brief cm_mon_stat.h include the definition of cm_mon_stat class.
*/

#ifndef _CM_MON_STAT_H_
#define _CM_MON_STAT_H_

#ifndef PATH_MAX
#define PATH_MAX                1024
#endif

#include <stdio.h>
#include <time.h>
#include <string.h>

#include "json/json.h"
#include "cm_porting.h"

using namespace std;

enum AGG_TYPE
{
  HOUR, DAY
};

enum MDTYPE
{
  DAILY = 0,
  WEEKLY,
  MONTHLY,
  YEARLY
};

// TODO: need a switch for monitoring data collection

class cm_mon_stat
{
  public:
    static cm_mon_stat *get_instance (void);
    bool initial (void);
    void gather_mon_data (void);
    bool set_mon_interval (time_t interval);
    bool get_mon_interval (time_t &interval) const;
    bool get_mon_statistic (const Json::Value req, Json::Value &res,
                            string &errmsg) const;

  protected:
    cm_mon_stat (string data_path);
    virtual ~ cm_mon_stat (void)
    {
      MUTEX_DESTROY (_data_mutex);
      delete _instance;
      _instance = NULL;
    }

  private:
    bool init_meta (int interval);
    bool reset_meta (int new_interval);
    bool flush_meta_file ();
    bool load_meta_file ();
    void aggregate_2_hour (time_t gather_time);
    void aggregate_2_day (time_t gather_time);
    void aggregate_os (int read_offset, int buf_base, int write_offset,
                       AGG_TYPE atype, time_t gather_time);
    void aggregate_dbs (int read_offset, int buf_base, int write_offset,
                        AGG_TYPE atype, time_t gather_time);
    void aggregate_brokers (int read_offset, int buf_base, int write_offset,
                            AGG_TYPE atype, time_t gather_time);
    void gather_daily_brokers_mon (time_t gather_time);
    bool gather_dbs_tran_query (time_t gather_time, Json::Value &db_tq);
    void gather_daily_dbs_mon (time_t gather_time);
    void gather_daily_os_mon (time_t gather_time);
    bool reset_mon_file (string fpath, int block_num, int mlen,
                         int new_interval);
    bool get_rrd_data (MDTYPE mdtype, string dpath, int didx, int midx,
                       int pfactor, bool ddiff, int mlen, Json::Value &res, string &errmsg) const;
    bool m_get_mon_statistic (const Json::Value req, Json::Value &res, string &errmsg) const;

  private:
    static cm_mon_stat *_instance;
    const string _data_path;
    const string _meta_file;
    Json::Value _meta;

    int _daily_idx;
    int _monthly_idx;
    int _yearly_idx;
    time_t _prev_gather;
    Json::Value _brokers;
    Json::Value _dbs;
    MUTEX_T _data_mutex;
    bool _init;
};

#endif /* _CM_MON_STAT_H_ */
