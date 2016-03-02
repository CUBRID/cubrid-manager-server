#!/usr/bin/env python
# -*- coding: utf-8 -*-

import struct
import json
import time
import sys


metric = "vol_freespace"
dtype = "monthly" 
bname = "query_editor"
dbname = "demodb"
volname = "demodb"

# globe
dpath = "/home/liuhj/CUBRID/var/manager/mon_data/"


def dump_mod_data(filename, pos, size):
    data = []
    fp = open(filename, "rb")
    fp.seek(pos, 0)
    for i in range(size):
        a, = struct.unpack("i", fp.read(4))
        data.append(a)
    return data

def dump_daily(mon_file, meta, m_len, m_idx, blk_idx):
    pos = blk_idx * (3600*24/meta["k_interval"] + 24*30 + 365) * m_len * 4 
    daily_data = dump_mod_data(mon_file, pos, 3600 * 24 / meta["k_interval"] * m_len)

    sec = int(time.time())
    
    read_idx = (sec % (3600 * 24))/meta["k_interval"] 
    
    for i in range(read_idx): 
        #print daily_data[i*m_len + m_idx],
        #print "read_idx:" + str(i),
        for j in range(m_len):
            print daily_data[i*m_len + j],
        print "\n",
    
    # daily diff    
    #prev = daily_data[m_idx]
    #for i in range(1, read_idx):
    #    now = daily_data[i*m_len + m_idx]
    #    print (now - prev)/meta["k_interval"],
    #    if now < prev:
    #        print i, now, prev
    #        raw_input()
    #    prev = now

def dump_monthly(mon_file, meta, m_len, m_idx, blk_idx):
    pos = (blk_idx * (3600*24/meta["k_interval"] + 24*30 + 365) + 3600*24/meta["k_interval"]) * m_len * 4 
    dump_data = dump_mod_data(mon_file, pos, 30*24*m_len)
    sec = int(time.time())
    read_idx = (sec % (30 *3600 * 24))/3600
    #for i in range(read_idx): 
    for i in range(30 * 24): 
        for j in range(m_len):
            print dump_data[i*m_len + j],
        print "\n",
        #print dump_data[i*m_len + m_idx],
        #print i, dump_data[i*m_len + m_idx]
    
def dump_yearly(mon_file, meta, m_len, m_idx, blk_idx):
    pos = (blk_idx * (3600*24/meta["k_interval"] + 24*30 + 365) + 3600*24/meta["k_interval"] + 30 * 24) * m_len * 4 
    dump_data = dump_mod_data(mon_file, pos, 365*m_len)
    sec = int(time.time())
    read_idx = (sec % (365 * 3600 * 24))/(3600 * 24)
    for i in range(read_idx): 
        print i, dump_data[i*m_len + m_idx]
    

if __name__ == '__main__':
    meta = json.load(open(dpath + "meta.json", "r"))
    if "os_" == metric[0:3]:
        mon_file = dpath + "os_mon"
        blk_idx = 0
        m_idx = meta["k_os_metrics"][metric] 
        m_len = len(meta["k_os_metrics"])
    elif "broker_" == metric[0:7]:
        mon_file = dpath + "broker_mon"
        blk_idx = meta["k_broker_rrd"][bname + "_idx"]
        m_idx = meta["k_broker_metrics"][metric] 
        m_len = len(meta["k_broker_metrics"])
    elif "db_" == metric[0:3]:
        mon_file = dpath + "db_mon"
        blk_idx = meta["k_db_rrd"][dbname + "_idx"]
        m_idx = meta["k_db_metrics"][metric] 
        m_len = len(meta["k_db_metrics"])
    elif "vol_" == metric[0:4]:
        mon_file = dpath + "vol_mon"
        blk_idx = meta["k_db_rrd"][dbname + "_vol"][volname]
        m_idx = 0
        m_len = 2
    else:
        print "metric is needed"
        sys.exit(1)
     
    if dtype == "daily":
        dump_daily(mon_file, meta, m_len, m_idx, blk_idx)
        
    elif dtype == "monthly":
        dump_monthly(mon_file, meta, m_len, m_idx, blk_idx)
    elif dtype == "yearly":
        dump_yearly(mon_file, meta, m_len, m_idx, blk_idx)
    else:
        print "dtype is needed"
        sys.exit(1)

    
