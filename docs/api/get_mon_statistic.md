# get_mon_statistic

Get mornitoring statistic data.

## Request Json Syntax

Get DB monitoring statistic data(HA monitoring data is included)

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted |
| metric | the metric of DB. the value should be "db_cpu_kernel", "db_cpu_user", "db_mem_phy", "db_mem_vir", "db_qps", "db_tps", "db_hit_ratio",   "db_fetch_pages", "db_dirty_pages", "db_io_read", "db_io_write", "db_ha_copy_delay_page", "db_ha_copy_delay_estimated",  "db_ha_apply_delay_page", "db_ha_apply_delay_estimated" and "db_freespace" |
| dtype | data type. daily, weekly, monthly or yearly |
| dbname | database name |

Get Broker monitoring statistic data

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted |
| metric | the metric of DB. the value should be "broker_tps", "broker_qps", "broker_long_t", "broker_long_q", "broker_req", "broker_err_q" and "broker_jq" |
| dtype | data type. daily, weekly, monthly or yearly |
| bname | broker name |

Get DB Volume monitoring statistic data

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted |
| metric | the metric of DB. the value should be "vol_freespace" |
| dtype | data type. daily, weekly, monthly or yearly |
| dbname | database name |
| volname | database volume name |

Get os monitoring statistics data

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted |
| metric | the metric of DB. the value should be "os_cpu_idle", "os_cpu_iowait", "os_cpu_user", "os_mem_phy_free", "os_mem_swap_free" and "os_disk_free" |
| dtype | data type. daily, weekly, monthly or yearly |

## Request Sample

Get DB monitoring statistic data(HA monitoring data is included)

```
{
  "task":"get_mon_statistic",
  "token":"4504b930fc1be99bf5dfd31fc5799faaa3f117fb903f397de087cd3544165d857926f07dd201b6aa",
  "metric": "db_hit_radio", 
  "dbname": "db1"
  }
```

Get Broker monitoring statistic data

```
{
  "task": "get_mon_statistic",
  "metric":"broker_long_t",
  "dtype": "monthly", 
  "bname": "broker1",
  "token": "xxxxxxx"
}
```

Get DB Volume monitoring statistic data

```
{
  "task":"get_mon_statistic",
  “metric”:”vol_freespace”,
  “dtype”:”yearly”,
  “dbname”:”db1”,
  “volname”:”testdb”,
   "token":"xxxxxxx"
}
```

Get os monitoring statistics data

```
{
  "task":"get_mon_statistic",
  “metric”:”os_cpu_user”,
  “dtype”:”weekly",
   "token":"xxxxxxx"
}
```

## Response Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |
| dbname | database name |
| bname | database broker name |
| data | an interge array of monitoring data |
| dtype | data type. daily, weekly, monthly or yearly |
| metric | The metric of database, broker, volume or host |

## Response Sample

```
{
  "task":"get_mon_statistic",
  “metric”:”broker_long_t”,
  “dtype”:”monthly”, 
  “bname”:”broker1”,
  “status”: “success”,
  “note”:”none”,
  “data”:11,17,23,42,24,12,15…
}
```
