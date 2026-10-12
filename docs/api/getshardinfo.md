# getshardinfo

Get the status of every shard broker by running `cubrid shard status -b -f`.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |

## Request Sample

```
{
  "task": "getshardinfo",
  "token": "cdfb4c5717170c5e9c6856b4d1c61ee8132bcc7d82bd609066ed9ece2554c47f7926f07dd201b6aa"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |
| shard | the list of the shard brokers |

### shard

shard is composed of objects with following structure

| **Key** | **Description** |
| --- | --- |
| name | the name of the shard broker |
| pid | the process id of the shard broker |
| psize | the size of the process, in KB |
| port | the port of the shard broker |
| active-p | the number of the active proxies |
| active-c | the number of the active application servers |
| req | the number of the requests |
| tps | transactions per second |
| qps | queries per second |
| k-qps | queries per second which use the shard key |
| h-key | the number of the hint keys |
| h-id | the number of the hint ids |
| h-all | the number of the hint alls |
| nk-qps | queries per second which do not use the shard key |
| long_tran | the number of the long transactions |
| long_tran_time | the threshold time of a long transaction |
| long_query | the number of the long queries |
| long_query_time | the threshold time of a long query |
| error_query | the number of the queries which ended with an error |
| access_mode | the access mode of the shard broker, such as RW or RO |
| state | the state of the shard broker |
| sqll | the SQL log mode of the shard broker |
| canceled | the number of the canceled requests |

## Response Sample

```
{
   "__EXEC_TIME" : "47 ms",
   "note" : "none",
   "shard" : [
      {
         "active-c" : "0",
         "active-p" : "0",
         "error_query" : "0",
         "h-all" : "0",
         "h-id" : "0",
         "h-key" : "0",
         "k-qps" : "0",
         "long_query" : "0",
         "long_query_time" : "60.0",
         "long_tran" : "0",
         "long_tran_time" : "60.0",
         "name" : "shard1",
         "nk-qps" : "0",
         "pid" : "18234",
         "port" : "40000",
         "psize" : "52204",
         "qps" : "0",
         "req" : "0",
         "tps" : "0"
      }
   ],
   "status" : "success",
   "task" : "getshardinfo"
}
```
