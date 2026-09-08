# getbrokersinfo

Get information of brokers.

## Request JSON syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |

## Request Sample

```
    {
        "task":"getbrokersinfo",        "token":"300ea42877b8fd414644196bb44e7a8bea3164a1a5a348c5381b47766536a56664ec74a35eeb28dd7926f07dd201b6aa7926f07dd201b6aa7926f07dd201b6aa7926f07dd201b6aa7926f07dd201b6aa7926f07dd201b6aa7926f07dd201b6aa7926f07dd201b6aa7926f07dd201b6aa7926f07dd201b6aa7926f07dd201b6aa"
    }
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| brokersinfo | list of broker info |
| brokerstatus | status of broker service. |
| note | if failed, a brief description will be given here |
| status | execution result, success or failed. |
| task | task name |

### Brokers Info

| **Key** | **Description** |
| --- | --- |
| broker | list of brokers |

#### Broker

| **Key** | **Description** |
| --- | --- |
| access_list | |
| appl_server_shm_id | server shared memory id |
| name | name of the broker |
| port | port number |
| source_env | |
| state | state of the broker |
| type | type |

When the broker is running (`brokerstatus` is `ON`), each broker also carries its runtime status:

| **Key** | **Description** |
| --- | --- |
| pid | the process id of the broker |
| as | the number of the application servers (CAS) |
| jq | the number of the jobs waiting in the queue |
| thr | the number of the threads |
| cpu | the cpu usage of the broker |
| time | the cpu time of the broker |
| req | the number of the requests |
| query | the number of the queries |
| tran | the number of the transactions |
| long_query | the number of the long queries |
| long_tran | the number of the long transactions |
| long_query_time | the threshold time of a long query |
| long_tran_time | the threshold time of a long transaction |
| error_query | the number of the queries which ended with an error |
| ses | the number of the sessions |
| access_mode | the access mode of the broker, such as RW, RO or SO |
| sqll | the SQL log mode of the broker |
| keep_conn | the keep-connection setting of the broker |
| auto | the automatic appl-server-add setting of the broker |
| log | the log setting of the broker |

## Response Sample

```
{
   "__EXEC_TIME" : "1 ms",
   "brokersinfo" : [
      {
         "broker" : [
            {
               "access_list" : "0",
               "access_mode" : "RW",
               "appl_server_shm_id" : "30000",
               "as" : "5",
               "auto" : "ON",
               "error_query" : "0",
               "jq" : "0",
               "keep_conn" : "AUTO",
               "log" : "/home/cubrid/CUBRID-11.5.0.2441-6ba9522-Linux.x86_64/log/broker",
               "long_query" : "0",
               "long_query_time" : "60.00",
               "long_tran" : "0",
               "long_tran_time" : "60.00",
               "name" : "query_editor",
               "pid" : "1998369",
               "port" : "30000",
               "query" : "0",
               "req" : "0",
               "ses" : "300",
               "source_env" : "0",
               "sqll" : "ALL",
               "state" : "ON",
               "tran" : "0",
               "type" : "CAS"
            }
         ]
      }
   ],
   "brokerstatus" : "ON",
   "note" : "none",
   "status" : "success",
   "task" : "getbrokersinfo"
}
```

> Lists are shortened to 1 entry here.
