# getdiagdata

Get monitoring data.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| db_name | database name |
| mon_db | yes or no, collect the monitoring data of the database server |
| mon_cas | yes or no, collect the monitoring data of the broker |
| broker_name | broker name, it is used when `mon_cas` is yes |
| cas_mon_req | yes or no, collect the number of the requests of the broker |
| cas_mon_tran | yes or no, collect the number of the transactions of the broker |
| cas_mon_act_session | yes or no, collect the number of the active sessions of the broker |
| mon_driver | yes or no, collect the monitoring data of the driver |
| mon_resource | yes or no, collect the monitoring data of the resources of the host |
| act_db | yes or no, collect the activity data of the database server |
| act_cas | yes or no, collect the activity data of the broker |
| act_driver | yes or no, collect the activity data of the driver |

## Request Sample

```
{
  "task": "getdiagdata",
  "token": "cdfb4c5717170c5e9c6856b4d1c61ee8132bcc7d82bd609066ed9ece2554c47f7926f07dd201b6aa",
  "db_name": "demodb",
  "mon_db": "yes",
  "mon_cas": "yes",
  "cas_mon_req": "yes",
  "cas_mon_tran": "yes",
  "cas_mon_act_session": "yes",
  "mon_driver": "no",
  "mon_resource": "no",
  "act_db": "no",
  "act_cas": "no",
  "act_driver": "no"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |
| db_mon | the monitoring data of the database server, it is returned when `mon_db` is yes |
| cas_mon | the monitoring data of the broker, it is returned when `mon_cas` is yes |

### db_mon

| **Key** | **Description** |
| --- | --- |
| mon_cub_query_open_page | the number of the pages opened by the queries |
| mon_cub_query_opened_page | the number of the pages which have been opened |
| mon_cub_query_slow_query | the number of the slow queries |
| mon_cub_query_full_scan | the number of the full scans |
| mon_cub_lock_deadlock | the number of the deadlocks |
| mon_cub_lock_request | the number of the lock requests |
| mon_cub_conn_cli_request | the number of the client requests |
| mon_cub_conn_aborted_clients | the number of the aborted clients |
| mon_cub_conn_conn_req | the number of the connection requests |
| mon_cub_conn_conn_reject | the number of the rejected connections |
| mon_cub_buffer_page_write | the number of the pages written to the buffer |
| mon_cub_buffer_page_read | the number of the pages read from the buffer |

### cas_mon

| **Key** | **Description** |
| --- | --- |
| cas_mon_req | the number of the requests handled by the broker |
| cas_mon_query | the number of the queries executed by the broker |
| cas_mon_tran | the number of the transactions of the broker |
| cas_mon_long_query | the number of the long queries of the broker |
| cas_mon_long_tran | the number of the long transactions of the broker |
| cas_mon_error_query | the number of the queries which ended with an error |
| cas_mon_act_session | the number of the active sessions of the broker |

## Response Sample

```
{
   "__EXEC_TIME" : "1 ms",
   "cas_mon" : [
      {
         "cas_mon_act_session" : "1",
         "cas_mon_error_query" : "0",
         "cas_mon_long_query" : "0",
         "cas_mon_long_tran" : "0",
         "cas_mon_query" : "0",
         "cas_mon_req" : "0",
         "cas_mon_tran" : "0"
      }
   ],
   "note" : "none",
   "status" : "success",
   "task" : "getdiagdata"
}
```
