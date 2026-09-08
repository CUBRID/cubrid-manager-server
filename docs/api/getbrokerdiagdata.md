# getbrokerdiagdata

Get broker status.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| bname | broker name, it can be given several times |

## Request Sample

```
{
  "task": "getbrokerdiagdata",
  "token": "4504b930fc1be99bf5dfd31fc5799faaa3f117fb903f397de087cd3544165d857926f07dd201b6aa"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |
| cas_mon | the list of the requested brokers and of their monitoring data |
| time | the moment the data was collected, `YYYY/MM/DD HH:MM:SS` |

### cas_mon

cas_mon is composed of objects with following structure

| **Key** | **Description** |
| --- | --- |
| bname | broker name |
| cas_mon_req | the number of the requests handled by the broker |
| cas_mon_query | the number of the queries executed by the broker |
| cas_mon_tran | the number of the transactions of the broker |
| cas_mon_long_query | the number of the long queries of the broker |
| cas_mon_long_tran | the number of the long transactions of the broker |
| cas_mon_error_query | the number of the queries which ended with an error |
| cas_mon_session | the number of the sessions of the broker |
| cas_mon_act_session | the number of the active sessions of the broker |
| cas_mon_active | the number of the active application servers of the broker |

## Response Sample

```
{
   "__EXEC_TIME" : "2 ms",
   "cas_mon" : [
      {
         "cas_mon_act_session" : "0",
         "cas_mon_active" : "0",
         "cas_mon_error_query" : "0",
         "cas_mon_long_query" : "0",
         "cas_mon_long_tran" : "0",
         "cas_mon_query" : "0",
         "cas_mon_req" : "0",
         "cas_mon_session" : "0",
         "cas_mon_tran" : "0"
      }
   ],
   "note" : "none",
   "status" : "success",
   "task" : "getbrokerdiagdata",
   "time" : "2026/08/18 09:08:47"
}
```
