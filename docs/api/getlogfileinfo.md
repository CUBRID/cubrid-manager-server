# getlogfileinfo

Get logfile info.

Permissions required to run this task: none (any logged-in user)

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| broker | target broker name |

## Request Sample

```
{
  "task": "getlogfileinfo",
  "token": "cdfb4c5717170c5edd00cbca92930b73c8960905fd00c5b4e359db6c8c0075367926f07dd201b6aa",
  "broker": "query_editor"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| note | if failed, a brief description will be given here |
| status | execution result, success or failed. |
| task | task name |
| broker | target broker name |
| from | |
| logfileinfo | list of log file groups |

### logfile group

| **Key** | **Description** |
| --- | --- |
| logfile | list of log file information |

### logfile information

| **Key** | **Description** |
| --- | --- |
| lastupdate | date of last update |
| owner | owner of the log file |
| path | stored path of log file |
| size | size of log file |
| type | type of the log file |



## Response Sample

```

{
   "__EXEC_TIME" : "1 ms",
   "broker" : "query_editor",
   "from" : "",
   "logfileinfo" : [
      {
         "logfile" : [
            {
               "lastupdate" : "2025.06.09",
               "owner" : "cubrid",
               "path" : "/home/cubrid/CUBRID-11.4.0.1781-6b2bc75-Linux.x86_64/log/broker/error_log/query_editor_1.err",
               "size" : "9834",
               "type" : "error"
            },
            {
               "lastupdate" : "2025.06.09",
               "owner" : "cubrid",
               "path" : "/home/cubrid/CUBRID-11.4.0.1781-6b2bc75-Linux.x86_64/log/broker/sql_log/query_editor_5.slow.log",
               "size" : "0",
               "type" : "script"
            },
            {
               "lastupdate" : "2025.06.09",
               "owner" : "cubrid",
               "path" : "/home/cubrid/CUBRID-11.4.0.1781-6b2bc75-Linux.x86_64/log/broker/sql_log/query_editor_1.sql.log",
               "size" : "9711",
               "type" : "script"
            }
         ]
      }
   ],
   "note" : "none",
   "status" : "success",
   "task" : "getlogfileinfo"
}

```
