# getautoexecqueryerrlog

Get auto execution query error logs.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| start_time | the beginning of the period, in the `YYYY-MM-DD HH:MM:SS` form |
| end_time | the end of the period, in the `YYYY-MM-DD HH:MM:SS` form |

## Request Sample

```
{
  "task": "getautoexecqueryerrlog",
  "token": "4504b930fc1be99bf5dfd31fc5799faaa3f117fb903f397de087cd3544165d857926f07dd201b6aa"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |
| error | the list of the auto-execute query errors of the requested period |

### error

error is composed of objects with following structure

| **Key** | **Description** |
| --- | --- |
| dbname | database name |
| username | the database user which executed the query |
| query_id | the id of the auto-execute query plan which failed |
| error_time | the time the error occurred |
| error_code | the error code returned by the database |
| error_desc | the description of the error |

## Response Sample

```
{
   "__EXEC_TIME" : "1 ms",
   "error" : [
      {
         "@username" : "admin",
         "dbname" : "alatestdb",
         "error_code" : "0",
         "error_desc" : "start",
         "error_time" : "2026/08/14 14:18:03",
         "query_id" : "bbaa"
      },
      {
         "@username" : "admin",
         "dbname" : "alatestdb",
         "error_code" : "0",
         "error_desc" : "success",
         "error_time" : "2026/08/14 14:18:04",
         "query_id" : "bbaa"
      },
      {
         "@username" : "admin",
         "dbname" : "alatestdb",
         "error_code" : "0",
         "error_desc" : "start",
         "error_time" : "2026/08/14 14:22:03",
         "query_id" : "bbaa"
      }
   ],
   "note" : "none",
   "status" : "success",
   "task" : "getautoexecqueryerrlog"
}
```

> Lists are shortened to 3 entries here; the real response returned up to 34.
