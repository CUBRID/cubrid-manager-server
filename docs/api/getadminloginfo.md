# getadminloginfo

Get admin login logs.

Permissions required to run this task: ADMIN

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token returned by login |


## Request Sample

```
{
  "task": "getadminloginfo",
  "token": "cdfb4c5717170c5e9c6856b4d1c61ee8132bcc7d82bd609066ed9ece2554c47f7926f07dd201b6aa"
}
```


## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| note | if failed, a brief description will be given here |
| status | execution result, success or failed. |
| task | task name |
| adminloginfo | list of admin log information |

### admin log information 

| **Key** | **Description** |
| --- | --- |
| lastupdate | date of last update |
| owner | owner of the log file |
| path | path of the log file |
| size | size of the log file |


## Response Sample

```
{
   "__EXEC_TIME" : "0 ms",
   "adminloginfo" : [
      {
         "lastupdate" : "2025.06.30",
         "owner" : "cubrid",
         "path" : "/home/cubrid/CUBRID-11.4.0.1781-6b2bc75-Linux.x86_64/log/broker/cubrid_broker.log",
         "size" : "1395"
      }
   ],
   "note" : "none",
   "status" : "success",
   "task" : "getadminloginfo"
}
```