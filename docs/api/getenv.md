# getenv

Get the CUBRID Database environment variables.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |


## Request Sample

```
{
 "task":"getenv",
 "token":"4504b930fc1be99bf5dfd31fc5799faaa3f117fb903f397de087cd3544165d857926f07dd201b6aa"
 }
```

## Response Sample

```
{
   "BROKERVER" : "VERSION 11.5.0.2139",
   "CUBRID" : "/home/kshan/db/CUBRID",
   "CUBRIDVER" : "CUBRID 11.5.0 (11.5.0.2139-7150075) (64bit release build for Linux) (May  7 2026 23:18:11)",
   "CUBRID_DATABASES" : "/home/kshan/db/CUBRID/databases",
   "CUBRID_DBMT" : "/home/CUBRID",
   "HOSTMONTAB0" : "OFF",
   "HOSTMONTAB1" : "OFF",
   "HOSTMONTAB2" : "OFF",
   "HOSTMONTAB3" : "OFF",
   "__EXEC_TIME" : "16 ms",
   "note" : "none",
   "osinfo" : "LINUX",
   "status" : "success",
   "task" : "getenv"
}
```
