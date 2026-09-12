# stop_statdump

Related with [start_statdump](start_statdump.md), deactivate the previously started *statdump* process

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name to stop statdump process running on the dbname |
| dbuser | database username |
| dbpasswd | password of dbuser |
| async | default "no", if "yes" run the task in asynchronous mode |

* The status of a task running in asynchronous mode can be checked using the 'gettaskstatus' api

## Request Sample

```
{
  "task":"stop_statdump",
  "token": "cdfb4c5717170c5e9c6856b4d1c61ee8132bcc7d82bd609066ed9ece2554c47f7926f07dd201b6aa",
  "dbname": "demodb",
  "dbuser":"dba",
  "dbpasswd":"",
  "async":"yes"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed |
| note | if failed, a brief description will be given here |

## Response Sample

```
{
  "__EXEC_TIME" : "56 ms",
  "note" : "demodb",
  "status" : "success",
  "task" : "stop_statdump"
}
```

## Response Sample (async mode)
```
{
   "job-status" : "running",
   "note" : "none",
   "status" : "success",
   "task" : "stop_statdump",
   "uuid" : "14"
}
```
