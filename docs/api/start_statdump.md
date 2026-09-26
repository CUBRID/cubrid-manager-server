# start_statdump

Activate *background* statdump process to accumulate values per seconds, to stop it use [stop_statdump](stop_statdump.md)

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name to activate statdump|
| dbuser | database username |
| dbpasswd | password of dbuser |
| interval | interval as seconds for dumping statistics periodically |
| async | default "no", if "yes" run the task in asynchronous mode |

* The status of a task running in asynchronous mode can be checked using the 'gettaskstatus' api

## Request Sample

```json
{
  "task":"start_statdump",
  "token": "cdfb4c5717170c5e9c6856b4d1c61ee8132bcc7d82bd609066ed9ece2554c47f7926f07dd201b6aa",
  "dbname": "demodb",
  "dbuser":"dba",
  "dbpasswd":"",
  "interval":"5",
  "async":"yes"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed |
| pid | process id of statdump if succeed |
| note | if failed, a brief description will be given here |

## Response Sample

```
{
  "__EXEC_TIME" : "0 ms",
  "note" : "demodb",
  "pid" : "24989",
  "status" : "success",
  "task" : "start_statdump"
}
```

## Response Sample (async mode)
```
{
   "job-status" : "running",
   "note" : "none",
   "status" : "success",
   "task" : "start_statdump",
   "uuid" : "14"
}
```
