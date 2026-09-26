# stopdb

Stop database.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name |
| async | default "no", if "yes" run the task in asynchronous mode |

* The status of a task running in asynchronous mode can be checked using the 'gettaskstatus' api
* Only one of these database tasks — addvoldb, backupdb, checkdb, compactdb, copydb, createdb, deletedb, loaddb, optimizedb, renamedb, restoredb, startdb, stopdb, unloaddb — can run against the same `dbname` at a time, whether or not `async` is used; a request is rejected immediately if another one of them is already running on that database

## Request Sample

```
{
  "task":"stopdb",
  "token":"cdfb4c5717170c5e9c6856b4d1c61ee8132bcc7d82bd609066ed9ece2554c47f7926f07dd201b6aa",
  "dbname":"alatestdb",
  "async":"yes"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |

## Response Sample

```
{
   "__EXEC_TIME" : "33 ms",
   "note" : "none",
   "status" : "success",
   "task" : "stopdb"
}
```

## Response Sample (async mode)
```
{
   "job-status" : "running",
   "note" : "none",
   "status" : "success",
   "task" : "stopdb",
   "uuid" : "14"
}
```

## Response Sample (rejected: database busy)
```
{
   "job-status" : "rejected",
   "note" : "database 'xyz' is busy with another task ('createdb')",
   "status" : "failure",
   "task" : "stopdb"
}
```
