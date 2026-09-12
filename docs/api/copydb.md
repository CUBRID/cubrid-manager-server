# copydb

Copy database.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| srcdbname | source database |
| destdbname | destination database |
| exvolpath | extend volume path |
| logpath | log volume path |
| overwrite | on-off indicating whether to replace existing database |
| move | on-off indicating whether to remove existing database |
| advanced | on-off indicating whether to offer local control files |
| async | default "no", if "yes" run the task in asynchronous mode |

* The status of a task running in asynchronous mode can be checked using the 'gettaskstatus' api
* Only one of these database tasks — addvoldb, backupdb, checkdb, compactdb, copydb, createdb, deletedb, loaddb, optimizedb, renamedb, restoredb, startdb, stopdb, unloaddb — can run against the same `dbname` at a time, whether or not `async` is used; a request is rejected immediately if another one of them is already running on that database

## Request Sample

```
{
  "task":"copydb",
  "token":"cdfb4c5717170c5edfc2912f2940ab35013dd1336cf7d77e4cfaae281cffa1417926f07dd201b6aa",
  "srcdbname":"alatestdb",
  "destdbname":"destinationdb",
  "destdbpath":"$CUBRID_DATABASES/destinationdb",
  "exvolpath":"$CUBRID_DATABASES/destinationdb",
  "logpath":"$CUBRID_DATABASES/destinationdb",
  "overwrite":"y",
  "move":"n",
  "advanced":"off",
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
   "task" : "copydb"
}
```

## Response Sample (async mode)
```
{
   "job-status" : "running",
   "note" : "none",
   "status" : "success",
   "uuid" : "14"
}
```

## Response Sample (rejected: database busy)
```
{
   "job-status" : "rejected",
   "note" : "database 'xyz' is busy with another task ('createdb')",
   "status" : "failure",
   "task" : "copydb"
}
```
