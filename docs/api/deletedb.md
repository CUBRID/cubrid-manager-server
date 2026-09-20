# deletedb

Delete a database.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name |
| delbackup | on-off indicating whether to remove backup files |
| async | default "no", if "yes" run the task in asynchronous mode |

* The status of a task running in asynchronous mode can be checked using the 'gettaskstatus' api
* Only one of these database tasks — addvoldb, backupdb, checkdb, compactdb, copydb, createdb, deletedb, loaddb, optimizedb, renamedb, restoredb, startdb, stopdb, unloaddb — can run against the same `dbname` at a time, whether or not `async` is used; a request is rejected immediately if another one of them is already running on that database

## Request Sample

```
{
  "task":"deletedb",
  "token":"cdfb4c5717170c5e237a227a2ceeccc6ae9e10c16754fb85371c0d74fa0d9d577926f07dd201b6aa",
  "dbname":"alatestdb",
  "delbackup":"y",
  "async":"yes"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here; on a successful delete, may instead carry a warning that a manual check is recommended (see below) |

* Deleting the database itself is what `status` reflects. Afterward, CMS also does best-effort bookkeeping: removing the database's entries from its own user-authorization file (`cmdb.pass`) and from the auto-job config files (addvoldb/backupdb/history/execquery). If any of that bookkeeping fails - normally because a short internal lock could not be acquired in time - the database is **not** restored; `status` still reports `"success"`, and `note` instead explains that one or more of those files may still reference the deleted database and should be checked and cleaned up manually. This applies whether the task is run synchronously or with `async:"yes"` (see the async response samples below).

## Response Sample

```
{
   "__EXEC_TIME" : "393 ms",
   "note" : "none",
   "status" : "success",
   "task" : "deletedb"
}
```

## Response Sample (success, manual check recommended)
```
{
   "__EXEC_TIME" : "401 ms",
   "note" : "WARNING: database 'alatestdb' was deleted, but one or more bookkeeping files (cmdb.pass and/or the auto-job addvoldb/backupdb/history/execquery config files) could not be updated because a lock could not be acquired; manual check recommended",
   "status" : "success",
   "task" : "deletedb"
}
```

## Response Sample (async mode)
```
{
   "job-status" : "running",
   "note" : "none",
   "status" : "success",
   "task" : "deletedb",
   "uuid" : "14"
}
```

## Response Sample (rejected: database busy)
```
{
   "job-status" : "rejected",
   "note" : "database 'xyz' is busy with another task ('createdb')",
   "status" : "failure",
   "task" : "deletedb"
}
```
