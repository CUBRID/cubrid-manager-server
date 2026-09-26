# renamedb

Rename database.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name |
| rename | new database name |
| exvolpath | extend volume path |
| advanced | on-off indicating whether to offer local control files |
| forcedel | on-off indicating whether to remove backup files |
| async | default "no", if "yes" run the task in asynchronous mode |

* The status of a task running in asynchronous mode can be checked using the 'gettaskstatus' api
* Only one of these database tasks — addvoldb, backupdb, checkdb, compactdb, copydb, createdb, deletedb, loaddb, optimizedb, renamedb, restoredb, startdb, stopdb, unloaddb — can run against the same `dbname`/`rename` at a time, whether or not `async` is used; a request is rejected immediately if another one of them is already running on that database

## Request Sample

```
{
  "task":"renamedb",
  "token":"cdfb4c5717170c5edfc2912f2940ab35013dd1336cf7d77e4cfaae281cffa1417926f07dd201b6aa",
  "dbname":"destinationdb",
  "rename":"anotherdb",
  "exvolpath":"none",
  "advanced":"on",
  "volume":{"$CUBRID_DATABASES/destinationdb/destinationdb":"$CUBRID_DATABASES/anotherdb/anotherdb"},
  "forcedel":"y",
  "async":"yes"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here; on a successful rename, may instead carry a warning that a manual check is recommended (see below) |

* Renaming the database itself is what `status` reflects. Afterward, CMS also does best-effort bookkeeping: updating the database's entries in its own user-authorization file (`cmdb.pass`) and in the auto-job config files (addvoldb/backupdb/history/execquery) to the new name. If any of that bookkeeping fails - a lock timeout, a file I/O error, or an internal update error - the rename is **not** rolled back; `status` still reports `"success"`, and `note` instead names exactly which of those file(s) could not be updated and should be checked and cleaned up manually. This applies whether the task is run synchronously or with `async:"yes"`.

## Response Sample

```
{
  "__EXEC_TIME": "353 ms",
  "note": "none",
  "status": "success",
  "task": "renamedb"
}
```

## Response Sample (success, manual check recommended)
```
{
  "__EXEC_TIME": "360 ms",
  "note": "WARNING: database 'destinationdb' was renamed to 'anotherdb', but the following bookkeeping file(s) could not be updated (lock timeout, file I/O error, or an internal update error): the auto-job addvoldb config file, the auto-job execquery config file; stale entries still referencing the old name 'destinationdb' may remain and should be checked and cleaned up manually",
  "status": "success",
  "task": "renamedb"
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
   "task" : "renamedb"
}
```
