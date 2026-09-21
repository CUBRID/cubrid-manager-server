# gettaskstatus

Check the status of a task asynchronously running

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| uuid | uuid from the asynchronous task response |

* an uuid is dropped 3,600 seconds after the job is finished by default,<br>
 it can be changed in cm.conf, for example "async_job_ttl_sec=7200"

## Request Sample

```
{
  "task": "gettaskstatus",
  "token": "cdfb4c5717170c5e237a227a2ceeccc6ae9e10c16754fb85371c0d74fa0d9d577926f07dd201b6aa",
  "uuid":"$UUID"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| job-status | one of running, success, error, rejected |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here; for a handful of tasks (see below), may instead be non-"none" on a *successful* job to flag that a manual check is recommended |
| uuid | uuid given in the request |
| task | name of the original async task (e.g. createdb); absent while the job is still running |

* `rejected` is returned directly in the response to the original task request, when CMS could not start the async job at all - for example because the concurrent async job limit (`max_num_async_task`) was reached, or another async job was already running against the same database. See [Request Rejected](async_readme.md#request-rejected) for details. A rejected request never receives a `uuid`, so `job-status` is never `rejected` in an actual `gettaskstatus` response - it is listed here only for a complete reference of the possible `job-status` values.
* `job-status` is derived entirely from `status`: it is `"success"` whenever `status` is `"success"`, regardless of what `note` says. For [deletedb](deletedb.md), [renamedb](renamedb.md), [copydb](copydb.md) and [updateuser](updateuser.md), a non-"none" `note` on an otherwise successful job means the requested database operation completed, but some secondary bookkeeping (an internal cache/config file) could not be updated and should be checked manually - see each task's own page for what that means for it. It is not a partial success at the database-operation level, and `job-status`/`status` do not distinguish it from an unremarkable success; only `note` does.


## Response Sample if task is running

```
{
   "job-status" : "running",
   "note" : "none",
   "status" : "success",
   "uuid" : "14"
}
```

## Response Sample if task is completed successfully
```
{
   "__EXEC_TIME" : "66860 ms",
   "job-status" : "success",
   "note" : "none",
   "status" : "success",
   "task" : "createdb",
   "uuid" : "14"
}
```

## Response Sample if task is completed successfully but a manual check is recommended

See the note above the samples: this is still `job-status:"success"`/`status:"success"` - the database operation completed - but `note` is non-"none" because a secondary bookkeeping file could not be updated. Currently only [deletedb](deletedb.md), [renamedb](renamedb.md) and [copydb](copydb.md) can produce this in async mode.

```
{
   "__EXEC_TIME" : "401 ms",
   "job-status" : "success",
   "note" : "WARNING: database 'alatestdb' was deleted, but the following bookkeeping file(s) could not be updated (lock timeout, file I/O error, or an internal update error): cmdb.pass, the auto-job backupdb config file; manual check recommended",
   "status" : "success",
   "task" : "deletedb",
   "uuid" : "14"
}
```

## Response Sample if task is completed with error
```
{
   "__EXEC_TIME" : "26 ms",
   "job-status" : "error",
   "note" : "Couldn't create database.<end>Database \"testdb\" already exists.<end>",
   "status" : "failure",
   "task" : "createdb",
   "uuid" : "14"
}
```

## Response Sample if the original request was rejected

This is not a `gettaskstatus` response - it is the response CMS gives directly to the original `"async":"yes"` request when it rejects the job. It is shown here only because `job-status` can be `rejected`; see [Request Rejected](async_readme.md#request-rejected).

```
{
   "job-status" : "rejected",
   "note" : "maximum number of concurrent async tasks (8) reached; try again later",
   "status" : "failure",
   "task" : "compactdb"
}
```

## Response Sample with invalid uuid
```
{
   "note" : "invalid uuid",
   "status" : "failure"
}
```

## See Also

* [Asynchronous Task Execution](async_readme.md)
* [getserverstatus](getserverstatus.md)
