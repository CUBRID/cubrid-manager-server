# Asynchronous Task Execution

Run a supported task in the background instead of waiting for it to finish.

## Overview

Clients can ask CMS to execute certain long-running tasks asynchronously by sending `"async":"yes"` in the request. Instead of blocking until the task finishes, CMS immediately returns a response containing a unique job identifier (`uuid`). The client then polls the [gettaskstatus](gettaskstatus.md) task with that `uuid` to check whether the job is still running and, once finished, whether it succeeded or failed.

If `async` is not specified in the request, it defaults to `"async":"no"` and the task runs synchronously, as usual.

## Async-Capable Tasks

25 tasks currently support `async`:

[addvoldb](addvoldb.md), [backupdb](backupdb.md), [broker_restart](broker_restart.md), [broker_start](broker_start.md), [broker_stop](broker_stop.md), [checkdb](checkdb.md), [compactdb](compactdb.md), [copydb](copydb.md), [createdb](createdb.md), [deletedb](deletedb.md), [ha_reload](ha_reload.md), [ha_start](ha_start.md), [ha_stop](ha_stop.md), [loaddb](loaddb.md), [lockdb](lockdb.md), [optimizedb](optimizedb.md), [renamedb](renamedb.md), [restoredb](restoredb.md), [start_statdump](start_statdump.md), [startbroker](startbroker.md), [startdb](startdb.md), [stop_statdump](stop_statdump.md), [stopbroker](stopbroker.md), [stopdb](stopdb.md), [unloaddb](unloaddb.md)

Each of these tasks accepts the `async` key alongside its own task-specific parameters; see the individual task pages linked above for their full request/response syntax.

Sending `"async":"yes"` on any task not listed above is not an error: CMS silently ignores it and runs the task synchronously, the same as if `async` had been omitted.

## Requesting Async Execution

Add `"async":"yes"` to the request of any task listed above:

```
{
  "task":"backupdb",
  "dbname":"demodb",
  "async":"yes"
}
```

If CMS can start the job, it returns a response right away, without waiting for the task to complete:

```
{
   "job-status" : "running",
   "note" : "none",
   "status" : "success",
   "uuid" : "14"
}
```

### Request Rejected

CMS rejects the request instead of starting the job when either of these is true:

* the server already has `max_num_async_task` async jobs running (see [Configuration](#configuration) below), or
* the task is one that must run exclusively against its database (for example `backupdb`, `restoredb`, `copydb`) and another job is already running against that same database.

A rejected request never gets a `uuid`, since the job never started:
```
{
   "job-status" : "rejected",
   "note" : "database 'xyz' is busy with another task ('createdb')",
   "status" : "failure",
   "task" : "startdb"
}
```

```
{
   "job-status" : "rejected",
   "note" : "maximum number of concurrent async tasks (8) reached; try again later",
   "status" : "failure",
   "task" : "compactdb"
}
```

Check `note` for the reason and retry the request later. (This exclusivity check only serializes async job bookkeeping; access to shared credential/connection files such as `cmdb.pass` is separately protected by an in-process mutex, `file_resource_guard`.)

### A Note on Request Latency

The bookkeeping updates that the tasks above perform on `cmdb.pass` and the auto-job config files run off CMS's global request-serialization lock, so they do not delay unrelated requests while waiting on `file_resource_guard` (bounded to ~5 seconds; see above). The same is true of [setautoexecquery](setautoexecquery.md) itself: like every task except [getserverstatus](getserverstatus.md), it is dispatched entirely off that global lock, so a slow `file_resource_guard` wait on `autoexecquery.conf` - for example, contention from another `setautoexecquery` call, or from a `deletedb`/`renamedb`/`copydb`/`updateuser` bookkeeping update racing on the same file - only delays requests waiting on that same lock. It no longer blocks unrelated requests such as a `gettaskstatus` poll.

Only three things run under CMS's global request-serialization lock: token and authority validation, `gettaskstatus` handling, and `getserverstatus` (which reads its counters directly with no locking of its own and relies on the lock being held for that). All three are short, in-memory operations with no file or network I/O, so this lock is never held for long.

This is a deliberate check-then-act gap, not a bug: a task's authority is validated while that lock is held, but the task itself then runs after the lock is released. A permission change (e.g. an `updateuser` call demoting or removing the user) that lands in that window won't be picked up until the *next* request - a request already past the check can still run with the authority it had at check time. The window is narrow and the impact is limited to that one in-flight request, so this is accepted as a reasonable trade-off against serializing every task's execution behind a single global lock.

The auto-job configuration tasks (`getautostart`, `setautostart`, `getautojobconf`, `setautojobconf`, `execautostart`, `automail`) are not yet documented individually, but the same pattern applies to them: they wait on `file_resource_guard` for `autojobs.conf` (bounded to ~5 seconds; see above) and can return a failure response such as `"failed to lock autojobs.conf"` if that wait times out.

These tasks share a second failure mode unrelated to locking: if `autojobs.conf` exists but can't be parsed as JSON, `getautostart`, `setautostart`, `getautojobconf`, and `setautojobconf` all fail with `"autojobs.conf is corrupt"` rather than silently proceeding as if it were empty. A missing `autojobs.conf` is not an error - it's the normal state before any of these tasks have saved anything yet, so `getautostart`/`getautojobconf` return an empty result for it instead of failing. To recover from a corrupt `autojobs.conf`, delete the file; CMS treats its absence as normal and starts a fresh, empty configuration on the next successful save.

## Checking Job Status

Use the returned `uuid` to poll [gettaskstatus](gettaskstatus.md):

```
{
  "task": "gettaskstatus",
  "token": "$TOKEN",
  "uuid": "14"
}
```

`job-status` in the response is one of `running`, `success`, or `error`. (`rejected` is also a possible `job-status` value, but only in the immediate response to the original task request - see [Request Rejected](#request-rejected) above; a rejected request never receives a `uuid`, so it is never something you check with `gettaskstatus`.) See [gettaskstatus](gettaskstatus.md) for the full response syntax and samples.

A `uuid` is only valid for a limited time after the job finishes; see `async_job_ttl_sec` below.

To see the async subsystem's overall state instead of one specific job - how many slots are in use, which databases are currently busy, any long-running jobs - use [getserverstatus](getserverstatus.md).

## Configuration

The following parameters, configurable in `cm.conf`, control async job behavior:

| **Key** | **Description** | **Minimum** | **Default** | **Maximum** |
| --- | --- | --- | --- | --- |
| max_num_async_task | Maximum number of async jobs that can run simultaneously on the server. | 1 | 8 | 12 |
| async_job_ttl_sec | Number of seconds a completed job's `uuid` remains valid for [gettaskstatus](gettaskstatus.md) lookups, before it is dropped. | 60 (1 minute) | 3600 (1 hour) | 604800 (1 week) |
| async_long_job_sec | Execution time, in seconds, after which CMS considers an async job to have been running for an excessive amount of time. CMS does not terminate the job when this threshold is exceeded; it only records that the job has run long. | 60 (1 minute) | 86400 (1 day) | 604800 (1 week) |

### Example

`async_job_ttl_sec` and `async_long_job_sec` below are deliberately set above
their defaults (3600 and 86400) - for a deployment where `gettaskstatus` is
polled less often, or where individual jobs are expected to legitimately run
for a day or more, and the "long job" warning threshold should reflect that.
`max_num_async_task` is left at its default of 8 here.

```
...
max_num_async_task=8
async_job_ttl_sec=86400
async_long_job_sec=259200
...
```

## See Also

* [gettaskstatus](gettaskstatus.md)
* [getserverstatus](getserverstatus.md)
* [CUBRID Manager Server API Manual](README.md)
