# Asynchronous Task Execution

Run a supported task in the background instead of waiting for it to finish.

## Overview

Clients can ask CMS to execute certain long-running tasks asynchronously by sending `"async":"yes"` in the request. Instead of blocking until the task finishes, CMS immediately returns a response containing a unique job identifier (`uuid`). The client then polls the [gettaskstatus](gettaskstatus.md) task with that `uuid` to check whether the job is still running and, once finished, whether it succeeded or failed.

If `async` is not specified in the request, it defaults to `"async":"no"` and the task runs synchronously, as usual.

## Async-Capable Tasks

25 tasks currently support `async`:

[addvoldb](addvoldb.md), [backupdb](backupdb.md), [broker_restart](broker_restart.md), [broker_start](broker_start.md), [broker_stop](broker_stop.md), [checkdb](checkdb.md), [compactdb](compactdb.md), [copydb](copydb.md), [createdb](createdb.md), [deletedb](deletedb.md), [ha_reload](ha_reload.md), [ha_start](ha_start.md), [ha_stop](ha_stop.md), [loaddb](loaddb.md), [lockdb](lockdb.md), [optimizedb](optimizedb.md), [renamedb](renamedb.md), [restoredb](restoredb.md), [start_statdump](start_statdump.md), [startbroker](startbroker.md), [startdb](startdb.md), [stop_statdump](stop_statdump.md), [stopbroker](stopbroker.md), [stopdb](stopdb.md), [unloaddb](unloaddb.md)

Each of these tasks accepts the `async` key alongside its own task-specific parameters; see the individual task pages linked above for their full request/response syntax.

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
* the task is one that must run exclusively against its database (for example `backupdb`, `restoredb`, `copydb`) and another async job is already running against that same database.

A rejected request never gets a `uuid`, since the job never started:

```
{
   "job-status" : "rejected",
   "note" : "maximum number of concurrent async tasks (8) reached; try again later",
   "status" : "failure"
}
```

Check `note` for the reason and retry the request later.

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

## Configuration

The following parameters, configurable in `cm.conf`, control async job behavior:

| **Key** | **Description** | **Default** | **Maximum** |
| --- | --- | --- | --- |
| max_num_async_task | Maximum number of async jobs that can run simultaneously on the server. | 8 | 12 |
| async_job_ttl_sec | Number of seconds a completed job's `uuid` remains valid for [gettaskstatus](gettaskstatus.md) lookups, before it is dropped. | 3600 (1 hour) | 604800 (1 week) |
| async_long_job_sec | Execution time, in seconds, after which CMS considers an async job to have been running for an excessive amount of time. CMS does not terminate the job when this threshold is exceeded; it only records that the job has run long. | 86400 (1 day) | 604800 (1 week) |

### Example

```
...
max_num_async_task=8
async_job_ttl_sec=86400
async_long_job_sec=259200
...
```

## See Also

* [CUBRID Manager Server API Manual](README.md)
