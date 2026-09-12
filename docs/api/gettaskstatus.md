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
| note | if failed, a brief description will be given here |
| uuid | uuid given in the request |

* `rejected` is returned directly in the response to the original task request, when CMS could not start the async job at all - for example because the concurrent async job limit (`max_num_async_task`) was reached, or another async job was already running against the same database. See [Request Rejected](async_readme.md#request-rejected) for details. A rejected request never receives a `uuid`, so `job-status` is never `rejected` in an actual `gettaskstatus` response - it is listed here only for a complete reference of the possible `job-status` values.


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
   "status" : "failure"
}
```

## Response Sample with invalid uuid
```
{
   "note" : "invalid uuid",
   "status" : "failure"
}
```
