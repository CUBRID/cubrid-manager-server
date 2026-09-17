# getserverstatus

Get an instant health snapshot of the async-job subsystem: how many async jobs are running, which databases are currently busy with an exclusive async task, jobs still waiting to be collected via [gettaskstatus](gettaskstatus.md), any long-running jobs, the relevant `cm.conf` settings, and the statdump daemon list. Unlike most tasks, this does not start a worker thread or an external process - the response is built immediately from in-memory state.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |

## Request Sample

```
{
 "task":"getserverstatus",
 "token":"4504b930fc1be99bf5dfd31fc5799faaa3f117fb903f397de087cd3544165d857926f07dd201b6aa"
 }
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| note | if failed, a brief description will be given here |
| status | execution result, success or failed. |
| task | task name |
| cm-conf | `cm.conf` settings relevant to the async subsystem; see below |
| async-slot | current async job slot usage; see below |
| request-map | in-memory async job tracking table status; see below |
| db-running-async | list of databases currently busy with an exclusive async task |
| | a copydb/renamedb job appears as two entries (source and target) |
| statdump-daemon | list of running statdump daemons |

### cm-conf

| **Key** | **Description** |
| --- | --- |
| CUBRID_Version | CUBRID engine version string the server is running against |
| async_job_ttl_sec | see `async_job_ttl_sec` in [Asynchronous Task Execution](async_readme.md#configuration) |
| async_long_job_sec | see `async_long_job_sec` in [Asynchronous Task Execution](async_readme.md#configuration) |
| max_num_async_task | see `max_num_async_task` in [Asynchronous Task Execution](async_readme.md#configuration) |
| http_timeout | seconds an `"async":"no"` request waits for the job to finish before falling back to background running and give a `"job-status":"running"` response (see `http_timeout` in `cm.conf`) |

### async-slot

| **Key** | **Description** |
| --- | --- |
| num_async_job_running | number of async job slots currently occupied by real `"async":"yes"` jobs; counted against `max_async_job` |
| max_async_job | same value as `cm-conf.max_num_async_task` |
| num_timeout_fallback_jobs | number of jobs that ran past `http_timeout` on a *synchronous* (`"async":"no"`) request and fell back to being tracked like an async job; tracked separately from `num_async_job_running` so this kind of traffic can never block genuine `"async":"yes"` admission |

* `num_timeout_fallback_jobs` is absent from the response when built against an older CMS version that predates the fallback-job counter.

### request-map

The in-memory table that backs [gettaskstatus](gettaskstatus.md) lookups.

| **Key** | **Description** |
| --- | --- |
| map_size | total number of jobs currently tracked (running + finished but not yet past `async_job_ttl_sec`) |
| running | number of tracked jobs still running |
| finished_pending_ttl | number of tracked jobs that finished and are waiting to be collected (or to expire after `async_job_ttl_sec`) |
| long_jobs | number of currently-running jobs that have exceeded `async_long_job_sec` |
| longest_task_running_sec | how long, in seconds, the longest currently-running job has been running |
| long_job_list | details of each job counted in `long_jobs`; see below |

#### long_job_list entries

| **Key** | **Description** |
| --- | --- |
| uuid | the job's uuid, usable with [gettaskstatus](gettaskstatus.md) |
| task | name of the task the job is running |
| db_name | database name(s) the job is running against |
| requester_id | id of the user who started the job |
| elapsed_sec | how long the job has been running, in seconds |

### db-running-async entries

Databases currently marked busy by an exclusive async task (see [Request Rejected](async_readme.md#request-rejected)).

| **Key** | **Description** |
| --- | --- |
| db_name | database name |
| task | task currently running exclusively against that database |

### statdump-daemon entries

| **Key** | **Description** |
| --- | --- |
| db_name | database name the statdump daemon is running against |
| interval | statdump collection interval, in seconds |
| pid | process id of the statdump daemon |
| status | daemon status |
| started | when the daemon was started |

## Response Sample

```
{
   "async-slot" : {
      "max_async_job" : 8,
      "num_async_job_running" : 0,
      "num_timeout_fallback_jobs" : 0
   },
   "cm-conf" : {
      "CUBRID_Version" : "11.5.0.2512-77bd76b",
      "async_job_ttl_sec" : 3600,
      "async_long_job_sec" : 86400,
      "http_timeout" : 30,
      "max_num_async_task" : 8
   },
   "db-running-async" : null,
   "note" : "none",
   "request-map" : {
      "finished_pending_ttl" : 0,
      "long_job_list" : null,
      "long_jobs" : 0,
      "longest_task_running_sec" : 0,
      "map_size" : 0,
      "running" : 0
   },
   "statdump-daemon" : null,
   "status" : "success",
   "task" : "getserverstatus"
}
```

## Response Sample with jobs in progress

```
{
   "async-slot" : {
      "max_async_job" : 8,
      "num_async_job_running" : 2,
      "num_timeout_fallback_jobs" : 1
   },
   "cm-conf" : {
      "CUBRID_Version" : "11.5.0.2512-77bd76b",
      "async_job_ttl_sec" : 3600,
      "async_long_job_sec" : 86400,
      "http_timeout" : 30,
      "max_num_async_task" : 8
   },
   "db-running-async" : [
      {
         "db_name" : "demodb",
         "task" : "backupdb"
      }
   ],
   "note" : "none",
   "request-map" : {
      "finished_pending_ttl" : 1,
      "long_job_list" : [
         {
            "db_name" : "demodb",
            "elapsed_sec" : 96400,
            "requester_id" : "dba",
            "task" : "backupdb",
            "uuid" : "14"
         }
      ],
      "long_jobs" : 1,
      "longest_task_running_sec" : 96400,
      "map_size" : 4,
      "running" : 3
   },
   "statdump-daemon" : null,
   "status" : "success",
   "task" : "getserverstatus"
}
```

## See Also

* [Asynchronous Task Execution](async_readme.md)
* [gettaskstatus](gettaskstatus.md)
