# getserverstatus

Get an instant health snapshot of the async-job subsystem: how many async jobs are running, which databases are currently busy with an exclusive async task, jobs still waiting to be collected via [gettaskstatus](gettaskstatus.md), any long-running jobs, the relevant `cm.conf` settings, and the statdump daemon list. Also returns this CMS process's own identity (version, start time, pid, uptime, and a restart-unique instance identifier) and the CUBRID engine version it's running against. Unlike most tasks, this does not start a worker thread or an external process - the response is built immediately from in-memory state.

This task requires admin authority (`AU_ADMIN`). If you only need this process's identity (`server-information`) - for example, to run the restart-detection procedure in [Orphan Jobs After a CMS Restart](async_readme.md#orphan-jobs-after-a-cms-restart) - use [getserverinfo](getserverinfo.md) instead, which any authenticated user can call.

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
| CUBRID_engine_version | CUBRID engine version string the server is running against |
| server-information | this CMS process's own version, start time, pid, uptime, and restart-unique instance identifier; see below |
| cm-conf | `cm.conf` settings relevant to the async subsystem; see below |
| async-slot | current async job slot usage; see below |
| request-map | in-memory async job tracking table status; see below |
| db-running-async | list of databases currently busy with an exclusive async task |
| statdump-daemon | list of running statdump daemons |

* a copydb/renamedb job appears in `db-running-async` as two entries (source and target)

### server-information

| **Key** | **Description** |
| --- | --- |
| version | CMS's own build/version string (distinct from `CUBRID_engine_version` above, which is the engine's) |
| start_time | wall-clock time this CMS process started, `YYYY-MM-DD HH:MM:SS ±HHMM` (server-local time and its UTC offset, e.g. `+0900`/`+0000` - whatever this process's own time zone actually is). The offset is numeric, not a zone abbreviation like `KST`, so it's unambiguous and safe to embed regardless of platform or locale. This is informational only - do not use it (or your own clock) to detect a restart, see `uuid` below |
| pid | process id of this CMS process. Usually differs after a restart, but not guaranteed - the OS can reuse a pid. This is informational only - see `uuid` below for the reliable way to detect a restart |
| uptime_sec | seconds since `start_time`, as measured on this host by this process alone (not a cross-host comparison). Can be negative if the server's own clock was stepped backward (NTP correction, manual adjustment) since `start_time` |
| uuid | an opaque decimal-digit string, this CMS process instance's own identity, up to 19 digits long (CMS always sends it as a JSON string, same as a job [uuid](async_readme.md), to avoid JSON's 32-bit integer limit - but it is *not* in the same number space as a job `uuid`: the two are drawn independently of each other, so any one job's uuid matches this value only by chance - on the order of 1 in 2^20 for that job, the same odds as this uuid's own restart-to-restart uniqueness below - never because one is derived from the other, and it's harmless either way since they're different fields). High bits are this process's start time in milliseconds, low 20 bits are drawn fresh from a random source at every startup, so two restarts collide only if they land in the same millisecond *and* draw the same 20-bit value (roughly 1 in 10^6) - effectively unique in practice, and unlike `pid`, not reusable by the OS and not defeated by a system clock set back to an exact earlier reading. It's the recommended way to detect a restart; see [Orphan Jobs After a CMS Restart](async_readme.md#orphan-jobs-after-a-cms-restart) |

### cm-conf

| **Key** | **Description** |
| --- | --- |
| cm_port | port this CMS process is listening on |
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
   "CUBRID_engine_version" : "11.5.0.2512-77bd76b",
   "async-slot" : {
      "max_async_job" : 8,
      "num_async_job_running" : 0,
      "num_timeout_fallback_jobs" : 0
   },
   "cm-conf" : {
      "async_job_ttl_sec" : 3600,
      "async_long_job_sec" : 86400,
      "cm_port" : 8001,
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
   "server-information" : {
      "pid" : 2346068,
      "start_time" : "2026-09-28 09:00:00 +0900",
      "uptime_sec" : 3600,
      "uuid" : "1877531532242829529",
      "version" : "11.4.0.0428"
   },
   "statdump-daemon" : null,
   "status" : "success",
   "task" : "getserverstatus"
}
```

## Response Sample with jobs in progress

```
{
   "CUBRID_engine_version" : "11.5.0.2512-77bd76b",
   "async-slot" : {
      "max_async_job" : 8,
      "num_async_job_running" : 2,
      "num_timeout_fallback_jobs" : 1
   },
   "cm-conf" : {
      "async_job_ttl_sec" : 3600,
      "async_long_job_sec" : 86400,
      "cm_port" : 8001,
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
            "uuid" : "1877531532242829532"
         }
      ],
      "long_jobs" : 1,
      "longest_task_running_sec" : 96400,
      "map_size" : 4,
      "running" : 3
   },
   "server-information" : {
      "pid" : 2346068,
      "start_time" : "2026-09-28 09:00:00 +0900",
      "uptime_sec" : 96500,
      "uuid" : "1877531532242829529",
      "version" : "11.4.0.0428"
   },
   "statdump-daemon" : null,
   "status" : "success",
   "task" : "getserverstatus"
}
```

## See Also

* [getserverinfo](getserverinfo.md) - just this process's identity, for callers without admin authority
* [Asynchronous Task Execution](async_readme.md)
* [gettaskstatus](gettaskstatus.md)
