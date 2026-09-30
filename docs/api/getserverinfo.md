# getserverinfo

Get this CMS process's own identity: version, start time, pid, uptime, and a restart-unique instance identifier. This is the lightweight counterpart to [getserverstatus](getserverstatus.md): it returns only these fields, flattened directly into the response, without the async-job subsystem internals (`cm-conf`, `async-slot`, `request-map`, `db-running-async`, `statdump-daemon`) that `getserverstatus` requires admin authority for, and without the CUBRID engine version (for that, see `CUBRIDVER` in [getcmsenv](getcmsenv.md), which is available before login). Any authenticated user can call `getserverinfo` regardless of role, so a non-admin client (for example, a DBC-only user issuing `createdb` with `"async":"yes"`) can still perform the restart-detection procedure described in [Orphan Jobs After a CMS Restart](async_readme.md#orphan-jobs-after-a-cms-restart) without needing an admin session. Like `getserverstatus`, this does not start a worker thread or an external process - the response is built immediately from in-memory state.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |

## Request Sample

```
{
 "task":"getserverinfo",
 "token":"4504b930fc1be99bf5dfd31fc5799faaa3f117fb903f397de087cd3544165d857926f07dd201b6aa"
 }
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| note | if failed, a brief description will be given here |
| status | execution result, success or failed. |
| task | task name |
| version | CMS's own build/version string (not the CUBRID engine version - see `CUBRIDVER` in [getcmsenv](getcmsenv.md) for that) |
| start_time | wall-clock time this CMS process started, `YYYY-MM-DD HH:MM:SS ±HHMM` (server-local time and its UTC offset, e.g. `+0900`/`+0000` - whatever this process's own time zone actually is). The offset is numeric, not a zone abbreviation like `KST`, so it's unambiguous and safe to embed regardless of platform or locale. This is informational only - do not use it (or your own clock) to detect a restart, see `uuid` below |
| pid | process id of this CMS process. Usually differs after a restart, but not guaranteed - the OS can reuse a pid. This is informational only - see `uuid` below for the reliable way to detect a restart |
| uptime_sec | seconds since `start_time`, as measured on this host by this process alone (not a cross-host comparison). Can be negative if the server's own clock was stepped backward (NTP correction, manual adjustment) since `start_time` |
| uuid | an opaque decimal-digit string, this CMS process instance's own identity, up to 19 digits long (same shape as a job [uuid](async_readme.md), and CMS always sends it as a JSON string for the same reason - see there). Unlike `pid`, this is guaranteed to differ every time CMS restarts, with no "OS can reuse it" caveat - it's the recommended way to detect a restart; see [Orphan Jobs After a CMS Restart](async_readme.md#orphan-jobs-after-a-cms-restart) |

## Response Sample

```
{
   "note" : "none",
   "pid" : 2438742,
   "start_time" : "2026-09-29 23:29:53 +0900",
   "status" : "success",
   "task" : "getserverinfo",
   "uptime_sec" : 14,
   "uuid" : "1876952383000000000",
   "version" : "11.4.0.0446"
}
```

## See Also

* [getserverstatus](getserverstatus.md) - the admin-only superset that also reports async-job subsystem state and the CUBRID engine version
* [getcmsenv](getcmsenv.md) - CMS environment info available before login, including the CUBRID engine version (`CUBRIDVER`)
* [Asynchronous Task Execution](async_readme.md)
* [gettaskstatus](gettaskstatus.md)
