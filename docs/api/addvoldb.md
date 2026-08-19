# addvoldb

Add a new volume.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name |
| volname | volume name |
| purpose | generic, data, index, temp |
| size_need_mb | size of the volume in megabytes (MB) |
| async | default "no", if "yes" run the task in asynchronous mode |

* The status of a task running in asynchronous mode can be checked using the 'gettaskstatus' api

## Request Sample

```
{
  "task":"addvoldb",
  "dbname":"demodb",
  "volname":"testvol",
  "purpose":"generic",
  "size_need_mb":"500",
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
  "__EXEC_TIME": "72 ms",
  "note": "none",
  "status": "success",
  "task": "addvoldb"
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
