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
| note | if failed, a brief description will be given here |

## Response Sample

```
{
  "__EXEC_TIME": "353 ms",
  "note": "none",
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
   "task" : "renamedb",
   "uuid" : "14"
}
```
