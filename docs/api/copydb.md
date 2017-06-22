# copydb

Copy database.

## Request Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| srcdbname | source database |
| destdbname | destination database |
| exvolpath | extend volume path |
| logpath | log volume path |
| overwrite | on-off indicating whether to replace existed database |
| move | on-off indicating whether to remove existed database |
| advanced | on-off indicating whether to offer local control files |

## Request Sample

```
{
  "task":"copydb",
  "token":"cdfb4c5717170c5edfc2912f2940ab35013dd1336cf7d77e4cfaae281cffa1417926f07dd201b6aa",
  "srcdbname":"alatestdb",
  "destdbname":"destinationdb",
  "destdbpath":"$CUBRID_DATABASES/destinationdb",
  "exvolpath":"$CUBRID_DATABASES/destinationdb",
  "logpath":"$CUBRID_DATABASES/destinationdb",
  "overwrite":"y",
  "move":"n",
  "advanced":"off"
}
```

## Response Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |

## Response Sample

```
{
   "__EXEC_TIME" : "33 ms",
   "note" : "none",
   "status" : "success",
   "task" : "copydb"
}
```
