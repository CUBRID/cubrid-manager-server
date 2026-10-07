# getbackuplist

Get backup list.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |

## Request Sample

```
{
  "task": "getbackuplist",
  "token": "cdfb4c5717170c5e237a227a2ceeccc6ae9e10c16754fb85371c0d74fa0d9d577926f07dd201b6aa",
  "dbname": "alatestdb"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |
| level0 | the backup volume of level 0, `none` when it does not exist |
| level1 | the backup volume of level 1, `none` when it does not exist |
| level2 | the backup volume of level 2, `none` when it does not exist |

## Response Sample

```
{
   "__EXEC_TIME" : "0 ms",
   "level0" : "/home/cubrid/CUBRID-11.5.0.2441-6ba9522-Linux.x86_64/databases/alatestdb/backup/alatestdb_backup_lv0/alatestdb_bk0v000",
   "level1" : "none",
   "level2" : "none",
   "note" : "none",
   "status" : "success",
   "task" : "getbackuplist"
}
```
