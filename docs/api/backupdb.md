# backupdb

The backupdb interface will create a database backup file.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name |
| level | backup level, 0, 1 or 2 |
| volname | the name of the backup volume |
| backupdir | the directory the backup volume is created in |
| removelog | y or n, remove the archive logs after the backup |
| check | y or n, check the consistency of the database before the backup |
| mt | the number of the threads used by the backup, 0 means the number of the cores |
| zip | y or n, compress the backup volume |

## Request Sample

```
{
  "task": "backupdb",
  "token": "cdfb4c5717170c5e237a227a2ceeccc6ae9e10c16754fb85371c0d74fa0d9d577926f07dd201b6aa",
  "dbname": "alatestdb",
  "level": "0",
  "volname": "alatestdb_backup_lv0",
  "backupdir": "$CUBRID_DATABASES/alatestdb/backup",
  "removelog": "n",
  "check": "y",
  "mt": "0",
  "zip": "y"
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
   "__EXEC_TIME" : "12 ms",
   "note" : "none",
   "status" : "success",
   "task" : "backupdb"
}
```
