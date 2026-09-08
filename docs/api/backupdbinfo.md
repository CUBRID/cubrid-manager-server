# backupdbinfo

The backupdbinfo interface will get database backup information.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name |

## Request Sample

```
{
  "task": "backupdbinfo",
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
| dbdir | the default backup directory of the database |
| freespace | the free space of the database directory, in MB |
| level\<n\> | the backup volumes of that backup level, one key per level in use |

### level\<n\>

The key is the backup level of the volume, taken from the first column of
`<log path>/<dbname>_bkvinf`, which the engine writes as
`<level> <unit number> <volume path>`. The levels are the ones of
`cubrid backupdb --level`: `level0` full, `level1` since the last full backup,
`level2` since the last level 1. Only the levels that actually have a volume
appear, so a database with a single full backup answers with `level0` alone.

Every level holds objects with the following structure.

| **Key** | **Description** |
| --- | --- |
| path | the full path of the backup volume |
| size | the size of the backup volume file, in bytes |
| data | the last modification time of that file, `YYYY.MM.DD.HH.MM` |

## Response Sample

```
{
   "__EXEC_TIME" : "25 ms",
   "dbdir" : "/home/cubrid/CUBRID-11.5.0.2441-6ba9522-Linux.x86_64/databases/alatestdb/backup",
   "freespace" : "445672",
   "level0" : [
      {
         "data" : "2026.08.18.09.08",
         "path" : "/home/cubrid/CUBRID-11.5.0.2441-6ba9522-Linux.x86_64/databases/alatestdb/backup/alatestdb_backup_lv0/alatestdb_bk0v000",
         "size" : "2110464"
      }
   ],
   "note" : "none",
   "status" : "success",
   "task" : "backupdbinfo"
}
```
