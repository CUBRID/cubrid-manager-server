# backupdb

The backupdb interface will create databases backup file.

## Request Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |

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
  "zip": "y",
  "safereplication": "n"
}
```
