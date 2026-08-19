# restoredb

The restoredb interface will restore a database from backup.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | a name of the database |
| date | restore the database up to its condition at given DATE, DATE is given as follows: dd-mm-yyyy:hh:mm:ss. none is backup time. |
| level | LEVEL of backup to be restored |
| partial | perform partial recovery if any log archive is absent |
| pathname | PATH is a directory of backup volumes to be restored |
| recoverypath | restore the database and log volumes to the path specified in the database location file |
| async | default "no", if "yes" run the task in asynchronous mode |

* The status of a task running in asynchronous mode can be checked using the 'gettaskstatus' api

## Request Sample

```
{
  "task": "restoredb",
  "token": "cdfb4c5717170c5e237a227a2ceeccc6ae9e10c16754fb85371c0d74fa0d9d577926f07dd201b6aa",
  "dbname": "alatestdb",
  "date": "none",
  "level": "0",
  "partial": "y",
  "pathname": "$CUBRID_DATABASES/alatestdb/backup/alatestdb_backup_lv0",
  "recoverypath": "$CUBRID_DATABASES/alatestdb",
  "async":"yes"
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
