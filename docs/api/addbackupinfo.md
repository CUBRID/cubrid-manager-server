# addbackupinfo

Add a backup schedule.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name |
| backupid | auto-backup plan id |
| path | the directory the backup volume is created in |
| period_type | the cycle of auto-backup, such as weekly, monthly, everyday and special. |
| period_date | backup date. |
| time | auto-backup time (or interval, start with "i", the measurement is minutes) |
| level | auto-backup level |
| archivedel | on-off indicating whether to delete archive file |
| storeold | on-off indicating whether to delete old files |
| onoff | on-off indicating whether the auto-backup plan is enabled |
| zip | on-off indicating whether to zip in auto-backup |
| updatestatus | on-off indicating whether to update statistic infromation |
| check | on-off indicating whether to start consistency check |
| mt | the number of auto-backup threads |
| bknum | the number of backup files to keep. Optional, `1` is used when it is omitted |

## Request Sample

```
{
  "task": "addbackupinfo",
  "token": "cdfb4c5717170c5e51196b3bf16112949ea2e1dcf05030c13351f8d4306356bf7926f07dd201b6aa",
  "dbname": "demodb",
  "backupid": "qw",
  "path": "$CUBRID_DATABASES/alatestdb/backup",
  "period_type": "Special",
  "period_date": "$AUTO_DATE",
  "time": "$AUTO_TIME",
  "level": "0",
  "archivedel": "OFF",
  "updatestatus": "ON",
  "storeold": "ON",
  "onoff": "ON",
  "zip": "y",
  "check": "y",
  "mt": "2",
  "bknum": "1"
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
   "__EXEC_TIME" : "72 ms",
   "note" : "none",
   "status" : "success",
   "task" : "addbackupinfo"
}
```
