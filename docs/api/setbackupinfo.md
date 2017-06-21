# setbackupinfo

Add an auto-backup plan

## Request Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name |
| backupid | auto-backup plan id |
| period_type | the cycle of auto-backup, such as weeky, monthly, everyday and special. |
| period_date | backup date. |
| time | auto-backup time (or interval, start with "i", the measurement is minutes) |
| level | auto-backup level  |
| archivedel | on-off indicating whether to delete archive file |
| storeold | on-off indicating whether to delete old files |
| zip | on-off indicating whether to zip in auto-backup |
| updatestatus | on-off indicating whether to update statistic infromation |
| check | on-off indicating whehter to start consistency check |
| mt | the number of auto-backup threads |

## Request Sample

```
{
  "task": "setbackupinfo",
  "token": "cdfb4c5717170c5e9c6856b4d1c61ee8132bcc7d82bd609066ed9ece2554c47f7926f07dd201b6aa",
  "dbname": "alatestdb",
  "backupid": "qw",
  "path": "$CUBRID_DATABASES/alatestdb/backup",
  "period_type": "Special",
  "period_date": "$AUTO_DATE",
  "time": "$AUTO_TIME",
  "level": "0",
  "archivedel": "ON",
  "updatestatus": "ON",
  "storeold": "ON",
  "onoff": "ON",
  "zip": "y",
  "check": "y",
  "mt": "0"
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
   "__EXEC_TIME" : "320 ms",
   "note" : "none",
   "status" : "success",
   "task" : "setbackupinfo"
}
```
