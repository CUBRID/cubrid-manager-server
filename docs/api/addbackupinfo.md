# addbackupinfo

Add a backup schedule.

## Request Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |

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
  "mt": "2"
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
   "__EXEC_TIME" : "72 ms",
   "note" : "none",
   "status" : "success",
   "task" : "addbackupinfo"
}
```
