# deletebackupinfo

Delete a backup meta data.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name |
| backupid | the id of the auto-backup plan to be deleted |

## Request Sample

```
{
  "task": "deletebackupinfo",
  "token": "cdfb4c5717170c5e9c6856b4d1c61ee8132bcc7d82bd609066ed9ece2554c47f7926f07dd201b6aa",
  "dbname": "alatestdb",
  "backupid": "qw"
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
   "task" : "deletebackupinfo"
}
```
