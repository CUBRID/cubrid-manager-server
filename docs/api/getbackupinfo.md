# getbackupinfo

Get backup info.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name. |

## Request Sample

```
{
  "task": "getbackupinfo",
  "token": "cdfb4c5717170c5e9c6856b4d1c61ee8132bcc7d82bd609066ed9ece2554c47f7926f07dd201b6aa",
  "dbname": "alatestdb"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |
| dbname | database name |
| <dbname> | the list of the auto-backup plans of that database, the key is the database name itself |

The keys of an auto-backup plan are the ones described in [addbackupinfo](addbackupinfo.md).

## Response Sample

```
{
   "__EXEC_TIME" : "0 ms",
   "dbname" : "alatestdb",
   "note" : "none",
   "status" : "success",
   "task" : "getbackupinfo"
}
```
