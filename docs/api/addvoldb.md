# addvoldb

Add a new volume.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name |
| volname | volume name. Optional, the server names the volume itself when it is omitted |
| purpose | generic, data, index, temp |
| path | the directory the volume is created in. Optional, the database directory is used when it is omitted |
| size_need_mb | size of the volume in megabytes (MB) |

## Request Sample

```
{
  "task":"addvoldb",
  "token":"cdfb4c5717170c5e9c6856b4d1c61ee8132bcc7d82bd609066ed9ece2554c47f7926f07dd201b6aa",
  "dbname":"demodb",
  "volname":"testvol",
  "purpose":"generic",
  "path":"/home/cubrid/CUBRID/databases/demodb",
  "size_need_mb":"500"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |
| dbname | database name |
| purpose | the purpose of the added volume, such as data, index, temp or generic |

## Response Sample

```
{
   "__EXEC_TIME" : "229 ms",
   "dbname" : "demodb",
   "note" : "none",
   "purpose" : "generic",
   "status" : "success",
   "task" : "addvoldb"
}
```
