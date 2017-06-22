# compactdb

Compact database.

## Request Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name |
| verbose | on-off indicating whether to show detail informations |

## Request Sample

```
{
  "task":"compactdb",
  "token":"cdfb4c5717170c5e9c6856b4d1c61ee8132bcc7d82bd609066ed9ece2554c47f7926f07dd201b6aa",
  "dbname":"alatestdb",
  "verbose":"y"
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
   "task" : "compactdb"
}
```
