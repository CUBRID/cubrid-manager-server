# deletedb

Delete a database.

## Request Json Syntax

| **Ke**y | **Description** |
| task | task name |
| token | token string encrypted. |
| dbname | database name |
| delbackup | on-off indicating whether to remove backup files |

## Request Sample

```
{
  "task":"deletedb",
  "token":"cdfb4c5717170c5e237a227a2ceeccc6ae9e10c16754fb85371c0d74fa0d9d577926f07dd201b6aa",
  "dbname":"alatestdb",
  "delbackup":"y"
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
   "__EXEC_TIME" : "393 ms",
   "note" : "none",
   "status" : "success",
   "task" : "deletedb"
}
```
