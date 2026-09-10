# getdbsize

Get database size information.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name |

## Request Sample

```
{
  "task": "getdbsize",
  "token": "cdfb4c5717170c5e237a227a2ceeccc6ae9e10c16754fb85371c0d74fa0d9d577926f07dd201b6aa",
  "dbname": "alatestdb"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |
| dbsize | the size of the database, in MB |

## Response Sample

```
{
   "__EXEC_TIME" : "49 ms",
   "dbsize" : "150999328",
   "note" : "none",
   "status" : "success",
   "task" : "getdbsize"
}
```
