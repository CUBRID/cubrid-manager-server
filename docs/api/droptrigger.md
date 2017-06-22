# droptrigger

Drop a trigger.

## Request Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |

## Request Sample

```
{
  "task": "droptrigger",
  "token": "cdfb4c5717170c5e52c7be2e979d2b1abf6a689bc913b6adf7426b1af535049d7926f07dd201b6aa",
  "dbname": "demodb",
  "triggername": "example"
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
   "task" : "droptrigger"
}
```
