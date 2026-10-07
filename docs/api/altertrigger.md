# altertrigger

Alter a trigger.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name |
| triggername | the name of the trigger to be altered |
| status | ACTIVE or INACTIVE |
| priority | the priority of the trigger |

## Request Sample

```
{
  "task": "altertrigger",
  "token": "cdfb4c5717170c5e9c6856b4d1c61ee8132bcc7d82bd609066ed9ece2554c47f7926f07dd201b6aa",
  "dbname": "demodb",
  "triggername": "example",
  "status": "INACTIVE",
  "priority": "00.00"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. Not the trigger status of the request, which happens to share the key name |
| note | if failed, a brief description will be given here |
| dbname | database name |


## Response Sample

```
{
   "__EXEC_TIME" : "40 ms",
   "dbname" : "demodb",
   "note" : "none",
   "status" : "success",
   "task" : "altertrigger"
}
```
