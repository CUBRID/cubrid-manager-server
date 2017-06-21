# addtrigger

Add a trigger.

## Request Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |

## Request Sample

```
{
  "task": "addtrigger",
  "token": "8ec1ab8a91333c7812b01dad653e9472ac3797d549ff3a79b1675dadedea4cd47926f07dd201b6aa",
  "dbname": "demodb",
  "triggername": "example",
  "conditiontime": "BEFORE",
  "eventtype": "STATEMENT UPDATE",
  "action": "REJECT",
  "eventtarget": "history(score)",
  "condition": "1=1",
  "status": "ACTIVE",
  "priority": "00.00"
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
   "task" : "addtrigger"
}
```
