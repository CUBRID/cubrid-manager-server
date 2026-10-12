# addtrigger

Add a trigger.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name |
| triggername | the name of the trigger |
| conditiontime | BEFORE, AFTER or DEFERRED |
| eventtype | the event which fires the trigger, such as `STATEMENT UPDATE` |
| eventtarget | the target of the event, in the `<table>(<column>)` form |
| condition | the condition of the trigger |
| action | the action of the trigger, such as REJECT, INVALIDATE TRANSACTION or PRINT |
| status | ACTIVE or INACTIVE |
| priority | the priority of the trigger |

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
   "__EXEC_TIME" : "47 ms",
   "dbname" : "demodb",
   "note" : "none",
   "status" : "success",
   "task" : "addtrigger"
}
```
