# broker_restart

The broker_restart interface will restart a specified broker.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| bname | the name of the broker whose application servers are restarted |
| asnum | the number of the application servers to be restarted |

## Request Sample

```
{
  "task": "broker_restart",
  "token": "cdfb4c5717170c5e9c6856b4d1c61ee8132bcc7d82bd609066ed9ece2554c47f7926f07dd201b6aa",
  "bname": "query_editor",
  "asnum": "1"
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
   "task" : "broker_restart"
}
```
