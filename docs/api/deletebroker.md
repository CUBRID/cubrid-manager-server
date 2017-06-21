# deletebroker

The deletebroker interface delete specified database broker.

## Request Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |

## Request Sample

```
{
  "task": "deletebroker",
  "token": "cdfb4c5717170c5eff38bf38711a5318d74ad4769721528348698c5ef683475a7926f07dd201b6aa",
  "bname": "broker_test"
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
   "task" : "deletebroker"
}
```
