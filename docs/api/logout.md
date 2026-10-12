# logout

Close a session between manager server and manager client.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |

## Request Sample

```
{
  "task": "logout",
  "token": "ae873897a0a9a2afb9bb12a49c4237744a82ea77049df67c9b58d7acc5c0c7527926f07dd201b6aa"
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
   "__EXEC_TIME" : "1 ms",
   "note" : "",
   "status" : "success",
   "task" : "logout"
}
```
