# logout

Close a session between manager server and manager client.

Permissions required to run this task: none (any logged-in user)

* Only the session of the given token is closed; other sessions of the same user stay open.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token returned by login |

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
