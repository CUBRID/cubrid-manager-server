# logout

Close a session between manager server and manager client.

## Request Json Syntax

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
