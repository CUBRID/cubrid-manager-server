# heartbeatlist

Runs `cubrid heartbeat list` command.

## Request Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbmodeall | y : all, n : only includes HA-Node, Node excepts Applylogdb, Copylogdb, Server |
| dblist | database name |

## Request Sample

```
{
  "task": "heartbeatlist",
  "token": "cdfb4c5717170c5e673cf07a9b448162c895920ae8799faa2fbe13c787b4cbbd7926f07dd201b6aa",
  "dbmodeall": "y",
  "dblist": ""
}
```
