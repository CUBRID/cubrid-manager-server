# adddbmtuser

The adddbmtuser interface will create new databases manager user.

## Request Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |

## Request Sample

```
{
  "task": "adddbmtuser",
  "token": "cdfb4c5717170c5e357a14c1a398b40dd9d0db2c2c46fecac2a1ca5aa96e21aa7926f07dd201b6aa",
  "targetid": "yifan",
  "password": "1111",
  "casauth": "admin",
  "dbcreate": "none",
  "statusmonitorauth": "admin"
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
  "__EXEC_TIME": "72 ms",
  "note": "none",
  "status": "success",
  "task": "adddbmtuser"
}
```
