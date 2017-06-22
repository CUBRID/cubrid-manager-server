# createuser

Create database user.

## Request Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name |
| username | database user name |
| userpass | database user password |
| authorization | authorities of this user |

## Request Sample

```
{
  "task":"createuser",
  "token":"cdfb4c5717170c5ed30ef86644baf8151531ce5adff4a1f9a54711c51e0f50767926f07dd201b6aa",
  "dbname":"demodb",
  "username":"yifan",
  "userpass":"1111",
  "groups":{"group":"public"},
  "authorization":[]
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
   "__EXEC_TIME" : "647 ms",
   "note" : "none",
   "status" : "success",
   "task" : "createuser"
}
```
