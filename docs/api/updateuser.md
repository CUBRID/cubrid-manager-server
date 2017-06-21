# updateuser

Update database user information.

## Request Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name |
| username | database user name |
| password | user password |

## Request Sample

```
{
  "task":"updateuser",
  "token":"cdfb4c5717170c5edfc2912f2940ab35013dd1336cf7d77e4cfaae281cffa1417926f07dd201b6aa",
  "dbname":"demodb",
  "username":"yifan",
  "userpass":"1111",
  "groups": {"group":["public"}],
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
   "__EXEC_TIME" : "148 ms",
   "note" : "none",
   "status" : "success",
   "task" : "updateuser"
}
```
