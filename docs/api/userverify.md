# userverify

Check whether or not an user is valid.

## Request Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name |
| dbuser | database user id |
| dbpasswd | a password of dbuser |

## Request Sample

```
{
  "task": "userverify",
  "token": "cdfb4c5717170c5e0399fc5e0fe63d75bf6a689bc913b6ad8cb2f694498362597926f07dd201b6aa",
  "dbname": "demodb",
  "dbuser": "dba",
  "dbpasswd": ""
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
   "task" : "userverify"
}
```
