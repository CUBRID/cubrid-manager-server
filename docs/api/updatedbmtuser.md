# updatedbmtuser

The updatedbmtuser interface will update dbmt user information.

## Request Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| targetid | dbmt user name |
| casauth  | authorize cas user. |
| dbcreate | create databases authorization. |
| statusmonitorauth | monitor status authorization. |
| dbauth  | access of databases. |
| dbid  | databases operator user. |
| dbpassword  | databases user password. |
| dbbrokeraddress | databases broker address and port |

## Request Sample

```
{
  "task": "updatedbmtuser",
  "token": "cdfb4c5717170c5eb159540c0384c7424ea3fcd68c6ea615f538801cd09c6f3a7926f07dd201b6aa",
  "targetid": "admin",
  "dbauth": [
    {
      "dbname": "demodb",
      "dbid": "dba",
      "dbpassword": "",
      "dbbrokeraddress": "localhost,33000"
    }
  ],
  "casauth": "admin",
  "dbcreate": "admin",
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
   "__EXEC_TIME" : "72 ms",
   "note" : "none",
   "status" : "success",
   "task" : "updatedbmtuser"
}
```
