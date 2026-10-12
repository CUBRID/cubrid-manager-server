# classinfo

Get the information of tables from a database.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name |
| dbstatus | N/A |


## Request Sample

```
{
  "task":"classinfo",
  "token":"cdfb4c5717170c5ed30ef86644baf8151531ce5adff4a1f9a54711c51e0f50767926f07dd201b6aa",
  "dbname":"demodb",
  "dbstatus":"on"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |
| dbname | database name |
| systemclass | system class information list |
| classname | class name |
| owner | class owner |
| userclass | user class info list |

## Response Sample

```
{
   "__EXEC_TIME" : "31 ms",
   "dbname" : "demodb",
   "note" : "none",
   "status" : "success",
   "systemclass" : [
      {
         "class" : [
            {
               "classname" : "db_root",
               "owner" : "DBA",
               "virtual" : "normal"
            },
            {
               "classname" : "_db_user",
               "owner" : "DBA",
               "virtual" : "normal"
            },
            {
               "classname" : "_db_password",
               "owner" : "DBA",
               "virtual" : "normal"
            }
         ]
      }
   ],
   "task" : "classinfo",
   "userclass" : [
      {
         "class" : [
            {
               "classname" : "public.stadium",
               "owner" : "PUBLIC",
               "virtual" : "normal"
            },
            {
               "classname" : "public.code",
               "owner" : "PUBLIC",
               "virtual" : "normal"
            },
            {
               "classname" : "public.nation",
               "owner" : "PUBLIC",
               "virtual" : "normal"
            }
         ]
      }
   ]
}
```

> Lists are shortened to 3 entries here.
