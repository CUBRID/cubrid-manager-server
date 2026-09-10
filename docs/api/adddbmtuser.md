# adddbmtuser

The adddbmtuser interface will create a new database manager user.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| targetid | user name |
| password | user password |
| dbauth | a list of databases which is taken in charge by this user |
| casauth | the broker authority of the CM user |
| dbcreate | the database creation authority of the CM user |
| statusmonitorauth | the monitoring authority of the CM user |

### dbauth

dbauth is composed of objects with following structure

| **Key** | **Description** |
| --- | --- |
| dbname | database name |
| dbid | the database user id used to connect to that database |
| dbpassword | the password of that database user |
| dbbrokeraddress | the address of the broker used to connect to that database |

## Request Sample

```
{
  "task": "adddbmtuser",
  "token": "...",
  "targetid": "monitor1",
  "password": "1111",
  "dbauth": [
    {
      "dbname": "demodb",
      "dbid": "dba",
      "dbpassword": "",
      "dbbrokeraddress": "localhost,33000"
    }
  ],
  "casauth": "admin",
  "dbcreate": "none",
  "statusmonitorauth": "admin"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |
| dblist | a list of databases which is taken in charge by this user |
| dbname | database name |
| userlist | the list path |
| user | user information list |
| id | user name |
| auth_info | authority information |
| dbid | database dba id |
| dbbrokerport | broker port |
| user_auth | a value indicating user authorities |
| authority_list | the authorities granted to this user, including dbo,brk,mon,job,var,dbc and admin |

## Response Sample

```json
{
   "__EXEC_TIME" : "4 ms",
   "dblist" : [
      {
         "dbs" : [
            {
               "dbname" : "demodb"
            }
         ]
      }
   ],
   "note" : "none",
   "status" : "success",
   "task" : "adddbmtuser",
   "userlist" : [
      {
         "user" : [
            {
               "@id" : "admin",
               "casauth" : "admin",
               "dbauth" : [
                  {
                     "auth_info" : [
                        {
                           "@dbid" : "dba",
                           "dbbrokeraddress" : "localhost,33000",
                           "dbname" : "demodb"
                        }
                     ]
                  }
               ],
               "dbcreate" : "admin",
               "statusmonitorauth" : "admin"
            }
         ]
      }
   ]
}
```

> Lists are shortened to 1 entry here.
