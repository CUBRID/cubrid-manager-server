# getdbmtuserinfo

The getdbmtuserinfo interface will fetch CUBRID Manager user information.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |

## Request Sample

```
{
  "task": "getdbmtuserinfo",
  "token": "cdfb4c5717170c5e237a227a2ceeccc6ae9e10c16754fb85371c0d74fa0d9d577926f07dd201b6aa"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |
| dblist | the list of the databases of the host |
| userlist | the list of the CM users |

### dblist

dblist is composed of `dbs` objects with following structure

| **Key** | **Description** |
| --- | --- |
| dbname | database name |
| dbdir | the directory of the database |

### userlist

userlist is composed of `user` objects with following structure

| **Key** | **Description** |
| --- | --- |
| @id | the id of the CM user |
| casauth | the broker authority of the CM user |
| dbcreate | the database creation authority of the CM user |
| statusmonitorauth | the monitoring authority of the CM user |
| dbauth | the databases the CM user takes in charge of |
| dbname | database name |
| @dbid | the database user id used to connect to that database |
| dbbrokeraddress | the address of the broker used to connect to that database |

## Response Sample

```
{
   "__EXEC_TIME" : "0 ms",
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
   "task" : "getdbmtuserinfo",
   "userlist" : [
      {
         "user" : [
            {
               "@id" : "admin",
               "@passwd" : "admin",
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
