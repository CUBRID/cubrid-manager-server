# deletedbmtuser

The deletedbmtuser interface deletes a specified manager user.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| targetid | the id of the CM user to be deleted |

## Request Sample

```
{
  "task": "deletedbmtuser",
  "token": "cdfb4c5717170c5e9c6856b4d1c61ee8132bcc7d82bd609066ed9ece2554c47f7926f07dd201b6aa",
  "targetid": "yifan"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |
| dblist | the list of the databases of the host |
| userlist | the updated list of the CM users |

### dblist

dblist is composed of `dbs` objects with following structure

| **Key** | **Description** |
| --- | --- |
| dbname | database name |

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
| dbbrokeraddress | the address of the broker used to connect to that database |

See [getdbmtuserinfo](getdbmtuserinfo.md) for the same structure in detail.


## Response Sample

```
{
   "__EXEC_TIME" : "3 ms",
   "dblist" : [
      {
         "dbs" : [
            {
               "dbname" : "destinationdb"
            },
            {
               "dbname" : "alatestdb"
            },
            {
               "dbname" : "demodb"
            }
         ]
      }
   ],
   "note" : "none",
   "status" : "success",
   "task" : "deletedbmtuser",
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
                           "dbbrokeraddress" : "",
                           "dbname" : "destinationdb"
                        },
                        {
                           "@dbid" : "dba",
                           "dbbrokeraddress" : "",
                           "dbname" : "alatestdb"
                        },
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
