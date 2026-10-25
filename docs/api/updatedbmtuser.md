# updatedbmtuser

The updatedbmtuser interface will update DBMT user information.

Permissions required to run this task: ADMIN

## Request JSON Syntax

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

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |
| dblist | list of databases |
| userlist | list of user | 

### dblist
dblist is composed of objects with following structure 

| **Key** | **Description** |
| --- | --- |
| dbs | list of name of databases |

### dbs 

| **Key** | **Description** |
| --- | --- |
| dbname | name of database |

### userlist 
dblist is composed of objects with following structure 
| **Key** | **Description** |
| --- | --- |
| user | information of the user |

### user
User is composed of objects with following structure. 
| **Key** | **Description** |
| --- | --- |
| @id | dbmt user name |
| casauth | authority over cas |
| dbauth | List of authorities for the current database session |

### dbauth
dbauth is composed of objects with following structure

| **Key** | **Description** |
| --- | --- |
| auth_info | list of access to databases |
| dbcreate | create databases authorization |
| statusmonitorauth | monitor status authorization |

### auth_info
auth_info is composed of objects with following structure

| **Key** | **Description** |
| --- | --- |
| @dbid | databases operator user |
| dbbrokeraddress | address of broker connected to database |
| dbname | name of the database |




## Response Sample

```
 {
   "__EXEC_TIME" : "1 ms",
   "dblist" : [
      {
         "dbs" : [
            {
               "dbname" : "jdbcdb"
            },
            {
               "dbname" : "ctldb"
            },
            {
               "dbname" : "ha_test"
            }
         ]
      }
   ],
   "note" : "none",
   "status" : "success",
   "task" : "updatedbmtuser",
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
                           "dbbrokeraddress" : "192.168.2.36,30000",
                           "dbname" : "jdbcdb"
                        },
                        {
                           "@dbid" : "dba",
                           "dbbrokeraddress" : "192.168.2.36,30000",
                           "dbname" : "ctldb"
                        },
                        {
                           "@dbid" : "dba",
                           "dbbrokeraddress" : "192.168.2.36,33120",
                           "dbname" : "ha_test"
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
