# updatedbmtuser_new

Update CM/CWM user information

## Request Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| targetid | user name |
| password | user password |
| dbauth | a list of databases which is taken in charge by this user |
| authoritylist | the authorities granted to this user, including dbo,brk,mon,job,var,dbc and admin |

## Request Sample

```
{
  "task": "updatedbmtuser_new",
  "token": "...",
  "password": "1234567",
  "targetid": "hqy_admin280",
  "dbauth": [
    {
      "dbname": "db_3",
      "dbid": "dba",
      "dbpassword": "",
      "dbbrokeraddress": "localhost, 33000"
    },
    {
      "dbname": "db_5",
      "dbid": "dba",
      "dbpassword": "",
      "dbbrokeraddress": "localhost, 33000"
    }
  ],
  "authoritylist": {
    "dbc": "yes",
    "dbo": "no",
    "brk": "no",
    "mon": "no",
    "job": "no",
    "var": "yes"
  }
}
```

## Response Json Syntax

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

```
{
    "dblist" : 
       {
          "dbs" : [
             {
                "dbname" : "demodb"
             }
       }
    ],
    "note" : "none",
    "status" : "success",
    "task" : "updatedbmtuser_new",
    "userlist" : 
       {
          "user" : [
             {
                "@id" : "admin",
                "authority_list" : [ null ,
                "dbauth" : 
                   {
                      "auth_info" : [
                         {
                            "@dbid" : "dba",
                            "dbbrokeraddress" : "10.34.135.62,30000",
                            "dbname" : "demodb"
                         }
                   }
                ],
                "user_auth" : "admin"
             },
             {
                "@id" : "hqy_admin225",
                "authority_list" : 
                   {
                      "brk" : "yes",
                      "dbc" : "no",
                      "dbo" : "yes",
                      "job" : "no",
                      "mon" : "no",
                      "var" : "no"
                   }
                ,
                "dbauth" : 
                   {
                      "auth_info" : [
                         {
                            "@dbid" : "dba",
                            "dbbrokeraddress" : "localhost, 33000",
                            "dbname" : "db_3"
                         },
                         {
                            "@dbid" : "dba",
                            "dbbrokeraddress" : "localhost, 33000",
                            "dbname" : "db_5"
                         }
                   }
                ],
                "user_auth" : "6"
             }
          ]
       }
    ]
 }
```
