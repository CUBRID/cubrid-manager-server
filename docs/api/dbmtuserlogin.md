# dbmtuserlogin

The dbmtuserlogin interface will create a session to be accessed by a manager user.

Permissions required to run this task: none (any logged-in user)

* The DB login is kept in this session only (in memory, not on disk). Later requests of the same session that name `dbname` and give no `dbuser`/`dbpasswd` use it; other sessions do not.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token returned by login |
| targetid | dbmt user name |
| dbname | name of database |
| dbuser | id of db user |
| dbpasswd | password of db user |

## Request Sample

```
{
  "task": "dbmtuserlogin",
  "token": "8ec1ab8a91333c7867aad34ccaa8aa1310e3e4a76eb7181ba51bb67dca9780c87926f07dd201b6aa",
  "targetid": "admin",
  "dbname": "demodb",
  "dbuser": "dba",
  "dbpasswd": ""
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| note | if failed, a brief description will be given here |
| status | execution result, success or failed. |
| task | task name |
| @targetid |	dbmt user name |
| authority | authority of logged in user |
| dbname | name of the database |

## Response Sample

```
{
   "@targetid" : "admin",
   "__EXEC_TIME" : "38 ms",
   "authority" : "isdba",
   "dbname" : "ha_test",
   "note" : "none",
   "status" : "success",
   "task" : "dbmtuserlogin"
}

```