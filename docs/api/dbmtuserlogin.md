# dbmtuserlogin

The dbmtuserlogin interface will make a session to access by a manager user.

## Request Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |

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
