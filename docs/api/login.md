# login

Create a session by manager user.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| id | manager user id |
| password | a password |
| clientver | the version number of client |

## Request Sample

```
{
  "task": "login",
  "id": "admin",
  "password": "admin",
  "clientver": "8.4"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |
| token | the token which must be sent with the following requests |

When the login succeeds, `task` is returned as `authenticate`, not as `login`.

## Response Sample

```
{
   "note" : "none",
   "status" : "success",
   "task" : "authenticate",
   "token" : "ae873897a0a9a2af8ea817532a4d722b124c446cb75876b9924a258f6351977e7926f07dd201b6aa"
}
```
