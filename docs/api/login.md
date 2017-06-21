# login

Create a session by manager user.

## Request Json Syntax

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
