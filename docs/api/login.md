# login

Create a session by manager user.

Permissions required to run this task: none (no login required)

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

* `token` is an opaque random value of 256 hexadecimal characters.
* Each successful login creates a new session; the same user can hold several. `max_sessions_per_user` in `cm.conf` limits them (1 to 64, default 16); when a login would exceed the limit, the least recently used session of that user is closed. See [Session](README.md#session).

## Response Sample

```
{
   "note" : "none",
   "status" : "success",
   "task" : "authenticate",
   "token" : "3f9a...(256 hexadecimal characters)...c21e"
}
```
