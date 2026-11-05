# force_logout

The force_logout interface closes every session of a specified CM user, for example when a token may have leaked or after the user's password was changed.

Permissions required to run this task: ADMIN

* The user, its password and its authority are not changed. The user can log in again at once; to keep it out, change its password (`setdbmtpasswd`) or delete it (`deletedbmtuser`).
* A closed session's token is refused with the same response as an expired session. The DB logins saved in the closed sessions (`dbmtuserlogin`) are discarded with them.
* The target may be any CM user, the requester itself or another ADMIN user included. When it is the requester itself, this request succeeds and the next request with the same token is refused.
* A request that already passed the token check completes. An asynchronous task started by the user keeps running; its result can be read with `gettaskstatus` after the user logs in again.
* A user without any session is not an error: `closed_sessions` is 0.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token returned by login |
| targetid | the id of the CM user whose sessions are closed; a top-level string |

## Request Sample

```
{
  "task": "force_logout",
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
| targetid | the id of the CM user whose sessions were closed |
| closed_sessions | the number of sessions closed |

## Response Sample

```
{
  "__EXEC_TIME" : "1 ms",
  "closed_sessions" : 2,
  "note" : "none",
  "status" : "success",
  "targetid" : "yifan",
  "task" : "force_logout"
}
```

## Errors

| **Note** | **Cause** |
| --- | --- |
| Parameter(targetid) missing in the request. | `targetid` is missing or empty |
| Parameter(targetid) must be a string. | `targetid` is a number, an array or an object |
| The user does not exist: &lt;id&gt; | no CM user with that id |
| The user don't have authority to execute the task: force_logout | the requester is not an ADMIN user |
