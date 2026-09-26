# updateuser

Update database user information.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name |
| username | database user name |
| password | user password |

## Request Sample

```
{
  "task":"updateuser",
  "token":"cdfb4c5717170c5edfc2912f2940ab35013dd1336cf7d77e4cfaae281cffa1417926f07dd201b6aa",
  "dbname":"demodb",
  "username":"yifan",
  "userpass":"1111",
  "groups": {"group":["public"]},
  "authorization":[]
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here; on a successful password change, may instead carry a warning that a manual check is recommended (see below) |

* If `userpass` is given, the database user's password is changed first; that change is what `status` reflects. Updating the encrypted copy of the new password cached in `autoexecquery.conf` (used to run the user's scheduled auto-execute queries) is a separate, best-effort step performed afterward. If that step fails - a lock timeout, a file I/O error, or an internal update error - the password change is **not** rolled back and `status` still reports `"success"`; `note` instead explains that the cached copy in `autoexecquery.conf` may be stale and should be checked manually. Any scheduled auto-execute query for this user could keep using the old password until that is corrected.

## Response Sample

```
{
   "__EXEC_TIME" : "148 ms",
   "note" : "none",
   "status" : "success",
   "task" : "updateuser"
}
```

## Response Sample (success, manual check recommended)
```
{
   "__EXEC_TIME" : "151 ms",
   "note" : "WARNING: the password for database user 'yifan' on database 'demodb' was changed, but updating the cached password in autoexecquery.conf failed (lock timeout, file I/O error, or an internal update error); manual check recommended",
   "status" : "success",
   "task" : "updateuser"
}
```
