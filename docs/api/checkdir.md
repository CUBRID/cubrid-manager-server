# checkdir

Check whether the given directories exist. Every `dir` value of the request is tested and
only the directories that do not exist (or that CMS is not allowed to access) are reported
back in the `noexist` key. A request whose directories all exist returns success without
any `noexist` key.

Permissions required to run this task: none (any logged-in user)

* Paths are limited as described in [File Access](README.md#file-access): only under `$CUBRID` and `$CUBRID_DATABASES`, and never a protected file such as `conf/cm.pass`.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token returned by login |
| dir | the directory to be checked, it can be given several times |

## Request Sample

```
{
  "task": "checkdir",
  "token": "cdfb4c5717170c5e9c6856b4d1c61ee8132bcc7d82bd609066ed9ece2554c47f7926f07dd201b6aa",
  "dir": "$CUBRID_DATABASES"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |
| noexist | a directory of the request which does not exist |

## Response Sample

```
{
   "__EXEC_TIME" : "1 ms",
   "noexist" : "/home/cubrid/CUBRID/databases_bak",
   "note" : "none",
   "status" : "success",
   "task" : "checkdir"
}
```
