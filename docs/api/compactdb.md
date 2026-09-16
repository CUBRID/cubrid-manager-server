# compactdb

Compact database.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name |
| verbose | on-off indicating whether to show detailed information |
| input-class-file | path of a file that lists the classes to compact, one class name per line. cannot be given together with class-names |
| class-names | a list of class names to compact. cannot be given together with input-class-file |
| async | default "no", if "yes" run the task in asynchronous mode |

* The status of a task running in asynchronous mode can be checked using the 'gettaskstatus' api
* Only one of these database tasks — addvoldb, backupdb, checkdb, compactdb, copydb, createdb, deletedb, loaddb, optimizedb, renamedb, restoredb, startdb, stopdb, unloaddb — can run against the same `dbname` at a time, whether or not `async` is used; a request is rejected immediately if another one of them is already running on that database

## Request Sample

```
{
  "task":"compactdb",
  "token":"cdfb4c5717170c5e9c6856b4d1c61ee8132bcc7d82bd609066ed9ece2554c47f7926f07dd201b6aa",
  "dbname":"alatestdb",
  "input-class-file":"$CUBRID/tmp/alatestdb-input-class-file",
  "verbose":"y",
  "async":"yes"
}
```

`class-names` can be used instead of `input-class-file` when the caller wants to specify the target classes directly, without preparing a file itself:

```
{
  "task":"compactdb",
  "token":"cdfb4c5717170c5e9c6856b4d1c61ee8132bcc7d82bd609066ed9ece2554c47f7926f07dd201b6aa",
  "dbname":"alatestdb",
  "class-names":["public.athlete", "public.event", "public.history"],
  "verbose":"y"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |

## Response Sample

```
{
   "__EXEC_TIME" : "320 ms",
   "note" : "none",
   "status" : "success",
   "task" : "compactdb"
}
```

## Response Sample (async mode)
```
{
   "job-status" : "running",
   "note" : "none",
   "status" : "success",
   "uuid" : "14"
}
```

## Response Sample (rejected: database busy)
```
{
   "job-status" : "rejected",
   "note" : "database 'xyz' is busy with another task ('createdb')",
   "status" : "failure",
   "task" : "compactdb"
}
```
