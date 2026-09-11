# unloadinfo

Get the result of the previous [unloaddb](unloaddb.md) executions. The information is read from
the `$CUBRID_DATABASES/unloaddb.info` file, which [unloaddb](unloaddb.md) writes. When that file
does not exist, the request succeeds and returns no database entry.

Every unloaded file is reported with its path and its modification time, separated by a
semicolon: `<path>;<YYYY.MM.DD HH:MM>`. A file which has been deleted since it was unloaded is
not reported.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |

## Request Sample

```
{
  "task": "unloadinfo",
  "token": "cdfb4c5717170c5e9c6856b4d1c61ee8132bcc7d82bd609066ed9ece2554c47f7926f07dd201b6aa"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |
| database | the list of the databases which have been unloaded |

### database

database is composed of objects with following structure

| **Key** | **Description** |
| --- | --- |
| dbname | database name |
| schema | the schema file, in the `<path>;<lastupdate>` form |
| object | the object file, in the `<path>;<lastupdate>` form |
| index | the index file, in the `<path>;<lastupdate>` form |
| trigger | the trigger file, in the `<path>;<lastupdate>` form |

## Response Sample

```
{
   "__EXEC_TIME" : "0 ms",
   "database" : [
      {
         "dbname" : "demodb",
         "object" : "/home/cubrid/CUBRID-11.5.0.2441-6ba9522-Linux.x86_64/databases/demodb/demodb_objects;2026.08.18 09:08",
         "schema" : "/home/cubrid/CUBRID-11.5.0.2441-6ba9522-Linux.x86_64/databases/demodb/demodb_schema;2026.08.18 09:08"
      }
   ],
   "note" : "none",
   "status" : "success",
   "task" : "unloadinfo"
}
```
