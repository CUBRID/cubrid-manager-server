# loaddb

The loaddb interface will load a database from files.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | a name of the database |
| checkoption | check syntax for data file or not |
| period | insertion COUNT for periodic commit |
| user | load databases user name |
| estimated | estimated NUMBER of instances; default:none |
| oiduse | use OID |
| nolog | don’t create log |
| schema | schema file path |
| object | object file path |
| index | index file path |
| errorcontrolfile | FILE to control error(s) during loading |
| ignoreclassfile | input file of class names that skip load |
| no-user-specified-name | Find classes, serials, and triggers by their object names without their owner names |
| schema-file-list | name of schema-file-list, list of schema file names to be used in loaddb |
| delete_orignal_files | delete original file after load |
| async | default "no", if "yes" run the task in asynchronous mode |

* The status of a task running in asynchronous mode can be checked using the 'gettaskstatus' api

## Request Sample

```
{
  "task": "loaddb",
  "token": "cdfb4c5717170c5e34919b640249979f8375a218acf865b0b8100f0f25c069587926f07dd201b6aa",
  "dbname": "alatestdb",
  "checkoption": "both",
  "period": "none",
  "user": "dba",
  "estimated": "none",
  "oiduse": "yes",
  "nolog": "no",
  "schema": "$CUBRID_DATABASES/demodb/demodb_schema",
  "object": "$CUBRID_DATABASES/demodb/demodb_objects",
  "index": "none",
  "errorcontrolfile": "none",
  "ignoreclassfile": "none",
  "delete_orignal_files": "y",
  "async":"yes"
}
```

## Response Sample (async mode)
```
{
   "job-status" : "running",
   "note" : "none",
   "status" : "success",
   "task" : "loaddb",
   "uuid" : "14"
}
```
