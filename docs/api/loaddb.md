# loaddb

The loaddb interface will load database from files.

## Request Json Syntax

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
| delete_orignal_files | delete original file after load |

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
  "delete_orignal_files": "y"
}
```
