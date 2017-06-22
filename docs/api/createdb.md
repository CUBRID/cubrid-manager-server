# createdb

Create database.

## Request Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name |
| numpage | the number of pages |
| pagesize | the size of each page |
| logsize | the size of log volume |
| genvolpath | data volume path |
| logvolpath | log volume path |
| exvol | extend volume information |
| charset | language and charset, ex. en_US.iso88591, ko_KR.utf8. please refer to $CUBRID/conf/cubrid_locales.all.txt |

## Request Sample

```
{
   "task":"createdb",
   "token":"cdfb4c5717170c5e237a227a2ceeccc6ae9e10c16754fb85371c0d74fa0d9d577926f07dd201b6aa",
   "dbname":"alatestdb",
   "numpage":"10240",
   "pagesize":"4096",
   "logsize":"10240",
   "logpagesize":"4096",
   "genvolpath":"$CUBRID_DATABASES/alatestdb",
   "logvolpath":"$CUBRID_DATABASES/alatestdb",
   "exvol":{"alatestdb_data_x001":"data;100;$CUBRID_DATABASES/alatestdb"},
   "charset":"en_US.utf8",
   "overwrite_config_file":"YES"
 }
```

## Response Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |

## Response Sample

```
{
   "__EXEC_TIME" : "3593 ms",
   "note" : "none",
   "status" : "success",
   "task" : "createdb"
}
```

# Version 8.4.1, 8.4.3, 9.1.0

Create database.

## Request Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name |
| numpage | the number of pages |
| pagesize | the size of each page |
| logsize | the size of log volume |
| genvolpath | data volume path |
| logvolpath | log volume path |
| exvol | extend volume information |

## Request Sample

```
{
  "task":"createdb",
  "token":"cdfb4c5717170c5e237a227a2ceeccc6ae9e10c16754fb85371c0d74fa0d9d577926f07dd201b6aa",
  "dbname":"alatestdb",
  "numpage":"10240",
  "pagesize":"4096",
  "logsize":"10240",
  "logpagesize":"4096",
  "genvolpath":"$CUBRID_DATABASES/alatestdb",
  "logvolpath":"$CUBRID_DATABASES/alatestdb",
  "exvol":{"alatestdb_data_x001":"data;100;$CUBRID_DATABASES/alatestdb"},
  "overwrite_config_file":"YES"
}
```

## Response Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |

## Response Sample

```
{
   "__EXEC_TIME" : "3593 ms",
   "note" : "none",
   "status" : "success",
   "task" : "createdb"
}
```
