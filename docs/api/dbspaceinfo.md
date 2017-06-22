# dbspaceinfo

Get specified database space information.

## Request Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted |
| dbname | database name |

## Request Sample

```
{
  "task":"dbspaceinfo",
  "token":"cdfb4c5717170c5e237a227a2ceeccc6ae9e10c16754fb85371c0d74fa0d9d577926f07dd201b6aa",
  "dbname":"alatestdb"
}
```

## Response Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed |
| note | if failed, a brief description will be given here |
| dbname | database name |
| pagesize | the size of each page |
| spaceinfo | database space information |
| spacename | volume name |
| type | volume type |
| location | volume file path |
| totalpage | the total of pages |
| freepage | the total of avaliable pages |
| date | volume file created time |
| freespace | the total of free space |

## Response Sample

```
{
   "__EXEC_TIME" : "160 ms",
   "dbname" : "testdb",
   "freespace" : "7300",
   "logpagesize" : "16384",
   "note" : "none",
   "pagesize" : "16384",
   "spaceinfo" : 
      {
         "date" : "20130131",
         "freepage" : "1192",
         "location" : "/home/huangqiyu/cubrid_8.4.3/databases/testdb",
         "spacename" : "testdb",
         "totalpage" : "1280",
         "type" : "GENERIC"
      },
      {
         "date" : "20130131",
         "freepage" : "0",
         "location" : "/home/huangqiyu/cubrid_8.4.3/databases/testdb",
         "spacename" : "testdb_v1",
         "totalpage" : "1000",
         "type" : "DATA"
      },
      {
         "date" : "20130131",
         "freepage" : "1746",
         "location" : "/home/huangqiyu/cubrid_8.4.3/databases/testdb",
         "spacename" : "testdb_x002",
         "totalpage" : "1920",
         "type" : "DATA"
      },
      {
         "date" : "20130131",
         "freepage" : "385",
         "location" : "/home/huangqiyu/cubrid_8.4.3/databases/testdb",
         "spacename" : "testdb_t32766",
         "totalpage" : "434",
         "type" : "TEMP"
      },
      {
         "date" : "20130201",
         "freepage" : " ",
         "location" : "/home/huangqiyu/cubrid_8.4.3/databases/testdb",
         "spacename" : "testdb_lgat",
         "totalpage" : "32768",
         "type" : "Active_log"
      },
      {
         "date" : "20130131",
         "freepage" : " ",
         "location" : "/home/huangqiyu/cubrid_8.4.3/databases/testdb",
         "spacename" : "testdb_lgar_t",
         "totalpage" : "32768",
         "type" : "Archive_log"
      },
      {
         "date" : "",
         "freepage" : "0",
         "location" : "",
         "spacename" : "Total",
         "totlapage" : "0",
         "type" : ""
      }
   ,
   "status" : "success",
   "task" : "dbspaceinfo"
}
```
