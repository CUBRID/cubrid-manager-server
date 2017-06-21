# getloginfo

Get database log file information.

## Request Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name |

## Request Sample

```
{
  "task":"getloginfo",
  "token":"cdfb4c5717170c5e9c6856b4d1c61ee8132bcc7d82bd609066ed9ece2554c47f7926f07dd201b6aa",
  "dbname":"demodb"
}
```

## Response Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |
| dbname | database name |
| path | database log file path |
| @owner | database owner |
| size | the size of log file |
| lastupdate | update time |

## Response Sample

```
{
   "__EXEC_TIME" : "39 ms",
   "dbname" : "testdb",
   "loginfo" : 
      {
         "log" : [
            {
               "@owner" : "huangqiyu",
               "lastupdate" : "2013.01.07",
               "path" : "/home/huangqiyu/cubrid_8.4.3/log/server/testdb_20130107_1419.err",
               "size" : "0"
            },
            {
               "@owner" : "huangqiyu",
               "lastupdate" : "2013.01.31",
               "path" : "/home/huangqiyu/cubrid_8.4.3/log/server/testdb_20130131_1823.err",
               "size" : "0"
            },
            {
               "@owner" : "huangqiyu",
               "lastupdate" : "2013.01.07",
               "path" : "/home/huangqiyu/cubrid_8.4.3/log/server/testdb_20130107_1453.err",
               "size" : "0"
            },
            {
               "@owner" : "huangqiyu",
               "lastupdate" : "2013.01.15",
               "path" : "/home/huangqiyu/cubrid_8.4.3/log/server/testdb_20130115_1028.err",
               "size" : "0"
            },
            {
               "@owner" : "huangqiyu",
               "lastupdate" : "2013.01.10",
               "path" : "/home/huangqiyu/cubrid_8.4.3/log/server/testdb_20130110_1528.err",
               "size" : "0"
            },
            {
               "@owner" : "huangqiyu",
               "lastupdate" : "2013.01.05",
               "path" : "/home/huangqiyu/cubrid_8.4.3/log/server/testdb_20130105_1628.err",
               "size" : "0"
            },
            {
               "@owner" : "huangqiyu",
               "lastupdate" : "2013.01.05",
               "path" : "/home/huangqiyu/cubrid_8.4.3/log/server/testdb_20130105_1140.err",
               "size" : "9629"
            },
            {
               "@owner" : "huangqiyu",
               "lastupdate" : "2013.01.10",
               "path" : "/home/huangqiyu/cubrid_8.4.3/log/server/testdb_20130110_1526.err",
               "size" : "0"
            },
            {
               "@owner" : "huangqiyu",
               "lastupdate" : "2013.01.05",
               "path" : "/home/huangqiyu/cubrid_8.4.3/log/server/testdb_20130105_1525.err",
               "size" : "0"
            },
            {
               "@owner" : "huangqiyu",
               "lastupdate" : "2013.01.07",
               "path" : "/home/huangqiyu/cubrid_8.4.3/log/server/testdb_20130107_1350.err",
               "size" : "0"
            },
            {
               "@owner" : "huangqiyu",
               "lastupdate" : "2013.01.11",
               "path" : "/home/huangqiyu/cubrid_8.4.3/log/server/testdb_20130111_1453.err",
               "size" : "0"
            }
      }
   ],
   "note" : "none",
   "status" : "success",
   "task" : "getloginfo"
}
```
