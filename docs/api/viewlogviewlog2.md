# viewlog/viewlog2

Viwe specified log file.

## Request Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| path | log file path |
| start | the line number at the beginning |
| end | the line number at the end |

## Request Sample

```
{
  "task":"viewlog",
  "token":"cdfb4c5717170c5e9c6856b4d1c61ee8132bcc7d82bd609066ed9ece2554c47f7926f07dd201b6aa",
  "dbname":"demodb",
  "path":"$CUBRID/log/manager/cub_js.access.log",
  "start":"1",
  "end":"1000"
}
```

## Response Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |
| line | the content of log file |
| log | log file list |

## Response Sample

```
{
   "__EXEC_TIME" : "9 ms",
   "end" : "27",
   "log" : 
      {
         "line" : [
            "",
            "Time: 01/07/13 14:43:11.682 - ERROR *** file ../../src/transaction/boot_sr.c, line 2841 ERROR CODE = -4 Tran = -1, EID = 1",
            "Has been interrupted.",
            "",
            "*** The previous error message is the last one. ***",
            "",
            "",
            "Time: 01/07/13 14:44:05.820 - ERROR *** file ../../src/transaction/boot_sr.c, line 1337 ERROR CODE = -129 Tran = -1, EID = 1",
            "Unknown token \"comment\" was found on line 1.",
            "",
            "Time: 01/07/13 14:44:05.820 - ERROR *** file ../../src/transaction/boot_sr.c, line 1354 ERROR CODE = -128 Tran = -1, EID = 2",
            "Number of pages was not given on line 1.",
            "",
            "Time: 01/07/13 14:44:06.484 - ERROR *** file ../../src/transaction/boot_sr.c, line 2827 ERROR CODE = -123 Tran = -1, EID = 3",
            "Unable to create \"allvols\" for database \"/home/huangqiyu/cubrid_8.4.3/databases/testdb/testdb\".",
            "",
            "*** The previous error message is the last one. ***",
            "",
            "",
            "Time: 01/07/13 14:45:25.133 - ERROR *** file ../../src/transaction/boot_sr.c, line 1354 ERROR CODE = -128 Tran = -1, EID = 1",
            "Number of pages was not given on line 1.",
            "",
            "Time: 01/07/13 14:45:25.822 - ERROR *** file ../../src/transaction/boot_sr.c, line 2827 ERROR CODE = -123 Tran = -1, EID = 2",
            "Unable to create \"allvols\" for database \"/home/huangqiyu/cubrid_8.4.3/databases/testdb/testdb\".",
            "",
            "*** The previous error message is the last one. ***",
            ""
      }
   ],
   "note" : "none",
   "path" : "/home/huangqiyu/cubrid_8.4.3/log/testdb_createdb.err",
   "start" : "1",
   "status" : "success",
   "task" : "viewlog",
   "total" : "27"
}
```
