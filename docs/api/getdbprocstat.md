# getdbprocstat

Get database process statistics.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name |

## Request Sample

```
{
  "task": "getdbprocstat",
  "token": "cdfb4c5717170c5e0506c467ad74957c013dd1336cf7d77e9e00525d307c4e367926f07dd201b6aa",
  "dbname": "demodb"
}
```

## Response JSON Syntax
| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |
| dbstat | information of database status |


### dbstat
dbstat is composed of objects with following structure

| **Key** | **Description** |
| --- | --- |
| cpu_kernel | |
| cpu_user | |
| dbname | name of database |
| mem_physical | |
| mem_virtual | |



## Response Sample

```
{
   "__EXEC_TIME" : "13 ms",
   "dbstat" : [
      {
         "cpu_kernel" : "165147",
         "cpu_user" : "162071",
         "dbname" : "ha_test",
         "mem_physical" : "549388288",
         "mem_virtual" : "2784587776"
      }
   ],
   "note" : "none",
   "status" : "success",
   "task" : "getdbprocstat"
}
```
