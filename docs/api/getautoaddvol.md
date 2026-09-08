# getautoaddvol

Get auto addvol info.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name. |

## Request Sample

```
{
  "task": "getautoaddvol",
  "token": "cdfb4c5717170c5e9c6856b4d1c61ee8132bcc7d82bd609066ed9ece2554c47f7926f07dd201b6aa",
  "dbname": "demodb"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |
| data | ON or OFF, the automatic extension of the data volume is enabled |
| data_warn_outofspace | the free space ratio which triggers the extension of the data volume |
| data_ext_page | the number of the pages added to the data volume at every extension |
| index | ON or OFF, the automatic extension of the index volume is enabled |
| index_warn_outofspace | the free space ratio which triggers the extension of the index volume |
| index_ext_page | the number of the pages added to the index volume at every extension |

## Response Sample

```
{
   "__EXEC_TIME" : "3 ms",
   "data" : "ON",
   "data_ext_page" : "200",
   "data_warn_outofspace" : "0.05",
   "index" : "ON",
   "index_ext_page" : "200",
   "index_warn_outofspace" : "0.05",
   "note" : "none",
   "status" : "success",
   "task" : "getautoaddvol"
}
```
