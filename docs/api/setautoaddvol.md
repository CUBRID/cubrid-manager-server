# setautoaddvol

Set auto addvol option.

## Request Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |

## Request Sample

```
{
  "task": "setautoaddvol",
  "token": "cdfb4c5717170c5e9c6856b4d1c61ee8132bcc7d82bd609066ed9ece2554c47f7926f07dd201b6aa",
  "dbname": "demodb",
  "data": "ON",
  "data_warn_outofspace": "0.05",
  "data_ext_page": "200",
  "index": "ON",
  "index_warn_outofspace": "0.05",
  "index_ext_page": "200"
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
   "__EXEC_TIME" : "72 ms",
    "note" : "none",
   "status" : "success",
   "task" : "setautoaddvol"
}
```
