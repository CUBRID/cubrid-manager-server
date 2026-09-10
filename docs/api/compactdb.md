# compactdb

Compact database.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name |
| verbose | on-off indicating whether to show detailed information |

## Request Sample

```
{
  "task":"compactdb",
  "token":"cdfb4c5717170c5e9c6856b4d1c61ee8132bcc7d82bd609066ed9ece2554c47f7926f07dd201b6aa",
  "dbname":"alatestdb",
  "verbose":"y"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |
| log | the output of the compactdb utility |

### log

log is composed of objects with following structure

| **Key** | **Description** |
| --- | --- |
| line | a line of the compactdb output |

## Response Sample

```
{
   "__EXEC_TIME" : "728 ms",
   "log" : [
      {
         "line" : [ "", "Pass 1", "" ]
      }
   ],
   "note" : "none",
   "status" : "success",
   "task" : "compactdb"
}
```

> Lists are shortened to 3 entries here.
