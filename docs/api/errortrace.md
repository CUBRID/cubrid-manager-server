# errortrace

Get the error block which matches the given error id and error time from a CUBRID error log file.
A block is returned only when it contains both `EID = <eid>` and `<errtime> (`.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| logpath | the full path of the error log file |
| eid | error id to be traced |
| errtime | the time the error occurred |

## Request Sample

```
{
  "task": "errortrace",
  "token": "cdfb4c5717170c5e9c6856b4d1c61ee8132bcc7d82bd609066ed9ece2554c47f7926f07dd201b6aa",
  "logpath": "$CUBRID/log/server/demodb_20130107_1419.err",
  "eid": "1",
  "errtime": "01/07/13 14:43:11.682"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |
| errbloc | the lines of the matched error block |

### errbloc

errbloc is composed of objects with following structure

| **Key** | **Description** |
| --- | --- |
| line | a line of the error block |

## Response Sample

```
{
   "__EXEC_TIME" : "5 ms",
   "errbloc" : [
      {
         "line" : "Time: 01/07/13 14:43:11.682 - ERROR *** file ../../src/transaction/boot_sr.c, line 2841 ERROR CODE = -4 Tran = -1, EID = 1"
      },
      {
         "line" : "Has been interrupted."
      }
   ],
   "note" : "none",
   "status" : "success",
   "task" : "errortrace"
}
```
