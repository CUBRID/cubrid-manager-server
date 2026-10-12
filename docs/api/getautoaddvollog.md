# getautoaddvollog

Get auto addvoldb logs.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| start_time | the beginning of the period, in the `YYYY-MM-DD HH:MM:SS` form |
| end_time | the end of the period, in the `YYYY-MM-DD HH:MM:SS` form |


## Request Sample

```
{
  "task": "getautoaddvollog",
  "token": "cdfb4c5717170c5e9c6856b4d1c61ee8132bcc7d82bd609066ed9ece2554c47f7926f07dd201b6aa"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |
| log | the list of the automatic volume extensions of the requested period |

### log

log is composed of objects with following structure

| **Key** | **Description** |
| --- | --- |
| dbname | database name |
| volname | the name of the volume which has been added |
| purpose | the purpose of the volume, data, index, temp or generic |
| page | the number of the pages which have been added |
| time | the time the volume was added |
| outcome | the result of the extension |

## Response Sample

```
{
   "__EXEC_TIME" : "0 ms",
   "note" : "none",
   "status" : "success",
   "task" : "getautoaddvollog"
}
```
