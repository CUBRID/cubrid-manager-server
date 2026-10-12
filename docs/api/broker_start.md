# broker_start

The broker_start interface will start a specified broker.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| bname | the name of the broker to be started |
| async | default "no", if "yes" run the task in asynchronous mode |

* The status of a task running in asynchronous mode can be checked using the 'gettaskstatus' api

## Request Sample

```
{
  "task": "broker_start",
  "token": "cdfb4c5717170c5e9c6856b4d1c61ee8132bcc7d82bd609066ed9ece2554c47f7926f07dd201b6aa",
  "bname": "broker1",
  "async":"yes"
}
```

## Response Sample (async mode)
```
{
   "job-status" : "running",
   "note" : "none",
   "status" : "success",
   "task" : "broker_start",
   "uuid" : "1877908931382247367"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |

## Response Sample

```
{
   "__EXEC_TIME" : "12 ms",
   "note" : "none",
   "status" : "success",
   "task" : "broker_start"
}
```
