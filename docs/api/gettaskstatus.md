# gettaskstatus

Check the status of a task asynchronously running

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| uuid | uuid from the asynchronous task response |


## Request Sample

```
{
  "task": "gettaskstatus",
  "token": "cdfb4c5717170c5e237a227a2ceeccc6ae9e10c16754fb85371c0d74fa0d9d577926f07dd201b6aa",
  "uuid":"$UUID"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| job-status | one of running, success, error |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |
| uuid | uuid given in the request |


## Response Sample if task is running

```
{
   "job-status" : "running",
   "note" : "none",
   "status" : "success",
   "uuid" : "14"
}
```

## Response Sample if task is completed successfully
```
{
   "__EXEC_TIME" : "66860 ms",
   "job-status" : "success",
   "note" : "none",
   "status" : "success",
   "task" : "createdb",
   "uuid" : "14"
}
```
## Response Sample if task is completed with error
```
{
   "__EXEC_TIME" : "26 ms",
   "job-status" : "error",
   "note" : "Couldn't create database.<end>Database \"testdb\" already exists.<end>",
   "status" : "failure",
   "task" : "createdb",
   "uuid" : "14"
}
```

## Response Sample with invalid uuid
```
{
   "note" : "invalid uuid",
   "status" : "failure"
}
```
