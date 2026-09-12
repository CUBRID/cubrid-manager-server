# ha_reload

Runs `cubrid heartbeat reload` command.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| async | default "no", if "yes" run the task in asynchronous mode |

* The status of a task running in asynchronous mode can be checked using the 'gettaskstatus' api

## Request Sample

```
{
 "task":"ha_reload",
 "token":"4504b930fc1be99bf5dfd31fc5799faaa3f117fb903f397de087cd3544165d857926f07dd201b6aa",
 "async":"yes"
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
   "__EXEC_TIME" : "72 ms",
   "note" : "none",
   "status" : "success",
   "task" : "ha_reload"
}
```

## Response Sample (async mode)
```
{
   "job-status" : "running",
   "note" : "none",
   "status" : "success",
   "task" : "ha_reload",
   "uuid" : "14"
}
```
