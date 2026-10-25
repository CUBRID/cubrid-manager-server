# shard_start

Start shards or turn on a shard.

Permissions required to run this task: one of DBC, DBO, BRK

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token returned by login |
| shardname | turn on a shard if a shardname is defined. |

## Request Sample

```
{
  "task": "shard_start",
  "token": "4504b930fc1be99bf5dfd31fc5799faaa3f117fb903f397de087cd3544165d857926f07dd201b6aa",
  "shardname": "demoshard1"
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
   "task" : "shard_start"
}
```
