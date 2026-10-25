# gethaapplyinfo

Get copylog and applylog operations information

Permissions required to run this task: none (any logged-in user)

* Paths are limited as described in [File Access](README.md#file-access): only under `$CUBRID` and `$CUBRID_DATABASES`, and never a protected file such as `conf/cm.pass`.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token returned by login |
| dbname | database name |
| copylogpath | ha_copy log file path |
| remotehostname | remote host name |

## Request Sample

```
{
  "task": "gethaapplyinfo",
  "token": "8ec1ab8a91333c789ca635659ff41d6887cec4cd14324d3baee6412d6bbc1277e3e8c307e2088d187926f07dd201b6aa7926f07dd201b6aa7926f07dd201b6aa",
  "dbname": "ha_testdb",
  "copylogpath": "/home/huangqiyu/cubrid_8.4.3/databases/ha_testdb_DEV_92/",
  "remotehostname": "DEV_92"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |
| applyinglog_count | the number of applylog pages |
| applyinglog_estimated_time | estimated time of applylog operation |
| copyinglog_count | the number of copylog pages |
| copyinglog_estimated_time | estimated time of copylog operation |

## Response Sample

```
{
   "applyinglog_count" : "0",
   "applyinglog_estimated_time" : "",
   "copyinglog_count" : "0",
   "copyinglog_estimated_time" : "",
   "note" : "none",
   "status" : "success",
   "task" : "gethaapplyinfo"
}
```
