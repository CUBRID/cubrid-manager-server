# updatestatustemplate

Update an existing monitoring status template. Only the template whose name matches `name` is rewritten, the other templates of the
configuration file are kept unchanged.

A template describes which monitoring items are sampled, at which interval, and how they are
displayed. The items are given in `target_config`, where the key is the name of the monitoring
item and the value is `<color> <magnification>`.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| name | the name of the status template |
| desc | the description of the status template |
| db_name | the name of the database which is monitored |
| sampling_term | the sampling interval, in seconds |
| target_config | the list of the monitoring items of the template |

### target_config

target_config is composed of objects whose key is the name of a monitoring item and whose value
is the display configuration of that item, `<color> <magnification>`.

## Request Sample

```
{
  "task": "updatestatustemplate",
  "token": "cdfb4c5717170c5e9c6856b4d1c61ee8132bcc7d82bd609066ed9ece2554c47f7926f07dd201b6aa",
  "name": "dbserver_clier_requet",
  "desc": "client_request",
  "db_name": "demodb",
  "sampling_term": "5",
  "target_config": [
    {
      "server_conn_cli_request": "1 1"
    }
  ]
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
   "__EXEC_TIME" : "5 ms",
   "note" : "none",
   "status" : "success",
   "task" : "updatestatustemplate"
}
```
