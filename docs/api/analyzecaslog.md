# analyzecaslog

The analyzecaslog interface will fetch top list to parse broker sql log(s) with the broker_log_top utility.

## Request Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |

## Request Sample

```
{
  "task": "analyzecaslog",
  "token": "cdfb4c5717170c5e9c6856b4d1c61ee8132bcc7d82bd609066ed9ece2554c47f7926f07dd201b6aa",
  "logfilelist": [
    {
      "logfile": "$CUBRID/log/broker/sql_log/query_editor_1.sql.log"
    }
  ],
  "option_t": "yes"
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
   "task" : "analyzecaslog"
}
```
