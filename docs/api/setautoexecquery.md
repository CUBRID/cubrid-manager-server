# setautoexecquery

Set a configuration of a query automation.

## Request Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name |
| planlist | auto-query plan list |
| queryplan | auto-query plan |
| query_id | auto-query id |
| period | the cycle of auto-query, such as weeky, monthly, everyday and "one". |
| detail | auto-query time (or interval,start with "i", the measurement is minutes) |
| query_string | sql statement |

## Request Sample

```
{
  "task": "setautoexecquery",
  "token": "cdfb4c5717170c5e99586a2763e2b6dce92982faacefb068d7e5a24b9c5fa0a37926f07dd201b6aa",
  "dbname": "alatestdb",
  "planlist": [
    {
      "queryplan": [
        {
          "query_id": "bbaa",
          "username": "dba",
          "userpass": "none",
          "period": "ONE",
          "detail": "$AUTO_QUERY_TIME",
          "query_string": "select * from db_class;"
        }
      ]
    }
  ]
}
```
#
## Response Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |

#
## Response Sample

```
{
   "__EXEC_TIME" : "396 ms",
   "note" : "none",
   "status" : "success",
   "task" : "setautoexecquery",
}
```
