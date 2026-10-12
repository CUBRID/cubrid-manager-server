# setautoexecquery

Set a configuration of a query automation.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name |
| planlist | auto-query plan list |
| queryplan | auto-query plan |
| query_id | auto-query id |
| period | the cycle of auto-query, such as weekly, monthly, everyday and "one". |
| detail | auto-query time (or interval,start with "i", the measurement is minutes) |
| query_string | sql statement |

## Description of 'period', 'detail'

* **period**: the period must be one of the following values
  * ONE: execute once at a specific date
  * DAY: execute at a specific time every day
  * WEEK: execute on a specific day every week
  * MONTH: execute on specific days of each month

* **detail**: specify the time to execute (**must have two fields**: date and time).
  * if *period* is 'ONE', 'date' refers to specific date on which the task is to be executed <br>
  (for example, 'ONE', '2026/09/12 12:30')
  * if *period* is 'MONTH', 'date' refers to the day within the month on which the task is to be executed. <br>
  (for example, 'MONTH', '1 12:00')
  * if *period* is 'WEEK', 'date' is one of ('SUN', 'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT') <br>
  (for example, 'WEEK', 'MON 12:00')
  * if *period* is 'DAY', 'date' is 'EVERYDAY' <br>
  (for example 'DAY', 'EVERYDAY 12:30')

  * for repeated execution, specify the time duration in seconds, starting with 'i'.
  (for example if a query should be executed at every 60 seconds, 'DAY', 'EVERYDAY i60')
## Request Sample: ONCE

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
          "detail": "2026/09/12 12:30",
          "query_string": "select * from db_class;"
        }
      ]
    }
  ]
}
```
## Request Sample: execute once a Month
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
          "period": "MONTH",
          "detail": "1 12:30",
          "query_string": "select * from db_class;"
        }
      ]
    }
  ]
}
```

## Request Sample: execute at every 60 seconds
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
          "period": "DAY",
          "detail": "EVERYDAY i60",
          "query_string": "select * from db_class;"
        }
      ]
    }
  ]
}
```


#
## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |

#
## Response Sample

```json
{
   "__EXEC_TIME" : "396 ms",
   "note" : "none",
   "status" : "success",
   "task" : "setautoexecquery"
}
```
