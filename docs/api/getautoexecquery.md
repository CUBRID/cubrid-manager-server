# getautoexecquery

Get auto execution query information.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |

## Request Sample

```
{
  "task": "getautoexecquery",
  "token": "cdfb4c5717170c5e9c6856b4d1c61ee8132bcc7d82bd609066ed9ece2554c47f7926f07dd201b6aa",
  "dbname": "alatestdb"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |
| dbname | database name |
| planlist | the list of the auto-execute query plans of the database |

### planlist

planlist is composed of `queryplan` objects with following structure

| **Key** | **Description** |
| --- | --- |
| query_id | the id of the auto-execute query plan |
| username | the database user which executes the query |
| period | the cycle of the execution, such as EVERYDAY, WEEK, MONTH or ONE |
| detail | the execution time inside that cycle |
| query_string | the query which is executed |

## Response Sample

```
{
   "__EXEC_TIME" : "0 ms",
   "note" : "none",
   "planlist" : [
      {
         "dbname" : "alatestdb",
         "queryplan" : [
            {
               "@username" : "dba",
               "detail" : "2026/08/18 09:09",
               "period" : "ONE",
               "query_id" : "bbaa",
               "query_string" : "select * from db_class;"
            }
         ]
      }
   ],
   "status" : "success",
   "task" : "getautoexecquery"
}
```
