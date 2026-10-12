# gettransactioninfo

The gettransactioninfo interface fetches database transaction information.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name |

## Request Sample

```
{
  "task": "gettransactioninfo",
  "token": "cdfb4c5717170c5e9c6856b4d1c61ee8132bcc7d82bd609066ed9ece2554c47f7926f07dd201b6aa",
  "dbname": "demodb"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |
| dbname | database name |
| transactioninfo | transaction information list |
| transaction | transaction list |
| tranindex | transaction flag |
| user | user name |
| host | host name |
| pid | process id |
| program | process name |
| query_time | the elapsed time of the running query |
| tran_time | the elapsed time of the transaction |
| SQL_ID | the id of the running SQL |
| SQL_Text | the text of the running SQL |
| wait_for_lock_holder | the transaction indexes this transaction waits for |

## Response Sample

```json
{
   "__EXEC_TIME" : "49 ms",
   "dbname" : "demodb",
   "note" : "none",
   "status" : "success",
   "task" : "gettransactioninfo",
   "transactioninfo" : [
      {
         "transaction" : [
            {
               "@user" : "DBA",
               "SQL_ID" : "empty",
               "host" : "ai-work-49",
               "pid" : "2381237",
               "program" : "csql",
               "query_time" : "0.00",
               "tran_time" : "6.00",
               "tranindex" : "1(ACTIVE)",
               "wait_for_lock_holder" : "-1"
            },
            {
               "@user" : "DBA",
               "SQL_ID" : "empty",
               "host" : "ai-work-49",
               "pid" : "2381236",
               "program" : "csql",
               "query_time" : "0.00",
               "tran_time" : "6.00",
               "tranindex" : "2(ACTIVE)",
               "wait_for_lock_holder" : "-1"
            }
         ]
      }
   ]
}
```
