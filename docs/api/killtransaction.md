# killtransaction

Delete transactions, and return the rest of the transactions information.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name |
| type | options from killtransaction command. |
| parameter | a paramter according to the option in "type" field |

type:

```
i -- kill transactions in a specified index. 
u -- kill transactions for a specified user.
h -- kill transactions for a specified host name
p -- kill transactions for a specified program
s -- kill transactions for a specified SQL ID
q -- Displays the query-running status of transactions. 
d  -- display transactions information. it doesn't need parameter.
other letters should cause an error. 
```

## Request Sample

```
{
  "task": "killtransaction",
  "token": "cdfb4c5717170c5eb159540c0384c7424ea3fcd68c6ea615f538801cd09c6f3a7926f07dd201b6aa",
  "dbname": "demodb",
  "type": "i",
  "parameter": "2"
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

```
{
   "__EXEC_TIME" : "1106 ms",
   "dbname" : "demodb",
   "note" : "none",
   "status" : "success",
   "task" : "killtransaction",
   "transactioninfo" : [
      {
         "transaction" : [
            {
               "@user" : "DBA",
               "SQL_ID" : "empty",
               "host" : "ai-work-49",
               "pid" : "1997471",
               "program" : "csql",
               "query_time" : "0.00",
               "tran_time" : "8.60",
               "tranindex" : "2(ACTIVE)",
               "wait_for_lock_holder" : "-1"
            }
         ]
      }
   ]
}
```
