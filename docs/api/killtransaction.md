# killtransaction

Delete transactions, and return the rest of the transactions information.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name |
| dbuser | database username, must have dba Privileges |
| dbpassword | password for dbuser |
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
  "dbuser": "dbuser1",
  "dbpassword": "1234",
  "_DBPASSWD": "abcd",
  "type": "i",
  "parameter": "2(+)"
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

## Response Sample

```
{
   "__EXEC_TIME" : "35 ms",
   "dbname" : "demodb",
   "note" : "none",
   "status" : "success",
   "task" : "killtransaction",
   "transactioninfo" : 
      {
         "transaction" : [
            {
               "@user" : "DBA",
               "host" : "huangqiyu-VirtualBox",
               "pid" : "6632",
               "program" : "query_editor_cub_cas_1",
               "tranindex" : "1(ACTIVE)"
            }
      }
   ]
}
```
