# lockdb

Runs lockdb utility.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name |

## Request Sample

```
{
  "task": "lockdb",
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
| lockinfo | the lock information of the database |

### lockinfo

lockinfo holds the global lock configuration and the list of the transactions and of the locked
objects which the `cubrid lockdb` utility reports.

| **Key** | **Description** |
| --- | --- |
| esc | the lock escalation threshold |
| dinterval | the deadlock detection interval, in milliseconds |
| maxnumlock | the maximum number of the locks |
| transaction | the list of the transactions which hold or wait for a lock |
| tran_index | the index of the transaction |
| pname | the name of the program which opened the transaction |
| pid | the process id of that program |
| host | the host the program runs on |
| isolevel | the isolation level of the transaction |
| granted_mode | the lock mode which has been granted |
| timeout | the lock timeout of the transaction |
| lot | the list of the locked objects |
| entry | an entry of the lock table of one object |
| oid | the oid of the locked object |
| ob_type | the type of the locked object |
| num_holders | the number of the transactions which hold the lock |
| num_b_holders | the number of the transactions which hold the lock in a blocked state |
| num_waiters | the number of the transactions which wait for the lock |
| lock_holders | the list of the transactions which hold the lock |
| b_holders | the list of the transactions which hold the lock in a blocked state |
| waiters | the list of the transactions which wait for the lock |

## Response Sample

```
{
   "__EXEC_TIME" : "60 ms",
   "lockinfo" : [
      {
         "dinterval" : "1.00",
         "esc" : "100000",
         "lot" : [
            {
               "maxnumlock" : "-1",
               "numallocated" : "1000",
               "numlocked" : "0",
               "sizelock" : "242K"
            }
         ],
         "transaction" : [
            {
               "@uid" : "",
               "host" : "",
               "index" : "0",
               "isolevel" : "COMMITTED READ",
               "pid" : "0",
               "pname" : "",
               "timeout" : ":"
            },
            {
               "@uid" : "DBA",
               "host" : "ai-work-49",
               "index" : "1",
               "isolevel" : "COMMITTED READ",
               "pid" : "1997884",
               "pname" : "lockdb",
               "timeout" : ":"
            }
         ]
      }
   ],
   "note" : "none",
   "status" : "success",
   "task" : "lockdb"
}
```
