# gettransactioninfo

The gettransactioninfo interface fetches databases transactions information.

## Request Json Syntax

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

## Response Json Syntax

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
   "task" : "gettransactioninfo",
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
