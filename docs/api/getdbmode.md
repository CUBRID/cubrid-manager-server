# getdbmode

Get database mode.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dblist | database name |

## Request Sample

```
{
  "task": "getdbmode",
  "token": "cdfb4c5717170c5e6f12e5b1643a2b67132bcc7d82bd6090e92a55cddd5950db7926f07dd201b6aa",
  "dblist": "demodb"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |
| dbserver | the list of the requested databases and of their mode |

### dbserver

dbserver is composed of objects with following structure

| **Key** | **Description** |
| --- | --- |
| dbname | database name |
| server_mode | the HA mode of the database server: active, standby, maintenance or unknown |
| server_msg | the message returned with the mode, it is empty when there is none |

## Response Sample

```
{
   "__EXEC_TIME" : "27 ms",
   "dbserver" : [
      {
         "dbname" : "demodb",
         "server_mode" : "CS-mode",
         "server_msg" : "none"
      }
   ],
   "note" : "none",
   "status" : "success",
   "task" : "getdbmode"
}
```
