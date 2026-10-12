# getaddvolstatus

Get volume status.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |

## Request Sample

```
{
  "task": "getaddvolstatus",
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
| volpath | the directory the database volumes are created in |
| freespace | the free space of that directory, in MB |

## Response Sample

```
{
   "__EXEC_TIME" : "1 ms",
   "freespace" : "450720",
   "note" : "none",
   "status" : "success",
   "task" : "getaddvolstatus",
   "volpath" : "/home/cubrid/CUBRID-11.5.0.2441-6ba9522-Linux.x86_64/databases/demodb"
}
```
