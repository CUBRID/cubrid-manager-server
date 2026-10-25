# dbspace

Get the volume information of several databases at once. It returns, for every database of the
`dblist`, the same information as [dbspaceinfo](dbspaceinfo.md). A database which cannot be read
is skipped, it does not make the whole request fail.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dblist | the list of the database names |

## Request Sample

```
{
  "task": "dbspace",
  "token": "cdfb4c5717170c5e9c6856b4d1c61ee8132bcc7d82bd609066ed9ece2554c47f7926f07dd201b6aa",
  "dblist": [
    {
      "dbname": "demodb"
    },
    {
      "dbname": "testdb"
    }
  ]
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |
| <dbname> | the volume information of the database, the key is the database name itself. Its contents are the same as the response of [dbspaceinfo](dbspaceinfo.md) |

## Response Sample

```
{
   "__EXEC_TIME" : "38 ms",
   "demodb" : [
      {
         "dbname" : "demodb",
         "freespace" : "1023",
         "logpagesize" : "16384",
         "pagesize" : "16384",
         "spaceinfo" : [
            {
               "date" : "2026.08.11",
               "freepage" : "639",
               "location" : "/home/cubrid/CUBRID/databases/demodb",
               "totalpage" : "4096",
               "type" : "GENERIC",
               "vol" : "demodb"
            }
         ]
      }
   ],
   "note" : "none",
   "status" : "success",
   "task" : "dbspace"
}
```
