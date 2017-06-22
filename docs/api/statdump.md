# statdump

Get database statistics from a statdump utility.

## Request Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name |

## Request Sample

```
{
  "task": "statdump",
  "token": "cdfb4c5717170c5e2d40a680732333064610bcfeec1c0d870c43c1586a92dd1f7926f07dd201b6aa",
  "dbname": "demodb"
}
```
