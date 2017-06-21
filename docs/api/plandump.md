# plandump

Run plandump utility.

## Request Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name |
| plandrop | y : drop plans |

## Request Sample

```
{
  "task": "plandump",
  "token": "cdfb4c5717170c5e2d40a680732333064610bcfeec1c0d870c43c1586a92dd1f7926f07dd201b6aa",
  "dbname": "demodb",
  "plandrop": "y"
}
```
