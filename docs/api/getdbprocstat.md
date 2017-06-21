# getdbprocstat

Get databases' information in cubrid.

## Request Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name |

## Request Sample

```
{
  "task": "getdbprocstat",
  "token": "cdfb4c5717170c5e0506c467ad74957c013dd1336cf7d77e9e00525d307c4e367926f07dd201b6aa",
  "dbname": "demodb"
}
```
