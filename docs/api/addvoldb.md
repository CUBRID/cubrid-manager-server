# addvoldb

Add new volume.

## Request Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name |
| volname | volume name |
| purpose | generic, data, index, temp |
| size_need_mb | size of MB |

## Request Sample

```
{
  "task":"addvoldb",
  "dbname":"demodb",
  "volname":"testvol",
  "purpose":"generic",
  "size_need_mb":"500(MB)"
}
```

## Response Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |

## Response Sample

```
{
  "__EXEC_TIME": "72 ms",
  "note": "none",
  "status": "success",
  "task": "addvoldb"
}
```
