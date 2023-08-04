# unloaddb

The unloaddb interface will unload database server.

## Request Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | a name of the database |
| targetdir | PATH of output directory |
| usehash | whether use hash file, (yes/no), if yes, hashdir is valid. |
| hashdir | FILE for hash; default: generate by tmpnam() |
| target | unload schema/object or both |
| class | unload class list |
| classname | unload class name |
| ref | include referenced tables; |
| classonly | include specified class only |
| as-dba | extract the same schema file as the DBA |
| skip-index-detail | skip index deduplicate info |
| split-schema-files | split schema information by object |
| delimit | use '"' where an identifier begins and ends; default: don't use |
| estimate | estimated NUMBER of instances; default: auto computed |
| prefix | PREFIX for output files; default: the database name |
| cach | NUMBER of cached pages; default: 100 |
| lofile | lo file COUNT per a directory; default: 0 |

## Request Sample

```
{
  "task": "unloaddb",
  "token": "cdfb4c5717170c5e34919b640249979f8375a218acf865b0b8100f0f25c069587926f07dd201b6aa",
  "dbname": "demodb",
  "targetdir": "$CUBRID_DATABASES/demodb",
  "usehash": "no",
  "hashdir": "none",
  "target": "both",
  "class": [
    {
      "classname": "code"
    }
  ],
  "ref": "no",
  "classonly": "no",
  "delimit": "no",
  "estimate": "none",
  "prefix": "none",
  "cach": "none",
  "lofile": "none"
}
```
