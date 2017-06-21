# class

The class interface will get summary databases class information.

## Request Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name |
| classname | database table name |

## Request Sample

```
{
  "task":"class",
  "token":"cdfb4c5717170c5ed30ef86644baf8151531ce5adff4a1f9a54711c51e0f50767926f07dd201b6aa",
  "dbname":"demodb",
  "classname":"athlete"
}
```

## Response Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |
| classinfo | database table information |
| dbname | database name |
| classname | database table name |
| type | field type |
| owner | database table owner |
| virtual | indicate whether it is a view |
| attribute | fields infomation list |
| name | field name |
| inherit | which class(table) the field belong to |
| indexed | whether it is a index field |
| notnull | whether it can be null |
| shared | whether it can be shared |
| unique | whether it is unique |

## Response Sample

```
{
   "__EXEC_TIME" : "116 ms",
   "classinfo" : 
      {
         "attribute" : [
            {
               "default" : "",
               "indexed" : "n",
               "inherit" : "table1",
               "name" : "string1",
               "notnull" : "n",
               "shared" : "n",
               "type" : "character varying(40960)",
               "unique" : "n"
            },
            {
               "default" : "",
               "indexed" : "n",
               "inherit" : "table1",
               "name" : "string2",
               "notnull" : "n",
               "shared" : "n",
               "type" : "character varying(40960)",
               "unique" : "n"
            }
         ,
         "classname" : "table1",
         "dbname" : "testdb",
         "owner" : "PUBLIC",
         "type" : "user",
         "virtual" : "normal"
      }
   ],
   "note" : "none",
   "status" : "success",
   "task" : "class"
}
```
