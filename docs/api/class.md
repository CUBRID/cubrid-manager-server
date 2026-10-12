# class

The class interface will get summary database class information.

## Request JSON Syntax

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

## Response JSON Syntax

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
| attribute | fields information list |
| name | field name |
| inherit | which class(table) the field belong to |
| indexed | whether it is a index field |
| notnull | whether it can be null |
| shared | whether it can be shared |
| unique | whether it is unique |

## Response Sample

```json
{
   "__EXEC_TIME" : "29 ms",
   "classinfo" : [
      {
         "attribute" : [
            {
               "default" : "",
               "indexed" : "y",
               "inherit" : "public.athlete",
               "name" : "code",
               "notnull" : "y",
               "shared" : "n",
               "type" : "integer(10)",
               "unique" : "y"
            },
            {
               "default" : "",
               "indexed" : "n",
               "inherit" : "public.athlete",
               "name" : "name",
               "notnull" : "y",
               "shared" : "n",
               "type" : "character varying(40)",
               "unique" : "n"
            }
         ],
         "classname" : "public.athlete",
         "constraint" : [
            {
               "attribute" : [ "code" ],
               "name" : "pk_athlete_code",
               "type" : "PRIMARY KEY"
            },
            {
               "attribute" : [ "code" ],
               "name" : "n_athlete_code",
               "type" : "NOT NULL"
            }
         ],
         "dbname" : "demodb",
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

> Lists are shortened to 2 entries here.
