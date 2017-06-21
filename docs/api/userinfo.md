# userinfo

Get Databases' user information in cubrid.

## Request Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted |
| dbname | database name |

## Request Sample

```
{
  "task":"userinfo",
  "token":"cdfb4c5717170c5ed30ef86644baf8151531ce5adff4a1f9a54711c51e0f50767926f07dd201b6aa",
  "dbname":"demodb"
 }
```

## Response Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed |
| note | if failed, a brief description will be given here |
| dbname | database name |
| @name | user name |
| @id | user id number |
| user | user information list |
| groups | user group |
| authorization | user authorization |

## Response Sample

```
{
   "__EXEC_TIME" : "359 ms",
   "dbname" : "testdb",
   "note" : "none",
   "status" : "success",
   "task" : "userinfo",
   "user" : 
      {
         "@id" : "163810704",
         "@name" : "PUBLIC",
         "authorization" : [
            {
               "db_attr_setdomain_elm" : "1",
               "db_attribute" : "1",
               "db_auth" : "1",
               "db_authorization" : "65",
               "db_authorizations" : "65",
               "db_class" : "1",
               "db_direct_super_class" : "1",
               "db_ha_apply_info" : "1",
               "db_index" : "1",
               "db_index_key" : "1",
               "db_meth_arg" : "1",
               "db_meth_arg_setdomain_elm" : "1",
               "db_meth_file" : "1",
               "db_method" : "1",
               "db_partition" : "1",
               "db_root" : "65",
               "db_serial" : "1",
               "db_stored_procedure" : "1",
               "db_stored_procedure_args" : "1",
               "db_trig" : "1",
               "db_user" : "65",
               "db_vclass" : "1"
            }
         ,
         "groups" : null
      },
      {
         "@id" : "163810984",
         "@name" : "DBA",
         "authorization" : null,
         "groups" : null
      }
   ]
}
```
