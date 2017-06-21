# classinfo

Get the information of tables from a database.

## Request Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name |
| dbstatus | N/A |


## Request Sample

```
{
  "task":"classinfo",
  "token":"cdfb4c5717170c5ed30ef86644baf8151531ce5adff4a1f9a54711c51e0f50767926f07dd201b6aa",
  "dbname":"demodb",
  "dbstatus":"on"
}
```

## Response Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |
| dbname | database name |
| systemclass | system class information list |
| classname | class name |
| owner | class owner |
| userclass | user class info list |

## Response Sample

```
{
   "__EXEC_TIME" : "271 ms",
   "dbname" : "testdb",
   "note" : "none",
   "status" : "success",
   "systemclass" : 
      {
         "class" : [
            {
               "classname" : "db_root",
               "owner" : "DBA",
               "virtual" : "normal"
            },
            {
               "classname" : "db_user",
               "owner" : "DBA",
               "virtual" : "normal"
            },
            {
               "classname" : "db_password",
               "owner" : "DBA",
               "virtual" : "normal"
            },
            {
               "classname" : "db_authorization",
               "owner" : "DBA",
               "virtual" : "normal"
            },
            {
               "classname" : "db_authorizations",
               "owner" : "DBA",
               "virtual" : "normal"
            },
            {
               "classname" : "db_trigger",
               "owner" : "DBA",
               "virtual" : "normal"
            },
            {
               "classname" : "_db_class",
               "owner" : "DBA",
               "virtual" : "normal"
            },
            {
               "classname" : "_db_attribute",
               "owner" : "DBA",
               "virtual" : "normal"
            },
            {
               "classname" : "_db_domain",
               "owner" : "DBA",
               "virtual" : "normal"
            },
            {
               "classname" : "_db_method",
               "owner" : "DBA",
               "virtual" : "normal"
            },
            {
               "classname" : "_db_meth_sig",
               "owner" : "DBA",
               "virtual" : "normal"
            },
            {
               "classname" : "_db_meth_arg",
               "owner" : "DBA",
               "virtual" : "normal"
            },
            {
               "classname" : "_db_meth_file",
               "owner" : "DBA",
               "virtual" : "normal"
            },
            {
               "classname" : "_db_query_spec",
               "owner" : "DBA",
               "virtual" : "normal"
            },
            {
               "classname" : "_db_index",
               "owner" : "DBA",
               "virtual" : "normal"
            },
            {
               "classname" : "_db_index_key",
               "owner" : "DBA",
               "virtual" : "normal"
            },
            {
               "classname" : "_db_data_type",
               "owner" : "DBA",
               "virtual" : "normal"
            },
            {
               "classname" : "_db_auth",
               "owner" : "DBA",
               "virtual" : "normal"
            },
            {
               "classname" : "_db_partition",
               "owner" : "DBA",
               "virtual" : "normal"
            },
            {
               "classname" : "_db_stored_procedure",
               "owner" : "DBA",
               "virtual" : "normal"
            },
            {
               "classname" : "_db_stored_procedure_args",
               "owner" : "DBA",
               "virtual" : "normal"
            },
            {
               "classname" : "db_serial",
               "owner" : "DBA",
               "virtual" : "normal"
            },
            {
               "classname" : "db_ha_apply_info",
               "owner" : "DBA",
               "virtual" : "normal"
            },
            {
               "classname" : "db_class",
               "owner" : "DBA",
               "virtual" : "view"
            },
            {
               "classname" : "db_direct_super_class",
               "owner" : "DBA",
               "virtual" : "view"
            },
            {
               "classname" : "db_vclass",
               "owner" : "DBA",
               "virtual" : "view"
            },
            {
               "classname" : "db_attribute",
               "owner" : "DBA",
               "virtual" : "view"
            },
            {
               "classname" : "db_attr_setdomain_elm",
               "owner" : "DBA",
               "virtual" : "view"
            },
            {
               "classname" : "db_method",
               "owner" : "DBA",
               "virtual" : "view"
            },
            {
               "classname" : "db_meth_arg",
               "owner" : "DBA",
               "virtual" : "view"
            },
            {
               "classname" : "db_meth_arg_setdomain_elm",
               "owner" : "DBA",
               "virtual" : "view"
            },
            {
               "classname" : "db_meth_file",
               "owner" : "DBA",
               "virtual" : "view"
            },
            {
               "classname" : "db_index",
               "owner" : "DBA",
               "virtual" : "view"
            },
            {
               "classname" : "db_index_key",
               "owner" : "DBA",
               "virtual" : "view"
            },
            {
               "classname" : "db_auth",
               "owner" : "DBA",
               "virtual" : "view"
            },
            {
               "classname" : "db_trig",
               "owner" : "DBA",
               "virtual" : "view"
            },
            {
               "classname" : "db_partition",
               "owner" : "DBA",
               "virtual" : "view"
            },
            {
               "classname" : "db_stored_procedure",
               "owner" : "DBA",
               "virtual" : "view"
            },
            {
               "classname" : "db_stored_procedure_args",
               "owner" : "DBA",
               "virtual" : "view"
            }
      }
   ],
   "task" : "classinfo",
   "userclass" : 
      {
         "class" : [
            {
               "classname" : "table1",
               "owner" : "PUBLIC",
               "virtual" : "normal"
            },
            {
               "classname" : "table2",
               "owner" : "PUBLIC",
               "virtual" : "normal"
            }
      }
   ]
}
```
