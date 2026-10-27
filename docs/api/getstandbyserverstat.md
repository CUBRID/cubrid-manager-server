# getstandbyserverstat

Returns insert_counter, update_counter, delete_counter, commit_counter, fail_counter and replication delay on replica database.

Permissions required to run this task: none (any logged-in user)

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |

| task | Task name |
| token | Token string encrypted. |
| dbname | Database name |
| dbid | DBA user ID |
| dbpasswd | DBA user Password |

## Request Sample

```
{
  "task": "getstandbyserverstat",
  "token": "cdfb4c5717170c5e673cf07a9b448162c895920ae8799faa2fbe13c787b4cbbd7926f07dd201b6aa",
  "dbname": "demodb",
  "dbid": "dba",
  "dbpasswd": ""
}
```
