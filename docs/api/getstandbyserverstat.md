# getstandbyserverstat

Returns insert_counter, update_counter, delete_counter, commit_counter, fail_counter and replication delay on replica database.

## Request Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name |
| dbid | dba user id |
| dbpasswd | a password |

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
