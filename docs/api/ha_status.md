# ha_status

Runs `cubrid heartbeat status` command.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |

## Request Sample

```
{
  "task": "ha_status",
  "token": "4504b930fc1be99bf5dfd31fc5799faaa3f117fb903f397de087cd3544165d857926f07dd201b6aa"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |
| current_node | the host name of the node the request was sent to |
| current_node_state | the HA state of that node: master, slave, replica or unknown |
| ha_info | the list of the databases of the HA group and of their processes |

### ha_info

ha_info is composed of objects with following structure

| **Key** | **Description** |
| --- | --- |
| dbname | database name |
| copylogdb | the peer node of the copylogdb process |
| copylogdb_pid | the process id of the copylogdb process |
| copylogdb_state | the state of the copylogdb process |
| applylogdb | the peer node of the applylogdb process |
| applylogdb_pid | the process id of the applylogdb process |
| applylogdb_state | the state of the applylogdb process |

## Response Sample

```
{
   "__EXEC_TIME" : "72 ms",
   "current_node" : "node1",
   "current_node_state" : "master",
   "ha_info" : [
      {
         "applylogdb" : "node2",
         "applylogdb_pid" : "18422",
         "applylogdb_state" : "registered",
         "copylogdb" : "node2",
         "copylogdb_pid" : "18420",
         "copylogdb_state" : "registered",
         "dbname" : "demodb"
      }
   ],
   "note" : "none",
   "status" : "success",
   "task" : "ha_status"
}
```
