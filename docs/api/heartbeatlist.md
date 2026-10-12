# heartbeatlist

Runs `cubrid heartbeat list` command.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbmodeall | y : all, n : only includes HA-Node, Node excepts Applylogdb, Copylogdb, Server |
| dblist | database name |

## Request Sample

```
{
  "task": "heartbeatlist",
  "token": "cdfb4c5717170c5e673cf07a9b448162c895920ae8799faa2fbe13c787b4cbbd7926f07dd201b6aa",
  "dbmodeall": "y",
  "dblist": ""
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |
| hanodelist | the list of the nodes of the HA group |
| hadbinfolist | the list of the database servers of the HA group |

### hanodelist

hanodelist is composed of `node` objects with following structure

| **Key** | **Description** |
| --- | --- |
| currentnode | the host name of the node the request was sent to |
| currentnodestate | the HA state of that node |
| hostname | the host name of the node |
| ip | the ip address of the node |
| priority | the priority of the node inside the HA group |
| state | the HA state of the node: master, slave, replica or unknown |

### hadbinfolist

hadbinfolist is composed of `server` objects, which hold a `dbmode` and a `dbprocinfo` object

| **Key** | **Description** |
| --- | --- |
| dbname | database name |
| server_mode | the HA mode of the database server |
| server_msg | the message returned with the mode |
| hostname | the host name the process runs on |
| pid | the process id |
| logpath | the log directory of the process |
| state | the state of the process |

## Response Sample

```
{
   "__EXEC_TIME" : "58 ms",
   "hadbinfolist" : [
      {
         "server" : [
            {
               "dbmode" : [
                  {
                     "dbname" : "demodb",
                     "server_mode" : "active",
                     "server_msg" : ""
                  }
               ],
               "dbprocinfo" : [
                  {
                     "dbname" : "demodb",
                     "hostname" : "node1",
                     "logpath" : "/home/cubrid/CUBRID/databases/demodb/log",
                     "pid" : "18410",
                     "state" : "registered"
                  }
               ]
            }
         ]
      }
   ],
   "hanodelist" : [
      {
         "node" : [
            {
               "currentnode" : "node1",
               "currentnodestate" : "master",
               "hostname" : "node1",
               "ip" : "192.168.0.11",
               "priority" : "1",
               "state" : "master"
            }
         ]
      }
   ],
   "note" : "none",
   "status" : "success",
   "task" : "heartbeatlist"
}
```
