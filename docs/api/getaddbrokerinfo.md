# getaddbrokerinfo

Get broker configurations from a cubrid_broker.conf file.

Permissions required to run this task: none (any logged-in user)

## Request JSON Syntax

| **Key**  | **Description**                |
| -------- | ------------------------------ |
| task     | task name                      |
| token    | token string encrypted.        |
| confname | name of the configuration file |

## Request Sample

```
{
  "task": "getaddbrokerinfo",
  "token": "cdfb4c5717170c5e237a227a2ceeccc6ae9e10c16754fb85371c0d74fa0d9d577926f07dd201b6aa",
  "confname": "brokerconf"
}
```

## Response JSON Syntax

| **Key**  | **Description**                                   |
| -------- | ------------------------------------------------- |
| conflist | content of the configuration file                 |
| confname | name of the configuration file                    |
| note     | if failed, a brief description will be given here |
| status   | execution result, success or failed.              |
| task     | task name                                         |

## Response Sample

```
{
"__EXEC_TIME" : "0 ms",
"conflist" : [
    {
        "confdata" : [
            "#",
            "#  Copyright 2008 Search Solution Corporation",
            "#  Copyright 2016 CUBRID Corporation",
            "#",
            "#   Licensed under the Apache License, Version 2.0 (the \"License\");",
            "#   you may not use this file except in compliance with the License.",
            "#   You may obtain a copy of the License at",
            "#",
            "#       http://www.apache.org/licenses/LICENSE-2.0",
            "#",
            "#   Unless required by applicable law or agreed to in writing, software",
            "#   distributed under the License is distributed on an \"AS IS\" BASIS,",
            "#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.",
            "#   See the License for the specific language governing permissions and",
            "#   limitations under the License.",
            "",
            "[broker]",
            "MASTER_SHM_ID = 33122",
            "ADMIN_LOG_FILE = log/broker/cubrid_broker.log",
            "",
            "[%query_editor]",
            "SERVICE = OFF",
            "SSL = OFF",
            "BROKER_PORT = 30000",
            "MIN_NUM_APPL_SERVER = 5",
            "MAX_NUM_APPL_SERVER = 40",
            "APPL_SERVER_SHM_ID = 30000",
            "LOG_DIR = log/broker/sql_log",
            "ERROR_LOG_DIR = log/broker/error_log",
            "SQL_LOG = ON",
            "TIME_TO_KILL = 120",
            "SESSION_TIMEOUT = 300",
            "KEEP_CONNECTION = AUTO",
            "CCI_DEFAULT_AUTOCOMMIT = ON",
            "",
            "[%BROKER1]",
            "SERVICE = ON",
            "SSL = OFF",
            "BROKER_PORT = 33120",
            "MIN_NUM_APPL_SERVER = 5",
            "MAX_NUM_APPL_SERVER = 40",
            "APPL_SERVER_SHM_ID = 33120",
            "LOG_DIR = log/broker/sql_log",
            "ERROR_LOG_DIR = log/broker/error_log",
            "SQL_LOG = ON",
            "TIME_TO_KILL = 120",
            "SESSION_TIMEOUT = 300",
            "KEEP_CONNECTION = AUTO",
            "CCI_DEFAULT_AUTOCOMMIT = ON",
            ""
        ]
    }
],
"confname" : "broker",
"note" : "none",
"status" : "success",
"task" : "getaddbrokerinfo"
}
```
