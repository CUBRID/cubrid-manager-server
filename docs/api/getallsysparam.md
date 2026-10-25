# getallsysparam

Get configuration files.

Permissions required to run this task: none (any logged-in user)

* `confname` other than the listed names reads `$CUBRID/conf/<confname>`; a protected file such as `cm.pass` is refused (see [File Access](README.md#file-access)).

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token returned by login |
| confname | cubridconf, cmconf, haconf, databases |

## Request Sample

```
{
  "task": "getallsysparam",
  "token": "cdfb4c5717170c5e237a227a2ceeccc6ae9e10c16754fb85371c0d74fa0d9d577926f07dd201b6aa",
  "confname": "cubridconf"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| note | if failed, a brief description will be given here |
| status | execution result, success or failed. |
| task | task name |
| confname | name of the configuration file |
| conflist | list of configuration file data |

### conflist
conflist is composed of objects with following structure

| **Key** | **Description** |
| --- | --- |
| confdata | content of configuration file |

## Response Sample

```json
{
   "__EXEC_TIME" : "0 ms",
   "conflist" : [
      {
         "confdata" : [
            "# cm.conf ",
            "#     -- CUBRID database management tool server configuration file",
            "#",
            "#",
            "# When server starts, it looks for the environment variable ",
            "# 'CUBRID_MANAGER' and use it to locate this file. It is assumed that",
            "# 'CUBRID_MANAGER' is the root directory of all CUBRID Manager related files.",
            "#",
            "# Manager server section - a section for 'cubrid service' command",
            "# Common section - properties for CUBRID Manager Server",
            "# This section will be applied before starting manager server.",
            "[cm]",
            "#",
            "# Port number designation",
            "# A port for the connection between CUBRID Manager server and Client.",
            "# CUBRID Manager server uses the value cm_port. ",
            "# The default value is 8001. ",
            "#",
            "cm_port=8001",
            "",
            "#",
            "# CMS Process Monitoring interval setting",
            "#",
            "cm_process_monitor_interval=5",
            "",
            "#",
            "# Allowing Multiple connection with one CUBRID Manager user.",
            "#",
            "allow_user_multi_connection=YES",
            "",
            "###############################",
            "# diagnostics parameter",
            "###############################",
            "#",
            "# turn ON/OFF diag",
            "#",
            "#execute_diag=ON",
            "",
            "#",
            "# server long query time (sec)",
            "#",
            "server_long_query_time=10",
            "",
            "#",
            "# Auto jobs execution timeout (sec)",
            "# Default value: 43200 (12 hours)",
            "# Minimum value: 60",
            "auto_job_timeout=43200",
            "",
            "#",
            "# Define token active time(session timeout), default value is 7200.",
            "#",
            "#token_active_time=7200",
            "",
            "#",
            "# support monitoring statistic (YES/NO), default NO",
            "# If you want to use the advanced monitoring feature on CUBRID Manager,",
            "# you should set this value to YES.",
            "#",
            "support_mon_statistic=NO",
            "",
            "#",
            "# max log file number: default 10",
            "# When the log files is more than max_log_files,",
            "# The oldest log will be removed.",
            "#",
            "max_log_files=10"
         ]
      }
   ],
   "confname" : "cmconf",
   "note" : "none",
   "status" : "success",
   "task" : "getallsysparam"
}
```