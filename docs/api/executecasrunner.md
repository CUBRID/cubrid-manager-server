# executecasrunner

Replay SQL statements against a broker with the `broker_log_converter` and the
`broker_log_runner` utilities, and return their output.

The statements to be replayed are given in one of two ways. When `executelogfile` is `yes` and
`logfile` is given, the broker SQL log file of that path is replayed. Otherwise the lines of
`logstring` are written to a temporary log file which is replayed instead.

The broker port is taken from `cubrid_broker.conf`, using `brokername`.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| brokername | broker name, it is used to find the port of the broker |
| dbname | database name |
| username | database user id |
| passwd | the password of the database user |
| num_thread | the number of the threads which replay the statements |
| repeat_count | how many times the statements are replayed |
| show_queryresult | yes or no, include the result of the queries in the response |
| show_queryplan | yes or no, run the queries with the query plan option (`-Q`) |
| executelogfile | yes or no, replay an existing broker SQL log file instead of `logstring` |
| logfile | the full path of the broker SQL log file to be replayed, used when `executelogfile` is yes |
| logstring | the list of the SQL log lines to be replayed, used when `executelogfile` is not yes |

## Request Sample

```
{
  "task": "executecasrunner",
  "token": "cdfb4c5717170c5e9c6856b4d1c61ee8132bcc7d82bd609066ed9ece2554c47f7926f07dd201b6aa",
  "dbname": "demodb",
  "brokername": "query_editor",
  "username": "dba",
  "passwd": "",
  "num_thread": "1",
  "repeat_count": "1",
  "executelogfile": "no",
  "logstring": [],
  "show_queryresult": "yes"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |
| result_list | the messages which `broker_log_runner` reported |
| query_result_file | the full path of the file which holds the result of the replay |
| query_result_file_num | the number of the result files, it is the same as `num_thread` |

### result_list

result_list is composed of objects with following structure

| **Key** | **Description** |
| --- | --- |
| result | a line of the output of the replay |

The temporary files reported in `query_result_file` are removed with
[removecasrunnertmpfile](removecasrunnertmpfile.md).

## Response Sample

```
{
   "__EXEC_TIME" : "27 ms",
   "note" : "none",
   "query_result_file" : "/home/cubrid/CUBRID-11.5.0.2441-6ba9522-Linux.x86_64/tmp/log_run_res_142_1787011729_633904_383",
   "query_result_file_num" : "1",
   "result_list" : [
      {
         "result" : "stddev : 0.000000"
      }
   ],
   "status" : "success",
   "task" : "executecasrunner"
}
```
