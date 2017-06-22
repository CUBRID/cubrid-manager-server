# getbrokerstatus

Get broker status.

## Request Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| bname | broker name |

## Request Sample

```
{
  "task":"getbrokerstatus",
  "token":"cdfb4c5717170c5e9c6856b4d1c61ee8132bcc7d82bd609066ed9ece2554c47f7926f07dd201b6aa",
  "bname":"query_editor"
}
```

## Response Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |
| bname | broker name |
| asinfo | cas' informations |
| as_id | cas id |
| as_pid | cas process id |
| as_psize | cas process virtual memory size |
| as_status | cas process status |
| as_cpu | cpu usage of cas process |
| as_ctime | ctime of cas process |
| as_lat | the last access time of cas process |
| as_client_ip | client ip address |
| as_cur | N/A |
| as_dbhost | server host name |
| as_dbname | database name |
| as_error_query | the number of errors in query |
| as_long_query | the number of complicated queries |
| as_long_tran | the number of complicated transactions |
| as_num_query | the number of queries |
| as_num_tran | the number of transactions |

## Response Sample

```
{
   "__EXEC_TIME" : "51 ms",
   "asinfo" : 
      {
         "as_c" : "0",
         "as_client_ip" : "0.0.0.0",
         "as_cpu" : "0.00",
         "as_ctime" : "0:00",
         "as_cur" : "",
         "as_dbhost" : "",
         "as_dbname" : "",
         "as_error_query" : "0",
         "as_id" : "1",
         "as_lat" : "2013/02/01 15:30:23",
         "as_lct" : "",
         "as_long_query" : "0",
         "as_long_tran" : "0",
         "as_num_query" : "0",
         "as_num_tran" : "0",
         "as_pid" : "2263",
         "as_psize" : "25532",
         "as_status" : "IDLE"
      },
      {
         "as_c" : "0",
         "as_client_ip" : "0.0.0.0",
         "as_cpu" : "0.00",
         "as_ctime" : "0:00",
         "as_cur" : "",
         "as_dbhost" : "",
         "as_dbname" : "",
         "as_error_query" : "0",
         "as_id" : "2",
         "as_lat" : "2013/02/01 15:30:23",
         "as_lct" : "",
         "as_long_query" : "0",
         "as_long_tran" : "0",
         "as_num_query" : "0",
         "as_num_tran" : "0",
         "as_pid" : "2264",
         "as_psize" : "25532",
         "as_status" : "IDLE"
      },
      {
         "as_c" : "0",
         "as_client_ip" : "0.0.0.0",
         "as_cpu" : "0.00",
         "as_ctime" : "0:00",
         "as_cur" : "",
         "as_dbhost" : "",
         "as_dbname" : "",
         "as_error_query" : "0",
         "as_id" : "3",
         "as_lat" : "2013/02/01 15:30:23",
         "as_lct" : "",
         "as_long_query" : "0",
         "as_long_tran" : "0",
         "as_num_query" : "0",
         "as_num_tran" : "0",
         "as_pid" : "2265",
         "as_psize" : "25532",
         "as_status" : "IDLE"
      },
      {
         "as_c" : "0",
         "as_client_ip" : "0.0.0.0",
         "as_cpu" : "0.00",
         "as_ctime" : "0:00",
         "as_cur" : "",
         "as_dbhost" : "",
         "as_dbname" : "",
         "as_error_query" : "0",
         "as_id" : "4",
         "as_lat" : "2013/02/01 15:30:23",
         "as_lct" : "",
         "as_long_query" : "0",
         "as_long_tran" : "0",
         "as_num_query" : "0",
         "as_num_tran" : "0",
         "as_pid" : "2266",
         "as_psize" : "25532",
         "as_status" : "IDLE"
      },
      {
         "as_c" : "0",
         "as_client_ip" : "0.0.0.0",
         "as_cpu" : "0.00",
         "as_ctime" : "0:00",
         "as_cur" : "",
         "as_dbhost" : "",
         "as_dbname" : "",
         "as_error_query" : "0",
         "as_id" : "5",
         "as_lat" : "2013/02/01 15:30:23",
         "as_lct" : "",
         "as_long_query" : "0",
         "as_long_tran" : "0",
         "as_num_query" : "0",
         "as_num_tran" : "0",
         "as_pid" : "2267",
         "as_psize" : "25532",
         "as_status" : "IDLE"
      }
   ,
   "bname" : "query_editor",
   "note" : "none",
   "status" : "success",
   "task" : "getbrokerstatus",
   "time" : "2013/02/01 15:41:08"
}
```
