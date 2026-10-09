# paramdump

Run a paramdump utility.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name |
| both | "y" to retrieve parameters from both process of client and server, "n" to retrieve parameters from only server process |


## Request Sample

```
{
    "task":"paramdump","token":"300ea42877b8fd414644196bb44e7a8bea3164a1a5a348c5381b47766536a56664ec74a35eeb28dd7926f07dd201b6aa7926f07dd201b6aa7926f07dd201b6aa7926f07dd201b6aa7926f07dd201b6aa7926f07dd201b6aa7926f07dd201b6aa7926f07dd201b6aa7926f07dd201b6aa7926f07dd201b6aa7926f07dd201b6aa",
    "dbname":"demodb",
    "both":"n"
}
```



## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |
| dbname | database name |
| client | one entry holding the parameters as the client sees them |
| server | one entry holding the parameters as the server sees them |

### client / server

Both are composed of a single object whose keys are the system parameters
listed below. The same parameter can hold a different value on each side.

| **Key** | **Description** |
| --- | --- |
| access_ip_control | Specifies whether to enable IP-based access control to restrict server connections  |
| access_ip_control_file | Name of the file which contains the list of the allowed IP addresses for server |
| adaptive_flush_control | Determines whether flush capacity should be automatically adjusted every 50ms depending on work status during flush operation  |
| add_column_update_hard_default | Determines whether to provide a hard default value for a new column added using the `ALTER TABLE … ADD COLUMN` clause  |
| agg_hash_respect_order | Specifies whether groups in aggregate functions are returned in order |
| allow_truncated_string | Specifies whether to allow string truncation in string operations used in INSERT or UPDATE queries |
| alter_table_change_type_strict | Determines whether to allow values of columns to be converted when data type is changed |
| ansi_quotes | Determines how double quotation marks and single quotation marks should be processed. On 'yes', double quotation marks will be processed as Identifier quoting symbol |
| async_commit | Enable asynchronous commit |
| auto_restart_server | Determines if server should be restarted when `cub_master` process is terminated due to critical error |
| background_archiving | determines whether to periodically generate temporary archive logs at specific intervals |
| backup_volume_max_size_bytes | Split size of backup volume files created by the `cubrid backupdb` utility. |
| block_ddl_statement | Determines whether to block the execution of DDL from the client |
| block_nowhere_statement | Determines whether to block the execution of UPDATE / DELETE query without WHERE clause |
| call_stack_dump_activation_list | list of specific error codes to be included in call stack dumping, even when call stack dumping is disabled for all errors |
| call_stack_dump_deactivation_list | list of specific error codes to be excluded from call stack dumping, even when call stack dumping is enabled for all errors  |
| call_stack_dump_on_error | Determines whether call stack dumping will be executed when error occurs in database server |
| check_peer_alive | determines whether client and server to perform checks to verify if peer is alive |
| checkpoint_every_npages | Sets the checkpoint interval in units of number of log page. This parameter will be deprecated. |
| checkpoint_every_size | Sets the checkpoint interval in units of log page size. |
| checkpoint_interval | interval of checkpoint operation |
| checkpoint_interval_in_mins | Interval of checkpoint operation in unit of minutes. This parameter will be deprecated. |
| commit_on_shutdown | |
| communication_histogram | Parameter related to the csql interpreter's session command `;.h`. |
| compactdb_page_reclaim_only | Specifies the unit size for storage area reorganization by the `compactdb` utility  |
| compat_mode | |
| compat_numeric_division_scale | specifies how many decimal places to display in division results: no uses 9 places, yes depends on operand precision |
| compat_primary_key | |
| connection_timeout | |
| create_table_reuseoid | Determines which option should be used between `REUSE_OID` and `DONT_REUSE_OID` when table option is omitted in table creation |
| csql_auto_commit | |
| csql_history_num | number of SQL clauses stored in history log of CSQL interpreter |
| csql_single_line_mode | |
| cte_max_recursions | maximum number of iterations allowed for executing recursive parts of a CTE (Common Table Expression) query |
| cubrid_port_id | port of master process |
| data_aout_ratio | |
| data_buffer_neighbor_flush_nondirty | Determines whether to flush clean pages adjacent to dirty pages when victim candidate pages are flushed while the neighbor flush option is enabled  |
| data_buffer_neighbor_flush_pages | Number of adjacent pages which would be flushed using background flush |
| data_buffer_pages | Size of data buffer pages which is cached in memory by database server. Used in systems with version prior to 2008 R4.0 |
| data_buffer_size | size of data buffer which is cached in memory by database server |
| data_file_os_advise | Parameter to enhance I/O performance which is applicable only to Unix-based system  |
| db_hosts | Determines the list of available database server hosts and the order of connection |
| db_volume_size | default size of the database volume created when the --db-volume-size option is omitted in the cubrid createdb and cubrid addvoldb utilities.  |
| dblink_auto_commit | Determines whether dblink query to be automatically committed immediately |
| ddl_audit_log | Determines whether to log every `DDL` operation |
| ddl_audit_log_size | Maximum size of the `DDLAUDIT` log file |
| deadlock_detection_interval_in_secs | interval for detecting deadlocks involving suspended transactions |
| deduplicate_key_level | Value of deduplicate level which is assigned implicitly in Index creation clause.|
| default_week_format | default value of `mode` parameter of `WEEK()` function |
| dont_reuse_heap_file | Determines whether heap file which is deleted by `DROP TABLE` to reuse for `CREATE TABLE` |
| double_write_buffer_size | size of the memory and disk space of `Double Write Buffer (DWB)` |
| enable_memory_monitoring | Determines whether to monitor the heap memory usage of the server |
| enable_string_compression | Determines whether string compression should be executed when string is stored in Heap, Index and List |
| error_log | file name of error log for database server error |
| error_log_level | severity level of the errors to be written in log file |
| error_log_production_mode | |
| error_log_size | size of the error log file |
| error_log_warning | Determines whether error message to be prompted for those with `WARNING` severity level  |
| event_activation_list | |
| event_handler | |
| extended_statistics_activation | |
| flashback_timeout | Timeout for the user to enter the transaction identifier to be rolled back when running the flashback utility |
| force_remove_log_archives | Specifies whether to allow deletion of older log archive files, excluding the most recent ones as defined by log_max_archive   |
| garbage_collection | |
| group_commit_interval_in_msecs | interval (in msec) of group commit |
| group_concat_max_len | Maximum return value of `GROUP_CONCAT()` function |
| ha_apply_max_mem_size | Value of maximum memory that the replication log reflection process of CUBRID HA can use. |
| ha_applylogdb_ignore_error_list | List of error codes to be ignored even if they occur during replication in the CUBRID HA process. |
| ha_applylogdb_max_commit_interval | |
| ha_applylogdb_max_commit_interval_in_msecs | |
| ha_applylogdb_retry_error_list | |
| ha_check_disk_failure_interval | Interval(in seconds) for checking disk failure. |
| ha_copy_log_base | Parent path for saving replication logs. |
| ha_copy_log_max_archives | Maximum number of replication log files to preserve. |
| ha_copy_log_timeout | Maximum wait time for a node's database server process to receive a response from the replication log copy process of the peer node. |
| ha_copy_sync_mode | Storage mode for replication log. |
| ha_db_list | Name of the database to run in CUBRID HA mode. |
| ha_delay_limit | Threshold time used by CUBRID to determine whether replication is delayed.  |
| ha_delay_limit_delta | The value obtained by subtracting the replication delay release time from the replication delay time. |
| ha_enable_sql_logging | Specifies whether the applylogdb process creates log files for SQL statements applied to the database under the sql_log directory within the replication log directory (ha_copy_log_base). |
| ha_mode | Indicates whether HA (High Availability) mode is enabled and configures related options |
| ha_mode_for_sa_utils_only | |
| ha_node_list | Group name used within the HA group and host names of member nodes which are candidates of failover. |
| ha_ping_hosts | Host used to check connectivity at the moment failover starts on a slave node, to determine whether the failover was caused by a network issue. |
| ha_port_id | UDP port number which should be used to exchange heartbeat message. |
| ha_repl_filter_file | |
| ha_repl_filter_type | |
| ha_replica_delay | Interval of application of data replication between Master node and Replica node. CUBRID intentionally delays applying the replication by this value. |
| ha_replica_list | Group name used within the HA group and host names of member nodes which are not the candidates of failover (Replica nodes).  |
| ha_replica_time_bound | Only the transactions committed on the master node up to the time specified by the parameter are applied to the replica node. |
| ha_sql_log_max_count | Maximum number of recent SQL log files to preserve. If the number of SQL log file exceeds this value, the oldest log files are deleted first. |
| ha_sql_log_max_size_in_mbytes | Maximum size of the file created when logging SQL statements applied to the database by the `applylogdb` process.  |
| ha_sql_log_path | Path of SQL log file. |
| ha_tcp_ping_hosts | Hosts used to check connectivity via TCP when ha_ping_hosts is unavailable due to ICMP protocol being disabled. |
| ha_unacceptable_proc_restart_timediff | Restart interval for determining whether the server is in an abnormal state. Node is demoted from HA configuration if the restart interval is smaller than value of this parameter. |
| index_scan_in_oid_order | Determines if result of index scan should be aligned in order of oid. |
| index_scan_key_buffer_pages | |
| index_scan_key_buffer_size | |
| index_scan_oid_buffer_pages | Number of buffer pages where the OID list is to be temporarily saved during the index scan. After version 2008 R4.0, this parameter is replaced with `index_scan_oid_buffer_size`. |
| index_scan_oid_buffer_size | size of the buffer to temporarily store the list of OID during index scan, the unit is kilobytes |
| index_unfill_factor | Ratio of the size of extra space for index page node when index is created. |
| intl_check_input_string | Determines whether to check if input strings match the character set being used |
| intl_collation | specifies the name of the collation for the specific application client |
| intl_date_lang | specifies format of the localized calendar of string when no language name is provided as an parameter for functions handles `TIME, DATE, DATETIME, TIMESTAMP` |
| intl_mbs_support |  Specifies whether or not to support multibyte character set. After version 2008 R4.0, this parameter is deprecated. |
| intl_number_lang | locale applied when formatting strings as numbers or numbers as strings in conversion functions |
| isolation_level | isolation level of transaction |
| JSON_max_array_idx | sets the size limit when JSON functions modify the size of an array |
| loaddb_worker_count | Maximum number of threads allocated just for `loaddb` session |
| lock_escalation | Maximum number of the row level locks allowed before escalating to a table level lock  |
| lock_timeout | Client parameter to specify the lock wait timeout |
| lock_timeout_in_secs | client parameter (in seconds) to specify the lock wait timeout |
| log_buffer_pages | Number of log buffer pages to be cached in the memory. After version 2008 R4.0, this parameter is replaced with `log_buffer_size`. |
| log_buffer_size | size of the log buffer cached in memory |
| log_compress | |
| log_max_archives | Maximum number of archive log files to preserve |
| log_trace_flush_time | If log flushing takes longer than the time set by this parameter, the event is recorded in the database server log |
| log_volume_size | Default size of the log volume file created when the --log-volume-size is omitted in the `cubrid createdb` utility |
| lru_buffer_ratio | |
| lru_hot_ratio | |
| max_agg_hash_size | Maximum memory size allocated per transaction for hashing tuple groups in queries that include aggregation |
| max_clients | Maximum number of clients allowed to connect to database server |
| max_filter_pred_cache_entries | maximum number of filtered index expression that can be cached in memory |
| max_flush_pages_per_second | Maximum flush capacity for the flush operation from buffer to disk. This parameter will be deprecated. |
| max_flush_size_per_second | Maximum flush capacity for the flush operation from buffer to disk. |
| max_hash_list_scan_size | Maximum memory size allocated per transaction for building hash table in queries that include subquery |
| max_plan_cache_clones | Maximum clone cache value that one plan can have |
| max_plan_cache_entries | Maximum number of query execution plan cached in memory |
| max_query_cache_entries | Maximum number of queries that can be cached |
| max_query_per_tran | Maximum number of unclosed query that single transaction can hold at once  |
| max_subquery_cache_size | Maximum size of subquery cache |
| monitor_waiting_thread | |
| multi_range_optimization_limit | Performs index sort optimization for queries with `multi-range conditions (e.g., col IN (?, ?, ..., ?))` when the number of rows specified by the LIMIT clause is within the value of this parameter. |
| mysql_trigger_correlation_names | |
| no_backslash_escapes | determines whether backslash `\` should be used as escape sequence |
| num_private_chains | |
| only_full_group_by | Determines whether to use extended syntax for `GROUP BY` clause. Extended syntax is applied on 'no' |
| optimization_level | |
| oracle_compat_number_behavior | prevents trailing zeros after the decimal point for NUMERIC, DOUBLE, and FLOAT types, and disables scientific notation for DOUBLE and FLOAT on 'yes' for compatibility with other DBMSs (e.g., Oracle) |
| oracle_style_empty_string | NULL and empty string is treated as same value for the compatibility with other DBMSs (e.g., Oracle) |
| page_flush_interval | |
| page_flush_interval_in_msecs | |
| pipes_as_concat | Determines how double pipe symbol should be treated. On 'yes', treated as concatenation operator for string, on 'no', treated as treated as boolean operator 'OR'. |
| pl_transaction_control | Used to enable COMMIT and ROLLBACK for Java Stored Procedure. |
| plan_cache_logging | |
| plan_cache_timeout | |
| plus_as_concat | Determines how plus symbol should be treated. On 'yes' treated as concatenation operator for string, on 'no', treated as numeric operator. |
| print_index_detail | Specifies whether to display option information from the WITH clause when showing index definition details. |
| pthread_scope_process | |
| query_cache_size_in_pages | maximum number of result pages that can be cached |
| query_trace | |
| query_trace_format | |
| recovery_progress_logging_interval | Specifies whether to log detailed recovery process and sets the logging interval. |
| regexp_engine | Library used for regular expression operators and functions. `cppstd` and `re2` is available. Default value is `re2`  |
| require_like_escape_character | determines if escape sequence is used in `LIKE` clause |
| return_null_on_function_errors | determines whether certain SQL functions return NULL or raises an error with a message when an error occurs |
| rollback_on_lock_escalation | Determines if the transaction should be rolled back when lock escalation occurs |
| server_timezone | timezone of server |
| service::server | |
| service::service | |
| session_state_timeout | Specifies the period of time that session data is retained within the DB server process. |
| sort_buffer_pages | Number of buffer pages to be used when sorting. This parameter will be deprecated. |
| sort_buffer_size | Buffer size used for queries that perform sorting. |
| sort_limit_max_count | Specifies the maximum number of rows that the SORT-LIMIT optimization is applied in queries using the "ORDER BY … LIMIT N" clause.  |
| sql_trace_execution_plan | Indicates if execution plan of long running query should be prompted |
| sql_trace_ioread_pages | Logs queries that perform I/O reads exceeding this value specified by the parameter  |
| sql_trace_slow | Execution time threshold to consider a query as a long-running query.  |
| sql_trace_slow_msecs | Execution time threshold to consider a query as a long-running query. This parameter will be deprecated. |
| stored_procedure | Determines whether to enable stored procedure by executing cub_pl process |
| stored_procedure_dump_icode | |
| stored_procedure_port | TCP port to invoke stored procedure |
| stored_procedure_return_numeric_size | Precision and scale of the NUMERIC value returned in stored procedure |
| stored_procedure_uds | Enable the connection using Unix domain socket between `cub_pl` process and `cub_server` process. |
| stored_procedure_vm_options | Configuration parameters for the virtual machine of procedure language server |
| string_max_size_bytes | maximum size (in bytes) of string parameter for string function or string operation |
| supplemental_log | Determines whether to store required information for `flashback` and CDC(Change Data Capture) in log volume. |
| sync_on_flush_size | Interval (in pages) of synchronizing file i/o of operation system after flushing data pages and log pages from buffer. |
| sync_on_nflush | Interval (in pages) of synchronizing file i/o of operation system after flushing data pages and log pages from buffer. This parameter will be deprecated.|
| tcp_keepalive | specifies whether to apply the SO_KEEPALIVE option of the TCP network protocol. |
| tde_default_algorithm | Default algorithm which is used for creating TDE(Transparent Data Encryption) table. |
| tde_keys_file_path | Path to the key file for TDE (Transparent Data Encryption) |
| temp_file_max_size_in_pages | maximum number of pages allowed for expanding the temporary volume  |
| temp_file_memory_size_in_pages | number of buffer pages to cache temporal result of the query |
| temp_volume_path | path of the temporary temp volume which is automatically generated to execute complicated query or sort operation |
| thread_connection_pooling | Determines whether all threads that managing client connections are pooled at server startup |
| thread_connection_timeout_seconds | Waiting time before the threads managing client connections are terminated.  |
| thread_core_count | Number of thread groups to be pooled |
| thread_stacksize | size of the stack of thread |
| thread_worker_pooling | Determines whether all threads that execute client-requested tasks are pooled at server startup |
| thread_worker_timeout_seconds | Waiting time before worker threads that executes client-requested tasks are terminated |
| timezone | timezone of the session |
| tz_leap_second_support | specifies the support on leap second |
| unfill_factor | ratio of the heap pages allocated in preparation for data update |
| unicode_input_normalization | Specifies whether to store input Unicode characters in composed form at the system level  |
| unicode_output_normalization | Specifies whether to display output Unicode characters in composed form |
| update_use_attribute_references | Specifies whether the value of a previously mentioned column affects the update of other columns that reference it in the same query. |
| use_orderby_sort_limit | Specifies whether to keep only row_count intermediate results during sort and merge for queries with ORDER BY … LIMIT row_count clause |
| use_stat_estimation | Determines if prediction should be used to calculate the statistics. |
| use_user_hosts | specify which service to use for searching host name and ip address for CUBRID service |
| vacuum_log_block_pages | |
| vacuum_master_interval_in_msecs | |
| vacuum_ovfp_check_duration | Duration to preserve the number of index overflow collected by vacuum thread and the related information |
| vacuum_ovfp_check_threshold | Threshold (in pages) for collecting management information when the number of overflow pages linked to a single leaf node during index vacuuming exceeds this value |
| vacuum_worker_count | |
| volume_extension_path | default path for additional volume created when the `-F` option is omitted in the `cubrid addvolb` utility |
| xasl_cache_time_threshold_in_minutes | threshold (in minute) to clean up cached plan |

## Response Sample

```
{
   "__EXEC_TIME" : "59 ms",
   "client" : [
      {
         "access_ip_control" : "n",
         "access_ip_control_file" : "\"\"",
         "adaptive_flush_control" : "y",
         "add_column_update_hard_default" : "n",
         "agg_hash_respect_order" : "y",
         "allow_truncated_string" : "n",
         "alter_table_change_type_strict" : "y",
         "ansi_quotes" : "y",
         "async_commit" : "n",
         "auto_increment_cache_size" : "20",
         "auto_restart_server" : "y",
         "auto_scaling_window_size" : "4",
         "background_archiving" : "y",
         "backup_volume_max_size_bytes" : "0.0B",
         "bestspace_shard_count" : "8",
         "block_ddl_statement" : "n",
         "block_nowhere_statement" : "n",
         "call_stack_dump_activation_list" : "",
         "call_stack_dump_deactivation_list" : "",
         "call_stack_dump_on_error" : "n",
         "check_peer_alive" : "\"both\"",
         "checkpoint_every_npages" : "100000",
         "checkpoint_every_size" : "1.5G",
         "checkpoint_interval" : "360.000 sec",
         "checkpoint_interval_in_mins" : "6",
         "commit_on_shutdown" : "n",
         "communication_histogram" : "n",
         "compactdb_page_reclaim_only" : "0",
         "compat_mode" : "\"cubrid\"",
         "compat_primary_key" : "n",
         "connection_timeout" : "5",
         "create_table_reuseoid" : "y",
         "csql_auto_commit" : "y",
         "csql_history_num" : "50",
         "csql_single_line_mode" : "n",
         "cte_max_recursions" : "2000",
         "cubrid_port_id" : "1523",
         "data_aout_ratio" : "0.000000",
         "data_buffer_neighbor_flush_nondirty" : "n",
         "data_buffer_neighbor_flush_pages" : "8",
         "data_buffer_pages" : "32768",
         "data_buffer_size" : "512.0M",
         "data_file_os_advise" : "0",
         "db_hosts" : "\"\"",
         "db_volume_size" : "512.0M",
         "dblink_auto_commit" : "y",
         "ddl_audit_log" : "n",
         "ddl_audit_log_size" : "10.0M",
         "deadlock_detection_interval_in_secs" : "1.000000",
         "deduplicate_key_level" : "-1",
         "default_histogram_bucket_count" : "300",
         "default_week_format" : "0",
         "dont_reuse_heap_file" : "n",
         "double_write_buffer_size" : "2097152",
         "enable_memory_monitoring" : "n",
         "enable_string_compression" : "y",
         "error_log" : "\"cub_client.err\"",
         "error_log_level" : "\"notification\"",
         "error_log_production_mode" : "y",
         "error_log_size" : "536870912",
         "error_log_warning" : "n",
         "event_activation_list" : "",
         "event_handler" : "\"\"",
         "extended_statistics_activation" : "15",
         "flashback_timeout" : "300",
         "force_remove_log_archives" : "y",
         "garbage_collection" : "n",
         "group_commit_interval_in_msecs" : "0",
         "group_concat_max_len" : "1.0K",
         "ha_apply_max_mem_size" : "500",
         "ha_applylogdb_ignore_error_list" : "",
         "ha_applylogdb_max_commit_interval" : "500 msec",
         "ha_applylogdb_max_commit_interval_in_msecs" : "500",
         "ha_applylogdb_retry_error_list" : "",
         "ha_check_disk_failure_interval" : "15.000 sec",
         "ha_copy_log_base" : "\"\"",
         "ha_copy_log_max_archives" : "1",
         "ha_copy_log_timeout" : "5",
         "ha_copy_sync_mode" : "\"\"",
         "ha_db_list" : "\"\"",
         "ha_delay_limit" : "0 msec",
         "ha_delay_limit_delta" : "0 msec",
         "ha_enable_sql_logging" : "n",
         "ha_mode" : "\"off\"",
         "ha_node_list" : "\"ai-work-49@ai-work-49\"",
         "ha_ping_hosts" : "\"\"",
         "ha_port_id" : "59901",
         "ha_repl_filter_file" : "\"\"",
         "ha_repl_filter_type" : "\"none\"",
         "ha_replica_delay" : "0 msec",
         "ha_replica_list" : "\"\"",
         "ha_replica_time_bound" : "\"\"",
         "ha_sql_log_max_count" : "2",
         "ha_sql_log_max_size_in_mbytes" : "50",
         "ha_sql_log_path" : "\"\"",
         "ha_tcp_ping_hosts" : "\"\"",
         "ha_unacceptable_proc_restart_timediff" : "120.000 sec",
         "hardware_affinity" : "n",
         "index_scan_in_oid_order" : "n",
         "index_scan_key_buffer_pages" : "20",
         "index_scan_key_buffer_size" : "320.0K",
         "index_scan_oid_buffer_pages" : "4.000000",
         "index_scan_oid_buffer_size" : "64.0K",
         "index_unfill_factor" : "0.050000",
         "intl_check_input_string" : "n",
         "intl_collation" : "\"utf8_bin\"",
         "intl_date_lang" : "\"en_US\"",
         "intl_mbs_support" : "n",
         "intl_number_lang" : "\"en_US\"",
         "isolation_level" : "\"tran_rep_class_commit_instance\"",
         "json_max_array_idx" : "65536",
         "loaddb_worker_count" : "8",
         "lock_escalation" : "100000",
         "lock_timeout" : "1.000 sec",
         "lock_timeout_in_secs" : "1",
         "log_buffer_pages" : "16384",
         "log_buffer_size" : "256.0M",
         "log_compress" : "y",
         "log_max_archives" : "2147483647",
         "log_trace_flush_time" : "0 msec",
         "log_volume_size" : "512.0M",
         "lru_buffer_ratio" : "0.050000",
         "lru_hot_ratio" : "0.400000",
         "max_agg_hash_size" : "2.0M",
         "max_clients" : "100",
         "max_connection_worker" : "2",
         "max_filter_pred_cache_entries" : "1000",
         "max_flush_pages_per_second" : "10000",
         "max_flush_size_per_second" : "156.2M",
         "max_hash_list_scan_size" : "8.0M",
         "max_parallel_workers" : "100",
         "max_plan_cache_clones" : "1000",
         "max_plan_cache_entries" : "1000",
         "max_query_cache_entries" : "0",
         "max_query_per_tran" : "100",
         "max_subquery_cache_size" : "2.0M",
         "memoize_memory_limit" : "2.0M",
         "min_connection_worker" : "4",
         "monitor_waiting_thread" : "0",
         "multi_range_optimization_limit" : "100",
         "mysql_trigger_correlation_names" : "n",
         "no_backslash_escapes" : "y",
         "num_private_chains" : "-1",
         "only_full_group_by" : "n",
         "optimization_level" : "1",
         "oracle_compat_number_behavior" : "n",
         "oracle_style_empty_string" : "n",
         "page_flush_interval" : "1.000 sec",
         "page_flush_interval_in_msecs" : "1000",
         "parallelism" : "4",
         "pipes_as_concat" : "y",
         "pl_transaction_control" : "n",
         "plan_cache_logging" : "n",
         "plan_cache_timeout" : "-1",
         "plus_as_concat" : "y",
         "print_index_detail" : "n",
         "pthread_scope_process" : "y",
         "query_cache_size_in_pages" : "0",
         "query_trace" : "n",
         "query_trace_format" : "\"text\"",
         "recovery_progress_logging_interval" : "0",
         "recv_budget_per_connection" : "16384",
         "regexp_engine" : "\"re2\"",
         "require_like_escape_character" : "n",
         "return_null_on_function_errors" : "n",
         "rollback_on_lock_escalation" : "n",
         "send_budget_per_connection" : "32768",
         "server_timezone" : "\"Asia/Seoul\"",
         "service::server" : "\"\"",
         "service::service" : "\"\"",
         "session_state_timeout" : "21600",
         "sort_buffer_pages" : "128",
         "sort_buffer_size" : "2.0M",
         "sort_limit_max_count" : "1000",
         "sql_trace_execution_plan" : "0",
         "sql_trace_ioread_pages" : "0",
         "sql_trace_slow" : "-1",
         "sql_trace_slow_msecs" : "-1",
         "stored_procedure" : "y",
         "stored_procedure_dump_icode" : "n",
         "stored_procedure_port" : "0",
         "stored_procedure_uds" : "y",
         "stored_procedure_vm_options" : "\"\"",
         "string_max_size_bytes" : "1.0M",
         "supplemental_log" : "0",
         "sync_on_flush_size" : "3.1M",
         "sync_on_nflush" : "200",
         "task_group" : "1",
         "task_worker" : "-1",
         "tcp_keepalive" : "y",
         "tcp_keepalive_count" : "3",
         "tcp_keepalive_idle" : "300",
         "tcp_keepalive_interval" : "300",
         "tde_default_algorithm" : "\"aes\"",
         "tde_keys_file_path" : "\"\"",
         "temp_file_max_size_in_pages" : "-1",
         "temp_file_memory_size_in_pages" : "4",
         "temp_volume_path" : "\"\"",
         "thread_connection_pooling" : "y",
         "thread_connection_timeout_seconds" : "300",
         "thread_stacksize" : "1.0M",
         "thread_worker_pooling" : "y",
         "thread_worker_timeout_seconds" : "300",
         "timezone" : "\"Asia/Seoul\"",
         "tz_leap_second_support" : "n",
         "unfill_factor" : "0.100000",
         "unicode_input_normalization" : "n",
         "unicode_output_normalization" : "n",
         "update_statistics_update_histogram" : "n",
         "update_use_attribute_references" : "n",
         "use_orderby_sort_limit" : "y",
         "use_stat_estimation" : "n",
         "use_user_hosts" : "n",
         "vacuum_log_block_pages" : "0",
         "vacuum_master_interval_in_msecs" : "10",
         "vacuum_ovfp_check_duration" : "45000",
         "vacuum_ovfp_check_threshold" : "1000",
         "vacuum_worker_count" : "10",
         "volume_extension_path" : "\"\"",
         "xasl_cache_time_threshold_in_minutes" : "360"
      }
   ],
   "dbname" : "demodb",
   "note" : "none",
   "server" : [
      {
         "access_ip_control" : "n",
         "access_ip_control_file" : "\"\"",
         "adaptive_flush_control" : "y",
         "add_column_update_hard_default" : "n",
         "agg_hash_respect_order" : "y",
         "allow_truncated_string" : "n",
         "alter_table_change_type_strict" : "y",
         "ansi_quotes" : "y",
         "async_commit" : "n",
         "auto_increment_cache_size" : "20",
         "auto_restart_server" : "y",
         "auto_scaling_window_size" : "4",
         "background_archiving" : "y",
         "backup_volume_max_size_bytes" : "0.0B",
         "bestspace_shard_count" : "8",
         "block_ddl_statement" : "n",
         "block_nowhere_statement" : "n",
         "call_stack_dump_activation_list" : "-2,-7,-13,-14,-17,-19,-21,-22,-45,-46,-48,-50,-51,-52,-76,-78,-79,-81,-90,-96,-97,-313,-314,-407,-415,-416,-417,-583,-603,-836,-859,-890,-891,-976,-1040,-1075,-1131,-1084",
         "call_stack_dump_deactivation_list" : "",
         "call_stack_dump_on_error" : "n",
         "check_peer_alive" : "\"both\"",
         "checkpoint_every_npages" : "100000",
         "checkpoint_every_size" : "1.5G",
         "checkpoint_interval" : "360.000 sec",
         "checkpoint_interval_in_mins" : "6",
         "commit_on_shutdown" : "n",
         "communication_histogram" : "n",
         "compactdb_page_reclaim_only" : "0",
         "compat_mode" : "\"cubrid\"",
         "compat_primary_key" : "n",
         "connection_timeout" : "5",
         "create_table_reuseoid" : "y",
         "csql_auto_commit" : "y",
         "csql_history_num" : "50",
         "csql_single_line_mode" : "n",
         "cte_max_recursions" : "2000",
         "cubrid_port_id" : "1523",
         "data_aout_ratio" : "0.000000",
         "data_buffer_neighbor_flush_nondirty" : "n",
         "data_buffer_neighbor_flush_pages" : "8",
         "data_buffer_pages" : "32768",
         "data_buffer_size" : "512.0M",
         "data_file_os_advise" : "0",
         "db_hosts" : "\"\"",
         "db_volume_size" : "512.0M",
         "dblink_auto_commit" : "y",
         "ddl_audit_log" : "n",
         "ddl_audit_log_size" : "10.0M",
         "deadlock_detection_interval_in_secs" : "1.000000",
         "deduplicate_key_level" : "-1",
         "default_histogram_bucket_count" : "300",
         "default_week_format" : "0",
         "dont_reuse_heap_file" : "n",
         "double_write_buffer_size" : "2097152",
         "enable_memory_monitoring" : "n",
         "enable_string_compression" : "y",
         "error_log" : "\"server/demodb_20260818_0908.err\"",
         "error_log_level" : "\"notification\"",
         "error_log_production_mode" : "y",
         "error_log_size" : "536870912",
         "error_log_warning" : "n",
         "event_activation_list" : "",
         "event_handler" : "\"\"",
         "extended_statistics_activation" : "15",
         "flashback_timeout" : "300",
         "force_remove_log_archives" : "y",
         "garbage_collection" : "n",
         "group_commit_interval_in_msecs" : "0",
         "group_concat_max_len" : "1.0K",
         "ha_apply_max_mem_size" : "500",
         "ha_applylogdb_ignore_error_list" : "",
         "ha_applylogdb_max_commit_interval" : "500 msec",
         "ha_applylogdb_max_commit_interval_in_msecs" : "500",
         "ha_applylogdb_retry_error_list" : "",
         "ha_check_disk_failure_interval" : "15.000 sec",
         "ha_copy_log_base" : "\"\"",
         "ha_copy_log_max_archives" : "1",
         "ha_copy_log_timeout" : "5",
         "ha_copy_sync_mode" : "\"\"",
         "ha_db_list" : "\"\"",
         "ha_delay_limit" : "0 msec",
         "ha_delay_limit_delta" : "0 msec",
         "ha_enable_sql_logging" : "n",
         "ha_mode" : "\"off\"",
         "ha_node_list" : "\"ai-work-49@ai-work-49\"",
         "ha_ping_hosts" : "\"\"",
         "ha_port_id" : "59901",
         "ha_repl_filter_file" : "\"\"",
         "ha_repl_filter_type" : "\"none\"",
         "ha_replica_delay" : "0 msec",
         "ha_replica_list" : "\"\"",
         "ha_replica_time_bound" : "\"\"",
         "ha_sql_log_max_count" : "2",
         "ha_sql_log_max_size_in_mbytes" : "50",
         "ha_sql_log_path" : "\"\"",
         "ha_tcp_ping_hosts" : "\"\"",
         "ha_unacceptable_proc_restart_timediff" : "120.000 sec",
         "hardware_affinity" : "n",
         "index_scan_in_oid_order" : "n",
         "index_scan_key_buffer_pages" : "20",
         "index_scan_key_buffer_size" : "320.0K",
         "index_scan_oid_buffer_pages" : "4.000000",
         "index_scan_oid_buffer_size" : "64.0K",
         "index_unfill_factor" : "0.050000",
         "intl_check_input_string" : "n",
         "intl_collation" : "\"\"",
         "intl_date_lang" : "\"\"",
         "intl_mbs_support" : "n",
         "intl_number_lang" : "\"\"",
         "isolation_level" : "\"tran_rep_class_commit_instance\"",
         "json_max_array_idx" : "65536",
         "loaddb_worker_count" : "8",
         "lock_escalation" : "100000",
         "lock_timeout" : "-1",
         "lock_timeout_in_secs" : "-1",
         "log_buffer_pages" : "16384",
         "log_buffer_size" : "256.0M",
         "log_compress" : "y",
         "log_max_archives" : "0",
         "log_trace_flush_time" : "0 msec",
         "log_volume_size" : "512.0M",
         "lru_buffer_ratio" : "0.050000",
         "lru_hot_ratio" : "0.400000",
         "max_agg_hash_size" : "2.0M",
         "max_clients" : "100",
         "max_connection_worker" : "40",
         "max_filter_pred_cache_entries" : "1000",
         "max_flush_pages_per_second" : "10000",
         "max_flush_size_per_second" : "156.2M",
         "max_hash_list_scan_size" : "8.0M",
         "max_parallel_workers" : "100",
         "max_plan_cache_clones" : "1000",
         "max_plan_cache_entries" : "1000",
         "max_query_cache_entries" : "0",
         "max_query_per_tran" : "100",
         "max_subquery_cache_size" : "2.0M",
         "memoize_memory_limit" : "2.0M",
         "min_connection_worker" : "4",
         "monitor_waiting_thread" : "0",
         "multi_range_optimization_limit" : "100",
         "mysql_trigger_correlation_names" : "n",
         "no_backslash_escapes" : "y",
         "num_private_chains" : "-1",
         "only_full_group_by" : "n",
         "optimization_level" : "1",
         "oracle_compat_number_behavior" : "n",
         "oracle_style_empty_string" : "n",
         "page_flush_interval" : "1.000 sec",
         "page_flush_interval_in_msecs" : "1000",
         "parallelism" : "4",
         "pipes_as_concat" : "y",
         "pl_transaction_control" : "n",
         "plan_cache_logging" : "n",
         "plan_cache_timeout" : "-1",
         "plus_as_concat" : "y",
         "print_index_detail" : "n",
         "pthread_scope_process" : "y",
         "query_cache_size_in_pages" : "0",
         "query_trace" : "n",
         "query_trace_format" : "\"text\"",
         "recovery_progress_logging_interval" : "0",
         "recv_budget_per_connection" : "16384",
         "regexp_engine" : "\"re2\"",
         "require_like_escape_character" : "n",
         "return_null_on_function_errors" : "n",
         "rollback_on_lock_escalation" : "n",
         "send_budget_per_connection" : "32768",
         "server_timezone" : "\"Asia/Seoul\"",
         "service::server" : "\"\"",
         "service::service" : "\"server,broker,manager\"",
         "session_state_timeout" : "21600",
         "sort_buffer_pages" : "128",
         "sort_buffer_size" : "2.0M",
         "sort_limit_max_count" : "1000",
         "sql_trace_execution_plan" : "0",
         "sql_trace_ioread_pages" : "0",
         "sql_trace_slow" : "-1",
         "sql_trace_slow_msecs" : "-1",
         "stored_procedure" : "y",
         "stored_procedure_dump_icode" : "n",
         "stored_procedure_port" : "0",
         "stored_procedure_uds" : "y",
         "stored_procedure_vm_options" : "\"\"",
         "string_max_size_bytes" : "1.0M",
         "supplemental_log" : "0",
         "sync_on_flush_size" : "3.1M",
         "sync_on_nflush" : "200",
         "task_group" : "80",
         "task_worker" : "102",
         "tcp_keepalive" : "y",
         "tcp_keepalive_count" : "3",
         "tcp_keepalive_idle" : "300",
         "tcp_keepalive_interval" : "300",
         "tde_default_algorithm" : "\"aes\"",
         "tde_keys_file_path" : "\"\"",
         "temp_file_max_size_in_pages" : "-1",
         "temp_file_memory_size_in_pages" : "4",
         "temp_volume_path" : "\"\"",
         "thread_connection_pooling" : "y",
         "thread_connection_timeout_seconds" : "300",
         "thread_stacksize" : "1.0M",
         "thread_worker_pooling" : "y",
         "thread_worker_timeout_seconds" : "300",
         "timezone" : "\"\"",
         "tz_leap_second_support" : "n",
         "unfill_factor" : "0.100000",
         "unicode_input_normalization" : "n",
         "unicode_output_normalization" : "n",
         "update_statistics_update_histogram" : "n",
         "update_use_attribute_references" : "n",
         "use_orderby_sort_limit" : "y",
         "use_stat_estimation" : "n",
         "use_user_hosts" : "n",
         "vacuum_log_block_pages" : "31",
         "vacuum_master_interval_in_msecs" : "10",
         "vacuum_ovfp_check_duration" : "45000",
         "vacuum_ovfp_check_threshold" : "1000",
         "vacuum_worker_count" : "10",
         "volume_extension_path" : "\"\"",
         "xasl_cache_time_threshold_in_minutes" : "360"
      }
   ],
   "status" : "success",
   "task" : "paramdump"
}
```

> Lists are shortened to 1 entry here; the real response returned up to 0.
