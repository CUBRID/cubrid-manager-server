# statdump

Get database statistics from a statdump utility.

Permissions required to run this task: none (any logged-in user)

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token returned by login |
| dbname | database name |

## Request Sample

```
{
  "task": "statdump",
  "token": "cdfb4c5717170c5e2d40a680732333064610bcfeec1c0d870c43c1586a92dd1f7926f07dd201b6aa",
  "dbname": "demodb"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| data_page_buffer_hit_ratio | Hit rate of Data Buffer page, refer to manual to see the equation |
| dbname | name of database |
| note | if failed, a brief description will be given here  |
| num_adaptive_flush_log_pages | number of requested log data page from adaptive flush controller  |
| num_adaptive_flush_max_pages | number of token pages those are allocated by adaptive flush controller |
| num_adaptive_flush_pages | number of requested data page from adaptive flush controller |
| num_btree_covered | number of cases where the index contains all the data required by the query  |
| num_btree_deletes | number of deleted objects |
| num_btree_get_stats | invocation count of B-tree node statistics |
| num_btree_inserts | number of inserted objects |
| num_btree_merges | number of merge operations on B-tree nodes |
| num_btree_multirange_optimization | number of times multi-range optimization was applied for queries with `WHERE ... IN ... LIMIT` conditions |
| num_btree_noncovered | number of cases where the index partially or does not contain the data |
| num_btree_resumes | number of index scan attempts exceeded due to excessive result rows |
| num_btree_splits | number of split operations on B-tree nodes |
| num_btree_updates | number of updated objects |
| num_data_page_dirties | number of dirty pages |
| num_data_page_fetches | number of fetched pages |
| num_data_page_ioreads | number of pages read from disk |
| num_data_page_iowrites | number of pages written to disk |
| num_file_creates | number of created files |
| num_file_ioreads | estimated number of read data from disk |
| num_file_iosynches | number of times synchronization with disk was performed |
| num_file_iowrites | number of times stored data to disk |
| num_file_page_allocs | number of allocated pages |
| num_file_page_deallocs | number of deallocated pages |
| num_file_removes | number of removed file |
| num_heap_stats_bestspace_entries | number of "best page' in "best page" list |
| num_heap_stats_bestspace_maxed | maximum value of "best page" which can be stored in "best page" list |
| num_log_append_records | number of appended log records |
| num_log_archives | number of stored log |
| num_log_page_ioreads | number of read log pages |
| num_log_page_iowrites | number of stored log pages |
| num_log_wals | number of requested log flush to write data page |
| num_network_requests | number of network requests |
| num_object_locks_acquired | count of object locks acquired |
| num_object_locks_converted | count of type of object lock converted |
| num_object_locks_re_requested | count of object lock re-requested |
| num_object_locks_waits | number of objects waiting for lock |
| num_page_locks_acquired | count of page locks acquired |
| num_page_locks_converted | count of type of page lock converted |
| num_page_locks_re_requested | count of page lock re-requested |
| num_page_locks_waits | number of pages waiting for lock |
| num_plan_cache_add | count of newly added entries to the query cache |
| num_plan_cache_class_oid_hash_entries |  |
| num_plan_cache_delete | count of victimization of cache entry |
| num_plan_cache_full | number of times victim search was triggered due to query cache entry limit being exceeded |
| num_plan_cache_hit | number of query string hash table hits |
| num_plan_cache_invalid_xasl_id | number of xasl_id hash table misses, number of errors caused by client requesting a victimized entry removed from server|
| num_plan_cache_lookup | number of attempt to operate query cache lookup using specific key |
| num_plan_cache_miss | number of query string hash table misses  |
| num_plan_cache_query_string_hash_entries |  |
| num_plan_cache_xasl_id_hash_entries |  |
| num_prior_lsa_list_maxed | number of times the list of previous LSAs reached its maximum size |
| num_prior_lsa_list_removed | number of times entries were moved from the previous LSA list to the log buffer  |
| num_prior_lsa_list_size | size of prior longest sequence address list |
| num_query_deletes | number of times delete queries are operated |
| num_query_holdable_cursors | number of holdable cursors in server |
| num_query_inserts | number of times insert queries are operated |
| num_query_iscans | number of times index scan is operated |
| num_query_lscans | number of times list scan is operated |
| num_query_methscans | number of times method scan is operated |
| num_query_mjoins | number of times merge join is operated |
| num_query_nljoins |  number of times nested loop join is operated|
| num_query_objfetches | number of times object is fetched |
| num_query_selects | number of times select query is operated |
| num_query_setscans | number of times set scan is operated |
| num_query_sscans | number of times full scan(sequential scan) is operated |
| num_query_updates | number of times update query is operated |
| num_sort_data_pages | number of pages found in page buffer while sorting |
| num_sort_io_pages | number of pages fetched from disk while sorting |
| num_tran_commits | number of times committed |
| num_tran_end_topops | number of terminated top operation |
| num_tran_interrupts | number of interrupts |
| num_tran_rollbacks | number of rollbacks |
| num_tran_savepoints | number of savepoints |
| num_tran_start_topops | number of started top operation |
| status | execution result, success or failed. |
| task | task name |
| time | server time |
| time_ha_replication_delay | Replication latency |


## Response Sample

```
{
   "__EXEC_TIME" : "42 ms",
   "data_page_buffer_hit_ratio" : "0",
   "dbname" : "ha_test",
   "note" : "none",
   "num_adaptive_flush_log_pages" : "0",
   "num_adaptive_flush_max_pages" : "0",
   "num_adaptive_flush_pages" : "0",
   "num_btree_covered" : "0",
   "num_btree_deletes" : "0",
   "num_btree_get_stats" : "0",
   "num_btree_inserts" : "0",
   "num_btree_merges" : "0",
   "num_btree_multirange_optimization" : "0",
   "num_btree_noncovered" : "0",
   "num_btree_resumes" : "0",
   "num_btree_splits" : "0",
   "num_btree_updates" : "0",
   "num_data_page_dirties" : "0",
   "num_data_page_fetches" : "0",
   "num_data_page_ioreads" : "0",
   "num_data_page_iowrites" : "0",
   "num_file_creates" : "0",
   "num_file_ioreads" : "0",
   "num_file_iosynches" : "0",
   "num_file_iowrites" : "0",
   "num_file_page_allocs" : "0",
   "num_file_page_deallocs" : "0",
   "num_file_removes" : "0",
   "num_heap_stats_bestspace_entries" : "0",
   "num_heap_stats_bestspace_maxed" : "0",
   "num_log_append_records" : "0",
   "num_log_archives" : "0",
   "num_log_page_ioreads" : "0",
   "num_log_page_iowrites" : "0",
   "num_log_wals" : "0",
   "num_network_requests" : "53",
   "num_object_locks_acquired" : "0",
   "num_object_locks_converted" : "0",
   "num_object_locks_re_requested" : "0",
   "num_object_locks_waits" : "0",
   "num_page_locks_acquired" : "0",
   "num_page_locks_converted" : "0",
   "num_page_locks_re_requested" : "0",
   "num_page_locks_waits" : "0",
   "num_plan_cache_add" : "0",
   "num_plan_cache_class_oid_hash_entries" : "0",
   "num_plan_cache_delete" : "0",
   "num_plan_cache_full" : "0",
   "num_plan_cache_hit" : "0",
   "num_plan_cache_invalid_xasl_id" : "0",
   "num_plan_cache_lookup" : "0",
   "num_plan_cache_miss" : "0",
   "num_plan_cache_query_string_hash_entries" : "0",
   "num_plan_cache_xasl_id_hash_entries" : "0",
   "num_prior_lsa_list_maxed" : "0",
   "num_prior_lsa_list_removed" : "0",
   "num_prior_lsa_list_size" : "0",
   "num_query_deletes" : "0",
   "num_query_holdable_cursors" : "0",
   "num_query_inserts" : "0",
   "num_query_iscans" : "0",
   "num_query_lscans" : "0",
   "num_query_methscans" : "0",
   "num_query_mjoins" : "0",
   "num_query_nljoins" : "0",
   "num_query_objfetches" : "0",
   "num_query_selects" : "0",
   "num_query_setscans" : "0",
   "num_query_sscans" : "0",
   "num_query_updates" : "0",
   "num_sort_data_pages" : "0",
   "num_sort_io_pages" : "0",
   "num_tran_commits" : "0",
   "num_tran_end_topops" : "0",
   "num_tran_interrupts" : "0",
   "num_tran_rollbacks" : "0",
   "num_tran_savepoints" : "0",
   "num_tran_start_topops" : "0",
   "status" : "success",
   "task" : "statdump",
   "time" : "2025/06/30 12:17:45",
   "time_ha_replication_delay" : "0"
}
```