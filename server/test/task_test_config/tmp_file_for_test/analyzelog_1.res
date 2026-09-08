[Q1]
/home/yangming/cubrid/log/broker/sql_log/query_editor_1.sql.log:1
06/13 10:40:00.166 (0) CAS STARTED pid 13006
06/13 10:44:13.429 (0) CAS TERMINATED pid 13006
06/13 10:44:19.030 (0) CAS STARTED pid 13767
06/17 11:18:16.894 (0) CLIENT IP 192.168.0.1
06/17 11:18:16.911 (0) connect db ha_test@192.168.0.1 user dba url jdbc:cubrid:192.168.0.1:45000:ha_test@192.168.0.1:dba::charset=GBK
06/17 11:18:16.911 (0) DEFAULT isolation_level 3, lock_timeout -1
06/17 11:18:16.912 (0) get_version
06/17 11:18:16.912 (0) auto_commit
06/17 11:18:16.912 (0) auto_commit 0
06/17 11:18:16.912 (0) *** elapsed time 0.001
/home/yangming/cubrid/log/broker/sql_log/query_editor_1.sql.log:12
06/17 11:18:16.936 (1) prepare 0 
select class_name,owner_name,class_type,is_system_class,partitioned from db_class as a where LOWER(a.class_name) not in (select LOWER(partition_class_name) from db_partition) and is_system_class='NO' and class_type='CLASS'
06/17 11:18:16.993 (1) prepare srv_h_id 1
06/17 11:18:17.004 (1) execute srv_h_id 1 select class_name,owner_name,class_type,is_system_class,partitioned from db_class as a where LOWER(a.class_name) not in (select LOWER(partition_class_name) from db_partition) and is_system_class='NO' and class_type='CLASS'
06/17 11:18:17.007 (1) execute 0 tuple 7 time 0.094
06/17 11:18:17.025 (0) con_close
06/17 11:18:17.026 (0) disconnect
06/17 11:18:17.026 (0) STATE idle
06/17 11:18:52.616 (0) CLIENT IP 192.168.0.1
06/17 11:18:52.617 (0) connect db ha_test@192.168.0.1 user dba url jdbc:cubrid:192.168.0.1:45000:ha_test@192.168.0.1:dba::charset=GBK
06/17 11:18:52.617 (0) DEFAULT isolation_level 3, lock_timeout -1
06/17 11:18:52.618 (0) get_version
06/17 11:18:52.618 (0) auto_commit
06/17 11:18:52.618 (0) auto_commit 0
06/17 11:18:52.618 (0) *** elapsed time 0.000
