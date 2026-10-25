# dbspaceinfo

Get specified database space information.

Permissions required to run this task: none (any logged-in user)

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted |
| dbname | database name |

## Request Sample

```
{
  "task":"dbspaceinfo",
  "token":"cdfb4c5717170c5e237a227a2ceeccc6ae9e10c16754fb85371c0d74fa0d9d577926f07dd201b6aa",
  "dbname":"alatestdb"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| note | if failed, a brief description will be given here |
| status | execution result, success or failed. |
| task | task name |
| dbinfo | list of information about storage volume |
| dbname | name of database |
| fileinfo | |
| freespace | size of available space |
| logpagesize | size of log page |
| pagesize | size of each page |
| spaceinfo | list of information about space of volumes |

### dbinfo
dbinfo is composed of objects with following structure 

| **Key** | **Description** |
| --- | --- |
| free_size | size of available space |
| purpose | purpose of the volume |
| total_size | total size of the volume |
| type | type of the volume | 
| used_size | size of the used space |
| volume_count | number of the volume |

### fileinfo
fileinfo is composed of objects with following structure 

| **Key** | **Description** |
| --- | --- |
| data_type | data type |
| file_count | number of the files |
| file_table_size | size of file_table |
| reserved_size | size of reserved space |
| total_size | total size of the file |
| used_size | used size of the file |


### spaceinfo
spaceinfo is composed of objects with following structure

| **Key** | **Description** |
| --- | --- |
| data | creation date of volume | 
| freepage | the total of avaliable pages |
| location | path of volume file |
| purpose | purpose of the volume |
| spacename | name of the volume |
| totalpage | number of total pages |
| type | type of the volume |
| usedpage | number of used page |
| volid | id of the volume |


## Response Sample

```
{
   "__EXEC_TIME" : "37 ms",
   "dbinfo" : [
      {
         "free_size" : "27904",
         "purpose" : "PERMANENT",
         "total_size" : "32768",
         "type" : "PERMANENT",
         "used_size" : "4864",
         "volume_count" : "1"
      },
      {
         "free_size" : "0",
         "purpose" : "TEMPORARY",
         "total_size" : "0",
         "type" : "PERMANENT",
         "used_size" : "0",
         "volume_count" : "0"
      },
      {
         "free_size" : "0",
         "purpose" : "TEMPORARY",
         "total_size" : "0",
         "type" : "TEMPORARY",
         "used_size" : "0",
         "volume_count" : "0"
      }
   ],
   "dbname" : "ha_test",
   "fileinfo" : [
      {
         "data_type" : "INDEX",
         "file_count" : "28",
         "file_table_size" : "28",
         "reserved_size" : "1732",
         "total_size" : "1792",
         "used_size" : "32"
      },
      {
         "data_type" : "HEAP",
         "file_count" : "39",
         "file_table_size" : "39",
         "reserved_size" : "2396",
         "total_size" : "2496",
         "used_size" : "61"
      },
      {
         "data_type" : "SYSTEM",
         "file_count" : "8",
         "file_table_size" : "8",
         "reserved_size" : "473",
         "total_size" : "512",
         "used_size" : "31"
      },
      {
         "data_type" : "TEMP",
         "file_count" : "0",
         "file_table_size" : "0",
         "reserved_size" : "0",
         "total_size" : "0",
         "used_size" : "0"
      }
   ],
   "freespace" : "2471028",
   "logpagesize" : "16384",
   "note" : "none",
   "pagesize" : "16384",
   "spaceinfo" : [
      {
         "date" : "20250630",
         "freepage" : "27904",
         "location" : "/home/cubrid/HA_TEST/ha_test",
         "purpose" : "PERMANENT",
         "spacename" : "/home/cubrid/HA_TEST/ha_test",
         "totalpage" : "32768",
         "type" : "PERMANENT",
         "usedpage" : "4864",
         "volid" : "0"
      },
      {
         "date" : "20250630",
         "freepage" : " ",
         "location" : "/home/cubrid/HA_TEST",
         "spacename" : "ha_test_lgat",
         "totalpage" : "32768",
         "type" : "Active_log"
      },
      {
         "date" : "20250630",
         "freepage" : " ",
         "location" : "/home/cubrid/HA_TEST",
         "spacename" : "ha_test_lgar_t",
         "totalpage" : "32768",
         "type" : "Archive_log"
      }
   ],
   "status" : "success",
   "task" : "dbspaceinfo"
}
```
