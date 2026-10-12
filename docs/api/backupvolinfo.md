# backupvolinfo

The backupvolinfo interface will get database backup volume information.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name |
| level | backup level, 0, 1 or 2 |
| pathname | the full path of the backup volume |

## Request Sample

```
{
  "task": "backupvolinfo",
  "token": "cdfb4c5717170c5e9c6856b4d1c61ee8132bcc7d82bd609066ed9ece2554c47f7926f07dd201b6aa",
  "dbname": "alatestdb",
  "level": "0",
  "pathname": "$CUBRID_DATABASES/alatestdb/backup/alatestdb_backup_lv0"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |
| line | a line of the output of the `cubrid backupdb -r` utility |

## Response Sample

```
{
   "__EXEC_TIME" : "82 ms",
   "line" : [
      "",
      "",
      "*** BACKUP HEADER INFORMATION ***",
      "",
      "Database Name: /home/cubrid/CUBRID-11.5.0.2441-6ba9522-Linux.x86_64/databases/alatestdb/alatestdb",
      "   DB Creation Time: Tue Aug 18 09:08:16 2026",
      "   Pagesize: 4096",
      "Backup Level: 0 (FULL LEVEL)",
      "   Start_lsa: -1|-1",
      "   Last_lsa: 781|3000",
      "Backup Time: Tue Aug 18 09:08:25 2026",
      "   Backup Unit Num: 0",
      "Release: 11.5.0",
      "   Disk Version: 11.5",
      "Backup Pagesize: 131072",
      "Zip Method: 3 (LZ4)",
      "   Zip Level: 1 (ZIP LEVEL 1)",
      "Include Active Log: YES",
      "Previous Backup Level: 0",
      "   Time: Tue Aug 18 09:08:24 2026",
      "   (start_lsa was -1|-1)",
      "",
      "Database Volume Name: /home/cubrid/CUBRID-11.5.0.2441-6ba9522-Linux.x86_64/databases/alatestdb/alatestdb_keys",
      "   Volume Identifier: -6, Size: 65 bytes (1 pages)",
      "Database Volume Name: /home/cubrid/CUBRID-11.5.0.2441-6ba9522-Linux.x86_64/databases/alatestdb/alatestdb_vinf",
      "   Volume Identifier: -5, Size: 654 bytes (1 pages)",
      "Database Volume Name: /home/cubrid/CUBRID-11.5.0.2441-6ba9522-Linux.x86_64/databases/alatestdb/alatestdb",
      "   Volume Identifier: 0, Size: 50331648 bytes (3072 pages)",
      "Database Volume Name: /home/cubrid/CUBRID-11.5.0.2441-6ba9522-Linux.x86_64/databases/alatestdb/alatestdb_data_x001",
      "   Volume Identifier: 1, Size: 16777216 bytes (1024 pages)",
      "Database Volume Name: /home/cubrid/CUBRID-11.5.0.2441-6ba9522-Linux.x86_64/databases/alatestdb/alatestdb_x002",
      "   Volume Identifier: 2, Size: 16777216 bytes (1024 pages)",
      "Database Volume Name: /home/cubrid/CUBRID-11.5.0.2441-6ba9522-Linux.x86_64/databases/alatestdb/alatestdb_lginf",
      "   Volume Identifier: -4, Size: 288 bytes (1 pages)",
      "Database Volume Name: /home/cubrid/CUBRID-11.5.0.2441-6ba9522-Linux.x86_64/databases/alatestdb/alatestdb_lgat",
      "   Volume Identifier: -2, Size: 41943040 bytes (2560 pages)",
      ""
   ],
   "note" : "none",
   "status" : "success",
   "task" : "backupvolinfo"
}
```
