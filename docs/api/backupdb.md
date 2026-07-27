# backupdb

The backupdb interface will create a database backup file.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |

## Request Sample

```
{
  "task": "backupdb",
  "token": "cdfb4c5717170c5e237a227a2ceeccc6ae9e10c16754fb85371c0d74fa0d9d577926f07dd201b6aa",
  "dbname": "alatestdb",
  "level": "0",
  "backupdir": "$CUBRID_DATABASES/alatestdb/backup",
  "volname": "alatestdb_backup_lv0",
  "removelog": "n",
  "check": "y",
  "mt": "0",
  "zip": "y",
  "safereplication": "n"
}
```
## additional information about *backupdir* and *volume*
* The final backup directory is determined by the **backupdir** and **volname** parameters. <br>
  - If the value of backupdir is **/tmp/backupdir** and the value of volname is **lv0**,
  - the final database backup directory becomes **/tmp/backupdir/lv0**.
* If **volname is omitted**, backupdir is used as the database backup directory.
* The final backup directory name must be used as the **pathname** for the restoredb API.
* *volname* can be omitted, but *backupdir* cannot.
