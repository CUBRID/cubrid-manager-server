# getbackupinfo

Get backup info.

## Request Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| dbname | database name. |

## Request Sample

```
{
  "task": "getbackupinfo",
  "token": "cdfb4c5717170c5e9c6856b4d1c61ee8132bcc7d82bd609066ed9ece2554c47f7926f07dd201b6aa",
  "dbname": "alatestdb"
}
```
