# checkfile

## Request JSON Syntax

| **Key** | **Description**         |
| ------- | ----------------------- |
| task    | task name               |
| token   | token string encrypted. |
| file    | a file path to check for. It can be given more than once to check several files at once |

## Request Sample

```
{
    "task":"checkfile",
    "token": "cdfb4c5717170c5e9c6856b4d1c61ee8132bcc7d82bd609066ed9ece2554c47f7926f07dd201b6aa",
    "file": "$CUBRID/log/manager/cub_manager.log"
}

```

## Response JSON Syntax

| **Key** | **Description**                                   |
| ------- | ------------------------------------------------- |
| note    | if failed, a brief description will be given here |
| status  | execution result, success or failed.              |
| task    | task name                                         |
| existfile | a file of the request which exists. It is returned once per existing file |

## Response Sample

```
{
   "__EXEC_TIME" : "0 ms",
   "existfile" : "/home/cubrid/CUBRID-11.5.0.2441-6ba9522-Linux.x86_64/log/manager/cub_manager.log",
   "note" : "none",
   "status" : "success",
   "task" : "checkfile"
}
```
