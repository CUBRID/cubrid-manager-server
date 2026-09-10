# getenv

Get the environment of the CUBRID installation which CMS manages: the directories, the version
of the engine and of the broker, the host monitoring flags and the operating system.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |

## Request Sample

```
{
  "task": "getenv",
  "token": "cdfb4c5717170c5e9c6856b4d1c61ee8132bcc7d82bd609066ed9ece2554c47f7926f07dd201b6aa"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |
| CUBRID | the CUBRID installation directory |
| CUBRID_DATABASES | the directory of the databases |
| CUBRID_DBMT | the directory of the manager server, it has the same value as CUBRID |
| CUBRIDVER | the version of the CUBRID engine, `version information not available` when `cubrid_rel` cannot be executed |
| BROKERVER | the version of the broker, `version information not available` when `cubrid_broker --version` cannot be executed |
| HOSTMONTAB0 | ON or OFF, the first host monitoring flag of cm.conf |
| HOSTMONTAB1 | ON or OFF, the second host monitoring flag of cm.conf |
| HOSTMONTAB2 | ON or OFF, the third host monitoring flag of cm.conf |
| HOSTMONTAB3 | ON or OFF, the fourth host monitoring flag of cm.conf |
| osinfo | the operating system of the host: NT, LINUX, AIX, HPUX, UNIXWARE7, SOLARIS or unknown |

## Response Sample

```
{
   "BROKERVER" : "VERSION 11.5.0.2441",
   "CUBRID" : "/home/cubrid/CUBRID-11.5.0.2441-6ba9522-Linux.x86_64",
   "CUBRIDVER" : "CUBRID 11.5.0 (11.5.0.2441-6ba9522) (64bit release build for Linux) (Aug 14 2026 12:08:01)",
   "CUBRID_DATABASES" : "/home/cubrid/CUBRID-11.5.0.2441-6ba9522-Linux.x86_64/databases",
   "CUBRID_DBMT" : "/home/cubrid/CUBRID-11.5.0.2441-6ba9522-Linux.x86_64",
   "HOSTMONTAB0" : "OFF",
   "HOSTMONTAB1" : "OFF",
   "HOSTMONTAB2" : "OFF",
   "HOSTMONTAB3" : "OFF",
   "__EXEC_TIME" : "32 ms",
   "note" : "none",
   "osinfo" : "LINUX",
   "status" : "success",
   "task" : "getenv"
}
```
