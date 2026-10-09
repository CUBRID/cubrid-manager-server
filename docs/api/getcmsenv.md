# getcmsenv

Get the CUBRID Manager server environment variables.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |


## Request Sample

```
{
 "task":"getcmsenv",
 "token":"4504b930fc1be99bf5dfd31fc5799faaa3f117fb903f397de087cd3544165d857926f07dd201b6aa"
 }
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name. The server answers `getversion` here, not `getcmsenv` |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |
| CMS_VER | the build number of CMS |
| CUBRIDVER | the version of the CUBRID engine |
| PLATFORM | the processor architecture of the host |
| cm_port | the port CMS listens on |
| is_default_cert | yes or no, the SSL certificate in use is still the default one shipped with CMS |

## Response Sample

```
{
   "CMS_VER" : "11.4.0.0080",
   "CUBRIDVER" : "CUBRID 11.5.0 (11.5.0.2441-6ba9522) (64bit release build for Linux) (Aug 14 2026 12:08:01)",
   "PLATFORM" : "x64",
   "__EXEC_TIME" : "12 ms",
   "cm_port" : "8001",
   "is_default_cert" : "no",
   "note" : "none",
   "status" : "success",
   "task" : "getversion"
}
```
