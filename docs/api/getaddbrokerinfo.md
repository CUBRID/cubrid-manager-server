# getaddbrokerinfo

Get borker configurations from a cubrid_broker.conf file.

## Request Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |

## Request Sample

```
{
  "task": "getaddbrokerinfo",
  "token": "cdfb4c5717170c5e237a227a2ceeccc6ae9e10c16754fb85371c0d74fa0d9d577926f07dd201b6aa",
  "confname": "brokerconf"
}
```
