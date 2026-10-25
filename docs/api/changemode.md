# changemode

Change active status on broker.

Permissions required to run this task: one of DBC, DBO

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token returned by login |

## Request Sample

```
{
  "task": "changemode",
  "token": "cdfb4c5717170c5e6f12e5b1643a2b67132bcc7d82bd6090e92a55cddd5950db7926f07dd201b6aa",
  "dbname": "demodb",
  "modify": "active",
  "force": "y"
}
```
