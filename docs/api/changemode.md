# changemode

Change active status on broker.

## Request Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |

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
