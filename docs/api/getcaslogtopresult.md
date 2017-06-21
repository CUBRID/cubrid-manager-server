# getcaslogtopresult

Get databases' information in cubrid.

## Request Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| filename | a res file of broker log top utility |
| qindex | a query index |


## Request Sample

```
{
  "task": "getcaslogtopresult",
  "token": "cdfb4c5717170c5e9c6856b4d1c61ee8132bcc7d82bd609066ed9ece2554c47f7926f07dd201b6aa",
  "filename": "$CUBRID/tmp/analyzelog_1.res",
  "qindex": "[Q14]"
}
```
