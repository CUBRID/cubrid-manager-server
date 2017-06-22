# broker_stop

The broker_stop interface will stop specified broker.

## Request Json Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |


## Request Sample

```
{
  "task": "broker_stop",
  "token": "cdfb4c5717170c5e9c6856b4d1c61ee8132bcc7d82bd609066ed9ece2554c47f7926f07dd201b6aa",
  "bname": "broker1"
}
```
