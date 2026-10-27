# get_mon_interval

Get the monitoring statistic interval.

Permissions required to run this task: none (any logged-in user)

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token returned by login |

## Request Sample

```
{
  "task": "get_mon_interval",
  "token": "4504b930fc1be99bf5dfd31fc5799faaa3f117fb903f397de087cd3544165d857926f07dd201b6aa"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here. |
| interval | monitoring interval(seconds) |

## Response Sample

```
{
  "task": "get_mon_interval",
  "interval": 60,
  "status": "success",
  "note": "none"
}
```
