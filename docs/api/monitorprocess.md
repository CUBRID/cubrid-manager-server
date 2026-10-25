# monitorprocess

Monitor CMS process status.

Permissions required to run this task: none (any logged-in user)

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | monitorprocess |
| token | token string encrypted. |

## Request Sample

```
{
  "task": "monitorprocess",
  "token": "4504b930fc1be99bf5dfd31fc5799faaa3f117fb903f397de087cd3544165d857926f07dd201b6aa"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |
| cub_master | the value should be "exist" or "does not exist" in order to indicate whether this process exists. |

## Response Sample

```
{
  "cub_master": "does not exist",
  "note": "none",
  "status": "success",
  "task": "monitorprocess"
}
```
