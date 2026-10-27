# getautojobconf

Get a configuration of the automation jobs saved in `autojobs.conf`.

Permissions required to run this task: none (any logged-in user)

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token returned by login |
| service | the configuration to get: `mail_config`, `mail_report` or `auto_start`. Without it, the whole configuration is returned |

## Request Sample

```
{
  "task": "getautojobconf",
  "token": "",
  "service": "mail_config"
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |
| jobconf | the saved configuration of `service` as `setautojobconf` saved it; null if nothing is saved yet |

* The mail password of `mail_config` is never returned, neither in plain text nor in its stored form: `jobconf` of `mail_config` (and `mail_config` in the whole configuration) has no `password`. To keep the saved password, send `mail_config` back to `setautojobconf` without `password`.

## Response Sample

```
{
   "jobconf" : {
      "onoff" : 1,
      "receiver" : "dba@example.com"
   },
   "note" : "none",
   "status" : "success",
   "task" : "getautojobconf"
}
```
