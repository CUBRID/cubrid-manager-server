# setautojobconf

Save a configuration of the automation jobs in `autojobs.conf`.

Permissions required to run this task: one of DBC, DBO, JOB

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token returned by login |
| service | the configuration to save: `mail_config`, `mail_report` or `auto_start` |
| jobconf | the configuration; it replaces the saved one of `service` as a whole |

### password of mail_config

* For `mail_config`, `jobconf` must be an object.
* `password`: the SMTP password. It is stored encrypted and never returned by `getautojobconf`.
* When `password` is missing or empty, the saved password is kept, so a client can save the `mail_config` it got from `getautojobconf` (which has no `password`) without losing the password. A password cannot be cleared to empty this way.
* To use an SMTP server without authentication, save `mail_config` with an empty `username`: authentication is used only when `username` is not empty, so the saved password is then not used.

## Request Sample

```
{
  "task": "setautojobconf",
  "token": "",
  "service": "mail_config",
  "jobconf": {
    "onoff": 1,
    "receiver": "dba@example.com"
  }
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | execution result, success or failed. |
| note | if failed, a brief description will be given here |

## Response Sample

```
{
   "note" : "none",
   "status" : "success",
   "task" : "setautojobconf"
}
```
