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

### mail_config

`automail` sends the mail report with these members of `mail_config`:

| **Key** | **Description** |
| --- | --- |
| onoff | 1 to send the mail report, 0 not to |
| smtp_server | host name or IP address of the SMTP server; the port is always 25 |
| sender | sender address, `user@host` or `name <user@host>` |
| username | SMTP user name; empty for no authentication |
| password | SMTP password (see below) |
| authtype | 1: AUTH LOGIN, 2: AUTH PLAIN (default) |

The report is sent as a UTF-8 HTML mail. Each wait for the SMTP server (connecting, each reply) is at most 30 seconds. A mail that cannot be sent is logged in the CMS log with the reason; the `automail` response tells only whether it was sent.

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
