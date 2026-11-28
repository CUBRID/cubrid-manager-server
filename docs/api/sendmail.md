# sendmail

Send one mail through the SMTP server set by `smtp_server` in `cm.conf`, for example to check the
mail settings, and answer only whether it was sent.

- The server is always the one of `smtp_server` in `cm.conf` (see
  [SMTP server of sendmail](README.md#smtp-server-of-sendmail)); there is no default. When it is
  not set, or was not valid at startup, the task fails with
  `smtp_server is not configured in cm.conf.` without connecting anywhere. `smtp_server` of the
  request is ignored.
- The SMTP server is not looked up from the receiver's domain (no MX lookup).
- A failure is answered with `Failed to send mail.` only, whatever went wrong: the server refused
  the mail or the login, did not answer, could not be reached, or its name could not be
  resolved. The reply of the server and the reason are written to the CMS error log
  (`cub_manager.err`), with the step that failed.
- Each wait for the server (connecting, each reply) is at most 30 seconds.
- The mail is sent as UTF-8; the subject and the body may be in any language.
- CR, LF and NUL in `sender`, `receiver` and `msg_header` are refused before connecting.

Permissions required to run this task: one of DBC, DBO, MON

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token returned by login |
| sender | sender address, `user@host` or `name <user@host>` |
| receiver | receiver address, in the same form |
| username | SMTP user name. Optional; without it, or empty, no authentication |
| password | SMTP password. Optional |
| authtype | 1: AUTH LOGIN, 2: AUTH PLAIN. Optional, default 2 |
| msg_header | subject. Optional |
| msg_body | body. Optional |
| body_type | 1: HTML, otherwise plain text. Optional, default plain text |
| smtp_server | ignored; the server is set by `smtp_server` in `cm.conf` |

## Request Sample

```
{
  "task": "sendmail",
  "token": "cdfb4c5717170c5e9c6856b4d1c61ee8132bcc7d82bd609066ed9ece2554c47f7926f07dd201b6aa",
  "sender": "CUBRID Manager <cms@example.com>",
  "receiver": "dba@example.com",
  "username": "cms",
  "password": "secret",
  "authtype": 2,
  "msg_header": "mail settings test",
  "msg_body": "This is a test mail from CUBRID Manager Server.",
  "body_type": 0
}
```

## Response JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| status | success when the SMTP server accepted the mail, otherwise failure |
| note | `none` on success. On failure `Failed to send mail.`, `smtp_server is not configured in cm.conf.`, or the missing parameter |

## Response Sample

```
{
  "note": "none",
  "status": "success",
  "task": "sendmail"
}
```

```
{
  "note": "Failed to send mail.",
  "status": "failure",
  "task": "sendmail"
}
```
