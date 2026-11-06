# generatecert

> **Debug builds only.** Release builds do not offer this task and answer
> `Undefined request - generatecert`: replacing the key pair from a remote request would change the
> identity of the server, and the fingerprint clients pinned, without the server administrator
> knowing. In a release build, regenerate on the server instead: stop CMS, remove
> `cm_ssl_cert.crt` and `cm_ssl_cert.key`, and start it with `ssl_cert_auto_generate=YES`
> (see [TLS Certificate](ssl_certificate.md#generate-a-new-key-pair)).

Generate a new key pair (a self-signed certificate and its private key) for CMS, and replace
`$CUBRID/conf/cm_ssl_cert.crt` and `$CUBRID/conf/cm_ssl_cert.key` with it. The certificate is the
same as the one CMS generates at startup (see [TLS Certificate](ssl_certificate.md#generated-certificate)),
except for the subject and validity given in the request.

- The existing certificate and private key are replaced, whatever they are (including a
  certificate issued by a CA), and are not backed up. No `.bak` file is created.
- The two files are written to temporary files and renamed into place together; the private key
  has mode 0600. If the task fails, both files are left as they were.
- The running CMS keeps using the certificate it loaded; the new one is used after CMS is
  restarted. Clients that pinned the old certificate then see a new fingerprint.
- CMS logs who requested the task and from which address (`cub_manager.err`).
- The task works whatever `ssl_cert_auto_generate` in `cm.conf` is.

Permissions required to run this task: ADMIN (debug builds only)

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token returned by login |
| cname | country name (C) of the certificate subject, two letters, for example KR. Optional |
| stname | state or province name (ST) of the certificate subject. Optional |
| loname | locality name (L) of the certificate subject. Optional |
| orgname | organization name (O) of the certificate subject. Optional |
| orgutname | organizational unit name (OU) of the certificate subject. Optional |
| comname | common name (CN) of the certificate subject, up to 64 characters. Optional |
| email | email address (emailAddress) of the certificate subject. Optional |
| days | how many days the certificate is valid for, up to 36500. A value that is not a positive number means 365 |

The subject has only the fields given. When none is given, the default subject of
[the generated certificate](ssl_certificate.md#generated-certificate) is used. A field value
that a certificate cannot hold (for example a country name that is not two letters) fails the
task. The subject alternative names are those of the generated certificate: the default names and `ssl_cert_san` of `cm.conf`.

## Request Sample

```
{
  "task": "generatecert",
  "token": "cdfb4c5717170c5e9c6856b4d1c61ee8132bcc7d82bd609066ed9ece2554c47f7926f07dd201b6aa",
  "cname": "KR",
  "stname": "Gyeonggi",
  "loname": "Seongnam",
  "orgname": "CUBRID",
  "orgutname": "CUBRID",
  "comname": "cubrid.org",
  "email": "admin@cubrid.org",
  "days": "365"
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
   "__EXEC_TIME" : "426 ms",
   "note" : "none",
   "status" : "success",
   "task" : "generatecert"
}
```
