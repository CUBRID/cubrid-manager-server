# generatecert

Generate a new self signed SSL certificate and its private key for CMS, and write them to the
certificate files declared in `cm.conf`. The certificate which is currently installed is backed
up before it is replaced, unless a backup of the default certificate already exists.

CMS must be restarted for the new certificate to be used.
[getcmsenv](getcmsenv.md) reports, in `is_default_cert`, whether the certificate in use is still
the default one.

## Request JSON Syntax

| **Key** | **Description** |
| --- | --- |
| task | task name |
| token | token string encrypted. |
| cname | country name of the certificate subject, for example KR |
| stname | state or province name of the certificate subject |
| loname | locality name of the certificate subject |
| orgname | organization name of the certificate subject |
| orgutname | organizational unit name of the certificate subject |
| comname | common name of the certificate subject |
| email | the email address of the certificate subject |
| days | how many days the certificate is valid for |

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
