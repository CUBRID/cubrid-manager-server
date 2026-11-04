# TLS Certificate

CMS serves its interface only over TLS (`cm_port`, default 8001). This document describes the certificate and private key CMS uses, how CMS creates and checks them, how to replace them, and how a client should authenticate the server.

## Files

| **File** | **Content** |
| --- | --- |
| `$CUBRID/conf/cm_ssl_cert.crt` | certificate in PEM. It may be followed by intermediate CA certificates (a chain), server certificate first |
| `$CUBRID/conf/cm_ssl_cert.key` | private key in PEM, without a passphrase |

The two files are a pair: the private key must be the one of the certificate. No task that takes a file path can read or write them (see [File Access](README.md#file-access)); the only task that changes them is [generatecert](generatecert.md), which replaces both.

CMS does not ship a key pair. Up to CUBRID 11.3, and in earlier develop builds, every installation shipped the same key pair; its private key is public, so TLS did not authenticate the server. CMS generates a key pair of its own on the first start instead, and replaces a key pair an earlier version shipped.

## Startup check

When CMS starts, after reading `cm.conf` and before it starts serving TLS, it checks the two files. `ssl_cert_auto_generate` in `cm.conf` (`YES` or `NO`, default `YES`) decides whether CMS may generate or replace them. Any other value is reported and `YES` is used.

| **State of the files** | **YES (default)** | **NO** |
| --- | --- | --- |
| both missing (a link whose target is missing counts as missing) | generate a key pair, start | do not start |
| only one exists | do not start, keep the file | do not start, keep the file |
| a key pair shipped by an earlier version | replace it, start | start with an error log (do not start if a file cannot be read, the pair does not match or TLS refuses it) |
| a file cannot be read (permission, not PEM, protected by a passphrase) | do not start, keep the files | do not start, keep the files |
| the certificate and key do not match | do not start | do not start |
| any other pair (generated before, installed by the administrator, issued by a CA) | use it as is | use it as is |
| TLS refuses the pair it would use (for example a key smaller than the OpenSSL security level allows) | do not start, keep the files | do not start, keep the files |
| generation fails (for example `conf` is not writable) | do not start, keep the files | - |
| a path is not a regular file (for example a directory) | do not start | do not start |

- A shipped key is recognized by its public key (SHA-256 of the public key in DER), not by the certificate file, so a certificate re-signed with a shipped key, or issued by a CA for one, is also replaced. When either file holds a shipped key, the pair is replaced with `YES` even if the files do not match or one of them cannot be read: the key is public, so there is nothing to lose.
- Before using a pair it keeps or has generated, CMS loads it into a TLS context the way the server does. OpenSSL refuses for example an RSA 1024 key when its security level is 2 or higher, which depends on how OpenSSL is built and configured. The RSA 1024 keys shipped with CUBRID 11.3 and earlier and with some develop builds are such keys, so with `NO` an installation upgraded from 11.3 may not start; set `YES`, or install a key pair of RSA 2048 bits or more. At security level 3 or higher, OpenSSL refuses RSA 2048 too, including the key CMS generates.
- A replacement writes the new key and certificate to `<file>.tmp-<8 hex digits>` and sets the previous private key aside as `cm_ssl_cert.key.old-<8 hex digits>` until both are in place; when there is no previous key (the first generation), an empty `cm_ssl_cert.key.new-<8 hex digits>` records that instead. Like the key itself, these files (and any `cm_ssl_cert.key.*` or `cm_ssl_cert.crt.*` in `conf`) cannot be read or written by a file task, also while a replacement runs. If CMS stopped in the middle of one (a crash or power loss), the next start first puts the previous key pair back (for the first generation, removes the new key, so that `YES` generates again) or, when the replacement had completed, removes the previous key, and removes these files, whatever `ssl_cert_auto_generate` is; this is logged.
- When only one file exists, CMS never overwrites it: it may be a key the administrator is installing, and the private key of a CA-issued certificate cannot be recovered.
- With `YES`, the files `cm_ssl_cert_1024.crt/.key` and `cm_ssl_cert_2048.crt/.key` that an earlier version installed in `conf` are removed when they hold a shipped key. Other files of these names are left as they are. With `NO`, nothing is removed.
- When CMS does not start, the reason is printed on standard error, and the reason and what to do are written to `$CUBRID/log/manager/cub_manager.err`. For example:

```
CUBRID Manager Server : the SSL certificate /home/cubrid/CUBRID/conf/cm_ssl_cert.crt and private key /home/cubrid/CUBRID/conf/cm_ssl_cert.key do not match. See /home/cubrid/CUBRID/log/manager/cub_manager.err for what to do.
```

- On every start, CMS writes the SHA-256 fingerprint of the certificate in use to `$CUBRID/log/manager/cub_manager.log`, in the form `openssl` prints it:

```
SSL certificate /home/cubrid/CUBRID/conf/cm_ssl_cert.crt, SHA256 Fingerprint=89:03:15:76:...:AA:54
```

```
openssl x509 -in $CUBRID/conf/cm_ssl_cert.crt -noout -fingerprint -sha256
```

- With `NO` and a shipped key pair, CMS writes an error log on every start and [getcmsenv](getcmsenv.md) returns `is_default_cert` `yes`. `NO` is meant only for an environment that cannot change its certificate yet; it is not recommended.

## Generated certificate

| **Item** | **Value** |
| --- | --- |
| key | RSA 2048, generated for each installation. The private key is written with mode 0600 |
| version, serial number | X.509 v3, a random positive 128-bit serial number |
| signature | sha256WithRSAEncryption |
| subject, issuer | `C=KR, ST=SEOUL, L=Default City, O=CUBRID, OU=RND, CN=<host name>, emailAddress=admin@cubrid.com`, self-signed. When the host name is unknown, is not a valid DNS name (only letters, digits, `-` and `.`; for example a name with `_`) or is longer than 64 characters, CN is `cubrid-manager-server` |
| basic constraints | critical, CA:FALSE |
| key usage | critical, digitalSignature, keyEncipherment |
| extended key usage | serverAuth |
| subject key identifier | hash |
| subject alternative name | DNS: the host name (only when it is a valid DNS name), `localhost`; IP: `127.0.0.1`, `::1` and the IPv4 and IPv6 addresses of the network interfaces that are up (loopback, link-local, unspecified, IPv4-mapped and duplicate addresses excluded, at most 32) |
| validity | from one day before generation (for client clock skew), for 10 years |

The key and certificate are written to temporary files and renamed into place, so the two files always change together. When a path was a symbolic link, the link itself becomes a regular file. Only SHA-256 is used, so generation and the startup check also work with OpenSSL in FIPS mode.

## Replacing the key pair

The running CMS keeps the certificate it loaded at startup; a change to the files takes effect at the next start. Clients that pinned the old certificate see a new fingerprint (see [Server authentication by clients](#server-authentication-by-clients)).

### Install a certificate of your own (for example one issued by a CA)

1. `cubrid manager stop`
2. Replace both files together:
   - `cm_ssl_cert.crt`: the server certificate in PEM, followed by the intermediate CA certificates, if any.
   - `cm_ssl_cert.key`: the private key of that certificate in PEM, without a passphrase, readable by the account CMS runs as. Restrict it to that account (`chmod 600`).
   - Use a key OpenSSL accepts at its security level, for example RSA 2048 bits or more; CMS does not start with a key OpenSSL refuses.
3. `cubrid manager start`, and check the fingerprint in `cub_manager.log`.

CMS uses such a pair as it is and never replaces it, whatever `ssl_cert_auto_generate` is, unless it holds a shipped key.

### Generate a new key pair

- With `ssl_cert_auto_generate=YES`: `cubrid manager stop`, remove `cm_ssl_cert.crt` and `cm_ssl_cert.key`, then `cubrid manager start`. Remove both files: when only one is missing, CMS does not start.
- Or run [generatecert](generatecert.md) (ADMIN), and restart CMS.

Generate a new key pair when the private key may have leaked, or when the certificate no longer covers the addresses clients connect to: the subject alternative names are taken when the certificate is generated, so a client that verifies host names and connects by an IP address the server did not have then fails. A client that pins the fingerprint, or connects by host name, is not affected by an address change.

### Upgrade from an earlier version

On the first start after the upgrade, a shipped key pair (regular files, or links to `cm_ssl_cert_1024.*` / `cm_ssl_cert_2048.*`) is replaced and the leftover files are removed; the replacement is logged in `cub_manager.err`. If a CA issued a certificate for a shipped key, the replaced certificate is gone: request a new certificate for the new key and install it as above.

### Containers

The key pair is in `$CUBRID/conf`. If `conf` is not on a volume, every new container generates a new key pair, and clients see a new fingerprint each time. Keep `conf` on a volume.

## Server authentication by clients

A client must authenticate CMS by its certificate. Two ways fit CMS:

- **Fingerprint pinning (self-signed certificate, default).** On the first connection, show the SHA-256 fingerprint and let the user compare it with the one in `cub_manager.log` before accepting it. Store it per host and port, and afterwards connect only when it matches exactly. When it does not match, refuse the connection and warn the user that it may have changed through an upgrade or regeneration; update the stored fingerprint only when the user explicitly trusts the new one.
- **PKI verification (CA-issued certificate, or the CMS certificate added to the client's own trust store).** Verify the chain to a trusted CA, the host name or IP address against the subject alternative names (not the CN), the validity period and the serverAuth extended key usage.

In both cases:

- Do not use a trust manager that trusts every certificate or a host name verifier that accepts every host, and do not reconnect without verification when the verification fails.
- Configure the trust per connection, not for the whole JVM or process.
- Use TLS 1.2 or later (CMS accepts nothing older).
- Treat the keys shipped by earlier versions as untrusted. When [getcmsenv](getcmsenv.md) returns `is_default_cert` `yes`, warn that the server uses a public key.
