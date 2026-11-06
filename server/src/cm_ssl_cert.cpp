/*
 * Copyright (C) 2008 Search Solution Corporation. All rights reserved by Search Solution.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */


/*
 * cm_ssl_cert.cpp - the TLS certificate and private key of the manager server
 *
 *   cm_ssl_cert_lock_process ()        one cub_manager per configuration (main ())
 *   cm_ssl_cert_ensure ()              startup check: keep, generate or replace
 *   cm_ssl_cert_generate ()            new key pair (generatecert, debug builds only)
 *   cm_ssl_cert_shipped_key_in_use ()  result of the startup check
 *
 *   A key is identified by the SHA-256 of its public key (DER). MD5 is not
 *   used: it is not collision resistant, and FIPS mode OpenSSL refuses it.
 *   Only EVP and X509 APIs that OpenSSL 1.1.1 and 3.x both provide are used.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <string>
#include <vector>

#if defined (WINDOWS)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#else
#include <unistd.h>
#include <pwd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <dirent.h>
#endif

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "cm_log.h"
#include "cm_ssl_cert.h"

/*
 * Key pairs shipped by earlier versions. Their private keys are public, so a
 * server using one of them is not authenticated by TLS.
 * These are all the cm_ssl_cert*.key ever committed (every branch, all history).
 * sha256: SHA-256 of the public key in DER (SubjectPublicKeyInfo), that is
 *   openssl pkey -in <key> -pubout -outform DER | sha256sum
 */
static const struct
{
  const char *sha256;
  const char *desc;
} shipped_keys[] =
{
  {
    "385bea60bf0f9e720d38bd6e22edd51cb03170aca10d77b1618578f795fb55c3",
    "RSA 1024 key shipped with CUBRID 11.3 and earlier as cm_ssl_cert.key"
  },
  {
    "71e2a53e266bc02598e4fc82de5af98be4c58e0ded64cf07a254e2b05a1549ff",
    "RSA 1024 key shipped with develop builds as cm_ssl_cert_1024.key"
  },
  {
    "2e3f2eb5108a4d6574f29793e3ac5c24be748f53b9aebf2fcc7fdf3f68624f5d",
    "RSA 2048 key shipped with develop builds as cm_ssl_cert_2048.key"
  },
};

/*
 * Files an earlier version installed next to cm_ssl_cert.crt/.key, which were
 * links to them. They are removed only when they hold a shipped key.
 */
static const char *leftover_cert_names[] = { "cm_ssl_cert_1024.crt", "cm_ssl_cert_2048.crt" };
static const char *leftover_key_names[] = { "cm_ssl_cert_1024.key", "cm_ssl_cert_2048.key" };

/*
 * Default subject: CN is the host name, the other fields keep the values of
 * the certificate shipped before (informational only, a self-signed
 * certificate is trusted by its fingerprint).
 */
#define DEFAULT_SUBJECT_C               "KR"
#define DEFAULT_SUBJECT_ST              "SEOUL"
#define DEFAULT_SUBJECT_L               "Default City"
#define DEFAULT_SUBJECT_O               "CUBRID"
#define DEFAULT_SUBJECT_OU              "RND"
#define DEFAULT_SUBJECT_EMAIL           "admin@cubrid.com"
#define DEFAULT_SUBJECT_CN              "cubrid-manager-server"	/* host name unknown or too long */

/* the cm.conf item, for the messages */
#define CONF_AUTO_GENERATE              "ssl_cert_auto_generate"

#define CERT_RSA_BITS                   2048
#define CERT_DEFAULT_DAYS               3650
#define CERT_MAX_DAYS                   36500
#define CERT_BACKDATE_DAYS              1	/* notBefore: client clock skew */
#define CERT_SERIAL_BYTES               16	/* 128 bits */
#define CERT_CN_MAX                     64	/* ub-common-name */
#define CERT_DNS_NAME_MAX               253
#define CERT_DNS_LABEL_MAX              63
#define CERT_MAX_EXTRA_SAN              32	/* entries of ssl_cert_san */
#define CERT_MAX_FILE_SIZE              (1024 * 1024)

/*
 * Work files of a replacement (install_pair ()), <suffix> being 8 lower-case
 * hex digits (random_suffix ()). A replacement that stops midway (crash, power
 * loss) leaves them behind, and recover_interrupted () reads them.
 *   <path>.tmp-<suffix>  the new key or certificate, not in place yet
 *   <key>.old-<suffix>   the previous key, set aside
 *   <key>.new-<suffix>   empty: there was no previous key (first generation)
 */
#define WORK_TMP                        ".tmp-"
#define WORK_OLD                        ".old-"
#define WORK_NEW                        ".new-"
#define WORK_SUFFIX_LEN                 8

/*
 * Lock between processes: <key>.lock, held by the cub_manager process for as
 * long as it runs (see hold_process_lock ()). CERT_LOCK_WAIT_MS covers a
 * restart, where the previous process may still be exiting.
 */
#define PROCESS_LOCK                    ".lock"
#define CERT_LOCK_WAIT_MS               5000
#define CERT_LOCK_RETRY_MS              200

#define ARRAY_COUNT(a)                  (sizeof (a) / sizeof ((a)[0]))

enum path_kind
{
  PATH_ABSENT,			/* no such file, or a link to nothing */
  PATH_FILE,			/* a regular file, or cannot tell (read reports why) */
  PATH_NOT_FILE			/* a directory or another kind of file */
};

/*
 * ssl_file - a certificate or private key file as the startup check sees it
 */
struct ssl_file
{
    const char *what;		/* "certificate" or "private key" */
    std::string path;
    bool is_key;
    path_kind kind;
    bool loaded;			/* parsed and fingerprinted */
    std::string reason;		/* why it was not loaded */
    int shipped;			/* index in shipped_keys, -1 if not shipped */
    X509 *cert;			/* certificate only */
    EVP_PKEY *pkey;		/* private key, or public key of the certificate */

    ssl_file (const char *what_, const char *path_, bool is_key_)
      : what (what_), path (path_), is_key (is_key_), kind (PATH_ABSENT), loaded (false), shipped (-1), cert (NULL),
	pkey (NULL)
    {
    }

    ~ssl_file (void)
    {
      if (cert != NULL)
	{
	  X509_free (cert);
	}
      if (pkey != NULL)
	{
	  EVP_PKEY_free (pkey);
	}
    }

  private:
    ssl_file (const ssl_file &);
    ssl_file &operator= (const ssl_file &);
};

struct san_ip
{
  int len;			/* 4 or 16 */
  unsigned char addr[16];
};

/* set by cm_ssl_cert_ensure () at startup, before any request is served */
static bool shipped_key_in_use = false;

/*
 * cert_mutex () - serializes generation and replacement of the files
 */
static mutex_t *
cert_mutex (void)
{
  struct mutex_holder
  {
    mutex_t m;

    mutex_holder (void)
    {
      mutex_init (m);
    }
    ~mutex_holder (void)
    {
      /*
       * deliberately empty
       */
    }
  };
  static mutex_holder holder;

  return &holder.m;
}

struct cert_lock
{
    cert_lock (void)
    {
      mutex_lock (*cert_mutex ());
    }
    ~cert_lock (void)
    {
      mutex_unlock (*cert_mutex ());
    }

  private:
    cert_lock (const cert_lock &);
    cert_lock &operator= (const cert_lock &);
};

/*
 * openssl_error () - the first queued OpenSSL error as text; clears the queue
 */
static std::string
openssl_error (void)
{
  unsigned long e = ERR_get_error ();
  char buf[256];

  ERR_clear_error ();
  if (e == 0)
    {
      return std::string ();
    }
  ERR_error_string_n (e, buf, sizeof (buf));
  return std::string (buf);
}

/*
 * with_openssl_error () - msg, followed by the queued OpenSSL error if any
 */
static std::string
with_openssl_error (const std::string &msg)
{
  std::string e = openssl_error ();

  return e.empty ()? msg : msg + " (" + e + ")";
}

static std::string
errno_string (int err)
{
  return std::string (strerror (err));
}

#if defined (WINDOWS)
static std::string
win_error_string (DWORD err)
{
  char buf[512];
  DWORD n;

  n = FormatMessageA (FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, err, 0, buf, sizeof (buf),
		      NULL);
  while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' || buf[n - 1] == ' ' || buf[n - 1] == '.'))
    {
      n--;
    }
  if (n == 0)
    {
      return std::string ("Windows error ") + std::to_string ((unsigned long) err);
    }
  return std::string (buf, n);
}
#endif

static std::string
to_hex (const unsigned char *p, size_t n, bool fingerprint_format)
{
  static const char lower[] = "0123456789abcdef";
  static const char upper[] = "0123456789ABCDEF";
  const char *digits = fingerprint_format ? upper : lower;
  std::string s;
  size_t i;

  for (i = 0; i < n; i++)
    {
      if (fingerprint_format && i > 0)
	{
	  s += ':';
	}
      s += digits[p[i] >> 4];
      s += digits[p[i] & 0x0f];
    }
  return s;
}

static void
copy_error (char *buf, size_t size, const std::string &msg)
{
  size_t n;

  if (buf == NULL || size == 0)
    {
      return;
    }
  n = msg.size () < size - 1 ? msg.size () : size - 1;
  memcpy (buf, msg.data (), n);
  buf[n] = '\0';
}

static void
cleanse_string (std::string &s)
{
  if (!s.empty ())
    {
      OPENSSL_cleanse (&s[0], s.size ());
    }
  s.clear ();
}

/*
 * pubkey_sha256 () - lower-case hex SHA-256 of the public key in DER
 */
static bool
pubkey_sha256 (EVP_PKEY *pkey, std::string &hex)
{
  unsigned char *der = NULL;
  unsigned char md[EVP_MAX_MD_SIZE];
  unsigned int md_len = 0;
  int der_len;
  int ok;

  der_len = i2d_PUBKEY (pkey, &der);
  if (der_len <= 0)
    {
      return false;
    }
  ok = EVP_Digest (der, (size_t) der_len, md, &md_len, EVP_sha256 (), NULL);
  OPENSSL_free (der);
  if (ok != 1)
    {
      return false;
    }
  hex = to_hex (md, md_len, false);
  return true;
}

/*
 * cert_fingerprint () - SHA-256 fingerprint of the certificate, in the form
 *   openssl x509 -noout -fingerprint -sha256 prints it (AB:CD:...)
 */
static std::string
cert_fingerprint (X509 *cert)
{
  unsigned char md[EVP_MAX_MD_SIZE];
  unsigned int md_len = 0;

  if (X509_digest (cert, EVP_sha256 (), md, &md_len) != 1)
    {
      ERR_clear_error ();
      return std::string ("(unknown)");
    }
  return to_hex (md, md_len, true);
}

static int
find_shipped_key (const std::string &sha256)
{
  size_t i;

  for (i = 0; i < ARRAY_COUNT (shipped_keys); i++)
    {
      if (sha256 == shipped_keys[i].sha256)
	{
	  return (int) i;
	}
    }
  return -1;
}

/*
 * no_passphrase () - PEM passphrase callback that refuses, so that reading a
 *   protected key fails instead of prompting on the terminal
 */
static int
no_passphrase (char *buf, int size, int rwflag, void *u)
{
  (void) buf;
  (void) size;
  (void) rwflag;
  (void) u;
  return -1;
}

/*
 * check_path () - what is at path
 *
 *   is_link(out): path itself is a symbolic link
 */
static path_kind
check_path (const std::string &path, bool *is_link)
{
#if defined (WINDOWS)
  struct _stat64 st;

  *is_link = false;
  if (_stat64 (path.c_str (), &st) != 0)
    {
      return (errno == ENOENT) ? PATH_ABSENT : PATH_FILE;
    }
  return ((st.st_mode & _S_IFMT) == _S_IFREG) ? PATH_FILE : PATH_NOT_FILE;
#else
  struct stat st;

  *is_link = false;
  if (lstat (path.c_str (), &st) != 0)
    {
      return (errno == ENOENT || errno == ENOTDIR) ? PATH_ABSENT : PATH_FILE;
    }
  if (S_ISLNK (st.st_mode))
    {
      *is_link = true;
      if (stat (path.c_str (), &st) != 0)
	{
	  /* a link an earlier version made, whose target is gone */
	  return (errno == ENOENT || errno == ENOTDIR) ? PATH_ABSENT : PATH_FILE;
	}
    }
  return S_ISREG (st.st_mode) ? PATH_FILE : PATH_NOT_FILE;
#endif
}

/*
 * path_entry_exists () - is there a directory entry (a link counts) at path
 */
static bool
path_entry_exists (const std::string &path)
{
#if defined (WINDOWS)
  return GetFileAttributesA (path.c_str ()) != INVALID_FILE_ATTRIBUTES;
#else
  struct stat st;

  return lstat (path.c_str (), &st) == 0;
#endif
}

static bool
read_small_file (const std::string &path, std::string &data, std::string &reason)
{
  FILE *fp;
  char buf[4096];
  size_t n;
  bool ok = true;

  fp = fopen (path.c_str (), "rb");
  if (fp == NULL)
    {
      reason = errno_string (errno);
      return false;
    }
  while ((n = fread (buf, 1, sizeof (buf), fp)) > 0)
    {
      data.append (buf, n);
      if (data.size () > CERT_MAX_FILE_SIZE)
	{
	  reason = "the file is too large";
	  ok = false;
	  break;
	}
    }
  if (ok && ferror (fp))
    {
      reason = errno_string (errno);
      ok = false;
    }
  OPENSSL_cleanse (buf, sizeof (buf));
  fclose (fp);
  return ok;
}

/*
 * load_ssl_file () - read f.path and find out whether it holds a shipped key
 *
 *   On failure f.loaded stays false and f.reason says why.
 */
static void
load_ssl_file (ssl_file &f)
{
  std::string data;
  std::string sha256;
  BIO *bio = NULL;

  if (!read_small_file (f.path, data, f.reason))
    {
      cleanse_string (data);
      return;
    }

  ERR_clear_error ();
  bio = BIO_new_mem_buf (data.data (), (int) data.size ());
  if (bio == NULL)
    {
      f.reason = with_openssl_error ("out of memory");
      cleanse_string (data);
      return;
    }

  if (f.is_key)
    {
      f.pkey = PEM_read_bio_PrivateKey (bio, NULL, no_passphrase, NULL);
      if (f.pkey == NULL)
	{
	  if (data.find ("ENCRYPTED") != std::string::npos)
	    {
	      ERR_clear_error ();
	      f.reason = "the private key is protected by a passphrase, which is not supported";
	    }
	  else
	    {
	      f.reason = with_openssl_error ("not a PEM private key");
	    }
	}
    }
  else
    {
      f.cert = PEM_read_bio_X509 (bio, NULL, no_passphrase, NULL);
      if (f.cert == NULL)
	{
	  f.reason = with_openssl_error ("not a PEM certificate");
	}
      else
	{
	  f.pkey = X509_get_pubkey (f.cert);
	  if (f.pkey == NULL)
	    {
	      f.reason = with_openssl_error ("cannot get the public key of the certificate");
	    }
	}
    }
  BIO_free (bio);
  cleanse_string (data);

  if (f.pkey == NULL)
    {
      return;
    }
  if (!pubkey_sha256 (f.pkey, sha256))
    {
      f.reason = with_openssl_error ("cannot compute the public key fingerprint");
      return;
    }

  f.shipped = find_shipped_key (sha256);
  f.loaded = true;
  ERR_clear_error ();
}

static bool
pair_matches (ssl_file &cert, ssl_file &key)
{
  int ok;

  ok = X509_check_private_key (cert.cert, key.pkey);
  ERR_clear_error ();
  return ok == 1;
}

/*
 * self_issued () - is the certificate signed by its own key (a self-signed
 *   certificate, not one issued by a CA)
 *
 *   The issuer must be the subject and the signature must verify with the
 *   certificate's own public key. X509_check_issued () is not used: it also
 *   requires keyCertSign, which a server certificate (such as the one CMS
 *   generates) does not have.
 */
static bool
self_issued (X509 *cert)
{
  EVP_PKEY *pkey;
  bool ok;

  if (X509_NAME_cmp (X509_get_subject_name (cert), X509_get_issuer_name (cert)) != 0)
    {
      return false;
    }
  pkey = X509_get0_pubkey (cert);
  ok = pkey != NULL && X509_verify (cert, pkey) == 1;
  ERR_clear_error ();
  return ok;
}

/*
 * openssl_reason () - the reason of the first queued OpenSSL error, short
 *   (for example "ee key too small"); clears the queue
 */
static std::string
openssl_reason (void)
{
  unsigned long e = ERR_get_error ();
  const char *r;

  ERR_clear_error ();
  if (e == 0)
    {
      return std::string ("unknown error");
    }
  r = ERR_reason_error_string (e);
  if (r == NULL)
    {
      char buf[256];

      ERR_error_string_n (e, buf, sizeof (buf));
      return std::string (buf);
    }
  return std::string (r);
}

/*
 * tls_accepts () - can TLS use the key pair, loaded the way init_SSL () loads
 *   it? OpenSSL refuses for example a key smaller than its security level
 *   allows (RSA 1024 at level 2 or higher), which the earlier checks do not see.
 *
 *   reason(out): why not
 */
static bool
tls_accepts (const std::string &cert_path, const std::string &key_path, std::string &reason)
{
  SSL_CTX *ctx;
  bool ok = false;

  ERR_clear_error ();
  ctx = SSL_CTX_new (TLS_server_method ());
  if (ctx == NULL)
    {
      reason = "cannot create a TLS context: " + openssl_reason ();
      return false;
    }
  SSL_CTX_set_default_passwd_cb (ctx, no_passphrase);

  if (SSL_CTX_use_certificate_chain_file (ctx, cert_path.c_str ()) != 1)
    {
      reason = "the certificate: " + openssl_reason ();
    }
  else if (SSL_CTX_use_PrivateKey_file (ctx, key_path.c_str (), SSL_FILETYPE_PEM) != 1)
    {
      reason = "the private key: " + openssl_reason ();
    }
  else if (SSL_CTX_check_private_key (ctx) != 1)
    {
      reason = "the private key: " + openssl_reason ();
    }
  else
    {
      ok = true;
    }

  SSL_CTX_free (ctx);
  ERR_clear_error ();
  return ok;
}

/* ----------------------------------------------------------------- generation */

static std::string
local_host_name (void)
{
  char buf[256];

  memset (buf, 0, sizeof (buf));
#if defined (WINDOWS)
  DWORD size = (DWORD) sizeof (buf);

  if (!GetComputerNameExA (ComputerNameDnsHostname, buf, &size))
    {
      return std::string ();
    }
#else
  if (gethostname (buf, sizeof (buf) - 1) != 0)
    {
      return std::string ();
    }
#endif
  buf[sizeof (buf) - 1] = '\0';
  return std::string (buf);
}

/*
 * is_dns_name () - a host name as a SAN dNSName and the CN hold it
 *   (RFC 1123 labels): at most 253 characters; labels separated by single
 *   dots, each 1 to 63 letters, digits and '-', neither starting nor ending
 *   with '-'; no trailing dot, no wildcard. Strict clients refuse anything
 *   else, so such a name is left out rather than put in the certificate.
 */
static bool
is_dns_name (const std::string &name)
{
  size_t start = 0;

  if (name.empty () || name.size () > CERT_DNS_NAME_MAX)
    {
      return false;
    }
  while (start <= name.size ())
    {
      size_t dot = name.find ('.', start);
      size_t end = (dot == std::string::npos) ? name.size () : dot;
      size_t len = end - start;
      size_t i;

      if (len == 0 || len > CERT_DNS_LABEL_MAX || name[start] == '-' || name[end - 1] == '-')
	{
	  return false;		/* empty (a..b, .a, a.), too long, or '-' at an end */
	}
      for (i = start; i < end; i++)
	{
	  char c = name[i];

	  if (! ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-'))
	    {
	      return false;
	    }
	}
      if (dot == std::string::npos)
	{
	  break;
	}
      start = dot + 1;
    }
  return true;
}

static bool
same_ip (const san_ip &a, const san_ip &b)
{
  return a.len == b.len && memcmp (a.addr, b.addr, a.len) == 0;
}

/*
 * san_list - subject alternative names of a certificate to generate
 */
struct san_list
{
  std::vector < std::string > dns;
  std::vector < san_ip > ips;

  bool has_dns (const std::string &name) const
  {
    for (size_t i = 0; i < dns.size (); i++)
      {
	if (dns[i].size () == name.size () && strncasecmp (dns[i].c_str (), name.c_str (), name.size ()) == 0)
	  {
	    return true;
	  }
      }
    return false;
  }

  bool has_ip (const san_ip &ip) const
  {
    for (size_t i = 0; i < ips.size (); i++)
      {
	if (same_ip (ips[i], ip))
	  {
	    return true;
	  }
      }
    return false;
  }
};

/* ip_to_text () - an address as text, IPv6 uncompressed (as openssl prints it) */
static std::string
ip_to_text (const san_ip &ip)
{
  std::string t;
  int i;

  if (ip.len == 4)
    {
      for (i = 0; i < 4; i++)
	{
	  t += (i ? "." : "") + std::to_string ((unsigned int) ip.addr[i]);
	}
      return t;
    }
  for (i = 0; i < 16; i += 2)
    {
      static const char hex[] = "0123456789abcdef";
      unsigned int v = ((unsigned int) ip.addr[i] << 8) | ip.addr[i + 1];
      std::string g;

      do
	{
	  g.insert (g.begin (), hex[v & 0xf]);
	  v >>= 4;
	}
      while (v != 0);
      t += (i ? ":" : "") + g;
    }
  return t;
}

/* parse_ip () - an IPv4 or IPv6 address in text */
static bool
parse_ip (const std::string &text, san_ip &ip)
{
  ASN1_OCTET_STRING *oct = a2i_IPADDRESS (text.c_str ());
  int len;
  bool ok;

  if (oct == NULL)
    {
      ERR_clear_error ();
      return false;
    }
  len = ASN1_STRING_length (oct);
  ok = (len == 4 || len == 16);
  if (ok)
    {
      memset (&ip, 0, sizeof (ip));
      ip.len = len;
      memcpy (ip.addr, ASN1_STRING_get0_data (oct), (size_t) len);
    }
  ASN1_OCTET_STRING_free (oct);
  return ok;
}

static std::string
trim (const std::string &s)
{
  size_t b = s.find_first_not_of (" \t");
  size_t e = s.find_last_not_of (" \t");

  return (b == std::string::npos) ? std::string () : s.substr (b, e - b + 1);
}

/*
 * parse_extra_san () - the entries of ssl_cert_san (cm.conf):
 *   DNS:<name>,IP:<address>,... (prefixes case-insensitive)
 *
 *   out(in/out): entries added to it, skipping those already in it
 *   ignored(out): entries that are not used, with why
 */
static void
parse_extra_san (const char *spec, san_list &out, std::vector < std::string > &ignored)
{
  std::string all = (spec != NULL) ? spec : "";
  size_t pos = 0;
  int added = 0;

  while (pos <= all.size ())
    {
      size_t comma = all.find (',', pos);
      std::string entry = trim (all.substr (pos, (comma == std::string::npos) ? std::string::npos : comma - pos));
      std::string value;
      san_ip ip;

      pos = (comma == std::string::npos) ? all.size () + 1 : comma + 1;
      if (entry.empty ())
	{
	  continue;
	}
      if (added >= CERT_MAX_EXTRA_SAN)
	{
	  ignored.push_back (entry + " (more than " + std::to_string (CERT_MAX_EXTRA_SAN) + " entries)");
	  continue;
	}
      if (entry.size () > 4 && strncasecmp (entry.c_str (), "DNS:", 4) == 0)
	{
	  value = trim (entry.substr (4));
	  if (!is_dns_name (value))
	    {
	      ignored.push_back (entry + " (not a DNS name: letters, digits, '-' and '.' only)");
	    }
	  else if (!out.has_dns (value))
	    {
	      out.dns.push_back (value);
	      added++;
	    }
	}
      else if (entry.size () > 3 && strncasecmp (entry.c_str (), "IP:", 3) == 0)
	{
	  value = trim (entry.substr (3));
	  if (!parse_ip (value, ip))
	    {
	      ignored.push_back (entry + " (not an IPv4 or IPv6 address)");
	    }
	  else if (!out.has_ip (ip))
	    {
	      out.ips.push_back (ip);
	      added++;
	    }
	}
      else
	{
	  ignored.push_back (entry + " (neither DNS:<name> nor IP:<address>)");
	}
    }
}

/*
 * default_san () - DNS: the host name (when it is a valid DNS name),
 *   localhost / IP: 127.0.0.1, ::1
 *
 *   The certificate is sent in the TLS handshake, so anyone who can reach
 *   the port can read it without logging in. The addresses of the network
 *   interfaces (private, management, replication, container or VPN networks)
 *   are therefore not added by default; the administrator adds the names and
 *   addresses clients connect to with ssl_cert_san.
 */
static void
default_san (const std::string &host, san_list &out)
{
  static const san_ip v4_loopback = { 4, {127, 0, 0, 1} };
  static const san_ip v6_loopback = { 16, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1} };

  if (is_dns_name (host) && host != "localhost")
    {
      out.dns.push_back (host);
    }
  out.dns.push_back ("localhost");
  out.ips.push_back (v4_loopback);
  out.ips.push_back (v6_loopback);
}

static bool
push_dns_name (GENERAL_NAMES *gens, const std::string &name)
{
  GENERAL_NAME *gen = GENERAL_NAME_new ();
  ASN1_IA5STRING *ia5 = ASN1_IA5STRING_new ();

  if (gen == NULL || ia5 == NULL || ASN1_STRING_set (ia5, name.data (), (int) name.size ()) != 1)
    {
      GENERAL_NAME_free (gen);
      ASN1_IA5STRING_free (ia5);
      return false;
    }
  GENERAL_NAME_set0_value (gen, GEN_DNS, ia5);
  if (sk_GENERAL_NAME_push (gens, gen) == 0)
    {
      GENERAL_NAME_free (gen);
      return false;
    }
  return true;
}

static bool
push_ip (GENERAL_NAMES *gens, const san_ip &ip)
{
  GENERAL_NAME *gen = GENERAL_NAME_new ();
  ASN1_OCTET_STRING *oct = ASN1_OCTET_STRING_new ();

  if (gen == NULL || oct == NULL || ASN1_OCTET_STRING_set (oct, ip.addr, ip.len) != 1)
    {
      GENERAL_NAME_free (gen);
      ASN1_OCTET_STRING_free (oct);
      return false;
    }
  GENERAL_NAME_set0_value (gen, GEN_IPADD, oct);
  if (sk_GENERAL_NAME_push (gens, gen) == 0)
    {
      GENERAL_NAME_free (gen);
      return false;
    }
  return true;
}

/*
 * add_san () - the default names (default_san ()) and those of ssl_cert_san
 */
static bool
add_san (X509 *x, const std::string &host, const char *extra_san)
{
  GENERAL_NAMES *gens;
  san_list names;
  std::vector < std::string > ignored;
  bool ok = true;
  size_t i;

  gens = sk_GENERAL_NAME_new_null ();
  if (gens == NULL)
    {
      return false;
    }

  default_san (host, names);
  parse_extra_san (extra_san, names, ignored);	/* reported by report_extra_san () */

  for (i = 0; ok && i < names.dns.size (); i++)
    {
      ok = push_dns_name (gens, names.dns[i]);
    }
  for (i = 0; ok && i < names.ips.size (); i++)
    {
      ok = push_ip (gens, names.ips[i]);
    }
  ok = ok && X509_add1_ext_i2d (x, NID_subject_alt_name, gens, 0, X509V3_ADD_DEFAULT) == 1;

  GENERAL_NAMES_free (gens);
  return ok;
}

/*
 * report_extra_san () - log the entries of ssl_cert_san that are not used
 */
static void
report_extra_san (const char *extra_san)
{
  san_list names;
  std::vector < std::string > ignored;
  size_t i;

  parse_extra_san (extra_san, names, ignored);
  for (i = 0; i < ignored.size (); i++)
    {
      LOG_WARN ("ssl_cert_san in cm.conf: ignored %s", ignored[i].c_str ());
    }
}

static std::string
san_text (const san_list &names)
{
  std::string t;
  size_t i;

  for (i = 0; i < names.dns.size (); i++)
    {
      t += (t.empty ()? "DNS:" : ", DNS:") + names.dns[i];
    }
  for (i = 0; i < names.ips.size (); i++)
    {
      t += (t.empty ()? "IP:" : ", IP:") + ip_to_text (names.ips[i]);
    }
  return t;
}

/*
 * report_san_mismatch () - compare the subject alternative names of a
 *   self-signed certificate in use with those a generation would put in it
 *   now. ssl_cert_san is applied only when a key pair is generated, so after
 *   a change of it (or of the host name) the certificate still has the old
 *   names until it is generated again:
 *   - names of ssl_cert_san it does not have: clients that verify the host
 *     name cannot connect by them;
 *   - names it has that neither the defaults nor ssl_cert_san list: it still
 *     shows them to anyone who can reach the port (for example the interface
 *     addresses an earlier build put in it).
 *   A certificate issued by a CA is left alone: its names are what was asked
 *   of the CA, and ssl_cert_san does not apply to it.
 */
static void
report_san_mismatch (X509 *cert, const std::string &cert_path, const char *extra_san)
{
  san_list extra;		/* ssl_cert_san */
  san_list expected;		/* defaults and ssl_cert_san */
  san_list have;		/* in the certificate */
  san_list missing;
  san_list unexpected;
  std::vector < std::string > ignored;
  GENERAL_NAMES *gens;
  size_t i;
  int k;

  if (!self_issued (cert))
    {
      return;
    }

  parse_extra_san (extra_san, extra, ignored);
  default_san (local_host_name (), expected);
  parse_extra_san (extra_san, expected, ignored);

  gens = (GENERAL_NAMES *) X509_get_ext_d2i (cert, NID_subject_alt_name, NULL, NULL);
  for (k = 0; gens != NULL && k < sk_GENERAL_NAME_num (gens); k++)
    {
      GENERAL_NAME *gen = sk_GENERAL_NAME_value (gens, k);
      san_ip ip;

      if (gen->type == GEN_DNS)
	{
	  const ASN1_IA5STRING *s = gen->d.dNSName;

	  have.dns.push_back (std::string ((const char *) ASN1_STRING_get0_data (s), ASN1_STRING_length (s)));
	}
      else if (gen->type == GEN_IPADD && (ASN1_STRING_length (gen->d.iPAddress) == 4
					  || ASN1_STRING_length (gen->d.iPAddress) == 16))
	{
	  memset (&ip, 0, sizeof (ip));
	  ip.len = ASN1_STRING_length (gen->d.iPAddress);
	  memcpy (ip.addr, ASN1_STRING_get0_data (gen->d.iPAddress), (size_t) ip.len);
	  have.ips.push_back (ip);
	}
    }
  GENERAL_NAMES_free (gens);
  ERR_clear_error ();

  for (i = 0; i < extra.dns.size (); i++)
    {
      if (!have.has_dns (extra.dns[i]))
	{
	  missing.dns.push_back (extra.dns[i]);
	}
    }
  for (i = 0; i < extra.ips.size (); i++)
    {
      if (!have.has_ip (extra.ips[i]))
	{
	  missing.ips.push_back (extra.ips[i]);
	}
    }
  for (i = 0; i < have.dns.size (); i++)
    {
      if (!expected.has_dns (have.dns[i]))
	{
	  unexpected.dns.push_back (have.dns[i]);
	}
    }
  for (i = 0; i < have.ips.size (); i++)
    {
      if (!expected.has_ip (have.ips[i]))
	{
	  unexpected.ips.push_back (have.ips[i]);
	}
    }

  if (!missing.dns.empty () || !missing.ips.empty ())
    {
      LOG_WARN ("the SSL certificate %s does not have %s of ssl_cert_san in cm.conf.", cert_path.c_str (),
		san_text (missing).c_str ());
    }
  if (!unexpected.dns.empty () || !unexpected.ips.empty ())
    {
      LOG_WARN ("the SSL certificate %s has %s, which neither the defaults nor ssl_cert_san in cm.conf list; "
		"anyone who can reach the port can read them.", cert_path.c_str (), san_text (unexpected).c_str ());
    }
  if (!missing.dns.empty () || !missing.ips.empty () || !unexpected.dns.empty () || !unexpected.ips.empty ())
    {
      LOG_WARN ("ssl_cert_san is used only when a key pair is generated. To apply it, stop cub_manager, remove %s "
		"and its private key, and start it (%s=YES); clients then see a new fingerprint. If you installed "
		"this certificate yourself, you can ignore this.", cert_path.c_str (), CONF_AUTO_GENERATE);
    }
}

static bool
add_extension (X509 *x, int nid, const char *value)
{
  X509V3_CTX ctx;
  X509_EXTENSION *ext;
  bool ok;

  X509V3_set_ctx_nodb (&ctx);
  X509V3_set_ctx (&ctx, x, x, NULL, NULL, 0);
  ext = X509V3_EXT_conf_nid (NULL, &ctx, nid, (char *) value);
  if (ext == NULL)
    {
      return false;
    }
  ok = X509_add_ext (x, ext, -1) == 1;
  X509_EXTENSION_free (ext);
  return ok;
}

static bool
add_name_entry (X509_NAME *name, const char *field, const char *value, std::string &err)
{
  if (value == NULL || value[0] == '\0')
    {
      return true;
    }
  if (X509_NAME_add_entry_by_txt (name, field, MBSTRING_UTF8, (const unsigned char *) value, -1, -1, 0) != 1)
    {
      err = with_openssl_error (std::string ("invalid subject ") + field + " '" + value + "'");
      return false;
    }
  return true;
}

static bool
has_subject (const T_CM_SSL_CERT_OPTS *opts)
{
  const char *fields[7];
  size_t i;

  if (opts == NULL)
    {
      return false;
    }
  fields[0] = opts->country;
  fields[1] = opts->state;
  fields[2] = opts->locality;
  fields[3] = opts->organization;
  fields[4] = opts->org_unit;
  fields[5] = opts->common_name;
  fields[6] = opts->email;
  for (i = 0; i < ARRAY_COUNT (fields); i++)
    {
      if (fields[i] != NULL && fields[i][0] != '\0')
	{
	  return true;
	}
    }
  return false;
}

static bool
set_subject (X509 *x, const T_CM_SSL_CERT_OPTS *opts, const std::string &host, std::string &err)
{
  T_CM_SSL_CERT_OPTS def;
  X509_NAME *name = X509_get_subject_name (x);

  if (!has_subject (opts))
    {
      memset (&def, 0, sizeof (def));
      def.country = DEFAULT_SUBJECT_C;
      def.state = DEFAULT_SUBJECT_ST;
      def.locality = DEFAULT_SUBJECT_L;
      def.organization = DEFAULT_SUBJECT_O;
      def.org_unit = DEFAULT_SUBJECT_OU;
      def.common_name = (is_dns_name (host) && host.size () <= CERT_CN_MAX) ? host.c_str () : DEFAULT_SUBJECT_CN;
      def.email = DEFAULT_SUBJECT_EMAIL;
      opts = &def;
    }

  if (!add_name_entry (name, "C", opts->country, err) || !add_name_entry (name, "ST", opts->state, err)
      || !add_name_entry (name, "L", opts->locality, err) || !add_name_entry (name, "O", opts->organization, err)
      || !add_name_entry (name, "OU", opts->org_unit, err) || !add_name_entry (name, "CN", opts->common_name, err)
      || !add_name_entry (name, "emailAddress", opts->email, err))
    {
      return false;
    }

  /* self-signed */
  if (X509_set_issuer_name (x, name) != 1)
    {
      err = with_openssl_error ("cannot set the issuer");
      return false;
    }
  return true;
}

static bool
set_serial (X509 *x, std::string &err)
{
  unsigned char serial[CERT_SERIAL_BYTES];
  BIGNUM *bn;
  bool ok;

  if (RAND_bytes (serial, sizeof (serial)) != 1)
    {
      err = with_openssl_error ("the random number generator failed");
      return false;
    }
  serial[0] &= 0x7f;		/* positive */
  serial[sizeof (serial) - 1] |= 0x01;	/* not zero */

  bn = BN_bin2bn (serial, sizeof (serial), NULL);
  ok = bn != NULL && BN_to_ASN1_INTEGER (bn, X509_get_serialNumber (x)) != NULL;
  BN_free (bn);
  if (!ok)
    {
      err = with_openssl_error ("cannot set the serial number");
    }
  return ok;
}

static EVP_PKEY *
generate_rsa_key (std::string &err)
{
  EVP_PKEY_CTX *pctx;
  EVP_PKEY *pkey = NULL;

  pctx = EVP_PKEY_CTX_new_id (EVP_PKEY_RSA, NULL);
  if (pctx == NULL || EVP_PKEY_keygen_init (pctx) != 1 || EVP_PKEY_CTX_set_rsa_keygen_bits (pctx, CERT_RSA_BITS) != 1
      || EVP_PKEY_keygen (pctx, &pkey) != 1)
    {
      err = with_openssl_error ("RSA key generation failed");
      pkey = NULL;
    }
  EVP_PKEY_CTX_free (pctx);
  return pkey;
}

/*
 * build_cert () - a new RSA 2048 key and a self-signed certificate for it
 */
static bool
build_cert (const T_CM_SSL_CERT_OPTS *opts, X509 **cert_out, EVP_PKEY **key_out, std::string &err)
{
  int days = (opts != NULL) ? opts->days : 0;
  std::string host;
  EVP_PKEY *pkey = NULL;
  X509 *x = NULL;
  bool ok = false;

  if (days == 0)
    {
      days = CERT_DEFAULT_DAYS;
    }
  if (days < 0 || days > CERT_MAX_DAYS)
    {
      err = "invalid validity period " + std::to_string (days) + " days (1 to " + std::to_string (CERT_MAX_DAYS)
	    + ")";
      return false;
    }

  host = local_host_name ();
  ERR_clear_error ();

  do
    {
      pkey = generate_rsa_key (err);
      if (pkey == NULL)
	{
	  break;
	}

      x = X509_new ();
      if (x == NULL || X509_set_version (x, 2) != 1)	/* v3 */
	{
	  err = with_openssl_error ("out of memory");
	  break;
	}
      if (!set_serial (x, err))
	{
	  break;
	}
      if (X509_time_adj_ex (X509_getm_notBefore (x), -CERT_BACKDATE_DAYS, 0, NULL) == NULL
	  || X509_time_adj_ex (X509_getm_notAfter (x), days, 0, NULL) == NULL)
	{
	  err = with_openssl_error ("cannot set the validity period");
	  break;
	}
      if (X509_set_pubkey (x, pkey) != 1)
	{
	  err = with_openssl_error ("cannot set the public key");
	  break;
	}
      if (!set_subject (x, opts, host, err))
	{
	  break;
	}

      if (!add_extension (x, NID_basic_constraints, "critical,CA:FALSE")
	  || !add_extension (x, NID_key_usage, "critical,digitalSignature,keyEncipherment")
	  || !add_extension (x, NID_ext_key_usage, "serverAuth")
	  || !add_extension (x, NID_subject_key_identifier, "hash"))
	{
	  err = with_openssl_error ("cannot add the certificate extensions");
	  break;
	}
      if (!add_san (x, host, (opts != NULL) ? opts->extra_san : NULL))
	{
	  err = with_openssl_error ("cannot add the subject alternative names");
	  break;
	}

      if (X509_sign (x, pkey, EVP_sha256 ()) <= 0)
	{
	  err = with_openssl_error ("cannot sign the certificate");
	  break;
	}
      ok = true;
    }
  while (0);

  if (!ok)
    {
      X509_free (x);
      EVP_PKEY_free (pkey);
      return false;
    }
  *cert_out = x;
  *key_out = pkey;
  return true;
}

/* ------------------------------------------------------------------- files */

static bool
pem_private_key (EVP_PKEY *pkey, std::string &pem, std::string &err)
{
  BIO *bio = BIO_new (BIO_s_secmem ());
  char *p = NULL;
  long n;
  bool ok;

  /* PKCS#8, no passphrase: cub_manager starts unattended */
  ok = bio != NULL && PEM_write_bio_PrivateKey (bio, pkey, NULL, NULL, 0, NULL, NULL) == 1;
  if (ok)
    {
      n = BIO_get_mem_data (bio, &p);
      ok = n > 0 && p != NULL;
      if (ok)
	{
	  pem.assign (p, (size_t) n);
	}
    }
  if (!ok)
    {
      err = with_openssl_error ("cannot encode the private key");
    }
  BIO_free (bio);
  return ok;
}

static bool
pem_cert (X509 *cert, std::string &pem, std::string &err)
{
  BIO *bio = BIO_new (BIO_s_mem ());
  char *p = NULL;
  long n;
  bool ok;

  ok = bio != NULL && PEM_write_bio_X509 (bio, cert) == 1;
  if (ok)
    {
      n = BIO_get_mem_data (bio, &p);
      ok = n > 0 && p != NULL;
      if (ok)
	{
	  pem.assign (p, (size_t) n);
	}
    }
  if (!ok)
    {
      err = with_openssl_error ("cannot encode the certificate");
    }
  BIO_free (bio);
  return ok;
}

/*
 * write_new_file () - create path (it must not exist) and write data to disk
 *
 *   private_key(in): mode 0600, otherwise 0644 (both under the umask)
 */
static bool
write_new_file (const std::string &path, const std::string &data, bool private_key, std::string &err)
{
  size_t done = 0;
  int fd;
  int e = 0;

#if defined (WINDOWS)
  /* access is limited by the ACL inherited from the conf directory */
  (void) private_key;
  fd = _open (path.c_str (), _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY, _S_IREAD | _S_IWRITE);
  if (fd < 0)
    {
      err = "cannot create " + path + ": " + errno_string (errno);
      return false;
    }
  while (done < data.size () && e == 0)
    {
      int n = _write (fd, data.data () + done, (unsigned int) (data.size () - done));

      if (n <= 0)
	{
	  e = errno;
	  break;
	}
      done += (size_t) n;
    }
  if (e == 0 && _commit (fd) != 0)
    {
      e = errno;
    }
  if (_close (fd) != 0 && e == 0)
    {
      e = errno;
    }
#else
  fd = open (path.c_str (), O_WRONLY | O_CREAT | O_EXCL, private_key ? 0600 : 0644);
  if (fd < 0)
    {
      err = "cannot create " + path + ": " + errno_string (errno);
      return false;
    }
  if (private_key && fchmod (fd, 0600) != 0)
    {
      e = errno;
    }
  while (done < data.size () && e == 0)
    {
      ssize_t n = write (fd, data.data () + done, data.size () - done);

      if (n < 0)
	{
	  if (errno == EINTR)
	    {
	      continue;
	    }
	  e = errno;
	  break;
	}
      done += (size_t) n;
    }
  if (e == 0 && fsync (fd) != 0)
    {
      e = errno;
    }
  if (close (fd) != 0 && e == 0)
    {
      e = errno;
    }
#endif

  if (e != 0)
    {
      err = "cannot write " + path + ": " + errno_string (e);
      unlink (path.c_str ());
      return false;
    }
  return true;
}

/*
 * replace_file () - rename src to dst, replacing dst. When dst is a symbolic
 *   link, the link itself is replaced.
 */
static bool
replace_file (const std::string &src, const std::string &dst, std::string &err)
{
#if defined (WINDOWS)
  if (!MoveFileExA (src.c_str (), dst.c_str (), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
    {
      err = "cannot rename " + src + " to " + dst + ": " + win_error_string (GetLastError ());
      return false;
    }
#else
  if (rename (src.c_str (), dst.c_str ()) != 0)
    {
      err = "cannot rename " + src + " to " + dst + ": " + errno_string (errno);
      return false;
    }
#endif
  return true;
}

static std::string dir_of (const std::string &path);

/*
 * sync_dirs () - make the directory entries of path_a and path_b (their
 *   creations, renames and removals so far) durable
 *
 *   A replacement is a sequence of renames and removals that
 *   recover_interrupted () reads back after a crash or a power loss; it can
 *   only tell where the sequence stopped if each step reached the disk before
 *   the next one. The file contents are fsynced by write_new_file (), but a
 *   rename or unlink changes the directory, which POSIX makes durable only by
 *   fsyncing the directory. On Windows MoveFileEx () is called with
 *   MOVEFILE_WRITE_THROUGH, which returns once the move is on disk, and NTFS
 *   journals directory changes in order; there is no portable way to flush a
 *   directory handle there, so this does nothing.
 */
static bool
sync_dirs (const std::string &path_a, const std::string &path_b, std::string &err)
{
#if defined (WINDOWS)
  /* nothing to do in Windows, codes just avoid compiler warning */
  (void) path_a;
  (void) path_b;
  (void) err;
  return true;
#else
  std::string dirs[2];
  int n = 0;
  int i;

  dirs[n++] = dir_of (path_a);
  if (dir_of (path_b) != dirs[0])
    {
      dirs[n++] = dir_of (path_b);
    }
  for (i = 0; i < n; i++)
    {
      std::string dir = dirs[i].empty ()? std::string (".") : dirs[i];
      int flags = O_RDONLY;
      int fd;

#if defined (O_DIRECTORY)
      flags |= O_DIRECTORY;
#endif
#if defined (O_CLOEXEC)
      flags |= O_CLOEXEC;
#endif
      fd = open (dir.c_str (), flags);
      if (fd < 0)
	{
	  err = "cannot open the directory " + dir + ": " + errno_string (errno);
	  return false;
	}
      /* EINVAL: a file system that cannot sync a directory; nothing more can be done */
      if (fsync (fd) != 0 && errno != EINVAL)
	{
	  err = "cannot sync the directory " + dir + ": " + errno_string (errno);
	  close (fd);
	  return false;
	}
      close (fd);
    }
  return true;
#endif
}

static bool
random_suffix (std::string &suffix, std::string &err)
{
  unsigned char r[4];

  if (RAND_bytes (r, sizeof (r)) != 1)
    {
      err = with_openssl_error ("the random number generator failed");
      return false;
    }
  suffix = to_hex (r, sizeof (r), false);
  return true;
}

/*
 * install_pair () - put the new key and certificate in place
 *
 *   Both are written to temporary files first, then renamed over the old
 *   ones. The old key is set aside until the certificate is in place, so that
 *   on failure the old key and certificate are both back as they were. When
 *   there is no old key, an empty <key>.new-<suffix> records that instead, so
 *   that recover_interrupted () can tell a new key placed before an
 *   interruption from a key that was there.
 */
static bool
install_pair (const std::string &cert_path, const std::string &key_path, X509 *cert, EVP_PKEY *pkey,
	      std::string &err)
{
  std::string suffix;
  std::string key_pem;
  std::string cert_pem;
  std::string key_tmp;
  std::string cert_tmp;
  std::string key_old;
  std::string key_new_mark;
  std::string e2;
  bool key_set_aside = false;
  bool key_marked = false;
  bool key_placed = false;
  bool durable = false;
  bool ok = false;

  if (!random_suffix (suffix, err))
    {
      return false;
    }
  key_tmp = key_path + WORK_TMP + suffix;
  cert_tmp = cert_path + WORK_TMP + suffix;
  key_old = key_path + WORK_OLD + suffix;
  key_new_mark = key_path + WORK_NEW + suffix;

  do
    {
      if (!pem_private_key (pkey, key_pem, err) || !pem_cert (cert, cert_pem, err))
	{
	  break;
	}
      if (!write_new_file (key_tmp, key_pem, true, err))
	{
	  break;
	}
      if (!write_new_file (cert_tmp, cert_pem, false, err))
	{
	  break;
	}

      /*
       * Each step below reaches the disk before the next one (sync_dirs ()),
       * so that after a power loss recover_interrupted () finds a state the
       * sequence actually went through.
       */
      if (path_entry_exists (key_path))
	{
	  if (!replace_file (key_path, key_old, err))
	    {
	      break;
	    }
	  key_set_aside = true;
	}
      else
	{
	  if (!write_new_file (key_new_mark, std::string (), true, err))
	    {
	      break;
	    }
	  key_marked = true;
	}
      if (!sync_dirs (key_path, cert_path, err))
	{
	  break;
	}
      if (!replace_file (key_tmp, key_path, err))
	{
	  break;
	}
      key_placed = true;
      if (!sync_dirs (key_path, cert_path, err))
	{
	  break;
	}
      if (!replace_file (cert_tmp, cert_path, err))
	{
	  break;
	}
      /* From here the new pair is complete, so it is never undone */
      ok = true;
      durable = sync_dirs (key_path, cert_path, err);
    }
  while (0);

  cleanse_string (key_pem);

  if (ok && !durable)
    {
      /*
       * The new pair is in place but may not be on disk yet. Keep
       * <key>.old-<s> or <key>.new-<s>
       */
      LOG_WARN ("the new SSL key pair %s, %s is in place, but the directory cannot be synced: %s. %s is kept until "
		"the next start, which removes it.", cert_path.c_str (), key_path.c_str (), err.c_str (),
		(key_set_aside ? key_old : key_new_mark).c_str ());
      return true;
    }
  if (ok)
    {
      if (key_set_aside)
	{
	  unlink (key_old.c_str ());
	}
      if (key_marked)
	{
	  unlink (key_new_mark.c_str ());
	}
      /* a crash before this reaches the disk leaves a record of a completed replacement, which is removed */
      if (!sync_dirs (key_path, cert_path, e2))
	{
	  LOG_WARN ("%s", e2.c_str ());
	}
      return true;
    }

  /*
   * roll back: put the previous key back over the new one (one rename, so the
   * key path is never empty), or remove the new key when there was none. If
   * that fails too (for example another program keeps the new key open on
   * Windows), keep <cert>.tmp-<s> and <key>.old-<s> or <key>.new-<s>: they
   * are what recover_interrupted () needs at the next start to see that this
   * replacement did not complete. Without them it would take the new key as
   * complete and remove the previous one.
   */
  bool undone = true;

  if (key_set_aside)
    {
      if (!replace_file (key_old, key_path, e2))
	{
	  undone = false;
	}
    }
  else if (key_placed && unlink (key_path.c_str ()) != 0)
    {
      e2 = "cannot remove " + key_path + ": " + errno_string (errno);
      undone = false;
    }
  /* the previous state must be on disk before the records of the replacement are removed */
  if (undone && (key_set_aside || key_placed) && !sync_dirs (key_path, cert_path, e2))
    {
      undone = false;
    }

  if (!undone)
    {
      LOG_ERROR ("the SSL key pair could not be replaced (%s), and the previous state cannot be restored: %s. "
		 "%s and %s are kept so that the next start restores it; fix the cause (for example a program "
		 "that keeps the key file open) and restart.", err.c_str (), e2.c_str (),
		 (key_set_aside ? key_old : key_new_mark).c_str (), cert_tmp.c_str ());
      err += "; the previous state cannot be restored: " + e2 + " (restored at the next start)";
      if (!key_placed)
	{
	  unlink (key_tmp.c_str ());
	}
      return false;
    }

  unlink (key_tmp.c_str ());
  unlink (cert_tmp.c_str ());
  if (key_marked)
    {
      unlink (key_new_mark.c_str ());
    }
  return false;
}

/*
 * generate_pair () - build a key pair and install it at cert_path/key_path
 *
 *   cert_out(out): the new certificate, the caller frees it
 */
static bool
generate_pair (const std::string &cert_path, const std::string &key_path, const T_CM_SSL_CERT_OPTS *opts,
	       X509 **cert_out, std::string &err)
{
  X509 *cert = NULL;
  EVP_PKEY *pkey = NULL;
  bool ok;

  if (!build_cert (opts, &cert, &pkey, err))
    {
      return false;
    }
  ok = install_pair (cert_path, key_path, cert, pkey, err);
  EVP_PKEY_free (pkey);
  ERR_clear_error ();
  if (!ok)
    {
      X509_free (cert);
      return false;
    }
  *cert_out = cert;
  return true;
}

static void
log_fingerprint (const std::string &cert_path, X509 *cert)
{
  LOG_INFO ("SSL certificate %s, SHA256 Fingerprint=%s", cert_path.c_str (), cert_fingerprint (cert).c_str ());
}

static std::string
dir_of (const std::string &path)
{
#if defined (WINDOWS)
  size_t pos = path.find_last_of ("/\\");
#else
  size_t pos = path.find_last_of ('/');
#endif

  return (pos == std::string::npos) ? std::string () : path.substr (0, pos + 1);
}

/*
 * remove_leftovers () - remove cm_ssl_cert_1024.*, cm_ssl_cert_2048.* that an
 *   earlier version installed, when they hold a shipped key. Their private
 *   keys are public, so they are not backed up.
 */
static void
remove_leftover (const std::string &path, bool is_key, const std::string &cert_path, const std::string &key_path)
{
  bool is_link = false;

  if (path == cert_path || path == key_path)
    {
      return;
    }
  if (check_path (path, &is_link) != PATH_FILE || is_link)
    {
      return;
    }

  ssl_file f (is_key ? "private key" : "certificate", path.c_str (), is_key);

  load_ssl_file (f);
  if (!f.loaded)
    {
      LOG_WARN ("cannot check %s, a file name an earlier version used: %s; the file is left unchanged",
		path.c_str (), f.reason.c_str ());
      return;
    }
  if (f.shipped < 0)
    {
      return;
    }
  if (unlink (path.c_str ()) != 0)
    {
      LOG_WARN ("cannot remove %s, which holds the %s (the private key is public): %s", path.c_str (),
		shipped_keys[f.shipped].desc, errno_string (errno).c_str ());
      return;
    }
  LOG_INFO ("removed %s, which held the %s (the private key is public)", path.c_str (), shipped_keys[f.shipped].desc);
}

static void
remove_leftovers (const std::string &cert_path, const std::string &key_path)
{
  std::string cert_dir = dir_of (cert_path);
  std::string key_dir = dir_of (key_path);
  size_t i;

  for (i = 0; i < ARRAY_COUNT (leftover_cert_names); i++)
    {
      remove_leftover (cert_dir + leftover_cert_names[i], false, cert_path, key_path);
    }
  for (i = 0; i < ARRAY_COUNT (leftover_key_names); i++)
    {
      remove_leftover (key_dir + leftover_key_names[i], true, cert_path, key_path);
    }
}

static bool
is_work_suffix (const std::string &s)
{
  size_t i;

  if (s.size () != WORK_SUFFIX_LEN)
    {
      return false;
    }
  for (i = 0; i < s.size (); i++)
    {
      if (! ((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
	{
	  return false;
	}
    }
  return true;
}

/*
 * work_suffixes () - the suffixes of the files in the directory of path whose
 *   names are the name of path, then tag, then a suffix
 */
static std::vector < std::string >
work_suffixes (const std::string &path, const char *tag)
{
  std::vector < std::string > found;
  std::string dir = dir_of (path);
  std::string prefix = path.substr (dir.size ()) + tag;
  std::string name;

#if defined (WINDOWS)
  WIN32_FIND_DATAA fd;
  HANDLE h;

  h = FindFirstFileA ((dir.empty ()? std::string (".\\*") : dir + "*").c_str (), &fd);
  if (h == INVALID_HANDLE_VALUE)
    {
      return found;
    }
  do
    {
      name = fd.cFileName;
      if (name.compare (0, prefix.size (), prefix) == 0 && is_work_suffix (name.substr (prefix.size ())))
	{
	  found.push_back (name.substr (prefix.size ()));
	}
    }
  while (FindNextFileA (h, &fd));
  FindClose (h);
#else
  DIR *d;
  struct dirent *e;

  d = opendir (dir.empty ()? "." : dir.c_str ());
  if (d == NULL)
    {
      return found;
    }
  while ((e = readdir (d)) != NULL)
    {
      name = e->d_name;
      if (name.compare (0, prefix.size (), prefix) == 0 && is_work_suffix (name.substr (prefix.size ())))
	{
	  found.push_back (name.substr (prefix.size ()));
	}
    }
  closedir (d);
#endif
  return found;
}

/*
 * work_file_exists () - a regular file, or a link (the link itself is what
 *   install_pair () moved when the key path was a link)
 */
static bool
work_file_exists (const std::string &path)
{
#if defined (WINDOWS)
  struct _stat64 st;

  return _stat64 (path.c_str (), &st) == 0 && (st.st_mode & _S_IFMT) == _S_IFREG;
#else
  struct stat st;

  return lstat (path.c_str (), &st) == 0 && (S_ISREG (st.st_mode) || S_ISLNK (st.st_mode));
#endif
}

/*
 * recover_interrupted () - finish what an interrupted install_pair () left,
 *   before the startup check looks at the files
 *
 *   An interrupted replacement must leave the key pair as it was before, as
 *   a failed one does. <key>.old-<s> is the previous private key, set aside
 *   until the new certificate was in place:
 *   - the key path is empty: stopped before the new key was placed, put the
 *     previous key back.
 *   - <cert>.tmp-<s> still exists: stopped before the new certificate was
 *     placed, so the key is new but the certificate is not; put the
 *     previous key back.
 *   - otherwise the replacement completed: remove the previous key, as the
 *     replacement would have.
 *   The remaining <cert>.tmp-*, <key>.tmp-* were never put in place and are
 *   removed, except those of a replacement that could not be undone or whose
 *   key was changed afterwards. Done whatever ssl_cert_auto_generate is: it
 *   restores the state before the replacement, it does not generate anything.
 *
 *   return: false if a replacement could not be undone (the server must not
 *           start; its files are kept so that the next start decides again)
 *   why(out): the reason, when false
 */
/*
 * key_is_of_cert_file () - does the private key at key_path belong to the
 *   certificate at cert_path, that is, is it the new key of the replacement
 *   whose certificate was not put in place
 */
static bool
key_is_of_cert_file (const std::string &key_path, const std::string &cert_path)
{
  ssl_file key ("private key", key_path.c_str (), true);
  ssl_file cert ("certificate", cert_path.c_str (), false);

  load_ssl_file (key);
  load_ssl_file (cert);
  return key.loaded && cert.loaded && pair_matches (cert, key);
}

static bool
recover_interrupted (const std::string &cert_path, const std::string &key_path, std::string &why)
{
  std::vector < std::string > olds = work_suffixes (key_path, WORK_OLD);
  std::vector < std::string > news = work_suffixes (key_path, WORK_NEW);
  std::vector < std::string > keep;	/* suffixes whose work files must stay */
  std::vector < std::string > tmps;
  std::string err;
  bool ok = true;
  size_t i;

  /*
   * first generation (no previous key): <key>.new-<s> and <cert>.tmp-<s>
   * mean the certificate was not put in place, so the key at the key path,
   * if any, is the new one; remove it, as a failed generation does. The
   * startup check then generates again (YES) or reports that there is no key
   * pair (NO). A key that does not belong to <cert>.tmp-<s> was not placed by
   * that generation and is left alone.
   */
  for (i = 0; i < news.size (); i++)
    {
      std::string mark = key_path + WORK_NEW + news[i];
      std::string cert_tmp = cert_path + WORK_TMP + news[i];

      if (!work_file_exists (mark))
	{
	  continue;
	}
      if (work_file_exists (cert_tmp) && path_entry_exists (key_path))
	{
	  if (!key_is_of_cert_file (key_path, cert_tmp))
	    {
	      LOG_WARN ("an earlier generation of the SSL key pair was interrupted, but %s is not its key; "
			"it is left unchanged", key_path.c_str ());
	    }
	  else if (unlink (key_path.c_str ()) == 0)
	    {
	      LOG_WARN ("an earlier generation of the SSL key pair was interrupted before the certificate was in "
			"place: removed its private key %s", key_path.c_str ());
	    }
	  else
	    {
	      /* keep the record and the certificate: the next start decides again */
	      LOG_ERROR ("an earlier generation of the SSL key pair was interrupted, and its private key %s cannot "
			 "be removed: %s. The files are left as they are; fix the cause (for example a program that "
			 "keeps the file open) and restart.", key_path.c_str (), errno_string (errno).c_str ());
	      if (why.empty ())
		{
		  why = "cannot remove the private key " + key_path + " of an interrupted generation: "
			+ errno_string (errno);
		}
	      keep.push_back (news[i]);
	      ok = false;
	      continue;
	    }
	}
      unlink (mark.c_str ());
    }

  /*
   * replacement: <key>.old-<s> is the previous key. Put it back when the key
   * path is empty, or when <cert>.tmp-<s> shows that the new certificate was
   * not placed; otherwise the replacement completed and it is removed. If it
   * cannot be put back, nothing of that replacement is removed, so that the
   * next start can still tell that it was not completed.
   */
  for (i = 0; i < olds.size (); i++)
    {
      std::string old_key = key_path + WORK_OLD + olds[i];
      std::string cert_tmp = cert_path + WORK_TMP + olds[i];

      if (!work_file_exists (old_key))
	{
	  continue;
	}
      if (path_entry_exists (key_path) && work_file_exists (cert_tmp) && !key_is_of_cert_file (key_path, cert_tmp))
	{
	  /* the key was changed after the interruption: do not overwrite it, and keep the files */
	  LOG_WARN ("an earlier replacement of the SSL key pair was interrupted, but %s is not its new key; "
		    "it is left unchanged. The previous key is in %s and the certificate of the interrupted "
		    "replacement in %s; remove them when they are no longer needed.", key_path.c_str (),
		    old_key.c_str (), cert_tmp.c_str ());
	  keep.push_back (olds[i]);
	  continue;
	}
      if (!path_entry_exists (key_path) || work_file_exists (cert_tmp))
	{
	  if (replace_file (old_key, key_path, err))
	    {
	      LOG_WARN ("an earlier replacement of the SSL key pair was interrupted: restored the private key %s "
			"from %s", key_path.c_str (), old_key.c_str ());
	    }
	  else
	    {
	      LOG_ERROR ("an earlier replacement of the SSL key pair was interrupted, and the previous private key "
			 "cannot be restored: %s. The files are left as they are; fix the cause (for example a "
			 "program that keeps the file open) and restart, or rename %s to %s.", err.c_str (),
			 old_key.c_str (), key_path.c_str ());
	      if (why.empty ())
		{
		  why = "cannot restore the previous private key of an interrupted replacement: " + err;
		}
	      keep.push_back (olds[i]);
	      ok = false;
	    }
	}
      else if (unlink (old_key.c_str ()) == 0)
	{
	  LOG_INFO ("removed %s, the previous private key left by an earlier replacement of the SSL key pair",
		    old_key.c_str ());
	}
      else
	{
	  LOG_WARN ("cannot remove %s, the previous private key left by an earlier replacement of the SSL key pair: "
		    "%s", old_key.c_str (), errno_string (errno).c_str ());
	}
    }

  /*
   * the keys put back or removed above must be on disk before the temporary
   * certificates that tell an interrupted replacement are removed below
   */
  if (!sync_dirs (key_path, cert_path, err))
    {
      LOG_ERROR ("cannot make the recovery of an interrupted replacement of the SSL key pair durable: %s. "
		 "The files are left as they are; fix the cause and restart.", err.c_str ());
      if (why.empty ())
	{
	  why = "cannot recover an interrupted replacement of the SSL key pair: " + err;
	}
      return false;
    }

  for (int which = 0; which < 2; which++)
    {
      const std::string &path = (which == 0) ? cert_path : key_path;

      tmps = work_suffixes (path, WORK_TMP);
      for (i = 0; i < tmps.size (); i++)
	{
	  std::string tmp = path + WORK_TMP + tmps[i];
	  size_t k;

	  for (k = 0; k < keep.size () && keep[k] != tmps[i]; k++)
	    {
	      ;
	    }
	  if (k < keep.size () || !work_file_exists (tmp))
	    {
	      continue;
	    }
	  if (unlink (tmp.c_str ()) == 0)
	    {
	      LOG_INFO ("removed %s, left by an interrupted replacement of the SSL key pair", tmp.c_str ());
	    }
	  else
	    {
	      LOG_WARN ("cannot remove %s, left by an interrupted replacement of the SSL key pair: %s", tmp.c_str (),
			errno_string (errno).c_str ());
	    }
	}
    }
  if (!sync_dirs (key_path, cert_path, err))
    {
      LOG_WARN ("%s", err.c_str ());
    }
  return ok;
}

/*
 * report_key_mode () - warn when the private key that is kept as it is can
 *   be read or written by accounts other than its owner
 *
 *   A key CMS generates is 0600, but a key the administrator installed, or one
 *   an earlier version installed (0644), is used as it is, and CMS does not
 *   change the mode of a file it did not create. Windows: access is decided
 *   by the ACL, which this does not check.
 */
static void
report_key_mode (const std::string &key_path)
{
#if !defined (WINDOWS)
  struct stat st;

  if (stat (key_path.c_str (), &st) != 0 || (st.st_mode & 077) == 0)
    {
      return;
    }
  LOG_WARN ("the SSL private key %s can be accessed by other accounts (mode %04o): restrict it to the account "
	    "cub_manager runs as, for example chmod 600 %s", key_path.c_str (), (unsigned int) (st.st_mode & 07777),
	    key_path.c_str ());
#else
  (void) key_path;
#endif
}

/* ------------------------------------------------------------ startup check */

/*
 * fail () - keep the first reason the startup check stops for, in a line
 *   cub_manager prints on stderr (the details and what to do are logged)
 */
static int
fail (std::string &why, const std::string &reason)
{
  if (why.empty ())
    {
      why = reason;
    }
  return -1;
}

static int
fail_unreadable (std::string &why, const ssl_file &f)
{
  LOG_ERROR ("cannot tell whether the SSL %s %s holds a key shipped with an earlier version: %s. "
	     "The files are left unchanged; make the file readable by this account, in PEM, without a passphrase, "
	     "and restart.", f.what, f.path.c_str (), f.reason.c_str ());
  return fail (why, std::string ("cannot read the SSL ") + f.what + " " + f.path + ": " + f.reason);
}

static int
fail_mismatch (std::string &why, const ssl_file &cert, const ssl_file &key)
{
  LOG_ERROR ("the SSL certificate %s and private key %s do not match. "
	     "Replace both with a certificate and its own private key, and restart.", cert.path.c_str (),
	     key.path.c_str ());
  return fail (why, "the SSL certificate " + cert.path + " and private key " + key.path + " do not match");
}

/*
 * replace_pair () - generate a new key pair in place of the files
 *
 *   shipped(in): index of the shipped key being replaced, -1 if none exists
 */
static int
replace_pair (ssl_file &cert, ssl_file &key, int shipped, const char *extra_san, std::string &why)
{
  T_CM_SSL_CERT_OPTS opts;	/* default subject and validity */

  memset (&opts, 0, sizeof (opts));
  opts.extra_san = extra_san;
  X509 *new_cert = NULL;
  std::string err;

  if (!generate_pair (cert.path, key.path, &opts, &new_cert, err))
    {
      LOG_ERROR ("failed to generate a new SSL key pair: %s. The existing files are left unchanged. "
		 "Fix the cause and restart, or install a certificate and its private key as %s and %s.",
		 err.c_str (), cert.path.c_str (), key.path.c_str ());
      return fail (why, "failed to generate a new SSL key pair: " + err);
    }

  if (shipped >= 0)
    {
      LOG_WARN ("replaced the SSL key pair %s, %s, which held the %s (the private key is public), "
		"with a newly generated one. Clients that pinned the old certificate will be warned once.",
		cert.path.c_str (), key.path.c_str (), shipped_keys[shipped].desc);
      if (cert.loaded && !self_issued (cert.cert))
	{
	  LOG_WARN ("the replaced certificate was issued by a CA for a shipped key. "
		    "Request a new certificate from the CA for the new key, and install it with the new key.");
	}
    }
  else
    {
      LOG_INFO ("generated a new SSL key pair: %s, %s", cert.path.c_str (), key.path.c_str ());
    }
  log_fingerprint (cert.path, new_cert);
  X509_free (new_cert);

  remove_leftovers (cert.path, key.path);

  if (!tls_accepts (cert.path, key.path, err))
    {
      LOG_ERROR ("TLS refuses the newly generated SSL key pair %s, %s: %s. "
		 "The OpenSSL configuration may require a stronger key than RSA 2048; "
		 "install a certificate and its private key that it accepts, and restart.",
		 cert.path.c_str (), key.path.c_str (), err.c_str ());
      return fail (why, "TLS refuses the newly generated SSL key pair " + cert.path + ", " + key.path + " ("
		   + err + ")");
    }
  return 0;
}

static int
ensure_pair (ssl_file &cert, ssl_file &key, bool auto_generate, const char *extra_san, std::string &why)
{
  std::string reason;
  int shipped;

  if (cert.kind == PATH_NOT_FILE || key.kind == PATH_NOT_FILE)
    {
      if (cert.kind == PATH_NOT_FILE)
	{
	  LOG_ERROR ("the SSL certificate %s is not a regular file. Fix it and restart.", cert.path.c_str ());
	  fail (why, "the SSL certificate " + cert.path + " is not a regular file");
	}
      if (key.kind == PATH_NOT_FILE)
	{
	  LOG_ERROR ("the SSL private key %s is not a regular file. Fix it and restart.", key.path.c_str ());
	  fail (why, "the SSL private key " + key.path + " is not a regular file");
	}
      return -1;
    }

  /* none: a new installation, or the links of an earlier version are broken */
  if (cert.kind == PATH_ABSENT && key.kind == PATH_ABSENT)
    {
      if (!auto_generate)
	{
	  LOG_ERROR ("the SSL certificate %s and private key %s do not exist. "
		     "Install a certificate and its private key, or set %s=YES in cm.conf to generate them.",
		     cert.path.c_str (), key.path.c_str (), CONF_AUTO_GENERATE);
	  return fail (why, "the SSL certificate " + cert.path + " and private key " + key.path
		       + " do not exist (" CONF_AUTO_GENERATE "=NO)");
	}
      return replace_pair (cert, key, -1, extra_san, why);
    }

  /*
   * only one: never overwrite the remaining file, it may be a key the
   * administrator is installing, and the private key of a CA issued
   * certificate cannot be recovered
   */
  if (cert.kind == PATH_ABSENT || key.kind == PATH_ABSENT)
    {
      ssl_file &missing = (cert.kind == PATH_ABSENT) ? cert : key;
      ssl_file &present = (cert.kind == PATH_ABSENT) ? key : cert;

      load_ssl_file (present);
      LOG_ERROR ("the SSL %s %s does not exist, while the %s %s does. The existing file is left unchanged. "
		 "Restore the missing file, or remove both files and restart to generate a new key pair (%s=YES).",
		 missing.what, missing.path.c_str (), present.what, present.path.c_str (), CONF_AUTO_GENERATE);
      if (present.loaded && present.shipped >= 0)
	{
	  LOG_ERROR ("the remaining %s holds the %s, whose private key is public. "
		     "Remove it and restart to generate a new key pair (%s=YES).", present.path.c_str (),
		     shipped_keys[present.shipped].desc, CONF_AUTO_GENERATE);
	}
      return fail (why, std::string ("the SSL ") + missing.what + " " + missing.path + " does not exist, while the "
		   + present.what + " " + present.path + " does");
    }

  load_ssl_file (cert);
  load_ssl_file (key);

  /* a shipped key in either file: it is public, so there is nothing to lose */
  shipped = (cert.loaded && cert.shipped >= 0) ? cert.shipped : ((key.loaded && key.shipped >= 0) ? key.shipped : -1);
  if (shipped >= 0)
    {
      if (auto_generate)
	{
	  return replace_pair (cert, key, shipped, extra_san, why);
	}

      if (!cert.loaded || !key.loaded)
	{
	  int ret = fail_unreadable (why, cert.loaded ? key : cert);

	  LOG_ERROR ("the other file holds the %s, whose private key is public.", shipped_keys[shipped].desc);
	  return ret;
	}
      if (!pair_matches (cert, key))
	{
	  return fail_mismatch (why, cert, key);
	}
      if (!tls_accepts (cert.path, key.path, reason))
	{
	  LOG_ERROR ("the SSL key pair %s, %s is the %s, and TLS refuses it: %s. "
		     "Set %s=YES in cm.conf and restart to replace it, or install a certificate and its private key "
		     "that TLS accepts (for example RSA 2048 bits or more).", cert.path.c_str (), key.path.c_str (),
		     shipped_keys[shipped].desc, reason.c_str (), CONF_AUTO_GENERATE);
	  return fail (why, "the SSL key pair " + cert.path + ", " + key.path + " is the "
		       + shipped_keys[shipped].desc + ", and TLS refuses it (" + reason + ")");
	}
      LOG_ERROR ("the SSL key pair %s, %s is the %s. Its private key is public, so TLS does not authenticate "
		 "this server. Set %s=YES in cm.conf and restart, or install a certificate with a new private "
		 "key.", cert.path.c_str (), key.path.c_str (), shipped_keys[shipped].desc,
		 CONF_AUTO_GENERATE);
      shipped_key_in_use = true;
      log_fingerprint (cert.path, cert.cert);
      return 0;
    }

  /* cannot tell: do not start with what may be a shipped key, do not overwrite */
  if (!cert.loaded || !key.loaded)
    {
      if (!cert.loaded)
	{
	  fail_unreadable (why, cert);
	}
      if (!key.loaded)
	{
	  fail_unreadable (why, key);
	}
      return -1;
    }

  if (!pair_matches (cert, key))
    {
      return fail_mismatch (why, cert, key);
    }

  /* generated before, or installed by the administrator: use as is */
  if (!tls_accepts (cert.path, key.path, reason))
    {
      LOG_ERROR ("TLS refuses the SSL key pair %s, %s: %s. The files are left unchanged; install a certificate "
		 "and its private key that TLS accepts (for example RSA 2048 bits or more), and restart.",
		 cert.path.c_str (), key.path.c_str (), reason.c_str ());
      return fail (why, "TLS refuses the SSL key pair " + cert.path + ", " + key.path + " (" + reason + ")");
    }
  log_fingerprint (cert.path, cert.cert);
  report_san_mismatch (cert.cert, cert.path, extra_san);
  report_key_mode (key.path);
  if (auto_generate)
    {
      remove_leftovers (cert.path, key.path);
    }
  return 0;
}

/* ---------------------------------------------------------- process lock */

/*
 * hold_process_lock () - take <key>.lock for this process, until it exits
 *
 *   cert_lock serializes the threads of one process only. Two cub_manager
 *   processes started at the same time can both pass the pid file check and
 *   reach the startup check before either binds the port (and with
 *   SO_REUSEADDR on Windows, binding does not exclude the second one either),
 *   so they could recover or generate in the same directory at once: one
 *   removing the other's work files, or each placing its own key or
 *   certificate. The process that takes this lock keeps it while it runs, so
 *   it covers the recovery, the generation and the moment TLS loads the files,
 *   and a second process stops before it touches any file. main () takes it
 *   through cm_ssl_cert_lock_process () right after it becomes a daemon,
 *   before init_files () and before the pid file is written, so that a
 *   second process cannot remove or overwrite the files of the first.
 *
 *   POSIX: an fcntl () write lock, which a forked child (a task) does not
 *   inherit and which ends when the process ends; the descriptor is closed
 *   on exec. Windows: LockFileEx () on a handle that is not inherited.
 *   The lock file is left in place: removing it would let another process
 *   lock a new file of the same name.
 *
 *   When the lock file cannot be created because this process cannot write
 *   in its directory (permissions, a read-only file system, or on Windows an
 *   ACL), no lock is taken: then this process cannot create, rename or
 *   remove anything there, and a key pair in a read-only conf is still used
 *   as it is. If another account could still write there, the worst case is
 *   that this process reads a pair being replaced, which the pair check
 *   refuses.
 *
 *   return: true if this process holds the lock (taken now or before)
 */
#if !defined (WINDOWS)
/*
 * dir_writable () - can this process create files in the directory of path.
 *   access () checks the effective permissions, POSIX ACLs included. (On
 *   Windows _access () looks only at the read-only attribute, not at the
 *   ACL, so the Windows code decides from what CreateFileA () returns.)
 */
static bool
dir_writable (const std::string &path)
{
  std::string dir = dir_of (path);

  return access (dir.empty ()? "." : dir.c_str (), W_OK) == 0;
}
#endif

#if !defined (WINDOWS)
/*
 * lock_file_owner () - "owner <name> (uid <n>), mode 0600; this process runs as
 *   <name> (uid <n>)", to explain why the lock file cannot be opened
 */
static std::string
lock_file_owner (const std::string &path)
{
  struct stat st;
  struct passwd *pw;
  char mode[8];
  std::string t;

  if (stat (path.c_str (), &st) != 0)
    {
      return std::string ();
    }
  pw = getpwuid (st.st_uid);
  snprintf (mode, sizeof (mode), "%04o", (unsigned int) (st.st_mode & 07777));
  t = "owner " + std::string (pw != NULL ? pw->pw_name : "?") + " (uid " + std::to_string ((long) st.st_uid)
      + "), mode " + mode;
  pw = getpwuid (geteuid ());
  t += "; this process runs as " + std::string (pw != NULL ? pw->pw_name : "?") + " (uid "
       + std::to_string ((long) geteuid ()) + ")";
  return t;
}
#endif

/*
 *   busy(out): true when another process holds the lock, false when the lock
 *              file cannot be used (err says why and what to do)
 */
static bool
hold_process_lock (const std::string &key_path, std::string &err, bool &busy)
{
  static bool held = false;
  std::string path = key_path + PROCESS_LOCK;
  int waited = 0;

  busy = false;

  if (held)
    {
      return true;
    }

#if defined (WINDOWS)
  HANDLE h = CreateFileA (path.c_str (), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
			  OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

  if (h == INVALID_HANDLE_VALUE && GetLastError () == ERROR_ACCESS_DENIED)
    {
      DWORD attr = GetFileAttributesA (path.c_str ());
      DWORD e = GetLastError ();

      /*
       * Decided by what Windows returns, as the ACL may deny writing even when
       * _access () says otherwise:
       * - no lock file, and it cannot be created: this account cannot create
       *   files in conf, so it cannot replace anything there; go on without
       *   the lock, as for a read-only conf.
       * - the lock file exists but cannot be opened for writing: a read
       *   handle is enough for LockFileEx ().
       */
      if (attr == INVALID_FILE_ATTRIBUTES && (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND))
	{
	  return true;
	}
      h = CreateFileA (path.c_str (), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
		       FILE_ATTRIBUTE_NORMAL, NULL);
    }
  if (h == INVALID_HANDLE_VALUE)
    {
      DWORD e = GetLastError ();

      err = "cannot open the lock file " + path + ": " + win_error_string (e);
      if (e == ERROR_ACCESS_DENIED)
	{
	  err += ". It was probably created by cub_manager running as another account: give the account cub_manager "
		 "runs as read and write access to it, or remove it while no cub_manager is running";
	}
      return false;
    }
  for (;;)
    {
      OVERLAPPED ov;

      memset (&ov, 0, sizeof (ov));
      if (LockFileEx (h, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &ov))
	{
	  break;
	}
      if (GetLastError () != ERROR_LOCK_VIOLATION || waited >= CERT_LOCK_WAIT_MS)
	{
	  busy = (GetLastError () == ERROR_LOCK_VIOLATION);
	  err = busy ? "another cub_manager process holds " + path
		: "cannot lock " + path + ": " + win_error_string (GetLastError ());
	  CloseHandle (h);
	  return false;
	}
      Sleep (CERT_LOCK_RETRY_MS);
      waited += CERT_LOCK_RETRY_MS;
    }
  /* the handle stays open until the process exits */
#else
  struct flock fl;
  int fd = open (path.c_str (), O_RDWR | O_CREAT | O_CLOEXEC, 0600);

  if (fd < 0)
    {
      int e = errno;

      if ((e == EACCES || e == EPERM || e == EROFS) && !dir_writable (path))
	{
	  return true;
	}
      err = "cannot open the lock file " + path + ": " + errno_string (e);
      if (e == EACCES || e == EPERM)
	{
	  /* for example left by cub_manager started once as root: not another running process */
	  std::string owner = lock_file_owner (path);

	  err += (owner.empty ()? std::string () : " (" + owner + ")")
		 + ". It was probably created by cub_manager running as another account: make it readable and writable "
		 "by the account cub_manager runs as (chown or chmod), or remove it while no cub_manager is running";
	}
      return false;
    }
  for (;;)
    {
      memset (&fl, 0, sizeof (fl));
      fl.l_type = F_WRLCK;
      fl.l_whence = SEEK_SET;
      if (fcntl (fd, F_SETLK, &fl) == 0)
	{
	  break;
	}
      if ((errno != EACCES && errno != EAGAIN) || waited >= CERT_LOCK_WAIT_MS)
	{
	  busy = (errno == EACCES || errno == EAGAIN);
	  err = busy ? "another cub_manager process holds " + path : "cannot lock " + path + ": " + errno_string (errno);
	  close (fd);
	  return false;
	}
      usleep (CERT_LOCK_RETRY_MS * 1000);
      waited += CERT_LOCK_RETRY_MS;
    }
  /* the descriptor stays open until the process exits */
#endif

  held = true;
  return true;
}

/*
 * cm_ssl_cert_ensure () - check the key pair at startup, before init_SSL ()
 *
 *   return: 0 if cert_path/key_path hold a usable key pair (kept, generated or
 *           replaced), -1 if the manager must not start. The reason and what
 *           to do are logged.
 *   cert_path(in): certificate file (PEM)
 *   key_path(in): private key file (PEM)
 *   auto_generate(in): ssl_cert_auto_generate of cm.conf
 *   extra_san(in): ssl_cert_san of cm.conf, used when a key pair is generated;
 *                  NULL or empty for none
 *   err_buf(out): on failure, why in one line (for stderr), may be NULL
 *   err_size(in): size of err_buf
 */
int
cm_ssl_cert_ensure (const char *cert_path, const char *key_path, bool auto_generate, const char *extra_san,
		    char *err_buf, size_t err_size)
{
  cert_lock lock;
  bool is_link = false;
  std::string why;
  int ret;

  shipped_key_in_use = false;
  copy_error (err_buf, err_size, std::string ());
  if (cert_path == NULL || cert_path[0] == '\0' || key_path == NULL || key_path[0] == '\0')
    {
      LOG_ERROR ("the SSL certificate or private key path is not set");
      copy_error (err_buf, err_size, "the SSL certificate or private key path is not set");
      return -1;
    }

  ssl_file cert ("certificate", cert_path, false);
  ssl_file key ("private key", key_path, true);
  std::string err;
  bool busy = false;

  /* one process at a time in this directory, from here until it exits */
  if (!hold_process_lock (key.path, err, busy))
    {
      if (busy)
	{
	  LOG_ERROR ("cannot check the SSL key pair: %s. Another cub_manager may be starting or running with the "
		     "same configuration; stop it, or wait until it has started, and retry.", err.c_str ());
	}
      else
	{
	  LOG_ERROR ("cannot check the SSL key pair: %s.", err.c_str ());
	}
      why = "cannot check the SSL key pair: " + err;
      ret = -1;
    }
  /* an interrupted replacement that cannot be undone: do not start, keep its files */
  else if (!recover_interrupted (cert.path, key.path, why))
    {
      ret = -1;
    }
  else
    {
      cert.kind = check_path (cert.path, &is_link);
      key.kind = check_path (key.path, &is_link);
      report_extra_san (extra_san);
      ret = ensure_pair (cert, key, auto_generate, extra_san, why);
    }
  ERR_clear_error ();
  if (ret != 0)
    {
      copy_error (err_buf, err_size, why.empty ()? std::string ("the SSL key pair cannot be used") : why);
    }
  return ret;
}

/*
 * cm_ssl_cert_generate () - generate a new key pair and replace the files
 *
 *   Used by generatecert, which only debug builds offer (CBRD-27829); the
 *   startup check generates through the same code.
 *
 *   return: 0 on success, -1 on failure (the existing files are unchanged).
 *   cert_path(in): certificate file (PEM)
 *   key_path(in): private key file (PEM), created with mode 0600
 *   opts(in): subject and validity, NULL for the defaults
 *   err_buf(out): why it failed, may be NULL
 *   err_size(in): size of err_buf
 */
int
cm_ssl_cert_generate (const char *cert_path, const char *key_path, const T_CM_SSL_CERT_OPTS *opts, char *err_buf,
		      size_t err_size)
{
  cert_lock lock;
  X509 *cert = NULL;
  std::string err;

  copy_error (err_buf, err_size, std::string ());
  if (cert_path == NULL || cert_path[0] == '\0' || key_path == NULL || key_path[0] == '\0')
    {
      copy_error (err_buf, err_size, "the SSL certificate or private key path is not set");
      return -1;
    }

  /* held already when the server started through cm_ssl_cert_ensure () */
  bool busy = false;

  if (!hold_process_lock (key_path, err, busy))
    {
      LOG_ERROR ("cannot generate a new SSL key pair: %s", err.c_str ());
      copy_error (err_buf, err_size, "Cannot generate a new SSL key pair: " + err);
      return -1;
    }

  report_extra_san ((opts != NULL) ? opts->extra_san : NULL);
  if (!generate_pair (cert_path, key_path, opts, &cert, err))
    {
      LOG_ERROR ("failed to generate a new SSL key pair %s, %s: %s. The existing files are left unchanged.",
		 cert_path, key_path, err.c_str ());
      copy_error (err_buf, err_size, "Failed to generate a new SSL key pair: " + err);
      return -1;
    }

  LOG_INFO ("generated a new SSL key pair: %s, %s", cert_path, key_path);
  log_fingerprint (cert_path, cert);
  X509_free (cert);
  return 0;
}

/*
 * cm_ssl_cert_lock_process () - make this process the only cub_manager using
 *   this configuration: take the lock <key_path>.lock and keep it until the
 *   process exits. Called by main () before it touches any shared file (the
 *   pid file, the session list); cm_ssl_cert_ensure () takes it too if it was
 *   not taken. Waits a few seconds for a previous process that is exiting.
 *
 *   return: 0 if this process holds it (or the directory is not writable, so
 *           that no process can change anything there), -1 if another process
 *           holds it
 *   key_path(in): private key file (PEM); the lock file is next to it
 *   err_buf(out): on failure, why in one line (for stderr), may be NULL
 *   err_size(in): size of err_buf
 */
int
cm_ssl_cert_lock_process (const char *key_path, char *err_buf, size_t err_size)
{
  std::string err;

  copy_error (err_buf, err_size, std::string ());
  if (key_path == NULL || key_path[0] == '\0')
    {
      copy_error (err_buf, err_size, "the SSL private key path is not set");
      return -1;
    }
  bool busy = false;

  if (!hold_process_lock (key_path, err, busy))
    {
      if (busy)
	{
	  LOG_ERROR ("another cub_manager may be starting or running with the same configuration: %s. Stop it, or "
		     "wait until it has started, and retry.", err.c_str ());
	}
      else
	{
	  LOG_ERROR ("cannot take the lock of this configuration: %s.", err.c_str ());
	}
      copy_error (err_buf, err_size, err);
      return -1;
    }
  return 0;
}

/*
 * cm_ssl_cert_shipped_key_in_use () - did cm_ssl_cert_ensure () accept a key
 *   pair that an earlier version shipped (ssl_cert_auto_generate=NO)?
 */
bool
cm_ssl_cert_shipped_key_in_use (void)
{
  return shipped_key_in_use;
}
