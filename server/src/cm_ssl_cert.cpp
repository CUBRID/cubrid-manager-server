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
 *   cm_ssl_cert_ensure ()              startup check: keep, generate or replace
 *   cm_ssl_cert_generate ()            new key pair (startup and generatecert)
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
#include <iphlpapi.h>
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#else
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <ifaddrs.h>
#endif

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
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
#define CERT_MAX_IF_ADDRS               32	/* interface addresses in SAN */
#define CERT_MAX_FILE_SIZE              (1024 * 1024)

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
 * self_issued () - is the certificate issued by itself (not by a CA)
 */
static bool
self_issued (X509 *cert)
{
  int ok;

  ok = X509_check_issued (cert, cert);
  ERR_clear_error ();
  return ok == X509_V_OK;
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
 * is_dns_name () - letters, digits, '-' and '.', as a SAN dNSName allows
 */
static bool
is_dns_name (const std::string &name)
{
  size_t i;

  if (name.empty () || name.size () > CERT_DNS_NAME_MAX || name[0] == '.' || name[0] == '-'
      || name[name.size () - 1] == '.')
    {
      return false;
    }
  for (i = 0; i < name.size (); i++)
    {
      char c = name[i];

      if (! ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.'))
	{
	  return false;
	}
    }
  return true;
}

/*
 * skip_ip () - loopback, link-local, unspecified and IPv4-mapped addresses
 *   are not put in the SAN from the interfaces (loopback is added as fixed)
 */
static bool
skip_ip (const san_ip &ip)
{
  static const unsigned char zero[16] = { 0 };
  static const unsigned char v4_mapped[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

  if (ip.len == 4)
    {
      return ip.addr[0] == 127 || ip.addr[0] == 0 || (ip.addr[0] == 169 && ip.addr[1] == 254);
    }
  if (memcmp (ip.addr, zero, 15) == 0 && (ip.addr[15] == 0 || ip.addr[15] == 1))
    {
      return true;		/* :: and ::1 */
    }
  if (ip.addr[0] == 0xfe && (ip.addr[1] & 0xc0) == 0x80)
    {
      return true;		/* fe80::/10 */
    }
  return memcmp (ip.addr, v4_mapped, sizeof (v4_mapped)) == 0;
}

static void
add_unique_ip (std::vector < san_ip > &ips, const san_ip &ip)
{
  size_t i;

  for (i = 0; i < ips.size (); i++)
    {
      if (ips[i].len == ip.len && memcmp (ips[i].addr, ip.addr, ip.len) == 0)
	{
	  return;
	}
    }
  ips.push_back (ip);
}

static bool
sockaddr_to_ip (const struct sockaddr *sa, san_ip &ip)
{
  if (sa == NULL)
    {
      return false;
    }
  memset (&ip, 0, sizeof (ip));
  if (sa->sa_family == AF_INET)
    {
      ip.len = 4;
      memcpy (ip.addr, & ((const struct sockaddr_in *) sa)->sin_addr, 4);
      return true;
    }
  if (sa->sa_family == AF_INET6)
    {
      ip.len = 16;
      memcpy (ip.addr, & ((const struct sockaddr_in6 *) sa)->sin6_addr, 16);
      return true;
    }
  return false;
}

/*
 * collect_interface_ips () - addresses of the interfaces that are up,
 *   appended to ips (at most CERT_MAX_IF_ADDRS of them)
 */
static void
collect_interface_ips (std::vector < san_ip > &ips)
{
  size_t limit = ips.size () + CERT_MAX_IF_ADDRS;
  san_ip ip;

#if defined (WINDOWS)
  ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
  ULONG size = 16 * 1024;
  ULONG ret = ERROR_BUFFER_OVERFLOW;
  std::vector < unsigned char >buf;
  PIP_ADAPTER_ADDRESSES adapter;
  PIP_ADAPTER_UNICAST_ADDRESS ua;
  int tries;

  for (tries = 0; tries < 3 && ret == ERROR_BUFFER_OVERFLOW; tries++)
    {
      buf.resize (size);
      ret = GetAdaptersAddresses (AF_UNSPEC, flags, NULL, (PIP_ADAPTER_ADDRESSES) & buf[0], &size);
    }
  if (ret != NO_ERROR)
    {
      LOG_WARN ("cannot list the network interfaces (%s); the SAN has no interface address",
		win_error_string (ret).c_str ());
      return;
    }
  for (adapter = (PIP_ADAPTER_ADDRESSES) & buf[0]; adapter != NULL; adapter = adapter->Next)
    {
      if (adapter->OperStatus != IfOperStatusUp || adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
	{
	  continue;
	}
      for (ua = adapter->FirstUnicastAddress; ua != NULL; ua = ua->Next)
	{
	  if (ips.size () >= limit)
	    {
	      return;
	    }
	  if (sockaddr_to_ip (ua->Address.lpSockaddr, ip) && !skip_ip (ip))
	    {
	      add_unique_ip (ips, ip);
	    }
	}
    }
#else
  struct ifaddrs *ifs = NULL;
  struct ifaddrs *ifa;

  if (getifaddrs (&ifs) != 0)
    {
      LOG_WARN ("cannot list the network interfaces (%s); the SAN has no interface address",
		errno_string (errno).c_str ());
      return;
    }
  for (ifa = ifs; ifa != NULL && ips.size () < limit; ifa = ifa->ifa_next)
    {
      if (! (ifa->ifa_flags & IFF_UP) || ! (ifa->ifa_flags & IFF_RUNNING) || (ifa->ifa_flags & IFF_LOOPBACK))
	{
	  continue;
	}
      if (sockaddr_to_ip (ifa->ifa_addr, ip) && !skip_ip (ip))
	{
	  add_unique_ip (ips, ip);
	}
    }
  freeifaddrs (ifs);
#endif
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
 * add_san () - DNS: host name, localhost / IP: 127.0.0.1, ::1 and the
 *   addresses of the interfaces that are up
 */
static bool
add_san (X509 *x, const std::string &host)
{
  static const san_ip v4_loopback = { 4, {127, 0, 0, 1} };
  static const san_ip v6_loopback = { 16, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1} };
  GENERAL_NAMES *gens;
  std::vector < san_ip > ips;
  bool ok = true;
  size_t i;

  gens = sk_GENERAL_NAME_new_null ();
  if (gens == NULL)
    {
      return false;
    }

  ips.push_back (v4_loopback);
  ips.push_back (v6_loopback);
  collect_interface_ips (ips);

  if (is_dns_name (host) && host != "localhost")
    {
      ok = push_dns_name (gens, host);
    }
  ok = ok && push_dns_name (gens, "localhost");
  for (i = 0; ok && i < ips.size (); i++)
    {
      ok = push_ip (gens, ips[i]);
    }
  ok = ok && X509_add1_ext_i2d (x, NID_subject_alt_name, gens, 0, X509V3_ADD_DEFAULT) == 1;

  GENERAL_NAMES_free (gens);
  return ok;
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
      if (!add_san (x, host))
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
 *   on failure the old key and certificate are both back as they were.
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
  std::string e2;
  bool key_set_aside = false;
  bool key_placed = false;
  bool ok = false;

  if (!random_suffix (suffix, err))
    {
      return false;
    }
  key_tmp = key_path + ".tmp-" + suffix;
  cert_tmp = cert_path + ".tmp-" + suffix;
  key_old = key_path + ".old-" + suffix;

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

      if (path_entry_exists (key_path))
	{
	  if (!replace_file (key_path, key_old, err))
	    {
	      break;
	    }
	  key_set_aside = true;
	}
      if (!replace_file (key_tmp, key_path, err))
	{
	  break;
	}
      key_placed = true;
      if (!replace_file (cert_tmp, cert_path, err))
	{
	  break;
	}
      ok = true;
    }
  while (0);

  cleanse_string (key_pem);

  if (ok)
    {
      if (key_set_aside)
	{
	  unlink (key_old.c_str ());
	}
      return true;
    }

  /* roll back */
  if (key_placed)
    {
      unlink (key_path.c_str ());
    }
  if (key_set_aside && !replace_file (key_old, key_path, e2))
    {
      LOG_ERROR ("cannot restore the private key: %s; the previous key is in %s", e2.c_str (), key_old.c_str ());
    }
  unlink (key_tmp.c_str ());
  unlink (cert_tmp.c_str ());
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

/* ------------------------------------------------------------ startup check */

static void
log_unreadable (const ssl_file &f)
{
  LOG_ERROR ("cannot tell whether the SSL %s %s holds a key shipped with an earlier version: %s. "
	     "The files are left unchanged; make the file readable by this account, in PEM, without a passphrase, "
	     "and restart.", f.what, f.path.c_str (), f.reason.c_str ());
}

static void
log_mismatch (const ssl_file &cert, const ssl_file &key)
{
  LOG_ERROR ("the SSL certificate %s and private key %s do not match. "
	     "Replace both with a certificate and its own private key, and restart.", cert.path.c_str (),
	     key.path.c_str ());
}

/*
 * replace_pair () - generate a new key pair in place of the files
 *
 *   shipped(in): index of the shipped key being replaced, -1 if none exists
 */
static int
replace_pair (ssl_file &cert, ssl_file &key, int shipped)
{
  X509 *new_cert = NULL;
  std::string err;

  if (!generate_pair (cert.path, key.path, NULL, &new_cert, err))
    {
      LOG_ERROR ("failed to generate a new SSL key pair: %s. The existing files are left unchanged. "
		 "Fix the cause and restart, or install a certificate and its private key as %s and %s.",
		 err.c_str (), cert.path.c_str (), key.path.c_str ());
      return -1;
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
  return 0;
}

static int
ensure_pair (ssl_file &cert, ssl_file &key, bool auto_generate)
{
  int shipped;

  if (cert.kind == PATH_NOT_FILE || key.kind == PATH_NOT_FILE)
    {
      if (cert.kind == PATH_NOT_FILE)
	{
	  LOG_ERROR ("the SSL certificate %s is not a regular file. Fix it and restart.", cert.path.c_str ());
	}
      if (key.kind == PATH_NOT_FILE)
	{
	  LOG_ERROR ("the SSL private key %s is not a regular file. Fix it and restart.", key.path.c_str ());
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
	  return -1;
	}
      return replace_pair (cert, key, -1);
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
      return -1;
    }

  load_ssl_file (cert);
  load_ssl_file (key);

  /* a shipped key in either file: it is public, so there is nothing to lose */
  shipped = (cert.loaded && cert.shipped >= 0) ? cert.shipped : ((key.loaded && key.shipped >= 0) ? key.shipped : -1);
  if (shipped >= 0)
    {
      if (auto_generate)
	{
	  return replace_pair (cert, key, shipped);
	}

      if (!cert.loaded || !key.loaded)
	{
	  log_unreadable (cert.loaded ? key : cert);
	  LOG_ERROR ("the other file holds the %s, whose private key is public.", shipped_keys[shipped].desc);
	  return -1;
	}
      if (!pair_matches (cert, key))
	{
	  log_mismatch (cert, key);
	  return -1;
	}
      LOG_ERROR ("the SSL key pair %s, %s is the %s. Its private key is public, so TLS does not authenticate "
		 "this server. Set %s=YES in cm.conf and restart, run generatecert, or install a certificate with "
		 "a new private key.", cert.path.c_str (), key.path.c_str (), shipped_keys[shipped].desc,
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
	  log_unreadable (cert);
	}
      if (!key.loaded)
	{
	  log_unreadable (key);
	}
      return -1;
    }

  if (!pair_matches (cert, key))
    {
      log_mismatch (cert, key);
      return -1;
    }

  /* generated before, or installed by the administrator: use as is */
  log_fingerprint (cert.path, cert.cert);
  if (auto_generate)
    {
      remove_leftovers (cert.path, key.path);
    }
  return 0;
}

/* ------------------------------------------------------------------ public */

int
cm_ssl_cert_ensure (const char *cert_path, const char *key_path, bool auto_generate)
{
  cert_lock lock;
  bool is_link = false;
  int ret;

  shipped_key_in_use = false;
  if (cert_path == NULL || cert_path[0] == '\0' || key_path == NULL || key_path[0] == '\0')
    {
      LOG_ERROR ("the SSL certificate or private key path is not set");
      return -1;
    }

  ssl_file cert ("certificate", cert_path, false);
  ssl_file key ("private key", key_path, true);

  cert.kind = check_path (cert.path, &is_link);
  key.kind = check_path (key.path, &is_link);

  ret = ensure_pair (cert, key, auto_generate);
  ERR_clear_error ();
  return ret;
}

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

bool
cm_ssl_cert_shipped_key_in_use (void)
{
  return shipped_key_in_use;
}
