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
 * cm_ssl_cert.h - the TLS certificate and private key of the manager server
 *
 *   The key pair is not shipped. cub_manager generates one (RSA 2048,
 *   self-signed) when it starts without one, and replaces a key pair that an
 *   earlier version shipped (its private key is public). The rest of the
 *   manager uses only the three functions below.
 */

#ifndef _CM_SSL_CERT_H_
#define _CM_SSL_CERT_H_

#include <stddef.h>

/*
 * T_CM_SSL_CERT_OPTS - subject and validity of a generated certificate
 *
 *   A NULL or empty field is left out of the subject. When every subject field
 *   is left out (or opts is NULL), the default subject is used: CN is the host
 *   name, the other fields keep the values of the certificate shipped before.
 */
typedef struct
{
  const char *country;		/* C, two letters */
  const char *state;		/* ST */
  const char *locality;		/* L */
  const char *organization;	/* O */
  const char *org_unit;		/* OU */
  const char *common_name;	/* CN */
  const char *email;		/* emailAddress */
  int days;			/* validity in days, 0 = default (10 years) */
} T_CM_SSL_CERT_OPTS;

/*
 * cm_ssl_cert_ensure () - check the key pair at startup, before init_SSL ()
 *
 *   return: 0 if cert_path/key_path hold a usable key pair (kept, generated or
 *           replaced), -1 if the manager must not start. The reason and what
 *           to do are logged.
 *   cert_path(in): certificate file (PEM)
 *   key_path(in): private key file (PEM)
 *   auto_generate(in): ssl_cert_auto_generate of cm.conf
 *   err_buf(out): on failure, why in one line (for stderr), may be NULL
 *   err_size(in): size of err_buf
 */
extern int cm_ssl_cert_ensure (const char *cert_path, const char *key_path, bool auto_generate, char *err_buf,
			       size_t err_size);

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
extern int cm_ssl_cert_generate (const char *cert_path, const char *key_path, const T_CM_SSL_CERT_OPTS *opts,
				 char *err_buf, size_t err_size);

/*
 * cm_ssl_cert_shipped_key_in_use () - did cm_ssl_cert_ensure () accept a key
 *   pair that an earlier version shipped (ssl_cert_auto_generate=NO)?
 */
extern bool cm_ssl_cert_shipped_key_in_use (void);

#endif /* _CM_SSL_CERT_H_ */
