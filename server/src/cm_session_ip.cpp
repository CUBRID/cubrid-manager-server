/*
 * Copyright (C) 2016 Search Solution Corporation. All rights reserved by Search Solution.
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
 * cm_session_ip.cpp - see cm_session_ip.h
 */

#if defined(WINDOWS)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <string.h>

#include "cm_session_ip.h"

/*
 * ut_normalize_ip () - convert an IP address in text form to one standard
 *   form, so that two forms of the same address compare equal as strings.
 *
 *   An IPv4 address is written as inet_ntop () writes it. For an IPv6
 *   address, the scope after '%' (link-local address) is removed, and the
 *   address is written as inet_ntop () writes it, which drops leading zeros,
 *   compresses runs of zero fields and uses lowercase. An IPv4-mapped IPv6
 *   address (::ffff:1.2.3.4) is written as the IPv4 address (1.2.3.4).
 *
 *   return: true if src is an IP address and the result fits in dst;
 *           false otherwise, with dst set to "".
 *   src(in): address in text form
 *   dst(out): normalized address; DBMT_USER_IP_LEN bytes are always enough
 *   dst_size(in): size of dst
 */
bool
ut_normalize_ip (const char *src, char *dst, size_t dst_size)
{
  char addr_str[INET6_ADDRSTRLEN];
  const char *scope;
  size_t addr_len;
  struct in_addr addr4;
  struct in6_addr addr6;
  int i;

  if (dst == NULL || dst_size == 0)
    {
      return false;
    }
  dst[0] = '\0';

  if (src == NULL)
    {
      return false;
    }

  if (inet_pton (AF_INET, src, &addr4) == 1)
    {
      return inet_ntop (AF_INET, &addr4, dst, dst_size) != NULL;
    }

  /* IPv6: drop the scope (fe80::1%eth0 -> fe80::1) */
  scope = strchr (src, '%');
  addr_len = (scope != NULL) ? (size_t) (scope - src) : strlen (src);
  if (addr_len >= sizeof (addr_str))
    {
      return false;
    }
  memcpy (addr_str, src, addr_len);
  addr_str[addr_len] = '\0';

  if (inet_pton (AF_INET6, addr_str, &addr6) != 1)
    {
      return false;
    }

  /* IPv4-mapped IPv6 (::ffff:a.b.c.d): 10 zero bytes, 0xff 0xff, IPv4 */
  for (i = 0; i < 10 && addr6.s6_addr[i] == 0; i++)
    {
      ;
    }
  if (i == 10 && addr6.s6_addr[10] == 0xff && addr6.s6_addr[11] == 0xff)
    {
      memcpy (&addr4, &addr6.s6_addr[12], sizeof (addr4));
      if (inet_ntop (AF_INET, &addr4, dst, dst_size) == NULL)
	{
	  dst[0] = '\0';
	  return false;
	}
      return true;
    }

  if (inet_ntop (AF_INET6, &addr6, dst, dst_size) == NULL)
    {
      dst[0] = '\0';
      return false;
    }
  return true;
}

/*
 * ut_session_ip_compare () - compare the IP the session logged in from with
 *   the IP a request came from.
 *
 *   Both are normalized by ut_normalize_ip () and compared as strings, so
 *   two forms of the same address are the same. The port is not part of
 *   either. An address that cannot be normalized makes the result unknown,
 *   which the caller must not treat as a mismatch.
 *
 *   return: SESSION_IP_SAME, SESSION_IP_DIFFERENT or SESSION_IP_UNKNOWN
 *   login_ip(in): the session's login IP (NULL if unknown)
 *   request_ip(in): the request's IP (NULL if unknown)
 *   login_norm(out): login_ip normalized, "" if it cannot be
 *   request_norm(out): request_ip normalized, "" if it cannot be
 *   norm_size(in): size of login_norm and request_norm; DBMT_USER_IP_LEN
 *                  bytes are always enough
 */
T_SESSION_IP_MATCH
ut_session_ip_compare (const char *login_ip, const char *request_ip,
		       char *login_norm, char *request_norm, size_t norm_size)
{
  bool login_ok, request_ok;

  /* both are normalized even if the first fails, for the caller's log */
  login_ok = ut_normalize_ip (login_ip, login_norm, norm_size);
  request_ok = ut_normalize_ip (request_ip, request_norm, norm_size);

  if (!login_ok || !request_ok)
    {
      return SESSION_IP_UNKNOWN;
    }

  return (strcmp (login_norm, request_norm) == 0) ? SESSION_IP_SAME : SESSION_IP_DIFFERENT;
}

/*
 * ut_session_ip_action () - what to do with a request, from session_ip_check
 *   and the result of ut_session_ip_compare ().
 *
 *     mode     same    different   unknown
 *     off      allow   allow       allow
 *     log      allow   allow+warn  allow+warn
 *     enforce  allow   reject      allow+warn
 *
 *   Only enforce with another address rejects; an unknown address is never
 *   rejected, so a request whose address cannot be read does not log out a
 *   valid user.
 *
 *   return: SESSION_IP_ALLOW, SESSION_IP_ALLOW_WARN or SESSION_IP_REJECT
 *   mode(in): session_ip_check
 *   match(in): result of ut_session_ip_compare ()
 */
T_SESSION_IP_ACTION
ut_session_ip_action (T_SESSION_IP_CHECK mode, T_SESSION_IP_MATCH match)
{
  if (mode == SESSION_IP_CHECK_OFF || match == SESSION_IP_SAME)
    {
      return SESSION_IP_ALLOW;
    }

  if (match == SESSION_IP_DIFFERENT && mode == SESSION_IP_CHECK_ENFORCE)
    {
      return SESSION_IP_REJECT;
    }

  return SESSION_IP_ALLOW_WARN;
}
