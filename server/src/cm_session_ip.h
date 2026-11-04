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
 * cm_session_ip.h - compare the IP address a request came from with the IP
 *   address its session logged in from (session_ip_check of cm.conf).
 *
 *   No CUBRID or CMS dependency, so that the address comparison and the
 *   decision for each mode can be tested on their own
 *   (server/test/unit/test_session_ip.cpp). Logging and deleting the session
 *   stay with the caller, check_session_ip () in
 *   cm_server_extend_interface.cpp.
 */

#ifndef _CM_SESSION_IP_H_
#define _CM_SESSION_IP_H_

#include <stddef.h>

#include <algorithm>
#include <deque>
#include <string>

/*
 * session_ip_check of cm.conf: what to do when a request comes from an IP
 * address other than the one its session logged in from.
 */
typedef enum
{
  SESSION_IP_CHECK_OFF,		/* do not compare */
  SESSION_IP_CHECK_LOG,		/* log a warning, process the request */
  SESSION_IP_CHECK_ENFORCE	/* log a warning, reject the request and
				 * delete the session */
} T_SESSION_IP_CHECK;

/* result of comparing the login IP with the request IP */
typedef enum
{
  SESSION_IP_SAME,		/* the same address */
  SESSION_IP_DIFFERENT,		/* another address */
  SESSION_IP_UNKNOWN		/* either one cannot be read as an address */
} T_SESSION_IP_MATCH;

/* what the caller does with the request */
typedef enum
{
  SESSION_IP_ALLOW,		/* process it */
  SESSION_IP_ALLOW_WARN,	/* log a warning and process it */
  SESSION_IP_REJECT		/* log a warning, delete the session and
				 * reject it as an invalid token */
} T_SESSION_IP_ACTION;

bool ut_normalize_ip (const char *src, char *dst, size_t dst_size);
T_SESSION_IP_MATCH ut_session_ip_compare (const char *login_ip,
    const char *request_ip,
    char *login_norm,
    char *request_norm,
    size_t norm_size);
T_SESSION_IP_ACTION ut_session_ip_action (T_SESSION_IP_CHECK mode,
    T_SESSION_IP_MATCH match);

/*
 * SESSION_IP_WARNED_MAX - how many request addresses a session remembers
 *   having warned about. Enough for a forward proxy pool with a few outgoing
 *   addresses; when it is full, the address warned about longest ago is
 *   dropped, so the memory of a session stays bounded.
 */
#define SESSION_IP_WARNED_MAX 8

/*
 * ut_session_ip_should_warn () - whether a session IP warning is logged for a
 *   request from addr, given the addresses the session warned about
 *   recently, and remember addr among them.
 *
 *   The warning is logged only for an address that is not among the last
 *   SESSION_IP_WARNED_MAX addresses warned about in the session. A client
 *   that shares its token, or a forward proxy pool whose requests come from
 *   several addresses in turn (A, B, A, B, ...), polling every few seconds,
 *   would otherwise fill the error log with the same warning. The requests
 *   that are not logged here are recorded by login_ip= of the access log.
 *   A rejection (enforce) deletes the session and is always logged by the
 *   caller, without this.
 *
 *   Inline so that cm_user.cpp, which cm_admin also builds, can use it
 *   without linking cm_session_ip.cpp.
 *
 *   return: true to log the warning
 *   warned(in/out): the addresses warned about recently, oldest first
 *   addr(in): the request's address (normalized), or what was received when
 *             it is unknown; NULL for none
 */
inline bool
ut_session_ip_should_warn (std::deque<std::string> &warned, const char *addr)
{
  std::string key = (addr != NULL) ? addr : "-";

  if (std::find (warned.begin (), warned.end (), key) != warned.end ())
    {
      return false;
    }
  if (warned.size () >= SESSION_IP_WARNED_MAX)
    {
      warned.pop_front ();
    }
  warned.push_back (key);
  return true;
}

#endif /* _CM_SESSION_IP_H_ */
