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
 * test_session_ip.cpp - unit tests of server/src/cm_session_ip.cpp, the
 *   comparison behind session_ip_check (CBRD-27861).
 *
 *   enforce deletes the session and its DB logins, so a regression in the
 *   comparison either logs out a valid user (two forms of one address
 *   compare different) or lets another address through (two addresses
 *   compare the same). Both directions are covered, and so is the decision
 *   for every mode.
 *
 *   Build and run with run_unit_tests.sh in this directory; it needs no
 *   CUBRID build. A running manager server listens on IPv4 only, so the
 *   IPv6 forms here cannot be produced by an API test; the API test set
 *   task_session_ip_check checks the sessions themselves.
 */

#include <stdio.h>
#include <string.h>

#include "cm_session_ip.h"

#define NORM_SIZE 65		/* DBMT_USER_IP_LEN */

static int failures = 0;
static int checks = 0;

static void
check (bool ok, const char *what)
{
  checks++;
  if (!ok)
    {
      failures++;
      printf ("FAIL  %s\n", what);
    }
}

/* ut_normalize_ip (): src gives expect, or fails when expect is NULL */
static void
normalize (const char *src, const char *expect)
{
  char dst[NORM_SIZE];
  char what[256];
  bool ok;

  memset (dst, 'x', sizeof (dst));
  ok = ut_normalize_ip (src, dst, sizeof (dst));

  snprintf (what, sizeof (what), "normalize \"%s\" -> %s%s%s (got %s \"%s\")",
	    src ? src : "(null)", expect ? "\"" : "", expect ? expect : "failure", expect ? "\"" : "",
	    ok ? "true" : "false", dst);
  if (expect == NULL)
    {
      check (!ok && dst[0] == '\0', what);
    }
  else
    {
      check (ok && strcmp (dst, expect) == 0, what);
    }
}

static const char *
match_name (T_SESSION_IP_MATCH match)
{
  switch (match)
    {
    case SESSION_IP_SAME:
      return "same";
    case SESSION_IP_DIFFERENT:
      return "different";
    case SESSION_IP_UNKNOWN:
      return "unknown";
    }
  return "?";
}

static const char *
action_name (T_SESSION_IP_ACTION action)
{
  switch (action)
    {
    case SESSION_IP_ALLOW:
      return "allow";
    case SESSION_IP_ALLOW_WARN:
      return "allow+warn";
    case SESSION_IP_REJECT:
      return "reject";
    }
  return "?";
}

/* ut_session_ip_compare (): the login IP and the request IP give expect */
static void
compare (const char *login_ip, const char *request_ip, T_SESSION_IP_MATCH expect)
{
  char login_norm[NORM_SIZE];
  char request_norm[NORM_SIZE];
  char what[256];
  T_SESSION_IP_MATCH match;

  match = ut_session_ip_compare (login_ip, request_ip, login_norm, request_norm, NORM_SIZE);

  snprintf (what, sizeof (what), "compare login \"%s\", request \"%s\" -> %s (got %s)",
	    login_ip ? login_ip : "(null)", request_ip ? request_ip : "(null)",
	    match_name (expect), match_name (match));
  check (match == expect, what);
}

/* ut_session_ip_action (): mode and match give expect */
static void
action (T_SESSION_IP_CHECK mode, const char *mode_name, T_SESSION_IP_MATCH match,
	T_SESSION_IP_ACTION expect)
{
  char what[256];
  T_SESSION_IP_ACTION got;

  got = ut_session_ip_action (mode, match);

  snprintf (what, sizeof (what), "action %s, %s -> %s (got %s)", mode_name, match_name (match),
	    action_name (expect), action_name (got));
  check (got == expect, what);
}

static void
test_normalize (void)
{
  char small[8];

  /* IPv4 as it is */
  normalize ("127.0.0.1", "127.0.0.1");
  normalize ("10.0.0.2", "10.0.0.2");

  /* IPv4-mapped IPv6 becomes IPv4, whatever its spelling */
  normalize ("::ffff:1.2.3.4", "1.2.3.4");
  normalize ("::FFFF:1.2.3.4", "1.2.3.4");
  normalize ("::ffff:0102:0304", "1.2.3.4");
  normalize ("0:0:0:0:0:ffff:1.2.3.4", "1.2.3.4");

  /* one IPv6 address, written in different ways */
  normalize ("2001:db8::1", "2001:db8::1");
  normalize ("2001:DB8:0:0:0:0:0:1", "2001:db8::1");
  normalize ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1");
  normalize ("::1", "::1");

  /* the scope of a link-local address is dropped */
  normalize ("fe80::1%eth0", "fe80::1");
  normalize ("fe80::1%25", "fe80::1");

  /* not an address: fails with "" */
  normalize (NULL, NULL);
  normalize ("", NULL);
  normalize ("abc", NULL);
  normalize ("1.2.3", NULL);
  normalize ("1.2.3.4.5", NULL);
  normalize ("1.2.3.4:8001", NULL);
  normalize ("1.2.3.4%eth0", NULL);	/* IPv4 has no scope */
  normalize ("2001:db8::1::2", NULL);
  normalize ("localhost", NULL);
  normalize ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa%x", NULL);

  /* the result does not fit: fails with "" */
  memset (small, 'x', sizeof (small));
  check (!ut_normalize_ip ("2001:db8::1", small, sizeof (small)) && small[0] == '\0',
	 "normalize into a buffer that is too small -> failure");
}

static void
test_compare (void)
{
  char login_norm[NORM_SIZE];
  char request_norm[NORM_SIZE];

  /* the same address in another form must not log a valid user out */
  compare ("127.0.0.1", "127.0.0.1", SESSION_IP_SAME);
  compare ("1.2.3.4", "::ffff:1.2.3.4", SESSION_IP_SAME);
  compare ("::ffff:1.2.3.4", "1.2.3.4", SESSION_IP_SAME);
  compare ("2001:db8::1", "2001:DB8:0:0:0:0:0:1", SESSION_IP_SAME);
  compare ("2001:db8::1", "2001:0db8:0000:0000:0000:0000:0000:0001", SESSION_IP_SAME);
  compare ("fe80::1", "fe80::1%eth0", SESSION_IP_SAME);

  /* another address must not pass */
  compare ("127.0.0.1", "127.0.0.2", SESSION_IP_DIFFERENT);
  compare ("10.0.0.1", "10.0.0.10", SESSION_IP_DIFFERENT);
  compare ("1.2.3.4", "::ffff:1.2.3.5", SESSION_IP_DIFFERENT);
  compare ("1.2.3.4", "::1.2.3.4", SESSION_IP_DIFFERENT);	/* IPv4-compatible is not IPv4-mapped */
  compare ("2001:db8::1", "2001:db8::2", SESSION_IP_DIFFERENT);
  compare ("fe80::1%eth0", "fe80::2%eth0", SESSION_IP_DIFFERENT);
  compare ("::1", "127.0.0.1", SESSION_IP_DIFFERENT);

  /* an address that cannot be read is unknown, never a mismatch */
  compare (NULL, "127.0.0.1", SESSION_IP_UNKNOWN);
  compare ("127.0.0.1", NULL, SESSION_IP_UNKNOWN);
  compare ("", "127.0.0.1", SESSION_IP_UNKNOWN);
  compare ("127.0.0.1", "abc", SESSION_IP_UNKNOWN);
  compare ("abc", "abc", SESSION_IP_UNKNOWN);

  /* the normalized addresses come back for the log */
  ut_session_ip_compare ("::ffff:10.0.0.1", "2001:DB8::1", login_norm, request_norm, NORM_SIZE);
  check (strcmp (login_norm, "10.0.0.1") == 0 && strcmp (request_norm, "2001:db8::1") == 0,
	 "compare returns both addresses normalized");
  ut_session_ip_compare ("abc", "10.0.0.2", login_norm, request_norm, NORM_SIZE);
  check (login_norm[0] == '\0' && strcmp (request_norm, "10.0.0.2") == 0,
	 "compare normalizes the request IP even when the login IP is unknown");
}

static void
test_action (void)
{
  /* off: never warns or rejects */
  action (SESSION_IP_CHECK_OFF, "off", SESSION_IP_SAME, SESSION_IP_ALLOW);
  action (SESSION_IP_CHECK_OFF, "off", SESSION_IP_DIFFERENT, SESSION_IP_ALLOW);
  action (SESSION_IP_CHECK_OFF, "off", SESSION_IP_UNKNOWN, SESSION_IP_ALLOW);

  /* log: warns, never rejects */
  action (SESSION_IP_CHECK_LOG, "log", SESSION_IP_SAME, SESSION_IP_ALLOW);
  action (SESSION_IP_CHECK_LOG, "log", SESSION_IP_DIFFERENT, SESSION_IP_ALLOW_WARN);
  action (SESSION_IP_CHECK_LOG, "log", SESSION_IP_UNKNOWN, SESSION_IP_ALLOW_WARN);

  /* enforce: rejects only another address */
  action (SESSION_IP_CHECK_ENFORCE, "enforce", SESSION_IP_SAME, SESSION_IP_ALLOW);
  action (SESSION_IP_CHECK_ENFORCE, "enforce", SESSION_IP_DIFFERENT, SESSION_IP_REJECT);
  action (SESSION_IP_CHECK_ENFORCE, "enforce", SESSION_IP_UNKNOWN, SESSION_IP_ALLOW_WARN);
}

static void
test_should_warn (void)
{
  std::deque<std::string> warned;
  char addr[32];
  int i;

  /* the first request from another address is logged, the next ones are not */
  check (ut_session_ip_should_warn (warned, "10.0.0.2"), "first warning for 10.0.0.2 is logged");
  check (!ut_session_ip_should_warn (warned, "10.0.0.2"), "10.0.0.2 again is not logged");

  /* a proxy pool sending from A, B, A, B, ... is logged once per address */
  check (ut_session_ip_should_warn (warned, "10.0.0.3"), "first warning for 10.0.0.3 is logged");
  check (!ut_session_ip_should_warn (warned, "10.0.0.2"), "10.0.0.2 after 10.0.0.3 is not logged");
  check (!ut_session_ip_should_warn (warned, "10.0.0.3"), "10.0.0.3 after 10.0.0.2 is not logged");
  check (!ut_session_ip_should_warn (warned, "10.0.0.2"), "10.0.0.2 a third time is not logged");

  /* an unknown address (NULL) is remembered as "-" */
  check (ut_session_ip_should_warn (warned, NULL), "first warning for an unknown address is logged");
  check (!ut_session_ip_should_warn (warned, NULL), "an unknown address again is not logged");

  /* at most SESSION_IP_WARNED_MAX addresses; the oldest is dropped */
  warned.clear ();
  for (i = 0; i < SESSION_IP_WARNED_MAX; i++)
    {
      snprintf (addr, sizeof (addr), "10.1.0.%d", i);
      ut_session_ip_should_warn (warned, addr);
    }
  check (warned.size () == SESSION_IP_WARNED_MAX, "8 addresses are remembered");
  check (!ut_session_ip_should_warn (warned, "10.1.0.0"), "the oldest of 8 is still remembered");
  check (ut_session_ip_should_warn (warned, "10.9.9.9"), "a 9th address is logged");
  check (warned.size () == SESSION_IP_WARNED_MAX, "the set does not grow beyond 8");
  check (ut_session_ip_should_warn (warned, "10.1.0.0"), "the oldest address, dropped for the 9th, is logged again");
  check (!ut_session_ip_should_warn (warned, "10.9.9.9"), "the 9th address is still remembered");

  /* sessions do not share what they have logged */
  std::deque<std::string> other;
  check (ut_session_ip_should_warn (other, "10.0.0.2"), "another session logs 10.0.0.2 again");
}

int
main (void)
{
  test_normalize ();
  test_compare ();
  test_action ();
  test_should_warn ();

  printf ("%d of %d checks failed\n", failures, checks);
  return (failures == 0) ? 0 : 1;
}
