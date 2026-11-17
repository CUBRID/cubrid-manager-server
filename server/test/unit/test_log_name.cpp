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
 * test_log_name.cpp - unit tests of server/src/cm_log_name.cpp, the rules
 *   getlogfileinfo, getloginfo and getdberrorlog use to tell the log files
 *   of one broker or database from those of another (CBRD-26446).
 *
 *   A broker or database name can hold '_', the separator after the name in
 *   its log file names, so "<name>_..." can be a log of <name> or of another
 *   instance. Every case below is a file name the engine gives a log file,
 *   checked for the instance that owns it (true) and for the instances whose
 *   name it starts with (false).
 *
 *   The API test (task_result_check) runs a SHARD=OFF broker only; the
 *   SHARD=ON names are covered here.
 *
 *   Build and run with run_unit_tests.sh in this directory; it needs no
 *   CUBRID build.
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "cm_log_name.h"

#define OFF false
#define ON true

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

/* ut_is_broker_log_file (): fname for broker bname with SHARD shard gives expect */
static void
broker (const char *fname, const char *bname, bool shard, bool expect)
{
  char what[256];
  bool got = ut_is_broker_log_file (fname, bname, shard);

  snprintf (what, sizeof (what), "broker \"%s\" SHARD=%s: \"%s\" -> %s (got %s)", bname, shard ? "ON" : "OFF",
	    fname, expect ? "listed" : "not listed", got ? "listed" : "not listed");
  check (got == expect, what);
}

/* ut_is_db_server_err_log (): fname for database dbname gives expect */
static void
db (const char *fname, const char *dbname, bool expect)
{
  char what[256];
  bool got = ut_is_db_server_err_log (fname, dbname);

  snprintf (what, sizeof (what), "db \"%s\": \"%s\" -> %s (got %s)", dbname, fname,
	    expect ? "listed" : "not listed", got ? "listed" : "not listed");
  check (got == expect, what);
}

static void
test_broker_own_logs (void)
{
  /* the logs of a SHARD=OFF broker */
  broker ("query_editor.access", "query_editor", OFF, true);
  broker ("query_editor.access.20261117103000", "query_editor", OFF, true);
  broker ("query_editor.err", "query_editor", OFF, true);
  broker ("query_editor.err.1261117.1030", "query_editor", OFF, true);
  broker ("query_editor_qr_rule.err", "query_editor", OFF, true);
  broker ("query_editor_1.err", "query_editor", OFF, true);
  broker ("query_editor_12.sql.log", "query_editor", OFF, true);
  broker ("query_editor_1.slow.log", "query_editor", OFF, true);
  broker ("query_editor_1.sql.log.bak", "query_editor", OFF, true);

  /* the logs of a SHARD=ON broker: proxy access logs and <proxy>_<shard>_<cas> */
  broker ("shard1_1.access", "shard1", ON, true);
  broker ("shard1_2.access.20261117103000", "shard1", ON, true);
  broker ("shard1_1_0_1.sql.log", "shard1", ON, true);
  broker ("shard1_1_0_1.slow.log", "shard1", ON, true);
  broker ("shard1_2_3_10.err", "shard1", ON, true);
  broker ("shard1.err", "shard1", ON, true);
  broker ("shard1.err.1261117.1030", "shard1", ON, true);
  broker ("shard1_qr_rule.err", "shard1", ON, true);
  /* written before SHARD was turned on, and named after the broker alone */
  broker ("shard1.access", "shard1", ON, true);
}

static void
test_broker_shard_parameter (void)
{
  /* the CAS logs of the other SHARD value are not this broker's */
  broker ("query_editor_1_0_1.sql.log", "query_editor", OFF, false);
  broker ("query_editor_1.access", "query_editor", OFF, false);
  broker ("shard1_1.sql.log", "shard1", ON, false);
  broker ("shard1_1.err", "shard1", ON, false);
  broker ("shard1_1_0.sql.log", "shard1", ON, false);
  broker ("shard1_1_0_1.access", "shard1", ON, false);
  broker ("shard1_1_0_1_2.sql.log", "shard1", ON, false);

  /*
   * The engine gives the CAS log of proxy 1, shard 0, CAS 1 of a SHARD broker
   * "b" and the CAS log of CAS 1 of a broker "b_1_0" the same name. Only the
   * SHARD parameter tells them apart.
   */
  broker ("b_1_0_1.sql.log", "b", ON, true);
  broker ("b_1_0_1.sql.log", "b", OFF, false);
  broker ("b_1_0_1.sql.log", "b_1_0", OFF, true);
}

static void
test_broker_other_instances (void)
{
  const bool both[] = { OFF, ON };
  size_t i;

  for (i = 0; i < sizeof (both) / sizeof (both[0]); i++)
    {
      bool s = both[i];

      /* another broker whose name starts with "broker1" */
      broker ("broker1_a.access", "broker1", s, false);
      broker ("broker1_a.err", "broker1", s, false);
      broker ("broker1_a_1.err", "broker1", s, false);
      broker ("broker1_a_1.sql.log", "broker1", s, false);
      broker ("broker1_a_qr_rule.err", "broker1", s, false);
      broker ("broker11.access", "broker1", s, false);
      broker ("broker11_1.err", "broker1", s, false);
      broker ("broker1-x_1.err", "broker1", s, false);
      broker ("xbroker1_1.err", "broker1", s, false);
      broker ("broker77__1.sql.log", "broker77", s, false);
      broker ("query_editor_1.sql.log", "query", s, false);
      broker ("query_editor.access", "query", s, false);

      /* not a log file name */
      broker ("broker1", "broker1", s, false);
      broker ("broker1.", "broker1", s, false);
      broker ("broker1_1", "broker1", s, false);
      broker ("broker1_1.", "broker1", s, false);
      broker ("broker1_.err", "broker1", s, false);
      broker ("broker1.accessx", "broker1", s, false);
      broker ("broker1.access.x", "broker1", s, false);
      broker ("broker1.errx", "broker1", s, false);
      broker ("broker1.err.1261117", "broker1", s, false);
      broker ("broker1.err.x.1030", "broker1", s, false);
      broker ("broker1.err.bak", "broker1", s, false);
      broker ("broker1_qr_rule.err.bak", "broker1", s, false);
      broker ("broker1.sql.log", "broker1", s, false);
      broker ("broker1", "", s, false);
      broker (NULL, "broker1", s, false);
      broker ("broker1.access", NULL, s, false);
    }

  /* a name that ends with '_' is a name like any other */
  broker ("broker77__1.sql.log", "broker77_", OFF, true);
  broker ("broker77_.access", "broker77_", OFF, true);
  broker ("broker1_a_1.sql.log", "broker1_a", OFF, true);
}

static void
test_db_server_err_log (void)
{
  db ("demodb_20261117_1030.err", "demodb", true);
  db ("demodb_latest.err", "demodb", true);
  db ("db26446_a_20261116_1110.err", "db26446_a", true);
  db ("db26446_a_latest.err", "db26446_a", true);

  /* another database whose name starts with the requested one */
  db ("db26446_a_20261116_1110.err", "db26446", false);
  db ("db26446_a_latest.err", "db26446", false);
  db ("demodbx_20261117_1030.err", "demodb", false);
  db ("demodb2_latest.err", "demodb", false);
  db ("xdemodb_20261117_1030.err", "demodb", false);
  /* a database named after a date stamp is still told apart */
  db ("demodb_20261116_20261117_1030.err", "demodb", false);
  db ("demodb_20261116_20261117_1030.err", "demodb_20261116", true);

  /* not a server error log name */
  db ("demodb.err", "demodb", false);
  db ("demodb_2026111_1030.err", "demodb", false);
  db ("demodb_20261117_103.err", "demodb", false);
  db ("demodb_20261117-1030.err", "demodb", false);
  db ("demodb_20261117_1030.err.bak", "demodb", false);
  db ("demodb_20261117_1030", "demodb", false);
  db ("demodb_latest.err.bak", "demodb", false);
  db ("demodb_20261117_1030.err", "", false);
  db (NULL, "demodb", false);
  db ("demodb_latest.err", NULL, false);
}

static void
test_regular_file_mode (void)
{
  check (ut_is_regular_file_mode (S_IFREG | 0644), "a regular file is a log file");
  check (!ut_is_regular_file_mode (S_IFDIR | 0755), "a directory is not a log file");
}

int
main (void)
{
  test_broker_own_logs ();
  test_broker_shard_parameter ();
  test_broker_other_instances ();
  test_db_server_err_log ();
  test_regular_file_mode ();

  printf ("%d of %d checks failed\n", failures, checks);
  return (failures == 0) ? 0 : 1;
}
