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

#include <sstream>
#include <string>

#if !defined(WINDOWS)
#include <stdlib.h>
#include <unistd.h>
#endif

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
  /* the connections the ACL rejects, and its backup */
  broker ("query_editor.access.denied", "query_editor", OFF, true);
  broker ("query_editor.access.denied.20261117103000", "query_editor", OFF, true);
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
  broker ("shard1_qr_rule.err", "shard1", ON, true);
  /* written before SHARD was turned on, and named after the broker alone */
  broker ("shard1.access", "shard1", ON, true);
  broker ("shard1.access.denied", "shard1", ON, true);
}

/*
 * "<b>.err" is not a log of b: the engine writes nothing to the broker error
 * log path, and the name is the CAS error log of another broker.
 */
static void
test_broker_err (void)
{
  const bool both[] = { OFF, ON };
  size_t i;

  for (i = 0; i < sizeof (both) / sizeof (both[0]); i++)
    {
      bool s = both[i];

      /* the CAS 1 error log of the broker query_editor */
      broker ("query_editor_1.err", "query_editor_1", s, false);
      broker ("query_editor.err", "query_editor", s, false);
      broker ("query_editor.err.1261117.1030", "query_editor", s, false);
      broker ("shard1.err", "shard1", s, false);
    }
  broker ("query_editor_1.err", "query_editor", OFF, true);
}

static void
test_broker_shard_parameter (void)
{
  /* the CAS logs of the other SHARD value are not this broker's */
  broker ("query_editor_1_0_1.sql.log", "query_editor", OFF, false);
  broker ("query_editor_1.access", "query_editor", OFF, false);
  broker ("query_editor_1.access.denied", "query_editor", OFF, false);
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
      broker ("broker1_a.access.denied", "broker1", s, false);
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
      broker ("broker1.access.deniedx", "broker1", s, false);
      broker ("broker1.access.denied.", "broker1", s, false);
      broker ("broker1.access.denied.x", "broker1", s, false);
      broker ("broker1.access.denied.denied", "broker1", s, false);
      broker ("broker1.access.20261117103000.denied", "broker1", s, false);
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

/* ut_get_db_err_log_param (): error_log of dbname in cubrid.conf text conf gives expect ("": not set) */
static void
err_log_param (const char *conf, const char *dbname, const std::string &expect)
{
  char what[512];
  std::istringstream in (conf);
  std::string value;
  bool got = ut_get_db_err_log_param (in, dbname, value);

  snprintf (what, sizeof (what), "error_log of \"%s\" -> \"%s\" (got \"%s\")\n%s", dbname, expect.c_str (),
	    got ? value.c_str () : "", conf);
  check (expect.empty () ? !got : (got && value == expect), what);
}

/* ut_resolve_err_log_param (): param under $CUBRID/log gives expect ("": not resolvable) */
static void
err_log_path (const char *param, const std::string &expect)
{
  char what[512];
  std::string path;
  bool got = ut_resolve_err_log_param (param, "/home/cubrid/CUBRID/log", path);

  snprintf (what, sizeof (what), "error_log \"%s\" -> \"%s\" (got \"%s\")", param, expect.c_str (),
	    got ? path.c_str () : "");
  check (expect.empty () ? !got : (got && path == expect), what);
}

static void
test_db_err_log_param (void)
{
  /* [@<db>] over [common], whatever the order; other sections do not apply */
  err_log_param ("[common]\nerror_log=server/common.err\n[@demodb]\nerror_log=server/demodb.err\n",
		 "demodb", "server/demodb.err");
  err_log_param ("[@demodb]\nerror_log=server/demodb.err\n[common]\nerror_log=server/common.err\n",
		 "demodb", "server/demodb.err");
  err_log_param ("[common]\nerror_log=server/common.err\n[@demodb]\nerror_log=server/demodb.err\n",
		 "testdb", "server/common.err");
  err_log_param ("[@otherdb]\nerror_log=server/otherdb.err\n[common]\ndata_buffer_size=512M\n", "demodb", "");
  err_log_param ("[service]\nerror_log=server/service.err\n", "demodb", "");
  err_log_param ("[standalone]\nerror_log=server/sa.err\n", "demodb", "");
  /* [@demodb_a] is another database, and "@<db>" is case-sensitive as in the engine */
  err_log_param ("[@demodb_a]\nerror_log=server/demodb_a.err\n", "demodb", "");
  err_log_param ("[@DemoDB]\nerror_log=server/DemoDB.err\n", "demodb", "");
  err_log_param ("[ @demodb ]\nerror_log=server/demodb.err\n", "demodb", "server/demodb.err");
  err_log_param ("[COMMON]\nERROR_LOG=server/common.err\n", "demodb", "server/common.err");
  /* before any section, as [common] */
  err_log_param ("error_log=server/top.err\n", "demodb", "server/top.err");
  /*
   * no section is applied again with [@<db>] (prm_read_and_parse_ini_file ()):
   * it wins over [common] whatever their order, and over [@<db>] only when
   * it first appears after it
   */
  err_log_param ("error_log=server/top.err\n[common]\nerror_log=server/common.err\n", "demodb", "server/top.err");
  err_log_param ("[common]\nerror_log=server/common.err\n[ ]\nerror_log=server/none.err\n", "demodb",
		 "server/none.err");
  err_log_param ("error_log=server/top.err\n[@demodb]\nerror_log=server/demodb.err\n", "demodb",
		 "server/demodb.err");
  err_log_param ("[@demodb]\nerror_log=server/demodb.err\n[ ]\nerror_log=server/none.err\n", "demodb",
		 "server/none.err");
  /* the value of a later line, but the order of the first one */
  err_log_param ("error_log=server/top.err\n[@demodb]\nerror_log=server/demodb.err\n[ ]\nerror_log=server/last.err\n",
		 "demodb", "server/demodb.err");
  /* a last line that goes on into nothing is not read (ini_parser_load ()) */
  err_log_param ("[@demodb]\nerror_log=server/demodb.err\nerror_log=server/\\", "demodb", "server/demodb.err");
  /* "[]" names no section: the section goes on (ini_parse_line ()) */
  err_log_param ("[@demodb]\n[]\nerror_log=server/demodb.err\n", "demodb", "server/demodb.err");
  err_log_param ("[@otherdb]\n[]\nerror_log=server/otherdb.err\n", "demodb", "");
  err_log_param ("[common]\nerror_log=server/common.err\n[@demodb]\n[]\nerror_log=server/demodb.err\n", "demodb",
		 "server/demodb.err");
  /* the last one wins */
  err_log_param ("[@demodb]\nerror_log=server/first.err\nerror_log=server/last.err\n", "demodb",
		 "server/last.err");
  err_log_param ("[@demodb]\nerror_log=server/a.err\n[common]\n[@demodb]\nerror_log=server/b.err\n", "demodb",
		 "server/b.err");
  /* the value: spaces, quotes, comments, a line that goes on */
  err_log_param ("[@demodb]\n  error_log = server/demodb.err  \n", "demodb", "server/demodb.err");
  err_log_param ("[@demodb]\nerror_log=\"server/demo db.err\"\n", "demodb", "server/demo db.err");
  err_log_param ("[@demodb]\nerror_log='server/demodb.err' # memo\n", "demodb", "server/demodb.err");
  err_log_param ("[@demodb]\nerror_log=server/demodb.err # memo\n", "demodb", "server/demodb.err");
  err_log_param ("[@demodb]\nerror_log=server/demodb.err;memo\n", "demodb", "server/demodb.err");
  err_log_param ("[@demodb]\nerror_log=server/\\\ndemodb.err\n", "demodb", "server/demodb.err");
  err_log_param ("[@demodb]\r\nerror_log=server/demodb.err\r\n", "demodb", "server/demodb.err");
  /* not set */
  err_log_param ("[@demodb]\n#error_log=server/commented.err\n", "demodb", "");
  err_log_param ("[@demodb]\nerror_log=\n", "demodb", "");
  err_log_param ("[@demodb]\nerror_log=\"\"\n", "demodb", "");
  err_log_param ("[@demodb]\nerror_log_size=1000\n", "demodb", "");
  /* an empty [@<db>] value still wins over [common], as in the engine */
  err_log_param ("[common]\nerror_log=server/common.err\n[@demodb]\nerror_log=\n", "demodb", "");
  err_log_param ("", "demodb", "");
  err_log_param ("error_log=server/top.err\n", "", "");

  /* resolved as er_init () of the engine: relative to $CUBRID/log */
  err_log_path ("server/demodb.err", "/home/cubrid/CUBRID/log/server/demodb.err");
  err_log_path ("demodb.err", "/home/cubrid/CUBRID/log/demodb.err");
  err_log_path ("/var/log/cubrid/demodb.err", "/var/log/cubrid/demodb.err");
  err_log_path ("./demodb.err", "");
  err_log_path ("", "");

  check (ut_is_same_path ("/home/cubrid/CUBRID/log/server/demodb.err", "/home/cubrid/CUBRID/log/server/demodb.err"),
	 "the same path");
  check (!ut_is_same_path ("/home/cubrid/CUBRID/log/server/demodb.err", "/home/cubrid/CUBRID/log/server/demodb.er"),
	 "another path");
}

/* ut_lexical_path (): path gives expect */
static void
lexical (const char *path, const char *expect)
{
  char what[512];
  const std::string got = ut_lexical_path (path);

  snprintf (what, sizeof (what), "lexical \"%s\" -> \"%s\" (got \"%s\")", path, expect, got.c_str ());
  check (got == expect, what);
}

/* ut_windows_path_key (): whether path1 and path2 are the same file on Windows */
static void
windows_same (const char *path1, const char *path2, bool expect)
{
  char what[512];
  const bool got = ut_windows_path_key (path1) == ut_windows_path_key (path2);

  snprintf (what, sizeof (what), "Windows \"%s\" and \"%s\" -> %s (got %s)", path1, path2,
	    expect ? "the same" : "not the same", got ? "the same" : "not the same");
  check (got == expect, what);
}

/*
 * The paths ut_is_same_path () compares on Windows, checked here on any
 * platform through ut_windows_path_key ().
 */
static void
test_path_spelling (void)
{
  lexical ("/a/./b", "/a/b");
  lexical ("/a//b/", "/a/b");
  lexical ("/a/b/../c", "/a/c");
  lexical ("/a/b/c/../../d", "/a/d");
  lexical ("/../a", "/a");
  lexical ("a/../../b", "../b");
  lexical ("../a", "../a");
  lexical ("C:/x/../y", "C:/y");
  lexical ("C:/..", "C:");
  lexical ("C:/./x//y", "C:/x/y");
  lexical ("//srv/share/./x", "//srv/share/x");
  lexical ("///a", "/a");
  lexical (".", "");
  lexical ("", "");

  /* error_log=server/./demodb.err against the file found in $CUBRID/log/server (review of #168) */
  windows_same ("C:/CUBRID/log/server/./demodb.err", "C:/CUBRID/log/server/demodb.err", true);
  windows_same ("C:\\CUBRID\\log\\server\\demodb.err", "c:/cubrid/log/server/./DemoDB.err", true);
  windows_same ("C:/CUBRID//log/server/demodb.err", "C:/CUBRID/log/server/demodb.err", true);
  windows_same ("C:/CUBRID/log/server/../server/demodb.err", "C:/CUBRID/log/server/demodb.err", true);
  windows_same ("C:/CUBRID/log/demodb.err", "C:/CUBRID/log/server/demodb.err", false);
  windows_same ("C:/CUBRID/log/server/demodb_latest.err", "C:/CUBRID/log/server/demodb.err", false);
}

/*
 * ut_file_entry: the same directory entry however it is spelled, and not the
 * <db>_latest.err link to it. Needs a file system: a temporary directory with
 * log/server/demodb.err, the link demodb_latest.err to it, a hard link to it
 * under another name, and a link CUBRID_link to the directory, as a $CUBRID
 * that is a symbolic link.
 */
static void
test_file_entry (void)
{
#if !defined(WINDOWS)
  char tmpl[] = "/tmp/test_log_name.XXXXXX";
  const char *root = mkdtemp (tmpl);

  if (root == NULL)
    {
      check (false, "mkdtemp () for ut_file_entry");
      return;
    }

  const std::string dir = std::string (root) + "/CUBRID";
  const std::string link_dir = std::string (root) + "/CUBRID_link";
  const std::string server = dir + "/log/server";
  const std::string err = server + "/demodb.err";
  const std::string latest = server + "/demodb_latest.err";
  const std::string hard = server + "/demodb_hard.err";
  const std::string other = server + "/demodb_20261117_1030.err";
  bool made = mkdir (dir.c_str (), 0700) == 0 && mkdir ((dir + "/log").c_str (), 0700) == 0
	      && mkdir (server.c_str (), 0700) == 0;
  FILE *fp;

  if (made && (fp = fopen (err.c_str (), "w")) != NULL)
    {
      fclose (fp);
    }
  if (made && (fp = fopen (other.c_str (), "w")) != NULL)
    {
      fclose (fp);
    }
  made = made && symlink (err.c_str (), latest.c_str ()) == 0 && link (err.c_str (), hard.c_str ()) == 0
	 && symlink (dir.c_str (), link_dir.c_str ()) == 0;
  check (made, "a log directory for ut_file_entry");

  if (made)
    {
      const ut_file_entry entry (err);
      /* the configured path spelled another way */
      const ut_file_entry linked (link_dir + "/log/server/demodb.err");

      check (entry.is (err), "the same file");
      check (entry.is (dir + "//log/server/demodb.err"), "the same file, \"//\" in the path");
      check (entry.is (dir + "/log/server/../server/demodb.err"), "the same file, \"..\" in the path");
      check (entry.is (dir + "/log/server/./demodb.err"), "the same file, \".\" in the path");
      check (ut_file_entry (dir + "/log/server/./demodb.err").is (err), "the same file, error_log=server/./demodb.err");
      check (entry.is (link_dir + "/log/server/demodb.err"), "the same file, $CUBRID a symbolic link");
      check (linked.is (err), "the same file, the configured path through the link");
      check (!entry.is (latest), "not the <db>_latest.err link to the file");
      check (!entry.is (other), "another file");
      check (!entry.is (hard), "a hard link under another name is not looked for");

      /* an entry of a directory listing: the name first, then the file */
      check (entry.is (server, "demodb.err"), "the entry demodb.err of the directory");
      check (entry.is (dir + "//log/server", "demodb.err"), "the entry demodb.err, \"//\" in the directory");
      check (entry.is (link_dir + "/log/server", "demodb.err"), "the entry demodb.err, $CUBRID a symbolic link");
      check (!entry.is (server, "demodb_latest.err"), "not the entry <db>_latest.err, the link to the file");
      check (!entry.is (server, "demodb_20261117_1030.err"), "not another entry");
      check (!entry.is (server, "DEMODB.ERR"), "not an entry whose name differs in case");
      check (!entry.is (server, NULL), "no entry");
      /* the same name in another directory is another file */
      check (!entry.is (std::string (root), "demodb.err"), "not demodb.err of another directory");

      /* a file that is not there: the paths are compared */
      const ut_file_entry gone (server + "/gone.err");
      check (gone.is (server + "/gone.err"), "a missing file, the same path");
      check (!gone.is (dir + "//log/server/gone.err"), "a missing file, the path spelled another way");
      check (!gone.is (err), "a missing file, another file");
      check (!ut_file_entry ("").is (err), "no file");
    }

  unlink (latest.c_str ());
  unlink (hard.c_str ());
  unlink (err.c_str ());
  unlink (other.c_str ());
  rmdir (server.c_str ());
  rmdir ((dir + "/log").c_str ());
  rmdir (dir.c_str ());
  unlink (link_dir.c_str ());
  rmdir (root);
#endif
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
  test_broker_err ();
  test_broker_shard_parameter ();
  test_broker_other_instances ();
  test_db_server_err_log ();
  test_db_err_log_param ();
  test_path_spelling ();
  test_file_entry ();
  test_regular_file_mode ();

  printf ("%d of %d checks failed\n", failures, checks);
  return (failures == 0) ? 0 : 1;
}
