/*
 *
 * Copyright 2016 CUBRID Corporation
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */


/*
 * test_script_path.cpp - unit tests of server/src/cm_task_file.cpp, which
 *   script runscript may run.
 *
 *   Only a file directly under the script directory ($CUBRID/conf), judged
 *   by real paths; a regular, executable file that only the user CMS runs as
 *   and root can change, in a directory only they can change. Every refusal
 *   gives its own reason.
 *
 *   The owner checks need a file of another user, which only root can make;
 *   here the user CMS runs as is passed as another uid instead. Run as root,
 *   those checks are skipped, as every file then belongs to root.
 *
 *   Build and run with run_unit_tests.sh in this directory; it needs no
 *   CUBRID build.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <string>

#include "cm_task_file.h"

static int failures = 0;
static int checks = 0;
static char work_dir[] = "/tmp/test_script_path.XXXXXX";
static std::string conf_dir;
static unsigned int me;

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

static std::string
work_path (const std::string &rel)
{
  return std::string (work_dir) + "/" + rel;
}

static void
make_script (const std::string &rel, mode_t mode)
{
  std::string path = work_path (rel);
  FILE *fp = fopen (path.c_str (), "w");

  if (fp == NULL)
    {
      perror (path.c_str ());
      exit (2);
    }
  fputs ("#!/bin/sh\necho test\n", fp);
  fclose (fp);
  chmod (path.c_str (), mode);
}

static void
make_dir (const std::string &rel, mode_t mode)
{
  std::string path = work_path (rel);

  if (mkdir (path.c_str (), 0700) != 0)
    {
      perror (path.c_str ());
      exit (2);
    }
  chmod (path.c_str (), mode);
}

static void
make_link (const std::string &target, const std::string &rel)
{
  if (symlink (target.c_str (), work_path (rel).c_str ()) != 0)
    {
      perror ("symlink");
      exit (2);
    }
}

/* `path` (absolute) against `dir` (absolute) for the user `uid` */
static void
expect_in (const std::string &path, const std::string &dir, unsigned int uid, const char *reason)
{
  char err[1024] = "";
  char what[2048];
  std::string real;
  bool ok = ut_check_script_path (path.c_str (), dir.c_str (), uid, real, err, sizeof (err));

  if (reason == NULL)
    {
      snprintf (what, sizeof (what), "%s is allowed (got \"%s\")", path.c_str (), err);
      check (ok, what);
      snprintf (what, sizeof (what), "%s: the real path is given (got \"%s\")", path.c_str (), real.c_str ());
      check (ok && !real.empty () && real[0] == '/', what);
    }
  else
    {
      snprintf (what, sizeof (what), "%s is refused: \"%s\" (got \"%s\")", path.c_str (), reason, err);
      check (!ok && strstr (err, reason) != NULL, what);
      snprintf (what, sizeof (what), "%s: no real path on refusal", path.c_str ());
      check (real.empty (), what);
    }
}

/* `rel` under work_dir against conf_dir for the current user */
static void
expect (const std::string &rel, const char *reason)
{
  expect_in (work_path (rel), conf_dir, me, reason);
}

static void
test_allowed (void)
{
  char what[512];
  char err[1024] = "";
  std::string real;

  make_script ("conf/ok_0700.sh", 0700);
  make_script ("conf/ok_0755.sh", 0755);
  make_script ("conf/ok_0744.sh", 0744);
  expect ("conf/ok_0700.sh", NULL);
  expect ("conf/ok_0755.sh", NULL);
  expect ("conf/ok_0744.sh", NULL);

  /* other spellings of the same file */
  expect ("conf/../conf/ok_0700.sh", NULL);
  expect ("conf/./ok_0700.sh", NULL);

  /* a link in conf to a file in conf is that file, and that file is run */
  make_link (work_path ("conf/ok_0755.sh"), "conf/link_in.sh");
  expect ("conf/link_in.sh", NULL);
  ut_check_script_path (work_path ("conf/link_in.sh").c_str (), conf_dir.c_str (), me, real, err, sizeof (err));
  snprintf (what, sizeof (what), "a link in conf runs its target (got \"%s\")", real.c_str ());
  check (real == work_path ("conf/ok_0755.sh") || real.find ("/conf/ok_0755.sh") != std::string::npos, what);
}

static void
test_place (void)
{
  const char *outside = "only a script directly under";

  make_dir ("conf/sub", 0755);
  make_script ("conf/sub/sub.sh", 0700);
  make_script ("outside.sh", 0700);
  make_dir ("databases", 0755);
  make_script ("databases/db.sh", 0700);

  expect ("conf/sub/sub.sh", outside);
  expect ("outside.sh", outside);
  expect ("databases/db.sh", outside);
  expect ("conf/../outside.sh", outside);

  /* a link in conf to a file outside it */
  make_link (work_path ("outside.sh"), "conf/link_out.sh");
  expect ("conf/link_out.sh", outside);
  /* a link in conf to a file in a subdirectory */
  make_link (work_path ("conf/sub/sub.sh"), "conf/link_sub.sh");
  expect ("conf/link_sub.sh", outside);

  expect ("conf/no_such.sh", "the script does not exist");
  expect_in (work_path ("conf/ok_0700.sh"), work_path ("no_such_dir"), me, "the script directory does not exist");
}

static void
test_file (void)
{
  expect ("conf/sub", "the script is not a regular file");

  make_script ("conf/group_w.sh", 0775);
  expect ("conf/group_w.sh", "the script must not be writable by the group or others");
  make_script ("conf/others_w.sh", 0757);
  expect ("conf/others_w.sh", "the script must not be writable by the group or others");
  make_script ("conf/group_w_only.sh", 0720);
  expect ("conf/group_w_only.sh", "the script must not be writable by the group or others");

  /* what writeandsaveconf creates: no execute bit */
  make_script ("conf/no_exec.sh", 0644);
  expect ("conf/no_exec.sh", "the script is not executable");

  if (me != 0)
    {
      /* the files belong to `me`; CMS runs as someone else, who is not root */
      expect_in (work_path ("conf/ok_0700.sh"), conf_dir, me + 1,
		 "the script must be owned by the user CMS runs as or by root");
    }
  else
    {
      printf ("skipped: the owner of the script (running as root)\n");
    }
}

static void
test_dir (void)
{
  std::string dir;

  make_dir ("conf_group_w", 0775);
  make_script ("conf_group_w/a.sh", 0700);
  dir = work_path ("conf_group_w");
  expect_in (dir + "/a.sh", dir, me, "the script directory must not be writable by the group or others");

  make_dir ("conf_others_w", 0757);
  make_script ("conf_others_w/a.sh", 0700);
  dir = work_path ("conf_others_w");
  expect_in (dir + "/a.sh", dir, me, "the script directory must not be writable by the group or others");

  /* a link as the script directory is judged by what it points to */
  make_link (conf_dir, "conf_link");
  expect_in (work_path ("conf/ok_0700.sh"), work_path ("conf_link"), me, NULL);
  expect_in (work_path ("conf_link/ok_0700.sh"), conf_dir, me, NULL);

  if (me != 0)
    {
      /* a file of root in a directory of another user: refused for the directory */
      make_dir ("conf_other_owner", 0755);
      make_script ("conf_other_owner/a.sh", 0700);
      dir = work_path ("conf_other_owner");
      expect_in (dir + "/a.sh", dir, me + 1, "must be owned by the user CMS runs as or by root");
    }
}

static void
test_reason_format (void)
{
  char err[1024] = "";
  std::string real;
  std::string path = work_path ("conf/no%such.sh");

  ut_check_script_path (path.c_str (), conf_dir.c_str (), me, real, err, sizeof (err));
  check (strchr (err, '%') == NULL, "'%' in the path is not shown in the reason");
  check (!ut_check_script_path (NULL, conf_dir.c_str (), me, real, err, sizeof (err)), "NULL is refused");
}

int
main (void)
{
  if (mkdtemp (work_dir) == NULL)
    {
      perror ("mkdtemp");
      return 2;
    }
  umask (022);
  me = (unsigned int) geteuid ();
  make_dir ("conf", 0755);
  conf_dir = work_path ("conf");

  test_allowed ();
  test_place ();
  test_file ();
  test_dir ();
  test_reason_format ();

  if (failures == 0)
    {
      std::string cmd = std::string ("rm -rf ") + work_dir;
      if (system (cmd.c_str ()) != 0)
	{
	  printf ("warning: %s was not removed\n", work_dir);
	}
    }
  else
    {
      printf ("files left in %s\n", work_dir);
    }

  printf ("%d of %d checks failed\n", failures, checks);
  return (failures == 0) ? 0 : 1;
}
