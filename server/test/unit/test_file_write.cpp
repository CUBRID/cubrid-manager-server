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
 * test_file_write.cpp - unit tests of server/src/cm_task_file.cpp, how
 *   writeandsaveconf, setsysparam and writeprivatedata open the file they
 *   rewrite, and how writeandsaveconf writes its backup (CBRD-27831).
 *
 *   An executable file is refused and left as it was, whichever execute bit
 *   it has, also through a symbolic link; a file that is not executable is
 *   rewritten and keeps its mode; a new file is never created executable,
 *   even with umask 0, which the API test cannot set for a running CMS.
 *   The backup is written under the same rules: never into an executable
 *   file, and a new backup gets the mode of the original without its
 *   execute bits.
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

#define FIXTURE_TEXT "#!/bin/sh\necho fixture\n"
#define NEW_TEXT "new contents\n"

static int failures = 0;
static int checks = 0;
static char work_dir[] = "/tmp/test_file_write.XXXXXX";

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
work_path (const char *name)
{
  return std::string (work_dir) + "/" + name;
}

static void
make_file (const char *name, mode_t mode)
{
  std::string path = work_path (name);
  FILE *fp = fopen (path.c_str (), "w");

  if (fp == NULL)
    {
      perror (path.c_str ());
      exit (2);
    }
  fputs (FIXTURE_TEXT, fp);
  fclose (fp);
  chmod (path.c_str (), mode);
}

static std::string
file_text (const std::string &path)
{
  std::string text;
  char buf[256];
  FILE *fp = fopen (path.c_str (), "r");

  if (fp == NULL)
    {
      return "(cannot read)";
    }
  while (fgets (buf, sizeof (buf), fp) != NULL)
    {
      text += buf;
    }
  fclose (fp);
  return text;
}

static mode_t
file_mode (const std::string &path)
{
  struct stat st;

  if (stat (path.c_str (), &st) != 0)
    {
      return (mode_t) -1;
    }
  return st.st_mode & 07777;
}

/* ut_open_for_content_write () on `name`, writing NEW_TEXT when it opens */
static T_CONTENT_WRITE_RESULT
write_new_text (const char *name, char *err_buf, size_t err_size)
{
  std::string path = work_path (name);
  FILE *fp;
  T_CONTENT_WRITE_RESULT result;

  result = ut_open_for_content_write (path.c_str (), &fp, err_buf, err_size);
  if (result == CONTENT_WRITE_OK)
    {
      fputs (NEW_TEXT, fp);
      fclose (fp);
    }
  else
    {
      check (fp == NULL, "no FILE is returned when the file is not opened");
    }
  return result;
}

/* an executable file `name` (mode `mode`, possibly through a link) is refused and left as it was */
static void
refused (const char *name, const char *target, mode_t mode)
{
  char err[512] = "";
  char what[1024];
  std::string target_path = work_path (target);
  std::string expect_err = "writing to an executable file is not allowed: " + work_path (name);
  T_CONTENT_WRITE_RESULT result = write_new_text (name, err, sizeof (err));

  snprintf (what, sizeof (what), "%s (%04o) is refused", name, (unsigned int) mode);
  check (result == CONTENT_WRITE_EXECUTABLE, what);
  snprintf (what, sizeof (what), "%s: the reason is given (got \"%s\")", name, err);
  check (expect_err == err, what);
  snprintf (what, sizeof (what), "%s: the contents are not changed", name);
  check (file_text (target_path) == FIXTURE_TEXT, what);
  snprintf (what, sizeof (what), "%s: the mode is not changed", name);
  check (file_mode (target_path) == mode, what);
}

static void
test_executable_mode (void)
{
  check (!ut_is_executable_mode (S_IFREG | 0644), "0644 is not executable");
  check (!ut_is_executable_mode (S_IFREG | 0666), "0666 is not executable");
  check (ut_is_executable_mode (S_IFREG | 0755), "0755 is executable");
  check (ut_is_executable_mode (S_IFREG | 0700), "0700 is executable");
  check (ut_is_executable_mode (S_IFREG | 0744), "0744 (owner only) is executable");
  check (ut_is_executable_mode (S_IFREG | 0654), "0654 (group only) is executable");
  check (ut_is_executable_mode (S_IFREG | 0645), "0645 (others only) is executable");
}

static void
test_executable_extension (void)
{
  check (ut_has_executable_extension ("C:\\CUBRID\\conf\\a.bat"), "a.bat");
  check (ut_has_executable_extension ("C:\\CUBRID\\conf\\a.CMD"), "a.CMD, any case");
  check (ut_has_executable_extension ("C:/CUBRID/conf/a.ps1"), "a.ps1");
  check (ut_has_executable_extension ("C:\\CUBRID\\a.exe"), "a.exe");
  check (ut_has_executable_extension ("C:\\CUBRID\\conf\\a.bat."), "a.bat. opens a.bat");
  check (ut_has_executable_extension ("C:\\CUBRID\\conf\\a.bat . ."), "a.bat . . opens a.bat");
  check (ut_has_executable_extension ("\\\\?\\C:\\CUBRID\\conf\\ABCDEF~1.BAT"), "a final path");
  check (!ut_has_executable_extension ("C:\\CUBRID\\conf\\cubrid.conf"), "cubrid.conf");
  check (!ut_has_executable_extension ("C:\\CUBRID\\conf\\a.bat.txt"), "a.bat.txt");
  check (!ut_has_executable_extension ("C:\\CUBRID\\conf\\a.batx"), "a.batx");
  check (!ut_has_executable_extension ("C:\\CUBRID\\x.bat\\a"), "an executable directory name only");
  check (!ut_has_executable_extension ("C:\\CUBRID\\conf\\bat"), "no extension");
  check (!ut_has_executable_extension ("C:\\CUBRID\\conf\\..."), "dots only");
  check (!ut_has_executable_extension (NULL), "NULL");
}

static void
test_refused (void)
{
  make_file ("exec_0755.sh", 0755);
  refused ("exec_0755.sh", "exec_0755.sh", 0755);
  make_file ("exec_0700.sh", 0700);
  refused ("exec_0700.sh", "exec_0700.sh", 0700);
  make_file ("exec_0744.sh", 0744);
  refused ("exec_0744.sh", "exec_0744.sh", 0744);
  make_file ("exec_0654.sh", 0654);
  refused ("exec_0654.sh", "exec_0654.sh", 0654);
  make_file ("exec_0645.sh", 0645);
  refused ("exec_0645.sh", "exec_0645.sh", 0645);

  /* a link is judged by its target, which is left as it was */
  make_file ("link_target.sh", 0755);
  if (symlink (work_path ("link_target.sh").c_str (), work_path ("link.conf").c_str ()) != 0)
    {
      perror ("symlink");
      exit (2);
    }
  refused ("link.conf", "link_target.sh", 0755);
}

static void
test_written (void)
{
  char err[512] = "";
  std::string path;

  /* not executable: rewritten, the mode stays */
  make_file ("plain_0640.conf", 0640);
  path = work_path ("plain_0640.conf");
  check (write_new_text ("plain_0640.conf", err, sizeof (err)) == CONTENT_WRITE_OK, "0640 is written");
  check (file_text (path) == NEW_TEXT, "0640: the contents are replaced, not appended");
  check (file_mode (path) == 0640, "0640: the mode is not changed");
  check (err[0] == '\0', "0640: no reason is set");

  /* a link to a file that is not executable writes the target */
  make_file ("plain_target.conf", 0644);
  if (symlink (work_path ("plain_target.conf").c_str (), work_path ("plain_link.conf").c_str ()) != 0)
    {
      perror ("symlink");
      exit (2);
    }
  check (write_new_text ("plain_link.conf", err, sizeof (err)) == CONTENT_WRITE_OK, "a link to 0644 is written");
  check (file_text (work_path ("plain_target.conf")) == NEW_TEXT, "a link to 0644: the target is written");

  /* new file: never executable, even with umask 0 */
  umask (0);
  path = work_path ("new.conf");
  check (write_new_text ("new.conf", err, sizeof (err)) == CONTENT_WRITE_OK, "a new file is created");
  check (file_text (path) == NEW_TEXT, "a new file: the contents are written");
  check (file_mode (path) == 0644, "a new file is created 0644 with umask 0");
  umask (022);

  /* cannot be opened: no reason, so the caller keeps its own message */
  check (write_new_text ("no_such_dir/a.conf", err, sizeof (err)) == CONTENT_WRITE_OPEN_FAIL,
	 "a path under a missing directory is not opened");
  check (err[0] == '\0', "an open failure sets no reason");
}

static void
test_executable_file (void)
{
  char err[512] = "";
  std::string expect_err = "writing to an executable file is not allowed: " + work_path ("exec_0755.sh");

  /* the files test_refused () laid */
  check (ut_is_executable_file (work_path ("exec_0755.sh").c_str (), err, sizeof (err)), "0755 is an executable file");
  check (expect_err == err, "an executable file: the reason is given");
  check (ut_is_executable_file (work_path ("exec_0645.sh").c_str (), NULL, 0), "0645 is an executable file");
  check (ut_is_executable_file (work_path ("link.conf").c_str (), NULL, 0), "a link to 0755 is an executable file");

  err[0] = '\0';
  make_file ("plain_check.conf", 0640);
  check (!ut_is_executable_file (work_path ("plain_check.conf").c_str (), err, sizeof (err)), "0640 is not executable");
  check (err[0] == '\0', "not executable: no reason is set");
  check (!ut_is_executable_file (work_path ("no_such_file").c_str (), NULL, 0), "a missing file is not executable");
  check (!ut_is_executable_file (work_dir, NULL, 0), "a directory is not an executable file");
  check (!ut_is_executable_file (NULL, NULL, 0), "NULL is not an executable file");
}

/* ut_copy_to_backup () from `src` to `dest`, both under work_dir */
static T_CONTENT_WRITE_RESULT
backup (const char *src, const char *dest, char *err_buf, size_t err_size)
{
  return ut_copy_to_backup (work_path (src).c_str (), work_path (dest).c_str (), err_buf, err_size);
}

static void
test_backup (void)
{
  char err[512] = "";
  std::string expect_err;
  std::string src = work_path ("bak_src.conf");
  FILE *fp;

  /* bytes as they are: no trailing newline added, none dropped */
  fp = fopen (src.c_str (), "w");
  fputs ("line 1\nline 2 without newline", fp);
  fclose (fp);
  chmod (src.c_str (), 0600);

  umask (0);
  check (backup ("bak_src.conf", "bak_new.conf.bak", err, sizeof (err)) == CONTENT_WRITE_OK, "a new backup is written");
  check (file_text (work_path ("bak_new.conf.bak")) == "line 1\nline 2 without newline",
	 "a new backup has the same bytes");
  check (file_mode (work_path ("bak_new.conf.bak")) == 0600, "a new backup of 0600 is 0600 (umask 0)");

  /* the original is executable: the new backup is not */
  make_file ("bak_exec_src.sh", 0755);
  check (backup ("bak_exec_src.sh", "bak_exec_src.sh.bak", err, sizeof (err)) == CONTENT_WRITE_OK,
	 "a backup of 0755 is written");
  check (file_mode (work_path ("bak_exec_src.sh.bak")) == 0644, "a new backup of 0755 is 0644, not executable");
  umask (022);

  /* an existing backup that is not executable is replaced and keeps its mode */
  make_file ("bak_old.conf.bak", 0640);
  check (backup ("bak_src.conf", "bak_old.conf.bak", err, sizeof (err)) == CONTENT_WRITE_OK,
	 "an existing 0640 backup is written");
  check (file_text (work_path ("bak_old.conf.bak")) == "line 1\nline 2 without newline",
	 "an existing backup is replaced, not appended to");
  check (file_mode (work_path ("bak_old.conf.bak")) == 0640, "an existing backup keeps its mode");
  check (err[0] == '\0', "a written backup sets no reason");

  /* an executable backup is refused and left as it was */
  make_file ("bak_exec.conf.bak", 0755);
  expect_err = "writing to an executable file is not allowed: " + work_path ("bak_exec.conf.bak");
  check (backup ("bak_src.conf", "bak_exec.conf.bak", err, sizeof (err)) == CONTENT_WRITE_EXECUTABLE,
	 "an executable backup is refused");
  check (expect_err == err, "an executable backup: the reason names the backup");
  check (file_text (work_path ("bak_exec.conf.bak")) == FIXTURE_TEXT, "an executable backup: contents not changed");
  check (file_mode (work_path ("bak_exec.conf.bak")) == 0755, "an executable backup: mode not changed");

  /* a backup that is a link to an executable file is refused too */
  make_file ("bak_link_target.sh", 0700);
  if (symlink (work_path ("bak_link_target.sh").c_str (), work_path ("bak_link.conf.bak").c_str ()) != 0)
    {
      perror ("symlink");
      exit (2);
    }
  check (backup ("bak_src.conf", "bak_link.conf.bak", NULL, 0) == CONTENT_WRITE_EXECUTABLE,
	 "a backup linked to 0700 is refused");
  check (file_text (work_path ("bak_link_target.sh")) == FIXTURE_TEXT, "a backup linked to 0700: target not changed");

  /* nothing to copy: no backup is made, no reason is set */
  err[0] = '\0';
  check (backup ("no_such_file", "bak_missing.bak", err, sizeof (err)) == CONTENT_WRITE_OPEN_FAIL,
	 "a missing original fails");
  check (access (work_path ("bak_missing.bak").c_str (), F_OK) != 0, "a missing original: no backup is created");
  check (err[0] == '\0', "a missing original: no reason is set");
}

int
main (void)
{
  if (mkdtemp (work_dir) == NULL)
    {
      perror ("mkdtemp");
      return 2;
    }

  test_executable_mode ();
  test_executable_extension ();
  test_refused ();
  test_written ();
  test_executable_file ();
  test_backup ();

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
