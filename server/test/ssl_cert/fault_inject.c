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
 * fault_inject.c - LD_PRELOAD library for run_ssl_cert_tests.sh: makes
 *   chosen rename () and unlink () calls fail with EACCES, the way they fail
 *   on Windows when another program keeps a file open. Linux only.
 *
 *   FAULT_RENAME_SRC  comma-separated substrings: rename () fails when its
 *                     source path contains one of them
 *   FAULT_UNLINK_END  comma-separated suffixes: unlink () fails when its path
 *                     ends with one of them
 *   FAULT_FSYNC_DIR   if set, fsync () of a directory fails with EIO
 *   FAULT_FSYNC_DIR_NTH  if set to n, only the n-th fsync () of a directory
 *                     (counting from 1 in the process) fails with EIO
 *   FAULT_TRACE       a file to which each rename (), unlink () and fsync ()
 *                     of a directory is appended, one line each, so that a
 *                     test can check their order
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void
trace (const char *what, const char *a, const char *b)
{
  const char *path = getenv ("FAULT_TRACE");
  FILE *fp;

  if (path == NULL || path[0] == '\0')
    {
      return;
    }
  fp = fopen (path, "a");
  if (fp != NULL)
    {
      fprintf (fp, "%s %s%s%s\n", what, a, b != NULL ? " " : "", b != NULL ? b : "");
      fclose (fp);
    }
}

static int
matches (const char *path, const char *list, int suffix)
{
  char buf[1024];
  char *tok, *save = NULL;
  size_t plen = strlen (path);

  if (list == NULL || list[0] == '\0' || strlen (list) >= sizeof (buf))
    {
      return 0;
    }
  strcpy (buf, list);
  for (tok = strtok_r (buf, ",", &save); tok != NULL; tok = strtok_r (NULL, ",", &save))
    {
      size_t tlen = strlen (tok);

      if (suffix ? (plen >= tlen && strcmp (path + plen - tlen, tok) == 0) : (strstr (path, tok) != NULL))
	{
	  return 1;
	}
    }
  return 0;
}

int
rename (const char *oldpath, const char *newpath)
{
  static int (*real_rename) (const char *, const char *) = NULL;

  if (real_rename == NULL)
    {
      real_rename = (int (*)(const char *, const char *)) dlsym (RTLD_NEXT, "rename");
    }
  if (matches (oldpath, getenv ("FAULT_RENAME_SRC"), 0))
    {
      errno = EACCES;
      return -1;
    }
  trace ("rename", oldpath, newpath);
  return real_rename (oldpath, newpath);
}

int
unlink (const char *path)
{
  static int (*real_unlink) (const char *) = NULL;

  if (real_unlink == NULL)
    {
      real_unlink = (int (*)(const char *)) dlsym (RTLD_NEXT, "unlink");
    }
  if (matches (path, getenv ("FAULT_UNLINK_END"), 1))
    {
      errno = EACCES;
      return -1;
    }
  trace ("unlink", path, NULL);
  return real_unlink (path);
}

int
fsync (int fd)
{
  static int (*real_fsync) (int) = NULL;
  struct stat st;

  if (real_fsync == NULL)
    {
      real_fsync = (int (*)(int)) dlsym (RTLD_NEXT, "fsync");
    }
  if (fstat (fd, &st) == 0 && S_ISDIR (st.st_mode))
    {
      static int count = 0;
      const char *nth = getenv ("FAULT_FSYNC_DIR_NTH");

      count++;
      if (getenv ("FAULT_FSYNC_DIR") != NULL || (nth != NULL && atoi (nth) == count))
	{
	  errno = EIO;
	  return -1;
	}
      trace ("fsyncdir", "", NULL);
    }
  return real_fsync (fd);
}
