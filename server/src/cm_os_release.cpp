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
 * cm_os_release.cpp - see cm_os_release.h
 */

#if !defined(WINDOWS)

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "cm_os_release.h"

#define OS_RELEASE_VALUE_SIZE 128	/* BUFFER_MAX_LEN */

#if !defined(LINE_MAX)
#define LINE_MAX 2048
#endif

/* strip the white space ut_trim () strips, in place */
static void
os_release_trim (char *str)
{
  char *s = str;
  size_t len;

  while (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r')
    {
      s++;
    }
  len = strlen (s);
  while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t' || s[len - 1] == '\n' || s[len - 1] == '\r'))
    {
      len--;
    }
  memmove (str, s, len);
  str[len] = '\0';
}

/*
 * Length of the valid UTF-8 sequence of a non-ASCII character at p, or 0 if
 * the bytes there are not one. Overlong forms, surrogates, code points past
 * U+10FFFF and the C1 control characters U+0080..U+009F are not valid here.
 */
int
ut_utf8_char_len (const unsigned char *p)
{
  unsigned char lo = 0x80, hi = 0xBF;
  int n, i;

  if (p[0] >= 0xC2 && p[0] <= 0xDF)
    {
      n = 2;
      if (p[0] == 0xC2)
	{
	  lo = 0xA0;		/* U+0080..U+009F are the C1 controls */
	}
    }
  else if (p[0] >= 0xE0 && p[0] <= 0xEF)
    {
      n = 3;
      if (p[0] == 0xE0)
	{
	  lo = 0xA0;		/* overlong */
	}
      else if (p[0] == 0xED)
	{
	  hi = 0x9F;		/* surrogates */
	}
    }
  else if (p[0] >= 0xF0 && p[0] <= 0xF4)
    {
      n = 4;
      if (p[0] == 0xF0)
	{
	  lo = 0x90;		/* overlong */
	}
      else if (p[0] == 0xF4)
	{
	  hi = 0x8F;		/* past U+10FFFF */
	}
    }
  else
    {
      return 0;
    }

  if (p[1] < lo || p[1] > hi)
    {
      return 0;
    }
  for (i = 2; i < n; i++)
    {
      if (p[i] < 0x80 || p[i] > 0xBF)
	{
	  return 0;		/* also stops at the terminating '\0' */
	}
    }

  return n;
}

/*
 * Parse the value part of an os-release "KEY=VALUE" line (shell-like syntax).
 * Supports unquoted, '...' and "..." values (with \" \\ \$ \` escapes in
 * double quotes). Printable ASCII and valid UTF-8 characters are kept;
 * control characters (e.g. newline) and bytes that are not valid UTF-8 are
 * dropped, so the value cannot inject them into the response. A value longer
 * than dst_size - 1 bytes is cut at a character boundary.
 * Returns 0 on success (non-empty value), -1 otherwise.
 */
int
ut_parse_os_release_value (const char *src, char *dst, size_t dst_size)
{
  size_t len = 0;
  char quote = '\0';
  const char *p = src;
  bool full = false;

  if (dst == NULL || dst_size == 0)
    {
      return -1;
    }
  dst[0] = '\0';
  if (src == NULL)
    {
      return -1;
    }

  if (*p == '"' || *p == '\'')
    {
      quote = *p++;
    }

  for (; *p != '\0'; p++)
    {
      unsigned char c = (unsigned char) *p;
      int n;

      if (quote != '\0')
	{
	  if (c == (unsigned char) quote)
	    {
	      quote = '\0';
	      break;		/* closing quote */
	    }
	  if (quote == '"' && c == '\\' && p[1] != '\0'
	      && strchr ("\"\\$`", p[1]) != NULL)
	    {
	      c = (unsigned char) * (++p);
	    }
	}
      else if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '#')
	{
	  break;		/* end of unquoted value */
	}

      if (c < 0x80)
	{
	  if (c < 0x20 || c == 0x7F)
	    {
	      continue;		/* drop control characters */
	    }
	  n = 1;
	}
      else
	{
	  n = ut_utf8_char_len ((const unsigned char *) p);
	  if (n == 0)
	    {
	      continue;		/* drop a byte that is not valid UTF-8 */
	    }
	}

      /* truncate, but keep scanning for the closing quote */
      if (!full && len + n < dst_size)
	{
	  memcpy (dst + len, p, n);
	  len += n;
	}
      else
	{
	  full = true;		/* nothing after a character that did not fit */
	}
      p += n - 1;
    }

  if (quote != '\0')
    {
      dst[0] = '\0';		/* unterminated quote: malformed */
      return -1;
    }

  dst[len] = '\0';
  os_release_trim (dst);

  return (dst[0] != '\0') ? 0 : -1;
}

/*
 * Describe the host OS from os-release(5), taking the first of these whose
 * fields are all present and non-empty:
 *   "NAME VERSION", PRETTY_NAME, "NAME VERSION_ID", NAME
 * Not every host has VERSION (Arch Linux, Debian testing/sid, some minimal
 * images), so the rest are fallbacks. "Unknown" is returned if the file is
 * not available or none of them can be made.
 *
 * path is read, and fallback_path only if path does not exist (ENOENT, which
 * a dangling link gives as well), as os-release(5) specifies for
 * /etc/os-release and /usr/lib/os-release.
 */
void
ut_get_os_release_detail (const char *path, const char *fallback_path, char *buf, size_t buf_size)
{
  const long max_file_size = OS_RELEASE_MAX_FILE_SIZE;
  char line[LINE_MAX];
  char name[OS_RELEASE_VALUE_SIZE] = "";
  char version[OS_RELEASE_VALUE_SIZE] = "";
  char pretty_name[OS_RELEASE_VALUE_SIZE] = "";
  char version_id[OS_RELEASE_VALUE_SIZE] = "";
  struct stat st;
  FILE *fp = NULL;
  int fd;
  int skip_rest = 0;
  long total = 0;
  int flags = O_RDONLY | O_NONBLOCK;

  if (buf == NULL || buf_size == 0)
    {
      return;
    }
  snprintf (buf, buf_size, "%s", OS_RELEASE_UNKNOWN);
  if (path == NULL)
    {
      return;
    }

#if defined(O_CLOEXEC)
  flags |= O_CLOEXEC;
#endif
#if defined(O_NOCTTY)
  flags |= O_NOCTTY;
#endif

  /*
   * /etc/os-release is usually a symlink to /usr/lib/os-release, so the link
   * is followed. O_NONBLOCK prevents blocking on a FIFO and fstat() below
   * makes sure that only a regular file of sane size is read.
   */
  fd = open (path, flags);
  if (fd < 0 && errno == ENOENT && fallback_path != NULL)
    {
      /* missing (or a dangling link): the fallback of os-release(5) */
      fd = open (fallback_path, flags);
    }
  if (fd < 0)
    {
      return;
    }

  if (fstat (fd, &st) != 0 || !S_ISREG (st.st_mode)
      || st.st_size <= 0 || st.st_size > max_file_size)
    {
      close (fd);
      return;
    }

  fp = fdopen (fd, "r");
  if (fp == NULL)
    {
      close (fd);
      return;
    }

  while (fgets (line, sizeof (line), fp) != NULL)
    {
      size_t line_len = strlen (line);
      int has_newline = (line_len > 0 && line[line_len - 1] == '\n');

      total += (long) line_len;
      if (total > max_file_size)
	{
	  break;		/* the file grew while reading */
	}

      if (skip_rest)
	{
	  /* remainder of an over-long line; ignore it */
	  skip_rest = !has_newline;
	  continue;
	}
      if (!has_newline && !feof (fp))
	{
	  /* over-long line is ignored entirely */
	  skip_rest = 1;
	  continue;
	}

      os_release_trim (line);

      /* the last assignment wins, as in shell */
      if (strncmp (line, "NAME=", 5) == 0)
	{
	  ut_parse_os_release_value (line + 5, name, sizeof (name));
	}
      else if (strncmp (line, "VERSION=", 8) == 0)
	{
	  ut_parse_os_release_value (line + 8, version, sizeof (version));
	}
      else if (strncmp (line, "PRETTY_NAME=", 12) == 0)
	{
	  ut_parse_os_release_value (line + 12, pretty_name, sizeof (pretty_name));
	}
      else if (strncmp (line, "VERSION_ID=", 11) == 0)
	{
	  ut_parse_os_release_value (line + 11, version_id, sizeof (version_id));
	}
    }

  fclose (fp);			/* also closes fd */

  if (name[0] != '\0' && version[0] != '\0')
    {
      snprintf (buf, buf_size, "%s %s", name, version);
    }
  else if (pretty_name[0] != '\0')
    {
      snprintf (buf, buf_size, "%s", pretty_name);
    }
  else if (name[0] != '\0' && version_id[0] != '\0')
    {
      snprintf (buf, buf_size, "%s %s", name, version_id);
    }
  else if (name[0] != '\0')
    {
      snprintf (buf, buf_size, "%s", name);
    }
}

#endif /* !WINDOWS */
