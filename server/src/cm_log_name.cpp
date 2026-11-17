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
 * cm_log_name.cpp - see cm_log_name.h
 */

#include <ctype.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "cm_log_name.h"

/*
 * Check that fname is a log file of the broker bname.
 * A broker name can hold '_', the separator after the name in its log file
 * names, so the whole suffix after the name is checked:
 *   <bname>.access, <bname>.access.*        (access log)
 *   <bname>_<digits>.*                       (error_log, sql_log, slow log)
 */
bool
ut_is_broker_log_file (const char *fname, const char *bname)
{
  size_t len;
  const char *p;

  if (fname == NULL || bname == NULL)
    {
      return false;
    }

  len = strlen (bname);
  if (len == 0 || strncmp (fname, bname, len) != 0)
    {
      return false;
    }
  p = fname + len;

  if (strncmp (p, ".access", 7) == 0 && (p[7] == '\0' || p[7] == '.'))
    {
      return true;
    }

  if (*p != '_' || !isdigit ((unsigned char) p[1]))
    {
      return false;
    }
  for (p++; isdigit ((unsigned char) *p); p++)
    {
      ;
    }

  return *p == '.';
}

/*
 * Check that fname is a server error log of the database dbname:
 *   <dbname>_<YYYYMMDD>_<HHMM>.err, <dbname>_latest.err
 */
bool
ut_is_db_server_err_log (const char *fname, const char *dbname)
{
  const char *date_fmt = "DDDDDDDD_DDDD";	/* D: a digit */
  size_t len;
  const char *p;
  int i;

  if (fname == NULL || dbname == NULL)
    {
      return false;
    }

  len = strlen (dbname);
  if (len == 0 || strncmp (fname, dbname, len) != 0 || fname[len] != '_')
    {
      return false;
    }
  p = fname + len + 1;

  if (strcmp (p, "latest.err") == 0)
    {
      return true;
    }

  for (i = 0; date_fmt[i] != '\0'; i++)
    {
      if (date_fmt[i] == 'D' ? !isdigit ((unsigned char) p[i]) : p[i] != date_fmt[i])
	{
	  return false;
	}
    }

  return strcmp (p + i, ".err") == 0;
}

/*
 * Check that st_mode (from stat ()) is a regular file, so that a directory
 * whose name looks like a log file name is not listed as a log file.
 */
bool
ut_is_regular_file_mode (unsigned int st_mode)
{
#if defined(WINDOWS)
  return (st_mode & _S_IFMT) == _S_IFREG;
#else
  return S_ISREG (st_mode);
#endif
}
