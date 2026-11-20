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
 * Skip "." <digits>, the suffix the engine adds to a log file it backs up.
 * Returns what follows, or NULL when p does not start with it.
 */
static const char *
skip_dot_digits (const char *p)
{
  if (*p != '.' || !isdigit ((unsigned char) p[1]))
    {
      return NULL;
    }
  for (p++; isdigit ((unsigned char) *p); p++)
    {
      ;
    }
  return p;
}

/*
 * "access", "access.denied" or either followed by ".<digits>", a backup.
 * The connections the ACL of the broker (ACCESS_CONTROL) rejects are logged
 * to "<access log>.denied", and both are backed up the same way, cas_log.c
 * cas_access_log () and access_log_backup ().
 */
static bool
is_access_ext (const char *ext)
{
  if (strncmp (ext, "access", 6) != 0)
    {
      return false;
    }
  ext += 6;
  if (strncmp (ext, ".denied", 7) == 0)
    {
      ext += 7;
    }
  if (*ext == '\0')
    {
      return true;
    }
  ext = skip_dot_digits (ext);
  return ext != NULL && *ext == '\0';
}

/*
 * Check that fname is a log file of the broker bname, whose SHARD parameter
 * is shard. What follows bname has to be one of the names the engine gives
 * the log files of a broker:
 *
 *   any broker      <bname>.access[.denied][.<digits>]  access log (".denied":
 *                                                        rejected by the ACL)
 *                   <bname>.err[.<digits>.<digits>]  broker error log
 *                   <bname>_qr_rule.err              query replace rules
 *   SHARD=OFF       <bname>_<cas>.<ext>              CAS sql, slow, error log
 *   SHARD=ON        <bname>_<proxy>.access[.denied][.<digits>]  proxy access log
 *                   <bname>_<proxy>_<shard>_<cas>.<ext>          CAS logs
 *
 * The number of "_<digits>" groups is what tells the instance apart, so it
 * comes from the SHARD parameter and not from the file name: the CAS log
 * "b_1_0_1.sql.log" of a SHARD broker "b" and the CAS log of a broker
 * "b_1_0" have the same name, and only the parameter says which one is
 * meant. The names that hold no group belong to bname alone, so they are
 * accepted whatever the parameter, which keeps the logs written before it
 * was changed.
 */
bool
ut_is_broker_log_file (const char *fname, const char *bname, bool shard)
{
  size_t len;
  const char *p;
  int groups;

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

  if (*p == '.')
    {
      if (is_access_ext (p + 1))
	{
	  return true;
	}
      if (strncmp (p, ".err", 4) == 0)
	{
	  p += 4;
	  if (*p == '\0')
	    {
	      return true;
	    }
	  /* a backup, broker_admin_pub.c rename_error_log_file_name () */
	  p = skip_dot_digits (p);
	  if (p == NULL)
	    {
	      return false;
	    }
	  p = skip_dot_digits (p);
	  return p != NULL && *p == '\0';
	}
      return false;
    }

  if (strcmp (p, "_qr_rule.err") == 0)
    {
      return true;
    }

  for (groups = 0; *p == '_' && isdigit ((unsigned char) p[1]); groups++)
    {
      for (p++; isdigit ((unsigned char) *p); p++)
	{
	  ;
	}
    }
  if (groups == 0 || *p != '.' || p[1] == '\0')
    {
      return false;
    }
  p++;

  if (shard)
    {
      return (groups == 1 && is_access_ext (p)) || (groups == 3 && !is_access_ext (p));
    }
  return groups == 1 && !is_access_ext (p);
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
