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

#include <algorithm>

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
 *
 * "<bname>.err" is not accepted. The engine keeps a path for it
 * (broker_shm.c get_error_log_file_name ()) but writes nothing there, and
 * it is the CAS error log "<b>_<cas>.err" of a broker <b> when bname is
 * "<b>_<cas>".
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
      return is_access_ext (p + 1);
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

namespace
{
  std::string
  trim (const std::string &s)
  {
    const char *const spaces = " \t\r\n\v\f";
    const std::string::size_type begin = s.find_first_not_of (spaces);

    if (begin == std::string::npos)
      {
	return "";
      }
    return s.substr (begin, s.find_last_not_of (spaces) - begin + 1);
  }

  std::string
  to_lower (std::string s)
  {
    std::transform (s.begin (), s.end (), s.begin (), [] (unsigned char c)
    {
      return static_cast<char> (tolower (c));
    });
    return s;
  }

  /*
   * The name of a "[...]" line, as ini_parse_line () keeps it: "@<db>" and
   * "%<host>|<user>" as written, any other section in lower case.
   */
  std::string
  section_name (const std::string &line)
  {
    std::string name = trim (line.substr (1, line.find (']') - 1));

    if (!name.empty () && (name[0] == '@' || name[0] == '%'))
      {
	return name[0] + trim (name.substr (1));
      }
    return to_lower (name);
  }

  /*
   * The value of "key = value", as ini_parse_line () reads it: the text
   * between the quotes when it is quoted, otherwise up to ';' or '#', a
   * comment.
   */
  std::string
  ini_value (const std::string &text)
  {
    const std::string v = trim (text);

    if (!v.empty () && (v[0] == '"' || v[0] == '\''))
      {
	const std::string::size_type close = v.find (v[0], 1);

	if (close != std::string::npos)
	  {
	    return v.substr (1, close - 1);
	  }
      }
    return trim (v.substr (0, v.find_first_of (";#")));
  }

  bool
  is_abs_path (const std::string &path)
  {
#if defined(WINDOWS)
    return (!path.empty () && (path[0] == '/' || path[0] == '\\'))
	   || (path.size () > 2 && isalpha ((unsigned char) path[0]) && path[1] == ':'
	       && (path[2] == '/' || path[2] == '\\'));
#else
    return !path.empty () && path[0] == '/';
#endif
  }
}

/*
 * Read error_log of the database dbname from cubrid.conf conf, as the server
 * of dbname gets it:
 *   - [common] (and the lines before any section) then [@<dbname>], so the
 *     value of [@<dbname>] wins; "<dbname>" is compared case-sensitively,
 *     "common" is not. The other sections ([service], [standalone],
 *     [@<another db>], ...) do not apply to the server.
 *   - the last line wins when a section sets it more than once.
 *   - the key is case-insensitive, a value can be quoted, an unquoted value
 *     ends at ';' or '#', and a line that ends with '\' goes on in the next.
 * Returns false when error_log is not set or is empty.
 */
bool
ut_get_db_err_log_param (std::istream &conf, const std::string &dbname, std::string &value)
{
  const std::string db_section = "@" + dbname;
  std::string line, next, section, common_val, db_val;
  bool db_set = false;

  value.clear ();
  if (dbname.empty ())
    {
      return false;
    }

  while (std::getline (conf, line))
    {
      line = trim (line);
      while (!line.empty () && line.back () == '\\' && std::getline (conf, next))
	{
	  line.pop_back ();
	  line = trim (line + next);
	}

      if (line.empty () || line[0] == '#')
	{
	  continue;
	}
      if (line[0] == '[' && line.back () == ']')
	{
	  section = section_name (line);
	  continue;
	}

      const std::string::size_type eq = line.find ('=');
      if (eq == std::string::npos || to_lower (trim (line.substr (0, eq))) != "error_log")
	{
	  continue;
	}
      if (section.empty () || section == "common")
	{
	  common_val = ini_value (line.substr (eq + 1));
	}
      else if (section == db_section)
	{
	  db_val = ini_value (line.substr (eq + 1));
	  db_set = true;
	}
    }

  value = db_set ? db_val : common_val;
  return !value.empty ();
}

/*
 * The path of the file the server writes its error log to, for the value
 * param of error_log, as er_init () of the engine resolves it: an absolute
 * path as it is, any other path under the log directory log_dir
 * ($CUBRID/log), so "server/demodb.err" is $CUBRID/log/server/demodb.err.
 * A path that starts with '.' is relative to the working directory of the
 * server, which is not known here: false.
 */
bool
ut_resolve_err_log_param (const std::string &param, const std::string &log_dir, std::string &path)
{
  path.clear ();
  if (param.empty () || param[0] == '.' || log_dir.empty ())
    {
      return false;
    }
  path = is_abs_path (param) ? param : log_dir + "/" + param;
  return true;
}

/*
 * Whether path1 and path2, built from the same $CUBRID, name the same file.
 * On Windows the case and the separator ('\' or '/') do not matter.
 */
bool
ut_is_same_path (const std::string &path1, const std::string &path2)
{
#if defined(WINDOWS)
  auto normalize = [] (std::string path)
  {
    std::replace (path.begin (), path.end (), '\\', '/');
    return to_lower (path);
  };
  return normalize (path1) == normalize (path2);
#else
  return path1 == path2;
#endif
}

/* The last component of path */
static std::string
base_name (const std::string &path)
{
#if defined(WINDOWS)
  const std::string::size_type sep = path.find_last_of ("/\\");
#else
  const std::string::size_type sep = path.find_last_of ('/');
#endif
  return (sep == std::string::npos) ? path : path.substr (sep + 1);
}

ut_file_entry::ut_file_entry (const std::string &path)
  : m_path (path)
  , m_name (base_name (path))
  , m_known (false)
#if !defined(WINDOWS)
  , m_dev (0)
  , m_ino (0)
#endif
{
#if !defined(WINDOWS)
  struct stat st;

  if (lstat (path.c_str (), &st) == 0)
    {
      m_known = true;
      m_dev = st.st_dev;
      m_ino = st.st_ino;
    }
#endif
}

/*
 * Whether path names this directory entry: "//", ".." or a $CUBRID that is a
 * symbolic link in either path do not matter. The last component is not
 * followed (lstat ()), so <db>_latest.err, the link the engine keeps to the
 * current error log, is not taken for the file it points to.
 *   - Only an entry with the same file name is looked up: a hard link to the
 *     file under another name is not found.
 *   - The paths are compared (ut_is_same_path ()) when either cannot be
 *     lstat()ed, and on Windows.
 */
bool
ut_file_entry::is (const std::string &path) const
{
#if defined(WINDOWS)
  if (!ut_is_same_path (base_name (path), m_name))
    {
      return false;
    }
#else
  if (base_name (path) != m_name)
    {
      return false;
    }

  struct stat st;

  if (m_known && lstat (path.c_str (), &st) == 0)
    {
      return st.st_dev == m_dev && st.st_ino == m_ino;
    }
#endif
  return ut_is_same_path (path, m_path);
}
