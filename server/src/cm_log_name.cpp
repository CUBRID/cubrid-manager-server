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
#include <vector>

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
   * The name of a "[...]" line, as ini_parse_line () keeps it: the spaces
   * after a leading '@' or '%' removed, and in lower case except "@<db>",
   * which stays as written ("%<host>|<user>" is lowered too).
   */
  std::string
  section_name (const std::string &line)
  {
    std::string name = trim (line.substr (1, line.find (']') - 1));

    if (!name.empty () && (name[0] == '@' || name[0] == '%'))
      {
	name = name[0] + trim (name.substr (1));
      }
    return (!name.empty () && name[0] == '@') ? name : to_lower (name);
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
 * of dbname gets it. ini_parser.c keeps one entry for each "<section>:<key>",
 * with the value of its last line, in the order the entries first appear,
 * and system_parameter.c (prm_read_and_parse_ini_file ()) applies them in two
 * passes, for a server:
 *   1. the entries of [common] and of no section (the lines before any
 *      section, or after "[ ]"),
 *   2. the entries of [@<dbname>] and, again, of no section.
 * In each pass the entry that appears first is applied first, so the later
 * one wins. Thus [@<dbname>] wins over [common], and a value of no section
 * that appears after [@<dbname>] wins over both. Other sections ([service],
 * [standalone], [@<another db>], ...) do not apply to the server.
 *   - "@<dbname>" is case-sensitive, "common" and the key are not.
 *   - "[]" is not a section name: the section goes on, as in
 *     ini_parse_line (), whose sscanf ("[%[^]]") reads nothing then.
 *   - a value can be quoted, an unquoted value ends at ';' or '#', and a line
 *     that ends with '\' goes on in the next.
 * Returns false when error_log is not set or is empty.
 */
bool
ut_get_db_err_log_param (std::istream &conf, const std::string &dbname, std::string &value)
{
  /* the entry "<section>:error_log" of ini_parser.c */
  struct entry
  {
    bool set;
    int order;			/* when it first appears */
    std::string value;		/* of its last line */
  };
  entry none = { false, 0, "" }, common = { false, 0, "" }, db = { false, 0, "" };
  const std::string db_section = "@" + dbname;
  std::string line, next, section;
  int order = 0;

  value.clear ();
  if (dbname.empty ())
    {
      return false;
    }

  while (std::getline (conf, line))
    {
      line = trim (line);
      while (!line.empty () && line.back () == '\\')
	{
	  line.pop_back ();
	  if (!std::getline (conf, next))
	    {
	      /* the last line goes on into nothing: ini_parser.c never reads it */
	      line.clear ();
	      break;
	    }
	  line = trim (line + next);
	}

      if (line.empty () || line[0] == '#')
	{
	  continue;
	}
      if (line[0] == '[' && line.back () == ']')
	{
	  if (line[1] != ']')
	    {
	      section = section_name (line);
	    }
	  continue;
	}

      const std::string::size_type eq = line.find ('=');
      if (eq == std::string::npos || to_lower (trim (line.substr (0, eq))) != "error_log")
	{
	  continue;
	}

      entry *e = section.empty () ? &none : (section == "common") ? &common : (section == db_section) ? &db : NULL;
      if (e == NULL)
	{
	  continue;
	}
      if (!e->set)
	{
	  e->set = true;
	  e->order = order++;
	}
      e->value = ini_value (line.substr (eq + 1));
    }

  /* the later of a and b that is set, or NULL */
  auto later = [] (const entry *a, const entry *b) -> const entry *
  {
    if (!a->set)
      {
	return b->set ? b : NULL;
      }
    return (b->set && b->order > a->order) ? b : a;
  };
  const entry *got = later (&none, &db);	/* pass 2 */

  if (got == NULL)
    {
      got = later (&none, &common);	/* pass 1 */
    }
  if (got != NULL)
    {
      value = got->value;
    }
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
 * path spelled one way, read as Windows reads it (lexically): no "."
 * component, no repeated '/', no '/' at the end, and ".." folded into the
 * component before it. Above the root, or above the drive of "C:/...", ".."
 * stays at the root; a relative path keeps the ".." it starts with. A leading
 * "//" (a UNC path) is kept. Only '/' is a separator here: '\' is turned into
 * '/' by the caller where it is one (ut_windows_path_key ()).
 */
std::string
ut_lexical_path (const std::string &path)
{
  std::string prefix;
  std::vector<std::string> parts;
  std::string::size_type begin = 0;

  if (path.compare (0, 2, "//") == 0 && path.compare (0, 3, "///") != 0)
    {
      prefix = "//";
    }
  else if (!path.empty () && path[0] == '/')
    {
      prefix = "/";
    }

  while (begin <= path.size ())
    {
      std::string::size_type end = path.find ('/', begin);

      if (end == std::string::npos)
	{
	  end = path.size ();
	}

      const std::string part = path.substr (begin, end - begin);
      const bool at_drive = (prefix.empty () && parts.size () == 1 && parts[0].size () == 2 && parts[0][1] == ':');

      if (part.empty () || part == ".")
	{
	  ;
	}
      else if (part != "..")
	{
	  parts.push_back (part);
	}
      else if (!parts.empty () && parts.back () != ".." && !at_drive)
	{
	  parts.pop_back ();
	}
      else if (prefix.empty () && !at_drive)
	{
	  parts.push_back (part);
	}
      begin = end + 1;
    }

  std::string lexical = prefix;

  for (std::vector<std::string>::size_type i = 0; i < parts.size (); i++)
    {
      lexical += (i == 0 ? "" : "/") + parts[i];
    }
  return lexical;
}

/*
 * The key two Windows paths are compared by: '\' as '/', ut_lexical_path (),
 * and the case ignored, as Windows names a file. Built on every platform, so
 * that the unit tests check it.
 */
std::string
ut_windows_path_key (const std::string &path)
{
  std::string key = path;

  std::replace (key.begin (), key.end (), '\\', '/');
  return to_lower (ut_lexical_path (key));
}

/*
 * Whether path1 and path2, built from the same $CUBRID, name the same file.
 * On Windows they are compared by ut_windows_path_key (), so the case, the
 * separator ('\' or '/'), "." and ".." components and repeated separators do
 * not matter, e.g. error_log=server/./demodb.err. Elsewhere they are compared
 * as they are: ut_file_entry tells the file itself with lstat ().
 */
bool
ut_is_same_path (const std::string &path1, const std::string &path2)
{
#if defined(WINDOWS)
  return ut_windows_path_key (path1) == ut_windows_path_key (path2);
#else
  return path1 == path2;
#endif
}

/* The last component of path, "." and ".." read as ut_lexical_path () does */
static std::string
base_name (const std::string &path)
{
#if defined(WINDOWS)
  const std::string lexical = ut_windows_path_key (path);
#else
  const std::string lexical = ut_lexical_path (path);
#endif
  const std::string::size_type sep = lexical.find_last_of ('/');

  return (sep == std::string::npos) ? lexical : lexical.substr (sep + 1);
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
 * Whether path names this directory entry: ".", "..", "//" or a $CUBRID that
 * is a symbolic link in either path do not matter. The last component is not
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
  if (base_name (path) != m_name)
    {
      return false;
    }
#if !defined(WINDOWS)

  struct stat st;

  if (m_known && lstat (path.c_str (), &st) == 0)
    {
      return st.st_dev == m_dev && st.st_ino == m_ino;
    }
#endif
  return ut_is_same_path (path, m_path);
}
