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
 * cm_log_name.h - tell whether a file name is a log file of a given broker
 *   or database (CBRD-26446).
 *
 *   A broker or database name can hold '_', which is also the separator
 *   after the name in its log file names, so the whole suffix after the name
 *   is checked against the names the engine gives its log files.
 *
 *   No CUBRID or CMS dependency, so that the rules can be tested on their
 *   own (server/test/unit/test_log_name.cpp).
 */

#ifndef _CM_LOG_NAME_H_
#define _CM_LOG_NAME_H_

#include <istream>
#include <string>
#include <sys/types.h>

bool ut_is_broker_log_file (const char *fname, const char *bname, bool shard);
bool ut_is_db_server_err_log (const char *fname, const char *dbname);
bool ut_is_regular_file_mode (unsigned int st_mode);

/*
 * A database can name its server error log itself with error_log in
 * cubrid.conf, e.g. "server/demodb.err". That file is a log of the database
 * too, whatever its name. cubrid.conf is read here as the engine reads it
 * (ini_parser.c, system_parameter.c), without depending on the engine.
 */
bool ut_get_db_err_log_param (std::istream &conf, const std::string &dbname, std::string &value);
bool ut_resolve_err_log_param (const std::string &param, const std::string &log_dir, std::string &path);
bool ut_is_same_path (const std::string &path1, const std::string &path2);
std::string ut_lexical_path (const std::string &path);
std::string ut_windows_path_key (const std::string &path);

/*
 * A file to find in a directory listing by its directory entry, however its
 * path is spelled. Its lstat () is taken once, when it is made, and is() then
 * looks up only an entry with the same file name, so a listing of N files
 * costs at most one more lstat (), not 2N.
 */
class ut_file_entry
{
  public:
    explicit ut_file_entry (const std::string &path);
    bool is (const std::string &path) const;
    bool is (const std::string &dir, const char *name) const;

  private:
    std::string m_path;
    std::string m_name;
    bool m_known;
#if !defined(WINDOWS)
    dev_t m_dev;
    ino_t m_ino;
#endif
};

#endif /* _CM_LOG_NAME_H_ */
