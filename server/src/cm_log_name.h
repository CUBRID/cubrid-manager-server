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

bool ut_is_broker_log_file (const char *fname, const char *bname, bool shard);
bool ut_is_db_server_err_log (const char *fname, const char *dbname);
bool ut_is_regular_file_mode (unsigned int st_mode);

#endif /* _CM_LOG_NAME_H_ */
