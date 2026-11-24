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
 * cm_os_release.h - the OS of the host from os-release(5), returned by
 *   getenv as osinfo_detail (CBRD-28287). UNIX only.
 *
 *   It needs only the system headers, so server/test/unit tests it with
 *   fixed values and fixed os-release files: the API test sees only the
 *   os-release of the host it runs on.
 */

#ifndef _CM_OS_RELEASE_H_
#define _CM_OS_RELEASE_H_

#include <stddef.h>

#define OS_RELEASE_PATH "/etc/os-release"
#define OS_RELEASE_FALLBACK_PATH "/usr/lib/os-release"
#define OS_RELEASE_UNKNOWN "Unknown"

/*
 * Largest os-release read; the file is a few hundred bytes. A larger file,
 * one that is not a regular file, or one that grows past this while it is
 * read gives "Unknown".
 */
#define OS_RELEASE_MAX_FILE_SIZE (64 * 1024)

/*
 * Length of the valid UTF-8 sequence of a non-ASCII character at p, or 0 if
 * the bytes there are not one. Overlong forms, surrogates, code points past
 * U+10FFFF and the C1 control characters U+0080..U+009F are not valid.
 */
int ut_utf8_char_len (const unsigned char *p);

/*
 * The value part of an os-release "KEY=VALUE" line in shell-like syntax:
 * unquoted, '...' or "..." (\" \\ \$ \` escapes in double quotes). Printable
 * ASCII and valid UTF-8 are kept, control characters and invalid bytes are
 * dropped, white space around the value is trimmed, and a value longer than
 * dst_size - 1 bytes is cut at a character boundary.
 * Returns 0 for a non-empty value, -1 for an empty or malformed one
 * (unterminated quote), with dst set to "".
 */
int ut_parse_os_release_value (const char *src, char *dst, size_t dst_size);

/*
 * The OS from the os-release file at path, or at fallback_path (may be NULL)
 * if path does not exist: the first of "NAME VERSION", PRETTY_NAME,
 * "NAME VERSION_ID" and NAME whose fields are all present and non-empty.
 * The last assignment of a key wins, and a line longer than the line buffer
 * is ignored as a whole. buf is "Unknown" if the file cannot be read or none
 * of them can be made.
 */
void ut_get_os_release_detail (const char *path, const char *fallback_path, char *buf, size_t buf_size);

#endif /* _CM_OS_RELEASE_H_ */
