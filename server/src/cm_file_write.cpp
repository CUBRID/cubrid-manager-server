/*
 *
 * Copyright 2016 CUBRID Corporation
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

/*
 * cm_file_write.cpp - see cm_file_write.h
 */

#include <ctype.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <algorithm>
#include <string>

#if defined (WINDOWS)
#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

#include "cm_file_write.h"

#define EXECUTABLE_FILE_ERROR "writing to an executable file is not allowed"

#if defined (WINDOWS)
/* large enough for the long names GetFinalPathNameByHandle () returns */
#define FINAL_PATH_BUF_SIZE 4096
#endif

/*
 * The extensions Windows runs a file by (the default PATHEXT of Windows 10
 * and later, and .ps1 of PowerShell). The value of PATHEXT is not read: it
 * belongs to whoever starts CMS, and a value without .bat would let a .bat
 * file be written.
 */
static const char *executable_extensions[] =
{
  ".com", ".exe", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".msc", ".cpl", ".ps1", NULL
};

/*
 * ut_is_executable_mode () - st_mode has an execute bit for the owner, the
 *   group or the others. Any one of them is enough: someone can run the
 *   file. Windows has no execute bits (ut_has_executable_extension () is
 *   used there instead).
 */
bool
ut_is_executable_mode (unsigned int st_mode)
{
#if defined (WINDOWS)
  (void) st_mode;
  return false;
#else
  return (st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0;
#endif
}

/*
 * ut_has_executable_extension () - the last part of `path` ends with one of
 *   executable_extensions[], in any case. Trailing dots and spaces are
 *   dropped first, as Windows drops them when it opens the file ("a.bat."
 *   opens "a.bat"). Both '/' and '\' separate the parts, so that the result
 *   does not depend on the platform it is tested on.
 *   Only Windows uses it, but it is built on every platform so that the unit
 *   test, which runs on Linux (test_file_write.cpp), covers the rule.
 */
bool
ut_has_executable_extension (const char *path)
{
  std::string name;
  size_t pos;

  if (path == NULL)
    {
      return false;
    }

  name = path;
  pos = name.find_last_of ("/\\");
  if (pos != std::string::npos)
    {
      name = name.substr (pos + 1);
    }

  pos = name.find_last_not_of (". ");
  if (pos == std::string::npos)
    {
      return false;
    }
  name.erase (pos + 1);

  pos = name.find_last_of ('.');
  if (pos == std::string::npos)
    {
      return false;
    }
  name = name.substr (pos);
  std::transform (name.begin (), name.end (), name.begin (), (int (*) (int)) tolower);

  for (int i = 0; executable_extensions[i] != NULL; i++)
    {
      if (name == executable_extensions[i])
	{
	  return true;
	}
    }
  return false;
}

/*
 * set_executable_error () - "writing to an executable file is not allowed:
 *   <path>", in the form the path checks of cm_server_util.cpp use ('%' in
 *   the path shown as '*').
 */
static void
set_executable_error (char *err_buf, size_t err_size, const char *path)
{
  std::string shown = path;

  if (err_buf == NULL || err_size == 0)
    {
      return;
    }
  std::replace (shown.begin (), shown.end (), '%', '*');
  snprintf (err_buf, err_size, "%s: %s", EXECUTABLE_FILE_ERROR, shown.c_str ());
}

#if defined (WINDOWS)
/*
 * handle_is_executable () - the file open on `h` has an executable
 *   extension under the name Windows gives it, which covers a link, an 8.3
 *   short name (ABCDEF~1.BAT) and anything else that reaches a file by
 *   another name. Returns 1 if so, 0 if not, -1 if the name is not known.
 */
static int
handle_is_executable (HANDLE h)
{
  char buf[FINAL_PATH_BUF_SIZE];
  DWORD n;

  if (h == INVALID_HANDLE_VALUE)
    {
      return -1;
    }
  n = GetFinalPathNameByHandleA (h, buf, sizeof (buf), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  if (n == 0 || n >= sizeof (buf))
    {
      return -1;
    }
  return ut_has_executable_extension (buf) ? 1 : 0;
}
#endif

/*
 * How open_non_executable_for_write () writes the file on Windows: text mode
 * turns "\n" into "\r\n", as fopen (path, "w") does; a copy needs the bytes
 * as they are. Linux makes no difference.
 */
typedef enum
{
  WRITE_AS_TEXT,
  WRITE_AS_BINARY
} T_WRITE_FORMAT;

/*
 * open_non_executable_for_write () - open `path` to replace its contents
 *   unless it is an executable file; the common part of
 *   ut_open_for_content_write () and ut_copy_to_backup ().
 *
 *   Linux: the file (the target, if `path` is a symbolic link) is opened
 *   without O_TRUNC and judged by fstat () on that descriptor, then
 *   truncated. Judging the path first and opening it afterwards would leave
 *   a gap in which the file could be replaced. A new file is created with
 *   `create_mode` without its execute bits (the umask can only take more
 *   away), so a task never creates an executable file. An existing file that
 *   is not executable keeps its mode.
 *
 *   Windows: the extension decides (executable_extensions[]). It is checked
 *   on `path` before opening, so that no executable file is created, and on
 *   the name of the opened file, before it is truncated. `create_mode` is
 *   not used. `format` picks text or binary mode (T_WRITE_FORMAT).
 */
static T_CONTENT_WRITE_RESULT
open_non_executable_for_write (const char *path, unsigned int create_mode, T_WRITE_FORMAT format, FILE **fp,
			       char *err_buf, size_t err_size)
{
  int fd;
  FILE *outfile;

  *fp = NULL;
  if (path == NULL)
    {
      return CONTENT_WRITE_OPEN_FAIL;
    }

#if defined (WINDOWS)
  int executable;

  (void) create_mode;
  if (ut_has_executable_extension (path))
    {
      set_executable_error (err_buf, err_size, path);
      return CONTENT_WRITE_EXECUTABLE;
    }

  fd = _open (path, _O_WRONLY | _O_CREAT | (format == WRITE_AS_BINARY ? _O_BINARY : _O_TEXT), _S_IREAD | _S_IWRITE);
  if (fd < 0)
    {
      return CONTENT_WRITE_OPEN_FAIL;
    }

  executable = handle_is_executable ((HANDLE) _get_osfhandle (fd));
  if (executable != 0)
    {
      _close (fd);
      if (executable < 0)
	{
	  return CONTENT_WRITE_OPEN_FAIL;
	}
      set_executable_error (err_buf, err_size, path);
      return CONTENT_WRITE_EXECUTABLE;
    }

  if (_chsize_s (fd, 0) != 0)
    {
      _close (fd);
      return CONTENT_WRITE_OPEN_FAIL;
    }

  outfile = _fdopen (fd, format == WRITE_AS_BINARY ? "wb" : "w");
  if (outfile == NULL)
    {
      _close (fd);
      return CONTENT_WRITE_OPEN_FAIL;
    }
#else
  struct stat st;

  (void) format;
  fd = open (path, O_WRONLY | O_CREAT, (mode_t) (create_mode & 0666));
  if (fd < 0)
    {
      return CONTENT_WRITE_OPEN_FAIL;
    }

  if (fstat (fd, &st) != 0)
    {
      close (fd);
      return CONTENT_WRITE_OPEN_FAIL;
    }

  if (ut_is_executable_mode (st.st_mode))
    {
      close (fd);
      set_executable_error (err_buf, err_size, path);
      return CONTENT_WRITE_EXECUTABLE;
    }

  /* fopen ("w") does not truncate anything but a regular file either (a FIFO, /dev/null) */
  if (S_ISREG (st.st_mode) && ftruncate (fd, 0) != 0)
    {
      close (fd);
      return CONTENT_WRITE_OPEN_FAIL;
    }

  outfile = fdopen (fd, "w");
  if (outfile == NULL)
    {
      close (fd);
      return CONTENT_WRITE_OPEN_FAIL;
    }
#endif

  *fp = outfile;
  return CONTENT_WRITE_OK;
}

/*
 * ut_open_for_content_write () - open `path` for a task that replaces its
 *   contents, like fopen (path, "w"), unless it is an executable file.
 *
 *   An existing file keeps its inode and mode when it is rewritten, so
 *   writing an executable file would leave the new contents executable. It
 *   is refused, and left as it is (CONTENT_WRITE_EXECUTABLE, with the reason
 *   in err_buf). The execute bits are not dropped instead: that would break
 *   a script that is meant to be executable. A new file is created with at
 *   most 0644. See open_non_executable_for_write () for how the file is judged.
 *
 *   CONTENT_WRITE_OPEN_FAIL: the file could not be opened or truncated;
 *   err_buf is not changed, so the caller reports it as before. On
 *   CONTENT_WRITE_OK, *fp is open for writing and the file is empty.
 */
T_CONTENT_WRITE_RESULT
ut_open_for_content_write (const char *path, FILE **fp, char *err_buf, size_t err_size)
{
  return open_non_executable_for_write (path, 0644, WRITE_AS_TEXT, fp, err_buf, err_size);
}

/*
 * ut_is_executable_file () - the existing regular file `path` is
 *   executable, judged as open_non_executable_for_write () judges it: on Linux an execute bit
 *   (of the target, for a symbolic link), on Windows the extension of `path`
 *   or of the name Windows gives the file. If so, the reason is set in
 *   err_buf. false for a file that does not exist or cannot be examined.
 *
 *   Only for refusing before work that should not be done for a file that
 *   will be refused, such as the backup of writeandsaveconf. The file can
 *   change afterwards, so the write itself still has to go through
 *   ut_open_for_content_write ().
 */
bool
ut_is_executable_file (const char *path, char *err_buf, size_t err_size)
{
  bool executable = false;

  if (path == NULL)
    {
      return false;
    }

#if defined (WINDOWS)
  if (ut_has_executable_extension (path))
    {
      executable = true;
    }
  else
    {
      /* access 0: only query the name; FILE_FLAG_BACKUP_SEMANTICS opens directories */
      HANDLE h = CreateFileA (path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
			      OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);

      if (h != INVALID_HANDLE_VALUE)
	{
	  executable = (handle_is_executable (h) == 1);
	  CloseHandle (h);
	}
    }
#else
  struct stat st;

  executable = (stat (path, &st) == 0 && S_ISREG (st.st_mode) && ut_is_executable_mode (st.st_mode));
#endif

  if (executable)
    {
      set_executable_error (err_buf, err_size, path);
    }
  return executable;
}

/*
 * ut_copy_to_backup () - copy `src` to `dest`, its backup, writing `dest`
 *   as ut_open_for_content_write () writes a file: an executable `dest` is
 *   refused and left as it is (CONTENT_WRITE_EXECUTABLE, with the reason in
 *   err_buf), so that the contents of `src`, which a task may have written,
 *   never land in an executable file.
 *
 *   A new `dest` gets the mode of `src` without its execute bits (Linux), so
 *   that the backup of a private file stays private and is never
 *   executable; an existing `dest` keeps its mode. The bytes are copied as
 *   they are (binary mode on Windows).
 *
 *   CONTENT_WRITE_OPEN_FAIL: `src` could not be read or `dest` could not be
 *   written; err_buf is not changed. A `dest` that was written only in part
 *   is removed, as file_copy () does.
 */
T_CONTENT_WRITE_RESULT
ut_copy_to_backup (const char *src, const char *dest, char *err_buf, size_t err_size)
{
  FILE *infile, *outfile;
  char buf[8192];
  size_t n;
  unsigned int mode = 0644;
  bool ok = true;
  T_CONTENT_WRITE_RESULT result;

  if (src == NULL || dest == NULL)
    {
      return CONTENT_WRITE_OPEN_FAIL;
    }

#if !defined (WINDOWS)
  struct stat st;

  if (stat (src, &st) == 0)
    {
      mode = st.st_mode & 0666;
    }
#endif

  infile = fopen (src, "rb");
  if (infile == NULL)
    {
      return CONTENT_WRITE_OPEN_FAIL;
    }

  result = open_non_executable_for_write (dest, mode, WRITE_AS_BINARY, &outfile, err_buf, err_size);
  if (result != CONTENT_WRITE_OK)
    {
      fclose (infile);
      return result;
    }

  while ((n = fread (buf, 1, sizeof (buf), infile)) > 0)
    {
      if (fwrite (buf, 1, n, outfile) != n)
	{
	  ok = false;
	  break;
	}
    }
  if (ferror (infile))
    {
      ok = false;
    }
  fclose (infile);

  /* a write error can show up only when the file is closed */
  if (fclose (outfile) != 0)
    {
      ok = false;
    }

  if (!ok)
    {
      remove (dest);
      return CONTENT_WRITE_OPEN_FAIL;
    }
  return CONTENT_WRITE_OK;
}
