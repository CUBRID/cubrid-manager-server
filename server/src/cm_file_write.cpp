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
 * win_opened_file_is_executable () - the file open on `fd` has an executable
 *   extension under the name Windows gives it, which covers a link, an 8.3
 *   short name (ABCDEF~1.BAT) and anything else that reaches a file by
 *   another name. Returns 1 if so, 0 if not, -1 if the name is not known.
 */
static int
win_opened_file_is_executable (int fd)
{
  char buf[FINAL_PATH_BUF_SIZE];
  HANDLE h;
  DWORD n;

  h = (HANDLE) _get_osfhandle (fd);
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
 * ut_open_for_content_write () - open `path` for a task that replaces its
 *   contents, like fopen (path, "w"), unless it is an executable file.
 *
 *   An existing file keeps its inode and mode when it is rewritten, so
 *   writing an executable file would leave the new contents executable. It
 *   is refused, and left as it is (CONTENT_WRITE_EXECUTABLE, with the reason
 *   in err_buf). The execute bits are not dropped instead: that would break
 *   a script that is meant to be executable.
 *
 *   CONTENT_WRITE_OPEN_FAIL: the file could not be opened or truncated;
 *   err_buf is not changed, so the caller reports it as before. On
 *   CONTENT_WRITE_OK, *fp is open for writing and the file is empty.
 */
T_CONTENT_WRITE_RESULT
ut_open_for_content_write (const char *path, FILE **fp, char *err_buf, size_t err_size)
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

  if (ut_has_executable_extension (path))
    {
      set_executable_error (err_buf, err_size, path);
      return CONTENT_WRITE_EXECUTABLE;
    }

  /* text mode, as fopen (path, "w") opens it */
  fd = _open (path, _O_WRONLY | _O_CREAT | _O_TEXT, _S_IREAD | _S_IWRITE);
  if (fd < 0)
    {
      return CONTENT_WRITE_OPEN_FAIL;
    }

  executable = win_opened_file_is_executable (fd);
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

  outfile = _fdopen (fd, "w");
  if (outfile == NULL)
    {
      _close (fd);
      return CONTENT_WRITE_OPEN_FAIL;
    }
#else
  struct stat st;

  fd = open (path, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
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
