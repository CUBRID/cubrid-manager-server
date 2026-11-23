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
 * cm_task_file.cpp - see cm_task_file.h
 */

#include <ctype.h>
#include <fcntl.h>
#include <stdlib.h>
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

#include "cm_task_file.h"

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
 * set_path_reason () - "<reason>: <path>" in err_buf, in the form the path
 *   checks of cm_server_util.cpp use ('%' in the path shown as '*').
 */
static void
set_path_reason (char *err_buf, size_t err_size, const char *reason, const char *path)
{
  std::string shown = (path != NULL) ? path : "(NULL)";

  if (err_buf == NULL || err_size == 0)
    {
      return;
    }
  std::replace (shown.begin (), shown.end (), '%', '*');
  snprintf (err_buf, err_size, "%s: %s", reason, shown.c_str ());
}

#if defined (WINDOWS)
/*
 * win_final_path () - the name Windows gives the file or directory open on
 *   `h`: long names instead of 8.3 short names, the real case, and links and
 *   junctions resolved. Without the "\\?\" prefix GetFinalPathNameByHandle ()
 *   adds. false if the name is not known.
 */
static bool
win_final_path (HANDLE h, std::string &final_path)
{
  char buf[FINAL_PATH_BUF_SIZE];
  DWORD n;

  if (h == INVALID_HANDLE_VALUE)
    {
      return false;
    }
  n = GetFinalPathNameByHandleA (h, buf, sizeof (buf), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  if (n == 0 || n >= sizeof (buf))
    {
      return false;
    }

  final_path = buf;
  if (final_path.compare (0, 8, "\\\\?\\UNC\\") == 0)
    {
      final_path = "\\" + final_path.substr (7);
    }
  else if (final_path.compare (0, 4, "\\\\?\\") == 0)
    {
      final_path = final_path.substr (4);
    }
  return true;
}

/*
 * handle_is_executable () - the file open on `h` has an executable
 *   extension under the name Windows gives it, which covers a link, an 8.3
 *   short name (ABCDEF~1.BAT) and anything else that reaches a file by
 *   another name. Returns 1 if so, 0 if not, -1 if the name is not known.
 */
static int
handle_is_executable (HANDLE h)
{
  std::string final_path;

  if (!win_final_path (h, final_path))
    {
      return -1;
    }
  return ut_has_executable_extension (final_path.c_str ()) ? 1 : 0;
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
      set_path_reason (err_buf, err_size, EXECUTABLE_FILE_ERROR, path);
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
      set_path_reason (err_buf, err_size, EXECUTABLE_FILE_ERROR, path);
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
      set_path_reason (err_buf, err_size, EXECUTABLE_FILE_ERROR, path);
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
      set_path_reason (err_buf, err_size, EXECUTABLE_FILE_ERROR, path);
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

/*
 * real_path_of () - the path the operating system really opens for the
 *   existing file or directory `path`: on Linux realpath (), with symbolic
 *   links resolved; on Windows win_final_path (). false if it does not
 *   exist or cannot be resolved.
 */
static bool
real_path_of (const char *path, std::string &real)
{
#if defined (WINDOWS)
  HANDLE h;
  bool ok;

  /* access 0: only query the name; FILE_FLAG_BACKUP_SEMANTICS opens directories */
  h = CreateFileA (path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
		   FILE_FLAG_BACKUP_SEMANTICS, NULL);
  if (h == INVALID_HANDLE_VALUE)
    {
      return false;
    }
  ok = win_final_path (h, real);
  CloseHandle (h);
  return ok;
#else
  char *resolved = realpath (path, NULL);

  if (resolved == NULL)
    {
      return false;
    }
  real = resolved;
  free (resolved);
  return true;
#endif
}

/*
 * parent_of () - `path` without its last part, for a path real_path_of ()
 *   gave ("/a/b/c" -> "/a/b", "/a" -> "/").
 */
static std::string
parent_of (const std::string &path)
{
  size_t pos = path.find_last_of ("/\\");

  if (pos == std::string::npos)
    {
      return "";
    }
  if (pos == 0)
    {
      return path.substr (0, 1);
    }
  return path.substr (0, pos);
}

/* the same directory: case does not matter on Windows */
static bool
same_dir (const std::string &a, const std::string &b)
{
#if defined (WINDOWS)
  return a.size () == b.size () && std::equal (a.begin (), a.end (), b.begin (), [] (char x, char y)
  {
    return tolower ((unsigned char) x) == tolower ((unsigned char) y);
  });
#else
  return a == b;
#endif
}

#if !defined (WINDOWS)
/*
 * owned_and_not_shared () - `st` belongs to the user CMS runs as (cms_uid)
 *   or to root, and neither the group nor the others may write it. Only
 *   those two could then change it, and they could run anything anyway.
 *   Sets the reason and returns false otherwise. `what` names the file or
 *   directory in the reason.
 */
static bool
owned_and_not_shared (const struct stat &st, unsigned int cms_uid, const char *what, const char *path,
		      char *err_buf, size_t err_size)
{
  std::string reason;

  if (st.st_uid != cms_uid && st.st_uid != 0)
    {
      reason = std::string (what) + " must be owned by the user CMS runs as or by root";
      set_path_reason (err_buf, err_size, reason.c_str (), path);
      return false;
    }
  if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0)
    {
      reason = std::string (what) + " must not be writable by the group or others";
      set_path_reason (err_buf, err_size, reason.c_str (), path);
      return false;
    }
  return true;
}
#endif

/*
 * ut_check_script_path () - runscript may run `script_path`: a file directly
 *   under `script_dir` ($CUBRID/conf), which nobody but the user CMS runs as
 *   (`cms_uid`) and root can change. On success `real_path` holds the path
 *   to run, with links resolved, so that the file checked is the file run.
 *
 *   - The file must be directly under script_dir, not in a subdirectory.
 *     Both are compared by their real paths (real_path_of ()), so a link in
 *     script_dir that points outside it is refused, and a link that points
 *     to a file in script_dir is that file.
 *   - It must be a regular file.
 *   - Linux: the file and script_dir must be owned by cms_uid or root, and
 *     neither may be writable by the group or others. script_dir is checked
 *     too, as whoever can write it can replace the file after the check.
 *     The file must be executable (ut_is_executable_mode ()), so that what a
 *     task wrote is refused with a clear reason rather than failing to run:
 *     a task never creates an executable file, nor rewrites one
 *     (ut_open_for_content_write ()), so a task alone cannot make a script
 *     that runs.
 *   - Windows: the owner, write and execute checks are not done (ACLs; left
 *     for later), only the directory.
 *
 *   Each refusal sets its own reason in err_buf and returns false.
 */
bool
ut_check_script_path (const char *script_path, const char *script_dir, unsigned int cms_uid,
		      std::string &real_path, char *err_buf, size_t err_size)
{
  std::string real_dir;
  std::string real_file;
  std::string reason;

  real_path.clear ();
  if (script_path == NULL || script_dir == NULL)
    {
      set_path_reason (err_buf, err_size, "the script does not exist", script_path);
      return false;
    }

  if (!real_path_of (script_dir, real_dir))
    {
      set_path_reason (err_buf, err_size, "the script directory does not exist", script_dir);
      return false;
    }

  if (!real_path_of (script_path, real_file))
    {
      set_path_reason (err_buf, err_size, "the script does not exist", script_path);
      return false;
    }

  if (!same_dir (parent_of (real_file), real_dir))
    {
      reason = std::string ("only a script directly under ") + script_dir + " can be run";
      set_path_reason (err_buf, err_size, reason.c_str (), script_path);
      return false;
    }

#if defined (WINDOWS)
  (void) cms_uid;
  DWORD attr = GetFileAttributesA (real_file.c_str ());

  if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY) != 0)
    {
      set_path_reason (err_buf, err_size, "the script is not a regular file", script_path);
      return false;
    }
#else
  struct stat file_st, dir_st;

  if (stat (real_file.c_str (), &file_st) != 0 || !S_ISREG (file_st.st_mode))
    {
      set_path_reason (err_buf, err_size, "the script is not a regular file", script_path);
      return false;
    }

  if (!owned_and_not_shared (file_st, cms_uid, "the script", script_path, err_buf, err_size))
    {
      return false;
    }

  if (stat (real_dir.c_str (), &dir_st) != 0)
    {
      set_path_reason (err_buf, err_size, "the script directory does not exist", script_dir);
      return false;
    }

  if (!owned_and_not_shared (dir_st, cms_uid, "the script directory", script_dir, err_buf, err_size))
    {
      return false;
    }

  if (!ut_is_executable_mode (file_st.st_mode))
    {
      set_path_reason (err_buf, err_size, "the script is not executable", script_path);
      return false;
    }
#endif

  real_path = real_file;
  return true;
}
