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
 * test_os_release.cpp - unit tests of server/src/cm_os_release.cpp, the
 *   osinfo_detail value of getenv (CBRD-28287).
 *
 *   The API test compares osinfo_detail with the os-release of the host it
 *   runs on, a single well-formed file, so it never reaches the escapes, the
 *   unterminated quotes, invalid UTF-8, C1 characters, the truncation or the
 *   over-long lines. Those are checked here from tables of fixed inputs.
 *
 *   Build and run with run_unit_tests.sh in this directory; it needs no
 *   CUBRID build.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <string>

#include "cm_os_release.h"

#if !defined(LINE_MAX)
#define LINE_MAX 2048		/* as in cm_os_release.cpp */
#endif

#define VALUE_SIZE 128		/* the value buffers of cm_os_release.cpp */

static int failures = 0;
static int checks = 0;
static char tmp_dir[PATH_MAX];

static void
check (bool ok, const char *what)
{
  checks++;
  if (!ok)
    {
      failures++;
      printf ("FAIL  %s\n", what);
    }
}

/* ------------------------------------------------------- ut_utf8_char_len */

static const struct
{
  const char *what;
  const char *bytes;
  int expect;
} utf8_cases[] =
{
  {"U+00A0 (first after C1)", "\xc2\xa0", 2},
  {"U+00E9", "\xc3\xa9", 2},
  {"U+07FF", "\xdf\xbf", 2},
  {"U+0800", "\xe0\xa0\x80", 3},
  {"U+D55C (Hangul)", "\xed\x95\x9c", 3},
  {"U+D7FF (before surrogates)", "\xed\x9f\xbf", 3},
  {"U+E000 (after surrogates)", "\xee\x80\x80", 3},
  {"U+FFFF", "\xef\xbf\xbf", 3},
  {"U+10000", "\xf0\x90\x80\x80", 4},
  {"U+1F427 (emoji)", "\xf0\x9f\x90\xa7", 4},
  {"U+10FFFF", "\xf4\x8f\xbf\xbf", 4},
  {"C1 U+0080", "\xc2\x80", 0},
  {"C1 U+0085 (NEL)", "\xc2\x85", 0},
  {"C1 U+009F", "\xc2\x9f", 0},
  {"overlong 2 bytes C0", "\xc0\xaf", 0},
  {"overlong 2 bytes C1", "\xc1\xbf", 0},
  {"overlong 3 bytes", "\xe0\x9f\xbf", 0},
  {"overlong 4 bytes", "\xf0\x8f\xbf\xbf", 0},
  {"surrogate U+D800", "\xed\xa0\x80", 0},
  {"surrogate U+DFFF", "\xed\xbf\xbf", 0},
  {"past U+10FFFF", "\xf4\x90\x80\x80", 0},
  {"F5 lead", "\xf5\x80\x80\x80", 0},
  {"FF", "\xff", 0},
  {"lone continuation", "\x80", 0},
  {"bad continuation", "\xc3\x28", 0},
  {"cut 3-byte sequence", "\xe2\x82", 0},
  {"cut 4-byte sequence", "\xf0\x9f\x90", 0},
};

static void
test_utf8_char_len (void)
{
  char what[256];
  size_t i;

  for (i = 0; i < sizeof (utf8_cases) / sizeof (utf8_cases[0]); i++)
    {
      int got = ut_utf8_char_len ((const unsigned char *) utf8_cases[i].bytes);

      snprintf (what, sizeof (what), "utf8_char_len %s -> %d (got %d)", utf8_cases[i].what,
		utf8_cases[i].expect, got);
      check (got == utf8_cases[i].expect, what);
    }
}

/* ---------------------------------------------- ut_parse_os_release_value */

/* expect NULL: the value is empty or malformed, -1 with dst "" */
static const struct
{
  const char *src;
  size_t dst_size;
  const char *expect;
} value_cases[] =
{
  /* unquoted: ends at white space or a comment */
  {"rocky", VALUE_SIZE, "rocky"},
  {"8.10", VALUE_SIZE, "8.10"},
  {"Ubuntu # a comment", VALUE_SIZE, "Ubuntu"},
  {"Ubuntu#comment", VALUE_SIZE, "Ubuntu"},
  {"Linux Mint", VALUE_SIZE, "Linux"},

  /* quoted: white space and # belong to the value, outer white space is trimmed */
  {"\"Rocky Linux\"", VALUE_SIZE, "Rocky Linux"},
  {"'8.10 (Green Obsidian)'", VALUE_SIZE, "8.10 (Green Obsidian)"},
  {"\"a # b\"", VALUE_SIZE, "a # b"},
  {"\"  Rocky  \"", VALUE_SIZE, "Rocky"},
  {"\"Rocky\" trailing", VALUE_SIZE, "Rocky"},

  /* escapes: \" \\ \$ \` in double quotes; any other backslash stays */
  {"\"say \\\"hi\\\"\"", VALUE_SIZE, "say \"hi\""},
  {"\"a\\\\b\"", VALUE_SIZE, "a\\b"},
  {"\"\\$HOME \\`id\\`\"", VALUE_SIZE, "$HOME `id`"},
  {"\"a\\nb\"", VALUE_SIZE, "a\\nb"},
  {"\"ends with \\\"", VALUE_SIZE, NULL},	/* the escaped quote does not close it */
  {"'a\\\"b'", VALUE_SIZE, "a\\\"b"},	/* no escapes in single quotes */
  {"'it\"s'", VALUE_SIZE, "it\"s"},

  /* unterminated quotes and empty values */
  {"\"Rocky", VALUE_SIZE, NULL},
  {"'Rocky", VALUE_SIZE, NULL},
  {"", VALUE_SIZE, NULL},
  {"\"\"", VALUE_SIZE, NULL},
  {"''", VALUE_SIZE, NULL},
  {"\"   \"", VALUE_SIZE, NULL},

  /* control characters are dropped, so they cannot reach the response */
  {"\"a\tb\"", VALUE_SIZE, "ab"},
  {"\"a\x01" "b\x1f" "c\x7f\"", VALUE_SIZE, "abc"},
  {"\"\x01\x02\"", VALUE_SIZE, NULL},

  /* UTF-8 is kept */
  {"\"한국어 리눅스\"", VALUE_SIZE, "한국어 리눅스"},
  {"\"서버\"", VALUE_SIZE, "서버"},	/* nothing but non-ASCII */
  {"서버 x", VALUE_SIZE, "서버"},
  {"\"Ünïcödé\"", VALUE_SIZE, "Ünïcödé"},
  {"\"Debian 🐧\"", VALUE_SIZE, "Debian 🐧"},

  /* C1 and invalid UTF-8 are dropped, the rest of the value is kept */
  {"\"a\xc2\x85" "b\"", VALUE_SIZE, "ab"},
  {"\"a\xc0\xaf" "b\"", VALUE_SIZE, "ab"},
  {"\"a\xed\xa0\x80" "b\"", VALUE_SIZE, "ab"},
  {"\"a\xf4\x90\x80\x80" "b\"", VALUE_SIZE, "ab"},
  {"\"a\xff" "b\"", VALUE_SIZE, "ab"},
  {"\"a\xe2\x82\"", VALUE_SIZE, "a"},	/* cut sequence before the quote */
  {"\"\xff\xfe\"", VALUE_SIZE, NULL},

  /* truncation to dst_size - 1, at a character boundary; the closing quote is still found */
  {"\"0123456789\"", 8, "0123456"},
  {"0123456789", 8, "0123456"},
  {"\"0123456789", 8, NULL},
  {"\"ab한\"", 5, "ab"},	/* 3 bytes do not fit in the 2 left */
  {"\"ab한c\"", 5, "ab"},	/* and nothing after it is taken */
  {"\"abc한\"", 7, "abc한"},	/* exactly fits */
  {"abc", 1, NULL},
};

static void
test_parse_value (void)
{
  char what[512];
  size_t i;

  for (i = 0; i < sizeof (value_cases) / sizeof (value_cases[0]); i++)
    {
      const char *expect = value_cases[i].expect;
      char dst[256];
      int rc;

      memset (dst, 'x', sizeof (dst));
      rc = ut_parse_os_release_value (value_cases[i].src, dst, value_cases[i].dst_size);
      snprintf (what, sizeof (what), "value [%s] (size %zu) -> %s%s%s (got %d [%s])", value_cases[i].src,
		value_cases[i].dst_size, expect ? "[" : "", expect ? expect : "failure", expect ? "]" : "", rc, dst);
      if (expect == NULL)
	{
	  check (rc == -1 && dst[0] == '\0', what);
	}
      else
	{
	  check (rc == 0 && strcmp (dst, expect) == 0, what);
	}
    }

  {
    char dst[8] = "x";

    check (ut_parse_os_release_value ("abc", dst, 0) == -1, "value: dst_size 0 fails");
    check (ut_parse_os_release_value ("abc", NULL, 8) == -1, "value: NULL dst fails");
    check (ut_parse_os_release_value (NULL, dst, sizeof (dst)) == -1 && dst[0] == '\0',
	   "value: NULL src fails with \"\"");
  }
}

/* ----------------------------------------------- ut_get_os_release_detail */

static std::string
tmp_path (const char *name)
{
  return std::string (tmp_dir) + "/" + name;
}

static std::string
write_file (const char *name, const std::string &content)
{
  std::string path = tmp_path (name);
  FILE *fp = fopen (path.c_str (), "w");

  if (fp == NULL)
    {
      perror (path.c_str ());
      exit (2);
    }
  fwrite (content.data (), 1, content.size (), fp);
  fclose (fp);
  return path;
}

static void
detail_check (const char *label, const char *path, const char *fallback, size_t buf_size, const char *expect)
{
  char buf[512];
  char what[1024];

  memset (buf, 'x', sizeof (buf));
  ut_get_os_release_detail (path, fallback, buf, buf_size);
  buf[sizeof (buf) - 1] = '\0';
  snprintf (what, sizeof (what), "detail %s -> [%s] (got [%s])", label, expect, buf);
  check (strcmp (buf, expect) == 0, what);
}

static const struct
{
  const char *label;
  const char *content;
  const char *expect;
} detail_cases[] =
{
  {
    "Rocky Linux 8.10",
    "NAME=\"Rocky Linux\"\nVERSION=\"8.10 (Green Obsidian)\"\nID=\"rocky\"\nVERSION_ID=\"8.10\"\n"
    "PRETTY_NAME=\"Rocky Linux 8.10 (Green Obsidian)\"\n",
    "Rocky Linux 8.10 (Green Obsidian)"
  },
  {
    "Ubuntu 22.04",
    "PRETTY_NAME=\"Ubuntu 22.04.4 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"22.04\"\n"
    "VERSION=\"22.04.4 LTS (Jammy Jellyfish)\"\nVERSION_CODENAME=jammy\n",
    "Ubuntu 22.04.4 LTS (Jammy Jellyfish)"
  },
  {"unquoted values", "NAME=Fedora\nVERSION=40\n", "Fedora 40"},
  {
    "comments, blank lines, indentation", "# os-release\n\n  NAME='CentOS Linux'  \n\tVERSION='7 (Core)' # c\n",
    "CentOS Linux 7 (Core)"
  },
  {"CRLF line ends", "NAME=\"Rocky Linux\"\r\nVERSION=\"9.4\"\r\n", "Rocky Linux 9.4"},
  {"no newline at the end", "NAME=Debian\nVERSION=12", "Debian 12"},
  {"the last assignment wins", "NAME=A\nVERSION=1\nNAME=B\nVERSION=2\n", "B 2"},
  {"escapes", "NAME=\"My \\\"OS\\\"\"\nVERSION=\"1 \\$x\"\n", "My \"OS\" 1 $x"},
  {"UTF-8", "NAME=\"한국 리눅스\"\nVERSION=\"1 (테스트)\"\n", "한국 리눅스 1 (테스트)"},
  {"control and invalid bytes", "NAME=\"a\xff" "b\x01" "c\"\nVERSION=\"\xc2\x85" "x\"\n", "abc x"},

  /* without VERSION: PRETTY_NAME, then "NAME VERSION_ID", then NAME */
  {
    "Arch Linux (PRETTY_NAME)", "NAME=\"Arch Linux\"\nPRETTY_NAME=\"Arch Linux\"\nID=arch\nBUILD_ID=rolling\n",
    "Arch Linux"
  },
  {
    "Debian sid (PRETTY_NAME)", "PRETTY_NAME=\"Debian GNU/Linux trixie/sid\"\nNAME=\"Debian GNU/Linux\"\n",
    "Debian GNU/Linux trixie/sid"
  },
  {"NAME VERSION_ID", "NAME=\"Minimal\"\nVERSION_ID=\"3.19\"\n", "Minimal 3.19"},
  {"empty VERSION -> NAME VERSION_ID", "NAME=A\nVERSION=\"\"\nVERSION_ID=2\n", "A 2"},
  {"NAME only", "NAME=Foo\n", "Foo"},
  {"PRETTY_NAME only", "PRETTY_NAME=\"Only Pretty\"\n", "Only Pretty"},
  {"VERSION_ID is not VERSION", "NAME=A\nVERSION_ID=1\n", "A 1"},

  /* "Unknown" */
  {"VERSION_ID only", "VERSION_ID=1\n", "Unknown"},
  {"VERSION only", "VERSION=\"8.10\"\n", "Unknown"},
  {"empty NAME", "NAME=\"\"\nVERSION=1\n", "Unknown"},
  {"unterminated NAME", "NAME=\"A\nVERSION=1\n", "Unknown"},
  {"a malformed last NAME clears it", "NAME=A\nVERSION=1\nNAME=\"B\n", "Unknown"},
  {"lower-case keys", "name=A\nversion=1\n", "Unknown"},
  {"white space before =", "NAME =A\nVERSION =1\n", "Unknown"},
};

static void
test_detail (void)
{
  size_t i;

  for (i = 0; i < sizeof (detail_cases) / sizeof (detail_cases[0]); i++)
    {
      std::string path = write_file ("os-release", detail_cases[i].content);

      detail_check (detail_cases[i].label, path.c_str (), NULL, 512, detail_cases[i].expect);
    }

  /* files that are not read */
  detail_check ("empty file", write_file ("empty", "").c_str (), NULL, 512, "Unknown");
  detail_check ("missing file", tmp_path ("missing").c_str (), NULL, 512, "Unknown");
  detail_check ("directory", tmp_dir, NULL, 512, "Unknown");
  detail_check ("NULL path", NULL, NULL, 512, "Unknown");

  {
    std::string fifo = tmp_path ("fifo");

    if (mkfifo (fifo.c_str (), 0600) == 0)
      {
	detail_check ("FIFO (opened without blocking)", fifo.c_str (), NULL, 512, "Unknown");
      }
    else
      {
	perror ("mkfifo");
	check (false, "detail FIFO: mkfifo failed");
      }
  }

  {
    std::string big = "NAME=A\nVERSION=1\n" + std::string (OS_RELEASE_MAX_FILE_SIZE, '#') + "\n";

    detail_check ("file over the size limit", write_file ("big", big).c_str (), NULL, 512, "Unknown");
  }

  {
    /*
     * An over-long line is ignored as a whole: what follows its first
     * LINE_MAX - 1 bytes is not read as a line of its own.
     */
    std::string text = "NAME=A\nVERSION=1\n";

    text += "X=" + std::string (LINE_MAX - 3, 'x') + "NAME=Evil\n";
    detail_check ("over-long line is ignored", write_file ("long1", text).c_str (), NULL, 512, "A 1");

    text = "NAME=\"" + std::string (LINE_MAX, 'n') + "\"\nNAME=B\nVERSION=2\n";
    detail_check ("over-long NAME line, then a good one", write_file ("long2", text).c_str (), NULL, 512, "B 2");
  }

  {
    /* a value longer than the value buffer is cut */
    std::string text = "NAME=\"" + std::string (300, 'n') + "\"\nVERSION=1\n";

    detail_check ("long value", write_file ("longvalue", text).c_str (), NULL, 512,
		  (std::string (VALUE_SIZE - 1, 'n') + " 1").c_str ());
  }

  {
    std::string path = write_file ("short", "NAME=\"Rocky Linux\"\nVERSION=\"8.10\"\n");
    char buf[4] = "abc";

    detail_check ("into a short buffer", path.c_str (), NULL, 8, "Rocky L");
    ut_get_os_release_detail (path.c_str (), NULL, buf, 0);
    check (strcmp (buf, "abc") == 0, "detail: buf_size 0 leaves buf as it is");
  }
}

/* /usr/lib/os-release is read only when /etc/os-release does not exist */
static void
test_fallback (void)
{
  std::string etc = write_file ("etc", "NAME=Etc\nVERSION=1\n");
  std::string usr = write_file ("usr", "NAME=Usr\nVERSION=2\n");
  std::string noname = write_file ("etc-noname", "ID=x\n");
  std::string missing = tmp_path ("etc-missing");
  std::string dangling = tmp_path ("etc-dangling");
  std::string dir = tmp_path ("etc-dir");

  if (symlink (tmp_path ("nowhere").c_str (), dangling.c_str ()) != 0 || mkdir (dir.c_str (), 0700) != 0)
    {
      perror ("fallback fixtures");
      exit (2);
    }

  detail_check ("both exist: the first", etc.c_str (), usr.c_str (), 512, "Etc 1");
  detail_check ("the first missing: the fallback", missing.c_str (), usr.c_str (), 512, "Usr 2");
  detail_check ("the first a dangling link: the fallback", dangling.c_str (), usr.c_str (), 512, "Usr 2");
  detail_check ("the first without NAME: no fallback", noname.c_str (), usr.c_str (), 512, "Unknown");
  detail_check ("the first a directory: no fallback", dir.c_str (), usr.c_str (), 512, "Unknown");
  detail_check ("both missing", missing.c_str (), tmp_path ("usr-missing").c_str (), 512, "Unknown");
  detail_check ("no fallback given", missing.c_str (), NULL, 512, "Unknown");

  if (getuid () != 0)
    {
      std::string unreadable = write_file ("etc-unreadable", "NAME=Etc\nVERSION=1\n");

      chmod (unreadable.c_str (), 0);
      detail_check ("the first unreadable: no fallback", unreadable.c_str (), usr.c_str (), 512, "Unknown");
      chmod (unreadable.c_str (), 0600);
    }
}

int
main (void)
{
  const char *base = getenv ("TMPDIR");

  snprintf (tmp_dir, sizeof (tmp_dir), "%s/test_os_release.XXXXXX",
	    (base != NULL && base[0] != '\0') ? base : "/tmp");
  if (mkdtemp (tmp_dir) == NULL)
    {
      perror ("mkdtemp");
      return 2;
    }

  test_utf8_char_len ();
  test_parse_value ();
  test_detail ();
  test_fallback ();

  {
    std::string cmd = std::string ("rm -rf '") + tmp_dir + "'";

    if (system (cmd.c_str ()) != 0)
      {
	printf ("could not remove %s\n", tmp_dir);
      }
  }

  printf ("%d of %d checks failed\n", failures, checks);
  return (failures == 0) ? 0 : 1;
}
