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
 * ssl_cert_driver.cpp - calls server/src/cm_ssl_cert.cpp from the command
 *   line, for run_ssl_cert_tests.sh (CBRD-27829).
 *
 *   The startup check decides from files on disk, so the scenarios are set
 *   up as files by the script and this program only runs one call and
 *   prints its result. It is linked with cm_ssl_cert.cpp alone: no CUBRID
 *   build and no running manager server are needed.
 *
 *   ssl_cert_driver ensure <crt> <key> YES|NO
 *     cm_ssl_cert_ensure (); prints ret, shipped_in_use and why
 *   ssl_cert_driver generate <crt> <key> [country [common_name [days]]]
 *     cm_ssl_cert_generate (); without country the default options (NULL)
 *   ssl_cert_driver lock <key>
 *     cm_ssl_cert_lock_process (); prints ret and why
 *
 *   SSL_CERT_SAN, if set, is passed as ssl_cert_san of cm.conf.
 *
 *   The manager log is written to $LOGDIR/cub_manager.log (INFO) and
 *   $LOGDIR/cub_manager.err (WARN and above).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cm_log.h"
#include "cm_ssl_cert.h"

/* cm_log.h reads the log paths from the server configuration */
sys_config sco;

static int
usage (void)
{
  fprintf (stderr, "usage: ssl_cert_driver ensure <crt> <key> YES|NO\n"
	   "       ssl_cert_driver generate <crt> <key> [country [common_name [days]]]\n"
	   "       ssl_cert_driver lock <key>\n");
  return 2;
}

int
main (int argc, char **argv)
{
  const char *logdir = getenv ("LOGDIR");
  char msg[4096];
  int ret;

  if (logdir == NULL || logdir[0] == '\0' || argc < 3)
    {
      return usage ();
    }

  memset (&sco, 0, sizeof (sco));
  sco.szCubrid = (char *) logdir;
  snprintf (sco.szAccessLog, sizeof (sco.szAccessLog), "%s/cub_manager.log", logdir);
  snprintf (sco.szErrorLog, sizeof (sco.szErrorLog), "%s/cub_manager.err", logdir);
  sco.iMaxLogFileSize = 100 * 1024 * 1024;
  msg[0] = '\0';

  if (strcmp (argv[1], "lock") == 0 && argc == 3)
    {
      ret = cm_ssl_cert_lock_process (argv[2], msg, sizeof (msg));
      printf ("ret=%d why=%s\n", ret, msg);
      return ret == 0 ? 0 : 1;
    }

  if (strcmp (argv[1], "ensure") == 0 && argc == 5)
    {
      ret = cm_ssl_cert_ensure (argv[2], argv[3], strcmp (argv[4], "YES") == 0, getenv ("SSL_CERT_SAN"), msg,
				sizeof (msg));
      printf ("ret=%d shipped_in_use=%d why=%s\n", ret, cm_ssl_cert_shipped_key_in_use ()? 1 : 0, msg);
      return ret == 0 ? 0 : 1;
    }

  if (strcmp (argv[1], "generate") == 0 && argc <= 7)
    {
      T_CM_SSL_CERT_OPTS opts;

      memset (&opts, 0, sizeof (opts));
      opts.extra_san = getenv ("SSL_CERT_SAN");
      if (argc > 4)
	{
	  opts.country = argv[4];
	}
      if (argc > 5)
	{
	  opts.common_name = argv[5];
	}
      if (argc > 6)
	{
	  opts.days = atoi (argv[6]);
	}
      ret = cm_ssl_cert_generate (argv[2], argv[3], (argc > 4 || opts.extra_san != NULL) ? &opts : NULL, msg,
				  sizeof (msg));
      printf ("ret=%d err=%s\n", ret, msg);
      return ret == 0 ? 0 : 1;
    }

  return usage ();
}
