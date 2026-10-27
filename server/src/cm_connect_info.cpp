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
 * cm_connect_info.cpp -
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#if defined(WINDOWS)
#include <process.h>
#else
#include <unistd.h>
#endif

#include "cm_porting.h"
#include "cm_server_util.h"
#include "cm_config.h"
#include "cm_connect_info.h"

int
dbmt_con_search (const char *ip, const char *port, char *cli_ver)
{
  FILE *infile;
  int retval;
  int get_len, buf_len;
  char *strbuf;
  char sbuf[512];
  char ip_t[20], port_t[10];

  /* check if ip is an existing ip */
  retval = 0;
  file_resource_guard guard (*cm_conn_list_mutex (), FID_LOCK_CONN_LIST);
  if (!guard.ok ())
    {
      /*
       * This function has no way to report a message and its normal
       * return domain is {0, 1} (not found/found), not an ERR_* code, so
       * a lock failure is reported the same way an unreadable conlist
       * already is below
       */
      return retval;
    }

  infile = fopen (conf_get_dbmt_file (FID_CONN_LIST, sbuf), "r");
  if (infile != NULL)
    {
      strbuf = NULL;
      buf_len = get_len = 0;
      while ((get_len = ut_getline (&strbuf, &buf_len, infile)) != -1)
	{
	  /* remove character '\n' */
	  strbuf[strlen (strbuf) - 1] = '\0';

	  if (sscanf (strbuf, "%19s %9s", ip_t, port_t) == 2
	      && uStringEqual (ip, ip_t) && uStringEqual (port, port_t))
	    {
	      retval = 1;
	      sscanf (strbuf, "%*s %*s %*s %*s %14s", cli_ver);
	      break;
	    }
	  FREE_MEM (strbuf);
	  buf_len = 0;
	}
      fclose (infile);

      if (strbuf != NULL)
	{
	  FREE_MEM (strbuf);
	}
    }

  return retval;
}

int
dbmt_con_add (const char *ip, const char *port, const char *cli_ver,
	      const char *user_name)
{
  FILE *outfile;
  char strbuf[512];
  int retval;

  file_resource_guard guard (*cm_conn_list_mutex (), FID_LOCK_CONN_LIST);
  if (!guard.ok ())
    {
      return -1;
    }

  retval = -1;
  outfile = fopen (conf_get_dbmt_file (FID_CONN_LIST, strbuf), "a");
  if (outfile != NULL)
    {
      time_to_str (time (NULL), "%04d/%02d/%02d %02d:%02d:%02d", strbuf,
		   TIME_STR_FMT_DATE_TIME);
      fprintf (outfile, "%s %s %s %s %s\n", ip, port, strbuf, cli_ver, user_name);
      fclose (outfile);
      retval = 0;
    }

  return retval;
}

int
dbmt_con_delete (const char *ip, const char *port)
{
  char ip_t[20];
  char port_t[10];
  char version[16];
  char c_date[16];
  char c_time[16];
  char *strbuf;
  int buf_len, get_len;
  FILE *infile, *outfile;
  char tmpfile[PATH_MAX];
  char conn_list_file[512];
  int retval;

  file_resource_guard guard (*cm_conn_list_mutex (), FID_LOCK_CONN_LIST);
  if (!guard.ok ())
    {
      return -1;
    }

  conf_get_dbmt_file (FID_CONN_LIST, conn_list_file);
  infile = fopen (conn_list_file, "r");
  gen_tempfile_path (tmpfile, sco.dbmt_tmp_dir, "DBMT_util", TS_DBMT_CON_DELETE, PATH_MAX);
  outfile = fopen (tmpfile, "w");

  if (infile == NULL || outfile == NULL)
    {
      if (infile != NULL)
	{
	  fclose (infile);
	}
      if (outfile != NULL)
	{
	  fclose (outfile);
	}
      retval = -1;
    }
  else
    {
      strbuf = NULL;
      buf_len = get_len = 0;
      while ((get_len = ut_getline (&strbuf, &buf_len, infile)) != -1)
	{
	  ut_trim (strbuf);
	  sscanf (strbuf, "%19s %9s %15s %15s %15s", ip_t, port_t, c_date,
		  c_time, version);

	  if (!uStringEqual (ip, ip_t) || !uStringEqual (port, port_t))
	    {
	      fprintf (outfile, "%s\n", strbuf);
	    }
	  FREE_MEM (strbuf);
	  buf_len = 0;
	}
      fclose (outfile);
      fclose (infile);

      if (strbuf != NULL)
	{
	  FREE_MEM (strbuf);
	}

      move_file (tmpfile, conn_list_file);
      retval = 0;
    }

  return retval;
}
