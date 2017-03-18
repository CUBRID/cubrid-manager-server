/*
 * Copyright (C) 2014 Search Solution Corporation. All rights reserved by Search Solution.
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
*  cm_server.autoupdate.cpp
*/

#include "cm_server_autoupdate.h"
#include "cm_compress.h"
#include "cm_config.h"
#include "cm_dep.h"

#ifdef WINDOWS
#include <windows.h>
#include <wininet.h>
#include <io.h>
#else
#include <unistd.h>
#endif

#ifdef WINDOWS

#undef UNICODE
#pragma comment(lib, "wininet.lib")

int
generate_update_script (char *patch_name, char *url, char *path,
                        char *_dbmt_error)
{
  unsigned char file_buffer[DOWNLOAD_BUFFER];

  char zip_file[PATH_MAX];
  char zip_folder[PATH_MAX];
  char host_name[NAME_MAX];
  char remote_path[PATH_MAX];
  char shell_name[PATH_MAX];

  HINTERNET handle_open = 0;
  HINTERNET handle_connect = 0;
  HINTERNET handle_request = 0;

  DWORD read_bytes = 0;

  FILE *fout;

  size_t sum_size = 0;

  if (url == NULL || strcmp (url, "") == 0)
    {
      strncpy (host_name, DEFAULT_UPDATE_HOST_NAME, PATH_MAX);
      sprintf (remote_path, DEFAULT_UPDATE_REMOTE_PATH "%s", patch_name);
    }
  else
    {
      // TODO: use a static function instead, and offer more strict conditions.

      char *iter1, *iter2;

      iter1 = strstr (url, "//");
      iter2 = strstr (iter1 + 2, "/");

      strncpy (host_name, iter1 + 2, iter2 - iter1 - 2);
      strncpy (remote_path, iter2, PATH_MAX);
    }

  if (InternetAttemptConnect (0) != ERROR_SUCCESS)
    {
      sprintf (_dbmt_error,
               "InternetAttemptConnect(): CM Server is offline.");
      return ERR_SYSTEM_CALL;
    }

  handle_open =
    InternetOpen (TEXT ("auto_update"), INTERNET_OPEN_TYPE_PRECONFIG, NULL,
                  NULL, 0);
  if (handle_open == NULL)
    {
      sprintf (_dbmt_error, "InternetOpen() :  failed.");

      return ERR_SYSTEM_CALL;
    }

  handle_connect =
    InternetConnect (handle_open, host_name, INTERNET_INVALID_PORT_NUMBER,
                     NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
  if (handle_connect == NULL)
    {
      sprintf (_dbmt_error, "InternetConnect(): failed.");

      InternetCloseHandle (handle_open);

      return ERR_SYSTEM_CALL;
    }

  handle_request =
    HttpOpenRequest (handle_connect, TEXT ("GET"), remote_path, NULL, NULL,
                     NULL, INTERNET_FLAG_RELOAD, 0);
  if (handle_request == NULL)
    {
      sprintf (_dbmt_error, "HttpOpenRequest(): failed.");

      InternetCloseHandle (handle_connect);
      InternetCloseHandle (handle_open);

      return ERR_SYSTEM_CALL;
    }

  if (!HttpSendRequest (handle_request, NULL, 0, NULL, 0))
    {
      int err = GetLastError ();
      sprintf (_dbmt_error,
               "HttpSendRequest(): failed,  an error %d happened.", err);

      InternetCloseHandle (handle_request);
      InternetCloseHandle (handle_connect);
      InternetCloseHandle (handle_open);

      return ERR_SYSTEM_CALL;
    }

  sprintf (zip_file, "%s%s", path, patch_name);
  fout = fopen (zip_file, "wb+");
  if (fout == NULL)
    {
      sprintf (_dbmt_error, "%s", zip_file);
      return ERR_FILE_OPEN_FAIL;
    }

  do
    {

      if (!InternetReadFile
          (handle_request, file_buffer, DOWNLOAD_BUFFER, &read_bytes))
        {
          sprintf (_dbmt_error, "InternetReadFile(): download file failed!");

          InternetCloseHandle (handle_request);
          InternetCloseHandle (handle_connect);
          InternetCloseHandle (handle_open);

          fclose (fout);

          return ERR_SYSTEM_CALL;
        }

      fwrite (file_buffer, sizeof (unsigned char), read_bytes, fout);

      sum_size += read_bytes;
      printf ("sum_size = %d\n", sum_size);

    }
  while (read_bytes == DOWNLOAD_BUFFER);

  fclose (fout);

  strncpy (zip_folder, path, PATH_MAX);
  strcat (zip_folder, "patch");
  // create the folder for extracting zip file, otherwise unzip will fail.
  if (access (zip_folder, 0) != 0 && !CreateDirectory (zip_folder, NULL))
    {
      sprintf (_dbmt_error, "CreateDirectory(): create %s dir failed.",
               zip_folder);
      return ERR_SYSTEM_CALL;
    }

  if (!unzip (zip_file, zip_folder))
    {
      sprintf (_dbmt_error, "unzip %s failed.", zip_file);
      return ERR_SYSTEM_CALL;
    }

  sprintf (shell_name, "%s" SHELL_NAME, path);
  fout = fopen (shell_name, "w+");
  if (fout == NULL)
    {
      sprintf (_dbmt_error, SHELL_NAME);
      return ERR_FILE_OPEN_FAIL;
    }

  // backup
  fprintf (fout, "md %sbackup\n", path);
  fprintf (fout,
           "if exist %s\\bin\\cub_manager.exe copy /y %s\\bin\\cub_manager.exe %sbackup\\.\n",
           sco.szCubrid, sco.szCubrid, path);
  fprintf (fout,
           "if exist %s\\bin\\cm_admin.exe copy /y %s\\bin\\cm_admin.exe %sbackup\\.\n",
           sco.szCubrid, sco.szCubrid, path);

  fprintf (fout, "cubrid service stop\n");
  fprintf (fout, "cub_manager stop\n");

  //update
  fprintf (fout, "if exist %s\\cub_* copy /y %s\\cub_* %s\\bin\\.\n",
           zip_folder, zip_folder, sco.szCubrid);
  fprintf (fout,
           "if exist %s\\cm_admin copy /y %s\\cm_admin.exe %s\\bin\\.\n",
           zip_folder, zip_folder, sco.szCubrid);
  fprintf (fout,
           "for /f %%%%c in ('dir /b %s\\conf\\') do type %s\\conf\\%%%%c >> %s\\conf\\%%%%c\n",
           zip_folder, zip_folder, sco.szCubrid);

  fprintf (fout, "ping 127.0.0.1 -n 40 -w 1000 > nul\n");
  fprintf (fout, "cubrid service start\n");
  fprintf (fout, "cub_manager start\n");
  fprintf (fout, "echo \"CUBRID Manager Server is updated.\"", path);

  fclose (fout);

  return ERR_NO_ERROR;
}

#else

int
generate_update_script (char *patch_name, char *url, char *path,
                        char *_dbmt_error)
{
  FILE *fout;
  char shell_name[PATH_MAX];
  char chmod_cmd[PATH_MAX];

  if (url == NULL || strcmp (url, "") == 0)
    {
      strncpy (url, DEFAULT_PATCH_URL, PATH_MAX);
    }

  sprintf (shell_name, "%s" SHELL_NAME, path);

  fout = fopen (shell_name, "w");
  if (fout == NULL)
    {
      sprintf (_dbmt_error, SHELL_NAME);
      return ERR_FILE_OPEN_FAIL;
    }

  fprintf (fout, "rm -rf %spatch*\n", path);
  fprintf (fout, "wget -T 60 %s -P %s\n", url, path);
  fprintf (fout, "if [ $? -ne 0 ]; then\n");
  fprintf (fout, "\techo \"download patch file failed!\"\nfi\n");

  fprintf (fout, "unzip -u %s%s -d %spatch\n", path, patch_name, path);
  fprintf (fout, "if [ $? -ne 0 ]; then\n");
  fprintf (fout, "\techo \"unzip patch file failed!\"\nfi\n");

  fprintf (fout, "mkdir %sbackup\n", path);
  fprintf (fout,
           "cp %s/bin/cm_admin %s/bin/cub_manager %sbackup/.\n",
           sco.szCubrid, sco.szCubrid, path);
  fprintf (fout,
           "if [ -e %spatch/cub_manager ]; then\n", path);
  fprintf (fout, "\tcp %spatch/cub_* %s/bin/. -f\nfi\n", path, sco.szCubrid);

  fprintf (fout, "if [ -e %spatch/cm_admin ]; then\n", path);
  fprintf (fout, "\tcp %spatch/cm_admin %s/bin/. -f\nfi\n", path,
           sco.szCubrid);


  fprintf (fout, "if [ -d %spatch/conf ]; then\n", path);
  fprintf (fout, "\tfor conf_file in $(ls %spatch/conf)\n\tdo\n", path);
  fprintf (fout, "\t\tcp %s/conf/$conf_file %sbackup/.\n", sco.szCubrid,
           path);
  fprintf (fout,
           "\t\tcat %spatch/conf/$conf_file >> %s/conf/$conf_file\n\tdone\nfi\n",
           path, sco.szCubrid);

  fprintf (fout, "cubrid service restart\n");
  fprintf (fout, "echo \"CUBRID Manager Server is updated.n");

  fclose (fout);

  sprintf (chmod_cmd, "chmod +x %s", shell_name);
  system (chmod_cmd);

  return ERR_NO_ERROR;
}

#endif

mz_bool
unzip (const char *zip_file, const char *unzip_dir)
{

  mz_uint i;

  mz_bool status;

  mz_uint num_files, file_index;

  mz_zip_archive zip_archive;

  char unzip_file[MAX_LINE];

  if (NULL == zip_file || NULL == unzip_dir)
    {
      return MZ_FALSE;
    }

  //Now try to open the archive.
  memset (&zip_archive, 0, sizeof (zip_archive));

  status = mz_zip_reader_init_file (&zip_archive, zip_file, 0);

  if (!status)
    {
      return MZ_FALSE;
    }

  num_files = mz_zip_reader_get_num_files (&zip_archive);

  //Get and print information about each file in the archive.
  for (i = 0; i < num_files; i++)
    {

      mz_zip_archive_file_stat file_stat;
      status = mz_zip_reader_file_stat (&zip_archive, i, &file_stat);

      if (!status)
        {
          mz_zip_reader_end (&zip_archive);
          return MZ_FALSE;
        }

      snprintf (unzip_file, MAX_LINE, "%s/%s", unzip_dir,
                file_stat.m_filename);

      file_index =
        mz_zip_reader_locate_file (&zip_archive, file_stat.m_filename, NULL,
                                   0);

      if (mz_zip_reader_is_file_a_directory (&zip_archive, file_index))
        {
          //create sub directory according to the folder's name, which is zipped in zip file.
#ifdef WINDOWS
          if (access (unzip_file, 0) != 0
              && !CreateDirectory (unzip_file, NULL))
#else
          mode_t old_mode = umask (0);
          if (access (unzip_file, 0) != 0 && mkdir (unzip_file, 0700) != 0)
#endif
            {
#ifndef WINDOWS
              umask (old_mode);
#endif
              mz_zip_reader_end (&zip_archive);
              return MZ_FALSE;
            }
#ifndef WINDOWS
          umask (old_mode);
#endif
          continue;
        }

      status =
        mz_zip_reader_extract_file_to_file (&zip_archive,
                                            file_stat.m_filename, unzip_file,
                                            0);

      if (!status)
        {
          mz_zip_reader_end (&zip_archive);
          return MZ_FALSE;
        }
    }


  mz_zip_reader_end (&zip_archive);

  return MZ_TRUE;

}
