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
