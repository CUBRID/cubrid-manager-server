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


#ifndef __CM_LOG__H__
#define __CM_LOG__H__
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <iostream>
#include <map>
#include <list>

#if defined(WINDOWS)
#include <process.h>
#include <io.h>
#else
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <dirent.h>        /* opendir() ...   */
#endif

#include "cm_config.h"

using namespace std;

#define DEFAULT_LOG_LEVEL xINFO

#ifdef WINDOWS
#define mutex_t                           CRITICAL_SECTION
#define mutex_init(mutex)                 InitializeCriticalSection(&mutex)
#define mutex_lock(mutex)                 EnterCriticalSection(&mutex)
#define mutex_unlock(mutex)               LeaveCriticalSection(&mutex)
#define mutex_destory(mutex)              DeleteCriticalSection(&mutex)
#else
#define mutex_t                           pthread_mutex_t
#define mutex_init(mutex)                 pthread_mutex_init(&mutex, NULL)
#define mutex_lock(mutex)                 pthread_mutex_lock(&mutex)
#define mutex_unlock(mutex)               pthread_mutex_unlock(&mutex)
#define mutex_destory(mutex)              pthread_mutex_destroy(&mutex)
#endif

#define MAX_DATE_TIME_LENGTH   128

class CLog
{
  public:
    enum LOGLEVEL
    {
      xFATAL = 0,
      xERROR = 1,
      xWARN = 2,
      xINFO = 3,
      xDEBUG = 4,
    };

  protected:
    CLog ()
    {
      sLogLevel = CLog::xINFO;
      m_lTruncate = sco.iMaxLogFileSize;
      m_pLogFile = fopen (sco.szAccessLog, "a");
      m_pErrFile = fopen (sco.szErrorLog, "a");
      mutex_init (m_cs);
    };

    CLog (bool bappend, LOGLEVEL loglevel =
            CLog::DEFAULT_LOG_LEVEL, long maxloglen = sco.iMaxLogFileSize)
    {
      sLogLevel = loglevel;
      m_lTruncate = maxloglen;

      m_pLogFile = fopen (sco.szAccessLog, bappend ? "a" : "w");
      m_pErrFile = fopen (sco.szErrorLog, bappend ? "a" : "w");

      mutex_init (m_cs);
    }

  public:
    ~CLog ()
    {
      if (m_pLogFile)
        {
          fclose (m_pLogFile);
          m_pLogFile = NULL;
        }

      if (m_pErrFile)
        {
          fclose (m_pErrFile);
          m_pErrFile = NULL;
        }

      mutex_destory (m_cs);
    }

  private:
    LOGLEVEL _logLevel ()
    {
      return sLogLevel;
    }

    string _get_format_time ()
    {
      char buff[MAX_DATE_TIME_LENGTH] = "unkonwn";
      time_t lt;
      time (&lt);
      tm *t = localtime (&lt);
      if (t)
        {
          strftime (buff, MAX_DATE_TIME_LENGTH, "%Y%m%d %H:%M:%S", t);
        }
      return string (buff);
    }

    void
    _init_file_hander (void)
    {
      if (m_pLogFile != NULL)
        {
          fclose (m_pLogFile);
          m_pLogFile = NULL;
        }
      if (m_pErrFile != NULL)
        {
          fclose (m_pErrFile);
          m_pErrFile = NULL;
        }
    }

    void
    _get_current_time_year_mon_day_hour_minute_second (char *current_time)
    {
      time_t cur_time;

      time (&cur_time);
      strftime (current_time, MAX_DATE_TIME_LENGTH, "%Y%m%d%H%M%S", localtime (&cur_time));
    }

#if defined(WINDOWS)
    unsigned int
    _get_files_count (list < string > &files_list, const char *roor_dir, string special_key = "")
    {
      HANDLE handle;
      WIN32_FIND_DATA ffd;
      char find_path[PATH_MAX];
      string cms_log_name;

      snprintf (find_path, PATH_MAX, "%s/*", roor_dir);

      handle = FindFirstFile (find_path, &ffd);
      if (handle == INVALID_HANDLE_VALUE)
        {
          return 0;
        }
      while (FindNextFile (handle, &ffd))
        {
          if (ffd.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN
              || ffd.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM)
            {
              continue;
            }
          else if (! (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            {
              cms_log_name = ffd.cFileName;
              if (special_key.length() == 0)
                {
                  files_list.push_back (cms_log_name);
                }
              else
                {
                  if (cms_log_name.find (special_key) < cms_log_name.length())
                    {
                      files_list.push_back (cms_log_name);
                    }
                }
            }
        }
      FindClose (handle);

      return (unsigned int) files_list.size();
    }

#else

    unsigned int
    _get_files_count (list < string > &files_list, const char *roor_dir, string special_key = "")
    {
      DIR *dirptr = NULL;
      struct dirent *entry;
      string cms_log_name;

      if ((dirptr = opendir (roor_dir)) == NULL)
        {
          return 0;
        }
      while ((entry = readdir (dirptr)) != NULL)
        {
          if (strcmp (entry->d_name, ".") == 0 || strcmp (entry->d_name, "..") == 0)
            {
              continue;
            }

          cms_log_name = entry->d_name;

          if (special_key.length() == 0)
            {
              files_list.push_back (cms_log_name);
            }
          else
            {
              if (cms_log_name.find (special_key) < cms_log_name.length())
                {

                  files_list.push_back (cms_log_name);
                }
            }
        }

      closedir (dirptr);
      return files_list.size();
    }
#endif

    void
    _remove_oldest_file (list < string > &files_list)
    {
      list < string >::iterator itor;
      list < string > files_mtime_list;
      char log_full_path[PATH_MAX];
      char oldest_file[PATH_MAX];
      struct stat st;
      long oldest_time = LONG_MAX;

      char log_path[PATH_MAX];
      snprintf (log_path, PATH_MAX, "%s/%s", sco.szCubrid, DBMT_LOG_DIR);

      if (files_list.empty() == true)
        {
          return;
        }

      for (itor = files_list.begin(); itor != files_list.end(); itor++)
        {
          snprintf (log_full_path, PATH_MAX, "%s/%s", log_path, (*itor).c_str());
          stat (log_full_path, &st);
          if ((long) st.st_mtime < oldest_time)
            {
              oldest_time = (long) st.st_mtime;
              snprintf (oldest_file, PATH_MAX, "%s", log_full_path);
            }
        }

      unlink (oldest_file);
    }

    bool
    _backup_log_files (char *base_log_path, string error_log_name, string log_name)
    {
      int ret_backup_log = -1;
      int ret_backup_err = -1;
      char backup_log_name[PATH_MAX];
      char backup_err_name[PATH_MAX];
      char cur_time[MAX_DATE_TIME_LENGTH];

      backup_log_name[0] = '\0';
      backup_err_name[0] = '\0';
      cur_time[0] = '\0';

      _get_current_time_year_mon_day_hour_minute_second (cur_time);
      snprintf (backup_err_name, PATH_MAX, "%s/%s.%s", base_log_path, error_log_name.c_str(), cur_time);
      snprintf (backup_log_name, PATH_MAX, "%s/%s.%s", base_log_path, log_name.c_str(), cur_time);

      ret_backup_log = rename (sco.szAccessLog, backup_log_name);
      ret_backup_err = rename (sco.szErrorLog, backup_err_name);

      if ((ret_backup_log == -1) || (ret_backup_err == -1))
        {
          return false;
        }
      return true;
    }


  public:

    static CLog *GetInstance (unsigned int logLevel)
    {
      static CLog *instance_log = NULL;
      static CLog *instance_err = NULL;

      if ((logLevel <= CLog::xWARN) && (logLevel >= CLog::xFATAL))
        {
          // write log into error log file

          if ((instance_err == NULL) || (access (sco.szErrorLog, F_OK) < 0))
            {
              instance_err = new CLog (TRUE);
            }
          return instance_err;
        }
      else
        {
          // write log into normal log file
          if ((instance_log == NULL) || (access (sco.szAccessLog, F_OK) < 0))
            {
              instance_log = new CLog (TRUE);
            }
          return instance_log;
        }
    }

    void setLogLevel (const unsigned int level)
    {
      sLogLevel = (LOGLEVEL) level;
    }

    void formatLog (const int iPriority, const char *fmt, ...)
    {
      char log_path[PATH_MAX];
      list < string > log_files_list;

      string error_log_name = "cub_manager.err";
      string log_name = "cub_manager.log";

      log_path[0] = '\0';
      snprintf (log_path, PATH_MAX, "%s/%s", sco.szCubrid, DBMT_LOG_DIR);

      //check log level
      if (iPriority > _logLevel ())
        {
          return;
        }

      //format log message
      const char *strLevel;
      bool isErrorLog = false;
      switch (iPriority)
        {
        case CLog::xFATAL:
          strLevel = "FATAL";
          isErrorLog = true;
          break;
        case CLog::xERROR:
          strLevel = "ERROR";
          isErrorLog = true;
          break;
        case CLog::xWARN:
          strLevel = " WARN";
          isErrorLog = true;
          break;
        case CLog::xINFO:
          strLevel = " INFO";
          break;
        case CLog::xDEBUG:
        default:
          strLevel = "DEBUG";
          break;
        }

      if (isErrorLog == true)
        {
          if (m_pErrFile == NULL)
            {
              return;
            }
        }
      else
        {
          if (m_pLogFile == NULL)
            {
              return;
            }
        }

      //format log data
      size_t size = 1024;
      char *buffer = new char[size];
      memset (buffer, 0, size);

      while (1)
        {
          va_list args;
          va_start (args, fmt);
#ifdef _WIN32
          int n = _vsnprintf (buffer, size, fmt, args);
#else
          int n = vsnprintf (buffer, size, fmt, args);
#endif
          va_end (args);
          if ((n > -1) && (static_cast < size_t > (n) < size))
            {
              break;
            }

          size = (n > -1) ? n + 1 : size * 2;
          delete[]buffer;
          buffer = new char[size];
          memset (buffer, 0, size);
        }

      bool shouldBackupFiles = false;

      if (isErrorLog == true)
        {
          mutex_lock (m_cs);

          fprintf (m_pErrFile, "[%s] [%s] [%6d] %s\n",
                   _get_format_time ().c_str (), strLevel, getpid (), buffer);
          fflush (m_pErrFile);

          if (ftell (m_pErrFile) > m_lTruncate)
            {
              shouldBackupFiles = true;
            }
          mutex_unlock (m_cs);
        }
      else
        {
          mutex_lock (m_cs);

          fprintf (m_pLogFile, "[%s] [%s] [%6d] %s\n",
                   _get_format_time ().c_str (), strLevel, getpid (), buffer);

          fflush (m_pLogFile);

          if (ftell (m_pLogFile) > m_lTruncate)
            {
              shouldBackupFiles = true;
            }
          mutex_unlock (m_cs);
        }

      // backup log when the file grow too large
      if (shouldBackupFiles == true)
        {
          mutex_lock (m_cs);

          // init open file - close them firstly
          _init_file_hander ();

          // then move the cub_manager.log into new name log file.
          _backup_log_files (log_path, error_log_name, log_name);

          // remove the oldest file
          if (_get_files_count (log_files_list, log_path, error_log_name) > (unsigned int) sco.iMaxLogFiles)
            {
              _remove_oldest_file (log_files_list);
            }

          log_files_list.clear();
          // remove the oldest file
          if (_get_files_count (log_files_list, log_path, log_name) > (unsigned int) sco.iMaxLogFiles)
            {
              _remove_oldest_file (log_files_list);
            }
          mutex_unlock (m_cs);
        }
      delete[]buffer;
    }

  private:
    LOGLEVEL sLogLevel;
    mutex_t m_cs;
    FILE *m_pLogFile;
    FILE *m_pErrFile;
    long m_lTruncate;

};

#define STRINGIZE2(s) #s
#define STRINGIZE(s)  STRINGIZE2(s)

#ifndef LogPrefix
#define LogPrefix(fmt) std::string("[").append(__FUNCTION__).append(":").append(STRINGIZE(__LINE__)).append("] ").append(fmt).c_str()
#endif

#define LOG_DEBUG(fmt, ...) \
    CLog::GetInstance(CLog::xDEBUG)->formatLog(CLog::xDEBUG, LogPrefix(fmt), ##__VA_ARGS__)

#define LOG_INFO(fmt, ...) \
    CLog::GetInstance(CLog::xINFO)->formatLog(CLog::xINFO, LogPrefix(fmt),  ##__VA_ARGS__)

#define LOG_WARN(fmt, ...) \
    CLog::GetInstance(CLog::xWARN)->formatLog(CLog::xWARN, LogPrefix(fmt), ##__VA_ARGS__)

#define LOG_ERROR(fmt, ...) \
    CLog::GetInstance(CLog::xERROR)->formatLog(CLog::xERROR, LogPrefix(fmt), ##__VA_ARGS__)

#define LOG_FATAL(fmt, ...) \
    CLog::GetInstance(CLog::xFATAL)->formatLog(CLog::xFATAL, LogPrefix(fmt), ##__VA_ARGS__)

#endif
