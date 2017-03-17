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
 * cm_porting.h -
 */

#ifndef    _CM_PORTING_H_
#define    _CM_PORTING_H_

/*
 * IMPORTED SYSTEM HEADER FILES
 */
#include "config.h"

#include <errno.h>

#if defined(WINDOWS) && !defined (EOVERFLOW)
#define EOVERFLOW    75
#endif


#if !defined(WINDOWS)
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#else
#include <direct.h>
#endif

/*
 * IMPORTED OTHER HEADER FILES
 */

/*
 * EXPORTED DEFINITIONS
 */
#if defined(WINDOWS)
#define PATH_MAX    256
#endif

#if !defined(NAME_MAX)
#define NAME_MAX 256
#endif

#define MOVE_FILE(SRC_FILE, DEST_FILE)    \
    (unlink(DEST_FILE) || 1 ? rename(SRC_FILE, DEST_FILE) : -1)

#if defined(WINDOWS)
#define CLOSE_SOCKET(X)        if (!IS_INVALID_SOCKET(X)) closesocket(X)
#else
#define CLOSE_SOCKET(X)        if (!IS_INVALID_SOCKET(X)) close(X)
#endif

#if defined(WINDOWS)
#define    mkdir(dir, mode)               _mkdir(dir)
#define    access(dir, mode)              _access(dir, mode)
#define unlink(file)                      _unlink(file)
#define getpid()                          _getpid()
#define O_RDONLY                          _O_RDONLY
#define strcasecmp(str1, str2)            _stricmp(str1, str2)
#define strncasecmp(str1, str2, size)     _strnicmp(str1, str2, size)
#define snprintf                          _snprintf

#define R_OK            4
#define W_OK            2
#define F_OK            0
#define X_OK            F_OK

/*
* MAXHOSTNAMELEN definition
* This is defined in sys/param.h on the linux.
*/
#define MAXHOSTNAMELEN 64

#endif

#if defined(WINDOWS)
#define SLEEP_SEC(X)                Sleep((X) * 1000)
#define SLEEP_MILISEC(sec, msec)    Sleep((sec) * 1000 + (msec))
#else
#define SLEEP_SEC(X)                sleep(X)
#define    SLEEP_MILISEC(sec, msec)                                     \
            do {                                                        \
              struct timeval sleep_time_val;                            \
              sleep_time_val.tv_sec = sec;                              \
              sleep_time_val.tv_usec = (msec) * 1000;                   \
              select(0, 0, 0, 0, &sleep_time_val);                      \
            } while(0)
#endif

#if defined(WINDOWS)
#define TIMEVAL_MAKE(X)        _ftime(X)
#define TIMEVAL_GET_SEC(X)    ((int) ((X)->time))
#define TIMEVAL_GET_MSEC(X)    ((int) ((X)->millitm))
#else
#define TIMEVAL_MAKE(X)        gettimeofday(X, NULL)
#define TIMEVAL_GET_SEC(X)    ((int) ((X)->tv_sec))
#define TIMEVAL_GET_MSEC(X)    ((int) (((X)->tv_usec) / 1000))
#endif

#if defined(WINDOWS)
#define THREAD_BEGIN(THR_ID, FUNC, ARG)                                   \
    do {                                                                  \
      THR_ID = _beginthread(FUNC, 0, (void*) (ARG));                      \
    } while(0)
#elif HPUX10_2
#define    THREAD_BEGIN(THR_ID, FUNC, ARG)                                \
    do {                                                                  \
      pthread_create(&(THR_ID), pthread_attr_default, FUNC, ARG);         \
      pthread_detach(THR_ID);                                             \
    } while (0)
#elif UNIXWARE7
#define THREAD_BEGIN(THR_ID, FUNC, ARG)                                   \
    do {                                                                  \
      pthread_attr_t    thread_attr;                                      \
      pthread_attr_init(&thread_attr);                                    \
      pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED); \
      pthread_attr_setstacksize(&thread_attr, 100 * 1024);                \
      if (pthread_create(&(THR_ID), &thread_attr, FUNC, ARG) < 0){        \
        free ((void *) ARG);                                              \
        ARG = NULL;                                                       \
      }                                                                   \
      pthread_attr_destroy(&thread_attr);                                 \
    } while (0)
#else
#define THREAD_BEGIN(THR_ID, FUNC, ARG)                                   \
    do {                                                                  \
      pthread_attr_t    thread_attr;                                      \
      pthread_attr_init(&thread_attr);                                    \
      pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED); \
      if (pthread_create(&(THR_ID), &thread_attr, FUNC, ARG) < 0){        \
        free ((void *) ARG);                                              \
        ARG = NULL;                                                       \
      }                                                                   \
      pthread_attr_destroy(&thread_attr);                                 \
    } while (0)
#endif

#if defined(WINDOWS)
#define THREAD_CANCEL(THR_ID)                                             \
    do{                                                                   \
          if (THR_ID){                                                    \
        TerminateThread((HANDLE)THR_ID, 0);                               \
          }                                                               \
    } while(0)
#else
#define THREAD_CANCEL(THR_ID)                                             \
    do{                                                                   \
          if (THR_ID){                                                    \
        pthread_cancel (THR_ID);                                          \
          }                                                               \
    } while(0)
#endif


#ifdef UNIXWARE7
#define PROC_FORK()    fork1()
#else
#define PROC_FORK()    fork()
#endif

/*
 * EXPORTED TYPE DEFINITIONS
 */

#if defined(WINDOWS)
typedef struct _timeb T_TIMEVAL;
#else
typedef struct timeval T_TIMEVAL;
#endif

#if defined(WINDOWS) || defined(SOLARIS) || defined(HPUX)
typedef int T_SOCKLEN;
#elif defined(UNIXWARE7)
typedef size_t T_SOCKLEN;
#else
typedef socklen_t T_SOCKLEN;
#endif

#if defined(WINDOWS)
#define IS_INVALID_SOCKET(socket) ((socket) == INVALID_SOCKET)
#else
typedef int SOCKET;
#define INVALID_SOCKET (-1)
#define IS_INVALID_SOCKET(socket) ((socket) < 0)
#endif

#ifdef HAVE_INT64_T
typedef int64_t INT64;
#elif SIZEOF_LONG == 8
typedef long INT64;
#elif SIZEOF_LONG_LONG == 8
/* typedef long long INT64; */
#else
#error "Error: INT64"
#endif

/*
 * EXPORTED DEFINITIONS
 */

#if defined(WINDOWS)
#define THREAD_FUNC    void
#define T_THREAD       uintptr_t
#else
#define THREAD_FUNC    void*
#define T_THREAD       pthread_t
#endif

#if defined(WINDOWS)
#define DEL_FILE        "del"
#define DEL_FILE_OPT    "/F /Q"
#define DEL_DIR         "rmdir"
#define DEL_DIR_OPT     "/S /Q"
#else
#define DEL_FILE        "rm"
#define DEL_FILE_OPT    "-f"
#define DEL_DIR         "rm"
#define DEL_DIR_OPT     "-rf"
#endif

#if !defined(WINDOWS)
#define TRUE 1
#define FALSE 0
#endif

#if !HAVE_BZERO && HAVE_MEMSET
#define bzero(buf, bytes)      ((void) memset (buf, 0, bytes))
#endif

/* MUTEX & COND TYPE */
#if defined(WINDOWS)
#define MUTEX_T            HANDLE
#define COND_T             HANDLE
#else
#define MUTEX_T            pthread_mutex_t
#define COND_T             pthread_cond_t
#endif

/* MUTEX SIGNAL */
#if defined(WINDOWS)
#define MUTEX_INIT(MUTEX)                                        \
       ((MUTEX = CreateMutex(NULL, FALSE, NULL)) != NULL ?       \
                0 : -1 )

#define MUTEX_DESTROY(handle)                                    \
    ( (handle = (void *)(!CloseHandle(handle))) == 0 ?           \
       0 : -1)

#define MUTEX_LOCK(mutex)                                        \
    ( WaitForSingleObject(mutex, INFINITE) == WAIT_OBJECT_0 ?    \
    0 : -1)

#define MUTEX_UNLOCK(mutex)                                      \
    ( ReleaseMutex(mutex) != 0 ?  0 : -1 )
#elif HPUX10_2
#define    MUTEX_INIT(MUTEX)                                     \
    pthread_mutex_init(MUTEX, pthread_mutexattr_default);
#else

#define MUTEX_INIT(mutex)                                        \
    ( pthread_mutex_init(&(mutex), NULL) == 0 ?                  \
    0 : -1)

#define MUTEX_DESTROY(mutex)                                     \
    ( pthread_mutex_destroy(&(mutex)) == 0 ?                     \
    0 : -1)

#define MUTEX_LOCK(mutex)                                        \
    ( pthread_mutex_lock(&(mutex)) == 0 ?                        \
    0 : -1)

#define MUTEX_UNLOCK(mutex)                                      \
    ( pthread_mutex_unlock(&(mutex)) == 0 ?                      \
    0 : -1)

#endif

/* CONDITION SIGNAL */
#if defined(WINDOWS)
/* Creates an Event of auto-reset mode */
#define COND_INIT(cond_var)                                                  \
    ((cond_var = CreateEvent(NULL, FALSE, FALSE, NULL)) != NULL ? 0 : -1)

#define COND_WAIT(cond_var, mutex)                                            \
    (SignalObjectAndWait(mutex, cond_var, INFINITE, FALSE) == WAIT_OBJECT_0 ? \
    0 : -1)

#define COND_TIMEDWAIT(cond_var, mutex, timeout)                              \
    SignalObjectAndWait(mutex, cond_var, timeout, FALSE)

/* For an auto-reset event object, PulseEvent() returns after releasing a
 * waiting thread. If no threads are waiting, nothing happens - it simply
 * returns.
 */
#define COND_SIGNAL(cond_var)        (PulseEvent(cond_var) !=0 ? 0 : -1)

/* SetEvent() just wakes up one thread. It's actually not the broadcast. */
#define COND_BROADCAST(cond_var)     (SetEvent(cond_var) !=0 ? 0 : -1 )

#define COND_DESTROY(cond_var)                                               \
    ( (cond_var = (void *)CloseHandle(cond_var)) != 0 ? 0 : -1)
#else
/* Caution:
 *   There are some differences between pthreads and win32 threads
 *   over these macros of condition signal. Under the win32 threads,
 *     1. COND_WAIT() returns without acquiring lock.
 *     2. COND_BROADCAST() does not release all waiting threads, but keep
 *        signaling until only a thread is released. It continues signaling
 *        even if there is no thread to be waken up when this macro is called.
 *   You should take these into account for portability.
 */
#define COND_INIT(condvar)           pthread_cond_init(&(condvar), NULL)
#define COND_WAIT(c, m)              pthread_cond_wait(&(c), &(m))
#define COND_TIMEDWAIT(c, m, t)      pthread_cond_timedwait(&(c), &(m), &(t))
#define COND_SIGNAL(c)               pthread_cond_signal(&(c))
#define COND_BROADCAST(c)            pthread_cond_broadcast(&(c))
#define COND_DESTROY(condvar)        pthread_cond_destroy(&(condvar))
#endif

#endif /* _CM_PORTING_H_ */
