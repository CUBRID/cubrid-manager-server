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
 * cm_server_util.h -
 */

#ifndef _CM_SERVER_UTIL_H_
#define _CM_SERVER_UTIL_H_

#include "cm_porting.h"
#include "cm_dep.h"
#include "cm_cmd_exec.h"
#include "cm_job_task.h"

#ifndef WINDOWS
#include <sys/select.h>
#include <sys/types.h>
#include <sys/param.h>
#include <limits.h>
#include <stdint.h>
#else
#ifndef uint64_t
typedef unsigned __int64 uint64_t;
#endif
#endif

#define makestring1(x) #x
#define makestring(x) makestring1(x)

#define TOKEN_LENGTH 128    /* multiple of 8 */
#define TOKEN_ENC_LENGTH     (TOKEN_LENGTH * 2 + 1)
#define PASSWD_LENGTH 32
#define PASSWD_ENC_LENGTH    (PASSWD_LENGTH * 2 + 1)

#define REMOVE_DIR_FORCED    1
#define REMOVE_EMPTY_DIR     0

#define MAX_AUTOQUERY_SCRIPT_SIZE          4095
#define MAX_JOB_CONFIG_FILE_LINE_LENGTH    (4096 + 256)

#define BYTES_IN_K (1024)
#define BYTES_IN_M (1024 * 1024)
#define BYTES_IN_G (1024 * 1024 * 1024)

#define RSA_KEY_SIZE 1024

#ifdef _DEBUG_
#include "deb.h"
#define MALLOC(p) debug_malloc(p)
#else
#define MALLOC(p) malloc(p)
#endif

#define FREE_MEM(PTR)        \
    do {                     \
      if (PTR) {             \
        free(PTR);           \
        PTR = 0;             \
      }                      \
    } while (0)

#define REALLOC(PTR, SIZE)   \
    (PTR == NULL) ? malloc(SIZE) : realloc(PTR, SIZE)

#ifndef MAX
#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#endif

#ifndef MIN
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#endif

#define MAKE_MUTIPLE_EIGHT(num) (((num) + (8) - 1) & ~((8) - 1))

#ifdef AIX
//the size of stack per thread
#define AIX_STACKSIZE_PER_THREAD           (10*1024*1024)
#endif

typedef enum
{
  TIME_STR_FMT_DATE = NV_ADD_DATE,
  TIME_STR_FMT_TIME = NV_ADD_TIME,
  TIME_STR_FMT_DATE_TIME = NV_ADD_DATE_TIME
} T_TIME_STR_FMT_TYPE;

typedef struct
{
  uint64_t cpu_user;
  uint64_t cpu_kernel;
  uint64_t cpu_idle;
  uint64_t cpu_iowait;
  uint64_t mem_physical_total;
  uint64_t mem_physical_free;
  uint64_t mem_swap_total;
  uint64_t mem_swap_free;
} T_CMS_HOST_STAT;

typedef struct
{
  int pid;
  uint64_t cpu_kernel;
  uint64_t cpu_user;
  uint64_t mem_physical;
  uint64_t mem_virtual;    /* size item in statm file */
} T_CMS_PROC_STAT;

int _op_check_is_localhost (char *token, char *tmpdbname);
void append_host_to_dbname (char *name_buf, const char *dbname,
                            int buf_len);
void *increase_capacity (void *ptr, int block_size, int old_count,
                         int new_count);
char *strcpy_limit (char *dest, const char *src, int buf_len);
int ut_getdelim (char **lineptr, int *n, int delimiter, FILE *fp);
int ut_getline (char **lineptr, int *n, FILE *fp);
void ut_error_log (nvplist *req, const char *errmsg);
void ut_access_log (nvplist *req, const char *msg);
void uRemoveCRLF (char *str);
int uStringEqual (const char *str1, const char *str2);
int uStringEqualIgnoreCase (const char *str1, const char *str2);
int ut_gettaskcode (char *task);
int ut_send_response (SOCKET fd, nvplist *res);
int ut_receive_request (SOCKET fd, nvplist *req);
void ut_daemon_start (void);
void ut_dump_file_to_string (char *string, char *fname);
int uRetrieveDBDirectory (const char *dbname, char *target);
int _isRegisteredDB (char *);
//int uReadDBnfo (char *);
void uWriteDBnfo (void);
void uWriteDBnfo2 (T_SERVER_STATUS_RESULT *cmd_res);
int ut_get_dblist (nvplist *res, char dbdir_flag);
int uCreateLockFile (char *filename);
void uRemoveLockFile (int fd);
int uCreateDir (char *path);
int folder_copy (const char *src_dir, const char *dest_dir);
int uRemoveDir (char *dir, int remove_file_in_dir);
int string_tokenize_accept_laststring_space (char *str, char *tok[],
    int num_tok);
int make_version_info (const char *cli_ver, int *major_ver, int *minor_ver);
int file_copy (char *src_file, char *dest_file);
int move_file (char *src_file, char *dest_file);
void close_all_fds (int init_fd);
char *ut_trim (char *str);
void server_fd_clear (fd_set srv_fds);
int ut_write_pid (char *pid_file);
int ut_disk_free_space (char *path);
char *ip2str (unsigned char *ip, char *ip_str);
int string_tokenize (char *str, char *tok[], int num_tok);
int string_tokenize2 (char *str, char *tok[], int num_tok, int c);
int ut_get_task_info (const char *task, char *access_log_flag,
                      T_TASK_FUNC *task_func, T_USER_AUTH *auth);
char *time_to_str (time_t t, const char *fmt, char *buf, int type);
int read_from_socket (SOCKET fd, char *buf, int size);
int write_to_socket (SOCKET fd, const char *buf, int size);
int is_cmserver_process (int pid, const char *module_name);
int make_default_env (void);
#if defined(WINDOWS)
void remove_end_of_dir_ch (char *path);
#endif

#if defined(WINDOWS)
#define popen _popen
#define pclose _pclose
int kill (int pid, int signo);
void unix_style_path (char *path);
char *nt_style_path (char *path, char *new_path_buf);
#endif

int _ut_get_dbaccess (nvplist *req, char *dbid, char *dbpasswd);
void uGenerateStatus (nvplist *req, nvplist *res, int retval,
                      const char *_dbmt_error);
int ut_validate_token (nvplist *req);
void _ut_timeval_diff (struct timeval *start, struct timeval *end,
                       int *res_msec);
char *ut_token_generate (char *client_ip, char *client_port,
                         char *dbmt_id, int proc_id, time_t login_time);
void _accept_connection (nvplist *cli_request, nvplist *cli_response);
#if defined(WINDOWS)
int gettimeofday (struct timeval *tp, void *tzp);
#endif
int ut_run_child (const char *bin_path, const char *const argv[],
                  int wait_flag, const char *stdin_file,
                  const char *stdout_file, const char *stderr_file, int *exit_status);

int IsValidUserName (const char *pUserName);
int ut_validate_auth (nvplist *req);
int ut_get_token_active_time (time_t *active_time);
int remove_extra_subdir (const char *dirpath, const char *pattern,
                         unsigned int save_num);
int ut_get_filename (char *fullpath, int with_ext, char *ret_filename);
int ut_get_host_stat (T_CMS_HOST_STAT *stat, char *_dbmt_error);
int ut_get_proc_stat (T_CMS_PROC_STAT *stat, int pid);
int ut_record_cubrid_utility_log_stderr (const char *msg);
int ut_record_cubrid_utility_log_stdout (const char *msg);
int run_child_cwd (const char *const argv[], const char *dir, int wait_flag,
                     const char *stdin_file, char *stdout_file, char *stderr_file,
                     int *exit_status);
int run_child_linux (const char *pname, const char *const argv[], int wait_flag,
                     const char *stdin_file, char *stdout_file, char *stderr_file,
                     int *exit_status);
void write_manager_access_log (const char *protocol_str, const char *msg);
void write_manager_error_log (const char *protocol_str, const char *msg);

#endif                /* _CM_SERVER_UTIL_H_ */
