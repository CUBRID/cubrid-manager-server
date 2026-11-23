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
 * cm_task_file.h - the files a task writes or runs: a task does not
 *   rewrite an executable file nor create one, and runscript runs only a
 *   script that nobody but the user CMS runs as and root can change.
 *
 *   No CUBRID or CMS dependency, so that it can be tested on its own
 *   (server/test/unit/test_file_write.cpp).
 */

#ifndef _CM_TASK_FILE_H_
#define _CM_TASK_FILE_H_

#include <stddef.h>
#include <stdio.h>

#include <string>

typedef enum
{
  CONTENT_WRITE_OK,
  CONTENT_WRITE_EXECUTABLE,
  CONTENT_WRITE_OPEN_FAIL
} T_CONTENT_WRITE_RESULT;

bool ut_is_executable_mode (unsigned int st_mode);
bool ut_has_executable_extension (const char *path);
T_CONTENT_WRITE_RESULT ut_open_for_content_write (const char *path, FILE **fp, char *err_buf, size_t err_size);
bool ut_is_executable_file (const char *path, char *err_buf, size_t err_size);
T_CONTENT_WRITE_RESULT ut_copy_to_backup (const char *src, const char *dest, char *err_buf, size_t err_size);
bool ut_check_script_path (const char *script_path, const char *script_dir, unsigned int cms_uid,
			   std::string &real_path, char *err_buf, size_t err_size);

#endif /* _CM_TASK_FILE_H_ */
