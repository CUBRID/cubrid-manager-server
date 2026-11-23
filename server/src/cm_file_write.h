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
 * cm_file_write.h - open a file to replace its contents through a task,
 *   refusing an executable file (CBRD-27831).
 *
 *   No CUBRID or CMS dependency, so that it can be tested on its own
 *   (server/test/unit/test_file_write.cpp).
 */

#ifndef _CM_FILE_WRITE_H_
#define _CM_FILE_WRITE_H_

#include <stddef.h>
#include <stdio.h>

typedef enum
{
  CONTENT_WRITE_OK,
  CONTENT_WRITE_EXECUTABLE,
  CONTENT_WRITE_OPEN_FAIL
} T_CONTENT_WRITE_RESULT;

bool ut_is_executable_mode (unsigned int st_mode);
bool ut_has_executable_extension (const char *path);
T_CONTENT_WRITE_RESULT ut_open_for_content_write (const char *path, FILE **fp, char *err_buf, size_t err_size);

#endif /* _CM_FILE_WRITE_H_ */
