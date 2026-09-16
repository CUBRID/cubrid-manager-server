#
#  Copyright 2016 CUBRID Corporation
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#

# Builds the CUBRID Manager server either as part of a CUBRID build (add_subdirectory
# from the top-level CMakeLists.txt) or on its own through build_cmake.sh, which points
# this at a CUBRID build or install tree.
#
# The autotools build in this directory is left in place: 11.4 and earlier drive it from
# their own CMakeLists.txt and must keep working unchanged.

cmake_minimum_required(VERSION 3.21)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  set(CMS_STANDALONE TRUE)
  project(CUBRID-Manager-Server C CXX)
else()
  set(CMS_STANDALONE FALSE)
endif()

if(NOT UNIX)
  message(FATAL_ERROR "The CMake build of the manager server is UNIX only; use build.bat on Windows.")
endif()

# Do not inherit the server's compile flags and include path when built in its tree. Its
# warning set is -Werror, which this code has never been held to, and its generated
# version.h would land on the include path and clash with the manager's own version
# macros. Both were absent when this was built as an ExternalProject, so keep it that
# way. Build-type flags (-O2, -g) are separate variables and are still inherited.
set(CMAKE_C_FLAGS "")
set(CMAKE_CXX_FLAGS "")
set_property(DIRECTORY PROPERTY INCLUDE_DIRECTORIES "")
set_property(DIRECTORY PROPERTY COMPILE_DEFINITIONS "")

find_package(Threads REQUIRED)

# config.h, which cm_porting.h includes. The automake build gets it from autoconf; here
# only the macros the sources actually test are checked - see cmake/config.h.cmake.
include(CheckIncludeFile)
include(CheckFunctionExists)
include(CheckTypeSize)
check_function_exists(bzero HAVE_BZERO)
check_function_exists(memset HAVE_MEMSET)
check_function_exists(getopt_long HAVE_GETOPT_LONG)
check_include_file(getopt.h HAVE_GETOPT_H)
check_include_file(netinet/in.h HAVE_NETINET_IN_H)
check_include_file(sys/cdefs.h HAVE_SYS_CDEFS_H)
check_type_size(int64_t INT64_T)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/config.h.cmake
               ${CMAKE_CURRENT_BINARY_DIR}/config.h)

set(CMS_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(CMS_EXTERNAL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/external)

# RSA bits of the shipped self-signed certificate. 1024 is not offered: OpenSSL 3.x
# refuses to even load such a certificate ("ee key too small"), so a build configured
# that way would produce a manager whose HTTPS never comes up.
set(CMS_SSL_RSA_BITS 2048)

# --------------------------------------------------------------------------- version
file(READ ${CMAKE_CURRENT_SOURCE_DIR}/BUILD_NUMBER CMS_BUILD_NUMBER_FILE)
string(STRIP "${CMS_BUILD_NUMBER_FILE}" CMS_BUILD_NUMBER_FILE)
string(REGEX REPLACE "\\.[0-9]+$" "" CMS_RELEASE_STRING "${CMS_BUILD_NUMBER_FILE}")
string(REGEX REPLACE "\\.[0-9]+$" "" CMS_MAJOR_RELEASE_STRING "${CMS_RELEASE_STRING}")
string(REPLACE "." ";" CMS_VERSION_PARTS "${CMS_RELEASE_STRING}")
list(GET CMS_VERSION_PARTS 0 CMS_MAJOR_VERSION)
list(GET CMS_VERSION_PARTS 1 CMS_MINOR_VERSION)
list(GET CMS_VERSION_PARTS 2 CMS_PATCH_VERSION)

execute_process(COMMAND git rev-list --count HEAD
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  OUTPUT_VARIABLE CMS_COMMIT_COUNT
  OUTPUT_STRIP_TRAILING_WHITESPACE
  ERROR_QUIET)
if(NOT CMS_COMMIT_COUNT)
  set(CMS_COMMIT_COUNT 0)
endif()
string(REGEX REPLACE "^([0-9]+)$" "\\1" CMS_COMMIT_COUNT "${CMS_COMMIT_COUNT}")
string(LENGTH "${CMS_COMMIT_COUNT}" CMS_COMMIT_COUNT_LEN)
while(CMS_COMMIT_COUNT_LEN LESS 4)
  set(CMS_COMMIT_COUNT "0${CMS_COMMIT_COUNT}")
  string(LENGTH "${CMS_COMMIT_COUNT}" CMS_COMMIT_COUNT_LEN)
endwhile()
set(CMS_BUILD_NUMBER "${CMS_RELEASE_STRING}.${CMS_COMMIT_COUNT}")
message(STATUS "CUBRID Manager server version: ${CMS_BUILD_NUMBER}")

# ------------------------------------------------------- CUBRID and OpenSSL locations
#
# In-tree: take them straight from the targets this build defines.
# Standalone: CUBRID_INCLUDE_DIR / CUBRID_LIB_DIR / OPENSSL_* are resolved by
# build_cmake.sh (or passed by hand) and pointed at a build or install tree.
if(CMS_STANDALONE)
  foreach(required CUBRID_INCLUDE_DIR CUBRID_LIB_DIR OPENSSL_INCLUDE_DIR OPENSSL_LIBRARIES)
    if(NOT DEFINED ${required} OR "${${required}}" STREQUAL "")
      message(FATAL_ERROR
        "${required} is not set. Run build_cmake.sh, or pass -D${required}=... pointing at a CUBRID build or installation.")
    endif()
  endforeach()
  set(CMS_CUBRID_INCLUDES ${CUBRID_INCLUDE_DIR})
  set(CMS_OPENSSL_INCLUDES ${OPENSSL_INCLUDE_DIR})
  set(CMS_OPENSSL_LIBS ${OPENSSL_LIBRARIES})
  find_library(CMS_CUBRIDCS_LIB NAMES cubridcs PATHS ${CUBRID_LIB_DIR} NO_DEFAULT_PATH REQUIRED)
  find_library(CMS_CMDEP_LIB NAMES cmdep PATHS ${CUBRID_LIB_DIR} NO_DEFAULT_PATH REQUIRED)
  find_library(CMS_CMSTAT_LIB NAMES cmstat PATHS ${CUBRID_LIB_DIR} NO_DEFAULT_PATH REQUIRED)
  set(CMS_CUBRID_LIBS ${CMS_CUBRIDCS_LIB} ${CMS_CMDEP_LIB} ${CMS_CMSTAT_LIB})
  message(STATUS "CUBRID headers: ${CMS_CUBRID_INCLUDES}")
  message(STATUS "CUBRID libraries: ${CMS_CUBRID_LIBS}")
  message(STATUS "OpenSSL: ${CMS_OPENSSL_LIBS}")
else()
  # Public headers of the libraries this links against are not installed yet at build
  # time, so read them off the targets.
  get_target_property(CMS_CCI_HEADER cascci PUBLIC_HEADER)
  get_target_property(CMS_CMDEP_HEADER cmdep PUBLIC_HEADER)
  get_target_property(CMS_CMSTAT_HEADER cmstat PUBLIC_HEADER)
  set(CMS_CUBRID_INCLUDES "")
  foreach(header ${CMS_CCI_HEADER} ${CMS_CMDEP_HEADER} ${CMS_CMSTAT_HEADER})
    get_filename_component(header_dir ${header} DIRECTORY)
    list(APPEND CMS_CUBRID_INCLUDES ${header_dir})
  endforeach()
  list(REMOVE_DUPLICATES CMS_CUBRID_INCLUDES)
  set(CMS_CUBRID_LIBS cubridcs cmdep cmstat)
  set(CMS_OPENSSL_INCLUDES ${LIBOPENSSL_INCLUDES})
  set(CMS_OPENSSL_LIBS ${LIBOPENSSL_LIBS})
endif()

# jsoncpp and libevent stay as the prebuilt archives committed under external/.
# libevent_openssl only references OpenSSL's stable public API, so it links against
# 3.x unchanged.
set(CMS_EXTERNAL_INCLUDES
  ${CMS_EXTERNAL_DIR}/jsoncpp/linux_64/include
  ${CMS_EXTERNAL_DIR}/libevent/linux_64/include
  )
set(CMS_EXTERNAL_LIBS
  ${CMS_EXTERNAL_DIR}/jsoncpp/linux_64/lib/libjson.a
  ${CMS_EXTERNAL_DIR}/libevent/linux_64/lib/libevent.a
  ${CMS_EXTERNAL_DIR}/libevent/linux_64/lib/libevent_openssl.a
  )

# ------------------------------------------------------------------------ definitions
set(CMS_SYS_DEFS GCC LINUX _GNU_SOURCE I386 _GLIBCXX_USE_CXX11_ABI=0)
set(CMS_COMMON_DEFS ANSI=1 SYSV MAXPATHLEN=1024 _REENTRANT)
set(CMS_VERSION_DEFS
  MAJOR_VERSION=${CMS_MAJOR_VERSION}
  MINOR_VERSION=${CMS_MINOR_VERSION}
  PATCH_VERSION=${CMS_PATCH_VERSION}
  RELEASE_STRING=${CMS_RELEASE_STRING}
  MAJOR_RELEASE_STRING=${CMS_MAJOR_RELEASE_STRING}
  BUILD_NUMBER=${CMS_BUILD_NUMBER}
  )
set(CMS_WARN_FLAGS -Wall -W -Wwrite-strings -Wno-cast-qual -Wno-unused -pthread)

# ---------------------------------------------------------------------------- targets
set(CM_ADMIN_SOURCES
  ${CMS_SRC_DIR}/cm_text_encryption.c
  ${CMS_SRC_DIR}/cm_config.cpp
  ${CMS_SRC_DIR}/cm_server_util.cpp
  ${CMS_SRC_DIR}/cm_user.cpp
  ${CMS_SRC_DIR}/cm_cmd.cpp
  ${CMS_SRC_DIR}/cm_cmd_util.cpp
  ${CMS_SRC_DIR}/cm_connect_info.cpp
  ${CMS_SRC_DIR}/cm_cmd_task.cpp
  )

set(CUB_MANAGER_SOURCES
  ${CMS_SRC_DIR}/cm_server_util.cpp
  ${CMS_SRC_DIR}/cm_autojob.cpp
  ${CMS_SRC_DIR}/cm_text_encryption.c
  ${CMS_SRC_DIR}/cm_config.cpp
  ${CMS_SRC_DIR}/cm_job_task.cpp
  ${CMS_SRC_DIR}/cm_cmd_exec.cpp
  ${CMS_SRC_DIR}/cm_connect_info.cpp
  ${CMS_SRC_DIR}/cm_auto_task.cpp
  ${CMS_SRC_DIR}/cm_httpd.cpp
  ${CMS_SRC_DIR}/cm_mon_stat.cpp
  ${CMS_SRC_DIR}/cm_user.cpp
  ${CMS_SRC_DIR}/cm_http_server.cpp
  ${CMS_SRC_DIR}/cm_server_extend_interface.cpp
  ${CMS_SRC_DIR}/cm_server_interface.cpp
  ${CMS_SRC_DIR}/cm_server_autoupdate.cpp
  )

add_executable(cm_admin ${CM_ADMIN_SOURCES})
target_compile_definitions(cm_admin PRIVATE
  ${CMS_SYS_DEFS} ${CMS_COMMON_DEFS} ${CMS_VERSION_DEFS} _FILE_OFFSET_BITS=64)
target_compile_options(cm_admin PRIVATE ${CMS_WARN_FLAGS})
target_include_directories(cm_admin PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${CMS_SRC_DIR} ${CMS_CUBRID_INCLUDES})
target_link_libraries(cm_admin PRIVATE ${CMS_CUBRID_LIBS} Threads::Threads)

add_executable(cub_manager ${CUB_MANAGER_SOURCES})
target_compile_definitions(cub_manager PRIVATE
  ${CMS_SYS_DEFS} ${CMS_COMMON_DEFS} ${CMS_VERSION_DEFS}
  FSERVER_SLAVE JSON_SUPPORT EVENT__HAVE_OPENSSL _FILE_OFFSET_BITS=64)
target_compile_options(cub_manager PRIVATE ${CMS_WARN_FLAGS})
target_include_directories(cub_manager PRIVATE
  ${CMAKE_CURRENT_BINARY_DIR} ${CMS_SRC_DIR} ${CMS_CUBRID_INCLUDES} ${CMS_EXTERNAL_INCLUDES} ${CMS_OPENSSL_INCLUDES})
# OpenSSL is linked here rather than borrowed from libcubridcs, which used to export its
# bundled copy and no longer does. This also means the manager is compiled against the
# headers of the very library it links, which was not the case before.
# ${CMAKE_DL_LIBS} is for the static libcrypto, which calls dlopen/dlclose. In-tree it
# comes along with libcubridcs; a standalone build has to ask for it.
target_link_libraries(cub_manager PRIVATE
  ${CMS_CUBRID_LIBS} ${CMS_EXTERNAL_LIBS} ${CMS_OPENSSL_LIBS}
  Threads::Threads ${CMAKE_DL_LIBS} rt)

# The committed jsoncpp and libevent archives were built without -fPIC, so this has to
# be a non-PIE executable - which is what the automake build produced as well.
target_link_options(cub_manager PRIVATE -no-pie)

if(NOT CMS_STANDALONE)
  add_dependencies(cub_manager ${LIBOPENSSL_TARGET})
endif()

# ---------------------------------------------------------------------------- install
if(CMS_STANDALONE)
  set(CMS_BINDIR bin)
  set(CMS_CONFDIR conf)
else()
  set(CMS_BINDIR ${CUBRID_BINDIR})
  set(CMS_CONFDIR ${CUBRID_CONFDIR})
endif()

install(TARGETS cm_admin cub_manager
  RUNTIME DESTINATION ${CMS_BINDIR} COMPONENT Manager)

file(GLOB CMS_CONF_FILES ${CMAKE_CURRENT_SOURCE_DIR}/cmserver/conf/*.conf
                         ${CMAKE_CURRENT_SOURCE_DIR}/cmserver/conf/*.pass)
install(FILES ${CMS_CONF_FILES}
  DESTINATION ${CMS_CONFDIR} COMPONENT Manager)

install(FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/cmserver/conf/cm_ssl_cert_2048.crt
  ${CMAKE_CURRENT_SOURCE_DIR}/cmserver/conf/cm_ssl_cert_2048.key
  ${CMAKE_CURRENT_SOURCE_DIR}/cmserver/conf/cm_ssl_cert_1024.crt
  ${CMAKE_CURRENT_SOURCE_DIR}/cmserver/conf/cm_ssl_cert_1024.key
  DESTINATION ${CMS_CONFDIR} COMPONENT Manager)

file(MD5 ${CMAKE_CURRENT_SOURCE_DIR}/cmserver/conf/cm_ssl_cert_${CMS_SSL_RSA_BITS}.crt
     CMS_DEFAULT_CERT_MD5)
message(STATUS "Default certificate MD5 (RSA ${CMS_SSL_RSA_BITS}): ${CMS_DEFAULT_CERT_MD5}")
target_compile_definitions(cub_manager PRIVATE
  CMS_DEFAULT_CERT_MD5="${CMS_DEFAULT_CERT_MD5}")

# cm_ssl_cert.{crt,key} is the name the manager opens; keep it a link to the sized pair
# the way the automake build did.
install(CODE "
  set(cms_conf \"\$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/${CMS_CONFDIR}\")
  execute_process(COMMAND \${CMAKE_COMMAND} -E rm -f
    \"\${cms_conf}/cm_ssl_cert.crt\" \"\${cms_conf}/cm_ssl_cert.key\")
  execute_process(COMMAND \${CMAKE_COMMAND} -E create_symlink
    cm_ssl_cert_${CMS_SSL_RSA_BITS}.crt \"\${cms_conf}/cm_ssl_cert.crt\")
  execute_process(COMMAND \${CMAKE_COMMAND} -E create_symlink
    cm_ssl_cert_${CMS_SSL_RSA_BITS}.key \"\${cms_conf}/cm_ssl_cert.key\")
  " COMPONENT Manager)
