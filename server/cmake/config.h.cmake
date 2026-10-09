/* config.h for the CMake build.
 *
 * The automake build generates this from config.h.in with the full autoconf check set;
 * only the macros the sources actually test are reproduced here.
 */
#ifndef _CM_CMAKE_CONFIG_H_
#define _CM_CMAKE_CONFIG_H_

#cmakedefine HAVE_BZERO 1
#cmakedefine HAVE_MEMSET 1
#cmakedefine HAVE_GETOPT_H 1
#cmakedefine HAVE_GETOPT_LONG 1
#cmakedefine HAVE_NETINET_IN_H 1
#cmakedefine HAVE_SYS_CDEFS_H 1
#cmakedefine HAVE_INT64_T 1

#endif /* _CM_CMAKE_CONFIG_H_ */
