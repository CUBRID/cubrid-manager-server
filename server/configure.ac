#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT([CUBRID 2008], RELEASE, , cubrid)

AC_PREFIX_DEFAULT("${CUBRID}")

AC_CONFIG_SRCDIR([src/cm_autojob.cpp])
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE

EXTERNAL_DIR="external"
BUILD_DIR=`readlink -f .`

# Checks for programs.
remember_CFLAGS="$CFLAGS"
remember_CXXFLAGS="$CXXFLAGS"
remember_LDFLAGS="$LDFLAGS"
AC_PROG_CC
AC_PROG_CXX
AM_PROG_CC_C_O
AC_PROG_LIBTOOL
AC_PROG_RANLIB
AC_PROG_INSTALL
CFLAGS="$remember_CFLAGS"
CXXFLAGS="$remember_CXXFLAGS"
LDFLAGS="$remember_LDFLAGS -ldl"

# Checks bit model feature.
AC_ARG_ENABLE([64bit],
    [AS_HELP_STRING([--enable-64bit],
        [build 64 bit code @<:@default=no (32 bit code)@:>@])],
    [bit_model=$enableval],
    [bit_model=no])


AM_CONDITIONAL([BUILD_64], [test "$bit_model" = "yes"])

if test x"$prefix" = x"NONE"
then
    prefix="${CUBRID}"
fi

#System type
SYSTEM_TYPE="$host_vendor-$host_os"
MACHINE_TYPE="$host_cpu"
export SYSTEM_TYPE MACHINE_TYPE

case $SYSTEM_TYPE in
    *linux*) SYS_DEFS="-DGCC -DLINUX -D_GNU_SOURCE -DI386"
         SYS_LIBS="" 
         CMSTAT_LIB=""
        if test "$bit_model" = "yes"
        then
            BIT_MODEL="-m64"
        else
            BIT_MODEL="-m32"
            CC="$CC -m32"
            CXX="$CXX -m32"
        fi
        ;;
    *aix*)  
        SYS_DEFS="-DGCC -DAIX -D_GNU_SOURCE -DPPC -fsigned-char -D_THREAD_SAFE"
        SYS_LIBS="-Wl,-bmaxdata:0x800000000 -Wl,-bnoipath"
        CMSTAT_LIB="-lperfstat"
        CC="$CC -pthread"
        CXX="$CXX -pthread"
        if test "$enable_64bit" = "yes"
        then
          BIT_MODEL="-maix64"
          OBJECT_MODE="64"
          SYS_DEFS="$SYS_DEFS -DAIX_PPC64 -D__WORDSIZE=64"
          CC="$CC -maix64"
          CXX="$CXX -maix64"
          LDFLAGS="-Wl,-bbigtoc -Wl,-berok -Wl,-brtl -Wl,-bnortllib -Wl,-bnosymbolic -Wl,-bnoautoexp"
        else
          BIT_MODEL="-maix32"
          OBJECT_MODE="32"
          SYS_DEFS="$SYS_DEFS -D_LARGE_FILES -DAIX_PPC32 -D__WORDSIZE=32"
          CC="$CC -maix32"
          CXX="$CXX -maix32"
          LDFLAGS="-Wl,-bbigtoc -Wl,-berok -Wl,-brtl -Wl,-bnortllib -Wl,-bnosymbolic -Wl,-bnoautoexp"
        fi
        ;;	
    *)       SYS_DEFS=""
         SYS_LIBS="" ;;
esac

export BIT_MODEL CC CXX OBJECT_MODE

# Checks for libraries.
AC_CHECK_LIB([pthread], [pthread_create])
AC_CHECK_LIB([perfstat], [perfstat_cpu_total])

# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([limits.h],
    [],
    [AC_DEFINE([PATH_MAX], [512], [Max path length])])
AC_CHECK_HEADERS([limits.h],
    [],
    [AC_DEFINE([NAME_MAX], [255], [Max file name length])])
AC_CHECK_HEADERS([limits.h],
    [],
    [AC_DEFINE([LINE_MAX], [2048], [Max line length])])
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdlib.h string.h strings.h sys/file.h sys/param.h sys/socket.h sys/statvfs.h unistd.h])

AC_CHECK_HEADERS([getopt.h])
if test "x$ac_cv_header_getopt_h" = "xyes"; then
AC_DEFINE([HAVE_GETOPT_H], [], [To check OS have the getopt.h or not])
fi

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM
AC_TYPE_UID_T
AC_C_VOLATILE
AC_CHECK_SIZEOF([long])
AC_CHECK_SIZEOF([long long])
AC_CHECK_TYPES([int64_t, uint64_t])

if test "$GCC" = "yes"
then
	AC_MSG_CHECKING([for --hash-style=both linker support])
	remember_LDFLAGS="$LDFLAGS"
	hashstyle=`gcc -dumpspecs | grep hash-style=gnu`
	if test "x$hashstyle" != "x"
	then
		LDFLAGS="$LDFLAGS -Wl,--hash-style=both"
		AC_LINK_IFELSE([
                        #include <stdio.h>
                        int main(void) { return 0; }
                ], have_ld_hash_style=yes, have_ld_hash_style=no)

	else
		have_ld_hash_style=no
	fi

	if test "x$have_ld_hash_style" = "xyes"
	then
		AC_MSG_RESULT([yes])
	else
		AC_MSG_RESULT([no])
		LDFLAGS="$remember_LDFLAGS"
	fi
fi

# Checks for library functions.
case $SYSTEM_TYPE in
	*linux*)
		AC_FUNC_MALLOC
		AC_FUNC_REALLOC
		;;
	*)
	AC_FUNC_CLOSEDIR_VOID
	AC_PROG_GCC_TRADITIONAL
	AC_FUNC_MEMCMP
	AC_FUNC_MKTIME
	AC_TYPE_SIGNAL
	AC_FUNC_STAT
AC_CHECK_FUNCS([alarm bzero dup2 ftruncate gethostbyname gethostname inet_ntoa memset mkdir putenv regcomp rmdir select socket strcasecmp strchr strdup strerror strncasecmp strpbrk strrchr strstr sysconf])
esac

# Checks optional features.
AC_ARG_ENABLE([coverage],
    [AS_HELP_STRING([--enable-coverage],
        [build as code coverage mode @<:@default=no@:>@])],
    [enable_coverage=$enableval],
    [enable_coverage=no])

if test "$enable_coverage" = "yes"
then
    CFLAGS="$CFLAGS -fprofile-arcs -ftest-coverage"
    CXXFLAGS="$CXXFLAGS -fprofile-arcs -ftest-coverage"
    LDFLAGS="$LDFLAGS -lgcov"
fi

AC_ARG_ENABLE([debug],
    [AS_HELP_STRING([--enable-debug],
        [build as debug mode @<:@default=no (release mode)@:>@])],
    [enable_debug=$enableval],
    [enable_debug=no])

if test "$enable_debug" = "yes"
then
    CFLAGS="$CFLAGS -ggdb -fno-inline"
    CXXFLAGS="$CXXFLAGS -ggdb -fno-inline"
else
    CFLAGS="$CFLAGS -DNDEBUG -finline-functions -ggdb -O2"
    CXXFLAGS="$CXXFLAGS -DNDEBUG -finline-functions -ggdb -O2 -g"
fi
AM_CONDITIONAL([BUILD_DEBUG], [test "$enable_debug" = "yes"])

AC_ARG_ENABLE([profile],
    [AS_HELP_STRING([--enable-profile],
        [build as profile mode @<:@default=no@:>@])],
    [enable_profile=$enableval],
    [enable_profile=no])

if test "$enable_profile" = "yes"
then
    CFLAGS="$CFLAGS -g -pg"
    CXXFLAGS="$CXXFLAGS -g -pg"
fi

AC_ARG_WITH([cubrid-dir],
    AS_HELP_STRING([--with-cubrid-dir=PATH],
        [directory for cubrid @<:@default=$CUBRID@:>@]),
    [CUBRID_DIR=$withval],
    [CUBRID_DIR="${CUBRID}"])

AC_MSG_CHECKING([cubrid lib directory])
AC_ARG_WITH([cubrid-libdir],
    AS_HELP_STRING([--with-cubrid-libdir=PATH],
                   [directory for cubrid lib files @<:@default=with-cubrid-dir/lib@:>@]),
    [CUBRID_LIBDIR=$withval],
    [CUBRID_LIBDIR="$CUBRID_DIR/lib"])
AC_MSG_RESULT($CUBRID_LIBDIR)

AC_MSG_CHECKING([cubrid include directory])
AC_ARG_WITH([cubrid-includedir],
    AS_HELP_STRING([--with-cubrid-includedir=PATH],
                   [directory for cubrid include files @<:@default=with-cubrid-dir/include@:>@]),
    [CUBRID_INCLUDEDIR=$withval],
    [CUBRID_INCLUDEDIR="$CUBRID_DIR/include"])
AC_MSG_RESULT($CUBRID_INCLUDEDIR)


if test x"$CUBRID_LIBDIR" = x"/lib"
then
    AC_MSG_ERROR([--with-cubrid-libdir option not set properly, must not be empty!])
elif test x"$CUBRID_INCLUDEDIR" = x"/include"
then
    AC_MSG_ERROR([--with-cubrid-includedir option not set properly, must not be empty!])
else
    if test ! -d $CUBRID_LIBDIR; then
        AC_MSG_ERROR([--with-cubrid-libdir option not set properly, direcoty "$CUBRID_LIBDIR" is not exist.])
    fi
    if test ! -d $CUBRID_INCLUDEDIR; then
        AC_MSG_ERROR([--with-cubrid-includedir option not set properly, direcoty "$CUBRID_INCLUDEDIR" is not exist.])
    fi
    CMDEP_LIB="-L$CUBRID_LIBDIR -lcmdep"
    CMSTAT_LIB="-L$CUBRID_LIBDIR -lcmstat $CMSTAT_LIB"
    SRC_INC="-I$CUBRID_INCLUDEDIR"
fi

if test -e "$srcdir/build_external.sh"; then
    chmod -R +w $srcdir
    external_dir=`readlink -f $srcdir`
    if test "$bit_model" = "yes"; then
        case $SYSTEM_TYPE in
            *linux*) EXTERNAL_LIB="$external_dir/external/jsoncpp/linux_64/lib/libjson.a $external_dir/external/openssl/linux_64/lib/libssl.a $external_dir/external/openssl/linux_64/lib/libcrypto.a $external_dir/external/libevent/linux_64/lib/libevent.a $external_dir/external/libevent/linux_64/lib/libevent_openssl.a"
                EXTERNAL_INC="-I$external_dir/external/jsoncpp/linux_64/include -I$external_dir/external/libevent/linux_64/include -I$external_dir/external/openssl/linux_64/include" ;;
            *aix*)   EXTERNAL_LIB="$external_dir/external/jsoncpp/aix_64/lib/libjson.a $external_dir/external/openssl/aix_64/lib/libssl.a $external_dir/external/openssl/aix_64/lib/libcrypto.a $external_dir/external/libevent/aix_64/lib/libevent.a $external_dir/external/libevent/aix_64/lib/libevent_openssl.a"
                EXTERNAL_INC="-I$external_dir/external/jsoncpp/aix_64/include -I$external_dir/external/libevent/aix_64/include -I$external_dir/external/openssl/aix_64/include" ;;
            *)       EXTERNAL_LIB=""
                EXTERNAL_INC="" ;;
        esac
    else
        case $SYSTEM_TYPE in
            *linux*) EXTERNAL_LIB="$external_dir/external/jsoncpp/linux_32/lib/libjson.a $external_dir/external/openssl/linux_32/lib/libssl.a $external_dir/external/openssl/linux_32/lib/libcrypto.a $external_dir/external/libevent/linux_32/lib/libevent.a $external_dir/external/libevent/linux_32/lib/libevent_openssl.a"
                EXTERNAL_INC="-I$external_dir/external/jsoncpp/linux_32/include -I$external_dir/external/libevent/linux_32/include -I$external_dir/external/openssl/linux_32/include" ;;
            *aix*)   EXTERNAL_LIB="$external_dir/external/jsoncpp/aix_32/lib/libjson.a $external_dir/external/openssl/aix_32/lib/libssl.a $external_dir/external/openssl/aix_32/lib/libcrypto.a $external_dir/external/libevent/aix_32/lib/libevent.a $external_dir/external/libevent/aix_32/lib/libevent_openssl.a"
                EXTERNAL_INC="-I$external_dir/external/jsoncpp/aix_32/include -I$external_dir/external/libevent/aix_32/include -I$external_dir/external/openssl/aix_32/include" ;;
            *)       EXTERNAL_LIB=""
                EXTERNAL_INC="" ;;
        esac
    fi
fi

WARN="-Wall -W -Wwrite-strings -Wno-cast-qual -Wmissing-prototypes -Wredundant-decls -Wextra -Wlong-long"
CXXWARN="-Wall -W -Wwrite-strings -Wno-cast-qual -Wlong-long"
NOWARN="-Wno-unused"
CFLAGS="$CFLAGS $WARN $NOWARN"
CXXFLAGS="$CXXFLAGS $CXXWARN $NOWARN"

BUILD_NUMBER=`cat $srcdir/BUILD_NUMBER`
RELEASE_STRING=`echo $BUILD_NUMBER | sed -e "s|\.[[0-9]]*$||"`
MAJOR_RELEASE_STRING=`echo $RELEASE_STRING | sed -e "s|\.[[0-9]]*$||"`
MAJOR_VERSION=`echo $RELEASE_STRING | cut -d \. -f 1`
MINOR_VERSION=`echo $RELEASE_STRING | cut -d \. -f 2`
PATCH_VERSION=`echo $RELEASE_STRING | cut -d \. -f 3`
AC_SUBST(LT_VERSION,$MAJOR_VERSION:$MINOR_VERSION:$PATCH_VERSION)
m4_pattern_allow(LT_VERSION)

COMMON_DEFS="-DANSI=1 -DSYSV -DMAXPATHLEN=1024 -D_REENTRANT"
VERSION_DEFS="-DMAJOR_VERSION=$MAJOR_VERSION -DMINOR_VERSION=$MINOR_VERSION \
-DPATCH_VERSION=$PATCH_VERSION -DRELEASE_STRING=$RELEASE_STRING \
-DMAJOR_RELEASE_STRING=$MAJOR_RELEASE_STRING -DBUILD_NUMBER=$BUILD_NUMBER"


AC_SUBST([BUILD_NUMBER])
AC_SUBST([SYS_DEFS])
AC_SUBST([SYS_LIBS])
AC_SUBST([COMMON_DEFS])
AC_SUBST([VERSION_DEFS])
AC_SUBST([SRC_INC])
AC_SUBST([CMSTAT_LIB])
AC_SUBST([CMDEP_LIB])
AC_SUBST([EXTERNAL_LIB])
AC_SUBST([EXTERNAL_INC])
AC_SUBST([BUILD_DIR])
AC_SUBST([BIT_MODEL])
AC_SUBST([CONF_DIR])
AC_SUBST([VAR_DIR])
AC_SUBST([EXTERNAL_DIR])

AH_TOP([
#ifndef _CONFIG_H_
#define _CONFIG_H_
])
AH_BOTTOM([
#endif /* _CONFIG_H_ */
])

AC_CONFIG_FILES([Makefile
                 external/Makefile
                 cmserver/Makefile
                 cmserver/conf/Makefile])
AC_OUTPUT
