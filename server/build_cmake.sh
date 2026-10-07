#!/bin/sh
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
# Builds the manager server on its own, against a CUBRID source or build directory.
# An installed CUBRID cannot be used: it ships neither the public headers nor the
# OpenSSL the server was built with.

set -e

progname=$(basename "$0")
source_dir=$(cd "$(dirname "$0")" && pwd)

cubrid_dir="$source_dir/../.."
build_dir=""
build_type="Release"
prefix=""
do_install="no"

usage()
{
  cat <<EOF
Usage: $progname [options]

  -c, --with-cubrid <dir>  CUBRID source directory that has been built, or its build
                           directory (default: the CUBRID this manager is part of,
                           $(cd "$source_dir/../.." && pwd))
  -b, --build-dir <dir>    build directory
                           (default: build_<arch>_<build type>, as build.sh names it)
  -t, --build-type <type>  Release or Debug (default: $build_type)
  -p, --prefix [<dir>]     install after building, into <dir> if given and into
                           \$CUBRID otherwise. Without -p nothing is installed.
  -h, --help               this message

Examples:
  $progname                                          # the CUBRID this manager is part of
  $progname -c ~/source/cubrid                       # a source tree that has been built
  $progname -c ~/source/cubrid/build_x86_64_release  # its build tree
  $progname -p                                       # build, then install into \$CUBRID
  $progname -t Debug -p /opt/cubrid                  # debug build, install into /opt/cubrid
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    -c|--with-cubrid) cubrid_dir="$2"; shift 2 ;;
    -b|--build-dir)   build_dir="$2"; shift 2 ;;
    -t|--build-type)  build_type="$2"; shift 2 ;;
    -p|--prefix)
      do_install="yes"
      if [ -n "$2" ] && [ "${2#-}" = "$2" ]; then
        prefix="$2"; shift 2
      else
        shift
      fi
      ;;
    -h|--help)        usage; exit 0 ;;
    *) echo "$progname: unknown option $1" >&2; usage; exit 1 ;;
  esac
done

# Same naming as build.sh: build_<target>_<mode>.
if [ -z "$build_dir" ]; then
  build_target=$(uname -m 2>/dev/null)
  [ -n "$build_target" ] || build_target="x86_64"
  build_mode=$(echo "$build_type" | tr '[:upper:]' '[:lower:]')
  build_dir="$source_dir/build_${build_target}_${build_mode}"
fi

if [ -z "$cubrid_dir" ]; then
  echo "$progname: no CUBRID given. Use -c <dir> or set \$CUBRID." >&2
  exit 1
fi
if [ ! -d "$cubrid_dir" ]; then
  echo "$progname: $cubrid_dir is not a directory" >&2
  exit 1
fi
cubrid_dir=$(cd "$cubrid_dir" && pwd)

# Either directory leads to the other: a build directory records its source tree, and a
# source tree is searched for a build directory pointing back at it.
cubrid_src=""
cubrid_build=""

cache_home()
{
  sed -n 's/^CMAKE_HOME_DIRECTORY:INTERNAL=//p' "$1/CMakeCache.txt" 2>/dev/null | head -1
}

if [ -f "$cubrid_dir/CMakeCache.txt" ]; then
  cubrid_build="$cubrid_dir"
  cubrid_src=$(cache_home "$cubrid_build")
  if [ -z "$cubrid_src" ] || [ ! -f "$cubrid_src/CMakeLists.txt" ]; then
    echo "$progname: $cubrid_dir is a build directory but its source tree could not be found." >&2
    exit 1
  fi
elif [ -f "$cubrid_dir/CMakeLists.txt" ] && [ -d "$cubrid_dir/src/cm_common" ]; then
  cubrid_src="$cubrid_dir"
  for candidate in "$cubrid_dir"/build_*/CMakeCache.txt "$cubrid_dir"/*/CMakeCache.txt; do
    [ -f "$candidate" ] || continue
    d=$(dirname "$candidate")
    # Skip a build directory that has not been built.
    if [ "$(cache_home "$d")" = "$cubrid_src" ] && [ -e "$d/cs/libcubridcs.so" ]; then
      cubrid_build="$d"
      break
    fi
  done
  if [ -z "$cubrid_build" ]; then
    echo "$progname: no built build directory of $cubrid_src was found." >&2
    echo "  Build CUBRID first, or pass its build directory to -c." >&2
    exit 1
  fi
else
  echo "$progname: $cubrid_dir is neither a CUBRID source nor a CUBRID build directory." >&2
  echo "  Pass one of the two to -c. An installed CUBRID cannot be used: it ships neither" >&2
  echo "  the public headers nor the OpenSSL the server was built with." >&2
  exit 1
fi

cubrid_include_dir="$cubrid_src/src/cm_common;$cubrid_src/cubrid-cci/src/cci"
for h in "$cubrid_src/src/cm_common/cm_dep.h" "$cubrid_src/src/cm_common/cm_stat.h" \
         "$cubrid_src/cubrid-cci/src/cci/cas_cci.h"; do
  if [ ! -f "$h" ]; then
    echo "$progname: missing header $h" >&2
    exit 1
  fi
done

cubrid_lib_dir="$cubrid_build/cs;$cubrid_build/cm_common"
for l in "$cubrid_build/cs/libcubridcs.so" "$cubrid_build/cm_common/libcmdep.so" \
         "$cubrid_build/cm_common/libcmstat.so"; do
  if [ ! -e "$l" ]; then
    echo "$progname: $l is missing - build CUBRID first." >&2
    exit 1
  fi
done

# From the build tree only - never the CCI submodule's bundled copy or the system one,
# either of which could be a different version than the server's.
openssl_include_dir="$cubrid_build/3rdparty/include"
openssl_lib_dir="$cubrid_build/3rdparty/lib"
if [ ! -f "$openssl_include_dir/openssl/evp.h" ] || [ ! -f "$openssl_lib_dir/libssl.a" ]; then
  echo "$progname: no OpenSSL under $cubrid_build/3rdparty - build CUBRID first." >&2
  exit 1
fi

# CMake needs a prefix even when nothing will be installed.
if [ -z "$prefix" ]; then
  if [ -n "$CUBRID" ]; then
    prefix="$CUBRID"
  else
    echo "$progname: warning: \$CUBRID is not set, using $cubrid_build/_install/CUBRID" >&2
    prefix="$cubrid_build/_install/CUBRID"
  fi
fi
if [ -d "$prefix" ]; then
  prefix=$(cd "$prefix" && pwd)
fi

echo "CUBRID source    : $cubrid_src"
echo "CUBRID build     : $cubrid_build"
echo "  headers        : $cubrid_include_dir"
echo "  libraries      : $cubrid_lib_dir"
echo "OpenSSL headers  : $openssl_include_dir"
echo "OpenSSL libraries: $openssl_lib_dir"
if [ "$do_install" = "yes" ]; then
  echo "install prefix   : $prefix"
fi
echo "build type       : $build_type"

cmake -S "$source_dir" -B "$build_dir" \
  -DCMAKE_BUILD_TYPE="$build_type" \
  -DCMAKE_INSTALL_PREFIX="$prefix" \
  -DCUBRID_INCLUDE_DIR="$cubrid_include_dir" \
  -DCUBRID_LIB_DIR="$cubrid_lib_dir" \
  -DOPENSSL_INCLUDE_DIR="$openssl_include_dir" \
  -DOPENSSL_LIBRARIES="$openssl_lib_dir/libssl.a;$openssl_lib_dir/libcrypto.a"

cmake --build "$build_dir" -j "$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"

if [ "$do_install" = "yes" ]; then
  cmake --install "$build_dir"
fi

echo "$progname: done"
