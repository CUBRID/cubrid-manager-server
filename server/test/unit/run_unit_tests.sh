#!/bin/bash
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
# Build and run the unit tests of server/src that need no CUBRID build.
# Each test is one test_<name>.cpp here, linked with the server sources it
# names below. Exits non-zero if a test fails to build or fails.
#
#   ./run_unit_tests.sh            g++ by default; CXX=clang++ to change it

set -eu

here=$(cd "$(dirname "$0")" && pwd)
src="$here/../../src"
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT

cxx=${CXX:-g++}
flags="-std=gnu++11 -Wall -W -I$src"

# test name and the server sources it needs
tests=(
  "test_session_ip:cm_session_ip.cpp"
)

status=0
for entry in "${tests[@]}"; do
  name=${entry%%:*}
  sources=()
  for s in ${entry#*:}; do
    sources+=("$src/$s")
  done

  echo "== $name"
  # shellcheck disable=SC2086
  if ! $cxx $flags -o "$out/$name" "$here/$name.cpp" "${sources[@]}"; then
    echo "$name: build failed"
    status=1
    continue
  fi
  if ! "$out/$name"; then
    status=1
  fi
done

exit $status
