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
# Tests of the manager server key pair (server/src/cm_ssl_cert.cpp, CBRD-27829):
# the startup check (cm_ssl_cert_ensure ()) and generation
# (cm_ssl_cert_generate ()). Each scenario lays out a conf directory, runs
# ssl_cert_driver once, and checks the files, the result and the log.
# Needs no CUBRID build and no running manager server.
#
#   ./run_ssl_cert_tests.sh                       system OpenSSL, g++
#   OPENSSL_DIR=../../external/openssl/linux_64 ./run_ssl_cert_tests.sh
#                                                 another OpenSSL (include/, lib/libcrypto.a)
#   CXX=clang++ ./run_ssl_cert_tests.sh           another compiler
#
# The openssl command (3.0 or later) is used to make inputs and check outputs.
# Run as a user other than root: root reads and writes files regardless of
# their mode, so the permission scenarios are skipped as root.
# Exits non-zero if the driver does not build or a check fails.

set -u

here=$(cd "$(dirname "$0")" && pwd)
src="$here/../../src"
shipped="$here/shipped"
work=$(mktemp -d)
trap 'chmod -R u+rwx "$work" 2>/dev/null; rm -rf "$work"' EXIT

pass=0
fail=0
skip=0

# ------------------------------------------------------------------ build

if ! command -v openssl > /dev/null 2>&1; then
  echo "openssl command not found"
  exit 1
fi
case $(openssl version) in
  "OpenSSL 0."* | "OpenSSL 1."*)
    echo "openssl 3.0 or later is needed to make the inputs: $(openssl version)"
    exit 1
    ;;
esac

cxx=${CXX:-g++}
printf '#define HAVE_MEMSET 1\n#define HAVE_INT64_T 1\n' > "$work/config.h"
flags="-std=gnu++11 -Wall -W -Wno-unused -pthread -DGCC -DLINUX -D_GNU_SOURCE -D_REENTRANT -D_FILE_OFFSET_BITS=64"
flags="$flags -I$work -I$src"
if [ -n "${OPENSSL_DIR:-}" ]; then
  flags="$flags -I$OPENSSL_DIR/include"
  libs="$OPENSSL_DIR/lib/libssl.a $OPENSSL_DIR/lib/libcrypto.a -ldl"
else
  libs="-lssl -lcrypto"
fi

driver="$work/ssl_cert_driver"
# shellcheck disable=SC2086
if ! $cxx $flags -o "$driver" "$here/ssl_cert_driver.cpp" "$src/cm_ssl_cert.cpp" $libs; then
  echo "ssl_cert_driver: build failed"
  exit 1
fi

# LD_PRELOAD library that makes chosen rename () and unlink () calls fail
fault_lib="$work/fault_inject.so"
if ! ${CC:-cc} -shared -fPIC -o "$fault_lib" "$here/fault_inject.c" -ldl 2> /dev/null; then
  fault_lib=""
fi

# ---------------------------------------------------------------- helpers

ok ()
{
  if eval "$2"; then
    pass=$((pass + 1))
  else
    fail=$((fail + 1))
    echo "FAIL  $1"
  fi
}

skip_as_root ()
{
  if [ "$(id -u)" = 0 ]; then
    skip=$((skip + 1))
    echo "SKIP  $1 (running as root)"
    return 0
  fi
  return 1
}

# a fresh conf directory, as $CUBRID/conf
setup ()
{
  chmod -R u+rwx "$work/c" 2>/dev/null
  rm -rf "$work/c"
  mkdir -p "$work/c/conf"
  C="$work/c/conf"
  CRT="$C/cm_ssl_cert.crt"
  KEY="$C/cm_ssl_cert.key"
  export LOGDIR="$work/c"
}

ensure ()
{
  timeout 30 "$driver" ensure "$CRT" "$KEY" "$1" < /dev/null > "$work/out" 2>&1
  RET=$?
}

generate ()
{
  timeout 30 "$driver" generate "$CRT" "$KEY" "$@" < /dev/null > "$work/out" 2>&1
  RET=$?
}

log ()
{
  cat "$LOGDIR/cub_manager.log" "$LOGDIR/cub_manager.err" 2> /dev/null
}

# SHA-256 of the public key (DER) of a private key or a certificate
key_fp ()
{
  openssl pkey -in "$1" -pubout -outform DER 2> /dev/null | sha256sum | cut -c1-64
}

cert_fp ()
{
  openssl x509 -in "$1" -noout -pubkey 2> /dev/null | openssl pkey -pubin -outform DER 2> /dev/null \
    | sha256sum | cut -c1-64
}

is_shipped ()
{
  case $1 in
    385bea60* | 71e2a53e* | 2e3f2eb5*) return 0 ;;
  esac
  return 1
}

files_sum ()
{
  cat "$CRT" "$KEY" 2> /dev/null | md5sum
}

# files in conf, not counting the lock file between processes (<key>.lock)
nfiles ()
{
  ls -A "$C" | grep -v '^cm_ssl_cert\.key\.lock$' | wc -l
}

# a key pair of the administrator (not shipped)
make_own_pair ()
{
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$KEY" -out "$CRT" -subj /CN=own -days 30 2> /dev/null
}

# the files an earlier develop build installed: sized files and links to one size
install_develop ()
{
  cp "$shipped"/develop/cm_ssl_cert_* "$C"/
  ln -s "cm_ssl_cert_$1.crt" "$CRT"
  ln -s "cm_ssl_cert_$2.key" "$KEY"
}

host=$(hostname)

# an OpenSSL configuration that sets the TLS security level, for OPENSSL_CONF
for level in 1 2 3; do
  cat > "$work/seclevel$level.cnf" << EOF
openssl_conf = cms_conf
[cms_conf]
ssl_conf = cms_ssl
[cms_ssl]
system_default = cms_ssl_default
[cms_ssl_default]
CipherString = DEFAULT@SECLEVEL=$level
EOF
done

# ensure with the TLS security level $2 (1, 2 or 3)
ensure_at ()
{
  OPENSSL_CONF="$work/seclevel$2.cnf" timeout 30 "$driver" ensure "$CRT" "$KEY" "$1" < /dev/null > "$work/out" 2>&1
  RET=$?
}

# ---------------------------------------------------------------- fixtures

for f in 11.3/cm_ssl_cert develop/cm_ssl_cert_1024 develop/cm_ssl_cert_2048; do
  ok "fixture $f is a shipped key" "is_shipped \$(key_fp $shipped/$f.key)"
  ok "fixture $f is a pair" "[ \"\$(key_fp $shipped/$f.key)\" = \"\$(cert_fp $shipped/$f.crt)\" ]"
done

# ------------------------------------------------------------ new install

setup
ensure YES
ok "new, YES: starts" "[ $RET = 0 ] && grep -q 'why=$' $work/out"
ok "new, YES: regular files" "[ -f $CRT -a ! -L $CRT -a -f $KEY -a ! -L $KEY ]"
ok "new, YES: key 0600" "[ \$(stat -c %a $KEY) = 600 ]"
ok "new, YES: a pair" "[ \"\$(key_fp $KEY)\" = \"\$(cert_fp $CRT)\" ]"
ok "new, YES: not shipped" "! is_shipped \$(key_fp $KEY)"
ok "new, YES: nothing else left" "[ \$(nfiles) = 2 ]"

text=$(openssl x509 -in "$CRT" -noout -text)
ok "cert: version 3" "grep -q 'Version: 3' <<< \"\$text\""
ok "cert: RSA 2048" "grep -q 'Public-Key: (2048 bit)' <<< \"\$text\""
ok "cert: sha256WithRSAEncryption" "grep -q 'Signature Algorithm: sha256WithRSAEncryption' <<< \"\$text\""
ok "cert: basicConstraints critical CA:FALSE" \
  "grep -A1 'Basic Constraints: critical' <<< \"\$text\" | grep -q 'CA:FALSE'"
ok "cert: keyUsage critical" \
  "grep -A1 'Key Usage: critical' <<< \"\$text\" | grep -q 'Digital Signature, Key Encipherment'"
ok "cert: extendedKeyUsage serverAuth" \
  "grep -A1 'Extended Key Usage' <<< \"\$text\" | grep -q 'TLS Web Server Authentication'"
ok "cert: subjectKeyIdentifier" "grep -q 'Subject Key Identifier' <<< \"\$text\""
ok "cert: SAN localhost, 127.0.0.1, ::1" \
  "grep -A1 'Subject Alternative Name' <<< \"\$text\" | grep -q 'DNS:localhost, IP Address:127.0.0.1, IP Address:0:0:0:0:0:0:0:1'"
ok "cert: SAN has no interface address (only the loopback addresses)" \
  "[ \$(grep -A1 'Subject Alternative Name' <<< \"\$text\" | tail -1 | grep -o 'IP Address' | wc -l) = 2 ]"
ok "cert: default subject" \
  "openssl x509 -in $CRT -noout -subject | grep -q 'C = KR, ST = SEOUL, L = Default City, O = CUBRID, OU = RND, CN = .*, emailAddress = admin@cubrid.com'"
ok "cert: self-signed" \
  "[ \"\$(openssl x509 -in $CRT -noout -subject | cut -d= -f2-)\" = \"\$(openssl x509 -in $CRT -noout -issuer | cut -d= -f2-)\" ]"
serial=$(openssl x509 -in "$CRT" -noout -serial | cut -d= -f2)
ok "cert: random serial" "[ \${#serial} -ge 30 ]"
now=$(date +%s)
not_before=$(date -d "$(openssl x509 -in "$CRT" -noout -startdate | cut -d= -f2)" +%s)
not_after=$(date -d "$(openssl x509 -in "$CRT" -noout -enddate | cut -d= -f2)" +%s)
ok "cert: notBefore 1 day back" "[ \$((now - not_before)) -ge 86000 -a \$((now - not_before)) -le 86700 ]"
ok "cert: notAfter 10 years" "[ \$(((not_after - now) / 86400)) -ge 3649 -a \$(((not_after - now) / 86400)) -le 3650 ]"
fp=$(openssl x509 -in "$CRT" -noout -fingerprint -sha256 | cut -d= -f2)
ok "log: fingerprint as openssl prints it" "log | grep -q \"SHA256 Fingerprint=$fp\""

ok "verify: localhost" "openssl verify -CAfile $CRT -verify_hostname localhost $CRT > /dev/null 2>&1"
ok "verify: 127.0.0.1" "openssl verify -CAfile $CRT -verify_ip 127.0.0.1 $CRT > /dev/null 2>&1"
ok "verify: ::1" "openssl verify -CAfile $CRT -verify_ip ::1 $CRT > /dev/null 2>&1"
ok "verify: sslserver" "openssl verify -CAfile $CRT -purpose sslserver $CRT > /dev/null 2>&1"
case $host in
  *[!A-Za-z0-9.-]* | "") ;;
  *)
    ok "verify: host name" "openssl verify -CAfile $CRT -verify_hostname $host $CRT > /dev/null 2>&1"
    ;;
esac

# restart: the same pair, not generated again
sum=$(files_sum)
ensure YES
ok "restart: starts" "[ $RET = 0 ]"
ok "restart: files unchanged" "[ \"\$(files_sum)\" = \"$sum\" ]"
ok "restart: same fingerprint logged again" "[ \$(log | grep -c \"Fingerprint=$fp\") = 2 ]"

setup
ensure NO
ok "new, NO: does not start" "[ $RET != 0 ]"
ok "new, NO: nothing created" "[ ! -e $CRT -a ! -e $KEY ]"
ok "new, NO: what to do" "log | grep -q 'ssl_cert_auto_generate=YES'"
ok "new, NO: why" \
  "grep -q 'why=the SSL certificate .* and private key .* do not exist (ssl_cert_auto_generate=NO)' $work/out"

# ----------------------------------------------------------------- upgrade

setup
cp "$shipped/11.3/cm_ssl_cert.crt" "$CRT"
cp "$shipped/11.3/cm_ssl_cert.key" "$KEY"
ensure YES
ok "11.3 files: starts" "[ $RET = 0 ] && grep -q 'shipped_in_use=0' $work/out"
ok "11.3 files: replaced" "! is_shipped \$(key_fp $KEY) && [ \"\$(key_fp $KEY)\" = \"\$(cert_fp $CRT)\" ]"
ok "11.3 files: logged" "log | grep -q 'CUBRID 11.3 and earlier'"

for bits in 1024 2048; do
  setup
  install_develop $bits $bits
  ensure YES
  ok "develop $bits links: starts" "[ $RET = 0 ]"
  ok "develop $bits links: regular files" "[ -f $CRT -a ! -L $CRT -a -f $KEY -a ! -L $KEY ]"
  ok "develop $bits links: replaced" "! is_shipped \$(key_fp $KEY)"
  ok "develop $bits links: key 0600" "[ \$(stat -c %a $KEY) = 600 ]"
  ok "develop $bits links: leftover files removed" "[ \$(nfiles) = 2 ]"
done

setup
ln -s cm_ssl_cert_2048.crt "$CRT"
ln -s cm_ssl_cert_2048.key "$KEY"
ensure YES
ok "dangling links, YES: generated" "[ $RET = 0 ] && [ -f $CRT -a ! -L $CRT -a -f $KEY -a ! -L $KEY ]"
setup
ln -s cm_ssl_cert_2048.crt "$CRT"
ln -s cm_ssl_cert_2048.key "$KEY"
ensure NO
ok "dangling links, NO: does not start" "[ $RET != 0 ]"

setup
cp "$shipped/develop/cm_ssl_cert_2048.key" "$KEY"
openssl req -new -x509 -key "$KEY" -subj /CN=resigned -days 30 -out "$CRT" 2> /dev/null
ensure YES
ok "re-signed with a shipped key: replaced" "[ $RET = 0 ] && ! is_shipped \$(key_fp $KEY)"

setup
install_develop 2048 1024
ensure YES
ok "1024 key + 2048 cert, YES: replaced" "[ $RET = 0 ] && [ \"\$(key_fp $KEY)\" = \"\$(cert_fp $CRT)\" ]"
setup
install_develop 2048 1024
ensure NO
ok "1024 key + 2048 cert, NO: does not start" "[ $RET != 0 ] && log | grep -q 'do not match'"

setup
install_develop 2048 2048
ensure NO
ok "shipped pair, NO: starts with a warning" \
  "[ $RET = 0 ] && grep -q 'shipped_in_use=1' $work/out && grep -q 'ERROR' $LOGDIR/cub_manager.err"
ok "shipped pair, NO: nothing changed" "[ -L $CRT -a -L $KEY ] && [ \$(nfiles) = 6 ]"

# ---------------------------------------------------- only one of the two

for mode in YES NO; do
  for kind in shipped own; do
    for which in key crt; do
      setup
      if [ $kind = shipped ]; then
        src_key="$shipped/develop/cm_ssl_cert_2048.key"
        src_crt="$shipped/develop/cm_ssl_cert_2048.crt"
      else
        openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/own.key" -out "$work/own.crt" -subj /CN=own \
          2> /dev/null
        src_key="$work/own.key"
        src_crt="$work/own.crt"
      fi
      if [ $which = key ]; then
        cp "$src_key" "$KEY"
        left=$KEY
        missing=$CRT
      else
        cp "$src_crt" "$CRT"
        left=$CRT
        missing=$KEY
      fi
      sum=$(md5sum < "$left")
      ensure $mode
      name="only the $which ($kind), $mode"
      ok "$name: does not start, file kept" \
        "[ $RET != 0 ] && [ \"\$(md5sum < $left)\" = \"$sum\" ] && [ ! -e $missing ]"
      ok "$name: what is missing" \
        "log | grep -q 'does not exist, while' && grep -q 'why=the SSL .* does not exist, while the .* does$' $work/out"
      if [ $kind = shipped ]; then
        ok "$name: the remaining file is a shipped key" "log | grep -q 'the remaining'"
      else
        ok "$name: no shipped-key note" "! log | grep -q 'the remaining'"
      fi
    done
  done
done

# --------------------------------------------------- mismatch, cannot tell

for mode in YES NO; do
  setup
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$KEY" -out "$work/a.crt" -subj /CN=a 2> /dev/null
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/b.key" -out "$CRT" -subj /CN=b 2> /dev/null
  sum=$(files_sum)
  ensure $mode
  ok "mismatch, $mode: does not start, files kept" \
    "[ $RET != 0 ] && [ \"\$(files_sum)\" = \"$sum\" ] && log | grep -q 'do not match'"
  ok "mismatch, $mode: why" "grep -q 'why=the SSL certificate .* and private key .* do not match$' $work/out"

  if ! skip_as_root "unreadable key, $mode"; then
    setup
    make_own_pair
    chmod 000 "$KEY"
    sum=$(md5sum < "$CRT")
    ensure $mode
    ok "unreadable key, $mode: does not start, files kept" \
      "[ $RET != 0 ] && [ \"\$(md5sum < $CRT)\" = \"$sum\" ] && [ \$(stat -c %a $KEY) = 0 ]"
    ok "unreadable key, $mode: why" "grep -q 'why=cannot read the SSL private key .*: Permission denied$' $work/out"
  fi

  setup
  make_own_pair
  echo garbage > "$KEY"
  sum=$(files_sum)
  ensure $mode
  ok "corrupted key, $mode: does not start, files kept" \
    "[ $RET != 0 ] && [ \"\$(files_sum)\" = \"$sum\" ] && log | grep -q 'not a PEM private key'"

  setup
  make_own_pair
  openssl x509 -in "$CRT" -outform DER -out "$work/der"
  cp "$work/der" "$CRT"
  sum=$(files_sum)
  ensure $mode
  ok "DER certificate, $mode: does not start, files kept" \
    "[ $RET != 0 ] && [ \"\$(files_sum)\" = \"$sum\" ] && log | grep -q 'not a PEM certificate'"

  for format in pkcs8 traditional; do
    setup
    make_own_pair
    if [ $format = pkcs8 ]; then
      openssl pkey -in "$KEY" -aes256 -passout pass:secret -out "$work/enc"
    else
      openssl rsa -in "$KEY" -aes256 -passout pass:secret -traditional -out "$work/enc" 2> /dev/null
    fi
    cp "$work/enc" "$KEY"
    sum=$(files_sum)
    ensure $mode
    # 124: timeout, the check waited for a passphrase
    ok "passphrase key ($format), $mode: does not start, does not wait" \
      "[ $RET != 0 -a $RET != 124 ] && [ \"\$(files_sum)\" = \"$sum\" ] && log | grep -q 'passphrase'"
  done
done

if ! skip_as_root "unreadable key + shipped certificate"; then
  setup
  cp "$shipped/develop/cm_ssl_cert_2048.crt" "$CRT"
  cp "$shipped/develop/cm_ssl_cert_2048.key" "$KEY"
  chmod 000 "$KEY"
  ensure YES
  ok "unreadable key + shipped certificate, YES: replaced" "[ $RET = 0 ] && ! is_shipped \$(key_fp $KEY)"

  setup
  cp "$shipped/develop/cm_ssl_cert_2048.crt" "$CRT"
  cp "$shipped/develop/cm_ssl_cert_2048.key" "$KEY"
  chmod 000 "$KEY"
  sum=$(md5sum < "$CRT")
  ensure NO
  ok "unreadable key + shipped certificate, NO: does not start" \
    "[ $RET != 0 ] && [ \"\$(md5sum < $CRT)\" = \"$sum\" ]"
fi

if ! skip_as_root "conf not writable"; then
  setup
  cp "$shipped/develop/cm_ssl_cert_2048.crt" "$CRT"
  cp "$shipped/develop/cm_ssl_cert_2048.key" "$KEY"
  chmod 555 "$C"
  sum=$(files_sum)
  ensure YES
  ok "shipped pair, conf not writable: does not start, files kept" \
    "[ $RET != 0 ] && [ \"\$(files_sum)\" = \"$sum\" ]"
  ok "shipped pair, conf not writable: why" \
    "grep -q 'why=failed to generate a new SSL key pair: cannot create .*Permission denied$' $work/out"
  chmod 755 "$C"
fi

setup
mkdir "$CRT"
cp "$shipped/develop/cm_ssl_cert_2048.key" "$KEY"
ensure YES
ok "certificate path is a directory: does not start" \
  "[ $RET != 0 ] && grep -q 'why=the SSL certificate .* is not a regular file$' $work/out"

# --------------------------------------------------- administrator's pair

# the mode of a key kept as it is: a warning when other accounts can access it
for mode in 600 640 644; do
  setup
  make_own_pair
  chmod $mode "$KEY"
  ensure YES
  if [ $mode = 600 ]; then
    ok "own key $mode: no mode warning" "[ $RET = 0 ] && ! log | grep -q 'can be accessed by other accounts'"
  else
    ok "own key $mode: starts, mode warning with chmod 600" \
      "[ $RET = 0 ] && log | grep -q 'can be accessed by other accounts (mode 0$mode): .*chmod 600' && [ \$(stat -c %a $KEY) = $mode ]"
  fi
done

setup
cp "$shipped"/develop/cm_ssl_cert_* "$C"/
make_own_pair
sum=$(files_sum)
ensure YES
ok "own pair + leftover shipped files, YES: pair kept, leftovers removed" \
  "[ $RET = 0 ] && [ \"\$(files_sum)\" = \"$sum\" ] && [ \$(nfiles) = 2 ]"

setup
cp "$shipped"/develop/cm_ssl_cert_* "$C"/
make_own_pair
sum=$(files_sum)
ensure NO
ok "own pair + leftover shipped files, NO: nothing changed" \
  "[ $RET = 0 ] && [ \"\$(files_sum)\" = \"$sum\" ] && [ \$(nfiles) = 6 ] && grep -q 'shipped_in_use=0' $work/out"

setup
make_own_pair
echo junk > "$C/cm_ssl_cert_2048.key"
ensure YES
ok "own pair + unknown cm_ssl_cert_2048.key: kept" "[ $RET = 0 ] && [ -f $C/cm_ssl_cert_2048.key ]"

setup
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/ca.key" -out "$work/ca.crt" -subj /CN=RootCA -days 30 \
  2> /dev/null
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/int.key" -out "$work/int.crt" -subj /CN=Intermediate \
  -days 30 -CA "$work/ca.crt" -CAkey "$work/ca.key" -addext basicConstraints=critical,CA:TRUE 2> /dev/null
openssl req -newkey rsa:2048 -nodes -keyout "$KEY" -out "$work/srv.csr" -subj /CN=server 2> /dev/null
openssl x509 -req -in "$work/srv.csr" -CA "$work/int.crt" -CAkey "$work/int.key" -CAcreateserial -days 30 \
  -out "$work/srv.crt" 2> /dev/null
cat "$work/srv.crt" "$work/int.crt" > "$CRT"
sum=$(files_sum)
ensure YES
ok "CA-issued certificate with a chain: kept" "[ $RET = 0 ] && [ \"\$(files_sum)\" = \"$sum\" ]"

setup
openssl req -new -key "$shipped/develop/cm_ssl_cert_2048.key" -subj /CN=x -out "$work/s.csr" 2> /dev/null
openssl x509 -req -in "$work/s.csr" -CA "$work/ca.crt" -CAkey "$work/ca.key" -days 30 -out "$CRT" 2> /dev/null
cp "$shipped/develop/cm_ssl_cert_2048.key" "$KEY"
ensure YES
ok "CA-issued certificate for a shipped key: replaced, reissue noted" \
  "[ $RET = 0 ] && ! is_shipped \$(key_fp $KEY) && log | grep -q 'issued by a CA'"

# -------------------------------------------- interrupted replacement

# the files install_pair () leaves when it stops midway, suffix deadbeef
s=deadbeef

# stopped after setting the old key aside: no key, both new files written
for mode in YES NO; do
  setup
  make_own_pair
  sum=$(files_sum)
  mv "$KEY" "$KEY.old-$s"
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$KEY.tmp-$s" 2> /dev/null
  cp "$CRT" "$CRT.tmp-$s"
  ensure $mode
  ok "interrupted before the new key, $mode: previous pair restored" \
    "[ $RET = 0 ] && [ \"\$(files_sum)\" = \"$sum\" ] && [ \$(nfiles) = 2 ] && log | grep -q 'restored the private key'"
done

# stopped after placing the new key, before the new certificate
setup
make_own_pair
sum=$(files_sum)
mv "$KEY" "$KEY.old-$s"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$KEY" -out "$CRT.tmp-$s" -subj /CN=new -days 30 2> /dev/null
ensure YES
ok "interrupted before the new certificate: previous pair restored" \
  "[ $RET = 0 ] && [ \"\$(files_sum)\" = \"$sum\" ] && [ \$(nfiles) = 2 ]"

# stopped after the new certificate, before removing the previous key
setup
make_own_pair
sum=$(files_sum)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$KEY.old-$s" 2> /dev/null
ensure YES
ok "interrupted after the new certificate: previous key removed, pair kept" \
  "[ $RET = 0 ] && [ \"\$(files_sum)\" = \"$sum\" ] && [ \$(nfiles) = 2 ] && log | grep -q 'removed .*old-$s'"

# stopped while writing the temporary files
setup
make_own_pair
sum=$(files_sum)
echo partial > "$KEY.tmp-$s"
echo partial > "$CRT.tmp-$s"
ensure YES
ok "interrupted while writing: temporary files removed" \
  "[ $RET = 0 ] && [ \"\$(files_sum)\" = \"$sum\" ] && [ \$(nfiles) = 2 ]"

# the key path was a link (an earlier develop install): the link was set aside
setup
install_develop 2048 2048
mv "$KEY" "$KEY.old-$s"
ensure YES
ok "interrupted with a link as the key: link restored, then replaced" \
  "[ $RET = 0 ] && [ ! -L $KEY ] && ! is_shipped \$(key_fp $KEY) && [ \$(nfiles) = 2 ]"

# first generation (no previous key): <key>.new-<s> records it

# stopped after placing the new key, before the certificate
for mode in YES NO; do
  setup
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$KEY" -out "$CRT.tmp-$s" -subj /CN=new -days 30 2> /dev/null
  : > "$KEY.new-$s"
  first_key=$(key_fp "$KEY")
  ensure $mode
  if [ $mode = YES ]; then
    ok "first generation interrupted before the certificate, YES: generated again" \
      "[ $RET = 0 ] && [ \$(nfiles) = 2 ] && [ \"\$(key_fp $KEY)\" = \"\$(cert_fp $CRT)\" ] && [ \"\$(key_fp $KEY)\" != \"$first_key\" ] && log | grep -q 'removed its private key'"
  else
    ok "first generation interrupted before the certificate, NO: no key pair, as before" \
      "[ $RET != 0 ] && [ \$(nfiles) = 0 ] && grep -q 'do not exist (ssl_cert_auto_generate=NO)' $work/out"
  fi
done

# stopped before placing the new key
setup
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$KEY.tmp-$s" -out "$CRT.tmp-$s" -subj /CN=new -days 30 2> /dev/null
: > "$KEY.new-$s"
ensure YES
ok "first generation interrupted before the key: generated" \
  "[ $RET = 0 ] && [ \$(nfiles) = 2 ] && [ \"\$(key_fp $KEY)\" = \"\$(cert_fp $CRT)\" ]"

# stopped after placing both, before removing the record
setup
make_own_pair
sum=$(files_sum)
: > "$KEY.new-$s"
ensure YES
ok "first generation interrupted after the certificate: pair kept, record removed" \
  "[ $RET = 0 ] && [ \"\$(files_sum)\" = \"$sum\" ] && [ \$(nfiles) = 2 ]"

# the key was replaced by hand after the interruption: not removed
setup
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/new.key" -out "$CRT.tmp-$s" -subj /CN=new -days 30 2> /dev/null
: > "$KEY.new-$s"
make_own_pair
sum=$(files_sum)
ensure YES
ok "first generation interrupted, then a pair installed by hand: pair kept" \
  "[ $RET = 0 ] && [ \"\$(files_sum)\" = \"$sum\" ] && [ \$(nfiles) = 2 ] && log | grep -q 'is not its key'"

# a replacement interrupted before the certificate, then a pair installed by hand
setup
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$KEY.old-$s" 2> /dev/null
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/new.key" -out "$CRT.tmp-$s" -subj /CN=new -days 30 2> /dev/null
make_own_pair
sum=$(files_sum)
ensure YES
ok "replacement interrupted, then a pair installed by hand: pair kept" \
  "[ $RET = 0 ] && [ \"\$(files_sum)\" = \"$sum\" ] && log | grep -q 'is not its new key'"

# the previous key cannot be put back (conf not writable): do not start, keep the files
if ! skip_as_root "recovery that cannot be done"; then
  setup
  make_own_pair
  sum=$(files_sum)
  mv "$KEY" "$KEY.old-$s"
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$KEY" -out "$CRT.tmp-$s" -subj /CN=new -days 30 2> /dev/null
  chmod 555 "$C"
  ensure YES
  ok "previous key cannot be put back: does not start, files kept" \
    "[ $RET != 0 ] && [ -f $KEY.old-$s ] && [ -f $CRT.tmp-$s ] && [ -f $KEY ] && grep -q 'why=cannot restore the previous private key of an interrupted replacement' $work/out"
  ensure YES
  ok "previous key cannot be put back, second start: still does not start, files kept" \
    "[ $RET != 0 ] && [ -f $KEY.old-$s ] && [ -f $CRT.tmp-$s ]"
  chmod 755 "$C"
  ensure YES
  ok "previous key cannot be put back, after the cause is fixed: previous pair restored" \
    "[ $RET = 0 ] && [ \"\$(files_sum)\" = \"$sum\" ] && [ \$(nfiles) = 2 ]"

  setup
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$KEY" -out "$CRT.tmp-$s" -subj /CN=new -days 30 2> /dev/null
  : > "$KEY.new-$s"
  chmod 555 "$C"
  ensure YES
  ok "new key of a first generation cannot be removed: does not start, files kept" \
    "[ $RET != 0 ] && [ -f $KEY.new-$s ] && [ -f $CRT.tmp-$s ] && [ -f $KEY ] && grep -q 'why=cannot remove the private key .* of an interrupted generation' $work/out"
  chmod 755 "$C"
  ensure YES
  ok "new key of a first generation cannot be removed, after the cause is fixed: generated" \
    "[ $RET = 0 ] && [ \$(nfiles) = 2 ] && [ \"\$(key_fp $KEY)\" = \"\$(cert_fp $CRT)\" ]"
fi

# the key was changed after an interrupted replacement: the files of that replacement stay
setup
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$KEY.old-$s" 2> /dev/null
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/new.key" -out "$CRT.tmp-$s" -subj /CN=new -days 30 2> /dev/null
make_own_pair
ensure YES
ensure YES
ok "replacement interrupted, then a pair installed by hand: its files stay across starts" \
  "[ $RET = 0 ] && [ -f $KEY.old-$s ] && [ -f $CRT.tmp-$s ]"

# a replacement fails, and so does undoing it (another program keeps the new
# key open on Windows; simulated with fault_inject.so): the work files must stay
# so that the next start restores the previous pair
if [ -n "$fault_lib" ]; then
  setup
  make_own_pair
  sum=$(files_sum)
  LD_PRELOAD="$fault_lib" FAULT_RENAME_SRC="crt.tmp-,.key.old-" FAULT_UNLINK_END="/cm_ssl_cert.key" \
    timeout 30 "$driver" generate "$CRT" "$KEY" < /dev/null > "$work/out" 2>&1
  RET=$?
  ok "replacement and its undo both fail: fails, work files kept" \
    "[ $RET != 0 ] && [ \$(ls -A $C | grep -c '^cm_ssl_cert\.key\.old-') = 1 ] && [ \$(ls -A $C | grep -c '^cm_ssl_cert\.crt\.tmp-') = 1 ] && grep -q 'restored at the next start' $work/out"
  ensure YES
  ok "replacement and its undo both fail, next start: previous pair restored" \
    "[ $RET = 0 ] && [ \"\$(files_sum)\" = \"$sum\" ] && [ \$(nfiles) = 2 ]"

  setup
  LD_PRELOAD="$fault_lib" FAULT_RENAME_SRC="crt.tmp-" FAULT_UNLINK_END="/cm_ssl_cert.key" \
    timeout 30 "$driver" generate "$CRT" "$KEY" < /dev/null > "$work/out" 2>&1
  RET=$?
  ok "first generation and its undo both fail: fails, work files kept" \
    "[ $RET != 0 ] && [ -f $KEY ] && [ \$(ls -A $C | grep -c '^cm_ssl_cert\.key\.new-') = 1 ] && [ \$(ls -A $C | grep -c '^cm_ssl_cert\.crt\.tmp-') = 1 ]"
  ensure YES
  ok "first generation and its undo both fail, next start: generated again" \
    "[ $RET = 0 ] && [ \$(nfiles) = 2 ] && [ \"\$(key_fp $KEY)\" = \"\$(cert_fp $CRT)\" ]"

  # the undo succeeds: nothing is left
  setup
  make_own_pair
  sum=$(files_sum)
  LD_PRELOAD="$fault_lib" FAULT_RENAME_SRC="crt.tmp-" timeout 30 "$driver" generate "$CRT" "$KEY" \
    < /dev/null > "$work/out" 2>&1
  RET=$?
  ok "replacement fails, undone: previous pair, no work files" \
    "[ $RET != 0 ] && [ \"\$(files_sum)\" = \"$sum\" ] && [ \$(nfiles) = 2 ]"
else
  skip=$((skip + 1))
  echo "SKIP  failing undo scenarios (fault_inject.so could not be built)"
fi

# directory entries reach the disk in order: each rename is followed by an
# fsync of the directory before the next step (traced with fault_inject.so)
if [ -n "$fault_lib" ]; then
  setup
  make_own_pair
  LD_PRELOAD="$fault_lib" FAULT_TRACE="$work/trace" timeout 30 "$driver" generate "$CRT" "$KEY" \
    < /dev/null > "$work/out" 2>&1
  RET=$?
  steps=$(grep -v '^unlink [^ ]*\.tmp-' "$work/trace" | sed -e 's| [^ ]*/cm_ssl_cert\.key\.old-[0-9a-f]*| OLD|g' \
    -e 's| [^ ]*/cm_ssl_cert\.key\.tmp-[0-9a-f]*| KEYTMP|g' -e 's| [^ ]*/cm_ssl_cert\.crt\.tmp-[0-9a-f]*| CRTTMP|g' \
    -e 's| [^ ]*/cm_ssl_cert\.key | KEY |' -e 's| [^ ]*/cm_ssl_cert\.key$| KEY|' -e 's| [^ ]*/cm_ssl_cert\.crt$| CRT|' | tr '\n' ';')
  rm -f "$work/trace"
  ok "replacement: directory synced after each step" \
    "[ $RET = 0 ] && [ \"\$steps\" = 'rename KEY OLD;fsyncdir ;rename KEYTMP KEY;fsyncdir ;rename CRTTMP CRT;fsyncdir ;unlink OLD;fsyncdir ;' ]"

  # a directory that cannot be synced: the replacement is undone, the previous pair stays
  setup
  make_own_pair
  sum=$(files_sum)
  LD_PRELOAD="$fault_lib" FAULT_FSYNC_DIR=1 timeout 30 "$driver" generate "$CRT" "$KEY" \
    < /dev/null > "$work/out" 2>&1
  RET=$?
  ok "directory cannot be synced: generate fails, previous pair kept" \
    "[ $RET != 0 ] && [ \"\$(files_sum)\" = \"$sum\" ] && grep -q 'cannot sync the directory' $work/out"
  ensure YES
  ok "directory cannot be synced, next start: previous pair, no work files" \
    "[ $RET = 0 ] && [ \"\$(files_sum)\" = \"$sum\" ] && [ \$(nfiles) = 2 ]"

  # the directory cannot be synced after the new certificate is in place: the
  # new pair is kept (never the previous key with the new certificate), with
  # its record, which the next start removes
  setup
  make_own_pair
  old_key=$(key_fp "$KEY")
  LD_PRELOAD="$fault_lib" FAULT_FSYNC_DIR_NTH=3 timeout 30 "$driver" generate "$CRT" "$KEY" \
    < /dev/null > "$work/out" 2>&1
  RET=$?
  ok "sync fails after the certificate: new pair kept, record kept" \
    "[ $RET = 0 ] && [ \"\$(key_fp $KEY)\" = \"\$(cert_fp $CRT)\" ] && [ \"\$(key_fp $KEY)\" != \"$old_key\" ] && [ \$(ls -A $C | grep -c '^cm_ssl_cert\.key\.old-') = 1 ] && log | grep -q 'cannot be synced'"
  ensure YES
  ok "sync fails after the certificate, next start: new pair, record removed" \
    "[ $RET = 0 ] && [ \"\$(key_fp $KEY)\" = \"\$(cert_fp $CRT)\" ] && [ \"\$(key_fp $KEY)\" != \"$old_key\" ] && [ \$(nfiles) = 2 ]"

  setup
  LD_PRELOAD="$fault_lib" FAULT_FSYNC_DIR_NTH=3 timeout 30 "$driver" generate "$CRT" "$KEY" \
    < /dev/null > "$work/out" 2>&1
  RET=$?
  ok "first generation, sync fails after the certificate: pair kept, record kept" \
    "[ $RET = 0 ] && [ \"\$(key_fp $KEY)\" = \"\$(cert_fp $CRT)\" ] && [ \$(ls -A $C | grep -c '^cm_ssl_cert\.key\.new-') = 1 ]"
  ensure YES
  ok "first generation, sync fails after the certificate, next start: same pair, record removed" \
    "[ $RET = 0 ] && [ \"\$(key_fp $KEY)\" = \"\$(cert_fp $CRT)\" ] && [ \$(nfiles) = 2 ]"

  # the directory cannot be synced after the new key, before the certificate: undone
  setup
  make_own_pair
  sum=$(files_sum)
  LD_PRELOAD="$fault_lib" FAULT_FSYNC_DIR_NTH=2 timeout 30 "$driver" generate "$CRT" "$KEY" \
    < /dev/null > "$work/out" 2>&1
  RET=$?
  ok "sync fails after the key: undone, previous pair" \
    "[ $RET != 0 ] && [ \"\$(files_sum)\" = \"$sum\" ] && [ \$(nfiles) = 2 ]"
fi

# names that are not work files are left alone
setup
make_own_pair
echo keep > "$KEY.old-1234567"
echo keep > "$KEY.old-DEADBEEF"
echo keep > "$CRT.tmp-deadbeef.bak"
echo keep > "$KEY.new-deadbee"
ensure YES
ok "other names are not work files: kept" \
  "[ $RET = 0 ] && [ -f $KEY.old-1234567 ] && [ -f $KEY.old-DEADBEEF ] && [ -f $CRT.tmp-deadbeef.bak ] && [ -f $KEY.new-deadbee ]"

# ------------------------------------------------------- other processes

# another process holds the lock: stop before touching any file
setup
python3 -c "
import fcntl, sys, time
f = open(sys.argv[1], 'a')
fcntl.lockf(f, fcntl.LOCK_EX)
open(sys.argv[2], 'w').close()
time.sleep(15)
" "$KEY.lock" "$work/locked" &
holder=$!
for i in $(seq 1 50); do [ -f "$work/locked" ] && break; sleep 0.1; done
t0=$(date +%s)
ensure YES
t1=$(date +%s)
ok "lock held by another process: does not start, nothing created" \
  "[ $RET != 0 ] && [ \$(nfiles) = 0 ] && grep -q 'why=cannot check the SSL key pair: another cub_manager process holds' $work/out"
ok "lock held by another process: waits a few seconds first" "[ \$((t1 - t0)) -ge 4 -a \$((t1 - t0)) -le 10 ]"
kill $holder 2> /dev/null
wait $holder 2> /dev/null
rm -f "$work/locked"
ensure YES
ok "lock released: starts" "[ $RET = 0 ] && [ \$(nfiles) = 2 ]"

# cm_ssl_cert_lock_process (), which main () calls before it writes the pid file
setup
timeout 30 "$driver" lock "$KEY" < /dev/null > "$work/out" 2>&1
RET=$?
ok "lock_process: taken" "[ $RET = 0 ] && grep -q 'ret=0' $work/out && [ -f $KEY.lock ]"
python3 -c "
import fcntl, sys, time
f = open(sys.argv[1], 'a')
fcntl.lockf(f, fcntl.LOCK_EX)
open(sys.argv[2], 'w').close()
time.sleep(15)
" "$KEY.lock" "$work/locked" &
holder=$!
for i in $(seq 1 50); do [ -f "$work/locked" ] && break; sleep 0.1; done
timeout 30 "$driver" lock "$KEY" < /dev/null > "$work/out" 2>&1
RET=$?
ok "lock_process: held by another process, refused with the reason" \
  "[ $RET != 0 ] && grep -q 'why=another cub_manager process holds' $work/out"
kill $holder 2> /dev/null
wait $holder 2> /dev/null
rm -f "$work/locked"

# a read-only conf: no lock file can be created, and none is needed
if ! skip_as_root "read-only conf"; then
  setup
  make_own_pair
  sum=$(files_sum)
  chmod 555 "$C"
  ensure YES
  ok "own pair in a read-only conf: starts, nothing created" \
    "[ $RET = 0 ] && [ \"\$(files_sum)\" = \"$sum\" ] && [ ! -e $KEY.lock ]"
  chmod 755 "$C"
fi

# a lock file this account cannot open (for example left by a start as root):
# not reported as another running process
if ! skip_as_root "lock file of another account"; then
  setup
  make_own_pair
  : > "$KEY.lock"
  chmod 000 "$KEY.lock"
  ensure YES
  ok "lock file not openable: does not start, says to check its owner and mode" \
    "[ $RET != 0 ] && grep -q 'why=cannot check the SSL key pair: cannot open the lock file .*Permission denied (owner .*mode 0000; this process runs as' $work/out"
  ok "lock file not openable: not reported as another process" \
    "! log | grep -q 'Another cub_manager may be starting' && log | grep -q 'remove it while no cub_manager is running'"
  timeout 30 "$driver" lock "$KEY" < /dev/null > "$work/out" 2>&1
  ok "lock file not openable, lock_process: same reason" \
    "grep -q 'why=cannot open the lock file .*Permission denied' $work/out && ! log | grep -q 'another cub_manager may be starting'"
  chmod 600 "$KEY.lock"
fi

# several processes start at once on an empty conf: one pair, no work files
for round in 1 2 3; do
  setup
  for i in 1 2 3 4; do
    timeout 30 "$driver" ensure "$CRT" "$KEY" YES < /dev/null > "$work/out.$i" 2>&1 &
  done
  wait
  ok "4 processes at once ($round): all start with the same complete pair" \
    "[ \$(grep -l 'ret=0' $work/out.? | wc -l) = 4 ] && [ \$(nfiles) = 2 ] && [ \"\$(key_fp $KEY)\" = \"\$(cert_fp $CRT)\" ] && [ \$(log | grep -c 'generated a new SSL key pair') = 1 ]"
done

# ------------------------------------------------------- what TLS accepts

# whether OPENSSL_CONF sets the TLS security level with this OpenSSL
setup
cp "$shipped/develop/cm_ssl_cert_1024.crt" "$CRT"
cp "$shipped/develop/cm_ssl_cert_1024.key" "$KEY"
ensure_at NO 1
level1_ret=$RET
setup
cp "$shipped/develop/cm_ssl_cert_1024.crt" "$CRT"
cp "$shipped/develop/cm_ssl_cert_1024.key" "$KEY"
ensure_at NO 2
if [ $level1_ret = 0 ] && [ $RET != 0 ]; then
  for f in 11.3/cm_ssl_cert develop/cm_ssl_cert_1024; do
    setup
    cp "$shipped/$f.crt" "$CRT"
    cp "$shipped/$f.key" "$KEY"
    ensure_at NO 1
    ok "NO + $f, level 1: starts with a warning" "[ $RET = 0 ] && grep -q 'shipped_in_use=1' $work/out"

    setup
    cp "$shipped/$f.crt" "$CRT"
    cp "$shipped/$f.key" "$KEY"
    sum=$(files_sum)
    ensure_at NO 2
    ok "NO + $f, level 2: does not start, files kept" "[ $RET != 0 ] && [ \"\$(files_sum)\" = \"$sum\" ]"
    ok "NO + $f, level 2: why" \
      "grep -q 'why=the SSL key pair .* is the .*, and TLS refuses it (the certificate: .*key too small)$' $work/out"
    ok "NO + $f, level 2: what to do" "log | grep -q 'ssl_cert_auto_generate=YES in cm.conf and restart to replace it'"
    ok "NO + $f, level 2: not reported as in use" "grep -q 'shipped_in_use=0' $work/out"
  done

  setup
  cp "$shipped/11.3/cm_ssl_cert.crt" "$CRT"
  cp "$shipped/11.3/cm_ssl_cert.key" "$KEY"
  ensure_at YES 2
  ok "YES + 11.3 pair, level 2: replaced, starts" "[ $RET = 0 ] && ! is_shipped \$(key_fp $KEY)"

  setup
  install_develop 2048 2048
  ensure_at NO 2
  ok "NO + RSA 2048 shipped pair, level 2: starts with a warning" \
    "[ $RET = 0 ] && grep -q 'shipped_in_use=1' $work/out"

  setup
  openssl req -x509 -newkey rsa:1024 -nodes -keyout "$KEY" -out "$CRT" -subj /CN=own1024 -days 30 2> /dev/null
  sum=$(files_sum)
  ensure_at YES 2
  ok "own RSA 1024 pair, level 2: does not start, files kept" \
    "[ $RET != 0 ] && [ \"\$(files_sum)\" = \"$sum\" ] && grep -q 'why=TLS refuses the SSL key pair .*key too small)$' $work/out"

  setup
  ensure_at YES 3
  ok "new, YES, level 3: generated, but does not start" \
    "[ $RET != 0 ] && [ -f $CRT -a -f $KEY ] && grep -q 'why=TLS refuses the newly generated SSL key pair .*key too small)$' $work/out"
  ok "new, YES, level 3: what to do" "log | grep -q 'may require a stronger key than RSA 2048'"
else
  skip=$((skip + 1))
  echo "SKIP  TLS security level scenarios (OPENSSL_CONF does not set the TLS security level with this OpenSSL)"
fi

# ------------------------------------------------------------ ssl_cert_san

# names and addresses added to the defaults; duplicates of the defaults dropped
setup
export SSL_CERT_SAN="DNS:cms.example.com, IP:10.0.0.5,ip:fd00::5,dns:LOCALHOST,IP:127.0.0.1"
ensure YES
unset SSL_CERT_SAN
san=$(openssl x509 -in "$CRT" -noout -ext subjectAltName 2> /dev/null | tail -1)
ok "ssl_cert_san: starts" "[ $RET = 0 ]"
ok "ssl_cert_san: names and addresses added" \
  "grep -q 'DNS:cms.example.com' <<< \"\$san\" && grep -q 'IP Address:10.0.0.5' <<< \"\$san\" && grep -qi 'IP Address:FD00:0:0:0:0:0:0:5' <<< \"\$san\""
ok "ssl_cert_san: defaults kept, no duplicates" \
  "[ \$(grep -o -i 'DNS:localhost' <<< \"\$san\" | wc -l) = 1 ] && [ \$(grep -o 'IP Address:127.0.0.1' <<< \"\$san\" | wc -l) = 1 ] && grep -q 'IP Address:0:0:0:0:0:0:0:1' <<< \"\$san\""
ok "ssl_cert_san: verify cms.example.com" "openssl verify -CAfile $CRT -verify_hostname cms.example.com $CRT > /dev/null 2>&1"
ok "ssl_cert_san: verify 10.0.0.5" "openssl verify -CAfile $CRT -verify_ip 10.0.0.5 $CRT > /dev/null 2>&1"
ok "ssl_cert_san: verify fd00::5" "openssl verify -CAfile $CRT -verify_ip fd00::5 $CRT > /dev/null 2>&1"
sum=$(files_sum)
export SSL_CERT_SAN="DNS:cms.example.com,IP:10.0.0.5,IP:fd00::5"
ensure YES
unset SSL_CERT_SAN
ok "ssl_cert_san: restart with the same names, no warning" \
  "[ $RET = 0 ] && [ \"\$(files_sum)\" = \"$sum\" ] && ! log | grep -q 'does not have\\|which neither'"

# entries that cannot be used are logged and left out
setup
export SSL_CERT_SAN="DNS:bad_name,IP:999.1.1.1,FOO:x,DNS:,IP:10.0.0.6"
ensure YES
unset SSL_CERT_SAN
san=$(openssl x509 -in "$CRT" -noout -ext subjectAltName 2> /dev/null | tail -1)
ok "ssl_cert_san with bad entries: starts, good entry added" "[ $RET = 0 ] && grep -q 'IP Address:10.0.0.6' <<< \"\$san\""
ok "ssl_cert_san with bad entries: bad entries left out and logged" \
  "! grep -q 'bad_name' <<< \"\$san\" && [ \$(log | grep -c 'ssl_cert_san in cm.conf: ignored') = 4 ]"

# DNS names are checked label by label (RFC 1123)
setup
l63=$(printf 'a%.0s' $(seq 1 63))
export SSL_CERT_SAN="DNS:a..b,DNS:a-.example.com,DNS:-a.example.com,DNS:${l63}a.com,DNS:example.com.,DNS:a-b.example.com,DNS:${l63}.com"
ensure YES
unset SSL_CERT_SAN
san=$(openssl x509 -in "$CRT" -noout -ext subjectAltName 2> /dev/null | tail -1)
ok "ssl_cert_san DNS labels: valid names added" \
  "[ $RET = 0 ] && grep -q 'DNS:a-b.example.com' <<< \"\$san\" && grep -q \"DNS:${l63}.com\" <<< \"\$san\""
ok "ssl_cert_san DNS labels: empty, '-'-ended, 64-character labels and a trailing dot left out" \
  "! grep -q 'a\.\.b\|a-\.example\|-a\.example\|example\.com\.\|${l63}a' <<< \"\$san\" && [ \$(log | grep -c 'ssl_cert_san in cm.conf: ignored DNS:') = 5 ]"

# at most 32 entries
setup
list=""
for i in $(seq 1 33); do list="$list,IP:10.1.0.$i"; done
export SSL_CERT_SAN="${list#,}"
ensure YES
unset SSL_CERT_SAN
san=$(openssl x509 -in "$CRT" -noout -ext subjectAltName 2> /dev/null | tail -1)
ok "ssl_cert_san with 33 entries: 32 used, the rest logged" \
  "[ $RET = 0 ] && grep -q 'IP Address:10.1.0.32' <<< \"\$san\" && ! grep -q 'IP Address:10.1.0.33' <<< \"\$san\" && log | grep -q 'ignored IP:10.1.0.33 (more than 32 entries)'"

# applied only when generating: an existing pair is kept, and a warning says so
setup
make_own_pair
sum=$(files_sum)
export SSL_CERT_SAN="DNS:cms.example.com,IP:10.0.0.5"
ensure YES
unset SSL_CERT_SAN
ok "ssl_cert_san changed for an existing pair: pair kept, warning names the missing entries" \
  "[ $RET = 0 ] && [ \"\$(files_sum)\" = \"$sum\" ] && log | grep -q 'does not have DNS:cms.example.com, IP:10.0.0.5 of ssl_cert_san'"

# names in the certificate that the configuration no longer lists (self-signed only)
setup
export SSL_CERT_SAN="IP:10.0.0.5"
ensure YES
unset SSL_CERT_SAN
sum=$(files_sum)
ensure YES
ok "ssl_cert_san removed after generation: pair kept, warning names what the certificate still has" \
  "[ $RET = 0 ] && [ \"\$(files_sum)\" = \"$sum\" ] && log | grep -q 'has IP:10.0.0.5, which neither the defaults nor ssl_cert_san'"

# a certificate of an earlier build with the interface addresses
setup
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$KEY" -out "$CRT" -subj /CN=old -days 30 \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:192.168.0.10,IP:172.17.0.1" 2> /dev/null
ensure YES
ok "certificate with interface addresses: warning names them" \
  "[ $RET = 0 ] && log | grep -q 'has IP:192.168.0.10, IP:172.17.0.1, which neither'"

# a self-signed pair without names, and no ssl_cert_san: nothing to say
setup
make_own_pair
ensure YES
ok "own pair without SAN, no ssl_cert_san: no SAN warning" \
  "[ $RET = 0 ] && ! log | grep -q 'ssl_cert_san'"

# a CA-issued certificate: its names are what was asked of the CA, no warning either way
setup
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/ca2.key" -out "$work/ca2.crt" -subj /CN=RootCA2 -days 30 \
  2> /dev/null
openssl req -newkey rsa:2048 -nodes -keyout "$KEY" -out "$work/s2.csr" -subj /CN=server \
  -addext "subjectAltName=DNS:server.example.com,IP:192.168.0.20" 2> /dev/null
openssl x509 -req -in "$work/s2.csr" -CA "$work/ca2.crt" -CAkey "$work/ca2.key" -CAcreateserial -days 30 \
  -copy_extensions copy -out "$CRT" 2> /dev/null
export SSL_CERT_SAN="DNS:cms.example.com"
ensure YES
unset SSL_CERT_SAN
ok "CA-issued certificate with ssl_cert_san: no SAN warning" \
  "[ $RET = 0 ] && ! log | grep -q 'does not have\|which neither'"

# generate (generatecert) uses it too
setup
export SSL_CERT_SAN="DNS:gen.example.com"
timeout 30 "$driver" generate "$CRT" "$KEY" < /dev/null > "$work/out" 2>&1
RET=$?
unset SSL_CERT_SAN
ok "generate with ssl_cert_san: added" \
  "[ $RET = 0 ] && openssl x509 -in $CRT -noout -ext subjectAltName | grep -q 'DNS:gen.example.com'"

# --------------------------------------------------------------- generate

setup
install_develop 2048 2048
generate US myhost 30
ok "generate: succeeds" "[ $RET = 0 ]"
ok "generate: regular files, key 0600" "[ ! -L $CRT -a ! -L $KEY ] && [ \$(stat -c %a $KEY) = 600 ]"
ok "generate: subject from the options" \
  "[ \"\$(openssl x509 -in $CRT -noout -subject)\" = 'subject=C = US, CN = myhost' ]"
not_after=$(date -d "$(openssl x509 -in "$CRT" -noout -enddate | cut -d= -f2)" +%s)
ok "generate: validity from the options" \
  "[ \$(((not_after - now) / 86400)) -ge 29 -a \$(((not_after - now) / 86400)) -le 30 ]"
ok "generate: no .bak, no temporary file" "[ \$(ls -A $C | grep -c -e bak -e tmp -e old -e '\.new-') = 0 ]"
ok "generate: link targets left" "[ -f $C/cm_ssl_cert_2048.key ]"

sum=$(files_sum)
generate KOR
ok "generate: invalid country fails, files kept" \
  "[ $RET != 0 ] && [ \"\$(files_sum)\" = \"$sum\" ] && grep -q 'invalid subject C' $work/out && [ \$(nfiles) = 6 ]"
generate "" "" 99999
ok "generate: invalid validity fails, files kept" "[ $RET != 0 ] && [ \"\$(files_sum)\" = \"$sum\" ]"

generate
ok "generate: default subject" "[ $RET = 0 ] && openssl x509 -in $CRT -noout -subject | grep -q 'O = CUBRID'"

if ! skip_as_root "generate, conf not writable"; then
  chmod 555 "$C"
  sum=$(files_sum)
  generate
  ok "generate: conf not writable fails, files kept" "[ $RET != 0 ] && [ \"\$(files_sum)\" = \"$sum\" ]"
  chmod 755 "$C"
fi

# ------------------------------------------------------------------ result

echo "passed $pass, failed $fail, skipped $skip"
[ $fail = 0 ]
