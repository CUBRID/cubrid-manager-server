#!/bin/bash

cur_dir=`pwd`
ext_dir=$cur_dir/external
bit_mode=$1

chmod -R +w $ext_dir $cur_dir

function build_libevent()
{
    cd $ext_dir
    rm -rf libevent-2.1.4-alpha
    tar zxvf libevent-2.1.4-alpha.tar.gz
    cd libevent-2.1.4-alpha
    ./configure --prefix=$cur_dir CFLAGS="$CFLAGS $bit_mode" LDFLAGS="$LDFLAGS $bit_mode"
    make;
    make install
}

function build_json() 
{
    cd $ext_dir
    rm -rf jsoncpp-src-0.5.0
    tar zxvf jsoncpp-src-0.5.0.tar.gz
    cd jsoncpp-src-0.5.0
    g++ $bit_mode -o src/lib_json/json_reader.o -c -Wall -Iinclude src/lib_json/json_reader.cpp
    g++ $bit_mode -o src/lib_json/json_value.o -c -Wall -Iinclude src/lib_json/json_value.cpp
    g++ $bit_mode -o src/lib_json/json_writer.o -c -Wall -Iinclude src/lib_json/json_writer.cpp
    ar rc src/lib_json/libjson.a src/lib_json/json_reader.o src/lib_json/json_value.o src/lib_json/json_writer.o
    ranlib src/lib_json/libjson.a
    cp -r include $cur_dir
    cp src/lib_json/libjson.a $cur_dir/lib/
}

function build_openssl() 
{
    cd $ext_dir
    rm -rf openssl-1.0.1g
    tar zxvf openssl-1.0.1g.tar.gz 
    cd openssl-1.0.1g
    ./config --prefix=$ext_dir/openssl-1.0.1g/.openssl no-shared  threads  $bit_mode
    make
    make install LIBDIR=lib
}

echo -n "checking for openssl ... "
build_openssl > /dev/null
echo "found"
#build libevent
echo -n "checking for libevent ... "
build_libevent > /dev/null
echo "found"
#build json
echo -n "checking for json ... "
build_json  > /dev/null
echo "found"


cd $cur_dir
