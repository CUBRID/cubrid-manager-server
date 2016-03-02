#!/bin/bash
make clean
mkdir -p log

cub_js stop
cub_auto stop

valgrind  --leak-check=full --log-file=./log/cmserver_auto.valgrind.log cub_auto start
valgrind  --leak-check=full --log-file=./log/cmserver_js.valgrind.log cub_js start

cub_cmserver stop
sleep 3
valgrind  --leak-check=full --log-file=./log/cmserver_cmserver.valgrind.log cub_cmserver start

sed -i -e '/invalid file descriptor .* in syscall close/d' -e '/to select an alternative log fd/d' ./log/cmserver_*.valgrind.log*

cubrid deletedb anotherdb   #remove legacy test database
cubrid deletedb alatestdb #remove legacy test database
cubrid deletedb copydb #remove legacy test database
cubrid deletedb destinationdb #remove legacy test database

make test 

cub_js stop     #must stop before 'make lcov'
cub_auto stop   #must stop before 'make lcov'
sleep 5
make lcov

cubrid deletedb anotherdb   #remove legacy test database
cubrid deletedb copydb #remove legacy test database
cubrid deletedb destinationdb #remove legacy test database
cubrid deletedb alatestdb #remove legacy test database


