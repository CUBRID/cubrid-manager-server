#!/bin/bash

############################
CRT_PATH=`pwd`

########## set env #############
#source set_hudson_env.sh

chmod +x autogen.sh
##########build#############
./autogen.sh
./configure --enable-64bit --enable-coverage

make clean
make -j
make install
if [ $? = 0 ] 
then
echo "build success"
else
echo "build error"
fi


######### run test #############
case  x$1 in 
xtest)
cp $CUBRID/conf/cubrid.conf $CRT_PATH/test/task_test_config/orign/
#cp $CRT_PATH/test/task_test_config/ha_conf/cubrid.conf $CUBRID/conf/
cp -f $CRT_PATH/test/task_test_config/cm_conf/*.conf $CUBRID/conf/

cubrid service restart
cubrid server start demodb

cd test/
./hudsonbuild.sh
cubrid service stop

#cp  $CRT_PATH/test/task_test_config/orign/cubrid.conf $CUBRID/conf/
echo "test done!"

;;
xclean)
make clean
;;
*)
echo "invalid option! Valid option: [test]"
;;  

esac
