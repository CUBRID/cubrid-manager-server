CUR_PATH=$(shell /bin/pwd)
COVERAGE_PATH=../cmserver/

test:
	python test_cci.py
	/usr/bin/php -q test_tasks.php ./log/test_cmserver.xml
	g++ -o sendfile sendfile.cpp
	./sendfile task_test_case/jobfile task_test_case/jobfile.zip	
	python test_tasks.py

	
lcov:	
	rm -f $(CUR_PATH)/log/CM_SERVER.CoverageResult.info
	lcov -q -d $(COVERAGE_PATH) --no-recursion -b . -c -t CM_SERVER -o log/tmp.CM_SERVER.CoverageResult.info --ignore-errors source	
	lcov --remove log/tmp.CM_SERVER.CoverageResult.info stat.h sysmacros.h *.h -o log/CM_SERVER.CoverageResult.info
	rm log/tmp.CM_SERVER.CoverageResult.info

clean:
	rm -rf log

.PHONY: test lcov clean 
