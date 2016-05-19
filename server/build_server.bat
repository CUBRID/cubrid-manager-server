@echo off

REM prepare vc environment

call "%VS90COMNTOOLS%vsvars32.bat"

echo Start build cm_server ...
cd win

set cubrid_libdir=%cubrid_libdir%
set cubrid_includedir=%cubrid_includedir%

cmd /c devenv cmserver.sln /project install /rebuild "%mode%|%platform%"
set exitcode=%errorlevel%
cd ..
if not "%exitcode%" == "0" exit /b %exitcode%

cd win/install
cd CMServer_%mode%_%platform%

robocopy . %prefix%\ /e
if errorlevel 1 (
	set exitcode=0
	) else (
	set exitcode=%errorlevel%
	)
cd ..\..\..

