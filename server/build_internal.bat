@echo off

if "%1" == "" goto PRINT_USAGE

set cubrid_dir=%CUBRID%
set platform=Win32
set mode=release

:LOOP_BEGIN

if "%1" == "" goto LOOP_END

if "%1" == "--help" goto PRINT_USAGE
if "%1" == "--prefix" set prefix=%2& shift & shift & goto LOOP_BEGIN
if "%1" == "--with-cubrid-dir" set cubrid_dir=%2& shift & shift & goto LOOP_BEGIN
if "%1" == "--with-cubrid-libdir" set cubrid_libdir=%2& shift & shift & goto LOOP_BEGIN
if "%1" == "--with-cubrid-includedir" set cubrid_includedir=%2& shift & shift & goto LOOP_BEGIN
if "%1" == "--enable-64bit" set platform=x64& shift & goto LOOP_BEGIN
if "%1" == "--enable-debug" set mode=debug& shift & goto LOOP_BEGIN

shift
:LOOP_END

if "%cubrid_libdir%" == "" (
	set cubrid_libdir=%cubrid_dir%\lib
)

if "%cubrid_includedir%" == "" (
	set cubrid_includedir=%cubrid_dir%\include
)

if "%cubrid_libdir%" == "\lib" (
	echo "Please specify --with-cubrid-libdir option"
	exit /B 1
)

if "%cubrid_includedir%" == "\include" (
	echo "Please specify --with-cubrid-includedir option"
	exit /B 1
)

if "%prefix%" == "" (
	echo "Please specify --prefix option"
	exit /B 1
)

echo CUBRID include path is %cubrid_libdir%
echo CUBRID lib path is %cubrid_includedir%
echo OUTPUT path is %prefix%

echo Platform type is "%platform%"
echo Debug mode is "%mode%"

if not exist %prefix% (
	mkdir %prefix%
)

call build_server.bat
set exitcode=!errorlevel!

if "!exitcode!" == "0" (
	echo build successful
) else (
	echo build failed
	exit /b !exitcode!
)

set platform_token=%platform%
if "%platform%" == "Win32" set platform_token=x86

if "%mode%" == "debug" set is_debug=true

set target_server=pack_server

exit /b

:PRINT_USAGE
@echo Usage: build [OPTION]
@echo Build whole CUBRID Manager project
@echo.
@echo   --prefix=DIR                  build result output directory (required)
@echo   --with-cubrid-dir=DIR         directory have two sub directory (optional)
@echo                                 'include', 'lib'. default to %%CUBRID%%
@echo   --with-cubrid-libdir=DIR      directory have cubrid lib files (optional)
@echo                                 default to with_cubrid_dir\lib
@echo   --with-cubrid-includedir=DIR  directory have cubrid include files (optional)
@echo                                 default to with_cubrid_dir\include
@echo   --enable-64bit                build 64bit applications
@echo   --enable-debug                build debug version applications
@echo.
@echo   --help                        display this help and exit
@echo.
@echo   Examples:
@echo     build --prefix=c:\out\x64 --with-cubrid-dir=%%CUBRID%%
