@echo off

if "%1" == "" goto exit
if "%2" == "" goto exit

set SRC_DIR=%1
set DEST_DIR=%2
set exitcode=0

mkdir %DEST_DIR%
mkdir %DEST_DIR%\bin
mkdir %DEST_DIR%\conf

copy %SRC_DIR%\*.exe %DEST_DIR%\bin || exit /b 1

REM pdb may be absent in some configurations - not fatal
copy %SRC_DIR%\*.pdb %DEST_DIR%\bin

IF NOT EXIST "%DEST_DIR%\bin\cub_manager.exe" exit /b 1
IF NOT EXIST "%DEST_DIR%\bin\cm_admin.exe" exit /b 1

copy %SRC_DIR%\..\..\cmserver\conf\*.conf %DEST_DIR%\conf || exit /b 1
copy %SRC_DIR%\..\..\cmserver\conf\*.pass %DEST_DIR%\conf || exit /b 1
REM the TLS key pair is not installed: cub_manager generates it when it first starts

exit /b %errorlevel%
