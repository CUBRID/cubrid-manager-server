@echo off

if "%1" == "" goto exit
if "%2" == "" goto exit

set SRC_DIR=%1
set DEST_DIR=%2
set exitcode=0
set SSL_RSA_BITS=2048

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
copy %SRC_DIR%\..\..\cmserver\conf\cm_ssl* %DEST_DIR%\conf || exit /b 1
copy %SRC_DIR%\..\..\cmserver\conf\cm_ssl_cert_%SSL_RSA_BITS%.key %DEST_DIR%\conf\cm_ssl_cert.key || exit /b 1
copy %SRC_DIR%\..\..\cmserver\conf\cm_ssl_cert_%SSL_RSA_BITS%.crt %DEST_DIR%\conf\cm_ssl_cert.crt || exit /b 1

exit /b %errorlevel%
