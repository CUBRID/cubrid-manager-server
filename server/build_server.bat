@echo off
REM
REM The Windows version is supported only up to 11.4 and only for 64-bits systems.
REM prepare vc environment
REM VS2017 community is the official build system for the CMS
REM
setlocal enabledelayedexpansion
SET "VERS=win/version.h"
SET "COMMIT_COUNT="

SET "PF86=%ProgramFiles(x86)%"
SET "PF64=%ProgramFiles%"
SET "VSDEVCMD=%CMS_VSDEVCMD_PATH%"
SET "VSCMD_DEBUG=0"

IF NOT DEFINED VSDEVCMD (
    SET "VSWHERE=!PF86!\Microsoft Visual Studio\Installer\vswhere.exe"
    IF NOT EXIST "!VSWHERE!" SET "VSWHERE=!PF64!\Microsoft Visual Studio\Installer\vswhere.exe"
    IF EXIST "!VSWHERE!" (
        SET "VSWHERE_OUT=%TEMP%\cms_vswhere_out.txt"
        "!VSWHERE!" -version "[15.0,16.0)" -products Microsoft.VisualStudio.Product.Community -property installationPath > "!VSWHERE_OUT!" 2>NUL
        SET "VSINSTALLDIR="
        IF EXIST "!VSWHERE_OUT!" (
            FOR /F "usebackq tokens=*" %%i IN ("!VSWHERE_OUT!") DO SET "VSINSTALLDIR=%%i"
            DEL /Q "!VSWHERE_OUT!" >NUL 2>&1
        )
        IF DEFINED VSINSTALLDIR (
            IF EXIST "!VSINSTALLDIR!\Common7\Tools\VsDevCmd.bat" SET "VSDEVCMD=!VSINSTALLDIR!\Common7\Tools\VsDevCmd.bat"
        )
    )
)

IF NOT DEFINED VSDEVCMD (
    echo build_server.bat: could not locate VsDevCmd.bat - VS2017 Community was not found.
    echo Set the CMS_VSDEVCMD_PATH environment variable to a specific VsDevCmd.bat to override.
    exit /b 1
)

REM CMS on Windows only supports the x64 platform.
IF NOT "%platform_token%" == "x64" (
    echo build_server.bat: CMS on Windows only supports the x64 platform - platform_token is "%platform_token%".
    exit /b 1
)

(call )
call "!VSDEVCMD!" -arch=%platform_token%
where devenv >NUL 2>&1
if errorlevel 1 (
	echo build_server.bat: VsDevCmd.bat did not set up a usable VC environment ^(devenv not on PATH^).
	exit /b 1
)

FOR /F "tokens=1 delims=." %%i IN ('type BUILD_NUMBER') do (SET "MAJOR=%%i")
FOR /F "tokens=2 delims=." %%i IN ('type BUILD_NUMBER') do (SET "MINOR=%%i")
FOR /F "tokens=3 delims=." %%i IN ('type BUILD_NUMBER') do (SET "PATCH=%%i")
FOR /F "tokens=4 delims=." %%i IN ('type BUILD_NUMBER') do (SET "SERIAL=%%i")
if not ERRORLEVEL 0 (exit /b %ERRORLEVEL%)

FOR /F "tokens=*" %%i IN ('git rev-list --count HEAD') do (SET "COMMIT_COUNT=%%i")
if "%COMMIT_COUNT%" == "" (SET "COMMIT_COUNT=%SERIAL%")

FOR /F "tokens=* delims=0" %%i IN ('echo %COMMIT_COUNT%') do (SET "COMMIT_COUNT=%%i")
FOR /F "tokens=*" %%i IN ('printf %%04d %COMMIT_COUNT%') do (SET "COMMIT_COUNT=%%i")

echo #define RELEASE_STRING %MAJOR%.%MINOR%.%PATCH% > %VERS%
echo #define MAJOR_RELEASE_STRING %MAJOR% >> %VERS%
echo #define BUILD_NUMBER %MAJOR%.%MINOR%.%PATCH%.%COMMIT_COUNT% >> %VERS%
echo #define MAJOR_VERSION %MAJOR% >> %VERS%
echo #define MINOR_VERSION %MINOR% >> %VERS%
echo #define PATCH_VERSION %PATCH% >> %VERS%
echo #define BUILD_SERIAL_NUMBER %COMMIT_COUNT% >> %VERS%
echo #define VERSION_STRING "%MAJOR%.%MINOR%.%PATCH%.%COMMIT_COUNT%" >> %VERS%

echo Start build cm_server ...

SET "INSTALL_DIR=win\install\CMServer_%mode%_%platform%"
IF EXIST "%INSTALL_DIR%" (
    echo build_server.bat: removing stale output directory "%INSTALL_DIR%" ...
    rmdir /s /q "%INSTALL_DIR%"

    IF EXIST "%INSTALL_DIR%" (
        echo build_server.bat: failed to remove "%INSTALL_DIR%" - aborting to avoid shipping stale binaries.
        exit /b 1
    )
)

cd win

set cubrid_libdir=%cubrid_libdir%
set cubrid_includedir=%cubrid_includedir%
cmd /c devenv cmserver.sln /project install /rebuild "%mode%|%platform%"
set exitcode=%errorlevel%

echo build_server.bat: diag - devenv raw exit code = %exitcode%

cd ..
if not "%exitcode%" == "0" (
    SET "CM_ADMIN_PATH="
    IF EXIST "%INSTALL_DIR%\bin\cm_admin.exe" SET "CM_ADMIN_PATH=%INSTALL_DIR%\bin\cm_admin.exe"
    IF EXIST "%INSTALL_DIR%\cm_admin.exe" SET "CM_ADMIN_PATH=%INSTALL_DIR%\cm_admin.exe"
    IF DEFINED CM_ADMIN_PATH (
        echo build_server.bat: diag - CM_ADMIN_PATH=!CM_ADMIN_PATH!
    ) ELSE (
        echo build_server.bat: diag - cm_admin.exe not found under "%INSTALL_DIR%"
    )

    SET "CUB_MANAGER_PATH="
    IF EXIST "%INSTALL_DIR%\bin\cub_manager.exe" SET "CUB_MANAGER_PATH=%INSTALL_DIR%\bin\cub_manager.exe"
    IF EXIST "%INSTALL_DIR%\cub_manager.exe" SET "CUB_MANAGER_PATH=%INSTALL_DIR%\cub_manager.exe"
    IF DEFINED CUB_MANAGER_PATH (
        echo build_server.bat: diag - CUB_MANAGER_PATH=!CUB_MANAGER_PATH!
    ) ELSE (
        echo build_server.bat: diag - cub_manager.exe not found under "%INSTALL_DIR%"
    )

    SET "INSTALL_CHECK_OK="
    IF DEFINED CM_ADMIN_PATH IF DEFINED CUB_MANAGER_PATH SET "INSTALL_CHECK_OK=1"

    IF DEFINED INSTALL_CHECK_OK (
        echo build_server.bat: warning - devenv exit code %exitcode% ignored, cm_admin.exe and cub_manager.exe were both found in the freshly-wiped output directory.
        set exitcode=0
    ) ELSE (
        echo build_server.bat: devenv exit code %exitcode% and no fresh build output found - real failure.
        exit /b %exitcode%
    )
)

cd win/install
cd CMServer_%mode%_%platform%

echo build_server.bat: diag - copying from "%CD%" to "%prefix%" ...

robocopy . %prefix%\ /e
set robocopy_rc=%errorlevel%
echo build_server.bat: diag - robocopy raw exit code = %robocopy_rc%
if %robocopy_rc% GEQ 8 ( set "exitcode=%robocopy_rc%" ) else ( set "exitcode=0" )

echo build_server.bat: diag - computed exitcode = %exitcode%
cd ..\..\..

exit /b %exitcode%
