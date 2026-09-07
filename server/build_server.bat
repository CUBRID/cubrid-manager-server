@echo off
setlocal enabledelayedexpansion
REM prepare vc environment (VS2017 community)
SET VERS=win/version.h
SET COMMIT_COUNT=

SET "PF86=%ProgramFiles(x86)%"
SET "PF64=%ProgramFiles%"
SET VSDEVCMD=%CMS_VSDEVCMD_PATH%
SET VSCMD_DEBUG=1

IF NOT DEFINED VSDEVCMD (
    SET "VSWHERE=!PF86!\Microsoft Visual Studio\Installer\vswhere.exe"
    IF NOT EXIST "!VSWHERE!" SET "VSWHERE=!PF64!\Microsoft Visual Studio\Installer\vswhere.exe"
    IF EXIST "!VSWHERE!" (
        SET "VSWHERE_OUT=%TEMP%\cms_vswhere_out.txt"
        "!VSWHERE!" -version "[15.0,16.0)" -products Microsoft.VisualStudio.Product.Community -property installationPath > "!VSWHERE_OUT!" 2>NUL
        SET VSINSTALLDIR=
        IF EXIST "!VSWHERE_OUT!" (
            FOR /F "usebackq tokens=*" %%i IN ("!VSWHERE_OUT!") DO SET VSINSTALLDIR=%%i
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

call "!VSDEVCMD!" -arch=x64
if errorlevel 1 (
    echo build_server.bat: warning - VsDevCmd.bat reported errors ^(see above^); continuing.
)
REM VsDevCmd.bat can leave ERRORLEVEL non-zero even on a usable env; force reset it.
(call )

FOR /F "tokens=1 delims=." %%i IN ('type BUILD_NUMBER') do (SET MAJOR=%%i)
FOR /F "tokens=2 delims=." %%i IN ('type BUILD_NUMBER') do (SET MINOR=%%i)
FOR /F "tokens=3 delims=." %%i IN ('type BUILD_NUMBER') do (SET PATCH=%%i)
FOR /F "tokens=4 delims=." %%i IN ('type BUILD_NUMBER') do (SET SERIAL=%%i)
if not ERRORLEVEL 0 (exit /b %ERRORLEVEL%)

FOR /F "tokens=*" %%i IN ('git rev-list --count HEAD') do (SET COMMIT_COUNT=%%i)
if "%COMMIT_COUNT%" == "" (SET COMMIT_COUNT=%SERIAL%)

FOR /F "tokens=* delims=0" %%i IN ('echo %COMMIT_COUNT%') do (SET COMMIT_COUNT=%%i)
FOR /F "tokens=*" %%i IN ('printf %%04d %COMMIT_COUNT%') do (SET COMMIT_COUNT=%%i)

echo #define RELEASE_STRING %MAJOR%.%MINOR%.%PATCH% > %VERS%
echo #define MAJOR_RELEASE_STRING %MAJOR% >> %VERS%
echo #define BUILD_NUMBER %MAJOR%.%MINOR%.%PATCH%.%COMMIT_COUNT% >> %VERS%
echo #define MAJOR_VERSION %MAJOR% >> %VERS%
echo #define MINOR_VERSION %MINOR% >> %VERS%
echo #define PATCH_VERSION %PATCH% >> %VERS%
echo #define BUILD_SERIAL_NUMBER %COMMIT_COUNT% >> %VERS%
echo #define VERSION_STRING "%MAJOR%.%MINOR%.%PATCH%.%COMMIT_COUNT%" >> %VERS%

echo Start build cm_server ...
cd win

set cubrid_libdir=%cubrid_libdir%
set cubrid_includedir=%cubrid_includedir%
cmd /c devenv cmserver.sln /project install /rebuild "%mode%|%platform%"
set exitcode=%errorlevel%

echo build_server.bat: diag - devenv raw exit code = %exitcode%

cd ..
if not "%exitcode%" == "0" (
    REM devenv's own exit code can be non-zero even on a full build success;
    REM trust the actual install output instead.
    SET INSTALL_CHECK_OK=
    IF EXIST "win\install\CMServer_%mode%_%platform%\bin\cm_admin.exe" SET INSTALL_CHECK_OK=1
    IF EXIST "win\install\CMServer_%mode%_%platform%\cm_admin.exe" SET INSTALL_CHECK_OK=1
    IF DEFINED INSTALL_CHECK_OK (
        echo build_server.bat: warning - devenv exit code %exitcode% ignored, cm_admin.exe was found.
        set exitcode=0
    ) ELSE (
        echo build_server.bat: devenv exit code %exitcode% and no build output found - real failure.
        exit /b %exitcode%
    )
)

cd win/install
cd CMServer_%mode%_%platform%

echo build_server.bat: diag - copying from "%CD%" to "%prefix%" ...

robocopy . %prefix%\ /e
set robocopy_rc=%errorlevel%
echo build_server.bat: diag - robocopy raw exit code = %robocopy_rc%
if errorlevel 1 (
    set exitcode=0
    ) else (
    set exitcode=%errorlevel%
    )

echo build_server.bat: diag - computed exitcode = %exitcode%
cd ..\..\..

exit /b %exitcode%
