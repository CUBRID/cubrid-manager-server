@echo off
setlocal enabledelayedexpansion
REM prepare vc environment
SET VERS=win/version.h
SET COMMIT_COUNT=
REM ----------------------------------------------------------------------
REM Locate and initialize the Visual Studio build environment.
REM This build supports Visual Studio 2017 Community only
REM
REM Set CMS_VSDEVCMD_PATH to point at a different VsDevCmd.bat instead.
REM ----------------------------------------------------------------------
SET "PF86=%ProgramFiles(x86)%"
SET "PF64=%ProgramFiles%"
SET VSDEVCMD=%CMS_VSDEVCMD_PATH%

IF NOT DEFINED VSDEVCMD (
	FOR %%P IN ("!PF86!" "!PF64!") DO (
		IF NOT DEFINED VSDEVCMD (
			IF EXIST "%%~P\Microsoft Visual Studio\2017\Community\Common7\Tools\VsDevCmd.bat" (
				SET "VSDEVCMD=%%~P\Microsoft Visual Studio\2017\Community\Common7\Tools\VsDevCmd.bat"
			)
		)
	)
)

IF NOT DEFINED VSDEVCMD (
	echo build_server.bat: Visual Studio 2017 Community was not found.
	echo Set the CMS_VSDEVCMD_PATH environment variable to a specific VsDevCmd.bat to override.
	exit /b 1
)

call "!VSDEVCMD!" -arch=x64
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

