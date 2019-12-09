rem Copyright (c) 2019 London Trust Media Incorporated
rem
rem This file is part of the Private Internet Access Desktop Client.
rem
rem The Private Internet Access Desktop Client is free software: you can
rem redistribute it and/or modify it under the terms of the GNU General Public
rem License as published by the Free Software Foundation, either version 3 of
rem the License, or (at your option) any later version.
rem
rem The Private Internet Access Desktop Client is distributed in the hope that
rem it will be useful, but WITHOUT ANY WARRANTY; without even the implied
rem warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
rem GNU General Public License for more details.
rem
rem You should have received a copy of the GNU General Public License
rem along with the Private Internet Access Desktop Client.  If not, see
rem <https://www.gnu.org/licenses/>.

@echo off
setlocal EnableDelayedExpansion
pushd %~dp0

rem Specify these arguments in the environment before calling the script:
rem EWDK = path to EWDK (e.g. C:\EWDK\1804, tries to auto-detect)
rem See pia-sign-driver.bat for PIA_SIGN_* variables to define codesigning certificates

set ARG_SHOW_HELP=0
set ARG_CONFIG=Release

:arg_loop
if not "%1"=="" (
  if "%1"=="--help" (
    set ARG_SHOW_HELP=1
  ) else if "%1"=="--debug" (
    set ARG_CONFIG=Debug
  ) else (
    echo Unknown option %1
    set ARG_SHOW_HELP=1
  )
  shift
  goto arg_loop
)

if %ARG_SHOW_HELP% NEQ 0 (
  echo usage:
  echo   %0 [--debug]
  echo   %0 --help
  echo.
  echo Builds and signs the WFP callout driver.
  echo   --debug: Debug build ^(default is release^)
  echo   --help: Show help
  echo.
  echo EWDK:
  call pia-setup-ewdk.bat --help-env
  echo Code signing:
  call pia-sign-driver.bat --help-env
  exit /B 0
)

call pia-setup-ewdk.bat
@echo off

mkdir dist >NUL
mkdir tmp >NUL

for %%G in (x86,x64) do (
    rd /Q /S dist\%ARG_CONFIG%-%%G >NUL
    rd /Q /S tmp\%ARG_CONFIG%-%%G >NUL
    mkdir dist\%ARG_CONFIG%-%%G >NUL
    mkdir tmp\%ARG_CONFIG%-%%G >NUL
    if "%%G" == "x86" (
        rd /Q /S PiaWfpCallout\%ARG_CONFIG%
    ) else (
        rd /Q /S PiaWfpCallout\%ARG_CONFIG%
    )
)

for %%G in (x86,x64) do (
    set BUILD_ARCH=%%G
    set BUILD_DIST=dist\%ARG_CONFIG%-!BUILD_ARCH!
    set BUILD_TMP=tmp\%ARG_CONFIG%-!BUILD_ARCH!

    rem Ignore the WDF coinstaller when we copy artifacts.
    rem KMDF 1.9 is included with Windows 7, which is the earliest release we support.
    echo \WdfCoinstaller01009.dll >!BUILD_TMP!\xcopy_exclude.txt
    
    echo Building !BUILD_ARCH!
    msbuild.exe PiaWfpCallout\PiaWfpCallout.vcxproj -p:Configuration=%ARG_CONFIG% -p:Platform=!BUILD_ARCH!
    if !errorlevel! neq 0 goto error
    
    if [!BUILD_ARCH!] == [x86] (
        set OUTPUT_SUBDIR=""
    ) else (
        set OUTPUT_SUBDIR="!BUILD_ARCH!"
    )
    
    rem Copy artifacts to dist
    xcopy "PiaWfpCallout\!OUTPUT_SUBDIR!\%ARG_CONFIG%\PiaWfpCallout" "!BUILD_DIST!" /Q /E /I /Y /EXCLUDE:!BUILD_TMP!\xcopy_exclude.txt
    if !errorlevel! neq 0 goto error
    
    call pia-sign-driver.bat !BUILD_DIST!\piawfpcallout.cat dist pia-callout-%ARG_CONFIG%-!BUILD_ARCH!
    if !errorlevel! neq 0 goto error
)

:end
popd
endlocal
exit /b %errorlevel%

:error
if %errorlevel% equ 0 (
  set errorlevel=1
) else (
  echo.
  echo Build failed with error %errorlevel%!
)
goto end
