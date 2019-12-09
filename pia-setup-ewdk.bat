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
set SETUP_EWDK_ARG_SHOW_HELP=0
set SETUP_EWDK_ARG_SHOW_HELP_ENV_ONLY=0

:arg_loop
if not "%1"=="" (
  if "%1"=="--help" (
    set SETUP_EWDK_ARG_SHOW_HELP=1
  ) else if "%1"=="--help-env" (
    set SETUP_EWDK_ARG_SHOW_HELP=1
    set SETUP_EWDK_ARG_SHOW_HELP_ENV_ONLY=1
  ) else (
    echo Unknown option %1
    set SETUP_EWDK_ARG_SHOW_HELP=1
  )
  shift
  goto arg_loop
)

if %SETUP_EWDK_ARG_SHOW_HELP% NEQ 0 (
  rem help-env is used to embed the environment help in another script
  if %SETUP_EWDK_ARG_SHOW_HELP_ENV_ONLY% EQU 0 (
    echo usage:
    echo   %0
    echo   %0 --help
    echo.
    echo Locates and sets up the EWDK environment.
    echo Note: The EWDK setup script may turn echo back on.
    echo.
  )
  echo EWDK = path to the EWDK, by default the newest EWDK from C:\EWDK\* is used.
  echo.
  exit /B 0
)

if [%EWDK%] == [] (
  for /D %%G in ("C:\EWDK\*") do set "EWDK=%%G"
)
if not exist "%EWDK%" (
  echo Error: EWDK not found.
  goto error
)
echo * Using EWDK in %EWDK%

call "%EWDK%\BuildEnv\SetupBuildEnv.cmd"

:end
exit /b %errorlevel%

:error
if %errorlevel% equ 0 (
  set errorlevel=1
) else (
  echo.
  echo Build failed with error %errorlevel%!
)
goto end
