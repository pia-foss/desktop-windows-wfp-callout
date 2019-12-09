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

set SIGN_DRIVER_ARG_SHOW_HELP=0
set SIGN_DRIVER_ARG_SHOW_HELP_ENV_ONLY=0

:arg_loop
set PARAM_TEST=%1
if not "%PARAM_TEST%" == "" (
  set PARAM_TEST=%PARAM_TEST:~0,2%
)
if "%PARAM_TEST%"=="--" (
  if "%1"=="--help" (
    set SIGN_DRIVER_ARG_SHOW_HELP=1
  ) else if "%1"=="--help-env" (
    set SIGN_DRIVER_ARG_SHOW_HELP=1
    set SIGN_DRIVER_ARG_SHOW_HELP_ENV_ONLY=1
  ) else if "%1"=="--" (
    shift
    goto args_done
  ) else (
    echo Unknown option %1
    setSIGN_DRIVER_ ARG_SHOW_HELP=1
  )
  shift
  goto arg_loop
)

if "%3" == "" (
  set SIGN_DRIVER_ARG_SHOW_HELP=1
)

if %SIGN_DRIVER_ARG_SHOW_HELP% NEQ 0 (
  rem help-env is used to embed the environment help in another script
  if %SIGN_DRIVER_ARG_SHOW_HELP_ENV_ONLY% EQU 0 (
    echo usage:
    echo   %0 [--] driver.cat cab-path cab-name
    echo   %0 --help
    echo.
    echo Signs the specified cat files using the certificates and authorities specified by
    echo PIA_SIGN_SHA256_CERT, PIA_SIGN_SHA1_CERT, PIA_SIGN_CROSSCERT, and PIA_SIGN_TIMESTAMP.
    echo.
    echo   driver.cat - Path to the catalog file to sign
    echo   cab-path - Path to the folder where the cab should be generated
    echo   cab-name - Name of the cabinet archive to build, excluding extension
    echo   -- - Can be used to terminate switches if paths begin with "--"
    echo.
    echo The built cabinet archive contains all files from the directory containing driver.cat,
    echo including driver.cat itself.
    echo.
  )
  echo PIA_SIGN_SHA256_CERT = thumbprint of SHA256 EV certificate ^(needed for installable driver^)
  echo PIA_SIGN_SHA1_CERT = thumbprint of SHA1 EV certificate ^(optional^)
  echo PIA_SIGN_CROSSCERT = CA certificate file for EV certificate ^(default: DigiCert EV^)
  echo PIA_SIGN_TIMESTAMP = timestamp server for signing ^(default: DigiCert^)
  echo.
  exit /B 0
)

set DRIVER_CAT=%1
set DRIVER_CAT_PATH=%~dp1
set CAB_PATH=%2
set CAB_NAME=%3

if [%PIA_SIGN_CROSSCERT%] == [] set "PIA_SIGN_CROSSCERT=DigiCert-High-Assurance-EV-Root-CA.crt"
if [%PIA_SIGN_TIMESTAMP%] == [] set "PIA_SIGN_TIMESTAMP=http://timestamp.digicert.com"

if not [%PIA_SIGN_SHA256_CERT%] == [] (
    if not [%PIA_SIGN_SHA1_CERT%] == [] (
        echo * Double-signing driver with SHA1 and SHA256 certificates...
        
        for /R "%DRIVER_CAT_PATH%" %%G in (*.sys) do (
            call :double_sign_file %%G
            if !errorlevel! neq 0 goto error
        )
        
        call :double_sign_file %DRIVER_CAT%
        if !errorlevel! neq 0 goto error
    ) else (
        echo * Signing driver with SHA256 certificate...
        
        for /R "%DRIVER_CAT_PATH%" %%G in (*.sys) do (
            call :sha256_sign_file %%G
            if !errorlevel! neq 0 goto error
        )
        
        call :sha256_sign_file %DRIVER_CAT%
        if !errorlevel! neq 0 goto error
    )
    
    >"%CAB_PATH%\%CAB_NAME%.ddf" (
        echo .option explicit
        echo .set CabinetFileCountThreshold=0
        echo .set FolderFileCountThreshold=0
        echo .set FolderSizeThreshold=0
        echo .set MaxCabinetSize=0
        echo .set MaxDiskFileCount=0
        echo .set MaxDiskSize=0
        echo .set Cabinet=on
        echo .set Compress=on
        echo .set DiskDirectoryTemplate=%CAB_PATH%
        echo .set DestinationDir=Package
        echo .set CabinetNameTemplate=%CAB_NAME%.cab
        echo .set SourceDir=%DRIVER_CAT_PATH%
    )
    
    for /R "%DRIVER_CAT_PATH%" %%G in (*.*) do (
        echo %%~nxG >> "%CAB_PATH%\%CAB_NAME%.ddf"
    )
    
    makecab /F "%CAB_PATH%\%CAB_NAME%.ddf" >NUL
    if !errorlevel! neq 0 (
        set errorlevel=!errorlevel!
        del /Q /F "%CAB_PATH%\%CAB_NAME%.ddf"
        goto error
    )
    del /Q /F "%CAB_PATH%\%CAB_NAME%.ddf"
    
    echo * Signing CAB for Microsoft submission...
    signtool.exe sign /ac "%PIA_SIGN_CROSSCERT%" /fd sha256 /tr "%PIA_SIGN_TIMESTAMP%" /td sha256 /sha1 "%PIA_SIGN_SHA256_CERT%" "%CAB_PATH%\%CAB_NAME%.cab"
    if !errorlevel! neq 0 goto error
    
    echo.
    echo To get Microsoft certified drivers for Windows 10, submit the
    echo signed CAB files to the Microsoft Dev Center at:
    echo.
    echo https://developer.microsoft.com/en-us/dashboard/hardware
    echo.
) else (
    echo * No certificates specified; drivers will not be installable
)

goto end

:double_sign_file
echo * Signing %~nx1 with SHA1...
signtool.exe sign /ac "%PIA_SIGN_CROSSCERT%" /fd sha1 /tr "%PIA_SIGN_TIMESTAMP%" /td sha1 /sha1 "%PIA_SIGN_SHA1_CERT%" "%~1"
if !errorlevel! neq 0 exit /b
echo * Signing %~nx1 with SHA256...
signtool.exe sign /as /ac "%PIA_SIGN_CROSSCERT%" /fd sha256 /tr "%PIA_SIGN_TIMESTAMP%" /td sha256 /sha1 "%PIA_SIGN_SHA256_CERT%" "%~1"
exit /b

:sha256_sign_file
echo * Signing %~nx1 with SHA256...
signtool.exe sign /ac "%PIA_SIGN_CROSSCERT%" /fd sha256 /tr "%PIA_SIGN_TIMESTAMP%" /td sha256 /sha1 "%PIA_SIGN_SHA256_CERT%" "%~1"
exit /b

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
