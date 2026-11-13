@echo off
setlocal
set "SCRIPT_DIR=%~dp0"
set "NOPAUSE=0"
set "PSARGS="
:parse_args
if "%~1"=="" goto run_ps
if /i "%~1"=="--no-pause" (
    set "NOPAUSE=1"
    shift
    goto parse_args
)
set "PSARGS=%PSARGS% %1"
shift
goto parse_args

:run_ps
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%uninstall.ps1" %PSARGS%
set "RC=%ERRORLEVEL%"
if "%NOPAUSE%"=="1" exit /b %RC%
pause
exit /b %RC%
