@echo off
setlocal
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Run-EgressControlTests.ps1"
set "RC=%ERRORLEVEL%"
echo.
echo Test runner exit code: %RC%
pause
exit /b %RC%
