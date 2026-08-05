@echo off
setlocal
title FakeNet-NG - Public Reviewed IPv4 v17 VM Acceptance

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Run-ReviewedIPv4Tests.ps1"
set "TEST_EXIT=%ERRORLEVEL%"

echo.
echo Public IPv4 v17 VM test exit code: %TEST_EXIT%
echo Logs are plain files under: %~dp0Logs
pause
exit /b %TEST_EXIT%
