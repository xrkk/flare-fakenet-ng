@echo off
setlocal
title FakeNet-NG - Domain Takeover and Reviewed IPv4 v11 VM Acceptance

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Run-DomainTakeoverTests.ps1"
set "TEST_EXIT=%ERRORLEVEL%"

echo.
echo Combined v11 VM test exit code: %TEST_EXIT%
echo Logs are plain files under: %~dp0Logs
pause
exit /b %TEST_EXIT%
