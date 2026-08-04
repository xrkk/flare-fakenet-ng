@echo off
setlocal
title FakeNet-NG - Windows Domain Takeover VM Acceptance

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Run-DomainTakeoverTests.ps1"
set "TEST_EXIT=%ERRORLEVEL%"

echo.
echo Domain takeover VM test exit code: %TEST_EXIT%
echo Logs are plain files under: %~dp0Logs
pause
exit /b %TEST_EXIT%
