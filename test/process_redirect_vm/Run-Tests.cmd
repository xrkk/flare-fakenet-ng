@echo off
setlocal
title FakeNet-NG - Windows Process Redirect VM Acceptance

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Run-ProcessRedirectTests.ps1"
set "TEST_EXIT=%ERRORLEVEL%"

echo.
echo Process redirect VM test exit code: %TEST_EXIT%
echo Plain logs are under: %~dp0..\..\Logs
pause
exit /b %TEST_EXIT%
