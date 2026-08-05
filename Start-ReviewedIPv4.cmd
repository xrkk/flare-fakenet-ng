@echo off
setlocal
title FakeNet-NG - Windows Public IPv4 TCP 443 v13

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-ReviewedIPv4.ps1" -Profile baidu_tcp443
set "FAKENET_EXIT=%ERRORLEVEL%"

echo.
echo FakeNet-NG launcher exit code: %FAKENET_EXIT%
pause
exit /b %FAKENET_EXIT%
