@echo off
setlocal
title FakeNet-NG - Windows Private IPv4 Egress v12

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-ReviewedIPv4.ps1" -Profile exact_ports
set "FAKENET_EXIT=%ERRORLEVEL%"

echo.
echo FakeNet-NG launcher exit code: %FAKENET_EXIT%
pause
exit /b %FAKENET_EXIT%
