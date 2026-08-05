@echo off
setlocal
title FakeNet-NG - Windows Domain Takeover and Reviewed IPv4 Egress v11

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-DomainTakeover.ps1"
set "FAKENET_EXIT=%ERRORLEVEL%"

echo.
echo FakeNet-NG launcher exit code: %FAKENET_EXIT%
pause
exit /b %FAKENET_EXIT%
