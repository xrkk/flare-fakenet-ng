@echo off
setlocal
title FakeNet-NG - Windows Domain Allow List
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-EgressControl.ps1"
set "RC=%ERRORLEVEL%"
echo.
echo FakeNet-NG launcher exit code: %RC%
pause
exit /b %RC%
