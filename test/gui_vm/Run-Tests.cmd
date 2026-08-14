@echo off
setlocal
title FakeNet-NG - GUI Configuration Tool VM Acceptance

rem One click: self-elevate (single UAC consent), then fully unattended.
cd /d "%~dp0"

net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Requesting administrator privileges ...
    powershell.exe -NoLogo -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

set "PYTHON_CMD=python"
where python >nul 2>&1
if %ERRORLEVEL% NEQ 0 set "PYTHON_CMD=py -3"

%PYTHON_CMD% "%~dp0run_gui_vm_acceptance.py"
set "TEST_EXIT=%ERRORLEVEL%"

echo.
echo GUI VM acceptance exit code: %TEST_EXIT%  (0=PASS 1=FAIL 2=REFUSED)
echo Plain logs are under: %~dp0Logs
pause
exit /b %TEST_EXIT%
