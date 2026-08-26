@echo off
setlocal
title FakeNet-NG v33 Diagnostic Evidence
cd /d "%~dp0"

net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Requesting administrator privileges for the isolated VM diagnostic ...
    powershell.exe -NoLogo -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

set "PYTHON_CMD=python"
where python >nul 2>&1
if %ERRORLEVEL% NEQ 0 set "PYTHON_CMD=py -3"

%PYTHON_CMD% "%~dp0run_vm_diagnostics.py"
set "DIAG_EXIT=%ERRORLEVEL%"

echo.
echo Diagnostic exit code: %DIAG_EXIT%  (0=EVIDENCE CAPTURED 1=TOOL FAILURE 2=REFUSED)
echo Follow the final EVIDENCE path printed above; no other Windows command is required.
pause
exit /b %DIAG_EXIT%
