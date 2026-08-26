@echo off
setlocal EnableExtensions EnableDelayedExpansion
title FakeNet-NG - GUI Configuration Tool VM Acceptance

rem One formal entry: self-elevate, preflight Ubuntu once, then run A/P.
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

for /f "usebackq delims=" %%I in (`powershell.exe -NoLogo -NoProfile -Command "[DateTimeOffset]::UtcNow.ToString('o')"`) do set "SESSION_START_UTC=%%I"

%PYTHON_CMD% "%~dp0run_gui_vm_acceptance.py"
set "A_EXIT=%ERRORLEVEL%"
set "P_EXIT=1"
set "S_EXIT=1"
if %A_EXIT% EQU 0 (
    %PYTHON_CMD% "%~dp0run_policy_feature_tests.py"
    set "P_EXIT=!ERRORLEVEL!"
) else (
    echo [STOP] A group did not pass; P group was not started.
)
if %A_EXIT% EQU 0 if %P_EXIT% EQU 0 (
    %PYTHON_CMD% "%~dp0run_formal_stop_acceptance.py"
    set "S_EXIT=!ERRORLEVEL!"
) else (
    echo [STOP] A/P groups did not both pass; three-round GUI stop was not started.
)

set "TEST_EXIT=0"
if %A_EXIT% EQU 2 set "TEST_EXIT=2"
if %A_EXIT% EQU 1 set "TEST_EXIT=1"
if %P_EXIT% NEQ 0 if %A_EXIT% EQU 0 set "TEST_EXIT=%P_EXIT%"
if %S_EXIT% NEQ 0 if %A_EXIT% EQU 0 if %P_EXIT% EQU 0 set "TEST_EXIT=%S_EXIT%"

powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0Export-Logs.ps1" -SinceUtc "%SESSION_START_UTC%" -SessionLabel "formal-v34"
if %ERRORLEVEL% NEQ 0 set "TEST_EXIT=1"

echo.
echo Formal v34 A/P acceptance exit code: %TEST_EXIT%  (0=PASS 1=FAIL 2=REFUSED)
echo Evidence path is printed above and plain logs are under: %~dp0Logs
pause
exit /b %TEST_EXIT%
