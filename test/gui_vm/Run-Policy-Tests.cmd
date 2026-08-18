@echo off
setlocal
title FakeNet-NG - Policy Feature Tests (multi-domain + wildcard)

rem One click: self-elevate (single UAC consent), then fully unattended.
rem Exercises the v1.28 policy features with the real core: multi-domain
rem allowlist, *.wildcard matching, apex exclusion, default deny, and
rem multi-domain private-network takeover. VM only - refuses elsewhere.
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

%PYTHON_CMD% "%~dp0run_policy_feature_tests.py"
set "TEST_EXIT=%ERRORLEVEL%"

echo.
echo Policy feature test exit code: %TEST_EXIT%  (0=PASS 1=FAIL 2=REFUSED)
echo Plain logs are under: %~dp0Logs\policy-*
pause
exit /b %TEST_EXIT%
