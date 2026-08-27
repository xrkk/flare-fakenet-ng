@echo off
setlocal EnableExtensions
title FakeNet-NG v35 sample payload acceptance
cd /d "%~dp0\..\.."

net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Requesting administrator privileges ...
    powershell.exe -NoLogo -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

where python >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo REFUSED: Python 3 is required by the evidence runner.
    pause
    exit /b 2
)

python "%~dp0run_sample_payload_acceptance.py" --package-root "%CD%"
set "RESULT=%ERRORLEVEL%"
echo.
echo Sample payload acceptance exit code: %RESULT%  (0=PASS 1=FAIL 2=REFUSED)
pause
exit /b %RESULT%
