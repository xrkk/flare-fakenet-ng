@echo off
setlocal
chcp 65001 >nul

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-FNPR-Sentinel.ps1"
set "FNPR_EXIT=%ERRORLEVEL%"

echo.
echo FNPR/1 sentinel exit code: %FNPR_EXIT%
pause
exit /b %FNPR_EXIT%
