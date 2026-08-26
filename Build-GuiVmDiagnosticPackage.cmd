@echo off
setlocal
title Build FakeNet-NG v33 Diagnostic Package
cd /d "%~dp0"

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Build-GuiVmPackage.ps1" -SourceCommit HEAD -PackageMode Diagnostic -PackageVersion v33-diagnostic-02
set "BUILD_EXIT=%ERRORLEVEL%"

echo.
if %BUILD_EXIT% EQU 0 (
    echo Diagnostic package build completed. See the Package path above.
) else (
    echo Diagnostic package build failed with exit code %BUILD_EXIT%.
    echo The source must be committed and Windows Python/PyInstaller dependencies must be installed.
)
pause
exit /b %BUILD_EXIT%
