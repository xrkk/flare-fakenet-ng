@echo off
rem Manual-test evidence export (plan v1.27 section 12.30).
rem Copies package-root Logs\, pcaps and HTML reports into
rem test\gui_vm\Logs\manual-export-<timestamp>\ so manual sessions after
rem Run-Tests.cmd still export from one place. No elevation required.
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Export-Logs.ps1"
pause
