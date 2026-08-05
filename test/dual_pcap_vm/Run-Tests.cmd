@echo off
setlocal
title FakeNet-NG synchronized dual PCAP v1 VM acceptance
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Run-DualPcapTests.ps1"
exit /b %ERRORLEVEL%
