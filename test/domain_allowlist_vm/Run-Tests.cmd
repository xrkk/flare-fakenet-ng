@echo off
setlocal
echo Enter the reviewed IPv4 DNS server already configured in this VM.
echo The runner will refuse public-DNS fallback or a value absent from the pre-test configuration.
set /p "REVIEWED_DNS=Reviewed DNS IPv4: "
if not defined REVIEWED_DNS (
  echo A reviewed DNS IPv4 is required.
  pause
  exit /b 2
)
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Run-DomainAllowListTests.ps1" -ExternalDnsServer "%REVIEWED_DNS%"
set "RC=%ERRORLEVEL%"
echo.
echo Test runner exit code: %RC%
pause
exit /b %RC%
