$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ConsoleStopSignal.ps1')

$registered = $false
try {
    Initialize-ConsoleStopSignal
    $registered = $true
    if (Test-ConsoleStopRequested) {
        throw 'A new handler reported a stale stop request.'
    }
    Request-ConsoleStopForTest
    if (-not (Test-ConsoleStopRequested)) {
        throw 'The simulated stop request was not observed.'
    }
    if (Test-ConsoleStopRequested) {
        throw 'The stop request was not consumed exactly once.'
    }
} finally {
    if ($registered) {
        Remove-ConsoleStopSignal
    }
}

Remove-ConsoleStopSignal
Write-Host 'Console stop signal tests passed.'
