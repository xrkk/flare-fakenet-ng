$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'WinDivertVersionTools.ps1')

if (-not (Test-WinDivertVersionMatch `
        -Expected '1.3.0' -Actual '1.3 built by: WinDDK')) {
    throw 'The reviewed WinDivert 1.3 PE resource form was rejected.'
}
if (-not (Test-WinDivertVersionMatch -Expected '1.3' -Actual '1.3.0')) {
    throw 'A trailing numeric zero was not normalized.'
}
foreach ($actual in @(
        '1.3.1 built by: WinDDK',
        '1.30 built by: WinDDK',
        '1.3 built by: unknown',
        '1.3.0 arbitrary text',
        '1.3.0.0.0',
        '')) {
    if (Test-WinDivertVersionMatch -Expected '1.3.0' -Actual $actual) {
        throw ('An invalid or different WinDivert version was accepted: ' +
            $actual)
    }
}

Write-Host 'WinDivert PE version normalization test passed.'
