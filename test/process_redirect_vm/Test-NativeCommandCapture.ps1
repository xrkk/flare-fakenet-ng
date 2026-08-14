$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'NativeCommandTools.ps1')

$root = Join-Path ([IO.Path]::GetTempPath()) (
    'process-redirect-native-' + [Guid]::NewGuid().ToString('N'))
try {
    New-Item -ItemType Directory -Path $root | Out-Null
    $log = Join-Path $root 'native.log'
    $exitCode = Invoke-NativeCaptured {
        & $env:ComSpec /d /s /c `
            'echo packet monitor is not running 1>&2 & exit /b 7'
    } $log
    if ($exitCode -ne 7) {
        throw ('Native stderr exit code was not preserved: ' + $exitCode)
    }
    $text = Get-Content -Raw -LiteralPath $log
    if ($text -notmatch 'packet monitor is not running') {
        throw 'Native stderr text was not captured.'
    }
    if ($ErrorActionPreference -ne 'Stop') {
        throw 'Native capture did not restore ErrorActionPreference.'
    }
    Write-Host 'Native command stderr/exit capture test passed.'
} finally {
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force
    }
}
