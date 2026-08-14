$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'RouteTargetTools.ps1')

$expected = @('110.242.69.21', '192.168.204.1')
$json = $expected | ConvertTo-Json -Compress
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
$actual = @(ConvertFrom-RouteTargetsBase64 $encoded)

if ($actual.Count -ne 2 -or
        [string]$actual[0] -ne $expected[0] -or
        [string]$actual[1] -ne $expected[1] -or
        @($actual | Select-Object -Unique).Count -ne 2) {
    throw ('Route target decoding did not return two distinct addresses: ' +
        ($actual -join ','))
}
Write-Host 'Route target encoding test passed.'
