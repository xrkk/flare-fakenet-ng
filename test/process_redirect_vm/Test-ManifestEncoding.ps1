$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ManifestTools.ps1')

$path = [IO.Path]::GetTempFileName()
try {
    $expected = 'PLAN/2026.08.03/2026.08.03-01-Windows仅放行指定域名方案.md'
    $json = '{"path":"' + $expected + '"}'
    [IO.File]::WriteAllText(
        $path, $json, (New-Object Text.UTF8Encoding($false, $true)))
    $decoded = Read-StrictUtf8Json $path
    if ([string]$decoded.path -ne $expected) {
        throw ('Strict UTF-8 manifest decoding changed the path: ' +
            [string]$decoded.path)
    }
    Write-Host 'Strict UTF-8 manifest encoding test passed.'
} finally {
    if (Test-Path -LiteralPath $path -PathType Leaf) {
        Remove-Item -LiteralPath $path -Force
    }
}
