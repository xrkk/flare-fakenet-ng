$ErrorActionPreference = 'Stop'

$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$runnerPath = Join-Path $PSScriptRoot 'Run-ProcessRedirectTests.ps1'
$templatePath = Join-Path $root 'fakenet\configs\process_redirect_windows.ini'
$runner = Get-Content -Raw -LiteralPath $runnerPath
$template = Get-Content -Raw -LiteralPath $templatePath
$markers = @(
    '__RUNTIME_EXTERNAL_DNS__',
    '__RUNTIME_PROCESS_IMAGE_PATH__',
    '__RUNTIME_PROCESS_IMAGE_SHA256__',
    '__RUNTIME_PUBLIC_IPV4_A__',
    '__RUNTIME_PRIVATE_IPV4_B__'
)
foreach ($marker in $markers) {
    if (-not $runner.Contains("Replace('$marker'")) {
        throw ('Runner does not replace runtime-only marker: ' + $marker)
    }
    if (-not $template.Contains($marker)) {
        throw ('Config template does not contain runtime-only marker: ' + $marker)
    }
}

$runtime = $template.Replace('__RUNTIME_EXTERNAL_DNS__','192.168.204.2').
    Replace('__RUNTIME_PROCESS_IMAGE_PATH__','C:\reviewed\target.exe').
    Replace('__RUNTIME_PROCESS_IMAGE_SHA256__',('a' * 64)).
    Replace('__RUNTIME_PUBLIC_IPV4_A__','110.242.69.21').
    Replace('__RUNTIME_PRIVATE_IPV4_B__','192.168.204.1')
$remaining = @([regex]::Matches(
    $runtime, '__RUNTIME_[A-Z0-9_]+__') | ForEach-Object Value)
if ($remaining.Count -ne 0) {
    throw ('Runtime config still contains markers: ' +
        ($remaining -join ','))
}
Write-Host 'Runtime config marker separation test passed.'
