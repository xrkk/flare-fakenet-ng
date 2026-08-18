# Manual-test evidence export (plan v1.27 section 12.30).
#
# Copies everything the GUI and the GUI-launched core write next to the
# package root (Logs\*.log, pcaps, HTML reports) into the one-stop acceptance
# evidence location under test\gui_vm\Logs\, so a manual session that happens
# after Run-Tests.cmd still exports from a single folder. No elevation needed.

$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$packageRoot = (Resolve-Path (Join-Path $scriptDir '..\..')).Path
$logRoot = Join-Path $scriptDir 'Logs'
if (-not (Test-Path -LiteralPath $logRoot)) {
    New-Item -ItemType Directory -Path $logRoot | Out-Null
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$target = Join-Path $logRoot ('manual-export-' + $stamp)
New-Item -ItemType Directory -Path $target | Out-Null

$copied = 0
$patterns = @('Logs\*.log', 'Logs\*.pcap', 'packets_*.pcap',
              'packets_*.pcap.md5', 'report_*.html')
foreach ($pattern in $patterns) {
    $items = Get-ChildItem -Path (Join-Path $packageRoot $pattern) -File `
        -ErrorAction SilentlyContinue
    foreach ($item in $items) {
        Copy-Item -LiteralPath $item.FullName `
            -Destination (Join-Path $target $item.Name) -Force
        $copied++
    }
}

Write-Host ('Exported {0} file(s) to:' -f $copied)
Write-Host $target
if ($copied -eq 0) {
    Write-Host 'No package-root logs/pcaps/reports found - nothing to export.'
}
