# Manual-test evidence export (plan v1.27 section 12.30).
#
# Copies everything the GUI and the GUI-launched core write next to the
# package root (Logs\*.log, pcaps, HTML reports) into the one-stop acceptance
# evidence location under test\gui_vm\Logs\, so a manual session that happens
# after Run-Tests.cmd still exports from a single folder. No elevation needed.

[CmdletBinding()]
param(
    [string]$SinceUtc = '',
    [ValidatePattern('^[A-Za-z0-9-]{0,32}$')]
    [string]$SessionLabel = ''
)

$ErrorActionPreference = 'Stop'

$sinceBoundaryUtc = [DateTime]::MinValue
if ($SinceUtc) {
    try {
        $sinceBoundaryUtc = [DateTimeOffset]::Parse(
            $SinceUtc,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal).UtcDateTime
    } catch {
        throw ('Invalid -SinceUtc value: ' + $SinceUtc)
    }
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$packageRoot = (Resolve-Path (Join-Path $scriptDir '..\..')).Path
$logRoot = Join-Path $scriptDir 'Logs'
if (-not (Test-Path -LiteralPath $logRoot)) {
    New-Item -ItemType Directory -Path $logRoot | Out-Null
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$targetPrefix = if ($SessionLabel) {
    $SessionLabel + '-export-'
} else {
    'manual-export-'
}
$target = Join-Path $logRoot ($targetPrefix + $stamp)
New-Item -ItemType Directory -Path $target | Out-Null

$copied = 0
$patterns = @('Logs\*.log', 'Logs\*.pcap', 'Logs\diagnostic-*.tsv',
              'Logs\diagnostic-*.txt', 'Logs\diagnostic-*.json',
              'packets_*.pcap', 'packets_*.pcap.md5', 'report_*.html')
foreach ($pattern in $patterns) {
    $items = Get-ChildItem -Path (Join-Path $packageRoot $pattern) -File `
        -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTimeUtc -ge $sinceBoundaryUtc }
    foreach ($item in $items) {
        Copy-Item -LiteralPath $item.FullName `
            -Destination (Join-Path $target $item.Name) -Force
        $copied++
    }
}

# Copy the exact INI paths named by GUI/core launch evidence.  The previous
# exporter copied logs but omitted the bound config, which made a failed
# takeover session impossible to distinguish from a session where takeover
# was never enabled.
$configPaths = @{}
$sourceLogs = Get-ChildItem -Path (Join-Path $packageRoot 'Logs\*.log') -File `
    -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTimeUtc -ge $sinceBoundaryUtc }
foreach ($log in $sourceLogs) {
    $matches = Select-String -LiteralPath $log.FullName -Pattern @(
        'Loaded configuration file:\s*(.+)$',
        'FakeNet launch requested:\s*config=(.+)$')
    foreach ($match in $matches) {
        $candidate = $match.Matches[0].Groups[1].Value.Trim()
        if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            $configPaths[$candidate.ToLowerInvariant()] = $candidate
        }
    }
}

$configSources = @()
$configIndex = 0
foreach ($source in ($configPaths.Values | Sort-Object)) {
    $configIndex++
    $destinationName = 'config-{0:D2}-{1}' -f `
        $configIndex, (Split-Path -Leaf $source)
    Copy-Item -LiteralPath $source `
        -Destination (Join-Path $target $destinationName) -Force
    $configSources += ("{0}`t{1}" -f $destinationName, $source)
    $copied++
}
$utf8NoBom = New-Object System.Text.UTF8Encoding $false
if ($configSources.Count -gt 0) {
    [System.IO.File]::WriteAllLines(
        (Join-Path $target 'config-sources.tsv'),
        [string[]]$configSources,
        $utf8NoBom)
}

$latestCoreLog = Get-ChildItem `
    -Path (Join-Path $packageRoot 'Logs\fakenet-*.log') -File `
    -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notlike 'fakenet-GUI-*' } |
    Where-Object { $_.LastWriteTimeUtc -ge $sinceBoundaryUtc } |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
$stopMarkers = @()
$unclosedStop = $null
$stopDiagnosis = @()
if ($latestCoreLog) {
    $stopMarkers = @(Select-String -LiteralPath $latestCoreLog.FullName `
        -Pattern 'STOP_(PHASE|PROVIDER)_(BEGIN|END).*?(phase|name)=([^\s]+)')
    $activeStops = @{}
    $markerIndex = 0
    foreach ($marker in $stopMarkers) {
        $markerIndex++
        $kind = $marker.Matches[0].Groups[1].Value
        $action = $marker.Matches[0].Groups[2].Value
        $name = $marker.Matches[0].Groups[4].Value
        $key = '{0}:{1}' -f $kind, $name
        if ($action -eq 'BEGIN') {
            $activeStops[$key] = [PSCustomObject]@{
                Index = $markerIndex
                Line = $marker.Line.Trim()
            }
        } else {
            $activeStops.Remove($key)
        }
    }
    $unclosedStop = $activeStops.Values |
        Sort-Object Index -Descending |
        Select-Object -First 1
}

if (-not $latestCoreLog) {
    $stopDiagnosis += 'status=missing-core-log'
} elseif ($stopMarkers.Count -eq 0) {
    $stopDiagnosis += ('source_log={0}' -f $latestCoreLog.FullName)
    $stopDiagnosis += 'status=missing-diagnostic-markers'
} elseif ($unclosedStop) {
    $stopDiagnosis += ('source_log={0}' -f $latestCoreLog.FullName)
    $stopDiagnosis += 'status=unclosed-stop-boundary'
    $stopDiagnosis += ('boundary={0}' -f $unclosedStop.Line)
} else {
    $stopDiagnosis += ('source_log={0}' -f $latestCoreLog.FullName)
    $stopDiagnosis += 'status=no-unclosed-stop-boundary'
}
[System.IO.File]::WriteAllLines(
    (Join-Path $target 'stop-diagnosis.txt'),
    [string[]]$stopDiagnosis,
    $utf8NoBom)

# Bind every exported artifact to this evidence directory.  The hash file is
# intentionally computed last and does not include itself.
$hashLines = @()
foreach ($item in Get-ChildItem -LiteralPath $target -File | Sort-Object Name) {
    $hash = (Get-FileHash -LiteralPath $item.FullName `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $hashLines += ("{0}`t{1}" -f $hash, $item.Name)
}
[System.IO.File]::WriteAllLines(
    (Join-Path $target 'evidence-sha256.tsv'),
    [string[]]$hashLines,
    $utf8NoBom)

Write-Host ('Exported {0} file(s) to:' -f $copied)
Write-Host $target
Write-Host ('EVIDENCE_PATH=' + $target)
if ($copied -eq 0) {
    Write-Host 'No package-root logs/pcaps/reports found - nothing to export.'
}
if ($configSources.Count -gt 0) {
    Write-Host ('Included {0} referenced INI file(s) and SHA-256 evidence.' -f `
        $configSources.Count)
} else {
    Write-Host 'CONFIG EVIDENCE MISSING: no referenced INI file was found.'
    Write-Host 'Do not diagnose the GUI takeover chain from this export.'
}
if ($unclosedStop) {
    Write-Host ('STOP DIAGNOSIS: deepest unclosed phase/provider: {0}' -f `
        $unclosedStop.Line)
} elseif ($stopMarkers.Count -gt 0) {
    Write-Host 'STOP DIAGNOSIS: no unclosed stop phase/provider was found.'
} else {
    Write-Host 'STOP DIAGNOSTIC MARKERS MISSING: use a diagnostic build containing STOP_PHASE/STOP_PROVIDER events.'
}
