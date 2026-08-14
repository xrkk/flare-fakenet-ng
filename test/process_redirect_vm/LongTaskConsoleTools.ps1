function Write-LongTaskNotice {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$ExpectedDuration,
        [Parameter(Mandatory = $true)][string]$HardTimeout,
        [Parameter(Mandatory = $true)][string]$Detail,
        [switch]$ProgressEveryMinute
    )
    Write-Host ''
    Write-Host ('LONG TASK START: ' + $Name)
    Write-Host ('  Expected duration: ' + $ExpectedDuration)
    Write-Host ('  Hard timeout: ' + $HardTimeout)
    Write-Host ('  ' + $Detail)
    if ($ProgressEveryMinute) {
        Write-Host '  This window is still active; progress prints every minute.'
    } else {
        Write-Host '  This window is still active; wait for the final PASS/FAIL line.'
    }
}

function Get-CompletedConnectionCount {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return 0 }
    $stream = [IO.File]::Open(
        $Path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    try {
        $reader = [IO.StreamReader]::new(
            $stream, [Text.UTF8Encoding]::new($false, $true), $true)
        try {
            $count = 0
            while (($line = $reader.ReadLine()) -ne $null) {
                if ($line.Contains('"event":"connection"')) { $count++ }
            }
            return $count
        } finally { $reader.Dispose() }
    } finally { $stream.Dispose() }
}

function Write-LongTaskProgress {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][ValidateRange(0,[int]::MaxValue)]
        [int]$Completed,
        [Parameter(Mandatory = $true)][ValidateRange(1,[int]::MaxValue)]
        [int]$Total,
        [Parameter(Mandatory = $true)][ValidateRange(0,[int]::MaxValue)]
        [int]$ElapsedSeconds,
        [Parameter(Mandatory = $true)][ValidateRange(1,[int]::MaxValue)]
        [int]$HardTimeoutSeconds
    )
    $boundedCompleted = [Math]::Min($Completed, $Total)
    $percent = [string]::Format(
        [Globalization.CultureInfo]::InvariantCulture, '{0:F1}',
        (100.0 * $boundedCompleted / $Total))
    $elapsedMinutes = [string]::Format(
        [Globalization.CultureInfo]::InvariantCulture, '{0:F1}',
        ($ElapsedSeconds / 60.0))
    $timeoutMinutes = [string]::Format(
        [Globalization.CultureInfo]::InvariantCulture, '{0:F1}',
        ($HardTimeoutSeconds / 60.0))
    $eta = if ($boundedCompleted -gt 0 -and $ElapsedSeconds -gt 0) {
        [Math]::Max(0, (($ElapsedSeconds * $Total / $boundedCompleted) -
            $ElapsedSeconds) / 60.0)
    } else { 0 }
    $etaMinutes = [string]::Format(
        [Globalization.CultureInfo]::InvariantCulture, '{0:F1}', $eta)
    Write-Host (('LONG TASK PROGRESS: {0} {1}/{2} ({3}%) ' +
        'elapsed={4} min eta={5} min hard-timeout={6} min') -f
        $Name,$boundedCompleted,$Total,$percent,$elapsedMinutes,$etaMinutes,
        $timeoutMinutes)
}
