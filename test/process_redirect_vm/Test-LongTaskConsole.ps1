$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'LongTaskConsoleTools.ps1')

$notice = @(& {
    Write-LongTaskNotice `
        -Name 'OwnerGate10000' `
        -ExpectedDuration '16-22 minutes on the reviewed 4 GB VM' `
        -HardTimeout '25 minutes' `
        -ProgressEveryMinute `
        -Detail ('10,000 sequential connections. Local ephemeral ports may ' +
            'increase, wrap, or be reused; they are not a progress counter.')
} 6>&1 | ForEach-Object { [string]$_ }) -join "`n"

foreach ($required in @(
        'LONG TASK START: OwnerGate10000',
        'Expected duration: 16-22 minutes on the reviewed 4 GB VM',
        'Hard timeout: 25 minutes',
        'progress prints every minute',
        'Local ephemeral ports may increase, wrap, or be reused',
        'not a progress counter')) {
    if (-not $notice.Contains($required)) {
        throw ('Long-task notice is missing: ' + $required)
    }
}

$progress = @(& {
    Write-LongTaskProgress -Name 'OwnerGate10000' -Completed 2500 `
        -Total 10000 -ElapsedSeconds 300 -HardTimeoutSeconds 1500
} 6>&1 | ForEach-Object { [string]$_ }) -join "`n"
foreach ($required in @(
        'LONG TASK PROGRESS: OwnerGate10000',
        '2500/10000',
        '25.0%',
        'elapsed=5.0 min',
        'eta=15.0 min',
        'hard-timeout=25.0 min')) {
    if (-not $progress.Contains($required)) {
        throw ('Long-task progress is missing: ' + $required)
    }
}

$fixture = Join-Path $PSScriptRoot (
    '.long-task-progress-' + [Guid]::NewGuid().ToString('N') + '.jsonl')
try {
    [IO.File]::WriteAllText($fixture, (@(
        '{"event":"identity"}',
        '{"event":"connection","index":0}',
        '{"event":"connection","index":1}',
        '{"event":"summary"}') -join "`n"), [Text.UTF8Encoding]::new($false))
    if ((Get-CompletedConnectionCount $fixture) -ne 2) {
        throw 'Completed connection counter did not read the public JSONL evidence.'
    }
} finally {
    Remove-Item -LiteralPath $fixture -Force -ErrorAction SilentlyContinue
}

Write-Host 'Long-task console visibility test passed.'
