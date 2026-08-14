$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ProcessExitTools.ps1')

$root = Join-Path ([IO.Path]::GetTempPath()) (
    'process-redirect-exit-' + [Guid]::NewGuid().ToString('N'))
try {
    New-Item -ItemType Directory -Path $root | Out-Null
    $stdout = Join-Path $root 'stdout.log'
    $stderr = Join-Path $root 'stderr.log'
    $process = Start-Process -FilePath $env:ComSpec -PassThru `
        -WindowStyle Hidden -RedirectStandardOutput $stdout `
        -RedirectStandardError $stderr `
        -ArgumentList '/d /s /c "exit /b 7"'
    Register-ProcessExitCodeTracking $process
    if (-not $process.WaitForExit(5000)) {
        throw 'Exit-code tracking regression child timed out.'
    }
    $exitCode = Read-TrackedProcessExitCode $process
    if ($exitCode -ne 7 -or $exitCode.GetType().FullName -ne 'System.Int32') {
        throw ('Tracked child exit code was not Int32 7: ' + $exitCode)
    }

    $rejected = $false
    try {
        [void](Read-TrackedProcessExitCode (
            [Diagnostics.Process]::GetCurrentProcess()))
    } catch { $rejected = $true }
    if (-not $rejected) {
        throw 'An active process was accepted as exited.'
    }
    Write-Host 'Process exit-code tracking test passed.'
} finally {
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force
    }
}
