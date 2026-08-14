function Register-ProcessExitCodeTracking {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][Diagnostics.Process]$Process)

    try {
        $handle = $Process.Handle
    } catch {
        throw ('Unable to acquire child process handle for exit-code ' +
            'tracking: ' + $_.Exception.Message)
    }
    if ($handle -eq [IntPtr]::Zero) {
        throw 'Child process returned a zero handle for exit-code tracking.'
    }
}

function Read-TrackedProcessExitCode {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][Diagnostics.Process]$Process)

    if (-not $Process.HasExited) {
        throw 'Child process exit code was requested before process exit.'
    }
    $exitCode = $Process.ExitCode
    if ($null -eq $exitCode) {
        throw 'Child process exit code is unavailable after process exit.'
    }
    return [int]$exitCode
}
