function Invoke-NativeCaptured {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Command,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $previousPreference = $ErrorActionPreference
    $records = @()
    $nativeExitCode = $null
    try {
        # Windows PowerShell 5.1 wraps native stderr as ErrorRecord objects.
        # Capture those records without weakening the caller's global Stop
        # policy, then make the native integer exit code the sole verdict.
        $ErrorActionPreference = 'Continue'
        $records = @(& $Command 2>&1)
        $nativeExitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    $records | Out-File -LiteralPath $Path -Encoding UTF8
    if ($null -eq $nativeExitCode) {
        throw ('Native command did not publish an exit code; inspect ' + $Path)
    }
    return [int]$nativeExitCode
}
