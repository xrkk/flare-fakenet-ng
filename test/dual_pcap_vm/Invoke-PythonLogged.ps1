function Invoke-PythonLogged {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$PythonExe,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$LogPath,
        [AllowNull()][string]$InputText = $null
    )

    # Windows PowerShell 5.1 turns native stderr redirected into the success
    # stream into non-terminating ErrorRecord objects. Under the runner's
    # ErrorActionPreference=Stop, a harmless Python warning would otherwise
    # abort before LASTEXITCODE can be inspected.
    $previousPreference = $ErrorActionPreference
    $nativeExitCode = 1
    try {
        $ErrorActionPreference = 'Continue'
        if ($PSBoundParameters.ContainsKey('InputText')) {
            $InputText | & $PythonExe @Arguments 2>&1 |
                Tee-Object -FilePath $LogPath | Out-Host
        } else {
            & $PythonExe @Arguments 2>&1 |
                Tee-Object -FilePath $LogPath | Out-Host
        }
        $nativeExitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    return [int]$nativeExitCode
}
