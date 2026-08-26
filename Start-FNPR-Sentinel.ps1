[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$bindIPv4 = '192.168.204.1'
$listenPort = 443
$scriptPath = Join-Path $PSScriptRoot 'fnpr_sentinel.py'
$logRoot = Join-Path $PSScriptRoot 'dist\Logs'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$logDir = Join-Path $logRoot ("fnpr-sentinel-$stamp")
$logPath = Join-Path $logDir 'sentinel.log'

function Find-Python3 {
    $python = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($python) {
        $version = & $python.Source -c `
            "import sys; print(sys.version_info.major)" 2>$null
        if ($LASTEXITCODE -eq 0 -and [string]$version -eq '3') {
            return [PSCustomObject]@{
                Executable = $python.Source
                Prefix = @()
            }
        }
    }
    $launcher = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($launcher) {
        $version = & $launcher.Source -3 -c `
            "import sys; print(sys.version_info.major)" 2>$null
        if ($LASTEXITCODE -eq 0 -and [string]$version -eq '3') {
            return [PSCustomObject]@{
                Executable = $launcher.Source
                Prefix = @('-3')
            }
        }
    }
    throw 'Python 3 was not found. No dependency is downloaded automatically.'
}

try {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
        throw ('Listener script is missing: ' + $scriptPath)
    }
    $assigned = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object IPAddress -eq $bindIPv4)
    if ($assigned.Count -ne 1) {
        throw ("Required host-only IPv4 $bindIPv4 is not uniquely assigned on this host.")
    }
    $existing = @(Get-NetTCPConnection -State Listen -LocalPort $listenPort `
        -ErrorAction SilentlyContinue |
        Where-Object LocalAddress -in @($bindIPv4, '0.0.0.0'))
    if ($existing) {
        throw ("TCP/$listenPort is already listening on $bindIPv4 or all interfaces.")
    }
    $existingUdp = @(Get-NetUDPEndpoint -LocalPort $listenPort `
        -ErrorAction SilentlyContinue |
        Where-Object LocalAddress -in @($bindIPv4, '0.0.0.0'))
    if ($existingUdp) {
        throw ("UDP/$listenPort is already bound on $bindIPv4 or all interfaces.")
    }
    $runtime = Find-Python3
    Write-Host "Starting FNPR/1 TCP+UDP sentinel on $bindIPv4`:$listenPort"
    Write-Host 'This listener accepts only bounded FNPR/1 nonce probes.'
    Write-Host 'Press Ctrl+C to stop.'
    Write-Host ('Plain log: ' + $logPath)
    Write-Host ''

    $arguments = @($runtime.Prefix) + @(
        '-u', $scriptPath, '--log', $logPath)
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & $runtime.Executable @arguments 2>&1 |
            Tee-Object -FilePath (Join-Path $logDir 'console.log') | Out-Host
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    if ($exitCode -ne 0) {
        throw ("FNPR/1 sentinel exited with code $exitCode. See $logDir")
    }
    exit 0
} catch {
    Write-Host ('START FAILED: ' + $_.Exception.Message) -ForegroundColor Red
    if (Test-Path -LiteralPath $logDir) {
        $_ | Format-List * -Force | Out-File (
            Join-Path $logDir 'start-error.log') -Encoding utf8
        Write-Host ('Plain logs: ' + $logDir)
    }
    exit 1
}
