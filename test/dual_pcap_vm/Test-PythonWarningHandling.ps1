[CmdletBinding()]
param([string]$PythonPath = 'python.exe')

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Invoke-PythonLogged.ps1')
$logPath = Join-Path ([IO.Path]::GetTempPath()) (
    'dual-pcap-warning-' + [Guid]::NewGuid().ToString('N') + '.log')
try {
    $source = "import sys; sys.stderr.write('synthetic warning\n')"
    $exitCode = Invoke-PythonLogged -PythonExe $PythonPath `
        -Arguments @('-c', $source) -LogPath $logPath
    if ($exitCode -ne 0) { throw "Python exit code was $exitCode" }
    $text = Get-Content -LiteralPath $logPath -Raw
    if (-not $text.Contains('synthetic warning')) {
        throw 'Native stderr was not retained in the plaintext log.'
    }
    Write-Host 'PASS Python warning remained nonfatal and was logged.'
    exit 0
} finally {
    if (Test-Path -LiteralPath $logPath) {
        Remove-Item -LiteralPath $logPath -Force
    }
}
