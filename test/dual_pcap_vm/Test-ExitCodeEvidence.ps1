[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Read-ExitCodeEvidence.ps1')
$root = Join-Path ([IO.Path]::GetTempPath()) (
    'dual-pcap-exit-' + [Guid]::NewGuid().ToString('N'))
try {
    New-Item -ItemType Directory -Path $root | Out-Null
    $valid = Join-Path $root 'valid.txt'
    [IO.File]::WriteAllText($valid, "7`r`n", [Text.Encoding]::ASCII)
    if ((Read-ExitCodeEvidence -Path $valid) -ne 7) {
        throw 'Valid exit evidence was not parsed.'
    }
    $wrapped = Join-Path $root 'wrapped.txt'
    $wrappedTemp = $wrapped + '.tmp'
    $batch = Join-Path $root 'probe.cmd'
    $batchText = ("@echo off`r`n" +
        "cmd.exe /d /s /c `"exit /b 7`"`r`n" +
        "set `"FAKENET_EXIT=%ERRORLEVEL%`"`r`n" +
        "> `"$wrappedTemp`" echo %FAKENET_EXIT%`r`n" +
        "move /y `"$wrappedTemp`" `"$wrapped`" >nul`r`n" +
        "exit /b %FAKENET_EXIT%`r`n")
    [IO.File]::WriteAllText(
        $batch, $batchText, [Text.UTF8Encoding]::new($false))
    $process = Start-Process cmd.exe -PassThru -WindowStyle Hidden `
        -ArgumentList ('/d /s /c ""{0}""' -f $batch)
    $process.WaitForExit()
    if ((Read-ExitCodeEvidence -Path $wrapped) -ne 7) {
        throw 'Batch wrapper did not preserve the child exit code.'
    }
    foreach ($invalidText in @('', 'x', '-1', '256', "1`r`n2")) {
        $invalid = Join-Path $root (
            'invalid-' + [Guid]::NewGuid().ToString('N') + '.txt')
        [IO.File]::WriteAllText($invalid, $invalidText, [Text.Encoding]::ASCII)
        $rejected = $false
        try { $null = Read-ExitCodeEvidence -Path $invalid }
        catch { $rejected = $true }
        if (-not $rejected) { throw "Invalid evidence accepted: $invalidText" }
    }
    Write-Host 'PASS exit-code evidence parsing is strict.'
    exit 0
} finally {
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force
    }
}
