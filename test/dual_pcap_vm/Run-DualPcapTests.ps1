[CmdletBinding()]
param([string]$PythonPath = 'python.exe')

$ErrorActionPreference = 'Stop'
$script:ExitCode = 1
$script:TranscriptStarted = $false

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdministrator)) {
    $arguments = ('-NoLogo -NoProfile -ExecutionPolicy Bypass -File "{0}"' -f
        $PSCommandPath.Replace('"', '""'))
    $elevated = Start-Process powershell.exe -Verb RunAs -Wait -PassThru `
        -ArgumentList $arguments
    exit $elevated.ExitCode
}

function Test-IsVirtualMachine {
    $system = Get-CimInstance Win32_ComputerSystem
    $identity = ('{0} {1}' -f $system.Manufacturer, $system.Model).ToLowerInvariant()
    return $identity -match 'virtual|vmware|virtualbox|kvm|qemu|hyper-v|xen|parallels'
}

function Add-Result {
    param([string]$Name, [string]$Status, [string]$Detail = '')
    $line = "{0}`t{1}`t{2}" -f $Status, $Name, $Detail
    Add-Content -LiteralPath $script:ResultFile -Value $line -Encoding UTF8
    Write-Host $line
    if ($Status -eq 'FAIL') { $script:AnyFailure = $true }
}

function Test-PackageManifest {
    param([string]$Root)
    $path = Join-Path $Root 'dual-pcap-manifest.json'
    if (-not (Test-Path -LiteralPath $path)) {
        throw 'Package manifest is missing.'
    }
    $manifest = Get-Content -LiteralPath $path -Raw -Encoding UTF8 |
        ConvertFrom-Json
    if ($manifest.package_version -ne 'v1' -or
            $manifest.plan_version -ne 'v2') {
        throw 'Package/plan version contract mismatch.'
    }
    foreach ($file in @($manifest.files)) {
        $candidate = Join-Path $Root ([string]$file.path).Replace('/', '\')
        if (-not (Test-Path -LiteralPath $candidate)) {
            throw ('Manifest file is missing: ' + $file.path)
        }
        if ((Get-Item -LiteralPath $candidate).Length -ne [int64]$file.size) {
            throw ('Manifest size mismatch: ' + $file.path)
        }
        $hash = (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash
        if ($hash.ToLowerInvariant() -ne ([string]$file.sha256).ToLowerInvariant()) {
            throw ('Manifest hash mismatch: ' + $file.path)
        }
    }
}

function Get-NetworkSnapshot {
    $dns = @(Get-DnsClientServerAddress -AddressFamily IPv4 |
        Sort-Object InterfaceIndex |
        ForEach-Object {
            '{0}|{1}|{2}' -f $_.InterfaceIndex, $_.InterfaceAlias,
                (@($_.ServerAddresses) -join ',')
        })
    $routes = @(Get-NetRoute -AddressFamily IPv4 |
        Sort-Object InterfaceIndex, DestinationPrefix, NextHop, RouteMetric |
        ForEach-Object {
            '{0}|{1}|{2}|{3}|{4}' -f $_.InterfaceIndex,
                $_.DestinationPrefix, $_.NextHop, $_.RouteMetric, $_.PolicyStore
        })
    return [PSCustomObject]@{ Dns = $dns; Routes = $routes }
}

function Test-NetworkRestored {
    param($Before, [string]$CaseName)
    $after = Get-NetworkSnapshot
    $dnsDiff = @(Compare-Object $Before.Dns $after.Dns)
    $routeDiff = @(Compare-Object $Before.Routes $after.Routes)
    if ($dnsDiff.Count -eq 0 -and $routeDiff.Count -eq 0) {
        Add-Result ('NetworkRestore-' + $CaseName) 'PASS'
        return $true
    }
    $dnsDiff | Out-File -LiteralPath (
        Join-Path $script:LogRoot ($CaseName + '-dns-diff.txt')) -Encoding utf8
    $routeDiff | Out-File -LiteralPath (
        Join-Path $script:LogRoot ($CaseName + '-route-diff.txt')) -Encoding utf8
    Add-Result ('NetworkRestore-' + $CaseName) 'FAIL' 'DNS or route differs'
    return $false
}

function New-CaseConfig {
    param([string]$CaseDirectory)
    $source = Join-Path $script:RepoRoot 'fakenet\configs\default.ini'
    $destination = Join-Path $CaseDirectory 'dual-pcap.ini'
    $prefix = Join-Path $CaseDirectory 'packets'
    $text = Get-Content -LiteralPath $source -Raw
    $text = [regex]::Replace(
        $text, '(?mi)^DumpPackets\s*:\s*.*$', 'DumpPackets: Yes')
    $text = [regex]::Replace(
        $text, '(?mi)^DumpPacketsFilePrefix\s*:\s*.*$',
        'DumpPacketsFilePrefix: ' + $prefix)
    [IO.File]::WriteAllText(
        $destination, $text, [Text.UTF8Encoding]::new($false))
    return $destination
}

function New-LaunchCommand {
    param(
        [string]$CaseDirectory,
        [string]$ConfigPath,
        [string]$StopFlag,
        [string]$LogFile,
        [string]$FaultMode = ''
    )
    $cmdPath = Join-Path $CaseDirectory 'launch.cmd'
    if ($FaultMode) {
        $launcher = Join-Path $PSScriptRoot 'fault_launcher.py'
        $line = ('@"{0}" "{1}" --mode {2} --config "{3}" ' +
            '--stop-flag "{4}" --log-file "{5}"') -f
            $script:PythonExe, $launcher, $FaultMode, $ConfigPath,
            $StopFlag, $LogFile
    } else {
        $line = ('@"{0}" -m fakenet.fakenet --config-file "{1}" ' +
            '--stop-flag "{2}" --log-file "{3}" --no-pause') -f
            $script:PythonExe, $ConfigPath, $StopFlag, $LogFile
    }
    [IO.File]::WriteAllText(
        $cmdPath, ("@echo off`r`n@chcp 65001 >nul`r`n" +
            "$line`r`nexit /b %ERRORLEVEL%`r`n"),
        [Text.UTF8Encoding]::new($true))
    return $cmdPath
}

function Write-NewLogLines {
    param([string]$Path, [ref]$LineCount)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $lines = @(Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue)
    for ($index = $LineCount.Value; $index -lt $lines.Count; $index++) {
        Write-Host $lines[$index]
    }
    $LineCount.Value = $lines.Count
}

function Send-KnownTraffic {
    param([string]$OutputPath)
    $messages = @()
    foreach ($target in @(
            @('TCP4', '198.51.100.10', 80),
            @('TCP6', '::1', 80))) {
        try {
            $client = [Net.Sockets.TcpClient]::new()
            $pending = $client.BeginConnect($target[1], $target[2], $null, $null)
            $null = $pending.AsyncWaitHandle.WaitOne(1500)
            $client.Close()
            $messages += ('{0} attempted {1}:{2}' -f $target[0], $target[1], $target[2])
        } catch {
            $messages += ('{0} observed {1}' -f $target[0], $_.Exception.Message)
        }
    }
    foreach ($target in @(
            @('UDP4', '198.51.100.11', 5353),
            @('UDP6', '::1', 5353))) {
        try {
            $family = if ($target[0] -eq 'UDP6') {
                [Net.Sockets.AddressFamily]::InterNetworkV6
            } else {
                [Net.Sockets.AddressFamily]::InterNetwork
            }
            $udp = [Net.Sockets.UdpClient]::new($family)
            $bytes = [Text.Encoding]::ASCII.GetBytes('dual-pcap-v1')
            $null = $udp.Send($bytes, $bytes.Length, $target[1], $target[2])
            $udp.Close()
            $messages += ('{0} sent {1}:{2}' -f $target[0], $target[1], $target[2])
        } catch {
            $messages += ('{0} observed {1}' -f $target[0], $_.Exception.Message)
        }
    }
    $messages | Out-File -LiteralPath $OutputPath -Append -Encoding utf8
}

function Stop-CaseProcess {
    param($Process, [string]$StopFlag, [string]$CaseName)
    if (-not (Test-Path -LiteralPath $StopFlag)) {
        [IO.File]::WriteAllText($StopFlag, 'stop', [Text.Encoding]::ASCII)
    }
    if (-not $Process.WaitForExit(30000)) {
        Add-Result ('Stop-' + $CaseName) 'FAIL' 'process did not stop in 30 seconds'
        Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        $Process.WaitForExit()
    }
}

function Invoke-FakeNetCase {
    param([string]$CaseName, [string]$FaultMode = '', [switch]$Interactive)
    $caseDirectory = Join-Path $script:LogRoot $CaseName
    New-Item -ItemType Directory -Path $caseDirectory -Force | Out-Null
    $config = New-CaseConfig $caseDirectory
    $stopFlag = Join-Path $caseDirectory 'stop.flag'
    $logFile = Join-Path $caseDirectory 'fakenet.log'
    $stdout = Join-Path $caseDirectory 'console.out.txt'
    $stderr = Join-Path $caseDirectory 'console.err.txt'
    $trafficLog = Join-Path $caseDirectory 'traffic.txt'
    $command = New-LaunchCommand $caseDirectory $config $stopFlag $logFile $FaultMode
    $before = Get-NetworkSnapshot
    $cmdArguments = '/d /s /c ""{0}""' -f $command
    $process = Start-Process cmd.exe -PassThru -WorkingDirectory $script:RepoRoot `
        -ArgumentList $cmdArguments -RedirectStandardOutput $stdout `
        -RedirectStandardError $stderr -WindowStyle Hidden
    $deadline = [DateTime]::UtcNow.AddSeconds(45)
    while (-not $process.HasExited -and [DateTime]::UtcNow -lt $deadline) {
        if ((Test-Path -LiteralPath $logFile) -and
                ([string](Get-Content -LiteralPath $logFile -Raw)).Contains(
                    'Capturing traffic to')) { break }
        Start-Sleep -Milliseconds 200
        $process.Refresh()
    }
    if ($process.HasExited) {
        Add-Result ('Start-' + $CaseName) 'FAIL' ('exit=' + $process.ExitCode)
        Test-NetworkRestored $before $CaseName | Out-Null
        return $null
    }

    Send-KnownTraffic $trafficLog
    if ($Interactive) {
        Write-Host ''
        Write-Host 'FakeNet-NG is READY. Known IPv4/IPv6 traffic was generated.'
        Write-Host 'Press Ctrl+C or Enter to request a safe stop.'
        $oldMode = [Console]::TreatControlCAsInput
        [Console]::TreatControlCAsInput = $true
        $lineCount = 0
        try {
            while (-not $process.HasExited) {
                Write-NewLogLines $logFile ([ref]$lineCount)
                if ([Console]::KeyAvailable) {
                    $key = [Console]::ReadKey($true)
                    if ($key.Key -eq [ConsoleKey]::Enter -or
                            ($key.Modifiers -band [ConsoleModifiers]::Control -and
                             $key.Key -eq [ConsoleKey]::C)) {
                        Stop-CaseProcess $process $stopFlag $CaseName
                        break
                    }
                }
                Start-Sleep -Milliseconds 100
                $process.Refresh()
            }
            Write-NewLogLines $logFile ([ref]$lineCount)
        } finally {
            [Console]::TreatControlCAsInput = $oldMode
        }
    } elseif ($FaultMode -eq 'close') {
        Stop-CaseProcess $process $stopFlag $CaseName
    } else {
        $faultDeadline = [DateTime]::UtcNow.AddSeconds(20)
        while (-not $process.HasExited -and [DateTime]::UtcNow -lt $faultDeadline) {
            Send-KnownTraffic $trafficLog
            Start-Sleep -Milliseconds 250
            $process.Refresh()
        }
        if (-not $process.HasExited) {
            Add-Result ('FaultWake-' + $CaseName) 'FAIL' 'capture fault did not wake main loop'
            Stop-CaseProcess $process $stopFlag $CaseName
        }
    }
    $process.WaitForExit()
    $expected = if ($FaultMode) { 1 } else { 0 }
    if ($process.ExitCode -eq $expected) {
        Add-Result ('Exit-' + $CaseName) 'PASS' ('exit=' + $process.ExitCode)
    } else {
        Add-Result ('Exit-' + $CaseName) 'FAIL' (
            'expected={0}; actual={1}' -f $expected, $process.ExitCode)
    }
    Test-NetworkRestored $before $CaseName | Out-Null
    return $caseDirectory
}

try {
    if (-not (Test-IsVirtualMachine)) {
        throw 'REFUSED: this acceptance runner must execute in a virtual machine.'
    }
    $script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    Test-PackageManifest $script:RepoRoot
    $logsBase = Join-Path $PSScriptRoot 'Logs'
    New-Item -ItemType Directory -Path $logsBase -Force | Out-Null
    $script:LogRoot = Join-Path $logsBase (
        'dual-pcap-v1-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
    New-Item -ItemType Directory -Path $script:LogRoot -Force | Out-Null
    $script:ResultFile = Join-Path $script:LogRoot 'results.tsv'
    $script:AnyFailure = $false
    Start-Transcript -LiteralPath (Join-Path $script:LogRoot 'runner.log') | Out-Null
    $script:TranscriptStarted = $true

    $script:PythonExe = (Get-Command $PythonPath -ErrorAction Stop).Source
    & $script:PythonExe -m pip install --disable-pip-version-check --no-index `
        --find-links (Join-Path $script:RepoRoot 'wheelhouse') --require-hashes `
        -r (Join-Path $script:RepoRoot 'requirements-domain-takeover-windows.lock') *>&1 |
        Tee-Object -FilePath (Join-Path $script:LogRoot 'dependency-install.log')
    if ($LASTEXITCODE -ne 0) { throw 'Offline dependency installation failed.' }

    $identity = @'
import json, platform, dpkt
print(json.dumps({'python': platform.python_version(), 'machine': platform.machine(), 'dpkt': dpkt.__version__, 'dpkt_path': dpkt.__file__, 'dlt_raw': dpkt.pcap.DLT_RAW}, sort_keys=True))
'@
    $identity | & $script:PythonExe - 2>&1 |
        Tee-Object -FilePath (Join-Path $script:LogRoot 'python-identity.log')
    if ($LASTEXITCODE -ne 0) { throw 'Python identity check failed.' }
    Add-Result 'Dependencies' 'PASS' 'offline lock and actual import verified'

    Push-Location $script:RepoRoot
    try {
        & $script:PythonExe -m unittest discover -s test -p 'test_*.py' -v *>&1 |
            Tee-Object -FilePath (Join-Path $script:LogRoot 'unit-tests.log')
        if ($LASTEXITCODE -eq 0) { Add-Result 'PythonTests' 'PASS' }
        else { Add-Result 'PythonTests' 'FAIL' ('exit=' + $LASTEXITCODE) }

        & $script:PythonExe test\benchmark_dual_pcap.py --output (
            Join-Path $script:LogRoot 'performance.json') *>&1 |
            Tee-Object -FilePath (Join-Path $script:LogRoot 'performance.log')
        if ($LASTEXITCODE -eq 0) { Add-Result 'PerformanceGate' 'PASS' }
        else { Add-Result 'PerformanceGate' 'FAIL' ('exit=' + $LASTEXITCODE) }

        $normal = Invoke-FakeNetCase 'normal-ctrl-c' -Interactive
        if ($normal) {
            $raw = @(Get-ChildItem -LiteralPath $normal -Filter 'packets_*.pcap' |
                Where-Object Name -NotLike '*-converted.pcap')
            $ethernet = @(Get-ChildItem -LiteralPath $normal -Filter `
                'packets_*-converted.pcap')
            if ($raw.Count -eq 1 -and $ethernet.Count -eq 1) {
                & $script:PythonExe (Join-Path $PSScriptRoot 'verify_dual_pcap.py') `
                    $raw[0].FullName $ethernet[0].FullName --output (
                        Join-Path $normal 'pcap-verification.json') *>&1 |
                    Tee-Object -FilePath (Join-Path $normal 'pcap-verification.log')
                if ($LASTEXITCODE -eq 0) { Add-Result 'LivePcapPair' 'PASS' }
                else { Add-Result 'LivePcapPair' 'FAIL' ('exit=' + $LASTEXITCODE) }
            } else {
                Add-Result 'LivePcapPair' 'FAIL' 'expected exactly one pair'
            }
        }

        foreach ($mode in @('raw-write', 'ethernet-write', 'close')) {
            $null = Invoke-FakeNetCase ('fault-' + $mode) -FaultMode $mode
        }
    } finally {
        Pop-Location
    }

    if ($script:AnyFailure) { $script:ExitCode = 1 }
    else { $script:ExitCode = 0 }
} catch {
    if ($script:ResultFile) {
        Add-Result 'Runner' 'FAIL' $_.Exception.Message
    }
    Write-Error $_
    $script:ExitCode = 1
} finally {
    if ($script:TranscriptStarted) { Stop-Transcript | Out-Null }
    if ($script:LogRoot) {
        Write-Host ('Plain logs available at: ' + $script:LogRoot)
    }
}

exit $script:ExitCode
