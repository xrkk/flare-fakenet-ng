[CmdletBinding()]
param([switch]$Elevated)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ManifestTools.ps1')
. (Join-Path $PSScriptRoot 'RouteResultTools.ps1')
. (Join-Path $PSScriptRoot 'ProcessExitTools.ps1')
. (Join-Path $PSScriptRoot 'NativeCommandTools.ps1')
. (Join-Path $PSScriptRoot 'FakeNetLaunchTools.ps1')
. (Join-Path $PSScriptRoot 'WinDivertVersionTools.ps1')
. (Join-Path $PSScriptRoot 'LongTaskConsoleTools.ps1')
$script:ExitCode = 1
$script:LogDir = $null
$script:FakeNet = $null
$script:PktmonStarted = $false
$script:OriginalDns = @()
$script:VenvPython = $null
$script:StopFlag = $null
$script:ClientProcesses = @()
$reviewedA = '__REVIEWED_PUBLIC_IPV4_A__'
$reviewedB = '__REVIEWED_PRIVATE_IPV4_B__'
$sentinelPort = __REVIEWED_SENTINEL_PORT__
$packageVersion = '__PACKAGE_VERSION__'
$sentinelProtocol = 'FNPR/1'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-IsVirtualMachine {
    $system = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    $identity = ('{0} {1}' -f $system.Manufacturer, $system.Model).ToLowerInvariant()
    return $identity -match 'virtual|vmware|virtualbox|kvm|qemu|hyper-v|xen|parallels'
}

function Add-Result([string]$Name, [string]$Status, [string]$Detail) {
    $line = "{0}`t{1}`t{2}" -f $Status, $Name, $Detail
    Write-Host $line
    if ($script:LogDir) {
        Add-Content -LiteralPath (Join-Path $script:LogDir 'results.tsv') `
            -Value $line -Encoding utf8
    }
}

function Get-DnsSnapshot {
    return @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |
        Sort-Object InterfaceIndex | ForEach-Object {
            '{0}|{1}' -f $_.InterfaceIndex, (@($_.ServerAddresses) -join ',')
        })
}

function Select-ReviewedDns {
    $local = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
        Select-Object -ExpandProperty IPAddress)
    $interfaces = @{}
    Get-NetIPInterface -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object ConnectionState -eq 'Connected' |
        ForEach-Object { $interfaces[[int]$_.InterfaceIndex] = $_ }
    $routes = @(Get-NetRoute -AddressFamily IPv4 `
        -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
        Where-Object { $interfaces.ContainsKey([int]$_.InterfaceIndex) } |
        Sort-Object @{Expression={
            $_.RouteMetric + $interfaces[[int]$_.InterfaceIndex].InterfaceMetric
        }}, InterfaceIndex)
    foreach ($route in $routes) {
        $servers = @(Get-DnsClientServerAddress -InterfaceIndex `
            $route.InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop |
            Select-Object -ExpandProperty ServerAddresses)
        foreach ($server in $servers) {
            $parsed = $null
            if ([Net.IPAddress]::TryParse([string]$server, [ref]$parsed) -and
                    $parsed.AddressFamily -eq 'InterNetwork' -and
                    [string]$server -notin $local -and
                    [string]$server -notin @('0.0.0.0','127.0.0.1')) {
                return [string]$server
            }
        }
    }
    throw 'No reviewed IPv4 DNS server exists on the preferred default-route interface.'
}

function Assert-Manifest([string]$Root) {
    $manifestPath = Join-Path $Root 'process-redirect-manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw 'Package manifest is missing.'
    }
    $manifest = Read-StrictUtf8Json $manifestPath
    if ($manifest.package_version -ne $packageVersion -or
            $manifest.original_ipv4 -ne $reviewedA -or
            $manifest.target_ipv4 -ne $reviewedB -or
            [int]$manifest.sentinel_port -ne $sentinelPort -or
            $manifest.sentinel_protocol -ne $sentinelProtocol) {
        throw 'Manifest reviewed profile does not match the runner constants.'
    }
    $manifestIndex = 0
    foreach ($file in @($manifest.files)) {
        $relativePath = [string]$file.path
        $candidatePath = Join-Path $Root $relativePath
        $path = [IO.Path]::GetFullPath($candidatePath)
        if (-not $path.StartsWith(
                $Root + [IO.Path]::DirectorySeparatorChar,
                [StringComparison]::OrdinalIgnoreCase) -or
                -not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw ('Manifest file is missing or escapes package root: ' + $file.path)
        }
        $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne [string]$file.sha256 -or
                (Get-Item -LiteralPath $path).Length -ne [int64]$file.size) {
            throw ('Manifest mismatch: ' + $file.path)
        }
        $manifestIndex++
    }
    return $manifest
}

function Invoke-RouteSnapshot([string]$Root) {
    $handshake = Join-Path $script:LogDir 'route-handshake'
    New-Item -ItemType Directory -Path $handshake | Out-Null
    $ready = Join-Path $handshake 'ready'
    $go = Join-Path $handshake 'go'
    $stdout = Join-Path $script:LogDir 'route-snapshot.json'
    $stderr = Join-Path $script:LogDir 'route-snapshot.err.log'
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(
        (@($reviewedA, $reviewedB) | ConvertTo-Json -Compress)))
    $process = Start-Process powershell.exe -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr `
        -ArgumentList @('-NoLogo','-NoProfile','-NonInteractive',
            '-ExecutionPolicy','Bypass','-File',
            ('"{0}"' -f (Join-Path $Root 'Test-ProcessRedirectRoutes.ps1')),
             '-TargetsBase64',$encoded,'-ReadyFile',('"{0}"' -f $ready),
             '-GoFile',('"{0}"' -f $go))
    Register-ProcessExitCodeTracking $process
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    while (-not (Test-Path -LiteralPath $ready)) {
        if ($process.HasExited) { throw 'Route checker exited before READY.' }
        if ([DateTime]::UtcNow -ge $deadline) { throw 'Route checker READY timeout.' }
        Start-Sleep -Milliseconds 20
    }
    [IO.File]::WriteAllText($go, 'go', [Text.Encoding]::ASCII)
    if (-not $process.WaitForExit(5000)) {
        $process.Kill()
        throw 'Route checker completion timeout.'
    }
    $routeExitCode = Read-TrackedProcessExitCode $process
    if ($routeExitCode -ne 0) {
        throw ('Route checker failed: ' + (Get-Content $stderr -Raw))
    }
    $routeJson = Get-Content -LiteralPath $stdout -Raw
    $routes = @(ConvertFrom-RouteSnapshotJson $routeJson)
    if ($routes.Count -ne 2 -or
            @($routes.source_ipv4 | Select-Object -Unique).Count -ne 1 -or
            @($routes.interface_index | Select-Object -Unique).Count -ne 1) {
        throw 'A/B route snapshots do not share exactly one source and interface.'
    }
    foreach ($item in $routes) {
        if ([string]$item.weak_host_send -ne 'Disabled' -or
                [string]$item.weak_host_receive -ne 'Disabled' -or
                [string]$item.address_state -ne 'Preferred' -or
                [bool]$item.skip_as_source) {
            throw 'Weak-host or frozen source-address state is unsafe.'
        }
    }
    $targetRoute = $routes | Where-Object target_ipv4 -eq $reviewedB
    if ($targetRoute.next_hop -ne '0.0.0.0' -or
            $targetRoute.destination_prefix -eq '0.0.0.0/0') {
        throw 'B is not reached through a reviewed specific on-link route.'
    }
    return [PSCustomObject]@{
        Routes = $routes
        SourceIPv4 = [string]$routes[0].source_ipv4
        InterfaceIndex = [int]$routes[0].interface_index
    }
}

function Test-Sentinel([string]$SourceIPv4, [int]$InterfaceIndex) {
    $nonce = 'preflight-{0}' -f [Guid]::NewGuid().ToString('N')
    $client = [Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
    try {
        $client.Client.Bind([Net.IPEndPoint]::new(
            [Net.IPAddress]::Parse($SourceIPv4), 0))
        $connect = $client.ConnectAsync($reviewedB, $sentinelPort)
        if (-not $connect.Wait(3000) -or -not $client.Connected) {
            throw 'B sentinel connect timeout.'
        }
        $found = @(Find-NetRoute -RemoteIPAddress $reviewedB `
            -ErrorAction Stop)
        $best = ConvertFrom-FindNetRouteResult `
            -Result $found -Target $reviewedB
        if ([int]$best.NetRoute.InterfaceIndex -ne $InterfaceIndex -or
                [string]$best.IPAddress -ne $SourceIPv4) {
            throw 'B sentinel best route no longer matches the frozen source/interface.'
        }
        $stream = $client.GetStream()
        $stream.ReadTimeout = 3000
        $request = [Text.Encoding]::ASCII.GetBytes(
            "FNPR/1|$nonce|preflight`n")
        $stream.Write($request, 0, $request.Length)
        $buffer = New-Object byte[] 256
        $count = $stream.Read($buffer, 0, $buffer.Length)
        $response = [Text.Encoding]::ASCII.GetString($buffer, 0, $count)
        if ($response -ne "FNPR/1|$nonce|OK`n") {
            throw 'B sentinel nonce protocol mismatch.'
        }
        [IO.File]::WriteAllText(
            (Join-Path $script:LogDir 'sentinel-preflight.log'),
            "protocol=FNPR/1`nsource=$SourceIPv4`ninterface=$InterfaceIndex`ntarget=$reviewedB`nport=$sentinelPort`nnonce=$nonce`n",
            [Text.UTF8Encoding]::new($false))
    } finally {
        $client.Dispose()
    }
}

function Wait-LogMarker([string]$Path, [string]$ErrorPath,
                        [string]$Marker, [int]$Seconds) {
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($script:FakeNet.HasExited) {
            $exitCode = Read-TrackedProcessExitCode $script:FakeNet
            throw ('FakeNet exited before {0}; exit={1}; stderr={2}' -f
                $Marker,$exitCode,(Get-LogSummary $ErrorPath))
        }
        if (Test-AnyLogContainsMarker -Paths @($Path,$ErrorPath) `
                -Marker $Marker) {
            return
        }
        Start-Sleep -Milliseconds 100
    }
    throw ('Timed out waiting for ' + $Marker)
}

function Stop-FakeNet([string]$Root) {
    if (-not $script:FakeNet) { return }
    if (-not $script:FakeNet.HasExited) {
        [IO.File]::WriteAllText(
            $script:StopFlag, 'stop', [Text.Encoding]::ASCII)
        if (-not $script:FakeNet.WaitForExit(30000)) {
            throw 'FakeNet did not stop after the reviewed stop flag.'
        }
    }
    $fakeNetExitCode = Read-TrackedProcessExitCode $script:FakeNet
    if ($fakeNetExitCode -ne 0) {
        throw ('FakeNet exited with code ' + $fakeNetExitCode)
    }
}

function Register-ClientProcess($Process, [string]$LogName) {
    Register-ProcessExitCodeTracking $Process
    $script:ClientProcesses += [PSCustomObject]@{
        Process=$Process
        LogName=$LogName
    }
}

function Stop-TrackedClientProcesses {
    $failures = @()
    foreach ($entry in $script:ClientProcesses) {
        $process = $entry.Process
        if ($process.HasExited) { continue }
        Add-Result TARGET_PROCESS_STILL_RUNNING FAIL (
            'name={0};pid={1}; stopping before WinDivert closes' -f
                $entry.LogName,$process.Id)
        $script:ExitCode = 1
        try {
            $process.Kill()
            if (-not $process.WaitForExit(5000)) {
                $failures += (
                    'target client did not exit after kill: ' + $entry.LogName)
            }
        } catch {
            $failures += ('target client stop failed: {0}: {1}' -f
                $entry.LogName,$_.Exception.Message)
        }
    }
    if ($failures.Count) { throw ($failures -join '; ') }
}

function Invoke-Client([string]$Path, [string[]]$Arguments,
                       [string]$LogName, [int[]]$AcceptedExitCodes,
                       [int]$TimeoutMilliseconds=30000,
                       [string]$ProgressName='', [int]$ProgressTotal=0,
                       [int]$ProgressIntervalSeconds=60) {
    $stdout = Join-Path $script:LogDir ($LogName + '.jsonl')
    $stderr = Join-Path $script:LogDir ($LogName + '.err.log')
    $process = Start-Process -FilePath $Path -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr `
        -ArgumentList $Arguments
    Register-ClientProcess $process $LogName
    if ($ProgressName) {
        $started = [DateTime]::UtcNow
        $deadline = $started.AddMilliseconds($TimeoutMilliseconds)
        $nextProgress = $started.AddSeconds($ProgressIntervalSeconds)
        while (-not $process.WaitForExit(1000)) {
            $now = [DateTime]::UtcNow
            if ($now -ge $deadline) { throw ($LogName + ' timed out.') }
            if ($now -ge $nextProgress) {
                Write-LongTaskProgress -Name $ProgressName `
                    -Completed (Get-CompletedConnectionCount $stdout) `
                    -Total $ProgressTotal `
                    -ElapsedSeconds ([int]($now - $started).TotalSeconds) `
                    -HardTimeoutSeconds ([int]($TimeoutMilliseconds / 1000))
                $nextProgress = $now.AddSeconds($ProgressIntervalSeconds)
            }
        }
    } elseif (-not $process.WaitForExit($TimeoutMilliseconds)) {
        throw ($LogName + ' timed out.')
    }
    $clientExitCode = Read-TrackedProcessExitCode $process
    if ($clientExitCode -notin $AcceptedExitCodes) {
        throw ('{0} exit code {1} is not accepted.' -f $LogName,$clientExitCode)
    }
    return $clientExitCode
}

if (-not (Test-IsAdministrator)) {
    if ($Elevated) { Write-Error 'Administrator elevation failed.'; exit 1 }
    $arguments = @('-NoLogo','-NoProfile','-ExecutionPolicy','Bypass',
        '-File',('"{0}"' -f $PSCommandPath),'-Elevated')
    $elevatedProcess = Start-Process powershell.exe -Verb RunAs -Wait -PassThru `
        -ArgumentList $arguments
    exit $elevatedProcess.ExitCode
}

$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$logRoot = Join-Path $root 'dist\Logs'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$script:LogDir = Join-Path $logRoot ("process-redirect-$packageVersion-$stamp")
New-Item -ItemType Directory -Path $script:LogDir -Force | Out-Null
try {
    $script:OriginalDns = Get-DnsSnapshot
    $script:OriginalDns | Set-Content -LiteralPath (
        Join-Path $script:LogDir 'dns-before.txt') -Encoding utf8
    if (-not (Test-IsVirtualMachine)) { throw 'Physical host refused.' }
    $osVersion = [Environment]::OSVersion.Version
    if ($osVersion.Major -ne 10 -or $osVersion.Minor -ne 0 -or
            $osVersion.Build -ne 19045) {
        throw ('Unexpected Windows build: ' + $osVersion)
    }
    Add-Result WindowsBuild PASS ([string]$osVersion)
    $manifest = Assert-Manifest $root
    Add-Result Manifest PASS $packageVersion
    $dns = Select-ReviewedDns
    Add-Result DnsAutoSelection PASS $dns
    $route = Invoke-RouteSnapshot $root
    Add-Result RouteSnapshot PASS (
        'source={0};interface={1}' -f $route.SourceIPv4,$route.InterfaceIndex)
    Test-Sentinel $route.SourceIPv4 $route.InterfaceIndex
    Add-Result SentinelPreflight PASS "FNPR/1 $reviewedB`:$sentinelPort"

    Write-LongTaskNotice -Name 'OfflineEnvironmentSetup' `
        -ExpectedDuration '30-90 seconds on a fresh VM; cached runs are faster' `
        -HardTimeout 'No network fallback; any setup command failure stops the test' `
        -Detail 'Creating the package-local Python environment and installing locked wheels.'
    $venv = Join-Path $root '.process-redirect-venv'
    if (-not (Test-Path -LiteralPath (Join-Path $venv 'Scripts\python.exe'))) {
        & python.exe -m venv $venv
        if ($LASTEXITCODE -ne 0) { throw 'Unable to create package-local venv.' }
    }
    $script:VenvPython = Join-Path $venv 'Scripts\python.exe'
    & $script:VenvPython -m pip install --disable-pip-version-check `
        --no-index --require-hashes --find-links (Join-Path $root 'wheelhouse') `
        -r (Join-Path $root 'requirements-domain-takeover-windows.lock') `
        *> (Join-Path $script:LogDir 'dependency-install.log')
    if ($LASTEXITCODE -ne 0) { throw 'Offline dependency installation failed.' }
    $identity = & $script:VenvPython -c `
        "import json,platform,sys;print(json.dumps({'python':platform.python_version(),'machine':platform.machine()}))"
    $identity | Set-Content -LiteralPath (
        Join-Path $script:LogDir 'python-identity.json') -Encoding ascii
    $decodedIdentity = $identity | ConvertFrom-Json
    if ($decodedIdentity.python -ne '3.13.7' -or
            $decodedIdentity.machine -notmatch 'AMD64|x86_64') {
        throw ('Unexpected Python runtime: ' + $identity)
    }
    $winDivertIdentity = & $script:VenvPython -c (
        "import hashlib,json,pathlib; from pydivert import windivert_dll as w; " +
        "p=pathlib.Path(w.DLL_PATH).resolve(); print(json.dumps({" +
        "'dll_path':str(p),'dll_sha256':hashlib.sha256(p.read_bytes()).hexdigest()}))")
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to identify the installed WinDivert DLL.'
    }
    $decodedWinDivert = $winDivertIdentity | ConvertFrom-Json
    if ([string]$decodedWinDivert.dll_sha256 -ne
            [string]$manifest.expected_windivert_x64_dll_sha256) {
        throw 'Installed WinDivert DLL differs from the manifest-bound wheel.'
    }

    $targetClient = Join-Path $PSScriptRoot 'bin\reviewed-target-client.exe'
    $negativeClient = Join-Path $PSScriptRoot 'bin\non-target-client.exe'
    $targetHash = (Get-FileHash $targetClient -Algorithm SHA256).Hash.ToLowerInvariant()
    $negativeHash = (Get-FileHash $negativeClient -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($targetHash -ne [string]$manifest.target_client_sha256) {
        throw 'Reviewed target client hash does not match manifest.'
    }
    if ($negativeHash -ne [string]$manifest.non_target_client_sha256 -or
            $negativeHash -eq $targetHash) {
        throw 'Non-target client identity is not distinct and manifest-bound.'
    }
    $configTemplate = Get-Content -LiteralPath (
        Join-Path $root 'fakenet\configs\process_redirect_windows.ini') -Raw
    $runtimeConfig = $configTemplate.Replace('__RUNTIME_EXTERNAL_DNS__',$dns).
        Replace('__RUNTIME_PROCESS_IMAGE_PATH__',$targetClient).
        Replace('__RUNTIME_PROCESS_IMAGE_SHA256__',$targetHash).
        Replace('__RUNTIME_PUBLIC_IPV4_A__',$reviewedA).
        Replace('__RUNTIME_PRIVATE_IPV4_B__',$reviewedB)
    $remainingMarkers = @([regex]::Matches(
        $runtimeConfig,'__[A-Z0-9_]+__') | ForEach-Object Value |
        Select-Object -Unique)
    if ($remainingMarkers.Count -ne 0) {
        throw ('Runtime config contains unresolved markers: ' +
            ($remainingMarkers -join ','))
    }
    $configPath = Join-Path $script:LogDir 'reviewed-runtime.ini'
    [IO.File]::WriteAllText($configPath,$runtimeConfig,
        [Text.UTF8Encoding]::new($false))

    $pktmonPreStopLog = Join-Path $script:LogDir 'pktmon-pre-stop.log'
    $pktmonPreStopExit = Invoke-NativeCaptured {
        & pktmon.exe stop
    } $pktmonPreStopLog
    Add-Result PktmonPreStop OBSERVED (
        'exit={0}; stale capture cleanup may report not running' -f
            $pktmonPreStopExit)
    $etl = Join-Path $script:LogDir 'wire.etl'

    $fakeLog = Join-Path $script:LogDir 'fakenet.log'
    $fakeErr = Join-Path $script:LogDir 'fakenet.err.log'
    $script:StopFlag = Join-Path $script:LogDir 'stop-fakenet.flag'
    $hadPythonPath = Test-Path Env:PYTHONPATH
    $previousPythonPath = $env:PYTHONPATH
    Write-LongTaskNotice -Name 'FakeNetStartup' `
        -ExpectedDuration '10-70 seconds on the reviewed 4 GB VM' `
        -HardTimeout 'PROCESS_REDIRECT_READY: 60 seconds; DOMAIN_ALLOWLIST_READY: 10 seconds' `
        -Detail 'Starting FakeNet-NG and WinDivert, then waiting for both READY markers.'
    try {
        $env:PYTHONPATH = $root
        $script:FakeNet = Start-Process -FilePath $script:VenvPython `
            -PassThru -WorkingDirectory $script:LogDir `
            -RedirectStandardOutput $fakeLog `
            -RedirectStandardError $fakeErr -ArgumentList @(
                '-X','utf8','-u','-m','fakenet.fakenet',
                '-c',('"{0}"' -f $configPath),
                '-f',('"{0}"' -f $script:StopFlag),'-p','-v')
    } finally {
        if ($hadPythonPath) { $env:PYTHONPATH = $previousPythonPath }
        else { Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue }
    }
    Register-ProcessExitCodeTracking $script:FakeNet
    Wait-LogMarker $fakeLog $fakeErr 'PROCESS_REDIRECT_READY' 60
    Wait-LogMarker $fakeLog $fakeErr 'DOMAIN_ALLOWLIST_READY' 10
    Add-Result FakeNetReady PASS "pid=$($script:FakeNet.Id)"
    try {
        $writeProbe = [IO.File]::Open(
            $targetClient,[IO.FileMode]::Open,[IO.FileAccess]::Write,
            [IO.FileShare]::Read)
        $writeProbe.Dispose()
        throw 'Reviewed target image was writable while its frozen handle was active.'
    } catch [IO.IOException] {
        Add-Result FrozenImageWriteDenial PASS 'reviewed image write-open was denied'
    } catch [UnauthorizedAccessException] {
        Add-Result FrozenImageWriteDenial PASS 'reviewed image write-open was denied'
    }
    $serviceQueryExit = Invoke-NativeCaptured {
        & sc.exe query WinDivert1.3
    } (Join-Path $script:LogDir 'windivert-service.log')
    if ($serviceQueryExit -ne 0) {
        throw ('WinDivert1.3 service query failed with exit code ' +
            $serviceQueryExit)
    }
    $driver = Get-CimInstance Win32_SystemDriver `
        -Filter "Name='WinDivert1.3'" -ErrorAction Stop
    if (-not $driver -or $driver.State -ne 'Running') {
        throw 'WinDivert1.3 running driver could not be attributed.'
    }
    $driverPath = ([string]$driver.PathName).Trim('"')
    if ($driverPath.StartsWith('\??\')) { $driverPath = $driverPath.Substring(4) }
    if (-not (Test-Path -LiteralPath $driverPath -PathType Leaf)) {
        throw ('Loaded WinDivert driver path cannot be opened: ' + $driverPath)
    }
    $driverEvidence = [ordered]@{
        expected_version=[string]$manifest.expected_windivert_version
        expected_service=[string]$manifest.expected_windivert_service
        actual_service=[string]$driver.Name
        actual_state=[string]$driver.State
        actual_path=$driverPath
        expected_sys_sha256=[string]$manifest.expected_windivert_x64_sys_sha256
        actual_sha256=(Get-FileHash -LiteralPath $driverPath `
            -Algorithm SHA256).Hash.ToLowerInvariant()
        actual_file_version=(Get-Item -LiteralPath $driverPath).VersionInfo.FileVersion
        expected_dll_sha256=[string]$manifest.expected_windivert_x64_dll_sha256
        actual_dll_path=[string]$decodedWinDivert.dll_path
        actual_dll_sha256=[string]$decodedWinDivert.dll_sha256
    }
    $driverEvidence | ConvertTo-Json | Set-Content -LiteralPath (
        Join-Path $script:LogDir 'windivert-driver.json') -Encoding utf8
    if ($driverEvidence.actual_service -ne $driverEvidence.expected_service) {
        throw 'Loaded WinDivert service differs from reviewed baseline.'
    }
    if (-not (Test-WinDivertVersionMatch `
            -Expected ([string]$driverEvidence.expected_version) `
            -Actual ([string]$driverEvidence.actual_file_version))) {
        throw 'Loaded WinDivert file version differs from reviewed baseline.'
    }
    if ([string]$driverEvidence.actual_sha256 -ne
            [string]$manifest.expected_windivert_x64_sys_sha256) {
        throw 'Loaded WinDivert driver differs from the manifest-bound wheel.'
    }

    $baseArgs = @('--host',$reviewedA,'--port',[string]$sentinelPort)
    [void](Invoke-Client $negativeClient ($baseArgs + @(
        '--connections','1','--nonce-prefix','negative')) 'non-target-negative' @(1))
    Add-Result NonTargetIsolation PASS 'negative client did not receive sentinel response'

    # The independent wire verdict covers target traffic only. Capturing only
    # NIC components excludes pre-rewrite snapshots from upper stack layers.
    $pktmonStartExit = Invoke-NativeCaptured {
        & pktmon.exe start --capture --comp nics --pkt-size 0 --file-name $etl
    } (Join-Path $script:LogDir 'pktmon-start.log')
    if ($pktmonStartExit -ne 0) {
        throw ('pktmon start failed with exit code ' + $pktmonStartExit)
    }
    $script:PktmonStarted = $true

    [void](Invoke-Client $targetClient ($baseArgs + @(
        '--connections','1','--nonce-prefix','positive')) 'target-positive' @(0))
    Add-Result PositiveTarget PASS 'getpeername and nonce are in target-positive.jsonl'

    # Fixed reviewed pressure gate: 10,000 strict new flows at 25/s remains
    # below the 32/s owner budget. A synchronized 64-thread burst proves fail-closed
    # budget pressure without expecting every burst connection to succeed.
    Write-LongTaskNotice `
        -Name 'OwnerGate10000' `
        -ExpectedDuration '16-22 minutes on the reviewed 4 GB VM' `
        -HardTimeout '25 minutes' `
        -ProgressEveryMinute `
        -Detail ('10,000 sequential connections. Local ephemeral ports may ' +
            'increase, wrap, or be reused; they are not a progress counter.')
    [void](Invoke-Client $targetClient ($baseArgs + @(
        '--connections','10000','--minimum-start-interval-ms','40',
        '--nonce-prefix','owner-gate')) 'owner-gate-10000' @(0) 1500000 `
        'OwnerGate10000' 10000 60)
    Add-Result OwnerGate10000 PASS '10,000 target connections completed'
    [void](Invoke-Client $targetClient ($baseArgs + @(
        '--parallel-connections','64','--nonce-prefix','burst')) `
        'burst-64' @(0,1) 30000)
    Add-Result ConcurrentBurst64 PASS '64 synchronized flows ended; verifier requires audited budget denial and no wire A'

    Write-LongTaskNotice -Name 'StopAndVerify' `
        -ExpectedDuration '1-5 minutes, depending on capture size' `
        -HardTimeout 'FakeNet stop: 30 seconds; later verifiers are fail-closed' `
        -Detail 'Stopping capture, converting ETL, and validating wire/PCAP evidence.'
    Stop-TrackedClientProcesses
    Stop-FakeNet $root
    Add-Result GracefulStop PASS 'target clients exited before FakeNet stop flag'
    $script:FakeNet = $null
    $pktmonStopExit = Invoke-NativeCaptured {
        & pktmon.exe stop
    } (Join-Path $script:LogDir 'pktmon-stop.log')
    if ($pktmonStopExit -ne 0) {
        throw ('pktmon stop failed with exit code ' + $pktmonStopExit)
    }
    $script:PktmonStarted = $false
    $pcapng = Join-Path $script:LogDir 'wire.pcapng'
    $pktmonConvertExit = Invoke-NativeCaptured {
        & pktmon.exe etl2pcap $etl --out $pcapng
    } (Join-Path $script:LogDir 'pktmon-convert.log')
    if ($pktmonConvertExit -ne 0) {
        throw ('pktmon conversion failed with exit code ' +
            $pktmonConvertExit)
    }
    $verificationExit = Invoke-NativeCaptured {
        & $script:VenvPython `
            (Join-Path $PSScriptRoot 'verify_process_redirect.py') `
            --pcap $pcapng --original $reviewedA --target $reviewedB `
            --port $sentinelPort --log $fakeErr --target-client-log `
            (Join-Path $script:LogDir 'target-positive.jsonl') `
            --negative-client-log `
            (Join-Path $script:LogDir 'non-target-negative.jsonl') `
            --owner-client-log `
            (Join-Path $script:LogDir 'owner-gate-10000.jsonl') `
            --burst-client-log (Join-Path $script:LogDir 'burst-64.jsonl')
    } (Join-Path $script:LogDir 'verification.log')
    if ($verificationExit -ne 0) {
        throw ('Automated wire/log verification failed with exit code ' +
            $verificationExit)
    }
    Add-Result WireVerification PASS 'B observed; A absent; mapping/owner evidence present'
    $rawPcap = @(Get-ChildItem -LiteralPath $script:LogDir `
        -Filter 'process_redirect_packets_*.pcap' |
        Where-Object Name -NotLike '*-converted.pcap')
    if ($rawPcap.Count -ne 1) { throw 'Expected exactly one raw FakeNet PCAP.' }
    $convertedPcap = Join-Path $script:LogDir (
        $rawPcap[0].BaseName + '-converted.pcap')
    $dualPcapExit = Invoke-NativeCaptured {
        & $script:VenvPython (Join-Path $root `
            'test\dual_pcap_vm\verify_dual_pcap.py') `
            $rawPcap[0].FullName $convertedPcap --minimum-records 10 `
            --expected-versions 4 --output `
            (Join-Path $script:LogDir 'dual-pcap-verification.json')
    } (Join-Path $script:LogDir 'dual-pcap-command.log')
    if ($dualPcapExit -ne 0) {
        throw ('Raw/converted FakeNet PCAP verification failed with exit code ' +
            $dualPcapExit)
    }
    Add-Result DualPcapVerification PASS 'raw and converted policy views are synchronized'
    Start-Sleep -Seconds 2
    $afterDns = Get-DnsSnapshot
    $afterDns | Set-Content -LiteralPath (
        Join-Path $script:LogDir 'dns-after.txt') -Encoding utf8
    if ((Compare-Object $script:OriginalDns $afterDns)) {
        throw 'DNS restoration mismatch.'
    }
    Add-Result DnsRestoration PASS 'before/after snapshots match'
    $script:ExitCode = 0
} catch {
    Add-Result Runner FAIL ($_.Exception.Message.Replace("`t",' '))
    $_ | Format-List * -Force | Out-File (
        Join-Path $script:LogDir 'runner-error.log') -Encoding utf8
} finally {
    $clientsStopped = $false
    try { Stop-TrackedClientProcesses } catch {
        Add-Result Cleanup FAIL ('target client stop: ' + $_.Exception.Message)
        $script:ExitCode = 1
    }
    if (@($script:ClientProcesses | Where-Object {
                -not $_.Process.HasExited }).Count -eq 0) {
        $clientsStopped = $true
    }
    if ($clientsStopped) {
        try { Stop-FakeNet $root } catch {
            Add-Result Cleanup FAIL ('FakeNet stop: ' + $_.Exception.Message)
        }
    } else {
        Add-Result Cleanup FAIL (
            'FakeNet left running because a target client is still active; ' +
            'stop that client before stopping FakeNet/WinDivert')
        $script:ExitCode = 1
    }
    if ($script:PktmonStarted) {
        try {
            $finalPktmonExit = Invoke-NativeCaptured {
                & pktmon.exe stop
            } (Join-Path $script:LogDir 'pktmon-stop-finally.log')
            if ($finalPktmonExit -ne 0) {
                Add-Result Cleanup FAIL (
                    'pktmon final stop exit=' + $finalPktmonExit)
                $script:ExitCode = 1
            }
        } catch {
            Add-Result Cleanup FAIL (
                'pktmon final stop: ' + $_.Exception.Message)
            $script:ExitCode = 1
        }
        $script:PktmonStarted = $false
    }
    try {
        $finalDns = Get-DnsSnapshot
        $finalDns | Set-Content -LiteralPath (
            Join-Path $script:LogDir 'dns-final.txt') -Encoding utf8
        if (Compare-Object $script:OriginalDns $finalDns) {
            Add-Result Cleanup FAIL 'DNS final snapshot differs from pre-test state'
            $script:ExitCode = 1
        }
    } catch {
        Add-Result Cleanup FAIL ('DNS check: ' + $_.Exception.Message)
        $script:ExitCode = 1
    }
    Write-Host ('Plain logs available at: ' + $script:LogDir)
}
exit $script:ExitCode
