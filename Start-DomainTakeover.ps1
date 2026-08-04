[CmdletBinding()]
param([string]$PythonPath = 'python.exe')

$ErrorActionPreference = 'Stop'
$script:ExitCode = 1
$script:LogDir = $null
$script:TranscriptStarted = $false
$script:OriginalDnsSnapshot = @()
$script:NetworkSnapshotTaken = $false
$script:LockStream = $null
$script:LockPath = $null
$script:LockOwned = $false
$script:FakeNetProcess = $null
$script:StopFlag = $null

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $administrator = [Security.Principal.WindowsBuiltInRole]::Administrator
    return $principal.IsInRole($administrator)
}

function Test-IsVirtualMachine {
    $system = Get-CimInstance Win32_ComputerSystem
    $identity = ('{0} {1}' -f $system.Manufacturer, $system.Model).ToLowerInvariant()
    return ($identity -match
        'virtual|vmware|virtualbox|kvm|qemu|hyper-v|xen|parallels')
}

function Resolve-RepositoryRoot {
    $candidates = @(
        $PSScriptRoot,
        (Join-Path $PSScriptRoot 'flare-fakenet-ng'),
        (Join-Path $PSScriptRoot '..\..')
    )
    foreach ($candidate in $candidates) {
        $resolved = Resolve-Path -LiteralPath $candidate -ErrorAction SilentlyContinue
        $fakeNetEntry = if ($resolved) {
            Join-Path $resolved.Path 'fakenet\fakenet.py'
        } else {
            $null
        }
        if ($resolved -and (Test-Path -LiteralPath $fakeNetEntry)) {
            return $resolved.Path
        }
    }
    throw 'Cannot locate the flare-fakenet-ng repository.'
}

function Get-DnsSnapshot {
    return @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |
        Sort-Object InterfaceIndex |
        ForEach-Object {
            '{0}|{1}' -f $_.InterfaceIndex, (@($_.ServerAddresses) -join ',')
        })
}

function Select-OriginalDnsServer {
    $local = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
        Select-Object -ExpandProperty IPAddress)
    $interfaces = @{}
    Get-NetIPInterface -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object ConnectionState -eq 'Connected' |
        ForEach-Object { $interfaces[$_.InterfaceIndex] = $_ }
    $routeArguments = @{
        AddressFamily = 'IPv4'
        DestinationPrefix = '0.0.0.0/0'
        ErrorAction = 'Stop'
    }
    $routes = @(Get-NetRoute @routeArguments |
        Where-Object { $interfaces.ContainsKey($_.InterfaceIndex) } |
        Sort-Object @{Expression = {
            $_.RouteMetric + $interfaces[$_.InterfaceIndex].InterfaceMetric
        }}, InterfaceIndex)

    foreach ($route in $routes) {
        $dnsArguments = @{
            AddressFamily = 'IPv4'
            InterfaceIndex = $route.InterfaceIndex
            ErrorAction = 'Stop'
        }
        $dns = Get-DnsClientServerAddress @dnsArguments
        foreach ($candidate in @($dns.ServerAddresses)) {
            $candidate = [string]$candidate
            $parsed = $null
            if (-not [Net.IPAddress]::TryParse($candidate, [ref]$parsed) -or
                    $parsed.AddressFamily -ne
                    [Net.Sockets.AddressFamily]::InterNetwork) {
                continue
            }
            $octets = $parsed.GetAddressBytes()
            $invalid = ($candidate -in $local -or
                [Net.IPAddress]::IsLoopback($parsed) -or
                $candidate -eq '0.0.0.0' -or
                $candidate -eq '255.255.255.255' -or
                ($octets[0] -eq 169 -and $octets[1] -eq 254) -or
                ($octets[0] -ge 224 -and $octets[0] -le 239))
            if (-not $invalid) {
                return [PSCustomObject]@{
                    InterfaceAlias =
                        $interfaces[$route.InterfaceIndex].InterfaceAlias
                    Address = $candidate
                }
            }
        }
    }
    throw ('No usable IPv4 DNS server exists on a connected ' +
        'default-route interface. No fallback DNS was selected.')
}

function Test-IPv4PrefixContains {
    param([string]$Address, [string]$Prefix)
    $parts = $Prefix.Split('/')
    if ($parts.Count -ne 2) { return $false }
    $length = [int]$parts[1]
    if ($length -lt 0 -or $length -gt 32) { return $false }
    $addressBytes = ([Net.IPAddress]::Parse($Address)).GetAddressBytes()
    $networkBytes = ([Net.IPAddress]::Parse($parts[0])).GetAddressBytes()
    $whole = [Math]::Floor($length / 8)
    for ($index = 0; $index -lt $whole; $index++) {
        if ($addressBytes[$index] -ne $networkBytes[$index]) {
            return $false
        }
    }
    $remainder = $length % 8
    if ($remainder -eq 0) { return $true }
    $mask = [int](256 - [Math]::Pow(2, 8 - $remainder))
    return (($addressBytes[$whole] -band $mask) -eq
        ($networkBytes[$whole] -band $mask))
}

function Get-TakeoverRouteSnapshot {
    param([string]$Target)
    $interfaces = @{}
    Get-NetIPInterface -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object ConnectionState -eq 'Connected' |
        ForEach-Object { $interfaces[[int]$_.InterfaceIndex] = $_ }

    $routeArguments = @{
        AddressFamily = 'IPv4'
        PolicyStore = 'ActiveStore'
        ErrorAction = 'Stop'
    }
    $matches = @(
        Get-NetRoute @routeArguments |
            ForEach-Object {
                $index = [int]$_.InterfaceIndex
                $containsTarget = Test-IPv4PrefixContains $Target $_.DestinationPrefix
                if ($interfaces.ContainsKey($index) -and $containsTarget) {
                    [PSCustomObject]@{
                        Route = $_
                        PrefixLength =
                            [int]$_.DestinationPrefix.Split('/')[1]
                        TotalMetric = [uint64]$_.RouteMetric +
                            [uint64]$interfaces[$index].InterfaceMetric
                    }
                }
            }
    )
    if ($matches.Count -eq 0) {
        throw 'No active route contains the takeover target.'
    }
    $bestPrefix = ($matches | Measure-Object PrefixLength -Maximum).Maximum
    $prefixMatches = @($matches |
        Where-Object PrefixLength -eq $bestPrefix)
    $bestMetric = ($prefixMatches |
        Measure-Object TotalMetric -Minimum).Minimum
    $best = @($prefixMatches | Where-Object TotalMetric -eq $bestMetric)
    if ($best.Count -ne 1) {
        throw 'The effective takeover route is ambiguous.'
    }

    $selected = $best[0]
    $route = $selected.Route
    if ($selected.PrefixLength -eq 0) {
        throw 'The takeover target must not use the default route.'
    }
    if ([string]$route.NextHop -ne '0.0.0.0') {
        throw 'The takeover target must use an on-link route.'
    }

    $sourceAddresses = @(
        Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $route.InterfaceIndex -ErrorAction Stop |
            Where-Object {
                $_.AddressState -eq 'Preferred' -and
                -not $_.SkipAsSource -and
                [string]$_.IPAddress -ne $Target
            } | Select-Object -ExpandProperty IPAddress
    )
    $socket = [Net.Sockets.Socket]::new(
        [Net.Sockets.AddressFamily]::InterNetwork,
        [Net.Sockets.SocketType]::Dgram,
        [Net.Sockets.ProtocolType]::Udp)
    try {
        $socket.Connect([Net.IPAddress]::Parse($Target), 9)
        $source = [string]$socket.LocalEndPoint.Address
    } finally {
        $socket.Dispose()
    }
    if ($source -notin $sourceAddresses) {
        throw ('Windows selected a source address outside the ' +
            'best-route interface.')
    }

    return [PSCustomObject]@{
        interface_index = [int]$route.InterfaceIndex
        interface_alias =
            [string]$interfaces[[int]$route.InterfaceIndex].InterfaceAlias
        source_ipv4 = $source
        destination_prefix = [string]$route.DestinationPrefix
        next_hop = [string]$route.NextHop
        route_metric = [uint64]$route.RouteMetric
        interface_metric =
            [uint64]$interfaces[[int]$route.InterfaceIndex].InterfaceMetric
    }
}

function Get-IniValue {
    param([string]$Path, [string]$Key)
    $pattern = '^\s*{0}\s*:\s*(.*?)\s*$' -f [regex]::Escape($Key)
    $matches = @(Select-String -LiteralPath $Path -Pattern $pattern)
    if ($matches.Count -ne 1) {
        throw "Configuration key must occur exactly once: $Key"
    }
    return [string]$matches[0].Matches[0].Groups[1].Value
}

function Read-AndVerifyManifest {
    param([string]$Root)
    $path = Join-Path $Root 'domain-takeover-manifest.json'
    if (-not (Test-Path -LiteralPath $path)) {
        throw 'The reviewed package manifest is missing.'
    }
    $manifest = Get-Content -LiteralPath $path -Raw -Encoding UTF8 |
        ConvertFrom-Json
    if ($manifest.policy_version -ne 'v5' -or
            ([string]$manifest.source_commit) -notmatch '^[0-9a-f]{40}$' -or
            $manifest.allowed_domain -ne 'api.deepseek.com' -or
            $manifest.takeover_ipv4 -ne '192.168.204.1' -or
            [int]$manifest.takeover_dns_ttl -ne 60 -or
            $manifest.windows_build -ne '10.0.19045' -or
            $manifest.python_version -ne '3.13.7' -or
            $manifest.python_architecture -ne 'AMD64') {
        throw 'The package manifest does not match reviewed v5.'
    }

    $rootPath = (Resolve-Path -LiteralPath $Root).Path
    foreach ($entry in @($manifest.files)) {
        $entryPath = [string]$entry.path
        if ([string]::IsNullOrWhiteSpace($entryPath)) {
            throw 'Manifest contains an empty file path.'
        }
        $candidate = Join-Path $rootPath $entryPath
        $resolvedItem = Resolve-Path -LiteralPath $candidate -ErrorAction Stop
        if ($null -eq $resolvedItem -or
                [string]::IsNullOrWhiteSpace([string]$resolvedItem.Path)) {
            throw "Manifest file path cannot be resolved: $entryPath"
        }
        $resolved = [string]$resolvedItem.Path
        if (-not $resolved.StartsWith(
                $rootPath + [IO.Path]::DirectorySeparatorChar,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw "Manifest path escapes package root: $entryPath"
        }
        $actual = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToLowerInvariant()
        $expected = [string]$entry.sha256
        if ($expected -notmatch '^[0-9a-f]{64}$') {
            throw "Manifest contains an invalid SHA-256: $entryPath"
        }
        if ($actual -ne $expected.ToLowerInvariant()) {
            throw "Manifest hash mismatch: $entryPath"
        }
    }
    return $manifest
}

function Invoke-NativeCaptured {
    param([scriptblock]$Command, [string]$Path)
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $records = @(& $Command 2>&1)
        $nativeExitCode = [int]$LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    $records | Out-File -LiteralPath $Path -Encoding UTF8
    return $nativeExitCode
}

function Invoke-TakeoverProbe {
    param(
        [string]$Target,
        [string]$PortsValue,
        [int]$TimeoutMs,
        [string]$LogPath
    )
    if ([string]::IsNullOrWhiteSpace($PortsValue)) {
        'TAKEOVER_PROBE_SKIP reason=not_configured' |
            Set-Content -LiteralPath $LogPath -Encoding UTF8
        Write-Host 'TAKEOVER_PROBE_SKIP reason=not_configured'
        return
    }
    $raw = $PortsValue.Split(',')
    if ($raw.Count -gt 64 -or
            @($raw | Where-Object {
                $_.Trim() -notmatch '^\d+$'
            }).Count -gt 0) {
        throw 'ExternalTakeoverProbeTCPPorts is invalid.'
    }
    $ports = @($raw | ForEach-Object { [int]$_.Trim() })
    if (@($ports | Where-Object {
                $_ -lt 1 -or $_ -gt 65535
            }).Count -or
            @($ports | Select-Object -Unique).Count -ne $ports.Count) {
        throw 'ExternalTakeoverProbeTCPPorts has invalid or duplicate ports.'
    }
    if ($TimeoutMs -lt 100 -or $TimeoutMs -gt 5000) {
        throw 'ExternalTakeoverProbeTimeoutMs is outside 100..5000.'
    }

    $results = @()
    foreach ($port in $ports) {
        $client = New-Object Net.Sockets.TcpClient
        $watch = [Diagnostics.Stopwatch]::StartNew()
        $status = 'ERROR'
        try {
            $address = [Net.IPAddress]::Parse($Target)
            $task = $client.ConnectAsync($address, $port)
            try {
                if (-not $task.Wait($TimeoutMs)) {
                    $client.Close()
                    $status = 'TIMEOUT'
                } elseif ($task.Status -eq
                        [Threading.Tasks.TaskStatus]::RanToCompletion) {
                    $status = 'OPEN'
                }
            } catch [AggregateException] {
                $inner = $_.Exception.Flatten().InnerExceptions |
                    Select-Object -First 1
                if ($inner -is [Net.Sockets.SocketException] -and
                        $inner.SocketErrorCode -eq
                        [Net.Sockets.SocketError]::ConnectionRefused) {
                    $status = 'CLOSED'
                }
            }
        } catch [Net.Sockets.SocketException] {
            if ($_.Exception.SocketErrorCode -eq
                    [Net.Sockets.SocketError]::ConnectionRefused) {
                $status = 'CLOSED'
            }
        } finally {
            $client.Close()
            $client.Dispose()
            $watch.Stop()
        }
        $line = ('TAKEOVER_PROBE_RESULT ip={0} port={1} ' +
            'status={2} elapsed_ms={3}') -f
            $Target, $port, $status, $watch.ElapsedMilliseconds
        $results += $line
        $color = if ($status -eq 'OPEN') { 'Green' } else { 'Yellow' }
        Write-Host $line -ForegroundColor $color
    }
    $results | Set-Content -LiteralPath $LogPath -Encoding UTF8
}

function Show-FakeNetLogUntilEnter {
    param([Diagnostics.Process]$Process, [string]$Path)
    $stream = $null
    $reader = $null
    try {
        $stream = [IO.File]::Open(
            $Path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
            [IO.FileShare]::ReadWrite)
        $reader = [IO.StreamReader]::new(
            $stream, [Text.Encoding]::Default)
        Write-Host ''
        Write-Host '----- FakeNet-NG live log (press Enter to stop) -----'
        while ($true) {
            while ($reader.Peek() -ge 0) {
                Write-Host $reader.ReadLine()
            }
            $Process.Refresh()
            if ($Process.HasExited) {
                Start-Sleep -Milliseconds 100
                while ($reader.Peek() -ge 0) {
                    Write-Host $reader.ReadLine()
                }
                return $false
            }
            if ([Console]::KeyAvailable) {
                $key = [Console]::ReadKey($true)
                if ($key.Key -eq [ConsoleKey]::Enter) {
                    return $true
                }
            }
            Start-Sleep -Milliseconds 200
        }
    } finally {
        if ($reader) {
            $reader.Dispose()
        } elseif ($stream) {
            $stream.Dispose()
        }
    }
}

$vmIdentity = Get-CimInstance Win32_ComputerSystem
if (-not (Test-IsVirtualMachine)) {
    Write-Error (('REFUSED: this machine does not identify as a VM ' +
        '({0} / {1}).') -f
        $vmIdentity.Manufacturer, $vmIdentity.Model)
    exit 40
}
if (-not (Test-IsAdministrator)) {
    $arguments = @('-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', ('"{0}"' -f $PSCommandPath))
    if ($PythonPath -ne 'python.exe') {
        $arguments += @('-PythonPath', ('"{0}"' -f $PythonPath))
    }
    $elevatedArguments = @{
        FilePath = 'powershell.exe'
        Verb = 'RunAs'
        Wait = $true
        PassThru = $true
        ArgumentList = $arguments
    }
    $elevated = Start-Process @elevatedArguments
    exit $elevated.ExitCode
}

try {
    $repoRoot = Resolve-RepositoryRoot
    $logRoot = Join-Path $repoRoot 'dist\Logs'
    New-Item -ItemType Directory -Path $logRoot -Force | Out-Null
    $script:LockPath = Join-Path $logRoot 'domain-takeover-start.lock'
    try {
        $script:LockStream = [IO.File]::Open(
            $script:LockPath, [IO.FileMode]::OpenOrCreate,
            [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        $script:LockOwned = $true
    } catch {
        throw 'Another domain-takeover launcher is already running.'
    }

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $script:LogDir = Join-Path $logRoot ('domain-takeover-start-{0}' -f $stamp)
    New-Item -ItemType Directory -Path $script:LogDir -Force | Out-Null
    $transcriptPath = Join-Path $script:LogDir 'launcher-transcript.log'
    Start-Transcript -LiteralPath $transcriptPath | Out-Null
    $script:TranscriptStarted = $true

    Get-NetIPAddress | Format-List * |
        Out-File (Join-Path $script:LogDir 'ip-before.txt')
    Get-NetRoute | Sort-Object AddressFamily, DestinationPrefix |
        Format-Table -AutoSize |
        Out-File (Join-Path $script:LogDir 'routes-before.txt')
    Get-DnsClientServerAddress | Format-List * |
        Out-File (Join-Path $script:LogDir 'dns-before.txt')
    $script:OriginalDnsSnapshot = Get-DnsSnapshot
    $script:NetworkSnapshotTaken = $true

    $manifest = Read-AndVerifyManifest $repoRoot
    $os = Get-CimInstance Win32_OperatingSystem
    if ([string]$os.Version -ne [string]$manifest.windows_build) {
        throw ('Windows build mismatch. Expected {0}; observed {1}.' -f
            $manifest.windows_build, $os.Version)
    }
    if (-not [Environment]::Is64BitOperatingSystem) {
        throw 'The reviewed package requires Windows x64.'
    }

    $template = Join-Path $repoRoot 'fakenet\configs\domain_takeover_windows.ini'
    $templateHash = (Get-FileHash -LiteralPath $template -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($templateHash -ne ([string]$manifest.config_sha256).ToLowerInvariant()) {
        throw 'The takeover INI hash does not match the reviewed manifest.'
    }
    if ((Get-IniValue $template 'ExternalTakeoverIPv4') -ne
            '192.168.204.1' -or
            [int](Get-IniValue $template 'ExternalTakeoverDnsTTL') -ne 60) {
        throw 'The takeover configuration does not match reviewed v5.'
    }
    $probePorts = Get-IniValue $template 'ExternalTakeoverProbeTCPPorts'
    $probeTimeoutText = Get-IniValue $template 'ExternalTakeoverProbeTimeoutMs'
    if ($probeTimeoutText -notmatch '^\d+$') {
        throw 'ExternalTakeoverProbeTimeoutMs is invalid.'
    }

    $selection = Select-OriginalDnsServer
    $resolver = [string]$selection.Address
    if ($resolver -eq '192.168.204.1') {
        throw 'The takeover target cannot equal the upstream DNS server.'
    }
    Write-Host ('Using pre-start DNS: {0} ({1})' -f
        $resolver, $selection.InterfaceAlias) -ForegroundColor Cyan

    $route = Get-TakeoverRouteSnapshot '192.168.204.1'
    $routeLine = ('TAKEOVER_ROUTE_OK interface_index={0} ' +
        'interface_alias={1} source_ipv4={2} destination_prefix={3} ' +
        'next_hop={4} route_metric={5} interface_metric={6}') -f
        $route.interface_index, $route.interface_alias,
        $route.source_ipv4, $route.destination_prefix, $route.next_hop,
        $route.route_metric, $route.interface_metric
    $routeLog = Join-Path $script:LogDir 'takeover-route.log'
    $routeLine | Set-Content -LiteralPath $routeLog -Encoding UTF8
    Write-Host $routeLine -ForegroundColor Cyan

    $probeArguments = @{
        Target = '192.168.204.1'
        PortsValue = $probePorts
        TimeoutMs = [int]$probeTimeoutText
        LogPath = Join-Path $script:LogDir 'takeover-probe.log'
    }
    Invoke-TakeoverProbe @probeArguments

    $systemPython = (Get-Command $PythonPath -ErrorAction Stop).Source
    # Send dynamic Python source through stdin. Windows PowerShell 5.1 can
    # strip embedded double quotes while rebuilding native command lines.
    $identityCommand = "import json,platform,sys; print(json.dumps({'version':'.'.join(map(str,sys.version_info[:3])),'machine':platform.machine()}))"
    $identityLog = Join-Path $script:LogDir 'python-identity.log'
    $identityExit = Invoke-NativeCaptured {
        $identityCommand | & $systemPython -
    } $identityLog
    if ($identityExit -ne 0) {
        throw ('Unable to inspect the configured Python interpreter. See {0}.' -f
            $identityLog)
    }
    try {
        $identity = (Get-Content -Raw -LiteralPath $identityLog).Trim() |
            ConvertFrom-Json
    } catch {
        throw ('Python identity output is invalid. See {0}.' -f $identityLog)
    }
    if ($identity.version -ne $manifest.python_version -or
            $identity.machine.ToUpperInvariant() -ne
                $manifest.python_architecture) {
        throw ('Python mismatch. Expected {0}/{1}; observed {2}/{3}.' -f
            $manifest.python_version, $manifest.python_architecture,
            $identity.version, $identity.machine)
    }

    $venvRoot = Join-Path $repoRoot '.venv-domain-takeover'
    $venvPython = Join-Path $venvRoot 'Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $venvPython)) {
        $venvLog = Join-Path $script:LogDir 'venv-create.log'
        $venvExit = Invoke-NativeCaptured {
            & $systemPython -m venv $venvRoot
        } $venvLog
        if ($venvExit -ne 0 -or
                -not (Test-Path -LiteralPath $venvPython)) {
            throw 'Failed to create the package-local Python environment.'
        }
    }

    $wheelhouse = Join-Path $repoRoot 'wheelhouse'
    $lock = Join-Path $repoRoot 'requirements-domain-takeover-windows.lock'
    $installLog = Join-Path $script:LogDir 'dependency-install.log'
    $installExit = Invoke-NativeCaptured {
        & $venvPython -m pip install --disable-pip-version-check --no-index --find-links $wheelhouse --require-hashes -r $lock
    } $installLog
    if ($installExit -ne 0) {
        throw ('Offline dependency installation failed. No dependency ' +
            'was downloaded from the network.')
    }

    $dependencyLog = Join-Path $script:LogDir 'dependency-check.log'
    $dependencyExit = Invoke-NativeCaptured {
        $dependencyCommand = ('import dpkt,dnslib,netifaces,pydivert,pyftpdlib,jinja2,' +
            'OpenSSL,cryptography; from importlib.metadata import version;' +
            'assert version("pydivert")=="2.1.0";' +
            'assert version("netifaces-plus")=="0.12.5";' +
            'assert callable(netifaces.interfaces);' +
            'assert callable(netifaces.ifaddresses)')
        $dependencyCommand | & $venvPython -
    } $dependencyLog
    if ($dependencyExit -ne 0) {
        throw 'The package-local dependency/API check failed.'
    }

    $runtimeConfig = Join-Path $script:LogDir 'domain_takeover_runtime.ini'
    $templateText = Get-Content -LiteralPath $template -Raw
    if (([regex]::Matches($templateText,
                [regex]::Escape('__EXTERNAL_DNS__'))).Count -ne 1) {
        throw 'The reviewed configuration has an invalid DNS marker count.'
    }
    $templateText.Replace('__EXTERNAL_DNS__', $resolver) |
        Set-Content -LiteralPath $runtimeConfig -Encoding ASCII

    $manifestLine = ('TAKEOVER_POLICY_MANIFEST policy_version={0} ' +
        'config_sha256={1} source_commit={2} os_build={3} ' +
        'python={4} pydivert=2.1.0 ' +
        'netifaces_dist=netifaces-plus==0.12.5') -f
        $manifest.policy_version, $manifest.config_sha256,
        $manifest.source_commit, $manifest.windows_build,
        $manifest.python_version
    $manifestLog = Join-Path $script:LogDir 'policy-manifest.log'
    $manifestLine | Set-Content -LiteralPath $manifestLog -Encoding UTF8
    Write-Host $manifestLine -ForegroundColor Cyan

    $fakeLog = Join-Path $script:LogDir 'fakenet.log'
    $stdoutLog = Join-Path $script:LogDir 'fakenet-stdout.log'
    $stderrLog = Join-Path $script:LogDir 'fakenet-stderr.log'
    $script:StopFlag = Join-Path $script:LogDir 'stop-fakenet.flag'

    Write-Host ''
    Write-Host 'Starting reviewed Windows domain takeover policy.'
    Write-Host 'Real egress: api.deepseek.com TCP/443 exact TLS SNI.'
    Write-Host ('Other DNS A answers: 192.168.204.1; ' +
        'sink TCP/UDP ports unchanged.')
    Write-Host ('Plain logs: {0}' -f $script:LogDir)
    Write-Host ''

    $arguments = @('-m', 'fakenet.fakenet', '-c',
        ('"{0}"' -f $runtimeConfig), '-l', ('"{0}"' -f $fakeLog),
        '-f', ('"{0}"' -f $script:StopFlag), '-p', '-v')
    $fakeNetStart = @{
        FilePath = $venvPython
        ArgumentList = $arguments
        WorkingDirectory = $repoRoot
        WindowStyle = 'Hidden'
        PassThru = $true
        RedirectStandardOutput = $stdoutLog
        RedirectStandardError = $stderrLog
    }
    $script:FakeNetProcess = Start-Process @fakeNetStart
    $script:FakeNetProcess.EnableRaisingEvents = $true
    $null = $script:FakeNetProcess.Handle

    $ready = $false
    for ($index = 0; $index -lt 30; $index++) {
        Start-Sleep -Seconds 1
        $script:FakeNetProcess.Refresh()
        if ($script:FakeNetProcess.HasExited) { break }
        if ((Test-Path -LiteralPath $fakeLog) -and
                (Select-String -LiteralPath $fakeLog -Pattern 'DOMAIN_TAKEOVER_READY' -Quiet)) {
            $ready = $true
            break
        }
    }
    if (-not $ready) {
        throw ('FakeNet-NG exited early or did not become ready within ' +
            '30 seconds.')
    }

    Write-Host 'FakeNet-NG is READY. Start or restart the analysis tool now.'
    Write-Host ('The tool must use system DNS and connect directly to ' +
        'https://api.deepseek.com without proxy or DoH.')
    $stopRequested = Show-FakeNetLogUntilEnter -Process $script:FakeNetProcess -Path $fakeLog
    if (-not $stopRequested) {
        throw 'FakeNet-NG exited before a safe stop was requested.'
    }
    $script:ExitCode = 0
} catch {
    $script:ExitCode = 1
    Write-Host ''
    Write-Host ('START/RUN FAILED: {0}' -f $_.Exception.Message)
    if ($script:LogDir) {
        $fatalLog = Join-Path $script:LogDir 'fatal-error.log'
        $_ | Format-List * -Force | Out-File $fatalLog
    }
} finally {
    if ($script:FakeNetProcess) {
        try {
            $script:FakeNetProcess.Refresh()
            if (-not $script:FakeNetProcess.HasExited) {
                Write-Host 'Stopping FakeNet-NG and restoring network state...'
                Set-Content -LiteralPath $script:StopFlag -Value 'stop' -Encoding ASCII
                $script:FakeNetProcess.WaitForExit()
            }
            $script:FakeNetProcess.Refresh()
            if ($script:FakeNetProcess.ExitCode -ne 0) {
                Write-Host ('FakeNet-NG exit code: {0}' -f
                    $script:FakeNetProcess.ExitCode)
                $script:ExitCode = 1
            }
        } catch {
            Write-Host ('Unable to confirm FakeNet-NG shutdown: {0}' -f
                $_.Exception.Message)
            $script:ExitCode = 1
        }
    }
    if ($script:NetworkSnapshotTaken) {
        try {
            Get-DnsClientServerAddress | Format-List * |
                Out-File (Join-Path $script:LogDir 'dns-after.txt')
            Get-NetIPAddress | Format-List * |
                Out-File (Join-Path $script:LogDir 'ip-after.txt')
            Get-NetRoute | Sort-Object AddressFamily, DestinationPrefix |
                Format-Table -AutoSize |
                Out-File (Join-Path $script:LogDir 'routes-after.txt')
            $restored = Get-DnsSnapshot
            $difference = @(Compare-Object $script:OriginalDnsSnapshot $restored)
            if ($difference.Count -eq 0) {
                Write-Host 'DNS restoration check: PASS'
            } else {
                $differenceLog = Join-Path $script:LogDir 'dns-restore-difference.txt'
                $difference | Format-Table -AutoSize | Out-File $differenceLog
                Write-Host ('DNS restoration check: FAIL. Disconnect the VM ' +
                    'and restore its snapshot before reconnecting.')
                $script:ExitCode = 1
            }
        } catch {
            Write-Host ('DNS restoration check failed: {0}' -f
                $_.Exception.Message)
            $script:ExitCode = 1
        }
    }
    if ($script:TranscriptStarted) {
        Stop-Transcript | Out-Null
    }
    if ($script:LockStream) {
        $script:LockStream.Dispose()
    }
    if ($script:LockOwned -and $script:LockPath -and
            (Test-Path -LiteralPath $script:LockPath)) {
        Remove-Item -LiteralPath $script:LockPath -Force
    }
    if ($script:LogDir) {
        Write-Host ('Plain logs available at: {0}' -f $script:LogDir)
    }
}
exit $script:ExitCode
