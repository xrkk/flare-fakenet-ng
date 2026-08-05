[CmdletBinding()]
param(
    [string]$PythonPath = 'python.exe',
    [ValidateSet('baidu_tcp443')]
    [string]$Profile = 'baidu_tcp443'
)

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

function Test-ReviewedGlobalIPv4 {
    param([string]$Value)
    $address = $null
    if (-not [Net.IPAddress]::TryParse($Value, [ref]$address) -or
            $address.AddressFamily -ne
                [Net.Sockets.AddressFamily]::InterNetwork -or
            $address.ToString() -ne $Value) {
        return $false
    }
    $b = $address.GetAddressBytes()
    if ($b[0] -eq 0 -or $b[0] -eq 10 -or $b[0] -eq 127 -or
            $b[0] -ge 224 -or
            ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) -or
            ($b[0] -eq 169 -and $b[1] -eq 254) -or
            ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or
            ($b[0] -eq 192 -and $b[1] -eq 168) -or
            ($b[0] -eq 192 -and $b[1] -eq 0 -and $b[2] -in @(0, 2)) -or
            ($b[0] -eq 192 -and $b[1] -eq 88 -and $b[2] -eq 99) -or
            ($b[0] -eq 198 -and $b[1] -in @(18, 19)) -or
            ($b[0] -eq 198 -and $b[1] -eq 51 -and $b[2] -eq 100) -or
            ($b[0] -eq 203 -and $b[1] -eq 0 -and $b[2] -eq 113)) {
        return $false
    }
    return $true
}

function Assert-ReviewedDnsFreshness {
    param(
        [string]$Hostname,
        [string]$Target,
        [string]$Resolver,
        [string]$LogPath
    )
    if ($Hostname -ne 'www.baidu.com' -or
            -not (Test-ReviewedGlobalIPv4 $Target)) {
        throw 'Reviewed DNS freshness inputs do not match the public contract.'
    }
    $records = @(Resolve-DnsName -Name $Hostname -Type A -Server $Resolver `
        -DnsOnly -ErrorAction Stop)
    @($records | ForEach-Object {
        'name={0} type={1} ip={2} cname={3} ttl={4}' -f
            $_.Name, $_.Type, $_.IPAddress, $_.NameHost, $_.TTL
    }) | Set-Content -LiteralPath $LogPath -Encoding UTF8
    $addresses = @($records | Where-Object {
            $_.Type -eq 'A' -and
            -not [string]::IsNullOrWhiteSpace([string]$_.IPAddress)
        } | ForEach-Object { [string]$_.IPAddress } | Select-Object -Unique)
    if ($Target -notin $addresses) {
        throw ('Reviewed IPv4 is no longer present in the current A set. ' +
            'No alternate address was selected.')
    }
    Write-Host (('IP_ALLOW_DNS_FRESHNESS_OK hostname={0} ip={1} ' +
        'resolver={2} addresses={3}') -f
        $Hostname, $Target, $Resolver, ($addresses -join ','))
    return $addresses
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
    if ($manifest.policy_version -ne 'v7' -or
            $manifest.plan_version -ne 'v5' -or
            $manifest.package_version -ne 'v13' -or
            ([string]$manifest.source_commit) -notmatch '^[0-9a-f]{40}$' -or
            $manifest.allowed_domain -ne 'api.deepseek.com' -or
            $manifest.reviewed_hostname -ne 'www.baidu.com' -or
            $manifest.reviewed_ipv4_target -ne '110.242.69.21' -or
            $manifest.negative_test_ipv4 -ne '110.242.70.57' -or
            $manifest.dns_freshness_required -ne $true -or
            @($manifest.reviewed_ipv4_profiles).Count -ne 1 -or
            [int]$manifest.reviewed_route_probe_udp_port -ne 9 -or
            [int]$manifest.address_refresh_seconds -ne 5 -or
            $manifest.windows_build -ne '10.0.19045' -or
            $manifest.python_version -ne '3.13.7' -or
            $manifest.python_architecture -ne 'AMD64') {
        throw 'The package manifest does not match reviewed v13 contracts.'
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

function Get-FakeNetStopReason {
    param($KeyInfo)
    if ($KeyInfo.Key -eq [ConsoleKey]::Enter) {
        return 'Enter'
    }
    $control = [ConsoleModifiers]::Control
    if ($KeyInfo.KeyChar -eq [char]3 -or
            ($KeyInfo.Key -eq [ConsoleKey]::C -and
            ($KeyInfo.Modifiers -band $control) -eq $control)) {
        return 'Ctrl+C'
    }
    return $null
}

function Get-ReviewedRulesValue {
    param([string]$Path)
    $section = ''
    $collecting = $false
    $occurrences = 0
    $parts = @()
    foreach ($line in Get-Content -LiteralPath $Path) {
        if ($line -match '^\s*\[([^]]+)\]\s*$') {
            $section = $matches[1]
            $collecting = $false
            continue
        }
        if ($section -ne 'Diverter') { continue }
        if ($line -match '^ExternalAllowedIPv4Rules\s*:\s*(.*)$') {
            $occurrences++
            $collecting = $true
            $parts += $matches[1]
            continue
        }
        if ($line -match '^\s*(TCP|UDP)/[^:=]*[:=]') {
            throw 'Reviewed IPv4 rule fragment was parsed as an INI option.'
        }
        if ($collecting) {
            if ($line -match '^[ \t]+(.+)$') {
                $value = $matches[1].Trim()
                if ($value -and -not $value.StartsWith('#') -and
                        -not $value.StartsWith(';')) {
                    $parts += $value
                }
                continue
            }
            $collecting = $false
        }
    }
    if ($occurrences -ne 1) {
        throw 'ExternalAllowedIPv4Rules must occur exactly once in v13.'
    }
    return ($parts -join ' ').Trim()
}

function Get-NormalizedReviewedRules {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw 'ExternalAllowedIPv4Rules is empty.'
    }
    $parts = @($Value.Split(','))
    if ($parts.Count -gt 32 -or @($parts | Where-Object {
                [string]::IsNullOrWhiteSpace($_)
            }).Count -ne 0) {
        throw 'ExternalAllowedIPv4Rules has an empty item or too many rules.'
    }
    $normalized = @()
    $scopes = @{}
    $ips = @{}
    foreach ($part in $parts) {
        $token = $part.Trim()
        if ($token -notmatch '^(TCP|UDP)/([^/]+)/(\*|[0-9]+)$') {
            throw "Invalid reviewed IPv4 rule: $token"
        }
        $protocol = $matches[1]
        $ipv4 = $matches[2]
        $port = $matches[3]
        $address = $null
        if (-not [Net.IPAddress]::TryParse($ipv4, [ref]$address) -or
                $address.AddressFamily -ne
                    [Net.Sockets.AddressFamily]::InterNetwork -or
                $address.ToString() -ne $ipv4 -or
                ($port -ne '*' -and
                    ([int64]$port -lt 1 -or [int64]$port -gt 65535))) {
            throw "Invalid reviewed IPv4 or port: $token"
        }
        if (-not (Test-ReviewedGlobalIPv4 $ipv4)) {
            throw "Reviewed IPv4 is not global unicast: $token"
        }
        $canonical = '{0}/{1}/{2}' -f $protocol, $ipv4, $port
        if ($normalized -contains $canonical) {
            throw "Duplicate reviewed IPv4 rule: $canonical"
        }
        $scopeKey = '{0}/{1}' -f $protocol, $ipv4
        if (-not $scopes.ContainsKey($scopeKey)) { $scopes[$scopeKey] = @() }
        if (($port -eq '*' -and $scopes[$scopeKey].Count -gt 0) -or
                ($port -ne '*' -and $scopes[$scopeKey] -contains '*')) {
            throw "Wildcard and exact reviewed rules conflict: $scopeKey"
        }
        $scopes[$scopeKey] += $port
        $ips[$ipv4] = $true
        $normalized += $canonical
    }
    if ($ips.Count -gt 16) {
        throw 'ExternalAllowedIPv4Rules exceeds 16 distinct IPv4 addresses.'
    }
    return @($normalized | Sort-Object)
}

function Get-TextSha256 {
    param([string]$Text)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::ASCII.GetBytes($Text)
        return ([BitConverter]::ToString(
            $algorithm.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $algorithm.Dispose()
    }
}

function Invoke-ReviewedRoutePreflight {
    param([string]$Root, [string[]]$Targets)
    $scriptPath = Join-Path $Root 'Test-ReviewedIPv4Routes.ps1'
    if (-not (Test-Path -LiteralPath $scriptPath)) {
        throw 'Reviewed IPv4 route checker is missing.'
    }
    $targetJson = ConvertTo-Json @($Targets) -Compress
    $encoded = [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes($targetJson))
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = 'powershell.exe'
    $startInfo.Arguments = ('-NoLogo -NoProfile -NonInteractive ' +
        '-ExecutionPolicy Bypass -File "{0}" -TargetsBase64 {1}' -f
        $scriptPath, $encoded)
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            throw 'Unable to start reviewed IPv4 route checker.'
        }
        if (-not $process.WaitForExit(2000)) {
            try { $process.Kill() } catch {}
            throw 'Reviewed IPv4 batch route query exceeded 2 seconds.'
        }
        $stdout = $process.StandardOutput.ReadToEnd().Trim()
        $stderr = $process.StandardError.ReadToEnd().Trim()
        if ($process.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($stdout)) {
            throw ('Reviewed IPv4 route preflight failed: {0}' -f
                $(if ($stderr) { $stderr } else { 'no output' }))
        }
        $snapshots = @($stdout | ConvertFrom-Json)
        $observed = @($snapshots | ForEach-Object {
            [string]$_.target_ipv4
        } | Sort-Object)
        if (($observed -join ',') -ne (@($Targets | Sort-Object) -join ',')) {
            throw 'Reviewed IPv4 route snapshots do not match manifest targets.'
        }
        return $snapshots
    } finally {
        $process.Dispose()
    }
}

function Read-FakeNetStopReason {
    if (-not [Console]::KeyAvailable) {
        return $null
    }
    return Get-FakeNetStopReason ([Console]::ReadKey($true))
}

function Show-FakeNetLogUntilStop {
    param(
        $Process,
        [string]$Path,
        [string]$StopFlag,
        [scriptblock]$StopRequestReader = $null
    )
    $stream = $null
    $reader = $null
    $stopRequested = $false
    $usesConsoleReader = $null -eq $StopRequestReader
    $controlModeChanged = $false
    $originalControlMode = $false
    try {
        if ($usesConsoleReader) {
            $originalControlMode = [Console]::TreatControlCAsInput
            [Console]::TreatControlCAsInput = $true
            $controlModeChanged = $true
        }
        $stream = [IO.File]::Open(
            $Path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
            [IO.FileShare]::ReadWrite)
        $reader = [IO.StreamReader]::new(
            $stream, [Text.Encoding]::Default)
        $drainAvailableLog = {
            while ($true) {
                while ($reader.Peek() -ge 0) {
                    Write-Host $reader.ReadLine()
                }
                # StreamReader can cache EOF while FakeNet still owns and
                # grows the shared file.  Re-seek only after its current
                # character buffer is empty, then check for newly appended
                # bytes without skipping already buffered lines.
                $position = $reader.BaseStream.Position
                $reader.DiscardBufferedData()
                $null = $reader.BaseStream.Seek(
                    $position, [IO.SeekOrigin]::Begin)
                if ($reader.Peek() -lt 0) {
                    break
                }
            }
        }
        Write-Host ''
        Write-Host ('----- FakeNet-NG live log ' +
            '(press Ctrl+C or Enter to stop safely) -----')
        while ($true) {
            & $drainAvailableLog
            $Process.Refresh()
            if ($Process.HasExited) {
                Start-Sleep -Milliseconds 100
                & $drainAvailableLog
                return $stopRequested
            }
            if (-not $stopRequested) {
                $stopReason = if ($usesConsoleReader) {
                    Read-FakeNetStopReason
                } else {
                    & $StopRequestReader
                }
                if ($stopReason) {
                    $stopRequested = $true
                    Write-Host (('Safe stop requested by {0}; ' +
                        'draining FakeNet-NG shutdown logs...') -f
                        $stopReason)
                    Set-Content -LiteralPath $StopFlag -Value 'stop' `
                        -Encoding ASCII
                }
            }
            Start-Sleep -Milliseconds 200
        }
    } finally {
        if ($controlModeChanged) {
            [Console]::TreatControlCAsInput = $originalControlMode
        }
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
    $arguments += @('-Profile', $Profile)
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
    $script:LockPath = Join-Path $logRoot 'reviewed-ipv4-start.lock'
    try {
        $script:LockStream = [IO.File]::Open(
            $script:LockPath, [IO.FileMode]::OpenOrCreate,
            [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        $script:LockOwned = $true
    } catch {
        throw 'Another reviewed-IPv4 launcher is already running.'
    }

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $script:LogDir = Join-Path $logRoot (
        'reviewed-ipv4-{0}-{1}' -f $Profile, $stamp)
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

    $profileContract = @($manifest.reviewed_ipv4_profiles |
        Where-Object { [string]$_.name -eq $Profile })
    if ($profileContract.Count -ne 1) {
        throw "Manifest profile is missing or duplicated: $Profile"
    }
    $profileContract = $profileContract[0]
    $template = Join-Path $repoRoot (
        ([string]$profileContract.config_path).Replace('/', '\'))
    $templateHash = (Get-FileHash -LiteralPath $template -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($templateHash -ne
            ([string]$profileContract.config_sha256).ToLowerInvariant()) {
        throw 'The reviewed IPv4 profile hash does not match the manifest.'
    }
    $reviewedRulesRaw = Get-ReviewedRulesValue $template
    $reviewedRules = @(Get-NormalizedReviewedRules $reviewedRulesRaw)
    if ($reviewedRulesRaw -ne [string]$profileContract.rules_raw) {
        throw 'The exact reviewed IPv4 rule text does not match the manifest.'
    }
    $manifestRules = @($profileContract.rules | ForEach-Object {
        [string]$_
    })
    if (($reviewedRules -join ',') -ne ($manifestRules -join ',')) {
        throw 'The active reviewed IPv4 rules do not match the manifest.'
    }
    $reviewedRulesHash = Get-TextSha256 ($reviewedRules -join ',')
    if ($reviewedRulesHash -ne
            ([string]$profileContract.rules_sha256).ToLowerInvariant()) {
        throw 'The normalized reviewed IPv4 rule hash does not match manifest.'
    }
    $expectedRuleIds = @($reviewedRules | ForEach-Object {
        (Get-TextSha256 $_).Substring(0, 16)
    })
    $manifestRuleIds = @($profileContract.rule_ids | ForEach-Object {
        [string]$_
    })
    if (($expectedRuleIds -join ',') -ne ($manifestRuleIds -join ',')) {
        throw 'The reviewed IPv4 rule IDs do not match normalized rules.'
    }
    if ($reviewedRules.Count -ne 1 -or
            $reviewedRules[0] -ne 'TCP/110.242.69.21/443') {
        throw 'The v13 activity profile must contain only TCP/110.242.69.21/443.'
    }
    $reviewedTargetsFromRules = @($reviewedRules | ForEach-Object {
        $_.Split('/')[1]
    } | Select-Object -Unique)
    if (($reviewedTargetsFromRules -join ',') -ne '110.242.69.21') {
        throw 'The reviewed profile must target only 110.242.69.21.'
    }
    $sourceTemplateText = Get-Content -LiteralPath $template -Raw
    if ($sourceTemplateText -match '(?m)^ExternalTakeover' -or
            $sourceTemplateText -match
                '(?m)^ResponseA\s*:\s*192\.168\.204\.1\s*$') {
        throw 'Reviewed profile contains takeover fields or sink DNS answers.'
    }

    $selection = Select-OriginalDnsServer
    $resolver = [string]$selection.Address
    $localIPv4 = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
        Select-Object -ExpandProperty IPAddress)
    if ($resolver -in @('110.242.69.21', '110.242.70.57') -or
            '110.242.69.21' -in $localIPv4 -or
            '110.242.70.57' -in $localIPv4) {
        throw 'Reviewed or negative-test IPv4 conflicts with VM local/DNS state.'
    }
    Write-Host ('Using pre-start DNS: {0} ({1})' -f
        $resolver, $selection.InterfaceAlias) -ForegroundColor Cyan
    Assert-ReviewedDnsFreshness -Hostname $manifest.reviewed_hostname `
        -Target $manifest.reviewed_ipv4_target -Resolver $resolver `
        -LogPath (Join-Path $script:LogDir 'reviewed-dns-freshness.log') |
        Out-Null

    $reviewedTargets = @($reviewedTargetsFromRules | Sort-Object)
    $reviewedRoutes = @(
        Invoke-ReviewedRoutePreflight $repoRoot $reviewedTargets)
    $reviewedRouteLines = @()
    foreach ($snapshot in $reviewedRoutes) {
        $line = ('IP_ALLOW_ROUTE_OK rule_ip={0} interface_index={1} ' +
            'interface_alias={2} source_ipv4={3} destination_prefix={4} ' +
            'next_hop={5} route_metric={6} interface_metric={7}') -f
            $snapshot.target_ipv4, $snapshot.interface_index,
            $snapshot.interface_alias, $snapshot.source_ipv4,
            $snapshot.destination_prefix, $snapshot.next_hop,
            $snapshot.route_metric, $snapshot.interface_metric
        $reviewedRouteLines += $line
        Write-Host $line -ForegroundColor Cyan
    }
    $reviewedRouteLines | Set-Content -LiteralPath (
        Join-Path $script:LogDir 'reviewed-ip-routes.log') -Encoding UTF8
    for ($index = 0; $index -lt $reviewedRules.Count; $index++) {
        if ($reviewedRules[$index].EndsWith('/*')) {
            Write-Host (('IP_ALLOW_RISK_ACK rule_id={0} ' +
                'risk=all_ports_includes_dns_proxy_tunnel') -f
                $expectedRuleIds[$index]) -ForegroundColor Yellow
        }
    }

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

    $venvRoot = Join-Path $repoRoot '.venv-reviewed-ipv4'
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

    $runtimeConfig = Join-Path $script:LogDir (
        'domain_reviewed_ipv4_{0}_runtime.ini' -f $Profile)
    $templateText = Get-Content -LiteralPath $template -Raw
    if (([regex]::Matches($templateText,
                [regex]::Escape('__EXTERNAL_DNS__'))).Count -ne 1) {
        throw 'The reviewed configuration has an invalid DNS marker count.'
    }
    $templateText.Replace('__EXTERNAL_DNS__', $resolver) |
        Set-Content -LiteralPath $runtimeConfig -Encoding ASCII

    $manifestLine = ('IP_ALLOW_POLICY_MANIFEST policy_version={0} ' +
        'profile={1} config_sha256={2} source_commit={3} os_build={4} ' +
        'python={5} pydivert=2.1.0 ' +
        'netifaces_dist=netifaces-plus==0.12.5') -f
        $manifest.policy_version, $Profile, $profileContract.config_sha256,
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
    Write-Host ('Starting reviewed public IPv4 policy: {0}.' -f $Profile)
    Write-Host 'Real egress: api.deepseek.com TCP/443 exact TLS SNI.'
    Write-Host ('Reviewed direct target: 110.242.69.21 TCP/443 ' +
        '(www.baidu.com); takeover is disabled.')
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
                (Select-String -LiteralPath $fakeLog -Pattern 'IP_ALLOW_READY' -Quiet)) {
            $ready = $true
            break
        }
    }
    if (-not $ready) {
        throw ('FakeNet-NG exited early or did not become ready within ' +
            '30 seconds.')
    }
    if (Select-String -LiteralPath $fakeLog `
            -Pattern 'DOMAIN_TAKEOVER_READY|ALLOW_TAKEOVER_SINK' -Quiet) {
        throw 'Takeover event appeared in the reviewed-IP profile.'
    }

    Write-Host 'FakeNet-NG is READY. Generate reviewed public-IP traffic now.'
    $stopRequested = Show-FakeNetLogUntilStop `
        -Process $script:FakeNetProcess -Path $fakeLog `
        -StopFlag $script:StopFlag
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
