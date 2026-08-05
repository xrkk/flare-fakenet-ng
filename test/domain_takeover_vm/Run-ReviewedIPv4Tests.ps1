[CmdletBinding()]
param(
    [string]$PythonPath = "python.exe"
)

$ErrorActionPreference = 'Stop'
$script:ExitCode = 1
$script:FakeNetProcess = $null
$script:PktmonStarted = $false
$script:StopFlag = $null
$script:TranscriptStarted = $false
$script:OriginalDnsSnapshot = @()

function Add-Result {
    param([string]$Name, [string]$Status, [string]$Detail = "")
    $line = "{0}`t{1}`t{2}" -f $Status, $Name, $Detail
    Add-Content -LiteralPath $script:ResultFile -Value $line -Encoding UTF8
    Write-Host $line
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-IsVirtualMachine {
    $system = Get-CimInstance Win32_ComputerSystem
    $identity = ("{0} {1}" -f $system.Manufacturer, $system.Model).ToLowerInvariant()
    return $identity -match 'virtual|vmware|virtualbox|kvm|qemu|hyper-v|xen|parallels'
}

function Get-DnsSnapshot {
    return @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |
        Sort-Object InterfaceIndex |
        ForEach-Object {
            '{0}|{1}' -f $_.InterfaceIndex,
                (@($_.ServerAddresses) -join ',')
        })
}

function Resolve-RepositoryRoot {
    $bundled = Join-Path $PSScriptRoot 'flare-fakenet-ng'
    if (Test-Path -LiteralPath (Join-Path $bundled 'fakenet\fakenet.py')) {
        return (Resolve-Path -LiteralPath $bundled).Path
    }
    $source = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')
    if (Test-Path -LiteralPath (Join-Path $source 'fakenet\fakenet.py')) {
        return $source.Path
    }
    throw 'Cannot locate the bundled flare-fakenet-ng repository.'
}

function Select-OriginalDnsServer {
    $local = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
        Select-Object -ExpandProperty IPAddress)
    $interfaces = @{}
    Get-NetIPInterface -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object ConnectionState -eq 'Connected' |
        ForEach-Object { $interfaces[$_.InterfaceIndex] = $_ }
    $routes = @(Get-NetRoute -AddressFamily IPv4 `
            -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
        Where-Object { $interfaces.ContainsKey($_.InterfaceIndex) } |
        Sort-Object `
            @{Expression = {
                $_.RouteMetric + $interfaces[$_.InterfaceIndex].InterfaceMetric
            }}, InterfaceIndex)

    foreach ($route in $routes) {
        $dns = Get-DnsClientServerAddress -AddressFamily IPv4 `
            -InterfaceIndex $route.InterfaceIndex -ErrorAction Stop
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
                Add-Result 'DnsAutoSelection' 'PASS' (
                    'interface={0}; resolver={1}; source=pre-test VM configuration' -f
                    $interfaces[$route.InterfaceIndex].InterfaceAlias, $candidate)
                return [string]$candidate
            }
        }
    }
    throw 'No usable IPv4 DNS server exists on a connected default-route interface.'
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
    param([string]$Hostname, [string]$Target, [string]$Resolver)
    if ($Hostname -ne 'www.baidu.com' -or
            -not (Test-ReviewedGlobalIPv4 $Target)) {
        throw 'Reviewed DNS freshness inputs do not match the public contract.'
    }
    $records = @(Resolve-DnsName -Name $Hostname -Type A -Server $Resolver `
        -DnsOnly -ErrorAction Stop)
    @($records | ForEach-Object {
        'name={0} type={1} ip={2} cname={3} ttl={4}' -f
            $_.Name, $_.Type, $_.IPAddress, $_.NameHost, $_.TTL
    }) | Set-Content -LiteralPath (Join-Path $script:RunRoot `
        'reviewed-dns-freshness.log') -Encoding UTF8
    $addresses = @($records | Where-Object {
            $_.Type -eq 'A' -and
            -not [string]::IsNullOrWhiteSpace([string]$_.IPAddress)
        } | ForEach-Object { [string]$_.IPAddress } | Select-Object -Unique)
    if ($Target -notin $addresses) {
        throw ('Reviewed IPv4 is no longer present in the current A set. ' +
            'No alternate address was selected.')
    }
    Add-Result 'ReviewedDnsFreshness' 'PASS' (
        'hostname={0}; target={1}; resolver={2}; addresses={3}' -f
        $Hostname, $Target, $Resolver, ($addresses -join ','))
    return $addresses
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
            $manifest.package_version -ne 'v15' -or
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
        throw 'The package manifest does not match reviewed v15 contracts.'
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
        # Windows PowerShell 5.1 wraps native stderr as ErrorRecord objects. A
        # global Stop preference would otherwise turn normal unittest/curl
        # progress output into a terminating NativeCommandError.
        $ErrorActionPreference = 'Continue'
        $records = @(& $Command 2>&1)
        $nativeExitCode = [int]$LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    $records | Out-File -LiteralPath $Path -Encoding UTF8
    return $nativeExitCode
}

function Invoke-LoggedCommand {
    param(
        [string]$Name,
        [scriptblock]$Command,
        [switch]$RequireSuccess,
        [switch]$Native
    )
    $path = Join-Path $script:LogDir ($Name + '.log')
    try {
        if ($Native) {
            $commandExit = Invoke-NativeCaptured -Command $Command -Path $path
        } else {
            & $Command *>&1 | Out-File -LiteralPath $path -Encoding UTF8
            $commandExit = if ($?) { 0 } else { 1 }
        }
        if ($RequireSuccess -and $commandExit -ne 0) {
            throw "$Name failed with exit code $commandExit"
        }
        $status = if ($RequireSuccess) { 'PASS' } else { 'OBSERVED' }
        Add-Result $Name $status "exit=$commandExit; inspect capture and policy log"
    } catch {
        $_ | Out-File -LiteralPath $path -Encoding UTF8 -Append
        $status = if ($RequireSuccess) { 'FAIL' } else { 'OBSERVED' }
        Add-Result $Name $status "exception=$($_.Exception.GetType().Name); inspect capture and policy log"
        if ($RequireSuccess) { throw }
    }
}

function Test-ReviewedRuleMatch {
    param([string[]]$Rules, [string]$Protocol,
          [string]$Target, [int]$Port)
    foreach ($rule in $Rules) {
        $fields = $rule.Split('/')
        if ($fields.Count -eq 3 -and $fields[0] -eq $Protocol -and
                $fields[1] -eq $Target -and
                ($fields[2] -eq '*' -or [int]$fields[2] -eq $Port)) {
            return $true
        }
    }
    return $false
}

function Send-ReviewedMatrixPacket {
    param([string]$Protocol, [string]$Target, [int]$Port,
          [string]$Label)
    $line = $null
    if ($Protocol -eq 'TCP') {
        $client = [Net.Sockets.TcpClient]::new()
        try {
            $task = $client.ConnectAsync([Net.IPAddress]::Parse($Target), $Port)
            try { $null = $task.Wait(500) } catch {}
            $line = ('{0} proto=TCP ip={1} port={2} status={3}' -f
                $Label, $Target, $Port, $task.Status)
        } finally {
            $client.Close()
            $client.Dispose()
        }
    } else {
        $socket = [Net.Sockets.Socket]::new(
            [Net.Sockets.AddressFamily]::InterNetwork,
            [Net.Sockets.SocketType]::Dgram,
            [Net.Sockets.ProtocolType]::Udp)
        try {
            $payload = [Text.Encoding]::ASCII.GetBytes(
                'fakenet-reviewed-ip-v15')
            $sent = $socket.SendTo($payload,
                [Net.IPEndPoint]::new([Net.IPAddress]::Parse($Target), $Port))
            $line = ('{0} proto=UDP ip={1} port={2} bytes={3}' -f
                $Label, $Target, $Port, $sent)
        } finally {
            $socket.Close()
            $socket.Dispose()
        }
    }
    Add-Content -LiteralPath $script:ReviewedMatrixLog -Value $line `
        -Encoding UTF8
    Write-Host $line
}

function Invoke-ReviewedBaiduTls {
    param([string]$Target, [string]$Hostname)
    $baiduTlsCommand = @'
import json, socket, ssl, sys, time
target, hostname = sys.argv[1:3]
started = time.monotonic()
with socket.create_connection((target, 443), timeout=10) as raw:
    context = ssl.create_default_context()
    with context.wrap_socket(raw, server_hostname=hostname) as tls:
        certificate = tls.getpeercert()
        print(json.dumps({
            'target': target,
            'hostname': hostname,
            'tls_version': tls.version(),
            'cipher': tls.cipher()[0],
            'subject': certificate.get('subject'),
            'elapsed_ms': int((time.monotonic() - started) * 1000),
        }, sort_keys=True))
'@
    $log = Join-Path $script:LogDir 'baidu-tls-validation.log'
    $exitCode = Invoke-NativeCaptured {
        $baiduTlsCommand | & $script:Python - $Target $Hostname
    } $log
    if ($exitCode -ne 0) {
        throw 'Pinned Baidu TCP/TLS/SNI/certificate validation failed.'
    }
    Add-Content -LiteralPath $script:ReviewedMatrixLog `
        -Value ('POSITIVE_TLS proto=TCP ip={0} port=443 hostname={1}' -f
            $Target, $Hostname) -Encoding UTF8
    Add-Result 'BaiduTlsCertificate' 'PASS' (Get-Content $log -Raw).Trim()
}

function Invoke-ReviewedRuleMatrix {
    param([string]$Profile, [string[]]$Rules)
    $script:ReviewedMatrixLog = Join-Path $script:LogDir `
        'reviewed-ip-matrix.log'
    New-Item -ItemType File -Path $script:ReviewedMatrixLog -Force |
        Out-Null
    if ($Profile -ne 'baidu_tcp443' -or $Rules.Count -ne 1 -or
            $Rules[0] -ne 'TCP/110.242.69.21/443') {
        throw 'Reviewed v15 matrix/profile contract mismatch.'
    }
    Invoke-ReviewedBaiduTls -Target '110.242.69.21' `
        -Hostname 'www.baidu.com'
    foreach ($case in @(
            @('TCP', '110.242.69.21', 80),
            @('TCP', '110.242.69.21', 444),
            @('UDP', '110.242.69.21', 443),
            @('TCP', '110.242.70.57', 443))) {
        Send-ReviewedMatrixPacket -Protocol $case[0] `
            -Target $case[1] -Port $case[2] -Label 'NEGATIVE'
    }
    Add-Result 'ReviewedIPv4Matrix' 'OBSERVED' (
        'packet transmission attempted; use policy log and independent PCAPNG for verdict proof')
}

function Stop-TestComponents {
    if ($script:FakeNetProcess -and -not $script:FakeNetProcess.HasExited) {
        if ($script:StopFlag) {
            New-Item -ItemType File -Path $script:StopFlag -Force | Out-Null
        }
        if (-not $script:FakeNetProcess.WaitForExit(20000)) {
            Add-Result 'FakeNetStop' 'FAIL' 'graceful stop timed out; terminating process'
            $script:ExitCode = 1
            Stop-Process -Id $script:FakeNetProcess.Id -Force -ErrorAction SilentlyContinue
        } else {
            # Windows PowerShell 5.1 can leave ExitCode unpopulated for an
            # asynchronously started process until redirected streams finish
            # and the Process object refreshes.
            $script:FakeNetProcess.WaitForExit()
            $script:FakeNetProcess.Refresh()
            $processExitCode = $script:FakeNetProcess.ExitCode
            if ($null -eq $processExitCode) {
                Add-Result 'FakeNetStop' 'FAIL' 'process exited but exit code is unavailable'
                $script:ExitCode = 1
            } elseif ($processExitCode -ne 0) {
                Add-Result 'FakeNetStop' 'FAIL' ("exit={0}" -f $processExitCode)
                $script:ExitCode = 1
            } else {
                Add-Result 'FakeNetStop' 'PASS' 'graceful stop completed; exit=0'
            }
        }
    }
    if ($script:PktmonStarted) {
        $pktmonStopLog = Join-Path $script:LogDir 'pktmon-stop.log'
        $pktmonStopExit = Invoke-NativeCaptured {
            & pktmon.exe stop
        } $pktmonStopLog
        $script:PktmonStarted = $false
        if ($pktmonStopExit -ne 0) {
            Add-Result 'IndependentCaptureStop' 'FAIL' "pktmon exit=$pktmonStopExit"
            $script:ExitCode = 1
        }
        $etl = Join-Path $script:LogDir 'independent-capture.etl'
        $pcap = Join-Path $script:LogDir 'independent-capture.pcapng'
        if (Test-Path -LiteralPath $etl) {
            $pktmonConvertLog = Join-Path $script:LogDir 'pktmon-convert.log'
            $pktmonConvertExit = Invoke-NativeCaptured {
                & pktmon.exe etl2pcap $etl --out $pcap
            } $pktmonConvertLog
            if ($pktmonConvertExit -ne 0 -or -not (Test-Path -LiteralPath $pcap) -or
                    (Get-Item -LiteralPath $pcap).Length -eq 0) {
                Add-Result 'IndependentCaptureFile' 'FAIL' 'PCAPNG conversion failed or produced an empty file'
                $script:ExitCode = 1
            } else {
                Add-Result 'IndependentCaptureFile' 'PASS' $pcap
            }
        }
    }
}

function Get-NetworkState {
    return [PSCustomObject]@{
        Dns = @(Get-DnsSnapshot)
        Ip = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
            ForEach-Object { '{0}|{1}' -f $_.InterfaceIndex, $_.IPAddress } |
            Sort-Object)
        Route = @(Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop |
            ForEach-Object {
                '{0}|{1}|{2}|{3}|{4}' -f $_.InterfaceIndex,
                    $_.DestinationPrefix, $_.NextHop, $_.RouteMetric,
                    $_.PolicyStore
            } | Sort-Object)
    }
}

function Assert-NetworkStateEqual {
    param($Before, $After, [string]$Profile)
    if (@(Compare-Object $Before.Dns $After.Dns).Count -ne 0 -or
            @(Compare-Object $Before.Ip $After.Ip).Count -ne 0 -or
            @(Compare-Object $Before.Route $After.Route).Count -ne 0) {
        throw "DNS/IP/route state was not restored after profile $Profile"
    }
}

function Invoke-ProfileRun {
    param(
        [string]$Name,
        [string]$ConfigPath,
        [string]$ReadyEvent,
        [string[]]$Rules = @()
    )
    $profileDir = Join-Path $script:RunRoot $Name
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    $script:LogDir = $profileDir
    $script:FakeNetProcess = $null
    $script:PktmonStarted = $false
    $script:StopFlag = $null
    $script:ExitCode = 0
    $before = Get-NetworkState
    $before.Dns | Set-Content (Join-Path $profileDir 'dns-before.txt')
    $before.Ip | Set-Content (Join-Path $profileDir 'ip-before.txt')
    $before.Route | Set-Content (Join-Path $profileDir 'routes-before.txt')

    try {
        $templateText = Get-Content -LiteralPath $ConfigPath -Raw
        if (([regex]::Matches($templateText,
                    [regex]::Escape('__EXTERNAL_DNS__'))).Count -ne 1) {
            throw "Invalid DNS marker count in profile $Name"
        }
        $runtimeConfig = Join-Path $profileDir ("$Name-runtime.ini")
        $templateText.Replace('__EXTERNAL_DNS__', $script:Resolver) |
            Set-Content -LiteralPath $runtimeConfig -Encoding ASCII

        $etl = Join-Path $profileDir 'independent-capture.etl'
        $pktmonExit = Invoke-NativeCaptured {
            & pktmon.exe start --capture --pkt-size 0 --file-name $etl
        } (Join-Path $profileDir 'pktmon-start.log')
        if ($pktmonExit -ne 0) { throw "pktmon start failed: $Name" }
        $script:PktmonStarted = $true

        $script:StopFlag = Join-Path $profileDir 'stop-fakenet.flag'
        $fakeLog = Join-Path $profileDir 'fakenet.log'
        $fakeStdout = Join-Path $profileDir 'fakenet-stdout.log'
        $fakeStderr = Join-Path $profileDir 'fakenet-stderr.log'
        $arguments = @('-m', 'fakenet.fakenet', '-c',
            ('"{0}"' -f $runtimeConfig), '-l', ('"{0}"' -f $fakeLog),
            '-f', ('"{0}"' -f $script:StopFlag), '-p', '-v')
        $script:FakeNetProcess = Start-Process -FilePath $script:Python `
            -ArgumentList $arguments -WorkingDirectory $script:RepoRoot `
            -WindowStyle Hidden -PassThru `
            -RedirectStandardOutput $fakeStdout `
            -RedirectStandardError $fakeStderr
        $script:FakeNetProcess.EnableRaisingEvents = $true
        $null = $script:FakeNetProcess.Handle

        $ready = $false
        for ($index = 0; $index -lt 30; $index++) {
            Start-Sleep -Seconds 1
            $script:FakeNetProcess.Refresh()
            if ($script:FakeNetProcess.HasExited) {
                $stderrSummary = 'no stderr'
                if ((Test-Path -LiteralPath $fakeStderr) -and
                        (Get-Item -LiteralPath $fakeStderr).Length -gt 0) {
                    $stderrLines = @(Get-Content -LiteralPath $fakeStderr `
                        -Tail 12 -ErrorAction SilentlyContinue |
                        Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
                    if ($stderrLines.Count -gt 0) {
                        $stderrSummary = ($stderrLines -join ' | ')
                    }
                }
                throw ('FakeNet exited before readiness: {0}/{1}; ' +
                    'exit_code={2}; stderr={3}' -f $Name, $ReadyEvent,
                    $script:FakeNetProcess.ExitCode, $stderrSummary)
            }
            if ((Test-Path $fakeLog) -and
                    (Select-String $fakeLog -Pattern $ReadyEvent -Quiet)) {
                $ready = $true
                break
            }
        }
        if (-not $ready) { throw "Ready timeout: $Name/$ReadyEvent" }
        Add-Result "Ready-$Name" 'PASS' $ReadyEvent

        if ($Name -eq 'baidu_tcp443') {
            $readyText = Get-Content $fakeLog -Raw
            if ($readyText -match 'DOMAIN_TAKEOVER_READY|ALLOW_TAKEOVER_SINK') {
                throw "Takeover event polluted reviewed profile $Name"
            }
            Invoke-ReviewedRuleMatrix -Profile $Name -Rules $Rules
            $ordinaryAnswer = @(Resolve-DnsName reviewed-profile.invalid `
                -Type A -DnsOnly | Where-Object Type -eq 'A' |
                Select-Object -ExpandProperty IPAddress)
            if ('192.168.204.1' -in $ordinaryAnswer) {
                throw 'Reviewed profile synthesized the takeover sink.'
            }
        } else {
            $answers = @(Resolve-DnsName takeover-regression.invalid `
                -Type A -DnsOnly | Where-Object Type -eq 'A' |
                Select-Object -ExpandProperty IPAddress)
            if ($answers.Count -ne 1 -or $answers[0] -ne '192.168.204.1') {
                throw 'Takeover regression DNS answer mismatch.'
            }
            $script:ReviewedMatrixLog = Join-Path $profileDir `
                'takeover-matrix.log'
            Send-ReviewedMatrixPacket TCP '192.168.204.1' 18080 'TAKEOVER'
            Send-ReviewedMatrixPacket UDP '192.168.204.1' 18081 'TAKEOVER'
            Invoke-LoggedCommand -Name 'positive-api-deepseek' `
                -RequireSuccess -Native -Command {
                    & curl.exe --noproxy '*' -v --http1.1 --ssl-no-revoke `
                        --connect-timeout 10 --max-time 30 `
                        https://api.deepseek.com/
                }
        }
        Start-Sleep -Seconds 3
    } finally {
        Stop-TestComponents
        $script:FakeNetProcess = $null
        $script:StopFlag = $null
    }
    if ($script:ExitCode -ne 0) {
        throw "Profile shutdown/capture failed: $Name"
    }

    $after = Get-NetworkState
    $after.Dns | Set-Content (Join-Path $profileDir 'dns-after.txt')
    $after.Ip | Set-Content (Join-Path $profileDir 'ip-after.txt')
    $after.Route | Set-Content (Join-Path $profileDir 'routes-after.txt')
    Assert-NetworkStateEqual $before $after $Name
    Add-Result "Restore-$Name" 'PASS' 'DNS/IP/route snapshots match'

    $fakeText = Get-Content (Join-Path $profileDir 'fakenet.log') -Raw
    if ($Name -eq 'baidu_tcp443') {
        foreach ($event in @('IP_ALLOW_READY', 'IP_ALLOW_ROUTE_OK',
                'ALLOW_REVIEWED_IP_FIRST_FLOW')) {
            if ($fakeText -notmatch [regex]::Escape($event)) {
                throw "Required event absent in ${Name}: $event"
            }
        }
        if ($fakeText -match 'DOMAIN_TAKEOVER_READY|ALLOW_TAKEOVER_SINK') {
            throw "Forbidden takeover event appeared in $Name"
        }
        $pcap = Join-Path $profileDir 'independent-capture.pcapng'
        $report = Join-Path $profileDir 'pcap-verdicts.json'
        $analysisExit = Invoke-NativeCaptured {
            & $script:Python (Join-Path $script:RepoRoot `
                'test\analyze_reviewed_ipv4_pcap.py') $pcap $Name $report
        } (Join-Path $profileDir 'pcap-analysis.log')
        if ($analysisExit -ne 0) { throw "PCAP matrix failed: $Name" }
        Add-Result "Pcap-$Name" 'PASS' $report
    } else {
        foreach ($event in @('DOMAIN_TAKEOVER_READY',
                'ALLOW_TAKEOVER_SINK', 'DNS_LEASE_ADD',
                'REDIRECT_TLS_RELAY', 'TLS_SNI_ALLOW')) {
            if ($fakeText -notmatch [regex]::Escape($event)) {
                throw "Takeover regression event absent: $event"
            }
        }
        if ($fakeText -match 'IP_ALLOW_READY|ALLOW_REVIEWED_IP_FIRST_FLOW') {
            throw 'Reviewed-IP event appeared in takeover regression.'
        }
    }
    foreach ($event in @('IP_ALLOW_ROUTE_SUSPEND', 'TAKEOVER_SUSPEND',
            'policy_exception')) {
        if ($fakeText -match [regex]::Escape($event)) {
            throw "Forbidden event occurred in ${Name}: $event"
        }
    }
    Add-Result "Events-$Name" 'PASS'
}

$vmIdentity = Get-CimInstance Win32_ComputerSystem
if (-not (Test-IsVirtualMachine)) {
    Write-Error (("REFUSED: this machine does not identify as a VM ({0} / {1}). " +
        'The runner will not start FakeNet-NG on a possible host.') -f
        $vmIdentity.Manufacturer, $vmIdentity.Model)
    exit 40
}
if (-not (Test-IsAdministrator)) {
    $arguments = @('-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', ('"{0}"' -f $PSCommandPath))
    if ($PythonPath -ne 'python.exe') { $arguments += @('-PythonPath', $PythonPath) }
    $elevated = Start-Process powershell.exe -Verb RunAs -Wait -PassThru `
        -ArgumentList $arguments
    exit $elevated.ExitCode
}

$script:RepoRoot = Resolve-RepositoryRoot
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$script:RunRoot = Join-Path $PSScriptRoot `
        ("Logs\reviewed-ipv4-v15-{0}" -f $stamp)
New-Item -ItemType Directory -Path $script:RunRoot -Force | Out-Null
$script:LogDir = $script:RunRoot
$script:ResultFile = Join-Path $script:RunRoot 'results.tsv'
"status`ttest`tdetail" | Set-Content $script:ResultFile -Encoding UTF8
Start-Transcript (Join-Path $script:RunRoot 'runner-transcript.log') | Out-Null
$script:TranscriptStarted = $true

try {
    $manifest = Read-AndVerifyManifest $script:RepoRoot
    $os = Get-CimInstance Win32_OperatingSystem
    if ([string]$os.Version -ne [string]$manifest.windows_build -or
            -not [Environment]::Is64BitOperatingSystem) {
        throw 'Windows build/architecture does not match reviewed v15.'
    }
    Add-Result 'WindowsBuild' 'PASS' ([string]$os.Version)

    $script:Resolver = Select-OriginalDnsServer
    $localIPv4 = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
        Select-Object -ExpandProperty IPAddress)
    if ($script:Resolver -in @('110.242.69.21', '110.242.70.57') -or
            '110.242.69.21' -in $localIPv4 -or
            '110.242.70.57' -in $localIPv4) {
        throw 'Acceptance targets conflict with VM local/DNS state.'
    }
    Assert-ReviewedDnsFreshness -Hostname $manifest.reviewed_hostname `
        -Target $manifest.reviewed_ipv4_target -Resolver $script:Resolver |
        Out-Null
    $route = @(Invoke-ReviewedRoutePreflight $script:RepoRoot `
        @('110.242.69.21'))
    if ($route.Count -ne 1) {
        throw '110.242.69.21 does not have one unique best IPv4 route.'
    }
    Add-Result 'ReviewedRoute' 'PASS' $route[0].destination_prefix

    $systemPython = (Get-Command $PythonPath -ErrorAction Stop).Source
    $identityCommand = "import json,platform,sys; print(json.dumps({'version':'.'.join(map(str,sys.version_info[:3])),'machine':platform.machine()}))"
    $identityPath = Join-Path $script:RunRoot 'python-identity.log'
    $identityExit = Invoke-NativeCaptured {
        $identityCommand | & $systemPython -
    } $identityPath
    if ($identityExit -ne 0) { throw 'Unable to inspect Python.' }
    $identity = (Get-Content $identityPath -Raw).Trim() | ConvertFrom-Json
    if ($identity.version -ne $manifest.python_version -or
            $identity.machine.ToUpperInvariant() -ne
                $manifest.python_architecture) {
        throw 'Python ABI does not match reviewed v15.'
    }

    $venvRoot = Join-Path $script:RepoRoot '.venv-reviewed-ipv4'
    $venvPython = Join-Path $venvRoot 'Scripts\python.exe'
    $script:Python = $venvPython
    if (-not (Test-Path $script:Python)) {
        $venvExit = Invoke-NativeCaptured {
            & $systemPython -m venv $venvRoot
        } (Join-Path $script:RunRoot 'venv-create.log')
        if ($venvExit -ne 0 -or -not (Test-Path $script:Python)) {
            throw 'Package-local venv creation failed.'
        }
    }
    $installExit = Invoke-NativeCaptured {
        & $script:Python -m pip install --disable-pip-version-check `
            --no-index --find-links (Join-Path $script:RepoRoot 'wheelhouse') `
            --require-hashes -r (Join-Path $script:RepoRoot `
                'requirements-domain-takeover-windows.lock')
    } (Join-Path $script:RunRoot 'dependency-install.log')
    if ($installExit -ne 0) { throw 'Offline dependency installation failed.' }
    $dependencyCommand = ('import dpkt,dnslib,netifaces,pydivert,pyftpdlib,jinja2,' +
        'OpenSSL,cryptography; from importlib.metadata import version;' +
        'assert version("pydivert")=="2.1.0";' +
        'assert version("netifaces-plus")=="0.12.5"')
    $dependencyExit = Invoke-NativeCaptured {
        $dependencyCommand | & $venvPython -
    } (Join-Path $script:RunRoot 'dependency-check.log')
    if ($dependencyExit -ne 0) { throw 'Dependency contract failed.' }
    Add-Result 'Dependencies' 'PASS' 'offline/hash-locked'

    Push-Location $script:RepoRoot
    try {
        foreach ($test in @('test_egresspolicy.py', 'test_dns_policy.py',
                'test_tlshello.py', 'test_domain_egress_relay.py',
                'test_windows_egress_verdict.py',
                'test_linux_reviewed_ip_guard.py',
                'test_reviewed_ipv4_pcap.py')) {
            $testExit = Invoke-NativeCaptured {
                & $script:Python -m unittest discover -s test -p $test -v
            } (Join-Path $script:RunRoot ($test + '.log'))
            if ($testExit -ne 0) { throw "Unit test failed: $test" }
            Add-Result $test 'PASS'
        }
    } finally {
        Pop-Location
    }

    if (-not (Get-Command pktmon.exe -ErrorAction SilentlyContinue)) {
        throw 'pktmon.exe is required for independent evidence.'
    }
    $profileName = 'baidu_tcp443'
    $profile = @($manifest.reviewed_ipv4_profiles |
        Where-Object name -eq $profileName)
    if ($profile.Count -ne 1 -or
            [string]$profile[0].rules_raw -ne 'TCP/110.242.69.21/443' -or
            (@($profile[0].rules) -join ',') -ne
                'TCP/110.242.69.21/443') {
        throw 'The single Baidu TCP/443 profile is missing or expanded.'
    }
    $config = Join-Path $script:RepoRoot `
        (([string]$profile[0].config_path).Replace('/', '\'))
    $configHash = (Get-FileHash $config -Algorithm SHA256).Hash.ToLowerInvariant()
    $configText = Get-Content $config -Raw
    $ruleLines = @(Select-String $config `
        -Pattern '^ExternalAllowedIPv4Rules:\s*(.+)$')
    if ($configHash -ne
            ([string]$profile[0].config_sha256).ToLowerInvariant() -or
            $ruleLines.Count -ne 1 -or
            $ruleLines[0].Matches[0].Groups[1].Value -ne
                'TCP/110.242.69.21/443' -or
            $configText -match '(?m)^ExternalTakeover' -or
            $configText -match
                '(?m)^ResponseA\s*:\s*192\.168\.204\.1\s*$') {
        throw 'Baidu TCP/443 profile config contract mismatch.'
    }
    Invoke-ProfileRun $profileName $config 'IP_ALLOW_READY' `
        @('TCP/110.242.69.21/443')
    $takeover = $manifest.takeover_regression_profile
    $takeoverConfig = Join-Path $script:RepoRoot `
        (([string]$takeover.config_path).Replace('/', '\'))
    $takeoverText = Get-Content $takeoverConfig -Raw
    $takeoverHash = (Get-FileHash $takeoverConfig `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($takeoverHash -ne
            ([string]$takeover.config_sha256).ToLowerInvariant() -or
            $takeoverText -match '(?m)^ExternalAllowedIPv4Rules\s*:') {
        throw 'Takeover regression config contract mismatch.'
    }
    Invoke-ProfileRun 'takeover_regression' $takeoverConfig `
        'DOMAIN_TAKEOVER_READY'

    $script:LogDir = $script:RunRoot
    Add-Result 'Runner' 'PASS' 'both isolated profiles completed and restored'
    $script:ExitCode = 0
} catch {
    $script:LogDir = $script:RunRoot
    $_ | Format-List * -Force | Out-File (
        Join-Path $script:RunRoot 'fatal-error.log')
    Add-Result 'Runner' 'FAIL' $_.Exception.Message
    $script:ExitCode = 1
} finally {
    if ($script:FakeNetProcess -or $script:PktmonStarted) {
        Stop-TestComponents
    }
    $script:LogDir = $script:RunRoot
    if ($script:TranscriptStarted) { Stop-Transcript | Out-Null }
    Write-Host "Plain logs available at: $script:RunRoot"
}
exit $script:ExitCode
