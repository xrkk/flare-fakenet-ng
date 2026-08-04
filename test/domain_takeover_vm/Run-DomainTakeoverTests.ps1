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

$vmIdentity = Get-CimInstance Win32_ComputerSystem
if (-not (Test-IsVirtualMachine)) {
    Write-Error ("REFUSED: this machine does not identify as a VM ({0} / {1}). " +
        'The test runner will not start FakeNet-NG on a possible host.') -f
        $vmIdentity.Manufacturer, $vmIdentity.Model
    exit 40
}

if (-not (Test-IsAdministrator)) {
    $arguments = @('-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', ('"{0}"' -f $PSCommandPath))
    if ($PythonPath -ne 'python.exe') {
        $arguments += @('-PythonPath', $PythonPath)
    }
    $elevated = Start-Process powershell.exe -Verb RunAs -Wait -PassThru `
        -ArgumentList $arguments
    exit $elevated.ExitCode
}

$repoRoot = Resolve-RepositoryRoot
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$logRoot = Join-Path $PSScriptRoot 'Logs'
$script:LogDir = Join-Path $logRoot ("domain-takeover-{0}" -f $stamp)
New-Item -ItemType Directory -Path $script:LogDir -Force | Out-Null
$script:ResultFile = Join-Path $script:LogDir 'results.tsv'
"status`ttest`tdetail" | Set-Content -LiteralPath $script:ResultFile -Encoding UTF8
Start-Transcript -LiteralPath (Join-Path $script:LogDir 'runner-transcript.log') | Out-Null
$script:TranscriptStarted = $true

try {
    Get-ComputerInfo | Out-File (Join-Path $script:LogDir 'computer-info.txt')
    Get-NetIPAddress | Format-List * | Out-File (Join-Path $script:LogDir 'ip-before.txt')
    Get-DnsClientServerAddress | Format-List * |
        Out-File (Join-Path $script:LogDir 'dns-before.txt')
    $script:OriginalDnsSnapshot = Get-DnsSnapshot
    Get-NetRoute | Sort-Object AddressFamily,RouteMetric |
        Format-Table -AutoSize | Out-File (Join-Path $script:LogDir 'routes-before.txt')

    $ipv6Enabled = @(Get-NetAdapterBinding -ComponentID ms_tcpip6 |
        Where-Object Enabled).Count -gt 0
    if (-not $ipv6Enabled) {
        Add-Result 'IPv6Enabled' 'FAIL' 'enable IPv6 before the security acceptance run'
        throw 'IPv6 is disabled; this would mask the IPv6 enforcement test.'
    }
    Add-Result 'IPv6Enabled' 'PASS'

    $resolver = Select-OriginalDnsServer
    Add-Result 'ExternalDnsServer' 'PASS' $resolver

    $manifest = Read-AndVerifyManifest $repoRoot
    $os = Get-CimInstance Win32_OperatingSystem
    if ([string]$os.Version -ne [string]$manifest.windows_build) {
        Add-Result 'WindowsBuild' 'FAIL' ("expected={0}; observed={1}" -f
            $manifest.windows_build, $os.Version)
        throw 'Windows build does not match the reviewed VM baseline.'
    }
    Add-Result 'WindowsBuild' 'PASS' ([string]$os.Version)

    $systemPython = (Get-Command $PythonPath -ErrorAction Stop).Source
    # Send dynamic Python source through stdin. Windows PowerShell 5.1 can
    # strip embedded double quotes while rebuilding native command lines.
    $identityCommand = "import json,platform,sys; print(json.dumps({'version':'.'.join(map(str,sys.version_info[:3])),'machine':platform.machine()}))"
    $identityLog = Join-Path $script:LogDir 'python-identity.log'
    $identityExit = Invoke-NativeCaptured {
        $identityCommand | & $systemPython -
    } $identityLog
    if ($identityExit -ne 0) {
        Add-Result 'PythonABI' 'FAIL' 'see python-identity.log'
        throw 'Unable to inspect the configured Python interpreter.'
    }
    try {
        $identity = (Get-Content -Raw -LiteralPath $identityLog).Trim() |
            ConvertFrom-Json
    } catch {
        Add-Result 'PythonABI' 'FAIL' 'python-identity.log is not valid JSON'
        throw 'Python identity output is invalid.'
    }
    if ($identity.version -ne $manifest.python_version -or
            $identity.machine.ToUpperInvariant() -ne
                $manifest.python_architecture) {
        Add-Result 'PythonABI' 'FAIL' ("observed={0}/{1}" -f
            $identity.version, $identity.machine)
        throw 'Python version or architecture does not match reviewed v5.'
    }
    Add-Result 'PythonABI' 'PASS' ("{0}/{1}" -f
        $identity.version, $identity.machine)

    $venvRoot = Join-Path $repoRoot '.venv-domain-takeover'
    $python = Join-Path $venvRoot 'Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $python)) {
        $venvLog = Join-Path $script:LogDir 'venv-create.log'
        $venvExit = Invoke-NativeCaptured {
            & $systemPython -m venv $venvRoot
        } $venvLog
        if ($venvExit -ne 0 -or -not (Test-Path -LiteralPath $python)) {
            Add-Result 'OfflineVenv' 'FAIL' 'package-local venv creation failed'
            throw 'Failed to create package-local Python environment.'
        }
    }
    Add-Result 'OfflineVenv' 'PASS' $python

    $wheelhouse = Join-Path $repoRoot 'wheelhouse'
    $lock = Join-Path $repoRoot 'requirements-domain-takeover-windows.lock'
    $installLog = Join-Path $script:LogDir 'dependency-install.log'
    $installExit = Invoke-NativeCaptured {
        & $python -m pip install --disable-pip-version-check --no-index --find-links $wheelhouse --require-hashes -r $lock
    } $installLog
    if ($installExit -ne 0) {
        Add-Result 'Dependencies' 'FAIL' 'offline hash-locked installation failed'
        throw 'Required package-local dependencies could not be installed offline.'
    }
    $dependencyLog = Join-Path $script:LogDir 'dependency-check.log'
    $dependencyExit = Invoke-NativeCaptured {
        $dependencyCommand = ('import dpkt,dnslib,netifaces,pydivert,pyftpdlib,jinja2,' +
            'OpenSSL,cryptography; from importlib.metadata import version;' +
            'assert version("pydivert")=="2.1.0";' +
            'assert version("netifaces-plus")=="0.12.5";' +
            'assert callable(netifaces.interfaces);' +
            'assert callable(netifaces.ifaddresses);' +
            'print("dependency contract ok")')
        $dependencyCommand | & $python -
    } $dependencyLog
    if ($dependencyExit -ne 0) {
        Add-Result 'Dependencies' 'FAIL' 'distribution version/API check failed'
        throw 'Package-local dependency/API check failed.'
    }
    Add-Result 'Dependencies' 'PASS' 'offline lock and critical distribution/API checks passed'

    $contractOutput = Join-Path $script:LogDir 'launcher-contract-run.log'
    $launcherContract = Join-Path $PSScriptRoot 'Test-LauncherContracts.ps1'
    $contractExit = Invoke-NativeCaptured {
        & powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File $launcherContract -LauncherPath (Join-Path $repoRoot 'Start-DomainTakeover.ps1') -LogDirectory $script:LogDir
    } $contractOutput
    if ($contractExit -ne 0) {
        Add-Result 'LauncherContracts' 'FAIL' 'see launcher contract logs'
        throw 'PowerShell launcher contract tests failed.'
    }
    Add-Result 'LauncherContracts' 'PASS'

    Push-Location $repoRoot
    try {
        foreach ($test in @('test_egresspolicy.py', 'test_dns_policy.py',
                'test_tlshello.py', 'test_domain_egress_relay.py',
                'test_windows_egress_verdict.py',
                'test_ssl_utils.py', 'test_proxy_listener.py')) {
            $testLog = Join-Path $script:LogDir ($test + '.log')
            $testExit = Invoke-NativeCaptured {
                & $python -m unittest discover -s test -p $test -v
            } $testLog
            if ($testExit -ne 0) {
                Add-Result $test 'FAIL' 'see unit-test log'
                throw "Unit test failed: $test"
            }
            Add-Result $test 'PASS'
        }
    } finally {
        Pop-Location
    }

    $template = Join-Path $repoRoot 'fakenet\configs\domain_takeover_windows.ini'
    $runtimeConfig = Join-Path $script:LogDir 'domain_takeover_runtime.ini'
    $templateText = Get-Content -LiteralPath $template -Raw
    if (([regex]::Matches($templateText,
                [regex]::Escape('__EXTERNAL_DNS__'))).Count -ne 1) {
        throw 'The reviewed configuration has an invalid DNS marker count.'
    }
    $templateText.Replace('__EXTERNAL_DNS__', $resolver) |
        Set-Content -LiteralPath $runtimeConfig -Encoding ASCII

    $probeLines = @($templateText -split '\r?\n' | Where-Object {
        $_ -match '^[ \t]*ExternalTakeoverProbeTCPPorts[ \t]*:'
    })
    if ($probeLines.Count -ne 1 -or $probeLines[0] -notmatch
            '^[ \t]*ExternalTakeoverProbeTCPPorts[ \t]*:[ \t]*$') {
        Add-Result 'TakeoverProbeDefault' 'FAIL' 'reviewed package must default to an empty optional probe list'
        throw 'Reviewed optional probe default is not empty.'
    }
    Add-Result 'TakeoverProbeDefault' 'PASS' 'TAKEOVER_PROBE_SKIP reason=not_configured'

    $pktmon = Get-Command pktmon.exe -ErrorAction SilentlyContinue
    if (-not $pktmon) {
        Add-Result 'IndependentCapture' 'FAIL' 'pktmon.exe is required for independent evidence'
        throw 'pktmon.exe is unavailable.'
    }
    $etl = Join-Path $script:LogDir 'independent-capture.etl'
    $pktmonStartLog = Join-Path $script:LogDir 'pktmon-start.log'
    $pktmonStartExit = Invoke-NativeCaptured {
        & pktmon.exe start --capture --pkt-size 0 --file-name $etl
    } $pktmonStartLog
    if ($pktmonStartExit -ne 0) {
        Add-Result 'IndependentCapture' 'FAIL' 'pktmon start failed'
        throw 'Independent packet capture failed to start.'
    }
    $script:PktmonStarted = $true
    Add-Result 'IndependentCapture' 'PASS' 'pktmon capture started'

    $script:StopFlag = Join-Path $script:LogDir 'stop-fakenet.flag'
    $fakeLog = Join-Path $script:LogDir 'fakenet.log'
    $stdout = Join-Path $script:LogDir 'fakenet-stdout.log'
    $stderr = Join-Path $script:LogDir 'fakenet-stderr.log'
    $arguments = @('-m', 'fakenet.fakenet', '-c',
        ('"{0}"' -f $runtimeConfig), '-l', ('"{0}"' -f $fakeLog),
        '-f', ('"{0}"' -f $script:StopFlag), '-p', '-v')
    $startArguments = @{
        FilePath = $python
        ArgumentList = $arguments
        WorkingDirectory = $repoRoot
        WindowStyle = 'Hidden'
        PassThru = $true
        RedirectStandardOutput = $stdout
        RedirectStandardError = $stderr
    }
    $script:FakeNetProcess = Start-Process @startArguments
    $script:FakeNetProcess.EnableRaisingEvents = $true
    $null = $script:FakeNetProcess.Handle

    $ready = $false
    for ($i = 0; $i -lt 30; $i++) {
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
        Add-Result 'FakeNetReady' 'FAIL' 'process exited or readiness timeout'
        throw 'FakeNet did not become ready.'
    }
    Add-Result 'FakeNetReady' 'PASS'

    $allowedAnswers = @(Resolve-DnsName api.deepseek.com -Type A -DnsOnly |
        Where-Object Type -eq 'A' | Select-Object -ExpandProperty IPAddress)
    if ($allowedAnswers.Count -eq 0 -or '192.168.204.1' -in $allowedAnswers) {
        Add-Result 'AllowedDomainDNS' 'FAIL' ($allowedAnswers -join ',')
        throw 'Allowed domain did not return a real A answer.'
    }
    Add-Result 'AllowedDomainDNS' 'PASS' ($allowedAnswers -join ',')

    foreach ($name in @('takeover-one.invalid', 'takeover-two.invalid',
            'dns.msftncsi.com')) {
        $answers = @(Resolve-DnsName $name -Type A -DnsOnly |
            Where-Object Type -eq 'A' | Select-Object -ExpandProperty IPAddress)
        if ($answers.Count -ne 1 -or $answers[0] -ne '192.168.204.1') {
            Add-Result "SinkDNS-$name" 'FAIL' ($answers -join ',')
            throw "Sink DNS mismatch for $name"
        }
        Add-Result "SinkDNS-$name" 'PASS' '192.168.204.1'
    }

    $dnsParityCommand = @'
import socket, struct
from dnslib import DNSRecord, RCODE

def ask(name, qtype, tcp):
    wire = DNSRecord.question(name, qtype).pack()
    socktype = socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM
    sock = socket.socket(socket.AF_INET, socktype)
    sock.settimeout(5)
    try:
        if tcp:
            sock.connect(("127.0.0.1", 53))
            sock.sendall(struct.pack("!H", len(wire)) + wire)
            header = sock.recv(2)
            assert len(header) == 2
            remaining = struct.unpack("!H", header)[0]
            chunks = []
            while remaining:
                chunk = sock.recv(remaining)
                assert chunk
                chunks.append(chunk)
                remaining -= len(chunk)
            reply = DNSRecord.parse(b"".join(chunks))
        else:
            sock.sendto(wire, ("127.0.0.1", 53))
            reply = DNSRecord.parse(sock.recvfrom(65535)[0])
    finally:
        sock.close()
    return reply

for tcp in (False, True):
    answer = ask("takeover-parity.invalid", "A", tcp)
    assert answer.header.rcode == RCODE.NOERROR
    assert answer.header.qr == 1 and answer.header.aa == 1
    assert answer.header.ra == 1 and answer.header.rd == 1
    assert len(answer.rr) == 1
    assert str(answer.rr[0].rdata) == "192.168.204.1"
    assert answer.rr[0].ttl == 60
    nodata = ask("takeover-parity.invalid", "AAAA", tcp)
    assert nodata.header.rcode == RCODE.NOERROR
    assert not nodata.rr
print("UDP/TCP A parity and AAAA NODATA passed")
'@
    $dnsParityLog = Join-Path $script:LogDir 'dns-udp-tcp-parity.log'
    $dnsParityExit = Invoke-NativeCaptured {
        $dnsParityCommand | & $python -
    } $dnsParityLog
    if ($dnsParityExit -ne 0) {
        Add-Result 'DnsUdpTcpParity' 'FAIL' 'see dns-udp-tcp-parity.log'
        throw 'UDP/TCP DNS parity or AAAA NODATA failed.'
    }
    Add-Result 'DnsUdpTcpParity' 'PASS'

    Invoke-LoggedCommand -Name 'positive-api-deepseek' -RequireSuccess -Native -Command {
        & curl.exe --noproxy '*' -v --http1.1 --ssl-no-revoke --connect-timeout 10 --max-time 30 https://api.deepseek.com/
    }
    Invoke-LoggedCommand -Name 'sink-domain-tcp' -RequireSuccess -Native -Command {
        & $python -c "import socket; s=socket.socket(); s.settimeout(3); print('connect_ex',s.connect_ex(('takeover-flow.invalid',18080))); s.close()"
    }
    Invoke-LoggedCommand -Name 'sink-domain-udp' -RequireSuccess -Native -Command {
        & $python -c "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); print('sent',s.sendto(b'vm-acceptance-udp',('takeover-flow.invalid',18081))); s.close()"
    }
    Invoke-LoggedCommand -Name 'sink-direct-tcp' -RequireSuccess -Native -Command {
        & $python -c "import socket; s=socket.socket(); s.settimeout(3); print('connect_ex',s.connect_ex(('192.168.204.1',28080))); s.close()"
    }
    Invoke-LoggedCommand -Name 'sink-direct-udp443' -RequireSuccess -Native -Command {
        & $python -c "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); print('sent',s.sendto(b'vm-acceptance-udp443',('192.168.204.1',443))); s.close()"
    }
    Invoke-LoggedCommand -Name 'negative-other-private' -Native -Command {
        & $python -c "import socket; s=socket.socket(); s.settimeout(3); print('connect_ex',s.connect_ex(('192.168.204.2',28080))); s.close()"
    }
    Invoke-LoggedCommand -Name 'negative-public-ip' -Native -Command {
        & curl.exe --noproxy '*' -vk --connect-timeout 5 --max-time 10 https://1.1.1.1/
    }
    Invoke-LoggedCommand -Name 'negative-allowed-http' -Native -Command {
        & curl.exe --noproxy '*' -v --connect-timeout 5 --max-time 10 http://api.deepseek.com/
    }
    Invoke-LoggedCommand -Name 'negative-doh' -Native -Command {
        & curl.exe --noproxy '*' -vk --connect-timeout 5 --max-time 10 https://cloudflare-dns.com/dns-query
    }
    Invoke-LoggedCommand -Name 'negative-dot' -Native -Command {
        & $python -c "import socket; s=socket.socket(); s.settimeout(3); print('connect_ex',s.connect_ex(('1.1.1.1',853))); s.close()"
    }
    Invoke-LoggedCommand -Name 'negative-external-udp443' -Native -Command {
        & $python -c "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(b'blocked-quic-probe',('1.1.1.1',443)); s.close()"
    }
    Invoke-LoggedCommand -Name 'negative-ipv6' -Native -Command {
        & curl.exe --noproxy '*' -6 -vk --connect-timeout 5 --max-time 10 https://api.deepseek.com/
    }
    Invoke-LoggedCommand 'negative-external-dns' {
        Resolve-DnsName example.com -Type A -Server 8.8.8.8 -DnsOnly
    }

    Start-Sleep -Seconds 3
    $fakeText = Get-Content -LiteralPath $fakeLog -Raw
    foreach ($event in @('DOMAIN_TAKEOVER_READY', 'TAKEOVER_ROUTE_OK',
            'TAKEOVER_DNS_ANSWER', 'ALLOW_TAKEOVER_SINK',
            'DNS_LEASE_ADD', 'REDIRECT_TLS_RELAY', 'TLS_SNI_ALLOW',
            'ALLOW_INTERNAL_UPSTREAM', 'DROP_EXTERNAL')) {
        if ($fakeText -notmatch [regex]::Escape($event)) {
            Add-Result ("Event-{0}" -f $event) 'FAIL' 'required event absent'
            throw "Required policy event absent: $event"
        }
        Add-Result ("Event-{0}" -f $event) 'PASS'
    }
    foreach ($forbiddenEvent in @('TAKEOVER_SUSPEND', 'policy_exception')) {
        if ($fakeText -match [regex]::Escape($forbiddenEvent)) {
            Add-Result ("ForbiddenEvent-{0}" -f $forbiddenEvent) 'FAIL' 'event present'
            throw "Forbidden event occurred: $forbiddenEvent"
        }
        Add-Result ("ForbiddenEvent-{0}" -f $forbiddenEvent) 'PASS'
    }
    Add-Result 'SinkBoundary' 'OBSERVED' (
        'direct 192.168.204.1 TCP/UDP is intentionally allowed; PCAP must prove protocol, port, destination, and selected interface')
    Add-Result 'InboundResidualRisk' 'OBSERVED' (
        'inbound return traffic is outside the new sink verdict and is not claimed as mitigated')
    $script:ExitCode = 0
} catch {
    $_ | Format-List * -Force | Out-File (Join-Path $script:LogDir 'fatal-error.log')
    Add-Result 'Runner' 'FAIL' $_.Exception.Message
    $script:ExitCode = 1
} finally {
    Stop-TestComponents
    $dnsAfter = Get-DnsClientServerAddress
    $dnsAfter | Format-List * |
        Out-File (Join-Path $script:LogDir 'dns-after.txt')
    $restoredDnsSnapshot = Get-DnsSnapshot
    $dnsDifference = @(Compare-Object $script:OriginalDnsSnapshot $restoredDnsSnapshot)
    if ($dnsDifference.Count -eq 0) {
        Add-Result 'DnsRestore' 'PASS' 'IPv4 DNS server configuration matches pre-test snapshot'
    } else {
        $dnsDifference | Format-Table -AutoSize |
            Out-File (Join-Path $script:LogDir 'dns-restore-difference.txt')
        Add-Result 'DnsRestore' 'FAIL' 'configuration differs; restore the VM snapshot before reconnecting it'
        $script:ExitCode = 1
    }
    Get-NetIPAddress | Format-List * |
        Out-File (Join-Path $script:LogDir 'ip-after.txt')
    if ($script:TranscriptStarted) {
        Stop-Transcript | Out-Null
    }
    Write-Host "Plain logs available at: $script:LogDir"
}

exit $script:ExitCode
