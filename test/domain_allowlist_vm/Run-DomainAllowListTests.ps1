[CmdletBinding()]
param(
    [string]$ExternalDnsServer = "",
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
    $candidates = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |
        ForEach-Object { $_.ServerAddresses } |
        Where-Object { $_ -and $_ -notin $local -and $_ -notlike '127.*' } |
        Select-Object -Unique)
    if (-not $ExternalDnsServer) {
        throw 'Enter an explicitly reviewed pre-FakeNet IPv4 DNS server; automatic selection is disabled.'
    }
    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($ExternalDnsServer, [ref]$parsed) -or
            $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
        throw 'ExternalDnsServer must be an IPv4 address.'
    }
    if ($ExternalDnsServer -in $local -or $ExternalDnsServer -like '127.*') {
        throw 'ExternalDnsServer must not be a local address.'
    }
    if ($ExternalDnsServer -notin $candidates) {
        throw 'ExternalDnsServer must match the VM DNS configuration captured before FakeNet starts.'
    }
    return $ExternalDnsServer
}

function Invoke-LoggedCommand {
    param([string]$Name, [scriptblock]$Command, [switch]$RequireSuccess)
    $path = Join-Path $script:LogDir ($Name + '.log')
    try {
        & $Command *>&1 | Out-File -LiteralPath $path -Encoding UTF8
        $commandExit = $LASTEXITCODE
        if ($RequireSuccess -and $commandExit -ne 0) {
            throw "$Name failed with exit code $commandExit"
        }
        $status = if ($RequireSuccess) { 'PASS' } else { 'OBSERVED' }
        Add-Result $Name $status "exit=$commandExit; inspect capture and policy log"
    } catch {
        $_ | Out-File -LiteralPath $path -Encoding UTF8
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
        } elseif ($script:FakeNetProcess.ExitCode -ne 0) {
            Add-Result 'FakeNetStop' 'FAIL' ("exit={0}" -f $script:FakeNetProcess.ExitCode)
            $script:ExitCode = 1
        } else {
            Add-Result 'FakeNetStop' 'PASS' 'graceful stop completed'
        }
    }
    if ($script:PktmonStarted) {
        $pktmonStopLog = Join-Path $script:LogDir 'pktmon-stop.log'
        & pktmon.exe stop *> $pktmonStopLog
        $script:PktmonStarted = $false
        $etl = Join-Path $script:LogDir 'independent-capture.etl'
        $pcap = Join-Path $script:LogDir 'independent-capture.pcapng'
        if (Test-Path -LiteralPath $etl) {
            $pktmonConvertLog = Join-Path $script:LogDir 'pktmon-convert.log'
            & pktmon.exe etl2pcap $etl --out $pcap *> $pktmonConvertLog
            if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $pcap) -or
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
    if ($ExternalDnsServer) {
        $arguments += @('-ExternalDnsServer', $ExternalDnsServer)
    }
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
$script:LogDir = Join-Path $logRoot ("domain-allowlist-{0}" -f $stamp)
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

    $python = (Get-Command $PythonPath -ErrorAction Stop).Source
    $dependencyLog = Join-Path $script:LogDir 'dependency-check.log'
    & $python -c "import dpkt,dnslib,netifaces,pydivert; print('dependencies ok')" *> $dependencyLog
    if ($LASTEXITCODE -ne 0) {
        Add-Result 'Dependencies' 'FAIL' 'install requirements before retrying; no automatic download attempted'
        throw 'Required Python dependencies are missing.'
    }
    Add-Result 'Dependencies' 'PASS'

    Push-Location $repoRoot
    try {
        foreach ($test in @('test_egresspolicy.py', 'test_dns_policy.py',
                'test_tlshello.py', 'test_windows_egress_verdict.py')) {
            $testLog = Join-Path $script:LogDir ($test + '.log')
            & $python -m unittest discover -s test -p $test -v *> $testLog
            if ($LASTEXITCODE -ne 0) {
                Add-Result $test 'FAIL' 'see unit-test log'
                throw "Unit test failed: $test"
            }
            Add-Result $test 'PASS'
        }
    } finally {
        Pop-Location
    }

    $template = Join-Path $repoRoot 'fakenet\configs\domain_allowlist_windows.ini'
    $runtimeConfig = Join-Path $script:LogDir 'domain_allowlist_runtime.ini'
    (Get-Content -LiteralPath $template -Raw).Replace('__EXTERNAL_DNS__', $resolver) |
        Set-Content -LiteralPath $runtimeConfig -Encoding ASCII

    $pktmon = Get-Command pktmon.exe -ErrorAction SilentlyContinue
    if (-not $pktmon) {
        Add-Result 'IndependentCapture' 'FAIL' 'pktmon.exe is required for independent evidence'
        throw 'pktmon.exe is unavailable.'
    }
    $etl = Join-Path $script:LogDir 'independent-capture.etl'
    $pktmonStartLog = Join-Path $script:LogDir 'pktmon-start.log'
    & pktmon.exe start --capture --pkt-size 0 --file-name $etl *> $pktmonStartLog
    if ($LASTEXITCODE -ne 0) {
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
    $script:FakeNetProcess = Start-Process -FilePath $python -ArgumentList $arguments `
        -WorkingDirectory $repoRoot -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr

    $ready = $false
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Seconds 1
        if ($script:FakeNetProcess.HasExited) { break }
        if ((Test-Path $fakeLog) -and
                (Select-String -Path $fakeLog -Pattern 'DOMAIN_ALLOWLIST_READY' -Quiet)) {
            $ready = $true
            break
        }
    }
    if (-not $ready) {
        Add-Result 'FakeNetReady' 'FAIL' 'process exited or readiness timeout'
        throw 'FakeNet did not become ready.'
    }
    Add-Result 'FakeNetReady' 'PASS'

    Invoke-LoggedCommand 'dns-allowed' {
        Resolve-DnsName api.deepseek.com -Type A -DnsOnly
    }
    $allowedIp = @(Resolve-DnsName api.deepseek.com -Type A -DnsOnly |
        Where-Object Type -eq 'A' | Select-Object -First 1 -ExpandProperty IPAddress)
    if (-not $allowedIp) { throw 'Allowed domain returned no A record.' }
    $allowedIp = [string]$allowedIp[0]
    Add-Result 'AllowedIPv4' 'PASS' $allowedIp

    Invoke-LoggedCommand -Name 'positive-api-deepseek' -RequireSuccess -Command {
        & curl.exe --noproxy '*' -v --http1.1 --ssl-no-revoke `
            --connect-timeout 10 --max-time 30 https://api.deepseek.com/
    }
    Invoke-LoggedCommand -Name 'positive-ipv6-loopback' -RequireSuccess -Command {
        & ping.exe -6 ::1 -n 1
    }
    Invoke-LoggedCommand 'negative-example-https' {
        & curl.exe --noproxy '*' -vk --connect-timeout 5 --max-time 10 `
            https://example.com/
    }
    Invoke-LoggedCommand 'negative-allowed-http' {
        & curl.exe --noproxy '*' -v --connect-timeout 5 --max-time 10 `
            http://api.deepseek.com/
    }
    Invoke-LoggedCommand 'negative-direct-ip' {
        & curl.exe --noproxy '*' -vk --connect-timeout 5 --max-time 10 `
            ("https://{0}/" -f $allowedIp)
    }
    Invoke-LoggedCommand 'negative-wrong-sni' {
        & curl.exe --noproxy '*' -vk --connect-timeout 5 --max-time 10 `
            --resolve ("example.com:443:{0}" -f $allowedIp) https://example.com/
    }
    Invoke-LoggedCommand 'negative-ipv6' {
        & curl.exe --noproxy '*' -6 -vk --connect-timeout 5 --max-time 10 `
            https://api.deepseek.com/
    }
    Invoke-LoggedCommand 'negative-doh' {
        & curl.exe --noproxy '*' -vk --connect-timeout 5 --max-time 10 `
            https://cloudflare-dns.com/dns-query
    }
    Invoke-LoggedCommand 'negative-external-dns' {
        Resolve-DnsName example.com -Type A -Server 8.8.8.8 -DnsOnly
    }
    Invoke-LoggedCommand 'negative-direct-relay' {
        & $python -c "import socket; s=socket.socket(); s.settimeout(3); s.connect(('127.0.0.1',38927)); s.sendall(b'GET / HTTP/1.0\\r\\n\\r\\n'); s.recv(1)"
    }
    Invoke-LoggedCommand 'negative-dot' {
        & $python -c "import socket; s=socket.socket(); s.settimeout(3); s.connect(('1.1.1.1',853)); s.sendall(b'blocked-dot-probe'); s.close()"
    }
    Invoke-LoggedCommand 'negative-udp443' {
        & $python -c "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(b'blocked-quic-probe',('1.1.1.1',443)); s.close()"
    }

    Start-Sleep -Seconds 3
    $fakeText = Get-Content -LiteralPath $fakeLog -Raw
    foreach ($event in @('DOMAIN_ALLOWLIST_READY', 'DNS_LEASE_ADD', 'REDIRECT_TLS_RELAY',
            'TLS_SNI_ALLOW', 'ALLOW_INTERNAL_UPSTREAM', 'DROP_EXTERNAL')) {
        if ($fakeText -notmatch [regex]::Escape($event)) {
            Add-Result ("Event-{0}" -f $event) 'FAIL' 'required event absent'
            throw "Required policy event absent: $event"
        }
        Add-Result ("Event-{0}" -f $event) 'PASS'
    }
    if ($fakeText -match 'policy_exception') {
        Add-Result 'PolicyExceptions' 'FAIL' 'policy_exception present in FakeNet log'
        throw 'Policy exception occurred.'
    }
    Add-Result 'PolicyExceptions' 'PASS'
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
    $zip = Join-Path $logRoot ("DomainAllowList-TestLogs-{0}.zip" -f $stamp)
    Compress-Archive -LiteralPath $script:LogDir -DestinationPath $zip -Force
    Write-Host "Logs packaged at: $zip"
}

exit $script:ExitCode
