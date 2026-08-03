[CmdletBinding()]
param(
    [string]$PythonPath = 'python.exe'
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
    return $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-IsVirtualMachine {
    $system = Get-CimInstance Win32_ComputerSystem
    $identity = ('{0} {1}' -f $system.Manufacturer,
        $system.Model).ToLowerInvariant()
    return $identity -match `
        'virtual|vmware|virtualbox|kvm|qemu|hyper-v|xen|parallels'
}

function Resolve-RepositoryRoot {
    $candidates = @(
        $PSScriptRoot,
        (Join-Path $PSScriptRoot 'flare-fakenet-ng'),
        (Join-Path $PSScriptRoot '..\..')
    )
    foreach ($candidate in $candidates) {
        $resolved = Resolve-Path -LiteralPath $candidate `
            -ErrorAction SilentlyContinue
        if ($resolved -and (Test-Path -LiteralPath `
                (Join-Path $resolved.Path 'fakenet\fakenet.py'))) {
            return $resolved.Path
        }
    }
    throw 'Cannot locate the flare-fakenet-ng repository.'
}

function Get-DnsSnapshot {
    return @(Get-DnsClientServerAddress -AddressFamily IPv4 `
            -ErrorAction Stop |
        Sort-Object InterfaceIndex |
        ForEach-Object {
            '{0}|{1}' -f $_.InterfaceIndex,
                (@($_.ServerAddresses) -join ',')
        })
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
                return [PSCustomObject]@{
                    InterfaceAlias =
                        $interfaces[$route.InterfaceIndex].InterfaceAlias
                    Address = $candidate
                }
            }
        }
    }
    throw ('No usable IPv4 DNS server exists on a connected ' +
        'default-route interface. FakeNet-NG was not started.')
}

function Invoke-NativeCaptured {
    param(
        [scriptblock]$Command,
        [string]$Path
    )
    $previousPreference = $ErrorActionPreference
    try {
        # Windows PowerShell 5.1 wraps native stderr as ErrorRecord objects.
        $ErrorActionPreference = 'Continue'
        $records = @(& $Command 2>&1)
        $nativeExitCode = [int]$LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    $records | Out-File -LiteralPath $Path -Encoding UTF8
    return $nativeExitCode
}

$vmIdentity = Get-CimInstance Win32_ComputerSystem
if (-not (Test-IsVirtualMachine)) {
    Write-Error (('REFUSED: this machine does not identify as a VM ' +
        '({0} / {1}). The launcher will not start FakeNet-NG on a ' +
        'possible host.') -f $vmIdentity.Manufacturer, $vmIdentity.Model)
    exit 40
}

if (-not (Test-IsAdministrator)) {
    $arguments = @('-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', ('"{0}"' -f $PSCommandPath))
    if ($PythonPath -ne 'python.exe') {
        $arguments += @('-PythonPath', ('"{0}"' -f $PythonPath))
    }
    $elevated = Start-Process powershell.exe -Verb RunAs -Wait -PassThru `
        -ArgumentList $arguments
    exit $elevated.ExitCode
}

try {
    $repoRoot = Resolve-RepositoryRoot
    $logRoot = Join-Path $repoRoot 'dist\Logs'
    New-Item -ItemType Directory -Path $logRoot -Force | Out-Null

    $script:LockPath = Join-Path $logRoot 'domain-allowlist-start.lock'
    try {
        $script:LockStream = [IO.File]::Open(
            $script:LockPath,
            [IO.FileMode]::OpenOrCreate,
            [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::None)
        $script:LockOwned = $true
    } catch {
        throw ('Another one-click FakeNet-NG launcher appears to be running. ' +
            'Stop it before starting a second instance.')
    }

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $script:LogDir = Join-Path $logRoot `
        ('domain-allowlist-start-{0}' -f $stamp)
    New-Item -ItemType Directory -Path $script:LogDir -Force | Out-Null
    Start-Transcript -LiteralPath `
        (Join-Path $script:LogDir 'launcher-transcript.log') | Out-Null
    $script:TranscriptStarted = $true

    Get-NetIPAddress | Format-List * |
        Out-File (Join-Path $script:LogDir 'ip-before.txt')
    Get-DnsClientServerAddress | Format-List * |
        Out-File (Join-Path $script:LogDir 'dns-before.txt')
    $script:OriginalDnsSnapshot = Get-DnsSnapshot
    $script:NetworkSnapshotTaken = $true

    $ipv6Enabled = @(Get-NetAdapterBinding -ComponentID ms_tcpip6 |
        Where-Object Enabled).Count -gt 0
    if (-not $ipv6Enabled) {
        throw ('IPv6 is disabled. Keep IPv6 enabled so the reviewed policy ' +
            'can enforce and log the IPv6 boundary.')
    }

    $selection = Select-OriginalDnsServer
    $resolver = [string]$selection.Address
    Write-Host ('Using pre-start DNS: {0} ({1})' -f
        $resolver, $selection.InterfaceAlias) -ForegroundColor Cyan

    $python = (Get-Command $PythonPath -ErrorAction Stop).Source
    $dependencyLog = Join-Path $script:LogDir 'dependency-check.log'
    $dependencyExit = Invoke-NativeCaptured {
        & $python -c ('import dpkt,dnslib,netifaces,pydivert,' +
            'pyftpdlib,jinja2,OpenSSL,cryptography; ' +
            'print("dependencies ok")')
    } $dependencyLog
    if ($dependencyExit -ne 0) {
        throw ('Required Python dependencies are missing. See ' +
            $dependencyLog + '. No dependency was downloaded automatically.')
    }

    $template = Join-Path $repoRoot `
        'fakenet\configs\domain_allowlist_windows.ini'
    $templateText = Get-Content -LiteralPath $template -Raw
    if (([regex]::Matches($templateText,
                [regex]::Escape('__EXTERNAL_DNS__'))).Count -ne 1) {
        throw 'The reviewed configuration has an invalid DNS marker count.'
    }
    $runtimeConfig = Join-Path $script:LogDir `
        'domain_allowlist_runtime.ini'
    $templateText.Replace('__EXTERNAL_DNS__', $resolver) |
        Set-Content -LiteralPath $runtimeConfig -Encoding ASCII
    $fakeLog = Join-Path $script:LogDir 'fakenet.log'
    $stdoutLog = Join-Path $script:LogDir 'fakenet-stdout.log'
    $stderrLog = Join-Path $script:LogDir 'fakenet-stderr.log'
    $script:StopFlag = Join-Path $script:LogDir 'stop-fakenet.flag'

    @(
        'mode=DomainAllowList',
        'allowed_domain=api.deepseek.com',
        'allowed_tcp_port=443',
        ('dns_interface={0}' -f $selection.InterfaceAlias),
        ('dns_server={0}' -f $resolver),
        ('python={0}' -f $python),
        ('repository={0}' -f $repoRoot)
    ) | Set-Content -LiteralPath `
        (Join-Path $script:LogDir 'start-info.txt') -Encoding UTF8

    Write-Host ''
    Write-Host 'Starting FakeNet-NG with the reviewed Windows domain policy.' `
        -ForegroundColor Green
    Write-Host 'Allowed real egress: api.deepseek.com, TCP/443, exact TLS SNI.'
    Write-Host ('Plain logs: {0}' -f $script:LogDir)
    Write-Host ''

    $arguments = @('-m', 'fakenet.fakenet', '-c',
        ('"{0}"' -f $runtimeConfig), '-l', ('"{0}"' -f $fakeLog),
        '-f', ('"{0}"' -f $script:StopFlag), '-p', '-v')
    $script:FakeNetProcess = Start-Process -FilePath $python `
        -ArgumentList $arguments -WorkingDirectory $repoRoot `
        -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdoutLog `
        -RedirectStandardError $stderrLog
    $script:FakeNetProcess.EnableRaisingEvents = $true
    $null = $script:FakeNetProcess.Handle

    $ready = $false
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Seconds 1
        $script:FakeNetProcess.Refresh()
        if ($script:FakeNetProcess.HasExited) {
            break
        }
        if ((Test-Path -LiteralPath $fakeLog) -and
                (Select-String -LiteralPath $fakeLog `
                    -Pattern 'DOMAIN_ALLOWLIST_READY' -Quiet)) {
            $ready = $true
            break
        }
    }
    if (-not $ready) {
        throw ('FakeNet-NG exited early or did not become ready within ' +
            '30 seconds. See the plain logs for details.')
    }

    Write-Host 'FakeNet-NG is READY. You can start the sample now.' `
        -ForegroundColor Green
    Write-Host 'Keep this window open while the sample runs.'
    [void](Read-Host 'When analysis is finished, press Enter to stop safely')
    $script:ExitCode = 0
} catch {
    $script:ExitCode = 1
    Write-Host ''
    Write-Host ('START/RUN FAILED: {0}' -f $_.Exception.Message) `
        -ForegroundColor Red
    if ($script:LogDir) {
        $_ | Format-List * -Force | Out-File `
            (Join-Path $script:LogDir 'fatal-error.log')
    }
} finally {
    if ($script:FakeNetProcess) {
        try {
            $script:FakeNetProcess.Refresh()
            if (-not $script:FakeNetProcess.HasExited) {
                Write-Host 'Stopping FakeNet-NG and restoring network state...'
                Set-Content -LiteralPath $script:StopFlag -Value 'stop' `
                    -Encoding ASCII
                # The reviewed shutdown path owns DNS/network restoration. Do
                # not add a force-kill fallback that could interrupt cleanup.
                $script:FakeNetProcess.WaitForExit()
            }
            $script:FakeNetProcess.Refresh()
            $fakeNetExit = $script:FakeNetProcess.ExitCode
            if ($fakeNetExit -ne 0) {
                Write-Host "FakeNet-NG exit code: $fakeNetExit" `
                    -ForegroundColor Red
                $script:ExitCode = 1
            }
        } catch {
            Write-Host ('Unable to confirm FakeNet-NG shutdown: {0}' -f
                $_.Exception.Message) -ForegroundColor Red
            $script:ExitCode = 1
        }
    }
    if ($script:NetworkSnapshotTaken) {
        try {
            Get-DnsClientServerAddress | Format-List * |
                Out-File (Join-Path $script:LogDir 'dns-after.txt')
            Get-NetIPAddress | Format-List * |
                Out-File (Join-Path $script:LogDir 'ip-after.txt')
            $restoredDnsSnapshot = Get-DnsSnapshot
            $difference = @(Compare-Object `
                $script:OriginalDnsSnapshot $restoredDnsSnapshot)
            if ($difference.Count -eq 0) {
                Write-Host 'DNS restoration check: PASS' `
                    -ForegroundColor Green
            } else {
                $difference | Format-Table -AutoSize | Out-File `
                    (Join-Path $script:LogDir 'dns-restore-difference.txt')
                Write-Host ('DNS restoration check: FAIL. Disconnect the VM ' +
                    'network adapter and restore its snapshot before reconnecting.') `
                    -ForegroundColor Red
                $script:ExitCode = 1
            }
        } catch {
            Write-Host ('DNS restoration check failed: {0}. Disconnect the VM ' +
                'network adapter and restore its snapshot before reconnecting.' -f
                $_.Exception.Message) -ForegroundColor Red
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
