[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$LauncherPath,
    [Parameter(Mandatory=$true)][string]$RunnerPath,
    [Parameter(Mandatory=$true)][string]$LogDirectory,
    [switch]$SkipLiveRoute
)

$ErrorActionPreference = 'Stop'
$resultPath = Join-Path $LogDirectory 'launcher-contract-tests.log'
$results = New-Object Collections.Generic.List[string]

function Assert-Contract {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Add-Pass {
    param([string]$Name, [string]$Detail = '')
    $line = 'PASS {0} {1}' -f $Name, $Detail
    $script:results.Add($line)
    Write-Host $line
}

function Import-ReviewedFunction {
    param($Ast, [string]$Name)
    $matches = @($Ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq $Name
    }, $true))
    Assert-Contract ($matches.Count -eq 1) "Function AST mismatch: $Name"
    $pattern = '^function\s+' + [regex]::Escape($Name)
    $definition = $matches[0].Extent.Text -replace $pattern, ('function script:' + $Name)
    Invoke-Expression $definition
    return $matches[0]
}

function Assert-RouteArgumentFormatting {
    param($FunctionAst)
    $assignments = @($FunctionAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left.Extent.Text -eq '$startInfo.Arguments'
    }, $true))
    Assert-Contract ($assignments.Count -eq 1) 'Route argument assignment count mismatch.'
    $scriptPath = 'C:\Reviewed Path\Test-ReviewedIPv4Routes.ps1'
    $encoded = 'W10='
    $readyFile = 'C:\Reviewed Path\route.ready'
    $goFile = 'C:\Reviewed Path\route.go'
    $rendered = Invoke-Expression $assignments[0].Right.Extent.Text
    Assert-Contract ($rendered -notmatch '\{[0-3]\}') 'Route arguments retain a format placeholder.'
    foreach ($required in @($scriptPath, $encoded, $readyFile, $goFile)) {
        Assert-Contract ($rendered.Contains($required)) "Route arguments omitted: $required"
    }
}

function New-FakeClient {
    param($Task)
    $client = [PSCustomObject]@{
        Task = $Task
        Closed = 0
        Disposed = 0
    }
    $client | Add-Member ScriptMethod ConnectAsync {
        param($Address, $Port)
        return $this.Task
    }
    $client | Add-Member ScriptMethod Close { $this.Closed++ }
    $client | Add-Member ScriptMethod Dispose { $this.Disposed++ }
    return $client
}

function Invoke-FakeProbeCase {
    param([string]$Name, $Task, [string]$Expected)
    $script:CurrentFakeClient = New-FakeClient $Task
    $path = Join-Path $LogDirectory ("probe-$Name.log")
    Invoke-TakeoverProbe -Target '192.168.204.1' -PortsValue '443' `
        -TimeoutMs 500 -LogPath $path
    $line = Get-Content -LiteralPath $path -Raw
    Assert-Contract ($line -match ("status={0}" -f $Expected)) `
        "Probe $Name did not produce $Expected"
    Assert-Contract ($script:CurrentFakeClient.Closed -ge 1) `
        "Probe $Name did not close the client"
    Assert-Contract ($script:CurrentFakeClient.Disposed -ge 1) `
        "Probe $Name did not dispose the client"
    Add-Pass "Probe-$Name" $Expected
}

try {
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile(
        $LauncherPath, [ref]$tokens, [ref]$errors)
    Assert-Contract ($errors.Count -eq 0) 'Launcher PowerShell parse failed.'
    $prefixAst = Import-ReviewedFunction $ast 'Test-IPv4PrefixContains'
    $routeAst = Import-ReviewedFunction $ast 'Get-TakeoverRouteSnapshot'
    $reviewedValueAst = Import-ReviewedFunction $ast 'Get-ReviewedRulesValue'
    $reviewedRulesAst = Import-ReviewedFunction $ast 'Get-NormalizedReviewedRules'
    $reviewedGlobalAst = Import-ReviewedFunction $ast 'Test-ReviewedGlobalIPv4'
    $reviewedDnsAst = Import-ReviewedFunction $ast 'Assert-ReviewedDnsFreshness'
    $reviewedRouteAst = Import-ReviewedFunction $ast 'Invoke-ReviewedRoutePreflight'
    Assert-RouteArgumentFormatting $reviewedRouteAst
    $launcherTrafficReadyAst = Import-ReviewedFunction $ast `
        'Test-FakeNetTrafficReady'
    $probeAst = Import-ReviewedFunction $ast 'Invoke-TakeoverProbe'
    $stopReasonAst = Import-ReviewedFunction $ast 'Get-FakeNetStopReason'
    $liveLogAst = Import-ReviewedFunction $ast 'Show-FakeNetLogUntilStop'

    $runnerTokens = $null
    $runnerErrors = $null
    $runnerAst = [Management.Automation.Language.Parser]::ParseFile(
        $RunnerPath, [ref]$runnerTokens, [ref]$runnerErrors)
    Assert-Contract ($runnerErrors.Count -eq 0) 'Runner PowerShell parse failed.'
    $runnerRouteDefinitions = @($runnerAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq 'Invoke-ReviewedRoutePreflight'
    }, $true))
    $runnerRouteCalls = @($runnerAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -eq 'Invoke-ReviewedRoutePreflight'
    }, $true))
    Assert-Contract ($runnerRouteDefinitions.Count -eq 1) `
        'Runner must define Invoke-ReviewedRoutePreflight exactly once.'
    Assert-Contract ($runnerRouteCalls.Count -eq 1) `
        'Runner must call Invoke-ReviewedRoutePreflight exactly once.'
    Assert-RouteArgumentFormatting $runnerRouteDefinitions[0]
    $runnerTrafficReadyAst = Import-ReviewedFunction $runnerAst `
        'Test-FakeNetTrafficReady'
    foreach ($required in @('WaitForExit(2000)',
            'ElapsedMilliseconds -ge 15000',
            'Test-ReviewedIPv4Routes.ps1', 'RedirectStandardOutput',
            'RedirectStandardError', 'ReadyFile', 'GoFile')) {
        Assert-Contract ($runnerRouteDefinitions[0].Extent.Text.Contains($required)) `
            "Reviewed route runner gate is missing: $required"
    }
    Add-Pass 'RunnerReviewedRouteDeadlineStaticBoundary'

    $runnerProfileDefinitions = @($runnerAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq 'Invoke-ProfileRun'
    }, $true))
    Assert-Contract ($runnerProfileDefinitions.Count -eq 1) 'Runner must define Invoke-ProfileRun exactly once.'
    $runnerProfileText = $runnerProfileDefinitions[0].Extent.Text
    foreach ($required in @('FakeNet exited before readiness',
            'fakenet-stderr.log', '.ExitCode')) {
        Assert-Contract ($runnerProfileText.Contains($required)) "Runner early-exit readiness diagnostic is missing: $required"
    }
    Add-Pass 'RunnerReadinessEarlyExitStaticBoundary'

    foreach ($readyContract in @(
            [PSCustomObject]@{ Name='Launcher'; Ast=$launcherTrafficReadyAst },
            [PSCustomObject]@{ Name='Runner'; Ast=$runnerTrafficReadyAst })) {
        $readyPath = Join-Path $LogDirectory (
            'traffic-ready-{0}.log' -f $readyContract.Name.ToLowerInvariant())
        Set-Content -LiteralPath $readyPath -Value 'IP_ALLOW_READY' `
            -Encoding ASCII
        Assert-Contract (-not (Test-FakeNetTrafficReady $readyPath)) `
            "$($readyContract.Name) accepted constructor-only readiness."
        Add-Content -LiteralPath $readyPath `
            -Value 'DOMAIN_ALLOWLIST_READY' -Encoding ASCII
        Assert-Contract (Test-FakeNetTrafficReady $readyPath) `
            "$($readyContract.Name) rejected complete traffic readiness."
        foreach ($required in @('IP_ALLOW_READY', 'DOMAIN_ALLOWLIST_READY')) {
            Assert-Contract ($readyContract.Ast.Extent.Text.Contains($required)) `
                "$($readyContract.Name) traffic gate omitted: $required"
        }
    }
    Add-Pass 'ReviewedTrafficReadyRequiresPolicyAndWinDivert'

    $probeText = $probeAst.Extent.Text
    foreach ($required in @('IPAddress]::Parse', 'ConnectAsync', '.Wait(',
            '.Close()', '.Dispose()')) {
        Assert-Contract ($probeText.Contains($required)) `
            "Probe is missing reviewed operation: $required"
    }
    foreach ($forbidden in @('GetStream', '.Send(', '.Write(',
            'Resolve-DnsName', 'GetHost')) {
        Assert-Contract (-not $probeText.Contains($forbidden)) `
            "Probe contains forbidden operation: $forbidden"
    }
    Add-Pass 'ProbeStaticBoundary'

    $liveLogText = $liveLogAst.Extent.Text
    foreach ($required in @('TreatControlCAsInput', 'StopFlag',
            'StopRequestReader', 'draining FakeNet-NG shutdown logs')) {
        Assert-Contract ($liveLogText.Contains($required)) `
            "Live log stop handling is missing: $required"
    }
    Add-Pass 'LiveLogStaticBoundary'

    $singleConfig = Join-Path $LogDirectory 'reviewed-single.ini'
    @('[Diverter]',
      'ExternalAllowedIPv4Rules: TCP/110.242.69.21/443,UDP/110.242.70.57/*') |
        Set-Content -LiteralPath $singleConfig -Encoding ASCII
    $multiConfig = Join-Path $LogDirectory 'reviewed-multi.ini'
    @('[Diverter]',
      'ExternalAllowedIPv4Rules: TCP/110.242.69.21/443,',
      '    UDP/110.242.70.57/*') |
        Set-Content -LiteralPath $multiConfig -Encoding ASCII
    $singleRules = @(Get-NormalizedReviewedRules (
        Get-ReviewedRulesValue $singleConfig))
    $multiRules = @(Get-NormalizedReviewedRules (
        Get-ReviewedRulesValue $multiConfig))
    Assert-Contract (($singleRules -join ',') -eq ($multiRules -join ',')) `
        'Single-line and indented continuation rules normalized differently.'
    Add-Pass 'ReviewedRuleContinuation'

    Assert-Contract (Test-ReviewedGlobalIPv4 '110.242.69.21') `
        'Reviewed global IPv4 was rejected.'
    foreach ($invalid in @('192.168.204.1', '100.64.0.1', '127.0.0.1',
            '169.254.1.1', '192.0.0.9', '192.88.99.1',
            '198.51.100.1', '224.0.0.1')) {
        Assert-Contract (-not (Test-ReviewedGlobalIPv4 $invalid)) `
            "Non-global reviewed IPv4 was accepted: $invalid"
    }
    Add-Pass 'ReviewedRuleGlobalOnly'

    $badConfig = Join-Path $LogDirectory 'reviewed-reserved-option.ini'
    @('[Diverter]', 'ExternalAllowedIPv4Rules: TCP/110.242.69.21/443',
      'UDP/110.242.70.57/53 = stray') |
        Set-Content -LiteralPath $badConfig -Encoding ASCII
    $failed = $false
    try { Get-ReviewedRulesValue $badConfig | Out-Null } catch { $failed = $true }
    Assert-Contract $failed 'Reserved TCP/UDP option prefix was not rejected.'
    Add-Pass 'ReviewedRuleReservedOption'

    foreach ($required in @('WaitForExit(2000)',
            'ElapsedMilliseconds -ge 15000',
            'Test-ReviewedIPv4Routes.ps1', 'RedirectStandardOutput',
            'RedirectStandardError', 'ReadyFile', 'GoFile')) {
        Assert-Contract ($reviewedRouteAst.Extent.Text.Contains($required)) `
            "Reviewed route launcher gate is missing: $required"
    }
    Add-Pass 'ReviewedRouteDeadlineStaticBoundary'

    $routeChecker = Join-Path (Split-Path -Parent $LauncherPath) `
        'Test-ReviewedIPv4Routes.ps1'
    $routeCheckerText = Get-Content -LiteralPath $routeChecker -Raw
    foreach ($required in @('$routeProbeUdpPort = 9', '.Connect(',
            'Get-NetRoute', 'Get-NetIPAddress', 'Get-NetIPInterface',
            'Import-Module NetTCPIP', 'ReadyFile', 'GoFile')) {
        Assert-Contract ($routeCheckerText.Contains($required)) `
            "Reviewed route checker is missing: $required"
    }
    foreach ($forbidden in @('.Send(', '.SendTo(', 'Set-NetRoute',
            'New-NetRoute', 'Remove-NetRoute', 'route add', 'route delete',
            'Default route is not permitted',
            'Gateway route is not permitted')) {
        Assert-Contract (-not $routeCheckerText.Contains($forbidden)) `
            "Reviewed route checker contains mutation/send operation: $forbidden"
    }
    Add-Pass 'ReviewedRouteReadOnlyNoPayload'

    $script:DnsResolverObserved = $null
    function global:Resolve-DnsName {
        param($Name, $Type, $Server, [switch]$DnsOnly, $ErrorAction)
        $script:DnsResolverObserved = $Server
        return @(
            [PSCustomObject]@{Name='www.baidu.com'; Type='CNAME';
                IPAddress=$null; NameHost='www.a.shifen.com'; TTL=100},
            [PSCustomObject]@{Name='www.a.shifen.com'; Type='A';
                IPAddress='110.242.69.21'; NameHost=$null; TTL=100},
            [PSCustomObject]@{Name='www.a.shifen.com'; Type='A';
                IPAddress='110.242.70.57'; NameHost=$null; TTL=100})
    }
    try {
        $dnsLog = Join-Path $LogDirectory 'dns-freshness.log'
        $addresses = @(Assert-ReviewedDnsFreshness -Hostname 'www.baidu.com' `
            -Target '110.242.69.21' -Resolver '10.0.0.1' -LogPath $dnsLog)
        Assert-Contract ('110.242.69.21' -in $addresses) `
            'DNS freshness omitted the pinned target.'
        Assert-Contract ($script:DnsResolverObserved -eq '10.0.0.1') `
            'DNS freshness did not use the pre-start resolver.'
        $failed = $false
        try {
            Assert-ReviewedDnsFreshness -Hostname 'www.baidu.com' `
                -Target '110.242.69.22' -Resolver '10.0.0.1' `
                -LogPath $dnsLog | Out-Null
        } catch { $failed = $true }
        Assert-Contract $failed 'DNS freshness selected an alternate address.'
    } finally {
        Remove-Item Function:\global:Resolve-DnsName -ErrorAction SilentlyContinue
    }
    Add-Pass 'ReviewedDnsFreshnessNoFallback'

    $ctrlCKey = [PSCustomObject]@{
        Key = [ConsoleKey]::C
        KeyChar = [char]3
        Modifiers = [ConsoleModifiers]::Control
    }
    $enterKey = [PSCustomObject]@{
        Key = [ConsoleKey]::Enter
        KeyChar = [char]13
        Modifiers = [ConsoleModifiers]0
    }
    $otherKey = [PSCustomObject]@{
        Key = [ConsoleKey]::A
        KeyChar = [char]'a'
        Modifiers = [ConsoleModifiers]0
    }
    Assert-Contract ((Get-FakeNetStopReason $ctrlCKey) -eq 'Ctrl+C') `
        'Ctrl+C was not recognized as a safe stop key.'
    Assert-Contract ((Get-FakeNetStopReason $enterKey) -eq 'Enter') `
        'Enter was not recognized as a safe stop key.'
    Assert-Contract ($null -eq (Get-FakeNetStopReason $otherKey)) `
        'An unrelated key was recognized as a stop request.'
    Add-Pass 'LiveLogStopKeys'

    $livePath = Join-Path $LogDirectory 'live-log-contract.log'
    $stopFlag = Join-Path $LogDirectory 'live-log-contract.stop'
    Set-Content -LiteralPath $livePath -Value 'LIVE_BEFORE_STOP' `
        -Encoding Default
    Remove-Item -LiteralPath $stopFlag -Force -ErrorAction SilentlyContinue
    $fakeProcess = [PSCustomObject]@{
        HasExited = $false
        LogPath = $livePath
        StopFlag = $stopFlag
    }
    $fakeProcess | Add-Member ScriptMethod Refresh {
        if ((Test-Path -LiteralPath $this.StopFlag) -and
                -not $this.HasExited) {
            $payload = [Text.Encoding]::Default.GetBytes(
                "FAKENET_STOPPING_MARKER`r`nFAKENET_RESTORED_MARKER`r`n")
            $writer = [IO.File]::Open(
                $this.LogPath, [IO.FileMode]::Open, [IO.FileAccess]::Write,
                [IO.FileShare]::ReadWrite)
            try {
                $null = $writer.Seek(0, [IO.SeekOrigin]::End)
                $writer.Write($payload, 0, $payload.Length)
                $writer.Flush()
            } finally {
                $writer.Dispose()
            }
            $this.HasExited = $true
        }
    }
    $script:StopReaderCalls = 0
    $stopReader = {
        $script:StopReaderCalls++
        if ($script:StopReaderCalls -eq 1) { return 'Ctrl+C' }
        return $null
    }
    $liveOutput = @(Show-FakeNetLogUntilStop -Process $fakeProcess `
        -Path $livePath -StopFlag $stopFlag `
        -StopRequestReader $stopReader 6>&1)
    $liveOutputText = ($liveOutput | ForEach-Object { $_.ToString() }) -join "`n"
    Assert-Contract (Test-Path -LiteralPath $stopFlag) `
        'Ctrl+C contract did not create the safe stop flag.'
    Assert-Contract $fakeProcess.HasExited `
        'Live log contract did not wait for the fake process to exit.'
    Assert-Contract ($liveOutputText.Contains('FAKENET_STOPPING_MARKER')) `
        'Shutdown log was not forwarded after Ctrl+C.'
    Assert-Contract ($liveOutputText.Contains('FAKENET_RESTORED_MARKER')) `
        'Final restoration log was not drained after Ctrl+C.'
    Add-Pass 'LiveLogCtrlCDrain'

    $skipPath = Join-Path $LogDirectory 'probe-skip.log'
    Invoke-TakeoverProbe -Target '192.168.204.1' -PortsValue '' `
        -TimeoutMs 500 -LogPath $skipPath
    Assert-Contract ((Get-Content -Raw -LiteralPath $skipPath) -match
        'TAKEOVER_PROBE_SKIP reason=not_configured') 'Probe skip mismatch.'
    Add-Pass 'ProbeSkip'

    function global:New-Object {
        param([Parameter(Position=0)]$TypeName)
        if ([string]$TypeName -eq 'Net.Sockets.TcpClient') {
            return $script:CurrentFakeClient
        }
        throw "Unexpected New-Object call: $TypeName"
    }
    try {
        $success = [Threading.Tasks.TaskCompletionSource[bool]]::new()
        $success.SetResult($true)
        Invoke-FakeProbeCase 'open' $success.Task 'OPEN'

        $refused = [Threading.Tasks.TaskCompletionSource[bool]]::new()
        $refused.SetException([Net.Sockets.SocketException]::new(
            [int][Net.Sockets.SocketError]::ConnectionRefused))
        Invoke-FakeProbeCase 'refused' $refused.Task 'CLOSED'

        $other = [Threading.Tasks.TaskCompletionSource[bool]]::new()
        $other.SetException([Net.Sockets.SocketException]::new(
            [int][Net.Sockets.SocketError]::HostUnreachable))
        Invoke-FakeProbeCase 'error' $other.Task 'ERROR'

        $timeout = [PSCustomObject]@{
            Status = [Threading.Tasks.TaskStatus]::WaitingForActivation
        }
        $timeout | Add-Member ScriptMethod Wait { param($Milliseconds) $false }
        Invoke-FakeProbeCase 'timeout' $timeout 'TIMEOUT'
    } finally {
        Remove-Item Function:\global:New-Object -ErrorAction SilentlyContinue
    }

    if (-not $SkipLiveRoute) {
        $realRoute = Get-TakeoverRouteSnapshot '192.168.204.1'
        Assert-Contract ($realRoute.next_hop -eq '0.0.0.0') `
            'Real route is not on-link.'
        Assert-Contract ($realRoute.destination_prefix -ne '0.0.0.0/0') `
            'Real route unexpectedly uses the default route.'
        Add-Pass 'RouteUniqueOnLink' $realRoute.destination_prefix
    } else {
        Add-Pass 'RouteUniqueOnLink' 'skipped outside reviewed VM'
    }

    $routeText = $routeAst.Extent.Text
    foreach ($forbidden in @('Set-NetRoute', 'New-NetRoute',
            'Remove-NetRoute', 'route add', 'route delete')) {
        Assert-Contract (-not $routeText.Contains($forbidden)) `
            "Route preflight contains mutation command: $forbidden"
    }
    Add-Pass 'RouteStaticReadOnly'

    function global:Get-NetIPInterface {
        [PSCustomObject]@{
            InterfaceIndex = 7
            InterfaceAlias = 'Ethernet0'
            InterfaceMetric = 20
            ConnectionState = 'Connected'
        }
    }
    function global:Get-NetIPAddress { @() }
    try {
        $script:FakeRoutes = @()
        function global:Get-NetRoute { $script:FakeRoutes }
        foreach ($case in @(
                [PSCustomObject]@{ Name='missing'; Routes=@() },
                [PSCustomObject]@{ Name='default'; Routes=@(
                    [PSCustomObject]@{InterfaceIndex=7; DestinationPrefix='0.0.0.0/0'; NextHop='0.0.0.0'; RouteMetric=10}) },
                [PSCustomObject]@{ Name='gateway'; Routes=@(
                    [PSCustomObject]@{InterfaceIndex=7; DestinationPrefix='192.168.204.0/24'; NextHop='192.168.204.254'; RouteMetric=10}) },
                [PSCustomObject]@{ Name='ambiguous'; Routes=@(
                    [PSCustomObject]@{InterfaceIndex=7; DestinationPrefix='192.168.204.0/24'; NextHop='0.0.0.0'; RouteMetric=10},
                    [PSCustomObject]@{InterfaceIndex=7; DestinationPrefix='192.168.204.0/24'; NextHop='0.0.0.0'; RouteMetric=10}) })) {
            $script:FakeRoutes = $case.Routes
            $failed = $false
            try {
                Get-TakeoverRouteSnapshot '192.168.204.1' | Out-Null
            } catch {
                $failed = $true
            }
            Assert-Contract $failed "Route case did not fail closed: $($case.Name)"
            Add-Pass "Route-$($case.Name)"
        }
    } finally {
        Remove-Item Function:\global:Get-NetRoute -ErrorAction SilentlyContinue
        Remove-Item Function:\global:Get-NetIPAddress -ErrorAction SilentlyContinue
        Remove-Item Function:\global:Get-NetIPInterface -ErrorAction SilentlyContinue
    }

    $results | Set-Content -LiteralPath $resultPath -Encoding UTF8
    exit 0
} catch {
    $results | Set-Content -LiteralPath $resultPath -Encoding UTF8
    $_ | Format-List * -Force | Out-File -LiteralPath $resultPath `
        -Append -Encoding UTF8
    exit 1
}
