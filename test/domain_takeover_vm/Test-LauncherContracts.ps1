[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$LauncherPath,
    [Parameter(Mandatory=$true)][string]$LogDirectory
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
    $probeAst = Import-ReviewedFunction $ast 'Invoke-TakeoverProbe'

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

    $realRoute = Get-TakeoverRouteSnapshot '192.168.204.1'
    Assert-Contract ($realRoute.next_hop -eq '0.0.0.0') `
        'Real route is not on-link.'
    Assert-Contract ($realRoute.destination_prefix -ne '0.0.0.0/0') `
        'Real route unexpectedly uses the default route.'
    Add-Pass 'RouteUniqueOnLink' $realRoute.destination_prefix

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
