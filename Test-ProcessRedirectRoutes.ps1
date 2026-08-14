[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$TargetsBase64,
    [Parameter(Mandatory = $true)][string]$ReadyFile,
    [Parameter(Mandatory = $true)][string]$GoFile
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'test\process_redirect_vm\RouteTargetTools.ps1')
. (Join-Path $PSScriptRoot 'test\process_redirect_vm\RouteResultTools.ps1')
$targets = @(ConvertFrom-RouteTargetsBase64 $TargetsBase64)
if ($targets.Count -ne 2 -or
        @($targets | Select-Object -Unique).Count -ne 2) {
    throw 'Process redirect requires exactly two distinct route targets.'
}

Import-Module NetTCPIP -ErrorAction Stop
[IO.File]::WriteAllText($ReadyFile,'ready',[Text.Encoding]::ASCII)
$deadline = [Diagnostics.Stopwatch]::StartNew()
while (-not (Test-Path -LiteralPath $GoFile)) {
    if ($deadline.ElapsedMilliseconds -ge 15000) {
        throw 'Process route checker did not receive GO.'
    }
    Start-Sleep -Milliseconds 10
}

$results = @()
foreach ($target in $targets) {
    $parsed = $null
    if (-not [Net.IPAddress]::TryParse([string]$target,[ref]$parsed) -or
            $parsed.AddressFamily -ne 'InterNetwork' -or
            [string]$parsed -ne [string]$target) {
        throw ('Invalid process redirect route target: ' + $target)
    }
    $found = @(Find-NetRoute -RemoteIPAddress $target -ErrorAction Stop)
    $selection = ConvertFrom-FindNetRouteResult `
        -Result $found -Target ([string]$target)
    $route = $selection.NetRoute
    $source = [string]$selection.IPAddress
    $interface = Get-NetIPInterface -AddressFamily IPv4 `
        -InterfaceIndex $route.InterfaceIndex -ErrorAction Stop
    $address = @(Get-NetIPAddress -AddressFamily IPv4 `
        -InterfaceIndex $route.InterfaceIndex -IPAddress $source `
        -ErrorAction Stop)
    if ($address.Count -ne 1) {
        throw ('Frozen source address is not unique on its interface: ' + $source)
    }
    $results += [PSCustomObject]@{
        target_ipv4 = [string]$target
        interface_index = [int]$route.InterfaceIndex
        interface_alias = [string]$interface.InterfaceAlias
        source_ipv4 = $source
        destination_prefix = [string]$route.DestinationPrefix
        next_hop = [string]$route.NextHop
        route_metric = [uint64]$route.RouteMetric
        interface_metric = [uint64]$interface.InterfaceMetric
        weak_host_send = [string]$interface.WeakHostSend
        weak_host_receive = [string]$interface.WeakHostReceive
        address_state = [string]$address[0].AddressState
        skip_as_source = [bool]$address[0].SkipAsSource
    }
}
@($results) | ConvertTo-Json -Compress
