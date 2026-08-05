[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$TargetsBase64)

$ErrorActionPreference = 'Stop'
$routeProbeUdpPort = 9

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
        if ($addressBytes[$index] -ne $networkBytes[$index]) { return $false }
    }
    $remainder = $length % 8
    if ($remainder -eq 0) { return $true }
    $mask = [int](256 - [Math]::Pow(2, 8 - $remainder))
    return (($addressBytes[$whole] -band $mask) -eq
        ($networkBytes[$whole] -band $mask))
}

$json = [Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String($TargetsBase64))
$targets = @($json | ConvertFrom-Json)
if ($targets.Count -lt 1 -or $targets.Count -gt 16 -or
        @($targets | Select-Object -Unique).Count -ne $targets.Count) {
    throw 'Reviewed route target collection is invalid.'
}

$interfaces = @{}
Get-NetIPInterface -AddressFamily IPv4 -ErrorAction Stop |
    Where-Object ConnectionState -eq 'Connected' |
    ForEach-Object { $interfaces[[int]$_.InterfaceIndex] = $_ }
$routes = @(Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore `
    -ErrorAction Stop)
$results = @()

foreach ($targetValue in $targets) {
    $target = [string]$targetValue
    $parsedTarget = $null
    if (-not [Net.IPAddress]::TryParse($target, [ref]$parsedTarget) -or
            $parsedTarget.AddressFamily -ne
                [Net.Sockets.AddressFamily]::InterNetwork -or
            $parsedTarget.ToString() -ne $target) {
        throw "Invalid reviewed route target: $target"
    }
    $matches = @(
        $routes | ForEach-Object {
            $index = [int]$_.InterfaceIndex
            if ($interfaces.ContainsKey($index) -and
                    (Test-IPv4PrefixContains $target $_.DestinationPrefix)) {
                $prefixLength = [int]$_.DestinationPrefix.Split('/')[1]
                [PSCustomObject]@{
                    Route = $_
                    PrefixLength = $prefixLength
                    TotalMetric = [uint64]$_.RouteMetric +
                        [uint64]$interfaces[$index].InterfaceMetric
                }
            }
        }
    )
    if ($matches.Count -eq 0) { throw "No route for $target" }
    $bestPrefix = ($matches | Measure-Object PrefixLength -Maximum).Maximum
    $prefixMatches = @($matches | Where-Object PrefixLength -eq $bestPrefix)
    $bestMetric = ($prefixMatches | Measure-Object TotalMetric -Minimum).Minimum
    $best = @($prefixMatches | Where-Object TotalMetric -eq $bestMetric)
    if ($best.Count -ne 1) { throw "Ambiguous route for $target" }
    $selected = $best[0]
    $route = $selected.Route
    $sourceAddresses = @(
        Get-NetIPAddress -AddressFamily IPv4 `
                -InterfaceIndex $route.InterfaceIndex -ErrorAction Stop |
            Where-Object {
                $_.AddressState -eq 'Preferred' -and -not $_.SkipAsSource
            } | Select-Object -ExpandProperty IPAddress
    )
    $socket = [Net.Sockets.Socket]::new(
        [Net.Sockets.AddressFamily]::InterNetwork,
        [Net.Sockets.SocketType]::Dgram,
        [Net.Sockets.ProtocolType]::Udp)
    try {
        $socket.Connect($parsedTarget, $routeProbeUdpPort)
        $source = [string]$socket.LocalEndPoint.Address
    } finally {
        $socket.Dispose()
    }
    if ($source -notin $sourceAddresses) {
        throw "Selected source is not on the best interface for $target"
    }
    $results += [PSCustomObject]@{
        target_ipv4 = $target
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

@($results) | ConvertTo-Json -Compress
