$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'RouteResultTools.ps1')

$address = [PSCustomObject]@{
    IPAddress = '192.168.204.128'
    InterfaceIndex = 7
    AddressState = 'Preferred'
    SkipAsSource = $false
}
$route = [PSCustomObject]@{
    DestinationPrefix = '0.0.0.0/0'
    NextHop = '192.168.204.2'
    RouteMetric = 0
    InterfaceIndex = 7
}
$selection = ConvertFrom-FindNetRouteResult `
    -Result @($address, $route) -Target '110.242.69.21'
if ($selection.IPAddress -ne '192.168.204.128' -or
        $selection.NetIPAddress -ne $address -or
        $selection.NetRoute -ne $route) {
    throw 'The documented Find-NetRoute two-object result was not decoded.'
}

$snapshotJson = @(
    [PSCustomObject]@{ target_ipv4 = '110.242.69.21' },
    [PSCustomObject]@{ target_ipv4 = '192.168.204.1' }
) | ConvertTo-Json -Compress
$snapshots = @(ConvertFrom-RouteSnapshotJson $snapshotJson)
if ($snapshots.Count -ne 2 -or
        $snapshots[0].target_ipv4 -ne '110.242.69.21' -or
        $snapshots[1].target_ipv4 -ne '192.168.204.1') {
    throw 'The route snapshot JSON array was nested or changed.'
}

$failures = @(
    @($address),
    @($route),
    @($address, $address, $route),
    @($address, [PSCustomObject]@{
        DestinationPrefix = '192.168.204.0/24'
        NextHop = '0.0.0.0'
        RouteMetric = 0
        InterfaceIndex = 8
    })
)
foreach ($failure in $failures) {
    $rejected = $false
    try {
        [void](ConvertFrom-FindNetRouteResult `
            -Result @($failure) -Target '192.168.204.1')
    } catch { $rejected = $true }
    if (-not $rejected) {
        throw 'An incomplete, duplicate, or mismatched route result was accepted.'
    }
}
Write-Host 'Find-NetRoute result-shape test passed.'
