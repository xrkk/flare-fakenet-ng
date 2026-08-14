function ConvertFrom-FindNetRouteResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object[]]$Result,
        [Parameter(Mandatory = $true)][string]$Target
    )

    $items = @($Result)
    $addresses = @($items | Where-Object {
        $null -ne $_.PSObject.Properties['IPAddress'] -and
        $null -ne $_.PSObject.Properties['AddressState'] -and
        $null -ne $_.PSObject.Properties['SkipAsSource'] -and
        $null -eq $_.PSObject.Properties['DestinationPrefix']
    })
    $routes = @($items | Where-Object {
        $null -ne $_.PSObject.Properties['DestinationPrefix'] -and
        $null -ne $_.PSObject.Properties['NextHop'] -and
        $null -ne $_.PSObject.Properties['RouteMetric'] -and
        $null -eq $_.PSObject.Properties['IPAddress']
    })
    if ($items.Count -ne 2 -or $addresses.Count -ne 1 -or
            $routes.Count -ne 1) {
        throw ('Find-NetRoute did not return exactly one NetIPAddress and ' +
            'one NetRoute for ' + $Target)
    }

    $address = $addresses[0]
    $route = $routes[0]
    $source = [string]$address.IPAddress
    if ([string]::IsNullOrWhiteSpace($source) -or
            [int]$address.InterfaceIndex -le 0 -or
            [int]$route.InterfaceIndex -le 0 -or
            [int]$address.InterfaceIndex -ne [int]$route.InterfaceIndex) {
        throw ('Find-NetRoute source/interface pair is invalid for ' + $Target)
    }

    return [PSCustomObject]@{
        IPAddress = $source
        NetIPAddress = $address
        NetRoute = $route
    }
}

function ConvertFrom-RouteSnapshotJson {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Json)

    $decoded = $Json | ConvertFrom-Json
    foreach ($item in @($decoded)) {
        Write-Output $item
    }
}
