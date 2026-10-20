param(
    [switch]$Apply,
    [switch]$Restore,
    [string]$Confirm = '',
    [string]$StatePath = '',
    [string]$CommandId = ''
)
$ErrorActionPreference = 'Stop'
$IfIndex = 11
$Source = '2001:db8:204::149'
$Target6 = '2001:db8::77/128'
$NextHop6 = 'fe80::250:56ff:fec0:8'
$Target4 = '198.51.100.77/32'
$NextHop4 = '192.168.204.1'
if (-not $Apply -and -not $Restore) {
    [ordered]@{mode='plan'; address=$Source; routes=@($Target6,$Target4); mutation_executed=$false} | ConvertTo-Json -Compress
    exit 0
}
if ($Apply -and $Restore) { throw 'choose_one_action' }
if ($Confirm -ne 'local-fixture-only') { throw 'explicit_confirmation_required' }
$parsedId = [Guid]::Parse($CommandId)
if ($parsedId.ToString() -cne $CommandId) { throw 'canonical_command_id_required' }
$StatePath = [IO.Path]::GetFullPath($StatePath)
if ($StatePath -notmatch '^[ED]:\\' -or $StatePath -match '^\\\\') { throw 'local_E_or_D_state_required' }
$parent = Split-Path -Parent $StatePath
$entry = Get-Item -LiteralPath $parent -Force
while ($entry) {
    if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'reparse_state_ancestor' }
    $entry = $entry.Parent
}
$uuid = ([string](Get-CimInstance Win32_ComputerSystemProduct).UUID).ToUpperInvariant()
$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
if ($uuid -ne 'B3E04D56-3DB2-9F3D-4D52-3EC22C4CFDC0') { throw 'vm_identity_mismatch' }
$adapter = Get-NetAdapter -InterfaceIndex $IfIndex
if ($adapter.MacAddress -ne '00-0C-29-4C-FD-C0') { throw 'target_interface_mac_mismatch' }
function Save-State($value) {
    $pending = $StatePath + '.' + [Guid]::NewGuid().ToString('N') + '.pending'
    $bytes = [Text.Encoding]::UTF8.GetBytes(($value | ConvertTo-Json -Depth 12 -Compress))
    $stream = [IO.File]::Open($pending,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    if (Test-Path -LiteralPath $StatePath) {
        $old = Get-Item -LiteralPath $StatePath -Force
        if ($old.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'reparse_state_file' }
        [IO.File]::Replace($pending,$StatePath,$null)
    } else { [IO.File]::Move($pending,$StatePath) }
}
$changes = @(
    [ordered]@{kind='address';family='IPv6';value=$Source;prefix_length=64;if_index=$IfIndex},
    [ordered]@{kind='route';family='IPv6';value=$Target6;next_hop=$NextHop6;if_index=$IfIndex},
    [ordered]@{kind='route';family='IPv4';value=$Target4;next_hop=$NextHop4;if_index=$IfIndex}
)
function Current($item) {
    if ($item.kind -eq 'address') {
        return @(Get-NetIPAddress -InterfaceIndex $IfIndex -AddressFamily $item.family -ErrorAction Stop | Where-Object {$_.IPAddress -eq $item.value})
    }
    return @(Get-NetRoute -InterfaceIndex $IfIndex -AddressFamily $item.family -ErrorAction Stop | Where-Object {$_.DestinationPrefix -eq $item.value})
}
if ($Apply) {
    if (Test-Path -LiteralPath $StatePath) { throw 'state_already_exists' }
    foreach ($item in $changes) { if (@(Current $item).Count -ne 0) { throw 'preexisting_guest_item' } }
    # Exclusive ownership record precedes the first change and survives partial failure.
    $stream = [IO.File]::Open($StatePath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    $stream.Dispose()
    $state = [ordered]@{schema='fakenetng.guest-fixture-state.v2';command_id=$CommandId;vm_uuid=$uuid;boot_id=$boot;mac=$adapter.MacAddress;stage='prepared';planned=$changes;attempted=@();restored=@()}
    Save-State $state
    foreach ($item in $changes) {
        $state.attempted += $item
        $state.stage = 'creating'
        Save-State $state
        if ($item.kind -eq 'address') {
            New-NetIPAddress -InterfaceIndex $IfIndex -IPAddress $item.value -PrefixLength 64 -AddressFamily IPv6 -PolicyStore ActiveStore | Out-Null
        } else {
            New-NetRoute -InterfaceIndex $IfIndex -DestinationPrefix $item.value -NextHop $item.next_hop -AddressFamily $item.family -PolicyStore ActiveStore | Out-Null
        }
        if (@(Current $item).Count -ne 1) { throw 'guest_item_creation_unconfirmed' }
    }
    $state.stage = 'active'
    Save-State $state
    [ordered]@{mode='apply';state_path=$StatePath;command_id=$CommandId;changes=$changes;mutation_executed=$true} | ConvertTo-Json -Depth 12 -Compress
    exit 0
}
$file = Get-Item -LiteralPath $StatePath -Force
if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'reparse_state_file' }
$state = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
if ($state.schema -ne 'fakenetng.guest-fixture-state.v2' -or $state.command_id -cne $CommandId -or $state.vm_uuid -ne $uuid -or $state.boot_id -ne $boot -or $state.mac -ne $adapter.MacAddress) { throw 'guest_ownership_mismatch' }
if (($state.planned | ConvertTo-Json -Depth 10 -Compress) -cne ($changes | ConvertTo-Json -Depth 10 -Compress)) { throw 'guest_creation_manifest_drift' }
$owned = @($state.attempted)
[array]::Reverse($owned)
foreach ($item in $owned) {
    $current = @(Current $item)
    if ($current.Count -gt 1) { throw 'guest_item_ambiguous' }
    if ($current.Count -eq 1) {
        if ($item.kind -eq 'address') {
            if ($current[0].PrefixLength -ne 64 -or $current[0].PrefixOrigin -ne 'Manual') { throw 'owned_address_changed' }
            $current[0] | Remove-NetIPAddress -Confirm:$false -ErrorAction Stop
        } else {
            if ($current[0].NextHop -ne $item.next_hop) { throw 'owned_route_changed' }
            $current[0] | Remove-NetRoute -Confirm:$false -ErrorAction Stop
        }
        if (@(Current $item).Count -ne 0) { throw 'guest_item_removal_unconfirmed' }
    }
    $state.restored += $item
    Save-State $state
}
$state.stage = 'restored'
Save-State $state
[ordered]@{mode='restore';state_path=$StatePath;command_id=$CommandId;remaining=@()} | ConvertTo-Json -Compress
