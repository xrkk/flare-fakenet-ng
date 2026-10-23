$ErrorActionPreference = 'Stop'
$expected = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__EXPECTED__')) | ConvertFrom-Json
$creationWindow = $false
__SCOPE_HELPERS__
$root = 'C:\ProgramData\FakeNet-NG-MCP'
$dir = Join-Path $root ('artifacts\runs\' + $expected.run_id)
$parent = $null
$canary = $null
$owned = @()
try {
    $marker = Read-Marker
    Check-Marker $marker $expected
    if ($creationWindow) {
        $receipt = Get-Content -LiteralPath (Join-Path $dir 'creation-fault-triggered.json') -Raw | ConvertFrom-Json
        if ($receipt.nonce -cne $expected.nonce -or $receipt.fault -cne $expected.fault -or
            ($receipt.observation | ConvertTo-Json -Depth 20 -Compress) -cne ($expected.observation | ConvertTo-Json -Depth 20 -Compress)) { throw 'consumed creation receipt changed' }
        if (Test-Path -LiteralPath (Join-Path $root 'logs\fault-injection.json')) { throw 'fault not consumed' }
    }
    $service = Get-CimInstance Win32_Service -Filter "Name='fakenetng-mcp'"
    if ($service.State -ne 'Running' -or $service.ProcessId -ne $expected.supervisor.pid) { throw 'SCM identity mismatch' }
    $parent = Pin-Process $service.ProcessId
    if (!(Same-Identity $parent.identity $expected.supervisor) -or $parent.identity.image -ine 'C:\Program Files\FakeNet-NG-MCP\fakenetng-mcp.exe') { throw 'supervisor identity/image reused' }
    $ids = @()
    if ($null -ne $expected.child) {
        $child = Pin-Process $expected.child.pid
        $owned += $child
        if (!(Same-Identity $child.identity $expected.child) -or $child.identity.parent_pid -ne $parent.identity.pid -or
            $child.identity.image -ine 'C:\Program Files\FakeNet-NG-MCP\fakenetng-mcp-managed.exe' -or
            $child.command -notmatch ('managed-child[ ]+' + [regex]::Escape($expected.run_id) + '(?:[ ]|$)')) { throw 'managed child identity/image/run mismatch' }
        $child.identity.run_id = $expected.run_id
        $ids = @($child.identity.pid)
        # Expand only descendants of a pinned managed child. Each new process is
        # independently opened and its CIM birth checked against its held handle.
        $stable = $false
        for ($round=0; $round -lt 8; $round++) {
            $all = @(Get-CimInstance Win32_Process)
            $next = @($all | Where-Object {$_.ParentProcessId -in $ids -and $_.ProcessId -notin $ids})
            if ($next.Count -eq 0) { $stable = $true; break }
            foreach ($item in $next) {
                $pin = Pin-Process $item.ProcessId
                $owned += $pin
                $owner = @($owned | Where-Object {$_.identity.pid -eq $pin.identity.parent_pid})
                if ($owner.Count -ne 1 -or $pin.identity.parent_pid -ne $item.ParentProcessId -or
                    $pin.identity.creation_time -cne $item.CreationDate.ToFileTimeUtc().ToString() -or
                    [Int64]$pin.identity.creation_time -lt [Int64]$owner[0].identity.creation_time) { throw 'descendant ownership changed' }
                $ids += $pin.identity.pid
            }
        }
        if (!$stable) { throw 'process tree did not stabilize' }
    }
    foreach ($member in $expected.job_members) { if ($member -notin $ids) { throw 'Job member outside pinned tree' } }
    $before = @($owned | ForEach-Object {$_.identity})
    $canary = New-Canary
    $canaryIdentity = @{pid=$canary.Id;creation_time=$canary.StartTime.ToFileTimeUtc().ToString()}
    if ($canary.Id -in ($ids + @($parent.identity.pid))) { throw 'canary scope overlaps' }
    # Validate all held objects and the responsibility immediately before kill.
    foreach ($pin in $owned) {
        $item = Get-CimInstance Win32_Process -Filter "ProcessId=$($pin.identity.pid)"
        if ($pin.handle.HasExited -or !$item -or $item.CreationDate.ToFileTimeUtc().ToString() -cne $pin.identity.creation_time -or
            $item.ParentProcessId -ne $pin.identity.parent_pid -or $item.ExecutablePath -ine $pin.identity.image) { throw 'pinned tree changed before crash' }
    }
    $latestTree = @(Get-CimInstance Win32_Process)
    $unseen = @($latestTree | Where-Object {$_.ParentProcessId -in $ids -and $_.ProcessId -notin $ids})
    $runRoots = @($latestTree | Where-Object {$_.CommandLine -match ('managed-child[ ]+' + [regex]::Escape($expected.run_id) + '(?:[ ]|$)')})
    if ($unseen.Count -gt 0 -or @($runRoots | Where-Object {$_.ProcessId -notin $ids}).Count -gt 0) { throw 'unobserved managed process appeared; no crash issued' }
    Check-Marker (Read-Marker) $expected
    $latest = Get-CimInstance Win32_Service -Filter "Name='fakenetng-mcp'"
    if ($latest.State -ne 'Running' -or $latest.ProcessId -ne $parent.identity.pid -or $parent.handle.HasExited) { throw 'supervisor changed before crash' }
    # Only the pinned supervisor is terminated. Job close owns descendant exit.
    $parent.handle.Kill()
    $parentExited = $parent.handle.WaitForExit(10000)
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    do {
        $alive = @($owned | Where-Object {-not $_.handle.HasExited})
        $escaped = @(Get-CimInstance Win32_Process | Where-Object {
            $_.CommandLine -match ('managed-child[ ]+' + [regex]::Escape($expected.run_id) + '(?:[ ]|$)')
        } | Select-Object ProcessId,ParentProcessId,CommandLine,CreationDate)
        if ($alive.Count -eq 0 -and $escaped.Count -eq 0) { break }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    $result = @{run_id=$expected.run_id;supervisor=@{pid=$parent.identity.pid;creation_time=$parent.identity.creation_time};
        supervisor_exited=$parentExited;observed_tree=$before;remaining_pids=@($alive | ForEach-Object {$_.identity.pid});
        escaped=$escaped;canary=$canaryIdentity;canary_survived=(-not $canary.HasExited);marker=$marker}
    if ($creationWindow) { $result.receipt = $receipt }
} finally {
    if ($canary) {
        if (!$canary.HasExited) {$canary.Kill();[void]$canary.WaitForExit(10000)}
        $canary.Dispose()
    }
    foreach ($pin in $owned) {$pin.handle.Dispose()}
    if ($parent) {$parent.handle.Dispose()}
}
$result | ConvertTo-Json -Depth 20 -Compress
