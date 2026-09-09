$ErrorActionPreference = 'Stop'
$expected = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__EXPECTED__')) | ConvertFrom-Json
$root = 'C:\ProgramData\FakeNet-NG-MCP'
$dir = Join-Path $root ('artifacts\runs\' + $expected.run_id)
$receipt = Get-Content (Join-Path $dir 'creation-fault-triggered.json') -Raw | ConvertFrom-Json
if ($receipt.nonce -ne $expected.nonce -or $receipt.fault -ne $expected.fault) { throw 'receipt changed' }
$marker = Get-Content (Join-Path $root 'state\state.json') -Raw | ConvertFrom-Json
if ($marker.run_id -ne $expected.run_id -or $marker.command_id -ne $expected.command_id) { throw 'current responsibility mismatch' }
$service = Get-CimInstance Win32_Service -Filter "Name='fakenetng-mcp'"
if ($service.State -ne 'Running' -or $service.ProcessId -ne $expected.supervisor.pid) { throw 'SCM identity mismatch' }
$parent = $null
$canary = $null
$owned = @()
try {
    $parent = Get-Process -Id $service.ProcessId
    [void]$parent.Handle
    $info = Get-CimInstance Win32_Process -Filter "ProcessId=$($parent.Id)"
    if ($parent.StartTime.ToFileTimeUtc().ToString() -ne $expected.supervisor.creation_time -or
        $info.ExecutablePath -ne 'C:\Program Files\FakeNet-NG-MCP\fakenetng-mcp.exe') { throw 'supervisor identity reused' }
    foreach ($member in $receipt.observation.job_members) {
        $process = Get-Process -Id $member
        [void]$process.Handle
        $owned += $process
    }
    if ($receipt.observation.child) {
        $child = @($owned | Where-Object {$_.Id -eq $receipt.observation.child.pid})
        if ($child.Count -ne 1 -or $child[0].StartTime.ToFileTimeUtc().ToString() -ne $receipt.observation.child.creation_time) { throw 'child identity mismatch' }
    }
    $canary = Start-Process "$env:WINDIR\System32\notepad.exe" -PassThru
    [void]$canary.Handle
    $pinned = @($owned | ForEach-Object {@{pid=$_.Id;creation_time=$_.StartTime.ToFileTimeUtc().ToString()}})
    $latest = Get-CimInstance Win32_Service -Filter "Name='fakenetng-mcp'"
    if ($latest.ProcessId -ne $parent.Id -or $parent.HasExited) { throw 'supervisor changed before crash' }
    $parent.Kill()
    $parentExited = $parent.WaitForExit(10000)
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    do {
        $alive = @($owned | Where-Object {-not $_.HasExited})
        $escaped = @(Get-CimInstance Win32_Process | Where-Object {
            $_.CommandLine -match ('managed-child[ ]+' + $expected.run_id + '(?:[ ]|$)')
        } | Select-Object ProcessId,ParentProcessId,CommandLine,CreationDate)
        if ($alive.Count -eq 0 -and $escaped.Count -eq 0) { break }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    $result = @{supervisor=$expected.supervisor;supervisor_exited=$parentExited;
        pinned_members=$pinned;remaining_pids=@($alive | ForEach-Object {$_.Id});escaped=$escaped;
        canary_pid=$canary.Id;canary_creation=$canary.StartTime.ToFileTimeUtc().ToString();
        canary_survived=(-not $canary.HasExited);marker=$marker;receipt=$receipt}
} finally {
    if ($canary) {
        if (-not $canary.HasExited) {$canary.Kill();[void]$canary.WaitForExit(10000)}
        $canary.Dispose()
    }
    foreach ($process in $owned) {$process.Dispose()}
    if ($parent) {$parent.Dispose()}
}
$result | ConvertTo-Json -Depth 12 -Compress
