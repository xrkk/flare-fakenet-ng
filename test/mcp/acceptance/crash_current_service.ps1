$ErrorActionPreference = 'Stop'
# Tokens are replaced only after Python validates UUID and integer identities.
$expectedChild = __CHILD_PID__
$expectedCreation = '__CREATION__'
$expectedRun = '__RUN_ID__'
$owned = @()
$canary = $null
$supervisor = $null
try {
    $service = Get-CimInstance Win32_Service -Filter "Name='fakenetng-mcp'"
    if ($service.State -ne 'Running' -or $service.ProcessId -le 0) { throw 'SCM precondition' }
    $supervisor = Get-Process -Id $service.ProcessId
    [void]$supervisor.Handle
    $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$($supervisor.Id)"
    if ($parent.ExecutablePath -ne 'C:\Program Files\FakeNet-NG-MCP\fakenetng-mcp.exe') { throw 'SCM image mismatch' }
    $child = Get-Process -Id $expectedChild
    [void]$child.Handle
    $owned += $child
    $childInfo = Get-CimInstance Win32_Process -Filter "ProcessId=$expectedChild"
    if ($child.StartTime.ToFileTimeUtc().ToString() -ne $expectedCreation -or
        $childInfo.ParentProcessId -ne $supervisor.Id -or
        $childInfo.ExecutablePath -ne $parent.ExecutablePath -or
        $childInfo.CommandLine -notmatch ('managed-child[ ]+' + $expectedRun + '(?:[ ]|$)')) {
        throw 'managed run identity mismatch'
    }
    # Retain handles to the observed descendants, so PID reuse cannot mask exits.
    $all = @(Get-CimInstance Win32_Process)
    $ids = @($expectedChild)
    do {
        $next = @($all | Where-Object { $_.ParentProcessId -in $ids -and $_.ProcessId -notin $ids })
        foreach ($item in $next) {
            $process = Get-Process -Id $item.ProcessId
            [void]$process.Handle
            $owned += $process
            $ids += $process.Id
        }
    } while ($next.Count -gt 0)
    $before = @($owned | ForEach-Object { @{pid=$_.Id; creation_time=$_.StartTime.ToFileTimeUtc().ToString()} })
    $supervisorIdentity = @{pid=$supervisor.Id; creation_time=$supervisor.StartTime.ToFileTimeUtc().ToString(); image=$parent.ExecutablePath}
    # This process is owned by this invocation; no process-name cleanup is used.
    $canary = Start-Process "$env:WINDIR\System32\notepad.exe" -PassThru
    [void]$canary.Handle
    $canaryIdentity = @{pid=$canary.Id; creation_time=$canary.StartTime.ToFileTimeUtc().ToString()}
    $confirmed = Get-CimInstance Win32_Service -Filter "Name='fakenetng-mcp'"
    if ($confirmed.ProcessId -ne $supervisor.Id -or $supervisor.HasExited) { throw 'SCM identity changed before crash' }
    $supervisor.Kill()
    $supervisorExited = $supervisor.WaitForExit(10000)
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    do {
        $alive = @($owned | Where-Object { -not $_.HasExited })
        if ($alive.Count -eq 0) { break }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    $result = @{run_id=$expectedRun; supervisor=$supervisorIdentity; supervisor_exited=$supervisorExited;
        observed_tree=$before; remaining_pids=@($alive | ForEach-Object {$_.Id});
        canary=$canaryIdentity; canary_survived=(-not $canary.HasExited)}
} finally {
    if ($canary) {
        if (-not $canary.HasExited) { $canary.Kill(); [void]$canary.WaitForExit(10000) }
        $canary.Dispose()
    }
    foreach ($process in $owned) { $process.Dispose() }
    if ($supervisor) { $supervisor.Dispose() }
}
$result | ConvertTo-Json -Depth 6 -Compress
