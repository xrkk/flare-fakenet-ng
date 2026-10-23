$ErrorActionPreference = 'Stop'
$expected = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__EXPECTED__')) | ConvertFrom-Json
__SCOPE_HELPERS__
$pin = $null
try {
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        $service = Get-CimInstance Win32_Service -Filter "Name='fakenetng-mcp'"
        if ($service.State -eq 'Running' -and $service.ProcessId -gt 0) {break}
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($service.State -ne 'Running' -or $service.ProcessId -le 0) { throw 'SCM not running' }
    $pin = Pin-Process $service.ProcessId
    $listeners = @(Get-NetTCPConnection -State Listen -LocalPort $expected.port -ErrorAction Stop)
    $confirmed = Get-CimInstance Win32_Service -Filter "Name='fakenetng-mcp'"
    if ($confirmed.State -ne 'Running' -or $confirmed.ProcessId -ne $pin.identity.pid -or $pin.handle.HasExited) { throw 'SCM changed during observation' }
    $marker = if (Test-Path -LiteralPath 'C:\ProgramData\FakeNet-NG-MCP\state\state.json') {Read-Marker} else {$null}
    $result = @{pid=$pin.identity.pid;creation_time=$pin.identity.creation_time;image=$pin.identity.image;
        state=$service.State;endpoint_owned=($listeners.Count -gt 0 -and @($listeners | Where-Object {$_.OwningProcess -ne $pin.identity.pid}).Count -eq 0);
        marker=$marker;sampled_at=([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()/1000.0)}
} finally { if ($pin) {$pin.handle.Dispose()} }
$result | ConvertTo-Json -Depth 16 -Compress
