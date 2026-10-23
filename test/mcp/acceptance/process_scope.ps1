# Fixed helpers: all target processes are pinned by a held handle and FILETIME.
function Pin-Process([int]$processId) {
    $process = Get-Process -Id $processId -ErrorAction Stop
    try {
        [void]$process.Handle
        $item = Get-CimInstance Win32_Process -Filter "ProcessId=$processId"
        $birth = $process.StartTime.ToFileTimeUtc().ToString()
        if ($process.HasExited -or !$item -or $item.CreationDate.ToFileTimeUtc().ToString() -ne $birth) { throw 'process changed during pin' }
        return @{handle=$process; identity=@{pid=$process.Id;creation_time=$birth;image=$item.ExecutablePath;parent_pid=[int]$item.ParentProcessId};command=$item.CommandLine}
    } catch { $process.Dispose(); throw }
}
function Same-Identity($actual, $wanted) {
    return ($actual.pid -eq $wanted.pid -and $actual.creation_time -ceq $wanted.creation_time)
}
function Read-Marker {
    return (Get-Content -LiteralPath 'C:\ProgramData\FakeNet-NG-MCP\state\state.json' -Raw | ConvertFrom-Json)
}
function Check-Marker($marker, $expected) {
    if ($marker.run_id -cne $expected.run_id -or $marker.command_id -cne $expected.command_id -or $marker.needs_recovery -ne $true) { throw 'current responsibility mismatch' }
}
function New-Canary {
    $text = '[Threading.Thread]::Sleep(120000)'
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($text))
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
    $start.Arguments = '-NoProfile -NonInteractive -EncodedCommand ' + $encoded
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $process = [Diagnostics.Process]::Start($start)
    [void]$process.Handle
    if ($process.HasExited) { $process.Dispose(); throw 'canary failed to start' }
    return $process
}
