# Fixed helpers: all target processes are pinned by a held handle and FILETIME.
function Pin-Process([int]$processId) {
    $process = Get-Process -Id $processId -ErrorAction Stop
    try {
        [void]$process.Handle
        $birth = $process.StartTime.ToFileTimeUtc().ToString()
        $image = $process.Path
        $item = Get-CimInstance Win32_Process -Filter "ProcessId=$processId"
        if (!$item -or !$item.CreationDate -or !$image) { throw 'process identity missing during pin' }
        $cimBirth = $item.CreationDate.ToFileTimeUtc().ToString()
        $again = Get-Process -Id $processId -ErrorAction Stop
        try {
            [void]$again.Handle
            # DMTF/CIM carries microseconds; GetProcess FILETIME retains 100ns.
            # Quantize only that cross-representation check. The held process
            # and every returned/expected identity retain the complete value.
            if ($process.HasExited -or $again.HasExited -or $again.Id -ne $process.Id -or
                $item.ProcessId -ne $process.Id -or !$again.Path -or
                $again.StartTime.ToFileTimeUtc().ToString() -cne $birth -or
                $again.Path -ine $image -or $item.ExecutablePath -ine $image -or
                $birth.Length -lt 2 -or $cimBirth.Length -ne $birth.Length -or
                $cimBirth[$cimBirth.Length - 1] -cne '0' -or
                $cimBirth.Substring(0, $cimBirth.Length - 1) -cne $birth.Substring(0, $birth.Length - 1)) {
                throw 'process changed during pin'
            }
        } finally { $again.Dispose() }
        return @{handle=$process; cim_creation_time=$cimBirth; identity=@{pid=$process.Id;creation_time=$birth;image=$item.ExecutablePath;parent_pid=[int]$item.ParentProcessId};command=$item.CommandLine}
    } catch { $process.Dispose(); throw }
}
function Same-Identity($actual, $wanted) {
    return ($actual.pid -eq $wanted.pid -and $actual.creation_time -ceq $wanted.creation_time)
}
function Confirm-PinnedProcess($pin) {
    if (!$pin -or $pin.handle.HasExited -or
        $pin.handle.Id -ne $pin.identity.pid -or
        $pin.handle.StartTime.ToFileTimeUtc().ToString() -cne $pin.identity.creation_time -or
        $pin.handle.Path -ine $pin.identity.image) { throw 'held process changed' }
    $again = Pin-Process $pin.identity.pid
    try {
        if (!(Same-Identity $again.identity $pin.identity) -or
            $again.identity.image -ine $pin.identity.image -or
            $again.identity.parent_pid -ne $pin.identity.parent_pid -or
            $again.command -cne $pin.command -or $pin.handle.HasExited) {
            throw 'pinned process changed'
        }
    } finally { $again.handle.Dispose() }
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
