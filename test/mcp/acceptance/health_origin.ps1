$ErrorActionPreference='Stop'
function Read-HealthLogPrefix($stream, [long]$length) {
    if ($length -lt 0 -or $length -gt 8388608) { throw 'health log exceeds bounded evidence read' }
    $bytes = [byte[]]::new($length)
    $stream.Position = 0
    $offset = 0
    while ($offset -lt $length) {
        $count = $stream.Read($bytes, $offset, $length - $offset)
        if ($count -le 0) { throw 'health log short read' }
        $offset += $count
    }
    if ($stream.Length -lt $length) { throw 'health log truncated during read' }
    $stream.Position = 0
    $verified = 0
    $buffer = [byte[]]::new([Math]::Min(65536, [Math]::Max(1, $length)))
    while ($verified -lt $length) {
        $count = $stream.Read($buffer, 0, [Math]::Min($buffer.Length, $length - $verified))
        if ($count -le 0) { throw 'health log short verification read' }
        for ($i = 0; $i -lt $count; $i++) {
            if ($buffer[$i] -ne $bytes[$verified + $i]) { throw 'health log prefix changed during read' }
        }
        $verified += $count
    }
    if ($stream.Length -lt $length) { throw 'health log truncated during verification' }
    # A growing log is observed at opening length, never as an invented full tail.
    return ,$bytes
}
function Read-HealthLogBytes([string]$path) {
    $stream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try { return ,(Read-HealthLogPrefix $stream $stream.Length) }
    finally { $stream.Dispose() }
}
# END FIXED HEALTH LOG READERS
$expected=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__EXPECTED__'))|ConvertFrom-Json
__SCOPE_HELPERS__
$child=$null;$parent=$null
try {
    $service=Get-CimInstance Win32_Service -Filter "Name='fakenetng-mcp'"
    if($service.State -ne 'Running' -or $service.ProcessId -le 0 -or $service.ProcessId -eq $expected.child.pid){throw 'health SCM precondition'}
    $parent=Pin-Process $service.ProcessId
    if($parent.identity.image -ine 'C:\Program Files\FakeNet-NG-MCP\fakenetng-mcp.exe'){throw 'health SCM image/birth differs'}
    $child=Pin-Process $expected.child.pid
    if(!(Same-Identity $child.identity $expected.child) -or
       $child.identity.parent_pid -ne $parent.identity.pid -or
       $child.identity.image -ine 'C:\Program Files\FakeNet-NG-MCP\fakenetng-mcp-managed.exe' -or
       $child.command -notmatch ('managed-child[ ]+'+[regex]::Escape($expected.run_id)+'(?:[ ]|$)')){throw 'health child scope differs'}
    $root='C:\ProgramData\FakeNet-NG-MCP\artifacts\runs'
    $dir=Join-Path $root $expected.run_id;$path=Join-Path $dir 'run.log'
    foreach($item in @($root,$dir,$path)){if((Get-Item -LiteralPath $item -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'health evidence reparse refused'}}
    if((Get-Item -LiteralPath $path).Length -gt 8388608){throw 'health log exceeds bounded evidence read'}
    $bytes=Read-HealthLogBytes $path;$sha=[Security.Cryptography.SHA256]::Create()
    try{$hash=[BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','').ToLower()}finally{$sha.Dispose()}
    $again=Get-CimInstance Win32_Service -Filter "Name='fakenetng-mcp'"
    if($again.ProcessId -ne $parent.identity.pid -or $again.State -ne 'Running' -or $child.handle.HasExited -or $parent.handle.HasExited){throw 'health instance changed during read'}
    Confirm-PinnedProcess $parent
    Confirm-PinnedProcess $child
    $result=@{run_id=$expected.run_id;child=@{pid=$child.identity.pid;creation_time=$child.identity.creation_time;parent_pid=$parent.identity.pid;image=$child.identity.image;run_id=$expected.run_id};
        service=@{pid=$parent.identity.pid;creation_time=$parent.identity.creation_time;image=$parent.identity.image;state=$service.State};
        log=@{path=$path;body=[Convert]::ToBase64String($bytes);size=$bytes.Length;sha256=$hash}}
}finally{if($child){$child.handle.Dispose()};if($parent){$parent.handle.Dispose()}}
$result|ConvertTo-Json -Depth 12 -Compress
