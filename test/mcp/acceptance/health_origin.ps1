$ErrorActionPreference='Stop'
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
    $bytes=[IO.File]::ReadAllBytes($path);$sha=[Security.Cryptography.SHA256]::Create()
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
