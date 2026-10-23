$ErrorActionPreference='Stop'
$expected=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__EXPECTED__'))|ConvertFrom-Json
$child=$null;$parent=$null
try {
    $service=Get-CimInstance Win32_Service -Filter "Name='fakenetng-mcp'"
    if($service.State -ne 'Running' -or $service.ProcessId -le 0 -or $service.ProcessId -eq $expected.child.pid){throw 'health SCM precondition'}
    $parent=Get-Process -Id $service.ProcessId;[void]$parent.Handle
    $parentInfo=Get-CimInstance Win32_Process -Filter "ProcessId=$($parent.Id)"
    if($parent.HasExited -or $parentInfo.ExecutablePath -ine 'C:\Program Files\FakeNet-NG-MCP\fakenetng-mcp.exe' -or $parentInfo.CreationDate.ToFileTimeUtc() -ne $parent.StartTime.ToFileTimeUtc()){throw 'health SCM image/birth differs'}
    $child=Get-Process -Id $expected.child.pid;[void]$child.Handle
    $info=Get-CimInstance Win32_Process -Filter "ProcessId=$($child.Id)"
    if($child.HasExited -or $child.StartTime.ToFileTimeUtc().ToString() -cne $expected.child.creation_time -or
       $info.CreationDate.ToFileTimeUtc() -ne $child.StartTime.ToFileTimeUtc() -or $info.ParentProcessId -ne $parent.Id -or
       $info.ExecutablePath -ine 'C:\Program Files\FakeNet-NG-MCP\fakenetng-mcp-managed.exe' -or
       $info.CommandLine -notmatch ('managed-child[ ]+'+[regex]::Escape($expected.run_id)+'(?:[ ]|$)')){throw 'health child scope differs'}
    $root='C:\ProgramData\FakeNet-NG-MCP\artifacts\runs'
    $dir=Join-Path $root $expected.run_id;$path=Join-Path $dir 'run.log'
    foreach($item in @($root,$dir,$path)){if((Get-Item -LiteralPath $item -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'health evidence reparse refused'}}
    if((Get-Item -LiteralPath $path).Length -gt 8388608){throw 'health log exceeds bounded evidence read'}
    $bytes=[IO.File]::ReadAllBytes($path);$sha=[Security.Cryptography.SHA256]::Create()
    try{$hash=[BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','').ToLower()}finally{$sha.Dispose()}
    $again=Get-CimInstance Win32_Service -Filter "Name='fakenetng-mcp'"
    if($again.ProcessId -ne $parent.Id -or $again.State -ne 'Running' -or $child.HasExited -or $parent.HasExited){throw 'health instance changed during read'}
    $result=@{run_id=$expected.run_id;child=@{pid=$child.Id;creation_time=$child.StartTime.ToFileTimeUtc().ToString();parent_pid=$parent.Id;image=$info.ExecutablePath;run_id=$expected.run_id};
        service=@{pid=$parent.Id;creation_time=$parent.StartTime.ToFileTimeUtc().ToString();image=$parentInfo.ExecutablePath;state=$service.State};
        log=@{path=$path;body=[Convert]::ToBase64String($bytes);size=$bytes.Length;sha256=$hash}}
}finally{if($child){$child.Dispose()};if($parent){$parent.Dispose()}}
$result|ConvertTo-Json -Depth 12 -Compress
