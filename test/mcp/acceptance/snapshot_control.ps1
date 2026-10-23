$ErrorActionPreference = 'Stop'
$expected = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__EXPECTED__')) | ConvertFrom-Json
$root = 'C:\ProgramData\FakeNet-NG-MCP'
$path = Join-Path $root 'state\state.json'
$stateDir = Split-Path $path
foreach($directory in @($root,$stateDir,(Join-Path $root 'baselines'))){if((Get-Item -LiteralPath $directory -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'state root reparse point refused'}}
function Read-File($p) {
    $item = Get-Item -LiteralPath $p -ErrorAction Stop
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {throw 'state reparse point refused'}
    if ($item.Length -gt 8388608) {throw 'state observation exceeds bound'}
    $bytes = [IO.File]::ReadAllBytes($item.FullName)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {$hash = [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','').ToLower()} finally {$sha.Dispose()}
    return @{path=$item.FullName;body=[Convert]::ToBase64String($bytes);size=$bytes.Length;sha256=$hash}
}
$svc = Get-CimInstance Win32_Service -Filter "Name='fakenetng-mcp'"
$result = @{operation=$expected.operation;token=$expected.token}
switch ($expected.operation) {
 'read' {
    $marker = if (Test-Path -LiteralPath $path) {Read-File $path} else {$null}
    $rows = @(Get-ChildItem -LiteralPath (Join-Path $root 'baselines') -Filter '*.json' -ErrorAction Stop | ForEach-Object {Read-File $_.FullName})
    $service = @{state=$svc.State;pid=[int]$svc.ProcessId}
    if ($svc.ProcessId -gt 0) {
        $process = Get-Process -Id $svc.ProcessId
        try {
            [void]$process.Handle
            $info = Get-CimInstance Win32_Process -Filter "ProcessId=$($svc.ProcessId)"
            if ($process.HasExited -or $info.CreationDate.ToFileTimeUtc() -ne $process.StartTime.ToFileTimeUtc()) {throw 'SCM identity changed'}
            $service.creation_time=$process.StartTime.ToFileTimeUtc().ToString();$service.image=$info.ExecutablePath
            $listeners = @(Get-NetTCPConnection -State Listen -LocalPort $expected.port -ErrorAction Stop)
            $again=Get-CimInstance Win32_Service -Filter "Name='fakenetng-mcp'"
            if($again.ProcessId -ne $svc.ProcessId -or $again.State -ne $svc.State -or $process.HasExited){throw 'SCM changed during observation'}
            $result.endpoint_owned=($listeners.Count -gt 0 -and @($listeners | Where-Object {$_.OwningProcess -ne $svc.ProcessId}).Count -eq 0)
        } finally {$process.Dispose()}
    }
    $result.marker=$marker;$result.baselines=$rows;$result.service=$service
    $result.sampled_at=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()/1000.0
 }
 {$_ -in @('replace','restore-failed')} {
    if ($svc.State -ne 'Stopped' -or $svc.ProcessId) {
        if ($expected.operation -ne 'restore-failed' -or $svc.State -ne 'Running' -or $svc.ProcessId -ne $expected.service.pid) {throw 'state injection SCM identity differs'}
        $process=Get-Process -Id $svc.ProcessId
        try {[void]$process.Handle;if($process.HasExited -or $process.StartTime.ToFileTimeUtc().ToString() -cne $expected.service.creation_time) {throw 'restore service birth changed'}} finally {$process.Dispose()}
    }
    $current = if (Test-Path -LiteralPath $path) {Read-File $path} else {$null}
    if ($current.sha256 -cne $expected.before_sha256) {throw 'state preimage changed; preserve scene'}
    $bytes = [Convert]::FromBase64String($expected.body)
    if ($bytes.Length -gt 8388608) {throw 'state injection exceeds bound'}
    $temp = Join-Path $stateDir ('.acc008-' + $expected.token)
    $file = [IO.File]::Open($temp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {$file.Write($bytes,0,$bytes.Length);$file.Flush($true)} finally {$file.Dispose()}
    if ($current) {[IO.File]::Replace($temp,$path,$null)} else {[IO.File]::Move($temp,$path)}
    $result.before=$current;$result.after=Read-File $path
 }
 'acl-read' {$result.sddl=(Get-Acl -LiteralPath $stateDir).Sddl}
 'acl-deny' {
    $acl=Get-Acl -LiteralPath $stateDir
    if ($acl.Sddl -cne $expected.before) {throw 'ACL preimage changed'}
    $sid=New-Object Security.Principal.SecurityIdentifier 'S-1-5-18'
    $existing=@($acl.Access | Where-Object {$_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-5-18' -and $_.AccessControlType -eq 'Deny'})
    if ($existing.Count) {$result.available=$false;$result.before=$acl.Sddl;$result.reason='existing SYSTEM deny retained';break}
    $rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,[Security.AccessControl.FileSystemRights]::Write,'ContainerInherit,ObjectInherit','None','Deny')
    [void]$acl.AddAccessRule($rule);Set-Acl -LiteralPath $stateDir -AclObject $acl
    $result.available=$true;$result.before=$expected.before;$result.after=(Get-Acl -LiteralPath $stateDir).Sddl
    if ($result.before -ceq $result.after) {throw 'ACL change not observed'}
 }
 'acl-restore' {
    $acl=Get-Acl -LiteralPath $stateDir
    if ($acl.Sddl -cne $expected.after) {throw 'ACL changed after this attempt; preserve scene'}
    $acl.SetSecurityDescriptorSddlForm($expected.before);Set-Acl -LiteralPath $stateDir -AclObject $acl
    $result.sddl=(Get-Acl -LiteralPath $stateDir).Sddl
    if ($result.sddl -cne $expected.before) {throw 'original ACL restoration unconfirmed'}
 }
 'scan' {
    $install='C:\Program Files\FakeNet-NG-MCP\_internal'
    $files=@(Get-ChildItem -LiteralPath $install -Recurse -Force -ErrorAction Stop)
    if (@($files | Where-Object {$_.Attributes -band [IO.FileAttributes]::ReparsePoint}).Count) {throw 'scan reparse point'}
    $result.root=$install;$result.attempted=$true;$result.complete=$true
    $result.count=$files.Count;$result.pyc_count=@($files | Where-Object {!$_.PSIsContainer -and $_.Extension -ieq '.pyc'}).Count
    $result.files=@($files | ForEach-Object {@{path=$_.FullName;size=$_.Length;directory=$_.PSIsContainer}})
 }
 default {throw 'unknown fixed ACC008 operation'}
}
$result | ConvertTo-Json -Depth 20 -Compress
