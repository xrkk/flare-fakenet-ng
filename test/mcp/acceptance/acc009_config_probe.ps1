# ACC009_CONFIG_PROBE_V1: fixed owned-file operations, never arbitrary commands.
$ErrorActionPreference = 'Stop'
$request = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__REQUEST__')) | ConvertFrom-Json
function Hash-File($path) { (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLower() }
function No-Reparse($path) {
    $current = [IO.Path]::GetFullPath($path)
    while ($current) {
        $item = Get-Item -LiteralPath $current -Force -ErrorAction SilentlyContinue
        if ($item -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'unexpected reparse ancestor' }
        $parent = [IO.Path]::GetDirectoryName($current)
        if ($parent -eq $current) { break }; $current = $parent
    }
}
function Observe-File($path) {
    if (-not [IO.File]::Exists($path)) { return @{exists=$false;sha256=$null;creation_time=$null;size=0} }
    $file = Get-Item -LiteralPath $path -Force
    @{exists=$true;sha256=(Hash-File $path);creation_time=$file.CreationTimeUtc.ToFileTimeUtc().ToString();size=$file.Length}
}
if ($request.token -notmatch '^[0-9a-f]{32}$' -or $request.name -notmatch '^acc009-[a-z]+-[0-9a-f]{32}\.ini$') { throw 'invalid owned probe identity' }
$programRoot = if ($request.programdata_root) { $request.programdata_root } else { Join-Path $env:ProgramData 'FakeNet-NG-MCP' }
$configRoot = [IO.Path]::GetFullPath((Join-Path $programRoot 'configs\custom'))
No-Reparse $configRoot
$path = Join-Path $configRoot $request.name
$result = @{schema='fakenet.acc009-os.v1';operation=$request.operation;name=$request.name;token=$request.token;run_id=$request.run_id;path=$path}
if ($request.operation -eq 'file-probe') {
    No-Reparse $path
    $before = Observe-File $path
    if (-not $before.exists -or $before.sha256 -ne $request.sha256 -or ($request.creation_time -and $before.creation_time -ne $request.creation_time)) { throw 'probe target changed before operation' }
    $original = [IO.File]::ReadAllBytes($path)
    $write = @{attempted=$true;success=$false;win32_error=$null}
    try { [IO.File]::WriteAllBytes($path,$original);$write.success=$true }
    catch { $errorObject=$_.Exception.GetBaseException();$write.win32_error=($errorObject.HResult -band 65535);$write.error=$errorObject.Message }
    $delete = @{attempted=$true;success=$false;win32_error=$null}
    try { [IO.File]::Delete($path);$delete.success=(-not [IO.File]::Exists($path)) }
    catch { $errorObject=$_.Exception.GetBaseException();$delete.win32_error=($errorObject.HResult -band 65535);$delete.error=$errorObject.Message }
    $restored = $false
    if ($request.phase -eq 'stopped' -and $delete.success) {
        # Recreate only this invocation's removed file, never overwrite a racer.
        $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try { $stream.Write($original,0,$original.Length);$stream.Flush() } finally { $stream.Dispose() }
        $restored = ((Hash-File $path) -eq $request.sha256)
    }
    $result.phase=$request.phase;$result.before=$before;$result.write=$write;$result.delete=$delete
    $result.restored=$restored;$result.after=(Observe-File $path)
} elseif ($request.operation -in @('reparse-setup','reparse-cleanup')) {
    $leaf = 'fakenet-acc009-' + $request.token
    $createdWork=$false;$createdTarget=$false;$createdLink=$false
    if ($request.operation -eq 'reparse-setup') {
        if (Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue) { throw 'owned reparse name already exists; preserve scene' }
        $candidates = if ($request.work_root) { @($request.work_root) } else { @('E:\','D:\') }
        $work=$null;$selectionErrors=@()
        foreach ($workRoot in $candidates) {
            $workRoot=[IO.Path]::GetFullPath([string]$workRoot)
            $driveRoot=[IO.Path]::GetPathRoot($workRoot)
            if ($driveRoot -notin @('E:\','D:\') -or -not (Test-Path -LiteralPath $driveRoot -PathType Container)) { continue }
            No-Reparse $workRoot
            if (-not (Test-Path -LiteralPath $workRoot) -and $request.work_root) {
                $drive=[IO.DriveInfo]::new($driveRoot)
                if ($drive.AvailableFreeSpace -lt 1048576) { throw 'insufficient workspace capacity' }
                [IO.Directory]::CreateDirectory($workRoot) | Out-Null
                $result.workspace_created=$true
            }
            if (-not (Test-Path -LiteralPath $workRoot -PathType Container)) { continue }
            $result.workspace_root=$workRoot
            $candidate=Join-Path $workRoot $leaf
            if (Test-Path -LiteralPath $candidate) { throw 'owned reparse work name already exists; preserve scene' }
            try {
                $drive=[IO.DriveInfo]::new([IO.Path]::GetPathRoot($workRoot))
                if ($drive.AvailableFreeSpace -lt 1048576) { throw 'insufficient work space' }
                New-Item -ItemType Directory -Path $candidate -ErrorAction Stop | Out-Null
                $createdWork=$true;$work=$candidate;break
            } catch {
                if (Test-Path -LiteralPath $candidate) { throw 'work creation ownership unknown; preserve scene' }
                $selectionErrors += $_.Exception.Message
            }
        }
        if (-not $work) { throw ('no writable E/D work root: ' + ($selectionErrors -join '; ')) }
    } else { $work=$request.work_dir }
    if ([IO.Path]::GetPathRoot($work) -notin @('E:\','D:\') -or [IO.Path]::GetFileName($work) -ne $leaf) { throw 'foreign reparse work directory' }
    $target=Join-Path $work 'target.ini';$result.work_dir=$work;$result.target=$target
    $targetBytes=[Text.Encoding]::UTF8.GetBytes("acc009 benign controlled target`n")
    if ($request.operation -eq 'reparse-setup') {
        try {
            $stream=[IO.File]::Open($target,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
            try { $stream.Write($targetBytes,0,$targetBytes.Length) } finally { $stream.Dispose() };$createdTarget=$true
            $result.target_sha256=Hash-File $target
            New-Item -ItemType SymbolicLink -Path $path -Target $target -ErrorAction Stop | Out-Null;$createdLink=$true
            $result.created=$true;$result.cleanup_complete=$false
        } catch {
            $result.created=$false;$result.error=$_.Exception.Message
            if ($createdLink) { [IO.File]::Delete($path) }
            if ($createdTarget) { [IO.File]::Delete($target) }
            if ($createdWork) { [IO.Directory]::Delete($work,$false) }
            $result.cleanup_complete=(-not (Test-Path -LiteralPath $work) -and -not (Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue))
        }
    } else {
        $link=Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if (-not ($link.Attributes -band [IO.FileAttributes]::ReparsePoint) -or [IO.Path]::GetFullPath([string]$link.Target) -ne [IO.Path]::GetFullPath($target)) { throw 'reparse ownership changed; preserve scene' }
        No-Reparse $work
        if ((Hash-File $target) -ne $request.target_sha256) { throw 'reparse target bytes changed; preserve scene' }
        [IO.File]::Delete($path);[IO.File]::Delete($target);[IO.Directory]::Delete($work,$false)
        $result.cleanup_complete=(-not (Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue) -and -not (Test-Path -LiteralPath $work))
    }
} else { throw 'unsupported ACC009 probe operation' }
$result | ConvertTo-Json -Depth 8 -Compress
