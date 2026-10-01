param([Parameter(Mandatory=$true)][string]$Manifest,
      [ValidateSet('Listener','Cli')][string]$Mode='Listener')
$ErrorActionPreference='Stop'
function Write-NewJson($Path,$Value) {
    $bytes=[Text.Encoding]::UTF8.GetBytes(($Value|ConvertTo-Json -Depth 12 -Compress))
    $s=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try {$s.Write($bytes,0,$bytes.Length);$s.Flush($true)} finally {$s.Dispose()}
}
function Test-Release($Receipt,$Ready) {
    return ($Receipt.run_id -ceq $Ready.run_id -and $Receipt.controller -ceq $Ready.controller -and
      $Receipt.nonce -ceq $Ready.nonce -and $Receipt.pid -eq $Ready.pid -and
      [string]$Receipt.creation_time -ceq [string]$Ready.creation_time -and $Receipt.action -ceq 'release')
}
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class P14Native {
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool IsProcessInJob(IntPtr process,IntPtr job,out bool result);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool GetProcessTimes(IntPtr process,out long created,out long exited,out long kernel,out long user);
 public static long Created(IntPtr h) {long c,e,k,u;if(!GetProcessTimes(h,out c,out e,out k,out u))throw new System.ComponentModel.Win32Exception();return c;}
}
'@
$m=Get-Content -LiteralPath $Manifest -Raw|ConvertFrom-Json
foreach($field in @('run_id','controller','nonce')) {if(([guid]$m.$field).ToString() -cne $m.$field){throw 'invalid own identity'}}
$root=[IO.Path]::GetFullPath((Split-Path -Parent $Manifest))
if($root -cne [IO.Path]::GetFullPath([string]$m.directory)){throw 'manifest directory mismatch'}
if($m.lease_seconds -ne 1800){throw 'fixed fixture lease required'}
if((Get-FileHash -LiteralPath $PSCommandPath).Hash.ToLower() -cne $m.worker_sha256){throw 'worker hash mismatch'}
$self=Get-Process -Id $PID;$created=[P14Native]::Created($self.Handle)
$clock=[Diagnostics.Stopwatch]::StartNew();$ready=@{run_id=$m.run_id;controller=$m.controller;nonce=$m.nonce;pid=$PID;creation_time=[string]$created;mode=$Mode;utc=[DateTime]::UtcNow.ToString('o');qpc=[Diagnostics.Stopwatch]::GetTimestamp();frequency=[Diagnostics.Stopwatch]::Frequency}
if($Mode -eq 'Listener') {
    $inJob=$false;if(![P14Native]::IsProcessInJob($self.Handle,[IntPtr]::Zero,[ref]$inJob)){throw 'job membership unavailable'}
    if($inJob){throw 'external listener must not inherit any Job'}
    $listener=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0);$listener.ExclusiveAddressUse=$true
    $reason='lease_expired'
    try {
        $listener.Start();$ready.address='127.0.0.1';$ready.port=$listener.LocalEndpoint.Port;$ready.in_any_job=$inJob
        Write-NewJson (Join-Path $root 'ready.json') $ready
        while($clock.Elapsed.TotalSeconds -lt 1800) {
            $release=Join-Path $root 'release.json'
            if(Test-Path -LiteralPath $release) {
                try {$r=Get-Content -LiteralPath $release -Raw|ConvertFrom-Json;if(Test-Release $r $ready){$reason='cooperative_release';break}} catch {}
            }
            Start-Sleep -Milliseconds 100
        }
    } finally {
        $listener.Stop()
        Write-NewJson (Join-Path $root 'closed.json') (@{ready=$ready;reason=$reason;seconds=$clock.Elapsed.TotalSeconds;listener_stopped=$true;qpc=[Diagnostics.Stopwatch]::GetTimestamp();utc=[DateTime]::UtcNow.ToString('o')})
    }
} else {
    $exe='C:\Program Files\FakeNet-NG-MCP\fakenetng-mcp.exe'
    if((Get-FileHash $exe).Hash.ToLower() -cne $m.exe_sha256){throw 'installed CLI hash drift'}
    $svc=Get-CimInstance Win32_Service -Filter "Name='fakenetng-mcp'"
    $sp=Get-Process -Id $svc.ProcessId
    if($sp.Id -ne $m.service_pid -or [string][P14Native]::Created($sp.Handle) -cne [string]$m.service_filetime){throw 'service instance drift before CLI'}
    $psi=[Diagnostics.ProcessStartInfo]::new($exe,'stop');$psi.UseShellExecute=$false;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
    $p=[Diagnostics.Process]::Start($psi)
    $out=$p.StandardOutput.ReadToEndAsync();$err=$p.StandardError.ReadToEndAsync()
    $native=@{pid=$p.Id;creation_time=[string][P14Native]::Created($p.Handle);semantic='fakenetng-mcp.exe stop';qpc=[Diagnostics.Stopwatch]::GetTimestamp();frequency=[Diagnostics.Stopwatch]::Frequency}
    Write-NewJson (Join-Path $root 'ready.json') (@{ready=$ready;cli=$native})
    $ended=$p.WaitForExit(510000)
    $result=@{ready=$ready;cli=$native;native_ended=$ended;seconds=$clock.Elapsed.TotalSeconds;qpc_end=[Diagnostics.Stopwatch]::GetTimestamp();exit_code=$null;stdout=$null;stderr=$null}
    if($ended){$result.exit_code=$p.ExitCode;$result.stdout=$out.Result;$result.stderr=$err.Result}
    Write-NewJson (Join-Path $root 'result.json') $result
    $p.Dispose()
}
