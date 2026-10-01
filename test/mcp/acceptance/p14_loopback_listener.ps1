param([Parameter(Mandatory=$true)][string]$Manifest,
      [ValidateSet('Listener','Cli','Preflight')][string]$Mode='Listener')
$ErrorActionPreference='Stop'
function Write-NewJson($Path,$Value) {
    $bytes=[Text.Encoding]::UTF8.GetBytes(($Value|ConvertTo-Json -Depth 12 -Compress))
    $s=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try {$s.Write($bytes,0,$bytes.Length);$s.Flush($true)} finally {$s.Dispose()}
}
trap {
    $errorRecord=@{pid=$PID;error=($_|Out-String);utc=[DateTime]::UtcNow.ToString('o');mode=$Mode}
    Write-NewJson (Join-Path (Split-Path -Parent $Manifest) 'worker-error.json') $errorRecord
    exit 1
}
function Test-Release($Receipt,$Ready) {
    return ($Receipt.run_id -ceq $Ready.run_id -and $Receipt.controller -ceq $Ready.controller -and
      $Receipt.nonce -ceq $Ready.nonce -and $Receipt.pid -eq $Ready.pid -and
      [string]$Receipt.creation_time -ceq [string]$Ready.creation_time -and $Receipt.action -ceq 'release')
}
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
public class P14JobRow {public long supervisor_handle;public string[] members;public bool worker_member;}
public class P14JobProof {public string api="IsProcessInJob + QueryInformationJobObject";public int supervisor_pid;public string supervisor_creation;public int target_pid;public string target_creation;public P14JobRow[] jobs;public bool duplicates_closed;public bool probe_job_closed;}
public static class P14Jobs {
 [DllImport("ntdll.dll")] static extern int NtQuerySystemInformation(int kind,IntPtr buffer,int length,out int required);
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr CreateJobObject(IntPtr attributes,string name);
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,int pid);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool DuplicateHandle(IntPtr source,IntPtr handle,IntPtr target,out IntPtr result,uint access,bool inherit,uint options);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job,int kind,IntPtr data,int size,out int returned);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
 public static P14JobProof Witness(int supervisor,string supervisorCreated,int target,string targetCreated) {
  if(IntPtr.Size!=8)throw new Exception("64bit native witness required");
  IntPtr probe=CreateJobObject(IntPtr.Zero,null),buffer=IntPtr.Zero,source=IntPtr.Zero;
  var result=new P14JobProof{supervisor_pid=supervisor,supervisor_creation=supervisorCreated,target_pid=target,target_creation=targetCreated};
  var rows=new List<P14JobRow>();
  try {
   if(probe==IntPtr.Zero)throw new Win32Exception();
   using(var sp=Process.GetProcessById(supervisor))using(var tp=Process.GetProcessById(target)) {
    if(P14Native.Created(sp.Handle).ToString()!=supervisorCreated || P14Native.Created(tp.Handle).ToString()!=targetCreated)throw new Exception("native PID creation drift");
   }
   int size=1048576,required,status;
   while(true){buffer=Marshal.AllocHGlobal(size);status=NtQuerySystemInformation(64,buffer,size,out required);if(status==0)break;Marshal.FreeHGlobal(buffer);buffer=IntPtr.Zero;if(status!=unchecked((int)0xc0000004)||size>=16777216)throw new Exception("bounded handle table unavailable");size=Math.Min(16777216,Math.Max(size*2,required));}
   long count=Marshal.ReadInt64(buffer);if(count<0||count>(size-16)/40)throw new Exception("invalid handle table");
   int type=-1;long own=Process.GetCurrentProcess().Id;
   for(long i=0;i<count;i++){IntPtr e=IntPtr.Add(buffer,checked((int)(16+i*40)));if(Marshal.ReadInt64(e,8)==own && Marshal.ReadInt64(e,16)==probe.ToInt64()){type=(ushort)Marshal.ReadInt16(e,30);break;}}
   if(type<0)throw new Exception("Job type witness missing");
   source=OpenProcess(0x40,false,supervisor);if(source==IntPtr.Zero)throw new Win32Exception();
   for(long i=0;i<count;i++) {
    IntPtr e=IntPtr.Add(buffer,checked((int)(16+i*40)));if(Marshal.ReadInt64(e,8)!=supervisor || (ushort)Marshal.ReadInt16(e,30)!=type)continue;
    long number=Marshal.ReadInt64(e,16);IntPtr duplicate;
    if(!DuplicateHandle(source,new IntPtr(number),new IntPtr(-1),out duplicate,4,false,0))throw new Win32Exception();
    try {
     IntPtr list=Marshal.AllocHGlobal(16384);
     try {
      int returned;if(!QueryInformationJobObject(duplicate,3,list,16384,out returned))throw new Win32Exception();
      int n=Marshal.ReadInt32(list,4);if(n<0||n>2047)throw new Exception("bounded Job list unavailable");var members=new List<string>();bool hasTarget=false;
      for(int j=0;j<n;j++){long pid=Marshal.ReadInt64(list,8+j*8);members.Add(pid.ToString());if(pid==target)hasTarget=true;}
      if(hasTarget){bool inJob;using(var self=Process.GetCurrentProcess()){if(!P14Native.IsProcessInJob(self.Handle,duplicate,out inJob))throw new Win32Exception();}rows.Add(new P14JobRow{supervisor_handle=number,members=members.ToArray(),worker_member=inJob});}
     } finally {Marshal.FreeHGlobal(list);}
    } finally {CloseHandle(duplicate);}
   }
   if(rows.Count!=1)throw new Exception("exact current product ManagedJob not identified");
   if(rows[0].worker_member)throw new Exception("worker belongs to current product ManagedJob");
   using(var sp=Process.GetProcessById(supervisor))using(var tp=Process.GetProcessById(target)){if(P14Native.Created(sp.Handle).ToString()!=supervisorCreated||P14Native.Created(tp.Handle).ToString()!=targetCreated)throw new Exception("identity drift after witness");}
   result.jobs=rows.ToArray();result.duplicates_closed=true;
  } finally {if(source!=IntPtr.Zero)CloseHandle(source);if(buffer!=IntPtr.Zero)Marshal.FreeHGlobal(buffer);if(probe!=IntPtr.Zero){CloseHandle(probe);result.probe_job_closed=true;}}
  return result;
 }
}

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
Write-NewJson (Join-Path $root 'launch-receipt.json') ($ready + @{worker_sha256=$m.worker_sha256})
if($Mode -in @('Listener','Preflight')) {
    $inJob=$false;if(![P14Native]::IsProcessInJob($self.Handle,[IntPtr]::Zero,[ref]$inJob)){throw 'job membership unavailable'}
    if($Mode -eq 'Preflight') {
        $service=Get-CimInstance Win32_Service -Filter "Name='fakenetng-mcp'"
        if($service.State -ne 'Stopped' -or $service.ProcessId -ne 0 -or $m.service_pid -or $m.target_pid){throw 'preflight requires product service Stopped, no product target'}
        $jobProof=@{preflight_service_stopped=$true}
    } else {$jobProof=[P14Jobs]::Witness([int]$m.service_pid,[string]$m.service_filetime,[int]$m.target_pid,[string]$m.target_creation_time)}
    $ready.managed_job_proof=$jobProof
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
