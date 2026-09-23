# Copyright 2026 Google LLC
# VM-side real-traffic probe for test/mcp/acceptance/scenario_suite.py.
# It records one JSON object per observed action.  A traffic result is evidence
# only: the host verifies the corresponding pktmon/managed-flow chain before
# accepting a scenario.
[CmdletBinding()]
param(
    [ValidateSet('traffic', 'preflight-b1', 'ensure-client', 'identity')]
    [string]$Action = 'traffic',
    [ValidateSet('B1', 'B2', 'B3', 'B4', 'default')]
    [string]$Profile = 'B1',
    [string]$Nonce,
    [string]$CaptureRunId,
    [string]$CandidateId,
    [switch]$DiagnosticIdentity,
    [int]$IdentityPid,
    [string]$Output,
    [string]$StopFile,
    [string]$StartFile,
    [ValidateSet('hold', 'burst', 'stagger', 'drip', 'overlap')]
    [string]$Tempo = 'hold',
    [string]$Variant = 'baseline',
    [string]$TargetHost,
    [int]$TargetPort,
    [ValidateSet('tcp', 'tls', 'udp')]
    [string]$TargetProtocol = 'tcp',
    [ValidateSet('match', 'nonmatch')]
    [string]$ProcessMode = 'match',
    [string]$TlsServerName,
    [string]$FnprRole,
    [string]$AdditionalTargetsJson = '[]',
    [string]$CaseFile,
    [int]$StartupRetrySeconds = 70,
    [ValidateSet('before-start', 'during-start', 'after-healthy', 'restart-window', 'stop-window')]
    [string]$Interleave = 'during-start',
    [int]$CadenceMilliseconds = 250,
    [int]$HoldSeconds = 90
)

$ErrorActionPreference = 'Stop'

# Use one native UTC sample for both JSON representations. WinPS5 DateTime.UtcNow
# can remain unchanged across a complete short connection.
if (-not ('ScenarioProbeClock' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class ScenarioProbeClock {
    [DllImport("kernel32.dll")]
    private static extern void GetSystemTimePreciseAsFileTime(out long value);
    public static long UtcTicks() {
        long value; GetSystemTimePreciseAsFileTime(out value);
        return value + 504911232000000000L;
    }
    public static long[] Sample() {
        // Pair the clocks before returning to PowerShell. Formatting and
        // dynamic dispatch must not sit between the two observations.
        long utc = UtcTicks();
        long mono = System.Diagnostics.Stopwatch.GetTimestamp();
        return new long[] { utc, mono };
    }
}
'@
}

function Write-JsonLine([string]$Path, [hashtable]$Value) {
    $sample = [ScenarioProbeClock]::Sample()
    $ticks = $sample[0]
    $Value.utc = [DateTime]::new($ticks, [DateTimeKind]::Utc).ToString('o')
    $Value.utc_ticks = $ticks
    $Value.mono = $sample[1]
    if (-not $Value.ContainsKey('pid')) { $Value.pid = $PID }
    if (-not $Value.ContainsKey('worker')) { $Value.worker = 1 }
    if (-not $Value.ContainsKey('seq')) { $Value.seq = 0 }
    [IO.File]::AppendAllText($Path, (($Value | ConvertTo-Json -Depth 12 -Compress) + [Environment]::NewLine), [Text.UTF8Encoding]::new($false))
}

function Write-NativeJsonLine([string]$Path, [hashtable]$Value, [Int64]$UtcTicks, [Int64]$Mono, [Int64]$Frequency) {
    # B3's socket process supplies these values before stdout is drained.  Do
    # not turn a native send/close into a later wrapper observation.
    $Value.utc = [DateTime]::new($UtcTicks, [DateTimeKind]::Utc).ToString('o')
    $Value.utc_ticks = $UtcTicks
    $Value.mono = $Mono
    $Value.stopwatch_frequency = $Frequency
    if (-not $Value.ContainsKey('worker')) { $Value.worker = 1 }
    if (-not $Value.ContainsKey('seq')) { $Value.seq = 0 }
    [IO.File]::AppendAllText($Path, (($Value | ConvertTo-Json -Depth 12 -Compress) + [Environment]::NewLine), [Text.UTF8Encoding]::new($false))
}

function Get-NativeIdentity([int]$TargetPid, [string]$Run, [string]$Token, [string]$Candidate) {
    # Diagnostic only. phnt ntexapi.h class 90 / Win10 x64 layout:
    # GUID at 0, FirmwareType at 16, BootFlags at 24, sizeof=32.
    $base = @{schema='sst.native-identity.v1';supported=$false;run_id=$Run;nonce=$Token;candidate_id=$Candidate;
        boot_api='NtQuerySystemInformation';boot_class=90;boot_layout='phnt:SYSTEM_BOOT_ENVIRONMENT_INFORMATION:win10-19045-x64';
        process_api='GetProcessTimes';creation_unit='FILETIME_100ns_since_1601';frequency_api='QueryPerformanceFrequency';frequency_unit='ticks_per_second'}
    try {
        if (-not [Environment]::Is64BitProcess) { throw 'x64 process required' }
        $version = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Version
        if ($version -ne '10.0.19045') { throw ('unverified Windows build: '+$version) }
        if (-not ('SstNativeIdentity' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class SstNativeIdentity {
  [DllImport("ntdll.dll")] static extern int NtQuerySystemInformation(int cls, IntPtr buffer, uint length, out uint returned);
  [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetProcessTimes(IntPtr handle, out long created, out long exit, out long kernel, out long user);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool QueryPerformanceFrequency(out long frequency);
  public static object[] Boot() {
    IntPtr p=Marshal.AllocHGlobal(32);
    try {
      for(int i=0;i<32;i++) Marshal.WriteByte(p,i,0);
      uint returned; int status=NtQuerySystemInformation(90,p,32,out returned);
      byte[] raw=new byte[32]; Marshal.Copy(p,raw,0,32);
      if(status!=0 || returned!=32) throw new InvalidOperationException("class 90 status/length "+status+"/"+returned);
      byte[] guidBytes=new byte[16]; Array.Copy(raw,0,guidBytes,0,16);
      Guid guid=new Guid(guidBytes);
      if(guid==Guid.Empty) throw new InvalidOperationException("zero BootIdentifier");
      return new object[]{guid.ToString(),BitConverter.ToUInt32(raw,16),BitConverter.ToUInt64(raw,24),
        BitConverter.ToString(raw).Replace("-","").ToLowerInvariant(),status,returned};
    } finally { Marshal.FreeHGlobal(p); }
  }
  public static long Creation(int pid, int currentPid) {
    bool owned=pid!=currentPid; IntPtr h=owned?OpenProcess(0x1000,false,pid):GetCurrentProcess();
    if(h==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(),"OpenProcess");
    try { long c,e,k,u; if(!GetProcessTimes(h,out c,out e,out k,out u))
      throw new Win32Exception(Marshal.GetLastWin32Error(),"GetProcessTimes");
      if(c<=0) throw new InvalidOperationException("invalid creation FILETIME"); return c;
    } finally { if(owned) CloseHandle(h); }
  }
  public static long Frequency() { long hz; if(!QueryPerformanceFrequency(out hz) || hz<=0)
    throw new Win32Exception(Marshal.GetLastWin32Error(),"QueryPerformanceFrequency"); return hz; }
}
'@
        }
        $collector = [int]$PID
        if ($TargetPid -le 0) { $TargetPid = $collector }
        $boot = [SstNativeIdentity]::Boot()
        $machine = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop).MachineGuid
        if (-not $machine -or -not $env:COMPUTERNAME) { throw 'VM identity incomplete' }
        $base.supported=$true
        $base.boot=@{boot_identifier=[string]$boot[0];firmware_type=[uint32]$boot[1];boot_flags=[uint64]$boot[2];
            raw_hex=[string]$boot[3];ntstatus=[int]$boot[4];return_length=[int]$boot[5];buffer_length=32;information_class=90;layout=$base.boot_layout}
        $base.collector_pid=$collector
        $base.collector_creation_filetime_100ns=[SstNativeIdentity]::Creation($collector,$collector)
        $base.pid=$TargetPid
        $base.creation_filetime_100ns=[SstNativeIdentity]::Creation($TargetPid,$collector)
        $base.qpc_frequency=[SstNativeIdentity]::Frequency()
        $base.vm_identity=@{computer_name=$env:COMPUTERNAME;machine_guid=([string]$machine).ToLowerInvariant()}
    } catch { $base.supported=$false;$base.error=($_.Exception.GetType().Name+': '+$_.Exception.Message) }
    return $base
}

function Ensure-Output([string]$Path) {
    $parent = Split-Path -Parent $Path
    if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    if (Test-Path $Path) { throw "refusing to overwrite evidence $Path" }
}

function Get-Endpoint([string]$Bucket, [string]$EndpointHost, [int]$Port, [string]$Protocol) {
    if ($EndpointHost -and $Port -gt 0) { return @{ host = $EndpointHost; port = $Port; protocol = $Protocol } }
    switch ($Bucket) {
        'B1' { return @{ host = 'api.deepseek.com'; port = 443; protocol = 'tls' } }
        'B4' { return @{ host = 'api.deepseek.com'; port = 443; protocol = 'tls' } }
        'B2' { return @{ host = '10.20.30.40'; port = 1337; protocol = 'tcp' } }
        'B3' { return @{ host = '198.51.100.77'; port = 1337; protocol = 'tcp' } }
        default { return @{ host = '198.51.100.77'; port = 1337; protocol = 'tcp' } }
    }
}

function Wait-EngineReadiness([string]$Path, [string]$Token, [string]$Bucket, [string]$ProcessMode, [int]$BudgetSeconds, [datetime]$LauncherStartUtc, [string]$RunsRoot = 'C:\ProgramData\FakeNet-NG-MCP\artifacts\runs') {
    # A during-start probe released before the managed engine is armed
    # reaches the real internet (divert absent) and its one connection never
    # traverses the product (discovery100-109 sst-003). B3 additionally must
    # not launch its reviewed image before the product's quiescence check
    # passed (sst-035: PolicyConfigError). Connect only after the CURRENT
    # run's own run.log publishes its engine-ready line; runs older than
    # this launcher never satisfy the wait.
    # Readiness markers are the lines the diverter logs AFTER the WinDivert
    # handle opens (interception active). B2 relay configs publish
    # DOMAIN_TAKEOVER_READY instead of EGRESS_CONTROL_READY
    # (discovery100-112 sst-016); IP_ALLOW_READY is deliberately excluded
    # because it precedes the handle. B3 waits for the post-quiescence rule
    # line so the reviewed image launches only after the product accepts it.
    $isB3 = ($Bucket -eq 'B3' -and $ProcessMode -eq 'match')
    # The legacy default template never publishes the egress-control or
    # domain-takeover readiness lines.  Its interception-active fact used to
    # be the diverter's per-flow "requested TCP|UDP" record, which only
    # appears once some background packet actually arrives (candidate04-dns-01:
    # released 02:04:13, first background flow 02:05:28 - a 75s wait that no
    # quiet network can satisfy).  The product now logs the completion of
    # initialization/startup itself: FakeNet.start emits one timestamped INFO
    # FakeNet DEFAULT_INTERCEPTION_READY line after diverter.start() returns
    # cleanly (WinDivert handle open + receiver running).  The default wait
    # accepts ONLY that marker - never a background flow again.  B1/B2/B4
    # keep their two ready markers and B3 match keeps the post-quiescence
    # rule line.  Historical LEGACY_REQUESTED lines stay parseable by the
    # host oracle for old originals, but a new probe never falls back to them.
    $isLegacyDefault = ($Bucket -eq 'default')
    $markerPattern = if ($isB3) { 'PROCESS_REDIRECT_RULE_READY' }
                     elseif ($isLegacyDefault) { '^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}\s+INFO FakeNet DEFAULT_INTERCEPTION_READY\b' }
                     else { 'EGRESS_CONTROL_READY|DOMAIN_TAKEOVER_READY' }
    $deadline = [DateTime]::UtcNow.AddSeconds($BudgetSeconds)
    $observed = $null
    $matched = $null
    $matchedLine = $null
    while ([DateTime]::UtcNow -lt $deadline) {
        $runs = Get-ChildItem -LiteralPath $RunsRoot -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.CreationTimeUtc -gt $LauncherStartUtc } |
            Sort-Object CreationTimeUtc -Descending | Select-Object -First 4
        foreach ($run in $runs) {
            $log = Join-Path $run.FullName 'run.log'
            if (Test-Path -LiteralPath $log) {
                $hit = @(Select-String -LiteralPath $log -Pattern $markerPattern -ErrorAction SilentlyContinue | Select-Object -First 1)
                if ($hit.Count) {
                    $observed = $run.Name
                    $matchedLine = $hit[0].Line
                    if ($matchedLine -match '(EGRESS_CONTROL_READY|DOMAIN_TAKEOVER_READY|PROCESS_REDIRECT_RULE_READY)') { $matched = $Matches[1] }
                    elseif ($matchedLine -match 'DEFAULT_INTERCEPTION_READY') { $matched = 'DEFAULT_INTERCEPTION_READY' }
                    elseif ($matchedLine -match 'requested (TCP|UDP)') { $matched = 'LEGACY_REQUESTED_' + $Matches[1] }
                    break
                }
            }
        }
        if ($observed) { break }
        Start-Sleep -Milliseconds 50
    }
    if (-not $observed) { throw ("engine readiness marker not observed within $BudgetSeconds seconds: $markerPattern") }
    # The marker can precede the last listener bind by a moment; a short
    # settle keeps the single connection attempt inside the served window.
    Start-Sleep -Milliseconds 1000
    Write-JsonLine $Path @{ event = 'engine_ready_observed'; nonce = $Token; profile = $Bucket; process_mode = $ProcessMode; marker = $matched; marker_line = $matchedLine; run_id = $observed }
}

function Ensure-ProbeClient([string]$ResultPath) {
    $root = Split-Path -Parent $ResultPath
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    # Reuse a live previous build when its image still exists: recompiling
    # into the SAME exe path requires overwriting an image that antivirus
    # routinely holds for many minutes after first execution
    # (CS0016, discovery100-59 sst-041..045: locked across a whole batch).
    if (Test-Path -LiteralPath $ResultPath) {
        try {
            $prior = Get-Content -LiteralPath $ResultPath -Raw | ConvertFrom-Json
            if ($prior -and $prior.path -and (Test-Path -LiteralPath $prior.path)) {
                return $prior
            }
        } catch { }
    }
    # Each build writes under a unique name so csc never overwrites a file
    # any scanner may hold; stale builds are swept best-effort.
    Get-ChildItem -LiteralPath $root -Filter 'scenario-probe-client-*.exe' -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTimeUtc -lt [DateTime]::UtcNow.AddHours(-1) } |
        Remove-Item -Force -ErrorAction SilentlyContinue
    $buildId = [Guid]::NewGuid().ToString('N')
    $exe = Join-Path $root ("scenario-probe-client-$buildId.exe")
    $source = Join-Path $root ("scenario-probe-client-$buildId.cs")
    $clientSource = @'
using System;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading;
public static class ScenarioProbeClient {
  [System.Runtime.InteropServices.DllImport("kernel32.dll")]
  private static extern void GetSystemTimePreciseAsFileTime(out long value);
  private static long UtcTicks() {
    long value; GetSystemTimePreciseAsFileTime(out value);
    return value + 504911232000000000L;
  }
  public static int Main(string[] a) {
    if (a.Length != 6) return 2;
    var retrySeconds = Int32.Parse(a[5]);
    if (retrySeconds < 20 || retrySeconds > 120) return 2;
    var retryDeadline = DateTime.UtcNow.AddSeconds(retrySeconds); var attempt = 0;
    while (!File.Exists(a[2]) && DateTime.UtcNow < retryDeadline) {
      attempt++; Console.WriteLine("CONNECT_ATTEMPT|" + attempt + "|" + UtcTicks() + "|" + Stopwatch.GetTimestamp() + "|" + Stopwatch.Frequency);
      TcpClient c = null;
      try { c = new TcpClient();
        var ar = c.BeginConnect(a[0], Int32.Parse(a[1]), null, null);
        if (!ar.AsyncWaitHandle.WaitOne(1500)) throw new TimeoutException("connect timeout");
        c.EndConnect(ar); Console.WriteLine("ESTABLISHED|" + c.Client.LocalEndPoint + "|" + c.Client.RemoteEndPoint + "|" + UtcTicks() + "|" + Stopwatch.GetTimestamp() + "|" + Stopwatch.Frequency); Console.Out.Flush();
        var every = Math.Max(1, Int32.Parse(a[3]));
        var request = Encoding.ASCII.GetBytes("FNPR/1|" + a[4] + "|target\n");
        var stream = c.GetStream(); var next = DateTime.UtcNow; var count = 0;
        while (!File.Exists(a[2])) {
          if (DateTime.UtcNow >= next) { stream.Write(request, 0, request.Length); stream.Flush(); count++;
            Console.WriteLine("SEND|" + count + "|" + UtcTicks() + "|" + Stopwatch.GetTimestamp() + "|" + Stopwatch.Frequency); Console.Out.Flush(); next = DateTime.UtcNow.AddMilliseconds(every); }
          Thread.Sleep(Math.Min(25, every));
        }
        c.Close(); Console.WriteLine("CLOSE|" + UtcTicks() + "|" + Stopwatch.GetTimestamp() + "|" + Stopwatch.Frequency); Console.Out.Flush(); return 0;
      } catch (Exception ex) {
        Console.WriteLine("ERROR|" + attempt + "|" + ex.GetType().Name + "|" + UtcTicks() + "|" + Stopwatch.GetTimestamp() + "|" + Stopwatch.Frequency); Console.Out.Flush();
        if (c != null) c.Close(); Thread.Sleep(250);
      }
    }
    return 3;
  }
}
'@
    $needsBuild = $true
    if ($needsBuild) {
        $clientSource | Set-Content -LiteralPath $source -Encoding UTF8
        $csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
        if (-not (Test-Path $csc)) { $csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }
        if (-not (Test-Path $csc)) { throw 'C# compiler unavailable for B3 probe executable' }
        # A freshly written source or a just-recreated output is routinely
        # held for a moment by antivirus filters; retry across that window
        # instead of failing the scenario, and keep the compiler diagnostics
        # in the failure when retries are exhausted (discovery100-58
        # sst-041/042/043: three identical compilation failures with the
        # wrapper message only).
        $compiled = $false
        $attempts = @()
        $lastOutput = ''
        for ($attempt = 1; $attempt -le 5 -and -not $compiled; $attempt++) {
            $lastOutput = (& $csc /nologo /target:exe ("/out:$exe") $source 2>&1 | Out-String)
            $compiled = ($LASTEXITCODE -eq 0) -and (Test-Path $exe)
            $attempts += "attempt=$attempt exit=$LASTEXITCODE exe=$(Test-Path $exe)"
            if (-not $compiled) { Start-Sleep -Seconds 2 }
        }
        if (-not $compiled) { throw ('B3 probe executable compilation failed: ' + ($attempts -join '; ') + ' csc said: ' + $lastOutput) }
    }
    $row = @{ path = $exe; sha256 = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower(); public_ipv4 = '198.51.100.77'; private_ipv4 = '192.168.204.1' }
    [IO.File]::WriteAllText($ResultPath, ($row | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
    return $row
}

function Invoke-PreflightB1([string]$Token) {
    $url = "https://api.deepseek.com/$Token"
    $code = 1
    $text = & curl.exe --noproxy '*' -sS -o NUL -w '%{http_code}' --connect-timeout 10 --max-time 30 $url 2>$null
    if ($LASTEXITCODE -eq 0) { $code = 0 }
    @{ exit_code = $code; http_code = "$text"; url = $url; nonce = $Token } | ConvertTo-Json -Compress
}

function New-ApplicationRequest([string]$Kind, [string]$Token, [int]$Index) {
    # The request bytes are frozen by contract; the host oracle re-derives and
    # byte-compares them from the nonce, so nothing here is trusted as evidence.
    if ($Kind -in @('tcp-echo','udp-echo')) {
        return [Text.Encoding]::ASCII.GetBytes("SSTAPP-$Token-case-$Index")
    }
    if ($Kind -eq 'http-tcp') {
        return [Text.Encoding]::ASCII.GetBytes("GET /sst-$Token.html HTTP/1.1`r`nHost: $Token.invalid`r`nConnection: close`r`n`r`n")
    }
    if ($Kind -eq 'dns-udp') {
        $hash = [Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::ASCII.GetBytes("dns-$Token-case-$Index"))
        $bytes = New-Object System.Collections.Generic.List[byte]
        $bytes.Add($hash[0]); $bytes.Add($hash[1])   # transaction id
        $bytes.Add(1); $bytes.Add(0)                 # recursion desired
        $bytes.Add(0); $bytes.Add(1)                 # qdcount
        $bytes.Add(0); $bytes.Add(0); $bytes.Add(0); $bytes.Add(0); $bytes.Add(0); $bytes.Add(0)
        foreach ($label in "$Token.invalid".Split('.')) {
            $labelBytes = [Text.Encoding]::ASCII.GetBytes($label)
            $bytes.Add($labelBytes.Length); $bytes.AddRange($labelBytes)
        }
        $bytes.Add(0)                                # root label
        $bytes.Add(0); $bytes.Add(1)                 # qtype A
        $bytes.Add(0); $bytes.Add(1)                 # qclass IN
        return $bytes.ToArray()
    }
    throw "unknown application kind: $Kind"
}

function Get-HttpFrameTarget([System.Collections.Generic.List[byte]]$Chunks, [int]$Length) {
    # Returns the complete-frame byte count once the head terminated with
    # CRLFCRLF is fully received (Content-Length may legitimately be 0), -1
    # while the head is still incomplete, and -2 for a head that can never
    # frame legally (Transfer-Encoding, duplicate or invalid Content-Length):
    # the caller ends with an explicit protocol-error terminal instead of
    # waiting out the budget on a frame that must not be forged.
    for ($i = 0; $i -le $Length - 4; $i++) {
        if ($Chunks[$i] -eq 13 -and $Chunks[$i+1] -eq 10 -and $Chunks[$i+2] -eq 13 -and $Chunks[$i+3] -eq 10) {
            $head = [Text.Encoding]::ASCII.GetString($Chunks.ToArray(), 0, $i)
            $lengths = @()
            foreach ($line in ($head -split "`r`n")) {
                $parts = $line -split ':', 2
                if ($parts.Count -ne 2) { continue }
                $name = $parts[0].Trim().ToLower()
                if ($name -eq 'transfer-encoding') { return -2 }
                if ($name -eq 'content-length') { $lengths += $parts[1].Trim() }
            }
            if ($lengths.Count -ne 1) { return -2 }
            $value = 0
            if (-not [int]::TryParse($lengths[0], [System.Globalization.NumberStyles]::None, [Globalization.CultureInfo]::InvariantCulture, [ref]$value)) { return -2 }
            if ($value -lt 0) { return -2 }
            return $i + 4 + $value
        }
    }
    return -1
}

function Read-TcpResponse([Net.Sockets.NetworkStream]$Stream, [Net.Sockets.TcpClient]$Client,
                          [System.Diagnostics.Stopwatch]$Budget, [int]$FrameTarget) {
    # One accumulating loop shared by every application TCP read.  FrameTarget
    # greater than zero is a fixed byte count (the echo request length); zero
    # parses the HTTP Content-Length inside this same loop after every
    # accumulation, so a complete frame returns immediately without waiting
    # for the peer EOF.  Every read is bounded by both the 8 KiB scratch
    # buffer and the remaining 64 KiB response cap.  Already-received bytes
    # survive every exit path - timeout, EOF, cap, or exception - together
    # with explicit eof/timed_out/truncated/error terminals.
    $chunks = New-Object System.Collections.Generic.List[byte]
    $buffer = New-Object byte[] 8192
    $eof = $false; $timedOut = $false; $truncated = $false; $octets = 0
    $error = $null
    try {
        while ($true) {
            if ($FrameTarget -gt 0 -and $octets -ge $FrameTarget) { break }
            if ($FrameTarget -eq 0) {
                $target = Get-HttpFrameTarget $chunks $octets
                if ($target -eq -2) { $error = 'http head cannot frame legally'; break }
                if ($target -gt 0 -and $octets -ge $target) { break }
            }
            if ($octets -ge 65536) { $truncated = $true; break }
            $remainingMs = [int](10000 - $Budget.ElapsedMilliseconds)
            if ($remainingMs -le 0) { $timedOut = $true; break }
            if (-not $Client.Client.Poll([Math]::Max($remainingMs, 1) * 1000, [Net.Sockets.SelectMode]::SelectRead)) { $timedOut = $true; break }
            if ($Client.Available -eq 0) { $eof = $true; $truncated = $true; break }
            $take = [Math]::Min([Math]::Min($buffer.Length, $Client.Available), 65536 - $octets)
            if ($take -le 0) { $truncated = $true; break }
            $read = $Stream.Read($buffer, 0, $take)
            if ($read -le 0) { $eof = $true; $truncated = $true; break }
            for ($i = 0; $i -lt $read; $i++) { $chunks.Add($buffer[$i]) }
            $octets += $read
        }
        if (-not $eof -and $null -eq $error -and $Budget.ElapsedMilliseconds -ge 10000) {
            # An operation that returned past the shared deadline is a late
            # success: the native flag says timed out, no new tolerance.
            $timedOut = $true
        }
    } catch {
        $error = $_.Exception.Message
    }
    @{ data = $chunks.ToArray(); octets = $octets; eof = $eof; timed_out = $timedOut; truncated = $truncated; error = $error }
}

function Invoke-ApplicationCase([string]$Kind, [string]$CaseHost, [int]$Port, [string]$Path,
                                [string]$Token, [int]$Index, [string]$Connection, [string]$Expectation) {
    # One Stopwatch budget spans connect/UDP preparation through response
    # completion; every blocking call consumes only the remaining time and a
    # return past the deadline is a timeout.  The exchange event is always
    # recorded - partial bytes and terminal flags included - so an error
    # never reduces the evidence to a label.
    $request = New-ApplicationRequest $Kind $Token $Index
    $protocol = if ($Kind -in @('udp-echo','dns-udp')) { 'udp' } else { 'tcp' }
    $budget = [System.Diagnostics.Stopwatch]::StartNew()
    $startedMono = [Diagnostics.Stopwatch]::GetTimestamp()
    $frequency = [Diagnostics.Stopwatch]::Frequency
    $recorded = $false
    $local = ''; $remote = ''; $sendBefore = 0; $sendAfter = 0
    $response = $null; $eof = $false; $timedOut = $false; $truncated = $false
    $failure = $null
    try {
        if ($protocol -eq 'udp') {
            $udp = [Net.Sockets.UdpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
            try {
                # The destination is a frozen numeric sink address; parsing it
                # directly avoids any ambient DNS dependency.
                $udp.Connect([Net.IPAddress]::Parse($CaseHost), $Port)
                $local = $udp.Client.LocalEndPoint.ToString()
                $remote = $udp.Client.RemoteEndPoint.ToString()
                $remaining = [int](10000 - $budget.ElapsedMilliseconds)
                if ($remaining -le 0) { throw [TimeoutException]::New('application budget exhausted before UDP send') }
                $udp.Client.SendTimeout = $remaining
                $sendBefore = [ScenarioProbeClock]::UtcTicks()
                $sent = $udp.Send($request, $request.Length)
                $sendAfter = [ScenarioProbeClock]::UtcTicks()
                if ($budget.ElapsedMilliseconds -ge 10000) { $timedOut = $true; throw [TimeoutException]::New('UDP send returned after the budget') }
                Write-JsonLine $Path @{ event = 'case_udp_sent'; nonce = $Token; connection_id = $Connection; case_index = $Index; expectation = $Expectation; src = $local; dst = "$CaseHost`:$Port"; actual_dst = $remote; protocol = 'udp'; bytes = $sent; byte_count = $sent; send_before_ticks = $sendBefore; send_after_ticks = $sendAfter; application = $Kind }
                $remaining = [int](10000 - $budget.ElapsedMilliseconds)
                if ($remaining -le 0) { $timedOut = $true; throw [TimeoutException]::New('application budget exhausted before UDP receive') }
                $udp.Client.ReceiveTimeout = $remaining
                $peer = [Net.IPEndPoint]::new([Net.IPAddress]::Any, 0)
                $response = $udp.Receive([ref]$peer)
                $eof = $true
                if ($budget.ElapsedMilliseconds -ge 10000) { $timedOut = $true; throw [TimeoutException]::New('UDP receive returned after the budget') }
                Write-JsonLine $Path @{ event = 'case_application_exchange'; nonce = $Token; connection_id = $Connection; case_index = $Index; expectation = $Expectation; application = $Kind; protocol = 'udp'; src = $local; dst = "$CaseHost`:$Port"; actual_dst = $remote; peer = $peer.ToString(); pid = $PID; request_b64 = [Convert]::ToBase64String($request); response_b64 = [Convert]::ToBase64String($response); response_octets = $response.Length; eof = $true; timed_out = $false; truncated = $false; exchange_budget_seconds = 10; send_before_ticks = $sendBefore; send_after_ticks = $sendAfter; receive_after_ticks = [ScenarioProbeClock]::UtcTicks(); exchange_started_mono = $startedMono; exchange_finished_mono = [Diagnostics.Stopwatch]::GetTimestamp(); stopwatch_frequency = $frequency }
                $recorded = $true
                return
            } finally { $udp.Dispose() }
        }
        $client = [Net.Sockets.TcpClient]::new()
        try {
            if (-not $client.Client.Connected) { $client.Client.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Any, 0)) }
            $attemptLocal = $client.Client.LocalEndPoint.ToString()
            Write-JsonLine $Path @{ event = 'case_connect_attempt'; nonce = $Token; connection_id = $Connection; case_index = $Index; expectation = $Expectation; src = $attemptLocal; dst = "$CaseHost`:$Port"; protocol = 'tcp'; application = $Kind }
            $remaining = [int](10000 - $budget.ElapsedMilliseconds)
            if ($remaining -le 0) { $timedOut = $true; throw [TimeoutException]::New('application budget exhausted before connect') }
            $async = $client.BeginConnect([Net.IPAddress]::Parse($CaseHost), $Port, $null, $null)
            try {
                if (-not $async.AsyncWaitHandle.WaitOne($remaining)) { $timedOut = $true; throw [TimeoutException]::New('application case connect exceeded the remaining budget') }
                $client.EndConnect($async)
            } finally {
                $async.AsyncWaitHandle.Close()
            }
            if ($budget.ElapsedMilliseconds -ge 10000) { $timedOut = $true; throw [TimeoutException]::New('application connect returned after the budget') }
            $local = $client.Client.LocalEndPoint.ToString()
            $remote = $client.Client.RemoteEndPoint.ToString()
            Write-JsonLine $Path @{ event = 'case_established'; nonce = $Token; connection_id = $Connection; case_index = $Index; expectation = $Expectation; src = $local; dst = "$CaseHost`:$Port"; actual_dst = $remote; protocol = 'tcp'; application = $Kind }
            $stream = $client.GetStream()
            $remaining = [int](10000 - $budget.ElapsedMilliseconds)
            if ($remaining -le 0) { $timedOut = $true; throw [TimeoutException]::New('application budget exhausted before write') }
            $stream.WriteTimeout = $remaining
            $sendBefore = [ScenarioProbeClock]::UtcTicks()
            $stream.Write($request, 0, $request.Length); $stream.Flush()
            $sendAfter = [ScenarioProbeClock]::UtcTicks()
            if ($budget.ElapsedMilliseconds -ge 10000) { $timedOut = $true; throw [TimeoutException]::New('application write returned after the budget') }
            $requestEvent = if ($Kind -eq 'http-tcp') { 'case_request_sent' } else { 'case_send' }
            Write-JsonLine $Path @{ event = $requestEvent; nonce = $Token; connection_id = $Connection; case_index = $Index; expectation = $Expectation; bytes = $request.Length; byte_count = $request.Length; cadence_ms = 0; application = $Kind; send_before_ticks = $sendBefore; send_after_ticks = $sendAfter }
            $frameTarget = $request.Length
            if ($Kind -eq 'http-tcp') { $frameTarget = 0 }
            $received = Read-TcpResponse $stream $client $budget $frameTarget
            $response = $received.data
            $octets = $received.octets
            $eof = [bool]$received.eof; $timedOut = [bool]$received.timed_out; $truncated = [bool]$received.truncated
            if ($received.error) {
                $failure = [IO.InvalidDataException]::New("application $Kind protocol terminal: $($received.error)")
                throw $failure
            }
            if ($timedOut) { throw [TimeoutException]::New("application $Kind response exceeded the shared 10 second budget") }
            if ($truncated) { throw [IO.InvalidDataException]::New("application $Kind response is incomplete at EOF or exceeds the 64 KiB cap") }
            Write-JsonLine $Path @{ event = 'case_application_exchange'; nonce = $Token; connection_id = $Connection; case_index = $Index; expectation = $Expectation; application = $Kind; protocol = 'tcp'; src = $local; dst = "$CaseHost`:$Port"; actual_dst = $remote; peer = $remote; pid = $PID; request_b64 = [Convert]::ToBase64String($request); response_b64 = [Convert]::ToBase64String($response); response_octets = $octets; eof = [bool]$eof; timed_out = [bool]$timedOut; truncated = [bool]$truncated; exchange_budget_seconds = 10; send_before_ticks = $sendBefore; send_after_ticks = $sendAfter; receive_after_ticks = [ScenarioProbeClock]::UtcTicks(); exchange_started_mono = $startedMono; exchange_finished_mono = [Diagnostics.Stopwatch]::GetTimestamp(); stopwatch_frequency = $frequency }
            $recorded = $true
        } finally { $client.Dispose() }
    } catch {
        $failure = $_.Exception
        # PowerShell wraps socket exceptions; retain their actual timeout
        # terminal instead of only reporting a generic application failure.
        $cause = $failure
        while ($null -ne $cause) {
            if ($cause -is [TimeoutException] -or
                ($cause -is [Net.Sockets.SocketException] -and
                 $cause.SocketErrorCode -eq [Net.Sockets.SocketError]::TimedOut)) {
                $timedOut = $true
            }
            $cause = $cause.InnerException
        }
        if ($budget.ElapsedMilliseconds -ge 10000) { $timedOut = $true }
        throw
    } finally {
        if (-not $recorded) {
            # Failure evidence: the partial bytes and terminal flags are part
            # of the record; the thrown error still reaches case_error.
            $partial = if ($null -ne $response) { [Convert]::ToBase64String($response) } else { '' }
            $partialOctets = if ($null -ne $response) { $response.Length } else { 0 }
            $errorMessage = if ($null -ne $failure) { $failure.Message } else { 'application case failed before a complete exchange' }
            Write-JsonLine $Path @{ event = 'case_application_exchange'; nonce = $Token; connection_id = $Connection; case_index = $Index; expectation = $Expectation; application = $Kind; protocol = $protocol; src = $local; dst = "$CaseHost`:$Port"; actual_dst = $remote; pid = $PID; request_b64 = [Convert]::ToBase64String($request); response_b64 = $partial; response_octets = $partialOctets; eof = [bool]$eof; timed_out = [bool]$timedOut; truncated = [bool]$truncated; exchange_budget_seconds = 10; send_before_ticks = $sendBefore; send_after_ticks = $sendAfter; receive_after_ticks = [ScenarioProbeClock]::UtcTicks(); exchange_started_mono = $startedMono; exchange_finished_mono = [Diagnostics.Stopwatch]::GetTimestamp(); stopwatch_frequency = $frequency; error_terminal = $true; error_message = $errorMessage }
        }
    }
}

function Invoke-AdditionalTargets([object[]]$Targets, [string]$Path, [string]$Token, [int]$Cadence) {
    $index = 0
    foreach ($case in $Targets) {
        $index++
        $caseHost = [string]$case.host
        $port = [int]$case.port
        $protocol = [string]$case.protocol
        $expectation = [string]$case.expectation
        $sni = [string]$case.tls_server_name
        $fnprRole = [string]$case.fnpr_role
        $application = [string]$case.application
        if (-not $caseHost -or $port -lt 1 -or $port -gt 65535 -or $protocol -notin @('tcp','tls','udp')) {
            throw "additional target $index is invalid"
        }
        if ($application) {
            # Real application exchange cases carry their own full request/
            # response byte recording; an error fails the scenario (the host
            # oracle additionally re-verifies the bytes from the JSONL).
            $connection = "$Token-case-$index"
            try {
                Invoke-ApplicationCase $application $caseHost $port $Path $Token $index $connection $expectation
            } catch {
                Write-JsonLine $Path @{ event = 'case_error'; nonce = $Token; connection_id = $connection; case_index = $index; expectation = $expectation; protocol = $protocol; application = $application; error_type = $_.Exception.GetType().Name; message = $_.Exception.Message }
            } finally {
                Write-JsonLine $Path @{ event = 'case_close'; nonce = $Token; connection_id = $connection; case_index = $index; expectation = $expectation; protocol = $protocol; application = $application }
            }
            Start-Sleep -Milliseconds $Cadence
            continue
        }
        $connection = "$Token-case-$index"
        if ($protocol -eq 'udp') {
            $udp = [Net.Sockets.UdpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
            try {
                $resolved = @([Net.Dns]::GetHostAddresses($caseHost) | Where-Object {$_.AddressFamily -eq 'InterNetwork'} | Select-Object -First 1)
                if ($resolved.Count -ne 1) { throw 'additional UDP target did not resolve to one IPv4 address' }
                $udp.Connect($resolved[0], $port)
                $local = $udp.Client.LocalEndPoint.ToString()
                $remote = $udp.Client.RemoteEndPoint.ToString()
                $payload = [Text.Encoding]::ASCII.GetBytes("SST-$Token-case-$index")
                $sendBefore = [ScenarioProbeClock]::UtcTicks()
                $count = $udp.Send($payload, $payload.Length)
                $sendAfter = [ScenarioProbeClock]::UtcTicks()
                Write-JsonLine $Path @{ event = 'case_udp_sent'; nonce = $Token; connection_id = $connection; case_index = $index; expectation = $expectation; src = $local; dst = "$caseHost`:$port"; actual_dst = $remote; protocol = 'udp'; bytes = $count; byte_count = $count; send_before_ticks = $sendBefore; send_after_ticks = $sendAfter; cadence_ms = $Cadence }
            } catch {
                Write-JsonLine $Path @{ event = 'case_error'; nonce = $Token; connection_id = $connection; case_index = $index; expectation = $expectation; protocol = 'udp'; error_type = $_.Exception.GetType().Name; message = $_.Exception.Message }
            } finally {
                Write-JsonLine $Path @{ event = 'case_close'; nonce = $Token; connection_id = $connection; case_index = $index; expectation = $expectation; protocol = 'udp' }
                $udp.Dispose()
            }
            Start-Sleep -Milliseconds $Cadence
            continue
        }
        $client = [Net.Sockets.TcpClient]::new()
        try {
            # Bind eagerly so the local endpoint is known even when the
            # connect never completes: a silently dropped SYN (Drop policy)
            # leaves no established event, and the tuple is the only way the
            # host can bind the attempt to the policy drop line.
            if (-not $client.Client.Connected) { $client.Client.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Any, 0)) }
            $attemptLocal = $client.Client.LocalEndPoint.ToString()
            Write-JsonLine $Path @{ event = 'case_connect_attempt'; nonce = $Token; connection_id = $connection; case_index = $index; expectation = $expectation; src = $attemptLocal; dst = "$caseHost`:$port"; protocol = $protocol }
            $async = $client.BeginConnect($caseHost, $port, $null, $null)
            if (-not $async.AsyncWaitHandle.WaitOne(5000)) { throw [TimeoutException]::new('additional target connect timeout') }
            $client.EndConnect($async)
            $local = $client.Client.LocalEndPoint.ToString()
            $remote = $client.Client.RemoteEndPoint.ToString()
            Write-JsonLine $Path @{ event = 'case_established'; nonce = $Token; connection_id = $connection; case_index = $index; expectation = $expectation; src = $local; dst = "$caseHost`:$port"; actual_dst = $remote; protocol = $protocol }
            if ($protocol -eq 'tls') {
                $stream = [Net.Security.SslStream]::new($client.GetStream(), $false)
                $serverName = if ($sni) { $sni } else { $caseHost }
                Write-JsonLine $Path @{ event = 'case_tls_handshake_attempt'; nonce = $Token; connection_id = $connection; case_index = $index; expectation = $expectation; sni = $serverName; cadence_ms = $Cadence }
                $stream.ReadTimeout = 5000; $stream.WriteTimeout = 5000
                $stream.AuthenticateAsClient($serverName)
                $bytes = [Text.Encoding]::ASCII.GetBytes("GET /$Token/case/$index HTTP/1.1`r`nHost: $caseHost`r`nConnection: close`r`n`r`n")
                $stream.Write($bytes, 0, $bytes.Length);$stream.Flush()
                Write-JsonLine $Path @{ event = 'case_request_sent'; nonce = $Token; connection_id = $connection; case_index = $index; expectation = $expectation; bytes = $bytes.Length; cadence_ms = $Cadence }
                $stream.Dispose()
            } else {
                $bytes = if ($fnprRole) { [Text.Encoding]::ASCII.GetBytes("FNPR/1|$Token|$fnprRole`n") } else { [Text.Encoding]::ASCII.GetBytes("SST-$Token-case-$index") }
                $client.GetStream().Write($bytes, 0, $bytes.Length);$client.GetStream().Flush()
                Write-JsonLine $Path @{ event = 'case_send'; nonce = $Token; connection_id = $connection; case_index = $index; expectation = $expectation; bytes = $bytes.Length; cadence_ms = $Cadence; fnpr_role = $fnprRole }
                if ($fnprRole) {
                    $client.ReceiveTimeout = 3000;$buffer = New-Object byte[] 512;$read = $client.GetStream().Read($buffer, 0, $buffer.Length);$reply = [Text.Encoding]::ASCII.GetString($buffer, 0, $read)
                    Write-JsonLine $Path @{ event = 'case_response'; nonce = $Token; connection_id = $connection; case_index = $index; expectation = $expectation; response = $reply; fnpr_role = $fnprRole }
                }
            }
        } catch {
            Write-JsonLine $Path @{ event = 'case_error'; nonce = $Token; connection_id = $connection; case_index = $index; expectation = $expectation; protocol = $protocol; error_type = $_.Exception.GetType().Name; message = $_.Exception.Message }
        } finally {
            Write-JsonLine $Path @{ event = 'case_close'; nonce = $Token; connection_id = $connection; case_index = $index; expectation = $expectation; protocol = $protocol }
            $client.Dispose()
        }
        Start-Sleep -Milliseconds $Cadence
    }
}

function Invoke-PositiveCurl([string]$Path, [string]$Token) {
    # This is the accepted positive relay command: it keeps normal certificate
    # validation and explicitly bypasses any ambient proxy.  Its PID is later
    # joined to PROCESS_FLOW and the physical-NIC upstream tuple by the host.
    $root = Split-Path -Parent $Path
    $stdout = Join-Path $root 'positive-curl.stdout'
    $stderr = Join-Path $root 'positive-curl.stderr'
    if ((Test-Path $stdout) -or (Test-Path $stderr)) { throw 'positive curl output already exists' }
    $uri = "https://api.deepseek.com/$Token"
    $dnsBefore = [ScenarioProbeClock]::UtcTicks()
    $dnsIPv4 = @([Net.Dns]::GetHostAddresses('api.deepseek.com') | Where-Object {$_.AddressFamily -eq 'InterNetwork'} | ForEach-Object {$_.ToString()} | Sort-Object -Unique)
    if (-not $dnsIPv4.Count) { throw 'curl DNS IPv4 set is empty' }
    $process = Start-Process -FilePath 'curl.exe' -ArgumentList @('--noproxy','*','-sS','-o','NUL','-w','%{http_code}','--connect-timeout','10','--max-time','30',$uri) -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru -WindowStyle Hidden
    # Retain the native handle before exit; WinPS5 otherwise loses ExitCode.
    $nativeHandle = $process.Handle
    $creation = $process.StartTime.ToUniversalTime().Ticks
    Write-JsonLine $Path @{ event = 'curl_started'; nonce = $Token; pid = $process.Id; creation_ticks = $creation; dns_before_ticks = $dnsBefore; dns_ipv4 = $dnsIPv4; url = $uri; command = 'curl.exe --noproxy * -sS -o NUL -w %{http_code} --connect-timeout 10 --max-time 30' }
    if (-not $process.WaitForExit(45000)) { Stop-Process -Id $process.Id -Force; throw 'positive curl exceeded 45 seconds' }
    $out = if (Test-Path $stdout) { Get-Content -LiteralPath $stdout -Raw } else { '' }
    $err = if (Test-Path $stderr) { Get-Content -LiteralPath $stderr -Raw } else { '' }
    Write-JsonLine $Path @{ event = 'curl_completed'; nonce = $Token; pid = $process.Id; exit_code = $process.ExitCode; http_code = "$out".Trim(); stderr = "$err".Trim(); url = $uri }
}

function Invoke-Traffic([string]$Bucket, [string]$Path, [string]$Token, [string]$Stop, [string]$Start, [int]$Seconds, [string]$Tempo, [string]$Variant, [string]$Interleave, [int]$Cadence, [string]$TargetHost, [int]$TargetPort, [string]$TargetProtocol, [string]$ProcessMode, [string]$TlsServerName, [string]$FnprRole, [string]$AdditionalTargetsJson, [string]$CaseFile, [int]$StartupRetrySeconds) {
    Ensure-Output $Path
    $endpoint = Get-Endpoint $Bucket $TargetHost $TargetPort $TargetProtocol
    $sequence = 0
    # These axes change packet timing/lifetime, not merely manifest labels.
    $cadenceMs = $Cadence
    $betweenMs = $cadenceMs
    # The launcher is deliberately live before the lifecycle operation but it
    # must not make a socket until the runner releases this recorded gate.
    # This makes before/during/after/restart/stop windows observable facts.
    try { $parsedTargets = ConvertFrom-Json -InputObject $AdditionalTargetsJson; $additionalTargets = @(foreach ($target in $parsedTargets) { $target }) } catch { throw 'AdditionalTargetsJson is not a JSON array' }
    if ($additionalTargets.Count -gt 8) { throw 'AdditionalTargetsJson exceeds bounded case count' }
    if ($StartupRetrySeconds -lt 20 -or $StartupRetrySeconds -gt 120) { throw 'StartupRetrySeconds is outside the bounded range' }
    $ready = @{ event = 'ready'; nonce = $Token; pid = $PID; profile = $Bucket; variant = $Variant; tempo = $Tempo; interleave = $Interleave; cadence_ms = $Cadence; target_host = $endpoint.host; target_port = $endpoint.port; target_protocol = $endpoint.protocol; process_mode = $ProcessMode; fnpr_role = $FnprRole; additional_targets = $additionalTargets; startup_retry_seconds = $StartupRetrySeconds; creation_ticks = [Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime().Ticks; stopwatch_frequency = [Diagnostics.Stopwatch]::Frequency }
    if ($DiagnosticIdentity) { $ready.native_identity = Get-NativeIdentity $PID $CaptureRunId $Token $CandidateId }
    Write-JsonLine $Path $ready
    # A stop-window probe is released at the END of the active window by
    # definition; for a restart-lifecycle scenario that includes the whole
    # restart transition plus its recovery audit settle window (~150s), so
    # the plain 90s deadline expired before the release and the probe died
    # with 'probe start control was not released' (fakenet100 r09-run-07
    # sst-005 run-02). Every other interleave keeps the 90s bound.
    $releaseWaitSeconds = if ($Interleave -eq 'stop-window') { 300 } else { 90 }
    $releaseDeadline = [DateTime]::UtcNow.AddSeconds($releaseWaitSeconds)
    while (-not (Test-Path $Start) -and -not (Test-Path $Stop) -and [DateTime]::UtcNow -lt $releaseDeadline) { Start-Sleep -Milliseconds 20 }
    if (-not (Test-Path $Start)) { throw 'probe start control was not released' }
    Write-JsonLine $Path @{ event = 'released'; nonce = $Token; profile = $Bucket; interleave = $Interleave }
    # Only the during-start interleave races the engine; every other
    # interleave is released after the engine is already proven up.
    if ($Interleave -eq 'during-start') {
        Wait-EngineReadiness -Path $Path -Token $Token -Bucket $Bucket -ProcessMode $ProcessMode -BudgetSeconds $StartupRetrySeconds -LauncherStartUtc ([Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime() + [TimeSpan]::FromSeconds(-2))
    }
    # Startup/release waiting has its own bounded budgets. The traffic
    # window starts only when this probe is allowed and ready to connect.
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    $casesInvoked = [ref]$false
    $curlInvoked = [ref]$false
    function Invoke-ReleasedCases {
        if ($casesInvoked.Value -or -not $additionalTargets.Count -or -not $CaseFile -or -not (Test-Path $CaseFile)) { return }
        $release = Get-Content -LiteralPath $CaseFile -Raw -ErrorAction Stop
        if ($release.Trim() -ne 'after-healthy') { throw 'case release has an invalid lifecycle phase' }
        Write-JsonLine $Path @{ event = 'cases_released'; nonce = $Token; phase = $release.Trim(); count = $additionalTargets.Count }
        $casesInvoked.Value = $true
        Invoke-AdditionalTargets $additionalTargets $Path $Token $cadenceMs
        if (($Bucket -eq 'B1' -or $Bucket -eq 'B4') -and -not $curlInvoked.Value) {
            $curlInvoked.Value = $true
            Invoke-PositiveCurl $Path $Token
        }
        $casesInvoked.Value = $true
    }
    if ($Bucket -eq 'B3' -and $ProcessMode -eq 'match') {
        # B3 must originate from the exact image whose path/SHA is embedded in
        # the rendered config.  The launcher records its native stdout local
        # endpoint; the host still requires matching pktmon flow evidence.
        $suiteRoot = $PSScriptRoot
        $identityPath = Join-Path $suiteRoot 'probe-client.json'
        $identity = Ensure-ProbeClient $identityPath
        $stdout = Join-Path (Split-Path -Parent $Path) 'probe-client.stdout'
        $process = Start-Process -FilePath $identity.path -ArgumentList @($endpoint.host, $endpoint.port, $Stop, $Cadence, $Token, $StartupRetrySeconds) -RedirectStandardOutput $stdout -PassThru -WindowStyle Hidden
        $childCreation = (Get-Process -Id $process.Id).StartTime.ToUniversalTime().Ticks
        $childReady = @{ event = 'process_ready'; nonce = $Token; profile = $Bucket; variant = $Variant; tempo = $Tempo; interleave = $Interleave; pid = $process.Id; worker = 1; seq = 0; creation_ticks = $childCreation; stopwatch_frequency = [Diagnostics.Stopwatch]::Frequency }
        if ($DiagnosticIdentity) { $childReady.native_identity = Get-NativeIdentity $process.Id $CaptureRunId $Token $CandidateId }
        Write-JsonLine $Path $childReady
        Write-JsonLine $Path @{ event = 'process_started'; nonce = $Token; connection_id = "$Token-b3"; image = $identity.path; image_sha256 = $identity.sha256; child_pid = $process.Id; pid = $process.Id; dst = "$($endpoint.host):$($endpoint.port)" }
        $deadline = [DateTime]::UtcNow.AddSeconds($StartupRetrySeconds + 5)
        $script:b3EstablishedEmitted = $false
        while ((-not (Test-Path $stdout) -or -not ((Get-Content $stdout -Raw -ErrorAction SilentlyContinue) -match 'ESTABLISHED\|')) -and -not $process.HasExited -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 25 }
        $line = if (Test-Path $stdout) { @(Get-Content $stdout | Where-Object { $_ -like 'ESTABLISHED|*' } | Select-Object -First 1) } else { @() }
        $parts = if (@($line).Count) { @($line)[0] -split '\|', 6 } else { @() }
        $local = if ($parts.Count -eq 6) { $parts[1] } else { $null }
        $remote = if ($parts.Count -eq 6) { $parts[2] } else { $null }
        if ($local -and $remote) { $script:b3EstablishedEmitted = $true; Write-NativeJsonLine $Path @{ event = 'established'; nonce = $Token; connection_id = "$Token-b3"; pid = $process.Id; worker = 1; seq = 1; src = $local; dst = "$($endpoint.host):$($endpoint.port)"; actual_dst = $remote; child_pid = $process.Id } ([Int64]$parts[3]) ([Int64]$parts[4]) ([Int64]$parts[5]) }
        while (-not $process.HasExited -and -not (Test-Path $Stop)) { Start-Sleep -Milliseconds 200 }
        if (-not $process.HasExited) { if (-not (Test-Path $Stop)) { throw 'B3 probe stop control is absent' }; if (-not $process.WaitForExit(30000)) { throw 'B3 child did not close after stop control' } }
        $attemptCount = 0
        $errorCount = 0
        if (Test-Path $stdout) {
            foreach ($attempt in @(Get-Content $stdout | Where-Object { $_ -like 'CONNECT_ATTEMPT|*' })) {
                $attemptParts = $attempt -split '\|', 5
                if ($attemptParts.Count -ne 5) { throw 'B3 child supplied malformed native connect attempt' }
                $attemptCount++
                Write-NativeJsonLine $Path @{ event = 'connect_attempt'; nonce = $Token; connection_id = "$Token-b3-attempt-$($attemptParts[1])"; pid = $process.Id; worker = 1; seq = 0; child_pid = $process.Id; ordinal = [Int32]$attemptParts[1]; dst = "$($endpoint.host):$($endpoint.port)" } ([Int64]$attemptParts[2]) ([Int64]$attemptParts[3]) ([Int64]$attemptParts[4])
            }
            foreach ($error in @(Get-Content $stdout | Where-Object { $_ -like 'ERROR|*' })) {
                $errorParts = $error -split '\|', 6
                if ($errorParts.Count -ne 6) { throw 'B3 child supplied malformed native connect error' }
                $errorCount++
                Write-NativeJsonLine $Path @{ event = 'connect_error'; nonce = $Token; connection_id = "$Token-b3-attempt-$($errorParts[1])"; pid = $process.Id; worker = 1; seq = 0; child_pid = $process.Id; ordinal = [Int32]$errorParts[1]; error_type = $errorParts[2]; dst = "$($endpoint.host):$($endpoint.port)" } ([Int64]$errorParts[3]) ([Int64]$errorParts[4]) ([Int64]$errorParts[5])
            }
        }
        if ($attemptCount -eq 0) { throw 'B3 child supplied no native connect attempts' }
        if (-not $script:b3EstablishedEmitted) {
            # Fallback after child exit: with per-line flush the record is in
            # the file long before this point, but a poll-window miss must
            # not discard a connection the receiver actually served.
            $lateLine = if (Test-Path $stdout) { @(Get-Content $stdout | Where-Object { $_ -like 'ESTABLISHED|*' } | Select-Object -First 1) } else { @() }
            $lateParts = if (@($lateLine).Count) { @($lateLine)[0] -split '\|', 6 } else { @() }
            if ($lateParts.Count -eq 6) {
                $local = $lateParts[1]; $remote = $lateParts[2]
                Write-NativeJsonLine $Path @{ event = 'established'; nonce = $Token; connection_id = "$Token-b3"; pid = $process.Id; worker = 1; seq = 1; src = $local; dst = "$($endpoint.host):$($endpoint.port)"; actual_dst = $remote; child_pid = $process.Id } ([Int64]$lateParts[3]) ([Int64]$lateParts[4]) ([Int64]$lateParts[5])
            } else {
                # Diagnostic companion: SEND records prove a live connection,
                # so a missing ESTABLISHED record with SENDs present means
                # the line exists but does not match the pattern -- capture
                # the raw first bytes for offline root-causing.
                $sendCount0 = @((Get-Content $stdout) | Where-Object { $_ -like 'SEND|*' }).Count
                if ($sendCount0 -gt 0) {
                    $firstRaw = @((Get-Content $stdout) | Select-Object -First 1)
                    $firstText = if (@($firstRaw).Count) { @($firstRaw)[0].Substring(0, [Math]::Min(60, @($firstRaw)[0].Length)) } else { '' }
                    Write-JsonLine $Path @{ event = 'b3_established_parse_anomaly'; nonce = $Token; sends = $sendCount0; first_line = $firstText }
                }
            }
        }
        $closeLine = if (Test-Path $stdout) { @(Get-Content $stdout | Where-Object { $_ -like 'CLOSE|*' } | Select-Object -First 1) } else { @() }
        $closeParts = if (@($closeLine).Count) { @($closeLine)[0] -split '\|', 4 } else { @() }
        $closed = $closeParts.Count -eq 4
        $sendCount = 0
        if (Test-Path $stdout) { foreach ($send in @(Get-Content $stdout | Where-Object { $_ -like 'SEND|*' })) { $sendParts = $send -split '\|', 5; if ($sendParts.Count -ne 5) { throw 'B3 child supplied malformed native SEND' }; $sendCount++; Write-NativeJsonLine $Path @{ event = 'send'; nonce = $Token; connection_id = "$Token-b3"; pid = $process.Id; worker = 1; seq = 1; child_pid = $process.Id; ordinal = $sendCount; cadence_ms = $Cadence; src = $local; actual_dst = $remote } ([Int64]$sendParts[2]) ([Int64]$sendParts[3]) ([Int64]$sendParts[4]) } }
        if ($sendCount -eq 0) { throw 'B3 native client supplied no cadence-controlled send record' }
        if (-not $process.HasExited) {
            # The reviewed image must not outlive the scenario: the product's
            # start quiescence correctly refuses while it runs
            # (discovery100-67 sst-051: next start failed with 'reviewed
            # process image is already running before READY').
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            $process.WaitForExit(10000) | Out-Null
        }
        # A force-ended child leaves no CLOSE record: anchor the synthetic
        # terminal at the wrapper's own kill-time clock instead of zero --
        # a zero timestamp collapses the host-side lifetime window
        # (discovery100-69 sst-041..044: utc_ticks=0 made probe_end
        # negative and the lifetime check unsatisfiable).
        $closeTicks = if ($closed) { $closeParts[1] } else { [string][ScenarioProbeClock]::UtcTicks() }
        $closeMono = if ($closed) { $closeParts[2] } else { [string][Diagnostics.Stopwatch]::GetTimestamp() }
        $closeFreq = if ($closed) { $closeParts[3] } else { [Diagnostics.Stopwatch]::Frequency }
        Write-NativeJsonLine $Path @{ event = 'close'; nonce = $Token; connection_id = "$Token-b3"; pid = $process.Id; worker = 1; seq = 1; child_pid = $process.Id; exit_code = $process.ExitCode; src = $local; actual_dst = $remote; stdout = $stdout; native_close = $closed } ([Int64]$closeTicks) ([Int64]$closeMono) ([Int64]$closeFreq)
        Write-JsonLine $Path @{ event = 'finished'; nonce = $Token }
        return
    }
    if ($endpoint.protocol -eq 'udp') {
        $udp = [Net.Sockets.UdpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
        try {
            $resolved = @([Net.Dns]::GetHostAddresses($endpoint.host) | Where-Object {$_.AddressFamily -eq 'InterNetwork'} | Select-Object -First 1)
            if ($resolved.Count -ne 1) { throw 'primary UDP target did not resolve to one IPv4 address' }
            $udp.Connect($resolved[0], [int]$endpoint.port)
            $local = $udp.Client.LocalEndPoint.ToString()
            $remote = $udp.Client.RemoteEndPoint.ToString()
            $connection = "$Token-udp-1"
            while ([DateTime]::UtcNow -lt $deadline -and -not (Test-Path $Stop)) {
                Invoke-ReleasedCases
                $sequence++
                $payload = [Text.Encoding]::ASCII.GetBytes("SST-$Token-udp-$sequence")
                $sendBefore = [ScenarioProbeClock]::UtcTicks()
                $count = $udp.Send($payload, $payload.Length)
                $sendAfter = [ScenarioProbeClock]::UtcTicks()
                Write-JsonLine $Path @{ event = 'udp_sent'; nonce = $Token; connection_id = $connection; seq = $sequence; src = $local; dst = "$($endpoint.host):$($endpoint.port)"; actual_dst = $remote; protocol = 'udp'; bytes = $count; byte_count = $count; send_before_ticks = $sendBefore; send_after_ticks = $sendAfter; cadence_ms = $cadenceMs }
                Start-Sleep -Milliseconds $cadenceMs
            }
        } catch {
            Write-JsonLine $Path @{ event = 'error'; nonce = $Token; connection_id = "$Token-udp-1"; seq = $sequence; protocol = 'udp'; error_type = $_.Exception.GetType().Name; message = $_.Exception.Message }
        } finally {
            Write-JsonLine $Path @{ event = 'close'; nonce = $Token; connection_id = "$Token-udp-1"; seq = $sequence; protocol = 'udp' }
            $udp.Dispose()
        }
        Write-JsonLine $Path @{ event = 'finished'; nonce = $Token }
        return
    }
    while ([DateTime]::UtcNow -lt $deadline -and -not (Test-Path $Stop)) {
        Invoke-ReleasedCases
        $sequence++
        $connection = "${Token}-${sequence}"
        $client = [Net.Sockets.TcpClient]::new()
        try {
            Write-JsonLine $Path @{ event = 'connect_attempt'; nonce = $Token; connection_id = $connection; seq = $sequence; dst = "$($endpoint.host):$($endpoint.port)" }
            $async = $client.BeginConnect($endpoint.host, [int]$endpoint.port, $null, $null)
            if (-not $async.AsyncWaitHandle.WaitOne(10000)) { throw [TimeoutException]::new('connect timeout') }
            $client.EndConnect($async)
            $local = $client.Client.LocalEndPoint.ToString()
            $remote = $client.Client.RemoteEndPoint.ToString()
            Write-JsonLine $Path @{ event = 'established'; nonce = $Token; connection_id = $connection; seq = $sequence; src = $local; dst = "$($endpoint.host):$($endpoint.port)"; actual_dst = $remote }
            # Boundary cases are separately released by the controller after
            # the managed run has published healthy.  The primary session is
            # still opened at the declared interleave point above.
            if ($endpoint.protocol -eq 'tls') {
                $ssl = [Net.Security.SslStream]::new($client.GetStream(), $false)
                $sni = if ($TlsServerName) { $TlsServerName } else { $endpoint.host }
                # A denied SNI may reject during the ClientHello, before any
                # HTTP request can exist.  Preserve the exact TLS-send intent
                # as a separately correlated probe action; the host still
                # requires all-component send evidence and no NIC leakage.
                Write-JsonLine $Path @{ event = 'tls_handshake_attempt'; nonce = $Token; connection_id = $connection; seq = $sequence; cadence_ms = $cadenceMs; sni = $sni; bytes = 0 }
                $ssl.ReadTimeout = 5000; $ssl.WriteTimeout = 5000
                $ssl.AuthenticateAsClient($sni)
                $requestOrdinal = 0
                while ([DateTime]::UtcNow -lt $deadline -and -not (Test-Path $Stop)) {
                    Invoke-ReleasedCases
                    $requestOrdinal++
                    $request = "GET /$Token/$requestOrdinal HTTP/1.1`r`nHost: $($endpoint.host)`r`nConnection: keep-alive`r`n`r`n"
                    $bytes = [Text.Encoding]::ASCII.GetBytes($request)
                    $ssl.Write($bytes, 0, $bytes.Length)
                    $ssl.Flush()
                    Write-JsonLine $Path @{ event = 'request_sent'; nonce = $Token; connection_id = $connection; seq = $sequence; ordinal = $requestOrdinal; cadence_ms = $cadenceMs; bytes = $bytes.Length }
                    Start-Sleep -Milliseconds $cadenceMs
                }
                $ssl.Dispose()
            } else {
                $bytes = if ($FnprRole) { [Text.Encoding]::ASCII.GetBytes("FNPR/1|$Token|$FnprRole`n") } else { [Text.Encoding]::ASCII.GetBytes("SST-$Token-$sequence ") }
                while ([DateTime]::UtcNow -lt $deadline -and -not (Test-Path $Stop)) {
                    Invoke-ReleasedCases
                    $client.GetStream().Write($bytes, 0, $bytes.Length)
                    Write-JsonLine $Path @{ event = 'send'; nonce = $Token; connection_id = $connection; seq = $sequence; cadence_ms = $cadenceMs; bytes = $bytes.Length; fnpr_role = $FnprRole }
                    if ($FnprRole -and $sequence -eq 1) {
                        $client.ReceiveTimeout = 3000;$buffer = New-Object byte[] 512;$read = $client.GetStream().Read($buffer, 0, $buffer.Length);$reply = [Text.Encoding]::ASCII.GetString($buffer, 0, $read)
                        Write-JsonLine $Path @{ event = 'response'; nonce = $Token; connection_id = $connection; seq = $sequence; response = $reply; fnpr_role = $FnprRole }
                    }
                    Start-Sleep -Milliseconds $cadenceMs
                }
            }
        } catch {
            Write-JsonLine $Path @{ event = 'error'; nonce = $Token; connection_id = $connection; seq = $sequence; error_type = $_.Exception.GetType().Name; message = $_.Exception.Message }
        } finally {
            Write-JsonLine $Path @{ event = 'close'; nonce = $Token; connection_id = $connection; seq = $sequence }
            $client.Dispose()
        }
        Start-Sleep -Milliseconds $betweenMs
    }
    Write-JsonLine $Path @{ event = 'finished'; nonce = $Token }
}

switch ($Action) {
    'identity' {
        Get-NativeIdentity $IdentityPid $CaptureRunId $Nonce $CandidateId | ConvertTo-Json -Depth 8 -Compress
    }
    'ensure-client' {
        if (-not $Output) { throw '-Output is required for ensure-client' }
        Ensure-ProbeClient $Output | Out-Null
    }
    'preflight-b1' {
        if (-not $Nonce) { throw '-Nonce is required for preflight-b1' }
        Invoke-PreflightB1 $Nonce
    }
    'traffic' {
        if (-not $Output -or -not $Nonce -or -not $StopFile -or -not $StartFile) { throw '-Output, -Nonce, -StopFile and -StartFile are required for traffic' }
        Invoke-Traffic $Profile $Output $Nonce $StopFile $StartFile $HoldSeconds $Tempo $Variant $Interleave $CadenceMilliseconds $TargetHost $TargetPort $TargetProtocol $ProcessMode $TlsServerName $FnprRole $AdditionalTargetsJson $CaseFile $StartupRetrySeconds
    }
}
