# Copyright 2026 Google LLC
# VM-side real-traffic probe for test/mcp/acceptance/scenario_suite.py.
# It records one JSON object per observed action.  A traffic result is evidence
# only: the host verifies the corresponding pktmon/managed-flow chain before
# accepting a scenario.
[CmdletBinding()]
param(
    [ValidateSet('traffic', 'preflight-b1', 'ensure-client')]
    [string]$Action = 'traffic',
    [ValidateSet('B1', 'B2', 'B3', 'B4', 'default')]
    [string]$Profile = 'B1',
    [string]$Nonce,
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

function Write-JsonLine([string]$Path, [hashtable]$Value) {
    $Value.utc = [DateTime]::UtcNow.ToString('o')
    $Value.utc_ticks = [DateTime]::UtcNow.Ticks
    $Value.mono = [Diagnostics.Stopwatch]::GetTimestamp()
    if (-not $Value.ContainsKey('pid')) { $Value.pid = $PID }
    if (-not $Value.ContainsKey('worker')) { $Value.worker = 1 }
    if (-not $Value.ContainsKey('seq')) { $Value.seq = 0 }
    [IO.File]::AppendAllText($Path, (($Value | ConvertTo-Json -Compress) + [Environment]::NewLine), [Text.UTF8Encoding]::new($false))
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
    [IO.File]::AppendAllText($Path, (($Value | ConvertTo-Json -Compress) + [Environment]::NewLine), [Text.UTF8Encoding]::new($false))
}

function Ensure-Output([string]$Path) {
    $parent = Split-Path -Parent $Path
    if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    if (Test-Path $Path) { throw "refusing to overwrite evidence $Path" }
}

function Get-Endpoint([string]$Bucket, [string]$Host, [int]$Port, [string]$Protocol) {
    if ($Host -and $Port -gt 0) { return @{ host = $Host; port = $Port; protocol = $Protocol } }
    switch ($Bucket) {
        'B1' { return @{ host = 'api.deepseek.com'; port = 443; protocol = 'tls' } }
        'B4' { return @{ host = 'api.deepseek.com'; port = 443; protocol = 'tls' } }
        'B2' { return @{ host = '10.20.30.40'; port = 1337; protocol = 'tcp' } }
        'B3' { return @{ host = '198.51.100.77'; port = 1337; protocol = 'tcp' } }
        default { return @{ host = '198.51.100.77'; port = 1337; protocol = 'tcp' } }
    }
}

function Ensure-ProbeClient([string]$ResultPath) {
    $root = Split-Path -Parent $ResultPath
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    $exe = Join-Path $root 'scenario-probe-client.exe'
    $source = Join-Path $root 'scenario-probe-client.cs'
    $clientSource = @'
using System;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading;
public static class ScenarioProbeClient {
  public static int Main(string[] a) {
    if (a.Length != 6) return 2;
    var retrySeconds = Int32.Parse(a[5]);
    if (retrySeconds < 20 || retrySeconds > 120) return 2;
    var retryDeadline = DateTime.UtcNow.AddSeconds(retrySeconds); var attempt = 0;
    while (!File.Exists(a[2]) && DateTime.UtcNow < retryDeadline) {
      attempt++; Console.WriteLine("CONNECT_ATTEMPT|" + attempt + "|" + DateTime.UtcNow.Ticks + "|" + Stopwatch.GetTimestamp() + "|" + Stopwatch.Frequency);
      TcpClient c = null;
      try { c = new TcpClient();
        var ar = c.BeginConnect(a[0], Int32.Parse(a[1]), null, null);
        if (!ar.AsyncWaitHandle.WaitOne(1500)) throw new TimeoutException("connect timeout");
        c.EndConnect(ar); Console.WriteLine("ESTABLISHED|" + c.Client.LocalEndPoint + "|" + c.Client.RemoteEndPoint + "|" + DateTime.UtcNow.Ticks + "|" + Stopwatch.GetTimestamp() + "|" + Stopwatch.Frequency);
        var every = Math.Max(1, Int32.Parse(a[3]));
        var request = Encoding.ASCII.GetBytes("FNPR/1|" + a[4] + "|target\n");
        var stream = c.GetStream(); var next = DateTime.UtcNow; var count = 0;
        while (!File.Exists(a[2])) {
          if (DateTime.UtcNow >= next) { stream.Write(request, 0, request.Length); stream.Flush(); count++;
            Console.WriteLine("SEND|" + count + "|" + DateTime.UtcNow.Ticks + "|" + Stopwatch.GetTimestamp() + "|" + Stopwatch.Frequency); next = DateTime.UtcNow.AddMilliseconds(every); }
          Thread.Sleep(Math.Min(25, every));
        }
        c.Close(); Console.WriteLine("CLOSE|" + DateTime.UtcNow.Ticks + "|" + Stopwatch.GetTimestamp() + "|" + Stopwatch.Frequency); return 0;
      } catch (Exception ex) {
        Console.WriteLine("ERROR|" + attempt + "|" + ex.GetType().Name + "|" + DateTime.UtcNow.Ticks + "|" + Stopwatch.GetTimestamp() + "|" + Stopwatch.Frequency);
        if (c != null) c.Close(); Thread.Sleep(250);
      }
    }
    return 3;
  }
}
'@
    $needsBuild = (-not (Test-Path $exe)) -or (-not (Test-Path $source)) -or ((Get-Content $source -Raw) -ne $clientSource)
    if ($needsBuild) {
        $clientSource | Set-Content -LiteralPath $source -Encoding UTF8
        $csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
        if (-not (Test-Path $csc)) { $csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }
        if (-not (Test-Path $csc)) { throw 'C# compiler unavailable for B3 probe executable' }
        & $csc /nologo /target:exe ("/out:$exe") $source
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $exe)) { throw 'B3 probe executable compilation failed' }
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
        if (-not $caseHost -or $port -lt 1 -or $port -gt 65535 -or $protocol -notin @('tcp','tls','udp')) {
            throw "additional target $index is invalid"
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
                $count = $udp.Send($payload, $payload.Length)
                Write-JsonLine $Path @{ event = 'case_udp_sent'; nonce = $Token; connection_id = $connection; case_index = $index; expectation = $expectation; src = $local; dst = "$caseHost`:$port"; actual_dst = $remote; protocol = 'udp'; bytes = $count; cadence_ms = $Cadence }
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
            Write-JsonLine $Path @{ event = 'case_connect_attempt'; nonce = $Token; connection_id = $connection; case_index = $index; expectation = $expectation; dst = "$caseHost`:$port"; protocol = $protocol }
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
    $process = Start-Process -FilePath 'curl.exe' -ArgumentList @('--noproxy','*','-sS','-o','NUL','-w','%{http_code}','--connect-timeout','10','--max-time','30',$uri) -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru -WindowStyle Hidden
    $creation = (Get-Process -Id $process.Id -ErrorAction Stop).StartTime.ToUniversalTime().Ticks
    Write-JsonLine $Path @{ event = 'curl_started'; nonce = $Token; pid = $process.Id; creation_ticks = $creation; url = $uri; command = 'curl.exe --noproxy * -sS -o NUL -w %{http_code} --connect-timeout 10 --max-time 30' }
    if (-not $process.WaitForExit(45000)) { Stop-Process -Id $process.Id -Force; throw 'positive curl exceeded 45 seconds' }
    $out = if (Test-Path $stdout) { Get-Content -LiteralPath $stdout -Raw } else { '' }
    $err = if (Test-Path $stderr) { Get-Content -LiteralPath $stderr -Raw } else { '' }
    Write-JsonLine $Path @{ event = 'curl_completed'; nonce = $Token; pid = $process.Id; exit_code = $process.ExitCode; http_code = $out.Trim(); stderr = $err.Trim(); url = $uri }
}

function Invoke-Traffic([string]$Bucket, [string]$Path, [string]$Token, [string]$Stop, [string]$Start, [int]$Seconds, [string]$Tempo, [string]$Variant, [string]$Interleave, [int]$Cadence, [string]$TargetHost, [int]$TargetPort, [string]$TargetProtocol, [string]$ProcessMode, [string]$TlsServerName, [string]$FnprRole, [string]$AdditionalTargetsJson, [string]$CaseFile, [int]$StartupRetrySeconds) {
    Ensure-Output $Path
    $endpoint = Get-Endpoint $Bucket $TargetHost $TargetPort $TargetProtocol
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    $sequence = 0
    # These axes change packet timing/lifetime, not merely manifest labels.
    $cadenceMs = $Cadence
    $betweenMs = $cadenceMs
    # The launcher is deliberately live before the lifecycle operation but it
    # must not make a socket until the runner releases this recorded gate.
    # This makes before/during/after/restart/stop windows observable facts.
    try { $additionalTargets = @($AdditionalTargetsJson | ConvertFrom-Json) } catch { throw 'AdditionalTargetsJson is not a JSON array' }
    if ($additionalTargets.Count -gt 8) { throw 'AdditionalTargetsJson exceeds bounded case count' }
    if ($StartupRetrySeconds -lt 20 -or $StartupRetrySeconds -gt 120) { throw 'StartupRetrySeconds is outside the bounded range' }
    Write-JsonLine $Path @{ event = 'ready'; nonce = $Token; profile = $Bucket; variant = $Variant; tempo = $Tempo; interleave = $Interleave; cadence_ms = $Cadence; target_host = $endpoint.host; target_port = $endpoint.port; target_protocol = $endpoint.protocol; process_mode = $ProcessMode; fnpr_role = $FnprRole; additional_targets = $additionalTargets; startup_retry_seconds = $StartupRetrySeconds; creation_ticks = [Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime().Ticks; stopwatch_frequency = [Diagnostics.Stopwatch]::Frequency }
    $releaseDeadline = [DateTime]::UtcNow.AddSeconds(90)
    while (-not (Test-Path $Start) -and -not (Test-Path $Stop) -and [DateTime]::UtcNow -lt $releaseDeadline) { Start-Sleep -Milliseconds 20 }
    if (-not (Test-Path $Start)) { throw 'probe start control was not released' }
    Write-JsonLine $Path @{ event = 'released'; nonce = $Token; profile = $Bucket; interleave = $Interleave }
    $casesInvoked = [ref]$false
    $curlInvoked = [ref]$false
    function Invoke-ReleasedCases {
        if ($casesInvoked.Value -or -not $additionalTargets.Count -or -not $CaseFile -or -not (Test-Path $CaseFile)) { return }
        $release = Get-Content -LiteralPath $CaseFile -Raw -ErrorAction Stop
        if ($release.Trim() -ne 'after-healthy') { throw 'case release has an invalid lifecycle phase' }
        Write-JsonLine $Path @{ event = 'cases_released'; nonce = $Token; phase = $release.Trim(); count = $additionalTargets.Count }
        Invoke-AdditionalTargets $additionalTargets $Path $Token $cadenceMs
        if (($Bucket -eq 'B1' -or $Bucket -eq 'B4') -and -not $curlInvoked.Value) {
            Invoke-PositiveCurl $Path $Token
            $curlInvoked.Value = $true
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
        Write-JsonLine $Path @{ event = 'process_ready'; nonce = $Token; profile = $Bucket; variant = $Variant; tempo = $Tempo; interleave = $Interleave; pid = $process.Id; worker = 1; seq = 0; creation_ticks = $childCreation; stopwatch_frequency = [Diagnostics.Stopwatch]::Frequency }
        Write-JsonLine $Path @{ event = 'process_started'; nonce = $Token; connection_id = "$Token-b3"; image = $identity.path; image_sha256 = $identity.sha256; child_pid = $process.Id; pid = $process.Id; dst = "$($endpoint.host):$($endpoint.port)" }
        $deadline = [DateTime]::UtcNow.AddSeconds($StartupRetrySeconds + 5)
        while ((-not (Test-Path $stdout) -or -not ((Get-Content $stdout -Raw -ErrorAction SilentlyContinue) -match 'ESTABLISHED\|')) -and -not $process.HasExited -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 25 }
        $line = if (Test-Path $stdout) { @(Get-Content $stdout | Where-Object { $_ -like 'ESTABLISHED|*' } | Select-Object -First 1) } else { @() }
        $parts = if ($line.Count) { $line[0] -split '\|', 6 } else { @() }
        $local = if ($parts.Count -eq 6) { $parts[1] } else { $null }
        $remote = if ($parts.Count -eq 6) { $parts[2] } else { $null }
        if ($local -and $remote) { Write-NativeJsonLine $Path @{ event = 'established'; nonce = $Token; connection_id = "$Token-b3"; pid = $process.Id; worker = 1; seq = 1; src = $local; dst = "$($endpoint.host):$($endpoint.port)"; actual_dst = $remote; child_pid = $process.Id } ([Int64]$parts[3]) ([Int64]$parts[4]) ([Int64]$parts[5]) }
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
        $closeLine = if (Test-Path $stdout) { @(Get-Content $stdout | Where-Object { $_ -like 'CLOSE|*' } | Select-Object -First 1) } else { @() }
        $closeParts = if ($closeLine.Count) { $closeLine[0] -split '\|', 4 } else { @() }
        $closed = $closeParts.Count -eq 4
        if (-not $closed) { throw 'B3 child supplied no native post-close record' }
        $sendCount = 0
        if (Test-Path $stdout) { foreach ($send in @(Get-Content $stdout | Where-Object { $_ -like 'SEND|*' })) { $sendParts = $send -split '\|', 5; if ($sendParts.Count -ne 5) { throw 'B3 child supplied malformed native SEND' }; $sendCount++; Write-NativeJsonLine $Path @{ event = 'send'; nonce = $Token; connection_id = "$Token-b3"; pid = $process.Id; worker = 1; seq = 1; child_pid = $process.Id; ordinal = $sendCount; cadence_ms = $Cadence; src = $local; actual_dst = $remote } ([Int64]$sendParts[2]) ([Int64]$sendParts[3]) ([Int64]$sendParts[4]) } }
        if ($sendCount -eq 0) { throw 'B3 native client supplied no cadence-controlled send record' }
        Write-NativeJsonLine $Path @{ event = 'close'; nonce = $Token; connection_id = "$Token-b3"; pid = $process.Id; worker = 1; seq = 1; child_pid = $process.Id; exit_code = $process.ExitCode; src = $local; actual_dst = $remote; stdout = $stdout } ([Int64]$closeParts[1]) ([Int64]$closeParts[2]) ([Int64]$closeParts[3])
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
                $count = $udp.Send($payload, $payload.Length)
                Write-JsonLine $Path @{ event = 'udp_sent'; nonce = $Token; connection_id = $connection; seq = $sequence; src = $local; dst = "$($endpoint.host):$($endpoint.port)"; actual_dst = $remote; protocol = 'udp'; bytes = $count; cadence_ms = $cadenceMs }
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
