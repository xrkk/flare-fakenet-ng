"""Fixed benign Windows probe, matrix v1 and strict bounded result parsing.

The PowerShell payload is one fixed script.  Every protocol uses an explicit
address family, a bounded send/receive, an exact nonce/transaction check and
an independent final read by the host.  A timeout, ICMP unreachable text or a
non-empty response is never by itself a local-interception pass.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re

from fakenet.mcp import egress_contract

PROBE_SCHEMA = 'fakenetng.windows-egress-probe.v2'
POSITIVE_ID = 'local_interception_positive'
MATRIX_TIMEOUT_MS = 500
DEFAULT_DEADLINE_MS = 30000


PROBE_TEMPLATE = r'''
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$payload=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__PAYLOAD__'))|ConvertFrom-Json
$nonce=[string]$payload.nonce
$steps=@($payload.steps)
$deadline=if($payload.deadline_utc){[DateTime]::Parse([string]$payload.deadline_utc).ToUniversalTime()}else{[DateTime]::UtcNow.AddMilliseconds([int]$payload.deadline_ms)}
$out=[ordered]@{schema='__SCHEMA__';nonce=$nonce;instance=$null;identity=$null;firewall=@();firewall_error=$null;positive=$null;matrix_run=$false;stop_remaining=$false;steps=@();completed_at=$null}
try {
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
  $process=Get-Process -Id $PID
  $image=[string]$process.Path
  $os=Get-CimInstance Win32_OperatingSystem
  $system=Get-CimInstance Win32_ComputerSystemProduct
  $out.instance=[ordered]@{pid=$PID;creation_ticks=$process.StartTime.ToUniversalTime().ToFileTimeUtc();nonce=$nonce;script_hash=[string]$payload.script_hash;deadline_utc=$deadline.ToString('o')}
  $out.identity=[ordered]@{
    pid=$PID
    creation_ticks=$process.StartTime.ToUniversalTime().ToFileTimeUtc()
    account=[string]$identity.Name
    computer=[Environment]::MachineName
    sid=[string]$identity.User.Value
    session=[int]$process.SessionId
    image_path=$image
    image_sha256=(Get-FileHash -LiteralPath $image -Algorithm SHA256).Hash.ToLowerInvariant()
    vm_uuid=([string]$system.UUID).ToUpperInvariant()
    boot_id=$os.LastBootUpTime.ToUniversalTime().ToString('o')
    powershell=$PSVersionTable.PSVersion.ToString()
    token_integrity_level='unknown'
    policy_scope='unknown'
    protocol_class=[string]$payload.protocol_class
  }
  try {
    $groups=(& whoami /groups 2>$null | Out-String)
    $il=[regex]::Match($groups,'S-1-16-\d+')
    if($il.Success){$out.identity.token_integrity_level=$il.Value}
  } catch {}
  try {
    $xml=[string](Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop)
    if($xml){
      $sha=[Security.Cryptography.SHA256]::Create()
      $digest=$sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($xml))
      $out.identity.policy_scope='applocker:'+(($digest|ForEach-Object {$_.ToString('x2')}) -join '')
    }
  } catch {}
} catch { throw ('identity: '+[string]$_) }
try {
  $out.firewall=@(Get-NetFirewallProfile -PolicyStore ActiveStore|Select-Object Name,Enabled|ForEach-Object {[ordered]@{name=[string]$_.Name;enabled=[bool]$_.Enabled}})
} catch { $out.firewall_error=[string]$_ }
function Remaining-Ms {
  $ms=[int](([DateTime]::UtcNow - [DateTime]::UtcNow).TotalMilliseconds + 1)
  return [Math]::Max(0, [Math]::Min(__TIMEOUT__, [int]($deadline-[DateTime]::UtcNow).TotalMilliseconds))
}
function Test-Nonce([string]$text,[string]$nonce) {
  return [regex]::IsMatch($text,'(^|[^A-Za-z0-9])'+[regex]::Escape($nonce)+'([^A-Za-z0-9]|$)')
}
function Read-Text($stream) {
  $buffer=New-Object byte[] 4096
  try { $n=$stream.Read($buffer,0,$buffer.Length); if($n -gt 0){return [Text.Encoding]::UTF8.GetString($buffer,0,$n)} } catch {}
  return ''
}
function Read-Tcp($client) {
  try { $stream=$client.GetStream();$stream.ReadTimeout=[Math]::Max(1,(Remaining-Ms)); return (Read-Text $stream) } catch { return '' }
}
function Invoke-TcpStep($step,[string]$mode) {
  $result=[ordered]@{id=[string]$step.id;outcome='unknown';sent=0;received='';error=$null;response_type='tcp';status=$null;nonce_match=$false;address_family='';remote_endpoint='';local_endpoint='';started=[DateTime]::UtcNow.ToString('o');ended=$null;elapsed_ms=$null}
  $sw=[Diagnostics.Stopwatch]::StartNew();$client=$null;$ssl=$null;$ar=$null
  try {
    $address=[Net.IPAddress]::Parse([string]$step.destination)
    $result.address_family=$address.AddressFamily.ToString()
    $client=[Net.Sockets.TcpClient]::new($address.AddressFamily)
    $timeout=[Math]::Max(1,(Remaining-Ms))
    $ar=$client.BeginConnect($address,[int]$step.port,$null,$null)
    if(-not $ar.AsyncWaitHandle.WaitOne($timeout)){throw 'connect timeout'}
    $client.EndConnect($ar)
    $result.remote_endpoint=[string]$client.Client.RemoteEndPoint
    $result.local_endpoint=[string]$client.Client.LocalEndPoint
    $stream=$client.GetStream();$stream.ReadTimeout=$timeout
    if($mode -eq 'tcp_tls') {
      $ssl=[Net.Security.SslStream]::new($stream,$false,[Net.Security.RemoteCertificateValidationCallback]{ $true })
      $ssl.AuthenticateAsClient([string]$step.destination)
      $result.response_type='tls_http';$stream=$ssl
    } elseif($mode -eq 'tcp_http') {
      $result.response_type='http'
    } else {
      $result.response_type='tcp_nonce'
    }
    if($mode -eq 'tcp_raw') {
      $bytes=[Text.Encoding]::ASCII.GetBytes('MALTRACE-EGRESS-'+$nonce)
    } else {
      $wire='GET /maltrance-egress?nonce='+$nonce+' HTTP/1.1'+[Environment]::NewLine+'Host: '+[string]$step.destination+[Environment]::NewLine+'Connection: close'+[Environment]::NewLine+[Environment]::NewLine
      $bytes=[Text.Encoding]::ASCII.GetBytes($wire)
    }
    $stream.Write($bytes,0,$bytes.Length);$stream.Flush();$result.sent=$bytes.Length
    $result.received=Read-Text $stream
    $result.nonce_match=(Test-Nonce $result.received $nonce)
    if($mode -ne 'tcp_raw') {
      $match=[regex]::Match($result.received,'^HTTP/\d\.\d\s+(\d{3})')
      if($match.Success){$result.status=[int]$match.Groups[1].Value}
    }
    if($result.received){$result.outcome='response'}else{$result.outcome='no_response'}
  } catch { $result.error=[string]$_;$result.outcome='no_response' }
  finally { if($ar){try{$ar.AsyncWaitHandle.Dispose()}catch{}};if($ssl){try{$ssl.Dispose()}catch{}};if($client){try{$client.Close()}catch{}};$result.elapsed_ms=$sw.ElapsedMilliseconds;$result.ended=[DateTime]::UtcNow.ToString('o') }
  return $result
}
function Invoke-UdpStep($step) {
  $result=[ordered]@{id=[string]$step.id;outcome='unknown';sent=0;received='';error=$null;response_type='udp_nonce';status=$null;nonce_match=$false;address_family='';remote_endpoint='';local_endpoint='';started=[DateTime]::UtcNow.ToString('o');ended=$null;elapsed_ms=$null}
  $sw=[Diagnostics.Stopwatch]::StartNew();$client=$null
  try {
    $address=[Net.IPAddress]::Parse([string]$step.destination)
    $result.address_family=$address.AddressFamily.ToString()
    $client=[Net.Sockets.UdpClient]::new($address.AddressFamily)
    $client.Client.ReceiveTimeout=[Math]::Max(1,(Remaining-Ms))
    $bytes=[Text.Encoding]::ASCII.GetBytes('MALTRACE-EGRESS-'+$nonce)
    $result.sent=$bytes.Length
    $client.Connect($address,[int]$step.port)
    [void]$client.Send($bytes,$bytes.Length)
    $remote=[Net.IPEndPoint]::new([Net.IPAddress]::Any,0)
    $data=$client.Receive([ref]$remote)
    $result.received=[Text.Encoding]::UTF8.GetString($data)
    $result.remote_endpoint=[string]$remote
    $result.nonce_match=(Test-Nonce $result.received $nonce)
    if($result.received){$result.outcome='response'}else{$result.outcome='no_response'}
  } catch { $result.error=[string]$_;$result.outcome='no_response' }
  finally { if($client){try{$client.Close()}catch{}};$result.elapsed_ms=$sw.ElapsedMilliseconds;$result.ended=[DateTime]::UtcNow.ToString('o') }
  return $result
}
function Build-DnsQuery([string]$name,[int]$txid) {
  $labels=$name.TrimEnd('.').Split('.')
  $bytes=New-Object System.Collections.Generic.List[byte]
  $bytes.Add([byte](($txid -shr 8) -band 255));$bytes.Add([byte]($txid -band 255))
  $bytes.Add(0x01);$bytes.Add(0x00);$bytes.Add(0x00);$bytes.Add(0x01);$bytes.Add(0x00);$bytes.Add(0x00);$bytes.Add(0x00);$bytes.Add(0x00);$bytes.Add(0x00);$bytes.Add(0x00)
  foreach($label in $labels) {
    $raw=[Text.Encoding]::ASCII.GetBytes($label)
    if($raw.Length -gt 63){throw 'dns label too long'}
    $bytes.Add([byte]$raw.Length);foreach($b in $raw){$bytes.Add($b)}
  }
  $bytes.Add(0x00);$bytes.Add(0x00);$bytes.Add(0x01);$bytes.Add(0x00);$bytes.Add(0x01)
  return $bytes.ToArray()
}
function Invoke-DnsStep($step) {
  $result=[ordered]@{id=[string]$step.id;outcome='unknown';sent=0;received='';error=$null;response_type='dns';status=$null;nonce_match=$false;address_family='';remote_endpoint='';local_endpoint='';transaction_id=$null;question='';qtype=$null;qclass=$null;qr=$false;rcode=$null;started=[DateTime]::UtcNow.ToString('o');ended=$null;elapsed_ms=$null}
  $sw=[Diagnostics.Stopwatch]::StartNew();$client=$null
  try {
    $address=[Net.IPAddress]::Parse([string]$step.destination)
    $result.address_family=$address.AddressFamily.ToString()
    $name=[string]$step.question
    if(-not $name){$name='MALTRACE-'+$nonce+'.invalid'}
    $result.question=$name
    $client=[Net.Sockets.UdpClient]::new($address.AddressFamily)
    $client.Client.ReceiveTimeout=[Math]::Max(1,(Remaining-Ms))
    $bytes=Build-DnsQuery $name ([int]$step.dns_txid)
    $result.sent=$bytes.Length
    $client.Connect($address,53)
    $result.local_endpoint=[string]$client.Client.LocalEndPoint
    [void]$client.Send($bytes,$bytes.Length)
    $remote=[Net.IPEndPoint]::new([Net.IPAddress]::Any,0)
    $data=$client.Receive([ref]$remote)
    $result.remote_endpoint=[string]$remote
    if($data.Length -ge 12) {
      $result.transaction_id=[int]$data[0]*256+[int]$data[1]
      $result.qr=(($data[2] -band 0x80) -ne 0)
      $result.rcode=($data[3] -band 0x0f)
      $offset=12
      $labels=@()
      $guard=0
      while($offset -lt $data.Length -and $guard -lt 128) {
        $guard++
        $length=[int]$data[$offset]
        if($length -eq 0){$offset++;break}
        if(($length -band 0xc0) -ne 0){throw 'dns compression not accepted'}
        if($offset+1+$length -gt $data.Length){throw 'dns label out of range'}
        $labels += [Text.Encoding]::ASCII.GetString($data,$offset+1,$length)
        $offset += 1+$length
      }
      $parsed=($labels -join '.')
      $result.question=$parsed
      if($offset+4 -le $data.Length) {
        $result.qtype=([int]$data[$offset]*256+[int]$data[$offset+1])
        $result.qclass=([int]$data[$offset+2]*256+[int]$data[$offset+3])
      }
      $result.received='dns-bytes='+$data.Length
      $result.nonce_match=($parsed -ceq $name)
      if($result.qr -and $result.transaction_id -eq [int]$step.dns_txid -and $result.nonce_match){$result.outcome='response'}else{$result.outcome='no_response'}
    } else { $result.outcome='no_response' }
  } catch { $result.error=[string]$_;$result.outcome='no_response' }
  finally { if($client){try{$client.Close()}catch{}};$result.elapsed_ms=$sw.ElapsedMilliseconds;$result.ended=[DateTime]::UtcNow.ToString('o') }
  return $result
}

function Invoke-IcmpStep($step) {
  $result=[ordered]@{id=[string]$step.id;outcome='unknown';sent=0;received='';error=$null;response_type='icmp_echo';status=$null;nonce_match=$false;address_family='';remote_endpoint='';local_endpoint='';responder='';started=[DateTime]::UtcNow.ToString('o');ended=$null;elapsed_ms=$null}
  $sw=[Diagnostics.Stopwatch]::StartNew();$ping=$null
  try {
    $address=[Net.IPAddress]::Parse([string]$step.destination)
    $result.address_family=$address.AddressFamily.ToString()
    $wire=('MALTRACE-'+$nonce); if($wire.Length -lt 32){$wire=$wire.PadRight(32,'.')}
    $bytes=[Text.Encoding]::ASCII.GetBytes($wire)
    $ping=[Net.NetworkInformation.Ping]::new()
    $reply=$ping.Send($address,[Math]::Max(1,(Remaining-Ms)),$bytes)
    $result.sent=$bytes.Length
    $result.status=[string]$reply.Status
    $result.responder=[string]$reply.Address
    $result.remote_endpoint=[string]$reply.Address
    $result.received=[Text.Encoding]::ASCII.GetString($reply.Buffer)
    $result.nonce_match=(Test-Nonce $result.received $nonce)
    if($reply.Status -eq 'Success' -and $result.nonce_match){$result.outcome='response'}else{$result.outcome='no_response'}
  } catch { $result.error=[string]$_;$result.outcome='no_response' }
  finally { if($ping){try{$ping.Dispose()}catch{}};$result.elapsed_ms=$sw.ElapsedMilliseconds;$result.ended=[DateTime]::UtcNow.ToString('o') }
  return $result
}
try {
if($payload.positive_enabled) {
  $echoClient=$null;$echoSsl=$null;$ar=$null
  $positiveStarted=[DateTime]::UtcNow.ToString('o')
  try {
    $echoAddress=[Net.IPAddress]::Parse([string]$payload.echo.destination)
    $echoClient=[Net.Sockets.TcpClient]::new($echoAddress.AddressFamily)
    $timeout=[Math]::Max(1,(Remaining-Ms))
    $ar=$echoClient.BeginConnect($echoAddress,[int]$payload.echo.port,$null,$null)
    if(-not $ar.AsyncWaitHandle.WaitOne($timeout)){throw 'positive connect timeout'}
    $echoClient.EndConnect($ar)
    $stream=$echoClient.GetStream();$stream.ReadTimeout=$timeout
    $bytes=[Text.Encoding]::ASCII.GetBytes('MALTRACE-EGRESS-'+$nonce)
    $stream.Write($bytes,0,$bytes.Length);$stream.Flush()
    $received=Read-Text $stream
    $out.positive=[ordered]@{id='__POSITIVE__';sent=$bytes.Length;received=$received;nonce_match=(Test-Nonce $received $nonce);response_type='tcp_nonce';protocol='TCP';destination=[string]$echoAddress;port=[int]$payload.echo.port;address_family=$echoAddress.AddressFamily.ToString();remote_endpoint=[string]$echoClient.Client.RemoteEndPoint;local_endpoint=[string]$echoClient.Client.LocalEndPoint;started=$positiveStarted;ended=[DateTime]::UtcNow.ToString('o')}
  } catch { $out.positive=[ordered]@{id='__POSITIVE__';sent=0;received='';nonce_match=$false;response_type='tcp_nonce';protocol='TCP';destination=[string]$payload.echo.destination;port=[int]$payload.echo.port;error=[string]$_;started=$positiveStarted;ended=[DateTime]::UtcNow.ToString('o')} }
  finally { $positiveEnded=[DateTime]::UtcNow.ToString('o'); if($ar){try{$ar.AsyncWaitHandle.Dispose()}catch{}};if($echoSsl){try{$echoSsl.Dispose()}catch{}};if($echoClient){try{$echoClient.Close()}catch{}};if($out.positive){$out.positive.ended=$positiveEnded} }
}
if($payload.positive_enabled -and $out.positive.nonce_match) {
  $out.matrix_run=$true
    foreach($step in $steps) {
      if([DateTime]::UtcNow -gt $deadline){$out.stop_remaining=$true;break}
      switch([string]$step.probe_kind) {
        'tcp_http' { $out.steps += (Invoke-TcpStep $step 'tcp_http') }
        'tcp_tls' { $out.steps += (Invoke-TcpStep $step 'tcp_tls') }
        'tcp_raw' { $out.steps += (Invoke-TcpStep $step 'tcp_raw') }
        'udp_raw' { $out.steps += (Invoke-UdpStep $step) }
        'dns' { $out.steps += (Invoke-DnsStep $step) }
        'icmp' { $out.steps += (Invoke-IcmpStep $step) }
        default { $out.steps += [ordered]@{id=[string]$step.id;outcome='unknown';sent=0;received='';error='unknown kind';started=[DateTime]::UtcNow.ToString('o');ended=[DateTime]::UtcNow.ToString('o')} }
      }
      $last=$out.steps[$out.steps.Count-1]
      if([string]$step.expected -eq 'blocked' -and [string]$last.received){$out.stop_remaining=$true;break}
    }
  }
} finally { $out.completed_at=[DateTime]::UtcNow.ToString('o') }
[Console]::Out.WriteLine('MALTRACE_JSON:'+($out|ConvertTo-Json -Depth 14 -Compress))
'''


def apply_probe_kinds(rows, listener_map=None, redirect_all=True):
    listener_map = listener_map or {}
    for row in rows:
        kind = row.get('kind')
        port = row.get('port')
        listener = str(listener_map.get(port, '') or '').lower()
        if kind == 'icmp':
            probe = 'icmp'
        elif kind == 'dns':
            probe = 'dns' if ('dns' in listener or (
                not listener and redirect_all)) else 'unknown'
        elif kind == 'tcp':
            if 'http' in listener:
                probe = 'tcp_tls' if ':tls' in listener else 'tcp_http'
            elif 'tls' in listener or 'ssl' in listener:
                probe = 'tcp_tls'
            elif 'raw' in listener:
                probe = 'tcp_raw'
            elif listener:
                probe = 'unknown'
            elif redirect_all:
                probe = 'tcp_raw'
            else:
                probe = 'unknown'
        elif kind == 'udp':
            if 'dns' in listener:
                probe = 'dns'
            elif 'raw' in listener:
                probe = 'udp_raw'
            elif listener:
                probe = 'unknown'
            elif redirect_all:
                probe = 'udp_raw'
            else:
                probe = 'unknown'
        else:
            probe = 'unknown'
        row['probe_kind'] = probe
    return rows


def matrix_steps(random_tcp_port, random_udp_port, nonce=None,
                 listener_map=None, redirect_all=True):
    rows = egress_contract.matrix_definition(random_tcp_port, random_udp_port)
    if nonce is not None:
        for row in rows:
            if row['kind'] == 'dns':
                row['dns_txid'] = dns_txid(nonce, row['id'])
                row['question'] = 'MALTRACE-' + str(nonce) + '.invalid'
    return apply_probe_kinds(rows, listener_map, redirect_all)


def dns_txid(nonce, step_id):
    raw = ('%s:%s' % (nonce, step_id)).encode('utf-8')
    return int(hashlib.sha256(raw).hexdigest()[:4], 16)


def probe_payload(nonce, steps, echo_destination='198.51.100.77',
                  echo_port=1337, deadline_ms=DEFAULT_DEADLINE_MS,
                  protocol_class='mixed-v1', positive_enabled=True,
                  deadline_utc=''):
    return {
        'nonce': nonce,
        'steps': steps,
        'echo': {'destination': echo_destination, 'port': echo_port},
        'deadline_ms': int(deadline_ms),
        'deadline_utc': str(deadline_utc or ''),
        'protocol_class': protocol_class,
        'positive_enabled': bool(positive_enabled),
    }


def script_identity(nonce, steps, echo_destination='198.51.100.77',
                    echo_port=1337, deadline_ms=DEFAULT_DEADLINE_MS,
                    protocol_class='mixed-v1', positive_enabled=True,
                    deadline_utc=''):
    payload = probe_payload(nonce, steps, echo_destination, echo_port,
                            deadline_ms, protocol_class, positive_enabled,
                            deadline_utc)
    return hashlib.sha256(json.dumps(
        payload, ensure_ascii=False, sort_keys=True,
        separators=(',', ':')).encode('utf-8')).hexdigest()


def probe_script(nonce, steps, echo_destination='198.51.100.77',
                 echo_port=1337, deadline_ms=DEFAULT_DEADLINE_MS,
                 protocol_class='mixed-v1', positive_enabled=True,
                 deadline_utc=''):
    payload = probe_payload(nonce, steps, echo_destination, echo_port,
                            deadline_ms, protocol_class, positive_enabled,
                            deadline_utc)
    payload['script_hash'] = script_identity(
        nonce, steps, echo_destination, echo_port, deadline_ms,
        protocol_class, positive_enabled, deadline_utc)
    encoded = base64.b64encode(json.dumps(
        payload, ensure_ascii=False, sort_keys=True,
        separators=(',', ':')).encode('utf-8')).decode('ascii')
    script = PROBE_TEMPLATE.replace('__PAYLOAD__', encoded)
    script = script.replace('__SCHEMA__', PROBE_SCHEMA)
    script = script.replace('__TIMEOUT__', str(MATRIX_TIMEOUT_MS))
    script = script.replace('__POSITIVE__', POSITIVE_ID)
    return script


def script_sha256(script):
    return hashlib.sha256(script.encode('utf-8')).hexdigest()


def extract_marker(text):
    lines = [line for line in str(text or '').splitlines()
             if line.startswith('MALTRACE_JSON:')]
    if len(lines) != 1:
        raise ValueError('expected exactly one MALTRACE_JSON marker')
    return json.loads(lines[0][len('MALTRACE_JSON:'):])


def validate_probe_result(value, expected_ids, *, nonce=None,
                          expected_script_hash=None, positive_required=True):
    if not isinstance(value, dict) or value.get('schema') != PROBE_SCHEMA:
        raise ValueError('probe schema mismatch')
    if nonce is not None and value.get('nonce') != nonce:
        raise ValueError('probe nonce mismatch')
    if not isinstance(value.get('identity'), dict):
        raise ValueError('probe identity missing')
    instance = value.get('instance')
    if not isinstance(instance, dict):
        raise ValueError('probe instance missing')
    if instance.get('pid') is None or instance.get('creation_ticks') is None:
        raise ValueError('probe instance identity missing')
    if nonce is not None and instance.get('nonce') != nonce:
        raise ValueError('probe instance nonce mismatch')
    if expected_script_hash is not None and instance.get(
            'script_hash') != expected_script_hash:
        raise ValueError('probe script identity mismatch')
    positive = value.get('positive')
    if positive_required:
        if not isinstance(positive, dict) or positive.get('id') != POSITIVE_ID:
            raise ValueError('positive probe missing')
    steps = value.get('steps')
    if not isinstance(steps, list):
        raise ValueError('probe matrix rows missing')
    seen = []
    for step in steps:
        if not isinstance(step, dict) or not isinstance(step.get('id'), str):
            raise ValueError('probe step malformed')
        seen.append(step['id'])
    if value.get('matrix_run') is False:
        if steps:
            raise ValueError('probe matrix skipped but rows present')
        return value
    if value.get('matrix_run') is not True:
        raise ValueError('probe matrix_run missing')
    if len(seen) != len(set(seen)):
        raise ValueError('probe matrix duplicate row')
    if set(seen) != set(expected_ids):
        if value.get('stop_remaining') is True and set(seen).issubset(
                set(expected_ids)):
            return value
        raise ValueError('probe matrix coverage mismatch')
    return value


def expected_steps(bypass_tcp=(), bypass_udp=(), mapped_ports=(),
                   redirect_all=True, random_tcp_port=50001,
                   random_udp_port=50002, nonce=None, listener_map=None):
    bypass_tcp, bypass_udp = set(bypass_tcp), set(bypass_udp)
    mapped = set(mapped_ports)
    result = {}
    for step in matrix_steps(random_tcp_port, random_udp_port, nonce,
                             listener_map=listener_map,
                             redirect_all=redirect_all):
        if step['kind'] == 'icmp':
            expected, reason = 'blocked', 'icmp_not_intercepted'
        elif step['kind'] == 'dns':
            if 53 in mapped or redirect_all:
                expected, reason = 'local_fake', 'dns_listener'
            else:
                expected, reason = 'unknown', 'dns_listener_unmapped'
        elif step['kind'] in ('tcp', 'udp'):
            bypass = bypass_tcp if step['kind'] == 'tcp' else bypass_udp
            if step['port'] in bypass:
                expected, reason = 'blocked', 'configured_bypass'
            elif step['port'] in mapped or redirect_all:
                expected, reason = 'local_fake', ('listener_observed'
                                                  if step['port'] in mapped
                                                  else 'redirect_all')
            else:
                expected, reason = 'unknown', 'listener_unmapped'
        else:
            expected, reason = 'unknown', 'unknown_kind'
        if expected == 'local_fake' and step.get(
                'probe_kind') == 'unknown':
            expected, reason = 'unknown', 'unsupported_listener'
        result[step['id']] = dict(step, expected=expected, reason=reason)
    return result


def _endpoint_matches(value, destination, port):
    text = str(value or '')
    if not text:
        return False
    if ':' not in text:
        return False
    host, _, tail = text.rpartition(':')
    host = host.strip('[]').split('%')[0]
    if str(port) is not None and str(port).isdigit() and tail != str(port):
        return False
    return host == str(destination)


def _family_matches(value, family):
    text = str(value or '').lower()
    if family == 'ipv4':
        return text in ('internetwork', 'ipv4', 'af_inet', '2')
    if family == 'ipv6':
        return text in ('internetworkv6', 'ipv6', 'af_inet6', '23')
    return False


def classify_step(step, observed, expected, *, boundary_verified=None):
    observed = observed if isinstance(observed, dict) else {}
    received = str(observed.get('received') or '')
    error = str(observed.get('error') or '')
    sent = observed.get('sent')
    kind = str((step or {}).get('kind') or '')
    family = str((step or {}).get('family') or '')
    port = (step or {}).get('port')
    destination = str((step or {}).get('destination') or '')
    if expected == 'blocked':
        if received:
            return 'fail', 'unexpected_response'
        if boundary_verified is not True:
            return 'unknown', 'boundary_unverified'
        if type(sent) is not int or sent <= 0:
            return 'unknown', 'request_not_sent'
        return 'pass', 'independent_boundary_no_local_response'
    if expected != 'local_fake':
        return 'unknown', 'expectation_unknown'
    if not received or type(sent) is not int or sent <= 0:
        return 'unknown', 'no_verified_response'
    if kind in ('tcp', 'udp', 'dns', 'icmp') and not _family_matches(
            observed.get('address_family'), family):
        return 'unknown', 'address_family_mismatch'
    if not _endpoint_matches(observed.get('remote_endpoint'), destination,
                             port):
        return 'unknown', 'remote_endpoint_mismatch'
    if not str(observed.get('local_endpoint') or ''):
        return 'unknown', 'local_endpoint_missing'
    response_type = str(observed.get('response_type') or '')
    if kind == 'tcp':
        if response_type == 'tcp_nonce':
            if observed.get('nonce_match') is not True:
                return 'unknown', 'tcp_nonce_mismatch'
            if not isinstance(observed.get('elapsed_ms'), int):
                return 'unknown', 'elapsed_missing'
            return 'pass', 'strict_raw_tcp_nonce_response'
        if response_type not in ('http', 'tls_http'):
            return 'unknown', 'tcp_response_type_mismatch'
        status = observed.get('status')
        if type(status) is not int or not 100 <= status <= 599:
            return 'unknown', 'http_status_invalid'
        if observed.get('nonce_match') is not True:
            return 'unknown', 'tcp_nonce_mismatch'
        if not isinstance(observed.get('elapsed_ms'), int):
            return 'unknown', 'elapsed_missing'
        return 'pass', 'strict_http_nonce_response'
    if kind == 'udp':
        if response_type != 'udp_nonce' or observed.get(
                'nonce_match') is not True:
            return 'unknown', 'udp_nonce_mismatch'
        return 'pass', 'strict_udp_nonce_response'
    if kind == 'dns':
        if response_type != 'dns' or observed.get('qr') is not True:
            return 'unknown', 'dns_response_invalid'
        expected_txid = (step or {}).get('dns_txid')
        if expected_txid is not None and observed.get(
                'transaction_id') != expected_txid:
            return 'unknown', 'dns_transaction_mismatch'
        expected_question = str((step or {}).get('question') or '')
        if not expected_question or str(
                observed.get('question') or '') != expected_question:
            return 'unknown', 'dns_question_mismatch'
        if observed.get('qtype') != 1 or observed.get('qclass') != 1:
            return 'unknown', 'dns_question_type_mismatch'
        rcode = observed.get('rcode')
        if type(rcode) is not int or not 0 <= rcode <= 5:
            return 'unknown', 'dns_rcode_invalid'
        if observed.get('nonce_match') is not True:
            return 'unknown', 'dns_nonce_mismatch'
        return 'pass', 'strict_dns_transaction_response'
    if kind == 'icmp':
        if response_type != 'icmp_echo' or observed.get(
                'nonce_match') is not True:
            return 'unknown', 'icmp_nonce_mismatch'
        if str(observed.get('responder') or '') != destination:
            return 'unknown', 'icmp_responder_mismatch'
        return 'pass', 'strict_icmp_nonce_response'
    return 'unknown', 'response_not_verified'
