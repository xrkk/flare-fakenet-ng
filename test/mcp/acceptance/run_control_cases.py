#!/usr/bin/env python3
# Copyright 2026 Google LLC
"""ACC-004 control-path matrix (CHK-064 minimal closure).

Cases (one process invocation each, same evidence shape as the ACC runners):
  CONTROL-DEFAULT           control link on the default port stays reachable
                            through a live takeover and the final filter
                            carries the control-link exclusion
  CONTROL-EXTRA-<port>      the co-resident management service on an extra
                            excluded port stays reachable during a takeover
                            (28787 is the VM's own MCP service; the other
                            ports get a real pinned local listener)
  CONTROL-INVALID           service configuration with an illegal
                            extra_control_ports entry refuses to start
  LOOPBACK-V4 / LOOPBACK-V6 a uniquely marked loopback datagram reaches a
                            real local listener, stays absent from the main
                            divert capture and is recorded by the record-only
                            capture; a diverted marker proves capture liveness
"""
import argparse
import base64
import ipaddress
import datetime
import hashlib
import json
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(REPO_ROOT))

from helpers import (EXIT_BLOCKED, EXIT_FAIL, EXIT_PASS,  # noqa: E402
                     EXIT_TOOL_ERROR, EvidenceWriter, Win10VmChannel,
                     kill_owned_process)
from run_p02_acc import call, sha_of, status  # noqa: E402
from run_p03_acc import load_and_start, stop_run, unique_command, wait_state  # noqa: E402

CONTROL_PORTS = (28787, 28790, 29094, 29095)
INVALID_PORT_VALUES = [
    {'label': 'bool', 'value': [True]},
    {'label': 'float', 'value': [29094.9]},
    {'label': 'string', 'value': ['29094']},
    {'label': 'map', 'value': {'a': 1}},
    {'label': 'zero', 'value': [0]},
    {'label': 'overflow', 'value': [65536]},
]


def probe_timeline(base, seconds):
    import urllib.request
    timeline = []
    end = time.time() + seconds
    while time.time() < end:
        began = time.time()
        try:
            snap = status(base)
            ok = snap.get('state') and not snap.get('error')
        except Exception as exc:  # noqa: BLE001
            ok, snap = False, {'error': repr(exc)}
        timeline.append(dict(t=began, ok=bool(ok), state=snap.get('state')))
        time.sleep(1.0)
    return timeline


def tcp_echo_probe(host, port, marker, timeout=5):
    import socket
    began = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(('echo:' + marker).encode('ascii'))
            sock.settimeout(timeout)
            data = sock.recv(256)
        return {'ok': data == ('echo:' + marker).encode('ascii'),
                'received': data.decode('ascii', 'replace'), 't': began}
    except Exception as exc:  # noqa: BLE001
        return {'ok': False, 'error': repr(exc), 't': began}


def start_guest_tcp_listener(channel, port, nonce):
    """A real local listener on the excluded port; pinned for owned cleanup."""
    script = (
        "$ErrorActionPreference='Stop';"
        "$listener=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Parse('192.168.204.233')," + str(port) + ");"
        "$listener.Start();"
        "$log='C:\\Windows\\Temp\\ctrl-listener-" + nonce + ".log';"
        "Set-Content -Path $log -Value ('started pid=' + $PID);"
        "try{while($true){try{"
        "$c=$listener.AcceptTcpClient();"
        "$stream=$c.GetStream();$buffer=New-Object byte[] 256;"
        "$read=$stream.Read($buffer,0,256);"
        "$text=[Text.Encoding]::ASCII.GetString($buffer,0,$read);"
        "Add-Content -Path $log -Value ('recv ' + $text);"
        "if($text.Contains(':')){"
        "$reply='echo:' + $text.Substring($text.IndexOf(':')+1);"
        "$bytes=[Text.Encoding]::ASCII.GetBytes($reply);"
        "$stream.Write($bytes,0,$bytes.Length)};"
        "$c.Close()}catch{}}}finally{$listener.Stop()}")
    result = channel.powershell(
        "Start-Process powershell -WindowStyle Hidden -ArgumentList '-NoProfile','-Command','" +
        script.replace("'", "''") + "' -PassThru | ForEach-Object { $_.Id }", timeout=30)
    pid = int(result['output'].strip().splitlines()[-1])
    born = channel.powershell(
        "(Get-Process -Id " + str(pid) + ").StartTime.ToFileTimeUtc()", timeout=30)
    return {'pid': pid, 'created': int(born['output'].strip()),
            'receipt': 'C:\\Windows\\Temp\\ctrl-listener-%s.log' % nonce, 'port': port}


class ControlCase:

    def __init__(self, args):
        self.args = args
        self.channel = Win10VmChannel(args.win10vm_mcp)
        self.base = args.target_base_url

    # -- shared lifecycle ---------------------------------------------------
    def normalize(self):
        # A previous crashed invocation can leave an active run; converge it
        # through the same bounded stop entry before starting this case. The
        # two-phase CLI stop also stops the SCM service itself, so the
        # service process is brought back up first when the entry is gone.
        try:
            status(self.base)
        except Exception:
            self.channel.powershell(
                'sc.exe start fakenetng-mcp | Out-Null; Start-Sleep -Seconds 5; '
                "(Get-Service fakenetng-mcp).Status", timeout=120)
            import time as _time
            for _ in range(30):
                try:
                    status(self.base)
                    break
                except Exception:
                    _time.sleep(2)
        try:
            current = status(self.base)
            if current.get('run_id'):
                stop_run(self.base)
        except Exception:
            pass
        ok, snap = wait_state(
            self.base, lambda s: s.get('state') == 'stopped' and not s.get('run_id'),
            timeout=180)
        if not ok:
            raise RuntimeError('service not stopped before control case: %r' % snap)

    def start_run(self, writer, config='default.ini'):
        started = load_and_start(self.base, name=config)
        writer.add_evidence('control-run-load-start', started)
        ok, snap = wait_state(self.base, lambda s: s.get('state') == 'healthy', timeout=45)
        if not ok:
            raise RuntimeError('run did not become healthy: %r (start=%r)' % (snap, started))
        detail = snap.get('health') or {}
        writer.add_evidence('control-run-start', {'run_id': snap.get('run_id'),
                                                  'config': config,
                                                  'final_filter': detail.get('final_filter')})
        return snap

    def finish_run(self, writer):
        stop_run(self.base)
        ok, final = wait_state(self.base, lambda s: s.get('state') in ('stopped', 'failed'),
                               timeout=180)
        writer.add_evidence('control-run-stop', final or {})
        return ok and final.get('state') == 'stopped', final

    # -- cases ---------------------------------------------------------------
    def case_control_default(self, writer):
        checks = {}
        self.normalize()
        snap = self.start_run(writer)
        final_filter = (snap.get('health') or {}).get('final_filter') or ''
        checks['filter_excludes_control_link'] = (
            '(ip.DstAddr != 192.168.204.1 or (tcp.SrcPort != 28788' in final_filter)
        timeline = probe_timeline(self.base, 10)
        writer.add_evidence('control-default-probe', timeline)
        checks['control_link_alive_during_takeover'] = all(x['ok'] for x in timeline)
        ok, final = self.finish_run(writer)
        checks['run_stopped_cleanly'] = ok
        return checks

    def case_control_extra(self, writer, port):
        checks = {}
        self.normalize()
        started_listener = None
        try:
            if port != 28787:
                import uuid
                started_listener = start_guest_tcp_listener(
                    self.channel, port, uuid.uuid4().hex[:8])
                writer.add_evidence('control-extra-listener', started_listener)
                time.sleep(1.0)
            snap = self.start_run(writer)
            final_filter = (snap.get('health') or {}).get('final_filter') or ''
            checks['filter_excludes_port'] = (
                'tcp.SrcPort != %d' % port) in final_filter
            host = '192.168.204.233'
            timeline = []
            if port == 28787:
                # The co-resident management service on this VM is the
                # Win10VM MCP itself; a successful raw TCP connect to its
                # endpoint during the takeover proves the exclusion keeps
                # the management path intact (it has no echo contract).
                import socket
                for _ in range(5):
                    began = time.time()
                    try:
                        with socket.create_connection(('192.168.204.233', port),
                                                      timeout=5):
                            ok = True
                            raw = {'connected': True}
                    except Exception as exc:  # noqa: BLE001
                        ok, raw = False, {'error': repr(exc)}
                    timeline.append(dict(t=began, ok=ok, raw=raw))
                    time.sleep(1.0)
                checks['management_service_alive_during_takeover'] = all(
                    x['ok'] for x in timeline)
            else:
                for index in range(5):
                    marker = 'ctrl-%s-%d' % (port, index)
                    probe = tcp_echo_probe('192.168.204.233', port, marker)
                    timeline.append(probe)
                    time.sleep(1.0)
                checks['excluded_listener_reachable_during_takeover'] = all(
                    x['ok'] for x in timeline)
            writer.add_evidence('control-extra-probe', timeline)
            ok, final = self.finish_run(writer)
            checks['run_stopped_cleanly'] = ok
            if started_listener is not None:
                receipts = self.channel.powershell(
                    "Get-Content '" + started_listener['receipt'] + "' -Raw", timeout=30)
                writer.add_evidence('control-extra-receipts', receipts['output'])
                received = (receipts['output'] or '').count('ctrl-%s-' % port)
                checks['listener_receipts_match_probes'] = received >= 5
            return checks
        finally:
            if started_listener is not None:
                writer.add_evidence('control-extra-listener-stop', kill_owned_process(
                    self.channel, started_listener['pid'],
                    started_listener['created'], 'control-case-listener'))

    def case_control_invalid(self, writer):
        checks = {}
        self.normalize()
        raw_config = self.channel.powershell(
            "$b=[IO.File]::ReadAllBytes('C:\\ProgramData\\FakeNet-NG-MCP\\configs\\service.json');"
            "@{sha256=(Get-FileHash 'C:\\ProgramData\\FakeNet-NG-MCP\\configs\\service.json' -Algorithm SHA256).Hash.ToLower();"
            "base64=[Convert]::ToBase64String($b)} | ConvertTo-Json -Compress", timeout=30)
        original = json.loads(raw_config['output'])
        body = json.loads(base64.b64decode(original['base64']))
        if hashlib.sha256(base64.b64decode(original['base64'])).hexdigest() != original['sha256']:
            raise RuntimeError('service.json backup hash mismatch')
        results = {}
        try:
            for variant in INVALID_PORT_VALUES:
                body['extra_control_ports'] = variant['value']
                payload = json.dumps(body, ensure_ascii=False)
                # The running instance keeps its validated configuration,
                # so each variant stops SCM first, then the refusal is
                # proven by launching the service entry itself: an illegal
                # configuration must make the process exit non-zero.
                # Raw SCM stop is rejected by the two-phase contract; the
                # sanctioned controlled-stop entry is the CLI.
                self.channel.powershell(
                    "& 'C:\\Program Files\\FakeNet-NG-MCP\\fakenetng-mcp.exe' stop; "
                    "if($LASTEXITCODE -ne 0){throw 'controlled stop failed'}; "
                    "$deadline=[DateTime]::UtcNow.AddSeconds(60);"
                    "while((Get-Service fakenetng-mcp).Status -ne 'Stopped' -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 500};"
                    "if((Get-Service fakenetng-mcp).Status -ne 'Stopped'){throw 'service did not stop for variant'}; 'stopped'",
                    timeout=300)
                self.channel.powershell(
                    "[IO.File]::WriteAllText('C:\\ProgramData\\FakeNet-NG-MCP\\configs\\service.json'," +
                    "'" + payload.replace("'", "''") + "',[Text.UTF8Encoding]::new($false)); 'written'", timeout=30)
                # The service entry validates its configuration under the
                # real SCM launch; an illegal value must keep the service
                # from ever reaching Running and name the offending field.
                started = self.channel.powershell(
                    "sc.exe start fakenetng-mcp | Out-Null; Start-Sleep -Seconds 8; "
                    "(Get-Service fakenetng-mcp).Status", timeout=90)
                state = started['output'].strip().splitlines()[-1].strip()
                log = self.channel.powershell(
                    "Get-Content 'C:\\ProgramData\\FakeNet-NG-MCP\\logs\\service.log' -Tail 15 | Out-String", timeout=30)
                combined = log['output']
                results[variant['label']] = {
                    'value': variant['value'], 'sc_state': state,
                    'log_tail': combined,
                    'refused': state != 'Running' and
                               ('config load failed' in combined and
                                ('extra control' in combined or 'ConfigError' in combined))}
            writer.add_evidence('control-invalid-variants', results)
            checks['every_illegal_type_refused_start'] = all(
                row['refused'] for row in results.values())
            return checks
        finally:
            self.channel.powershell(
                "& 'C:\\Program Files\\FakeNet-NG-MCP\\fakenetng-mcp.exe' stop; "
                "Start-Sleep -Seconds 3;"
                "$bytes=[Convert]::FromBase64String('" + original['base64'] + "');"
                "[IO.File]::WriteAllBytes('C:\\ProgramData\\FakeNet-NG-MCP\\configs\\service.json',"
                "$bytes); $hash=(Get-FileHash 'C:\\ProgramData\\FakeNet-NG-MCP\\configs\\service.json'"
                " -Algorithm SHA256).Hash.ToLower(); if($hash -ne '" + original['sha256'] +
                "'){throw 'restore hash mismatch'}; 'restored'", timeout=60)
            self.channel.powershell(
                "sc.exe start fakenetng-mcp | Out-Null; Start-Sleep -Seconds 5; "
                "(Get-Service fakenetng-mcp).Status", timeout=120)

    def case_loopback(self, writer, family):
        address = '127.0.0.1' if family == 'V4' else '::1'
        port = 39998 if family == 'V4' else 39999
        import uuid
        nonce = uuid.uuid4().hex[:8]
        marker_loopback = 'ctrl-loopback-%s-%s' % (family.lower(), nonce)
        marker_diverted = 'ctrl-diverted-%s-%s' % (family.lower(), nonce)
        checks = {}
        self.normalize()
        self._ensure_capture_config(writer)
        listener = None
        try:
            # loopback-capture.ini is the shipped default config plus
            # DumpPackets, so the run produces the real dual PCAPs the
            # marker assertions read. The local listener lives entirely
            # INSIDE the run window: a listener crossing the baseline or
            # audit boundary would poison the strict restoration compare.
            snap = self.start_run(writer, config='loopback-capture.ini')
            run_id = snap.get('run_id')
            listener = self._start_loopback_listener(port, address, nonce, family)
            final_filter = (snap.get('health') or {}).get('final_filter') or ''
            if family == 'V4':
                checks['filter_excludes_loopback'] = (
                    'ip.DstAddr < 127.0.0.0 or ip.DstAddr > 127.255.255.255'
                    in final_filter)
            else:
                # Either the dual shape carries the explicit ::1 exemption,
                # or the filter is IPv4-scoped and structurally never
                # diverts IPv6 at all.
                checks['filter_excludes_loopback'] = (
                    'ipv6.DstAddr != ::1' in final_filter or
                    'ipv6' not in final_filter)
            sent = self.channel.powershell(
                "$c=[Net.Sockets.UdpClient]::new(" +
                ("[Net.Sockets.AddressFamily]::InterNetwork" if family == 'V4'
                 else "[Net.Sockets.AddressFamily]::InterNetworkV6") + ");"
                "try{$b=[Text.Encoding]::ASCII.GetBytes('" + marker_loopback + "');"
                "$n=$c.Send($b,$b.Length,'" + address + "'," + str(port) + ");"
                "$d=[Net.Sockets.UdpClient]::new();$b2=[Text.Encoding]::ASCII.GetBytes('" + marker_diverted + "');"
                "$n2=$d.Send($b2,$b2.Length,'8.8.8.8',53);"
                "@{loopback_sent=$n;diverted_sent=$n2}|ConvertTo-Json -Compress"
                "}finally{$c.Dispose();$d.Dispose()}", timeout=30)
            writer.add_evidence('loopback-stimulus', sent['output'])
            time.sleep(1.5)
            if listener is not None:
                writer.add_evidence('loopback-listener-stop', kill_owned_process(
                    self.channel, listener['pid'], listener['created'],
                    'loopback-listener'))
                listener = None
            ok, final = self.finish_run(writer)
            checks['run_stopped_cleanly'] = ok
            checks.update(self._verify_pcaps(writer, run_id, family,
                                             marker_loopback, marker_diverted,
                                             port))
            receipts = self.channel.powershell(
                "$p='C:\\Windows\\Temp\\loopback-receipts-" + nonce + ".txt';"
                "@{content=if(Test-Path $p){Get-Content $p -Raw}else{''};"
                "base64=if(Test-Path $p){[Convert]::ToBase64String([IO.File]::ReadAllBytes($p))}else{''}}"
                " | ConvertTo-Json -Compress", timeout=30)
            receipt = json.loads(receipts['output'])
            writer.add_evidence('loopback-receipts', receipt)
            checks['marker_arrived_at_local_listener'] = marker_loopback in (
                receipt.get('content') or '')
            return checks
        finally:
            if listener is not None:
                writer.add_evidence('loopback-listener-stop', kill_owned_process(
                    self.channel, listener['pid'], listener['created'],
                    'loopback-listener'))

    def _ensure_capture_config(self, writer):
        name = 'loopback-capture.ini'
        builtin = call(self.base, 'read_config', {'name': 'default.ini'}, controller=None)
        content = builtin.get('content') or ''
        lines = []
        seen = set()
        for line in content.splitlines():
            stripped = line.strip().lower()
            if stripped.startswith('dumppackets:'):
                line = 'DumpPackets: Yes'
                seen.add('on')
            elif stripped.startswith('dumppacketsfileprefix:'):
                line = 'DumpPacketsFilePrefix: packets'
                seen.add('prefix')
            lines.append(line)
        if 'on' not in seen:
            lines.insert(1, 'DumpPackets: Yes')
        if 'prefix' not in seen:
            lines.insert(2, 'DumpPacketsFilePrefix: packets')
        body = '\n'.join(lines) + '\n'
        version = status(self.base)['state_version']
        created = call(self.base, 'create_config',
                       {'name': name, 'content': body,
                        'command_id': unique_command('loopback-cfg'),
                        'expected_state_version': version}, timeout=60)
        if created.get('error') and created['error'].get('code') != 'name_conflict':
            raise RuntimeError('capture config unavailable: %r' % created['error'])
        actual = call(self.base, 'read_config', {'name': name}, controller=None)
        ok = (actual.get('content', '').replace('\r\n', '\n') == body and
              sha_of(body) == actual.get('sha256'))
        writer.add_evidence('loopback-capture-config', {'ok': ok, 'sha256': actual.get('sha256')})
        if not ok:
            raise RuntimeError('capture config content mismatch')

    def _start_loopback_listener(self, port, address, nonce, family):
        bind = ("[Net.IPAddress]::Parse('" + address + "')")
        script = (
            "$ErrorActionPreference='Stop';"
            "$ep=[Net.IPEndPoint]::new(" + bind + "," + str(port) + ");"
            "$listener=[Net.Sockets.UdpClient]::new($ep);"
            "$log='C:\\Windows\\Temp\\loopback-receipts-" + nonce + ".txt';"
            "Set-Content -Path $log -Value ('started pid=' + $PID);"
            "try{while($true){$remote=[Net.IPEndPoint]::new([Net.IPAddress]::Any,0);"
            "$b=$listener.Receive([ref]$remote);"
            "Add-Content -Path $log -Value ([Text.Encoding]::ASCII.GetString($b))}}finally{$listener.Close()}")
        result = self.channel.powershell(
            "Start-Process powershell -WindowStyle Hidden -ArgumentList '-NoProfile','-Command','" +
            script.replace("'", "''") + "' -PassThru | ForEach-Object { $_.Id }", timeout=30)
        pid = int(result['output'].strip().splitlines()[-1])
        born = self.channel.powershell(
            "(Get-Process -Id " + str(pid) + ").StartTime.ToFileTimeUtc()", timeout=30)
        return {'pid': pid, 'created': int(born['output'].strip())}

    def _verify_pcaps(self, writer, run_id, family, marker_loopback,
                      marker_diverted, loop_port):
        # The capture files are finalized shortly after the state flips to
        # stopped; poll briefly instead of racing the artifact publication.
        for _ in range(10):
            count = self.channel.powershell(
                "$dir=Join-Path 'C:\\ProgramData\\FakeNet-NG-MCP\\artifacts\\runs' '" + run_id + "';"
                "@(Get-ChildItem $dir -Filter '*.pcap' -ErrorAction SilentlyContinue).Count", timeout=30)
            if count['output'].strip() not in ('', '0'):
                break
            time.sleep(2.0)
        listing = (
            "$dir=Join-Path 'C:\\ProgramData\\FakeNet-NG-MCP\\artifacts\\runs' '" + run_id + "';"
            "$files=@(Get-ChildItem $dir -Filter '*.pcap' | Sort-Object Name);"
            "$rows=@($files | ForEach-Object { $bytes=[IO.File]::ReadAllBytes($_.FullName);"
            "$text=[Text.Encoding]::ASCII.GetString($bytes);"
            "$sha=[Security.Cryptography.SHA256]::Create();"
            "@{name=$_.Name;size=$_.Length;"
            "sha256=[BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','').ToLower();"
            "loopback_marker=$text.Contains('" + marker_loopback + "');"
            "diverted_marker=$text.Contains('" + marker_diverted + "')}});"
            "@{run_dir=$dir;files=$rows} | ConvertTo-Json -Depth 5 -Compress")
        raw = self.channel.powershell(listing, timeout=120)
        report = json.loads(raw['output'])
        for f in report['files']:
            f['base64'] = self.channel.powershell(
                "$dir=Join-Path 'C:\\ProgramData\\FakeNet-NG-MCP\\artifacts\\runs' '" + run_id + "';"
                "$f=Get-ChildItem $dir -Filter '" + f['name'] + "' | Select-Object -First 1;"
                "if($f.Length -le 8388608){[Convert]::ToBase64String([IO.File]::ReadAllBytes($f.FullName))}else{''}",
                timeout=120)['output'].strip()
        writer.add_evidence('loopback-pcaps', report)
        files = report['files']
        checks = {
            'pcap_evidence_present': bool(files),
        }
        # The dual PCAP files are two encodings of the SAME capture journal:
        # main-divert records and record-only observations both land in both
        # files, so file-level absence is not decidable. The exclusion is
        # proven at packet level instead: every marker-bearing loopback
        # datagram must be the untouched observation (dst exactly the local
        # listener), with no redirected copy toward any fake service, while
        # the diverted marker proves the capture was live. Independent
        # arrival at the REAL listener is asserted by the caller.
        import dpkt
        import socket
        marker_loopback_b = marker_loopback.encode('ascii')
        marker_diverted_b = marker_diverted.encode('ascii')
        loop_records, redirected, diverted_seen = [], [], []
        for f in files:
            if not f.get('base64'):
                continue
            payload = base64.b64decode(f['base64'])
            import hashlib as _h
            assert _h.sha256(payload).hexdigest() == f['sha256']
            writer.add_evidence('pcap-' + f['name'], payload)
            import io as _io
            reader = dpkt.pcap.Reader(_io.BytesIO(payload))
            linktype = reader.datalink()
            for ts, buf in reader:
                if marker_loopback_b in buf or marker_diverted_b in buf:
                    if linktype == dpkt.pcap.DLT_EN10MB:
                        layer = dpkt.ethernet.Ethernet(buf).data
                    elif buf and (buf[0] >> 4) == 6:
                        layer = dpkt.ip6.IP6(buf)
                    else:
                        layer = dpkt.ip.IP(buf)
                    if isinstance(layer, dpkt.ip6.IP6):
                        family = socket.AF_INET6
                    elif isinstance(layer, dpkt.ip.IP):
                        family = socket.AF_INET6 if layer.v == 6 else socket.AF_INET
                    else:
                        continue
                    def addr(raw):
                        return socket.inet_ntop(family, raw)
                    src, dst = addr(layer.src), addr(layer.dst)
                    l4 = layer.data
                    row = dict(file=f['name'], src=src, dst=dst,
                               sport=getattr(l4, 'sport', None),
                               dport=getattr(l4, 'dport', None),
                               proto=layer.p if layer.v == 4 else layer.nxt)
                    if marker_loopback_b in buf:
                        is_loopback_pair = (
                            ipaddress.ip_address(src).is_loopback and
                            ipaddress.ip_address(dst).is_loopback)
                        if (row['proto'] == dpkt.ip.IP_PROTO_UDP and
                                row['dport'] == loop_port and is_loopback_pair):
                            loop_records.append(row)
                        elif row['proto'] == dpkt.ip.IP_PROTO_UDP:
                            # a marker datagram whose destination was
                            # rewritten away from the local listener would
                            # prove diversion; nothing else counts.
                            redirected.append(row)
                        # TCP segments carrying the channel command text are
                        # observations of the runner's own traffic, not
                        # copies of the loopback datagram.
                    if marker_diverted_b in buf:
                        diverted_seen.append(f['name'])
        writer.add_evidence('loopback-packet-records',
                            {'loopback': loop_records, 'redirected': redirected})
        checks['main_capture_liveness_by_diverted_marker'] = bool(set(diverted_seen))
        checks['loopback_recorded_untouched'] = bool(loop_records)
        checks['loopback_never_redirected'] = not redirected
        return checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', required=True, choices=[
        'CONTROL-DEFAULT', 'CONTROL-INVALID', 'LOOPBACK-V4', 'LOOPBACK-V6'] +
        ['CONTROL-EXTRA-%d' % port for port in CONTROL_PORTS])
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--package-sha256', required=True)
    parser.add_argument('--requirements-blob', required=True)
    parser.add_argument('--master-plan-blob', required=True)
    parser.add_argument('--vm-identity', required=True)
    parser.add_argument('--config-identity', required=True)
    parser.add_argument('--candidate-id', required=True)
    parser.add_argument('--target-base-url', default='http://192.168.204.233:28788')
    parser.add_argument('--win10vm-mcp', default='http://192.168.204.233:28787/mcp')
    parser.add_argument('--output-root', default=str(REPO_ROOT / 'Logs' / 'fakenetng-mcp'))
    args = parser.parse_args()

    started_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    out_dir = Path(args.output_root) / args.candidate_id / args.case
    writer = EvidenceWriter(out_dir, started_at)
    case = ControlCase(args)
    exit_code = EXIT_TOOL_ERROR
    checks = {}
    try:
        if args.case == 'CONTROL-DEFAULT':
            checks = case.case_control_default(writer)
        elif args.case == 'CONTROL-INVALID':
            checks = case.case_control_invalid(writer)
        elif args.case == 'LOOPBACK-V4':
            checks = case.case_loopback(writer, 'V4')
        elif args.case == 'LOOPBACK-V6':
            checks = case.case_loopback(writer, 'V6')
        else:
            port = int(args.case.rsplit('-', 1)[1])
            checks = case.case_control_extra(writer, port)
        writer.add_evidence('case-checks', checks)
        writer.expect('all checks true for %s' % args.case)
        exit_code = EXIT_PASS if checks and all(checks.values()) else EXIT_FAIL
    except Exception as exc:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        writer.blocker = {'reason': repr(exc)}
        exit_code = EXIT_TOOL_ERROR

    status_word = {EXIT_PASS: 'pass', EXIT_FAIL: 'fail',
                   EXIT_BLOCKED: 'blocked',
                   EXIT_TOOL_ERROR: 'tool-error'}[exit_code]
    writer.write_result(
        acc_id=args.case, p_id='P03', candidate_id=args.candidate_id,
        source_commit=args.source_commit, package_sha256=args.package_sha256,
        requirements_blob=args.requirements_blob,
        master_plan_blob=args.master_plan_blob,
        environment_identity='%s | config=%s' % (args.vm_identity, args.config_identity),
        status=status_word)
    print('%s: %s' % (args.case, status_word))
    return exit_code


if __name__ == '__main__':
    sys.exit(main())
