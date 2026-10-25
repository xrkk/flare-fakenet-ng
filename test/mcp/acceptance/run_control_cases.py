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
import contextlib
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


def start_guest_tcp_listener(channel, port, nonce, host='192.168.204.233',
                             work_root='C:\\Windows\\Temp'):
    """A real local listener on the excluded port; pinned for owned cleanup."""
    from pathlib import PureWindowsPath
    log = str(PureWindowsPath(work_root) / ('ctrl-listener-' + nonce + '.log'))
    script = (
        "$ErrorActionPreference='Stop';"
        "$listener=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Parse('" + host + "')," + str(port) + ");"
        "$listener.Start();"
        "$log='" + log + "';"
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
            'receipt': log, 'port': port}


class ControlCase:

    def __init__(self, args):
        self.args = args
        self.channel = Win10VmChannel(args.win10vm_mcp)
        self.base = args.target_base_url
        from urllib.parse import urlsplit
        endpoint = urlsplit(self.base)
        self.guest_host = getattr(args, 'listen_ip', endpoint.hostname)
        self.control_port = getattr(args, 'listen_port', endpoint.port or 80)
        self.allowed_host = getattr(args, 'allowed_host', '192.168.204.1')
        self.guest_work_root = getattr(args, 'guest_work_root', 'C:\\Windows\\Temp')

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
            ('(ip.DstAddr != %s or (tcp.SrcPort != %d' %
             (self.allowed_host, self.control_port)) in final_filter)
        timeline = probe_timeline(self.base, 10)
        writer.add_evidence('control-default-probe', timeline)
        checks['control_link_alive_during_takeover'] = bool(timeline) and all(x['ok'] for x in timeline)
        ok, final = self.finish_run(writer)
        checks['run_stopped_cleanly'] = ok
        return checks

    @contextlib.contextmanager
    def extra_port_config(self, writer, port):
        """Bind one authorized test setting, restore only unchanged owned bytes."""
        from fakenet.mcp.config import ServiceConfig
        path = 'C:\\ProgramData\\FakeNet-NG-MCP\\configs\\service.json'
        observed = self.channel.powershell(
            "$ErrorActionPreference='Stop';$p='" + path + "';"
            "$b=[IO.File]::ReadAllBytes($p);"
            "@{sha256=(Get-FileHash $p -Algorithm SHA256).Hash.ToLower();"
            "base64=[Convert]::ToBase64String($b)}|ConvertTo-Json -Compress", timeout=30)
        original = json.loads(observed['output'])
        body = base64.b64decode(original['base64'], validate=True)
        if hashlib.sha256(body).hexdigest() != original['sha256']:
            raise RuntimeError('extra control config backup hash mismatch')
        parsed = json.loads(body)
        validated = ServiceConfig.from_dict(parsed)
        ports = list(validated.extra_control_ports)
        if port in ports:
            writer.add_evidence('extra-control-config-unchanged', original)
            yield
            return
        ports.append(port)
        parsed['extra_control_ports'] = ports
        configured = json.dumps(parsed, ensure_ascii=False).encode('utf-8')
        expected = hashlib.sha256(configured).hexdigest()
        begin = getattr(self.channel, 'control_extra_begin', None)
        if begin is not None:
            begin(port, original)
        owned_sha = original['sha256']
        changed = False
        try:
            self._extra_stop(writer, 'configured', owned_sha)
            owned_sha = self._extra_write(writer, 'configured', owned_sha, configured)
            changed = True
            started = self._extra_start(owned_sha, 5, 120)
            writer.add_evidence('extra-control-service-configured', started)
            if started['output'].strip() != 'Running':
                raise RuntimeError('service not running with extra control setting')
            observe = getattr(self.channel, 'control_extra_started', None)
            if observe is not None:
                observe('configured', {'base64': base64.b64encode(configured).decode('ascii'), 'sha256': owned_sha})
            yield
        finally:
            if changed:
                self._extra_stop(writer, 'restored', owned_sha)
                owned_sha = self._extra_write(writer, 'restored', owned_sha, body)
                restored = self._extra_start(owned_sha, 5, 120)
                writer.add_evidence('extra-control-service-restored', restored)
                if restored['output'].strip() != 'Running':
                    raise RuntimeError('service not running after config restore')
                observe = getattr(self.channel, 'control_extra_started', None)
                if observe is not None:
                    observe('restored', original)

    def case_control_extra(self, writer, port):
        if getattr(self.args, 'manage_extra_ports', False):
            with self.extra_port_config(writer, port):
                return self._case_control_extra(writer, port)
        return self._case_control_extra(writer, port)

    def _case_control_extra(self, writer, port):
        checks = {}
        self.normalize()
        started_listener = None
        try:
            if port != 28787:
                import uuid
                started_listener = start_guest_tcp_listener(
                    self.channel, port, uuid.uuid4().hex[:8],
                    self.guest_host, self.guest_work_root)
                writer.add_evidence('control-extra-listener', started_listener)
                time.sleep(1.0)
            snap = self.start_run(writer)
            final_filter = (snap.get('health') or {}).get('final_filter') or ''
            checks['filter_excludes_port'] = (
                'tcp.SrcPort != %d' % port) in final_filter
            host = self.guest_host
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
                        with socket.create_connection((host, port),
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
                    probe = tcp_echo_probe(host, port, marker)
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

    def _extra_stop(self, writer, label, expected_sha):
        """Exact original CLI stop, with real instance/exit and owned bytes."""
        raw = self.channel.powershell(
            "# CONTROL_EXTRA_STOP_V1\n$ErrorActionPreference='Stop';"
            "$exe='C:\\Program Files\\FakeNet-NG-MCP\\fakenetng-mcp.exe';"
            "$cfg='C:\\ProgramData\\FakeNet-NG-MCP\\configs\\service.json';"
            "if((Get-FileHash $cfg -Algorithm SHA256).Hash.ToLower() -cne '" + expected_sha + "'){throw 'control config owner changed'};"
            "$svc=Get-CimInstance Win32_Service -Filter \"Name='fakenetng-mcp'\";"
            "$old=$null;$before=$null;if($svc.State -eq 'Running' -and $svc.ProcessId){"
            "$old=Get-Process -Id $svc.ProcessId -ErrorAction Stop;[void]$old.Handle;"
            "if($old.Path -ine $exe){throw 'control service image differs'};"
            "$before=@{pid=$old.Id;birth=$old.StartTime.ToFileTimeUtc().ToString();image=$old.Path;"
            "sha256=(Get-FileHash -LiteralPath $old.Path -Algorithm SHA256).Hash.ToLower()}}"
            "elseif($svc.State -ne 'Stopped' -or $svc.ProcessId){throw 'control service transition unresolved'};"
            "$cli=@();if($old){$cli=@(& $exe stop 2>&1|ForEach-Object {\"$_\"});if($LASTEXITCODE -ne 0){throw 'controlled stop failed'}};"
            "$deadline=[DateTime]::UtcNow.AddSeconds(60);"
            "while((Get-Service fakenetng-mcp).Status -ne 'Stopped' -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 500};"
            "$after=Get-CimInstance Win32_Service -Filter \"Name='fakenetng-mcp'\";"
            "if($after.State -ne 'Stopped' -or $after.ProcessId){throw 'service did not stop for variant'};"
            "if($old -and !$old.WaitForExit(30000)){throw 'old control service has not exited'};"
            "@{before=$before;old_exited=[bool]$old;no_process_before=(!$old);scm_stopped=$true;pid_after=$after.ProcessId;"
            "config_sha256=(Get-FileHash $cfg -Algorithm SHA256).Hash.ToLower();cli_output=$cli}|ConvertTo-Json -Depth 5 -Compress", timeout=300)
        proof = json.loads(raw['output'])
        if (proof.get('scm_stopped') is not True or proof.get('pid_after') != 0 or
                proof.get('config_sha256') != expected_sha or
                (proof.get('before') is None and (proof.get('no_process_before') is not True or proof.get('old_exited') is not False)) or
                (proof.get('before') is not None and (proof.get('old_exited') is not True or proof.get('no_process_before') is not False))):
            raise RuntimeError('control stop/owned configuration proof differs')
        if proof.get('before') is not None and not hasattr(self, '_extra_image_sha'):
            self._extra_image_sha = proof['before']['sha256']
        writer.add_evidence('control-extra-stop-' + label, {'proof': proof, 'raw': raw})
        observe = getattr(self.channel, 'control_extra_stopped', None)
        if observe is not None:
            observe(label, proof)
        return proof

    def _extra_start(self, expected_sha, seconds, timeout):
        image_sha = getattr(self, '_extra_image_sha', None)
        if not image_sha:
            raise RuntimeError('original control service image was not observed')
        return self.channel.powershell(
            "# CONTROL_EXTRA_START_V1\n$ErrorActionPreference='Stop';"
            "$exe='C:\\Program Files\\FakeNet-NG-MCP\\fakenetng-mcp.exe';"
            "$cfg='C:\\ProgramData\\FakeNet-NG-MCP\\configs\\service.json';"
            "$svc=Get-CimInstance Win32_Service -Filter \"Name='fakenetng-mcp'\";"
            "if($svc.PathName -notmatch ('(?i)^\"?'+[regex]::Escape($exe)+'\"?(?:\\s|$)')){throw 'control SCM image path changed'};"
            "if((Get-FileHash $exe -Algorithm SHA256).Hash.ToLower() -cne '" + image_sha + "'){throw 'control SCM image hash changed'};"
            "if((Get-FileHash $cfg -Algorithm SHA256).Hash.ToLower() -cne '" + expected_sha + "'){throw 'control config owner changed'};"
            "sc.exe start fakenetng-mcp | Out-Null; Start-Sleep -Seconds " + str(seconds) + "; "
            "(Get-Service fakenetng-mcp).Status", timeout=timeout)

    def _extra_write(self, writer, label, expected_sha, data):
        encoded = base64.b64encode(data).decode('ascii')
        wanted = hashlib.sha256(data).hexdigest()
        raw = self.channel.powershell(
            "# CONTROL_EXTRA_WRITE_V1\n$ErrorActionPreference='Stop';$p='C:\\ProgramData\\FakeNet-NG-MCP\\configs\\service.json';"
            "if((Get-FileHash $p -Algorithm SHA256).Hash.ToLower() -cne '" + expected_sha + "'){throw 'control config owner changed'};"
            "$bytes=[Convert]::FromBase64String('" + encoded + "');[IO.File]::WriteAllBytes($p,$bytes);"
            "@{base64=[Convert]::ToBase64String([IO.File]::ReadAllBytes($p));"
            "sha256=(Get-FileHash $p -Algorithm SHA256).Hash.ToLower()}|ConvertTo-Json -Compress", timeout=30)
        observed = json.loads(raw['output'])
        if observed != {'base64': encoded, 'sha256': wanted}:
            raise RuntimeError('control configuration write/restore bytes differ')
        writer.add_evidence('control-extra-write-' + label, {'observed': observed, 'raw': raw})
        return wanted

    def _invalid_stop(self, writer, label, expected_sha):
        """Exact original CLI stop, with real instance/exit and owned bytes."""
        raw = self.channel.powershell(
            "# CONTROL_INVALID_STOP_V1\n$ErrorActionPreference='Stop';"
            "$exe='C:\\Program Files\\FakeNet-NG-MCP\\fakenetng-mcp.exe';"
            "$cfg='C:\\ProgramData\\FakeNet-NG-MCP\\configs\\service.json';"
            "if((Get-FileHash $cfg -Algorithm SHA256).Hash.ToLower() -cne '" + expected_sha + "'){throw 'control config owner changed'};"
            "$svc=Get-CimInstance Win32_Service -Filter \"Name='fakenetng-mcp'\";"
            "$old=$null;$before=$null;if($svc.State -eq 'Running' -and $svc.ProcessId){"
            "$old=Get-Process -Id $svc.ProcessId -ErrorAction Stop;[void]$old.Handle;"
            "if($old.Path -ine $exe){throw 'control service image differs'};"
            "$before=@{pid=$old.Id;birth=$old.StartTime.ToFileTimeUtc().ToString();image=$old.Path;"
            "sha256=(Get-FileHash -LiteralPath $old.Path -Algorithm SHA256).Hash.ToLower()}}"
            "elseif($svc.State -ne 'Stopped' -or $svc.ProcessId){throw 'control service transition unresolved'};"
            "$cli=@();if($old){$cli=@(& $exe stop 2>&1|ForEach-Object {\"$_\"});if($LASTEXITCODE -ne 0){throw 'controlled stop failed'}};"
            "$deadline=[DateTime]::UtcNow.AddSeconds(60);"
            "while((Get-Service fakenetng-mcp).Status -ne 'Stopped' -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 500};"
            "$after=Get-CimInstance Win32_Service -Filter \"Name='fakenetng-mcp'\";"
            "if($after.State -ne 'Stopped' -or $after.ProcessId){throw 'service did not stop for variant'};"
            "if($old -and !$old.WaitForExit(30000)){throw 'old control service has not exited'};"
            "@{before=$before;old_exited=[bool]$old;no_process_before=(!$old);scm_stopped=$true;pid_after=$after.ProcessId;"
            "config_sha256=(Get-FileHash $cfg -Algorithm SHA256).Hash.ToLower();cli_output=$cli}|ConvertTo-Json -Depth 5 -Compress", timeout=300)
        proof = json.loads(raw['output'])
        if (proof.get('scm_stopped') is not True or proof.get('pid_after') != 0 or
                proof.get('config_sha256') != expected_sha or
                (proof.get('before') is None and (proof.get('no_process_before') is not True or proof.get('old_exited') is not False)) or
                (proof.get('before') is not None and (proof.get('old_exited') is not True or proof.get('no_process_before') is not False))):
            raise RuntimeError('control stop/owned configuration proof differs')
        if proof.get('before') is not None and not hasattr(self, '_invalid_image_sha'):
            self._invalid_image_sha = proof['before']['sha256']
        writer.add_evidence('control-invalid-stop-' + label, {'proof': proof, 'raw': raw})
        observe = getattr(self.channel, 'control_invalid_stopped', None)
        if observe is not None:
            observe(label, proof)
        return proof

    def _invalid_start(self, expected_sha, seconds, timeout):
        image_sha = getattr(self, '_invalid_image_sha', None)
        if not image_sha:
            raise RuntimeError('original control service image was not observed')
        return self.channel.powershell(
            "# CONTROL_INVALID_START_V1\n$ErrorActionPreference='Stop';"
            "$exe='C:\\Program Files\\FakeNet-NG-MCP\\fakenetng-mcp.exe';"
            "$cfg='C:\\ProgramData\\FakeNet-NG-MCP\\configs\\service.json';"
            "$svc=Get-CimInstance Win32_Service -Filter \"Name='fakenetng-mcp'\";"
            "if($svc.PathName -notmatch ('(?i)^\"?'+[regex]::Escape($exe)+'\"?(?:\\s|$)')){throw 'control SCM image path changed'};"
            "if((Get-FileHash $exe -Algorithm SHA256).Hash.ToLower() -cne '" + image_sha + "'){throw 'control SCM image hash changed'};"
            "if((Get-FileHash $cfg -Algorithm SHA256).Hash.ToLower() -cne '" + expected_sha + "'){throw 'control config owner changed'};"
            "sc.exe start fakenetng-mcp | Out-Null; Start-Sleep -Seconds " + str(seconds) + "; "
            "(Get-Service fakenetng-mcp).Status", timeout=timeout)

    def _invalid_write(self, writer, label, expected_sha, data):
        encoded = base64.b64encode(data).decode('ascii')
        wanted = hashlib.sha256(data).hexdigest()
        raw = self.channel.powershell(
            "# CONTROL_INVALID_WRITE_V1\n$ErrorActionPreference='Stop';$p='C:\\ProgramData\\FakeNet-NG-MCP\\configs\\service.json';"
            "if((Get-FileHash $p -Algorithm SHA256).Hash.ToLower() -cne '" + expected_sha + "'){throw 'control config owner changed'};"
            "$bytes=[Convert]::FromBase64String('" + encoded + "');[IO.File]::WriteAllBytes($p,$bytes);"
            "@{base64=[Convert]::ToBase64String([IO.File]::ReadAllBytes($p));"
            "sha256=(Get-FileHash $p -Algorithm SHA256).Hash.ToLower()}|ConvertTo-Json -Compress", timeout=30)
        observed = json.loads(raw['output'])
        if observed != {'base64': encoded, 'sha256': wanted}:
            raise RuntimeError('control configuration write/restore bytes differ')
        writer.add_evidence('control-invalid-write-' + label, {'observed': observed, 'raw': raw})
        return wanted

    def case_control_invalid(self, writer):
        checks = {}
        self.normalize()
        raw_config = self.channel.powershell(
            "$b=[IO.File]::ReadAllBytes('C:\\ProgramData\\FakeNet-NG-MCP\\configs\\service.json');"
            "@{sha256=(Get-FileHash 'C:\\ProgramData\\FakeNet-NG-MCP\\configs\\service.json' -Algorithm SHA256).Hash.ToLower();"
            "base64=[Convert]::ToBase64String($b)} | ConvertTo-Json -Compress", timeout=30)
        original = json.loads(raw_config['output'])
        original_bytes = base64.b64decode(original['base64'], validate=True)
        if hashlib.sha256(original_bytes).hexdigest() != original['sha256']:
            raise RuntimeError('service.json backup hash mismatch')
        writer.add_evidence('control-invalid-original-config', original)
        begin = getattr(self.channel, 'control_invalid_begin', None)
        if begin is not None:
            begin(original)
        body = json.loads(original_bytes)
        owned_sha = original['sha256']
        results = {}
        try:
            for variant in INVALID_PORT_VALUES:
                body['extra_control_ports'] = variant['value']
                payload = json.dumps(body, ensure_ascii=False).encode('utf-8')
                self._invalid_stop(writer, variant['label'], owned_sha)
                owned_sha = self._invalid_write(writer, variant['label'], owned_sha, payload)
                cursor = self.channel.powershell(
                    "$p='C:\\ProgramData\\FakeNet-NG-MCP\\logs\\service.log';"
                    "if(Test-Path $p){(Get-Item $p).Length}else{0}", timeout=30)
                offset = int(cursor['output'].strip())
                if offset < 0:
                    raise RuntimeError('negative service log offset')
                started = self._invalid_start(owned_sha, 8, 90)
                state = started['output'].strip().splitlines()[-1].strip()
                log = self.channel.powershell(
                    "$ErrorActionPreference='Stop';$p='C:\\ProgramData\\FakeNet-NG-MCP\\logs\\service.log';"
                    "$s=[IO.File]::Open($p,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite);"
                    "try{if($s.Length -lt " + str(offset) + "){throw 'service log rotated; unknown attribution'};"
                    "[void]$s.Seek(" + str(offset) + ",[IO.SeekOrigin]::Begin);"
                    "$reader=[IO.StreamReader]::new($s,[Text.Encoding]::UTF8);$reader.ReadToEnd()}"
                    "finally{$s.Dispose()}", timeout=30)
                combined = log['output']
                results[variant['label']] = {
                    'value': variant['value'], 'sc_state': state, 'log_offset': offset,
                    'log_tail': combined,
                    'refused': state != 'Running' and
                               ('config load failed' in combined and
                                ('extra control' in combined or 'ConfigError' in combined))}
            writer.add_evidence('control-invalid-variants', results)
            checks['every_illegal_type_refused_start'] = all(row['refused'] for row in results.values())
            return checks
        finally:
            self._invalid_stop(writer, 'restore', owned_sha)
            owned_sha = self._invalid_write(writer, 'restore', owned_sha, original_bytes)
            if owned_sha != original['sha256']:
                raise RuntimeError('restore hash mismatch')
            restarted = self._invalid_start(owned_sha, 5, 120)
            writer.add_evidence('control-invalid-restored-start', restarted)
            if restarted['output'].strip() != 'Running':
                raise RuntimeError('restored control service is not running')
            complete = getattr(self.channel, 'control_invalid_restored', None)
            if complete is not None:
                complete(original)

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
            writer.add_evidence('loopback-listener', listener)
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
                "$n2=$d.Send($b2,$b2.Length,'" + self.allowed_host + "',53);"
                "@{loopback_sent=$n;diverted_sent=$n2;source_address=$c.Client.LocalEndPoint.Address.ToString();source_port=$c.Client.LocalEndPoint.Port;diverted_target='" + self.allowed_host + "'}|ConvertTo-Json -Compress"
                "}finally{$c.Dispose();$d.Dispose()}", timeout=30)
            writer.add_evidence('loopback-stimulus', sent['output'])
            stimulus = json.loads(sent['output'])
            if (stimulus.get('loopback_sent') != len(marker_loopback.encode('ascii')) or
                    stimulus.get('diverted_sent') != len(marker_diverted.encode('ascii')) or
                    stimulus.get('diverted_target') != self.allowed_host or
                    type(stimulus.get('source_port')) is not int or not 0 < stimulus['source_port'] < 65536):
                raise RuntimeError('loopback stimulus identity differs')
            time.sleep(1.5)
            receipt_path = listener['receipt']
            receipt_header = listener['header']
            if listener is not None:
                stopping = listener
                listener = None
                writer.add_evidence('loopback-listener-stop', self._stop_loopback_listener(stopping))
            ok, final = self.finish_run(writer)
            checks['run_stopped_cleanly'] = ok
            checks.update(self._verify_pcaps(writer, run_id, family,
                                             marker_loopback, marker_diverted,
                                             port, stimulus['source_port']))
            receipts = self.channel.powershell(
                "# LOOPBACK_RECEIPT_V1\n$ErrorActionPreference='Stop';$p='" + receipt_path.replace("'", "''") + "';"
                "$b=[IO.File]::ReadAllBytes($p);@{path=$p;size=$b.Length;"
                "sha256=(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLower();"
                "base64=[Convert]::ToBase64String($b)}|ConvertTo-Json -Compress", timeout=30)
            receipt = json.loads(receipts['output'])
            payload = base64.b64decode(receipt['base64'], validate=True)
            if (receipt.get('path') != receipt_path or len(payload) != receipt.get('size') or
                    hashlib.sha256(payload).hexdigest() != receipt.get('sha256')):
                raise RuntimeError('loopback receipt identity differs')
            lines = payload.decode('utf-8-sig').splitlines()
            wanted = 'recv ' + base64.b64encode(marker_loopback.encode('ascii')).decode('ascii')
            checks['marker_arrived_at_local_listener'] = (
                bool(lines) and lines[0] == receipt_header and wanted in lines[1:])
            writer.add_evidence('loopback-receipts', receipt)
            return checks
        finally:
            if listener is not None:
                stopping = listener
                listener = None
                writer.add_evidence('loopback-listener-stop', self._stop_loopback_listener(stopping))

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
        from pathlib import PureWindowsPath
        expected_address = '127.0.0.1' if family == 'V4' else '::1'
        if family not in ('V4', 'V6') or address != expected_address:
            raise ValueError('loopback listener family/address differs')
        receipt = str(PureWindowsPath(self.guest_work_root) / ('loopback-receipts-' + nonce + '.txt'))
        escaped = receipt.replace("'", "''")
        wildcard = 'Any' if family == 'V4' else 'IPv6Any'
        header_prefix = 'started ' + nonce + ' ' + family + ' ' + address + ' ' + str(port) + ' pid='
        script = (
            "$ErrorActionPreference='Stop';"
            "$ep=[Net.IPEndPoint]::new([Net.IPAddress]::Parse('" + address + "')," + str(port) + ");"
            "$listener=[Net.Sockets.UdpClient]::new($ep);$log='" + escaped + "';"
            "[IO.File]::WriteAllText($log,('" + header_prefix + "'+$PID+[Environment]::NewLine),[Text.UTF8Encoding]::new($false));"
            "try{while($true){$remote=[Net.IPEndPoint]::new([Net.IPAddress]::" + wildcard + ",0);"
            "$b=$listener.Receive([ref]$remote);"
            "[IO.File]::AppendAllText($log,('recv '+[Convert]::ToBase64String($b)+[Environment]::NewLine),[Text.UTF8Encoding]::new($false))}}finally{$listener.Close()}")
        result = self.channel.powershell(
            "# LOOPBACK_LISTENER_START_V1\n$ErrorActionPreference='Stop';if(Test-Path -LiteralPath '" + escaped + "'){throw 'loopback receipt collision'};"
            "Start-Process powershell -WindowStyle Hidden -ArgumentList '-NoProfile','-Command','" +
            script.replace("'", "''") + "' -PassThru | ForEach-Object { $_.Id }", timeout=30)
        pid = int(result['output'].strip().splitlines()[-1])
        header = header_prefix + str(pid)
        ready = self.channel.powershell(
            "# LOOPBACK_LISTENER_READY_V1\n$ErrorActionPreference='Stop';$p=Get-Process -Id " + str(pid) + ";[void]$p.Handle;"
            "$born=$p.StartTime.ToFileTimeUtc().ToString();$deadline=[DateTime]::UtcNow.AddSeconds(10);$path='" + escaped + "';"
            "while(!(Test-Path -LiteralPath $path) -and !$p.HasExited -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 100};"
            "if($p.HasExited -or !(Test-Path -LiteralPath $path)){throw 'loopback listener did not become ready'};"
            "$header=[IO.File]::ReadAllLines($path)[0];if($header -cne '" + header + "'){throw 'loopback listener receipt owner differs'};"
            "@{pid=$p.Id;created=$born;image=$p.Path;sha256=(Get-FileHash -LiteralPath $p.Path -Algorithm SHA256).Hash.ToLower();"
            "receipt=$path;header=$header}|ConvertTo-Json -Compress", timeout=30)
        observed = json.loads(ready['output'])
        if (observed.get('pid') != pid or not str(observed.get('created', '')).isdigit() or
                not observed.get('image') or len(observed.get('sha256', '')) != 64 or
                observed.get('receipt') != receipt or observed.get('header') != header):
            raise RuntimeError('loopback listener identity/readiness differs')
        return observed

    def _stop_loopback_listener(self, listener):
        raw = self.channel.powershell(
            "# LOOPBACK_LISTENER_STOP_V1\n$ErrorActionPreference='Stop';$p=Get-Process -Id " + str(listener['pid']) + ";[void]$p.Handle;"
            "if($p.StartTime.ToFileTimeUtc().ToString() -cne '" + str(listener['created']) + "' -or $p.Path -ine '" + listener['image'].replace("'", "''") + "'){throw 'loopback listener owner differs'};"
            "if((Get-FileHash -LiteralPath $p.Path -Algorithm SHA256).Hash.ToLower() -cne '" + listener['sha256'] + "'){throw 'loopback listener image changed'};"
            "$p.Kill();if(!$p.WaitForExit(5000)){throw 'loopback listener exit unresolved'};"
            "@{pid=" + str(listener['pid']) + ";birth='" + str(listener['created']) + "';exited=$true}|ConvertTo-Json -Compress", timeout=30)
        if json.loads(raw['output']) != {'pid': listener['pid'], 'birth': str(listener['created']), 'exited': True}:
            raise RuntimeError('loopback listener exit proof differs')
        return raw

    def _verify_pcaps(self, writer, run_id, family, marker_loopback,
                      marker_diverted, loop_port, loop_source_port):
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
        names = [item['name'] for item in files]
        converted = [name for name in names if name.endswith('-converted.pcap')]
        paired = (len(names) == len(set(names)) == 2 and len(converted) == 1 and
                  converted[0][:-len('-converted.pcap')] + '.pcap' in names)
        checks = {
            'pcap_evidence_present': bool(files),
            'dual_pcap_pair_present': paired,
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
        requested_family = socket.AF_INET if family == 'V4' else socket.AF_INET6
        requested_address = '127.0.0.1' if family == 'V4' else '::1'
        marker_loopback_b = marker_loopback.encode('ascii')
        marker_diverted_b = marker_diverted.encode('ascii')
        loop_records, redirected, diverted_seen = [], [], []
        for f in files:
            if not f.get('base64'):
                continue
            payload = base64.b64decode(f['base64'])
            import hashlib as _h
            if len(payload) != f['size'] or _h.sha256(payload).hexdigest() != f['sha256']:
                raise ValueError('loopback PCAP content identity differs')
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
                        packet_family = socket.AF_INET6
                    elif isinstance(layer, dpkt.ip.IP):
                        packet_family = socket.AF_INET6 if layer.v == 6 else socket.AF_INET
                    else:
                        continue
                    def addr(raw):
                        return socket.inet_ntop(packet_family, raw)
                    src, dst = addr(layer.src), addr(layer.dst)
                    l4 = layer.data
                    row = dict(file=f['name'], src=src, dst=dst,
                               sport=getattr(l4, 'sport', None),
                               dport=getattr(l4, 'dport', None),
                               proto=layer.p if layer.v == 4 else layer.nxt)
                    if not isinstance(l4, dpkt.udp.UDP):
                        continue
                    marker = bytes(l4.data)
                    if marker == marker_loopback_b:
                        is_loopback_pair = (
                            ipaddress.ip_address(src).is_loopback and
                            ipaddress.ip_address(dst).is_loopback)
                        if (packet_family == requested_family and src == dst == requested_address and
                                row['sport'] == loop_source_port and row['dport'] == loop_port and is_loopback_pair):
                            loop_records.append(row)
                        else:
                            redirected.append(row)
                    if (marker == marker_diverted_b and
                            not ipaddress.ip_address(dst).is_loopback):
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
