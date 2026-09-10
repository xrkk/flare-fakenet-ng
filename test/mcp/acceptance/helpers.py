# Copyright 2026 Google LLC
"""Shared helpers for the P01 ACC runner (§9.1 contract implementation)."""

import json
import subprocess
import sys
import threading
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

import anyio

from mcp import Client

DEFAULT_WIN10VM_MCP = 'http://192.168.204.149:28787/mcp'
HOST_ONLY_BIND = '192.168.204.1'


class StepError(RuntimeError):
    pass


def run_local(command, cwd=None, timeout=120):
    completed = subprocess.run(
        [str(item) for item in command], cwd=cwd, capture_output=True,
        text=True, timeout=timeout)
    return {
        'command': [str(item) for item in command],
        'returncode': completed.returncode,
        'stdout': completed.stdout,
        'stderr': completed.stderr,
    }


class PackageServer:
    """Temporary host-only HTTP service bound to 192.168.204.1 only."""

    def __init__(self, root, port=0):
        self.root = Path(root).resolve()
        handler = _make_handler(self.root)
        self.httpd = ThreadingHTTPServer((HOST_ONLY_BIND, port), handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever,
                                       daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=10)

    @property
    def base_url(self):
        return 'http://%s:%d' % (HOST_ONLY_BIND, self.port)


def _make_handler(root):
    class Handler(SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(root), **kwargs)

        def log_message(self, format, *args):  # noqa: A002
            pass

    return Handler


class Win10VmChannel:
    """Drive the acceptance VM through its existing Win10VM MCP server."""

    def __init__(self, url=DEFAULT_WIN10VM_MCP):
        self.url = url

    def powershell(self, command, timeout=120):
        record = {'tool': 'PowerShell', 'command': command,
                  'timeout': timeout}

        async def _call():
            async with Client(self.url,
                              read_timeout_seconds=timeout + 30) as client:
                result = await client.call_tool(
                    'PowerShell', {'command': command, 'timeout': timeout})
                return result

        outcome = anyio.run(_call)
        record['is_error'] = bool(getattr(outcome, 'is_error', False))
        texts = []
        content = getattr(outcome, 'content', None) or []
        for item in content:
            text = getattr(item, 'text', None)
            if text is not None:
                texts.append(text)
        raw = '\n'.join(texts)
        record['raw'] = raw
        output = raw
        exit_code = None
        marker = 'Status Code:'
        index = raw.rfind(marker)
        if index >= 0:
            tail = raw[index + len(marker):].strip()
            try:
                exit_code = int(tail.splitlines()[0].strip() or '0')
            except (ValueError, IndexError):
                exit_code = None
            output = raw[:index]
        if output.startswith('Response:'):
            output = output[len('Response:'):]
        record['output'] = output.strip()
        record['exit_code'] = exit_code
        if record['is_error'] or exit_code is None or exit_code != 0:
            raise StepError('PowerShell failed (exit=%s): %s' %
                            (exit_code, raw[:500]))
        return record

    def computer_name(self):
        record = self.powershell('$env:COMPUTERNAME', timeout=60)
        return record['output'].strip()


def controlled_service_stop(channel):
    """Use the installed two-phase CLI, then wait for its old host to exit."""
    return channel.powershell(
        "$ErrorActionPreference='Stop'; "
        "$exe='C:\\Program Files\\FakeNet-NG-MCP\\fakenetng-mcp.exe'; "
        "$svc=Get-CimInstance Win32_Service -Filter \"Name='fakenetng-mcp'\"; "
        "if($svc){if(!(Test-Path $exe)){throw 'installed service binary missing'}; "
        "$old=if($svc.ProcessId){Get-Process -Id $svc.ProcessId -ErrorAction SilentlyContinue}else{$null}; "
        "& $exe stop; if($LASTEXITCODE -ne 0){throw 'controlled pre-stop failed; preserve installed files'}; "
        "if((Get-Service fakenetng-mcp).Status -ne 'Stopped'){throw 'SCM not stopped'}; "
        "if($old -and !$old.WaitForExit(30000)){throw 'old service process has not exited'}; "
        "'controlled service stop completed'}else{"
        "$state='C:\\ProgramData\\FakeNet-NG-MCP\\state\\state.json'; "
        "if((Test-Path $state) -and (Get-Content $state -Raw | ConvertFrom-Json).needs_recovery)"
        "{throw 'service absent with unresolved recovery responsibility'}; 'service absent'}",
        timeout=1110)


def configure_fault_service(channel, enabled, grace, allow_change=True):
    """Configure only this service, using its controlled stop protocol."""
    current = channel.powershell(
        "$ErrorActionPreference='Stop'; "
        "$key='HKLM:\\SYSTEM\\CurrentControlSet\\Services\\fakenetng-mcp'; "
        "$envs=@((Get-ItemProperty $key -Name Environment -ErrorAction SilentlyContinue).Environment); "
        "$cfg=Get-Content 'C:\\ProgramData\\FakeNet-NG-MCP\\configs\\service.json' -Raw | ConvertFrom-Json; "
        "@{enabled=($envs -contains 'FAKENETNG_MCP_FAULT_INJECTION=1');grace=$cfg.stop_grace_seconds} | ConvertTo-Json -Compress",
        timeout=30)
    if json.loads(current['output']) == {'enabled': enabled, 'grace': grace}:
        return dict(current, reused_service_instance=True)
    if not allow_change:
        raise StepError('fault mode drift after recorded rounds; preserve evidence')
    channel.powershell(
        "if(Test-Path 'C:\\ProgramData\\FakeNet-NG-MCP\\logs\\fault-injection.json')"
        "{throw 'unconsumed fault; preserve scene'}; 'no unconsumed fault'", timeout=30)
    stopped = controlled_service_stop(channel)
    value = "@('FAKENETNG_MCP_FAULT_INJECTION=1')" if enabled else '@()'
    changed = channel.powershell(
        "$ErrorActionPreference='Stop'; $key='HKLM:\\SYSTEM\\CurrentControlSet\\Services\\fakenetng-mcp'; "
        "$preserved=@((Get-ItemProperty $key -Name Environment -ErrorAction SilentlyContinue).Environment | "
        "Where-Object {$_ -and $_ -notlike 'FAKENETNG_MCP_FAULT_INJECTION=*'}); "
        "New-ItemProperty $key -Name Environment -PropertyType MultiString -Value ($preserved + " + value + ") -Force | Out-Null; "
        "$path='C:\\ProgramData\\FakeNet-NG-MCP\\configs\\service.json'; $cfg=Get-Content $path -Raw | ConvertFrom-Json; "
        "$cfg | Add-Member -NotePropertyName stop_grace_seconds -NotePropertyValue " + str(int(grace)) + " -Force; "
        "[IO.File]::WriteAllText($path,($cfg | ConvertTo-Json),[Text.UTF8Encoding]::new($false)); "
        "Start-Service fakenetng-mcp; 'configured'", timeout=60)
    return {'before': current, 'stop': stopped, 'change': changed}


def arm_fault_file(channel, fault):
    import uuid
    from fakenet.mcp.faultinject import FAULTS
    if fault not in FAULTS:
        raise ValueError('unsupported fault class: ' + str(fault))
    payload = {'fault': fault, 'nonce': str(uuid.uuid4())}
    raw = channel.powershell(
        "$ErrorActionPreference='Stop'; $path='C:\\ProgramData\\FakeNet-NG-MCP\\logs\\fault-injection.json'; "
        "if(Test-Path $path){throw 'unconsumed fault file'}; "
        "[IO.File]::WriteAllText($path,'" + json.dumps(payload) + "',[Text.UTF8Encoding]::new($false)); "
        "Get-Content $path -Raw", timeout=30)
    if json.loads(raw['output']) != payload:
        raise StepError('fault file readback mismatch')
    return dict(payload, raw=raw)


def export_incident_bundle(channel, run_id, destination, incident_name='incident'):
    """Export the exact run's package, then verify its bytes on the host."""
    import base64
    import hashlib
    import uuid
    import zipfile
    import re
    from fakenet.mcp.incident import BASIC_ITEMS
    run_id = str(uuid.UUID(run_id))
    match = re.fullmatch(r'incident(?:-(\d{2,}))?', incident_name)
    if not match or (match.group(1) and int(match.group(1)) < 2):
        raise ValueError('invalid incident directory')
    token = uuid.uuid4().hex
    guest_zip = 'C:\\Windows\\Temp\\FakeNet-incident-' + token + '.zip'
    root = 'C:\\ProgramData\\FakeNet-NG-MCP\\artifacts\\' + run_id + '\\' + incident_name
    captured = channel.powershell(
        "$ErrorActionPreference='Stop'; $dir='" + root + "'; $zip='" + guest_zip + "'; "
        "$manifest=Join-Path $dir 'manifest.json'; $m=Get-Content $manifest -Raw | ConvertFrom-Json; "
        "if($m.run_id -ne '" + run_id + "'){throw 'incident run identity mismatch'}; "
        "Compress-Archive -Path (Join-Path $dir '*') -DestinationPath $zip; "
        "@{size=(Get-Item $zip).Length;sha256=(Get-FileHash $zip -Algorithm SHA256).Hash.ToLower(); "
        "manifest_sha256=(Get-FileHash $manifest -Algorithm SHA256).Hash.ToLower()} | ConvertTo-Json -Compress",
        timeout=120)
    metadata = json.loads(captured['output'])
    if not 0 < metadata['size'] <= 512 * 1024 * 1024:
        raise StepError('incident export size outside bound')
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    with destination.open('xb') as stream:
        for offset in range(0, metadata['size'], 262144):
            count = min(262144, metadata['size'] - offset)
            result = channel.powershell(
                "$ErrorActionPreference='Stop'; $s=[IO.File]::OpenRead('" + guest_zip + "'); "
                "try{[void]$s.Seek(" + str(offset) + ",[IO.SeekOrigin]::Begin); "
                "$b=New-Object byte[] " + str(count) + "; $n=$s.Read($b,0,$b.Length); "
                "if($n -ne $b.Length){throw 'short archive read'}; [Convert]::ToBase64String($b)}finally{$s.Dispose()}",
                timeout=30)
            block = base64.b64decode(result['output'], validate=True)
            if len(block) != count:
                raise StepError('incident transfer chunk length mismatch')
            stream.write(block)
            digest.update(block)
    if digest.hexdigest() != metadata['sha256']:
        raise StepError('incident archive transfer hash mismatch')
    with zipfile.ZipFile(destination) as archive:
        if len(set(archive.namelist())) != len(archive.namelist()):
            raise StepError('duplicate incident archive member')
        manifest_raw = archive.read('manifest.json')
        if hashlib.sha256(manifest_raw).hexdigest() != metadata['manifest_sha256']:
            raise StepError('incident manifest transfer hash mismatch')
        manifest = json.loads(manifest_raw)
        if manifest.get('run_id') != run_id:
            raise StepError('exported incident belongs to another run')
        verified, failures = [], []
        for entry in manifest.get('entries', []):
            name = entry.get('item', '')
            if not name or '/' in name or '\\' in name or name in ('.', '..'):
                raise StepError('invalid incident member name')
            if entry.get('result') != 'ok':
                if (name == 'userdump.dmp' and entry.get('result') == 'skipped' and
                        entry.get('failure_reason') == 'no escalation condition' and
                        entry.get('size') == 0 and entry.get('sha256') is None):
                    continue
                failures.append(name + ': ' + str(entry.get('failure_reason')))
                continue
            data = archive.read(name)
            if len(data) != entry.get('size') or hashlib.sha256(data).hexdigest() != entry.get('sha256'):
                raise StepError('incident member hash/size mismatch: ' + name)
            verified.append(name)
        missing = set(name for name, _ in BASIC_ITEMS) - set(verified)
        failures.extend('missing basic item: ' + name for name in sorted(missing))
    return {'path': str(destination), 'sha256': digest.hexdigest(), 'size': metadata['size'],
            'run_id': run_id, 'incident_name': incident_name, 'manifest': manifest, 'verified_members': verified,
            'complete': bool(manifest.get('complete')) and not failures,
            'failures': failures, 'transfer_metadata': captured}


def export_run_incidents(channel, run_id, destination):
    """Export every retained collection attempt of this exact run."""
    import uuid
    run_id = str(uuid.UUID(run_id))
    raw = channel.powershell(
        "$ErrorActionPreference='Stop';$root='C:\\ProgramData\\FakeNet-NG-MCP\\artifacts\\" + run_id + "'; "
        "$names=@(Get-ChildItem -LiteralPath $root -Directory | Where-Object {$_.Name -match '^incident(?:-[0-9]{2,})?$'} | "
        "Select-Object -ExpandProperty Name);ConvertTo-Json -InputObject $names -Compress", timeout=30)
    names = json.loads(raw['output'])
    if not isinstance(names, list) or not names or len(names) != len(set(names)):
        raise StepError('incident collection list missing or invalid')
    return [export_incident_bundle(channel, run_id,
            Path(destination) / (name + '-' + run_id + '.zip'), incident_name=name)
            for name in names]


class EvidenceWriter:

    def __init__(self, out_dir, started_at):
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        if (self.out_dir / 'result.json').exists():
            raise FileExistsError('acceptance result already exists; use a new evidence directory')
        self.started_at = started_at
        self.actions = []
        self.expected = []
        self.observed = []
        self.evidence = []
        self.blocker = None

    def action(self, name, detail):
        self.actions.append({'name': name, 'detail': detail})

    def expect(self, text):
        self.expected.append(text)

    def observe(self, text):
        self.observed.append(text)

    def add_evidence(self, name, content):
        if isinstance(content, (dict, list)):
            import hashlib
            import io

            raw = json.dumps(content, ensure_ascii=False, indent=2).encode(
                'utf-8')
            digest = hashlib.sha256(raw).hexdigest()
            path = self.out_dir / (name + '.json')
            with path.open('xb') as stream:
                stream.write(raw)
        else:
            import hashlib

            raw = str(content).encode('utf-8')
            digest = hashlib.sha256(raw).hexdigest()
            path = self.out_dir / name
            suffix = Path(name).suffix or '.txt'
            path = self.out_dir / (Path(name).stem + suffix)
            with path.open('xb') as stream:
                stream.write(raw)
        self.evidence.append({
            'name': name, 'path': str(path), 'sha256': digest,
            'size': len(raw)})
        return path

    def write_result(self, *, acc_id, p_id, candidate_id, source_commit,
                     package_sha256, requirements_blob, master_plan_blob,
                     environment_identity, status):
        import datetime

        result = {
            'acc_id': acc_id,
            'p_id': p_id,
            'candidate_id': candidate_id,
            'source_commit': source_commit,
            'package_sha256': package_sha256,
            'requirements_blob': requirements_blob,
            'master_plan_blob': master_plan_blob,
            'environment_identity': environment_identity,
            'started_at': self.started_at,
            'ended_at': datetime.datetime.now(
                datetime.timezone.utc).isoformat(),
            'status': status,
            'actions': self.actions,
            'expected': self.expected,
            'observed': self.observed,
            'evidence': self.evidence,
            'blocker': self.blocker,
        }
        with (self.out_dir / 'result.json').open('x', encoding='utf-8') as stream:
            stream.write(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
        return result


EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_BLOCKED = 2
EXIT_TOOL_ERROR = 3


def kill_current_service(channel, context=''):
    """Force-kill only the currently registered service instance.

    The PID and creation time come from SCM and are re-checked immediately
    before the kill, so an unrelated same-named process is never targeted
    and a reused PID is refused (CHK-062).
    """
    return channel.powershell(
        "$ErrorActionPreference='Stop'; "
        "$svc=Get-CimInstance Win32_Service -Filter \"Name='fakenetng-mcp'\"; "
        "if(-not $svc -or -not $svc.ProcessId){throw 'no service instance to kill'}; "
        "if($svc.PathName -notlike '*fakenetng-mcp.exe*'){throw 'service image unexpected'}; "
        "$p=Get-Process -Id $svc.ProcessId -ErrorAction Stop; "
        "$born=$p.StartTime.ToFileTimeUtc(); "
        "$again=Get-Process -Id $svc.ProcessId -ErrorAction Stop; "
        "if($again.StartTime.ToFileTimeUtc() -ne $born){throw 'service PID was reused'}; "
        "$again | Stop-Process -Force; "
        "@{killed_pid=$svc.ProcessId;created=$born;image=$p.Path;context='" + context + "'} | "
        "ConvertTo-Json -Compress", timeout=60)


def kill_owned_process(channel, pid, created, context=''):
    """Kill one runner-owned process, pinned by PID and creation time."""
    return channel.powershell(
        "$ErrorActionPreference='Stop'; "
        "$p=Get-Process -Id " + str(int(pid)) + " -ErrorAction Stop; "
        "if($p.StartTime.ToFileTimeUtc() -ne " + str(int(created)) + ")"
        "{throw 'owned process PID was reused'}; "
        "$p | Stop-Process -Force; 'KILLED'", timeout=60)
