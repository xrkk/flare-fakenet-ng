#!/usr/bin/env python3
# Copyright 2026 Google LLC
"""P05 release gate runner (sub-plan P05 v1).

Modes:
  normal  — ACC-012: >=100 normal start/stop rounds (50 builtin default.ini
            + 50 semantic-diff custom release-custom.ini), checkpointed per
            round under Logs/fakenetng-mcp/<cid>/release/.
  fault   — ACC-013: five fault classes x 10 rounds via the P04 in-process
            injector (machine env + service restart arming).
  final   — ACC-017: clean-snapshot native install end-to-end chain plus the
            tested-Windows-version declaration.
  summary — ACC index aggregation + release manifest into dist/.

Exit codes follow master-plan 9.1 (0/1/2/3+)."""

import argparse
import datetime
import hashlib
import json
import sys
import time
import threading
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from helpers import (EXIT_BLOCKED, EXIT_FAIL, EXIT_PASS,  # noqa: E402
                     EXIT_TOOL_ERROR, EvidenceWriter, Win10VmChannel)
from run_p02_acc import VALID_INI, call, sha_of, status  # noqa: E402
from run_p03_acc import continuous_probe, stop_run, unique_command, wait_state  # noqa: E402
sys.path.insert(0, str(REPO_ROOT))
from fakenet.mcp.faultinject import FAULTS  # noqa: E402
from evidence_integrity import (IDENTITY_FIELDS, validate_result,
                                validate_round, validate_rounds, validate_sample_category)

DEFAULT_INI = 'default.ini'
CUSTOM_INI = 'release-custom.ini'
CUSTOM_BODY_DELTA = ('DumpPacketsFilePrefix = release-custom')

FAULT_CLASSES = ('policy_pause', 'listener_stop', 'diverter_stop',
                'child_hang', 'cleanup_error')
NORMAL_ROUNDS_PER_CONFIG = 50
FAULT_ROUNDS_PER_CLASS = 10
CONTROL_CASE_LABELS = (
    'ACC-004-CONTROL-DEFAULT',
    'ACC-004-CONTROL-EXTRA-28787', 'ACC-004-CONTROL-EXTRA-28790',
    'ACC-004-CONTROL-EXTRA-29095', 'ACC-004-CONTROL-EXTRA-29094',
    'ACC-004-CONTROL-INVALID', 'ACC-004-LOOPBACK-V4', 'ACC-004-LOOPBACK-V6',
)


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sha256_text(text):
    return hashlib.sha256(str(text).encode('utf-8')).hexdigest()


class ReleaseGate:

    def __init__(self, args):
        self.args = args
        self.cid = args.candidate_id
        self.base = args.target_base_url
        self.channel = Win10VmChannel(args.win10vm_mcp)
        self.root = Path(args.output_root) / self.cid
        self.release = self.root / 'release'
        self.release.mkdir(parents=True, exist_ok=True)

    # -- environment capture (host-driven, P04 normalization) -------------
    def capture_sections(self):
        import uuid
        captured = {'started_at': time.time(), 'sections': {}}
        try:
            self._capture_sections(captured['sections'])
            captured['complete'] = True
            return captured['sections']
        except Exception as exc:
            captured.update(complete=False, error=repr(exc))
            raise
        finally:
            captured['ended_at'] = time.time()
            captured.update({field: getattr(self.args, field) for field in IDENTITY_FIELDS})
            raw = (json.dumps(captured, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
            path = self.release / ('environment-capture-' + uuid.uuid4().hex + '.json')
            with path.open('xb') as stream:
                stream.write(raw)
            if not hasattr(self, '_capture_evidence'):
                self._capture_evidence = []
            self._capture_evidence.append(dict(path=str(path), size=len(raw),
                                               sha256=hashlib.sha256(raw).hexdigest()))

    def _capture_sections(self, out):
        from fakenet.mcp.baseline import process_capture_script
        commands = {
            'routes': '& route.exe print -4; if($LASTEXITCODE -ne 0){throw "route capture failed"}',
            'listen_ports': '& netstat.exe -ano; if($LASTEXITCODE -ne 0){throw "endpoint capture failed"}',
            'windivert_processes': process_capture_script(),
            'services': 'Get-Service dnscache,mpssvc | Select-Object Name,Status | ConvertTo-Json -Compress',
        }
        out['dns_servers'] = self.capture_dns_servers()
        for section, command in commands.items():
            if section == 'listen_ports':
                # Mirror the product's capture hygiene: resolver helper
                # sockets on this VM open a rotating four-family UDP quad;
                # record only rows present in three time-separated samples.
                raw = self.channel.powershell(
                    "$ErrorActionPreference='Stop'; "
                    # PowerShell hosts (this session and the long-lived MCP
                    # command host) own rotating resolver sockets; they are
                    # acceptance-driver plumbing, not product environment.
                    "$noise=@(Get-Process pwsh,powershell -ErrorAction SilentlyContinue | ForEach-Object { $_.Id }); "
                    "$filter={ $cols=$_.Trim() -split [char]32; "
                    "if($cols.Count -ge 4 -and $cols[-1] -match '^[0-9]+$'){ -not ($noise -contains [int]$cols[-1]) } else { $true } }; "
                    "$s1=@(netstat -ano | Where-Object $filter); Start-Sleep -Milliseconds 1200; "
                    "$s2=@(netstat -ano | Where-Object $filter); Start-Sleep -Milliseconds 1200; "
                    "$s3=@(netstat -ano | Where-Object $filter); "
                    "$r1=@($s1 | Where-Object {$_.Trim()}); "
                    "$r2=@($s2 | Where-Object {$_.Trim()}); "
                    "$r3=@($s3 | Where-Object {$_.Trim()}); "
                    "(@($r1 | Where-Object { $r2 -contains $_ -and $r3 -contains $_ }) -join [char]10)",
                    timeout=90)['output'].strip()
            else:
                raw = self.channel.powershell("$ErrorActionPreference='Stop'; " + command,
                                              timeout=60)['output'].strip()
            if not raw:
                raise RuntimeError('empty capture: ' + section)
            out[section] = raw
        return out

    def capture_dns_servers(self):
        raw = self.channel.powershell(
            "$ErrorActionPreference = 'Stop'; "
            'Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop | '
            'Select-Object InterfaceAlias,ServerAddresses | '
            'ConvertTo-Json -Compress', timeout=60)['output'].strip()
        try:
            data = json.loads(raw)
        except (TypeError, ValueError) as exc:
            raise RuntimeError('DNS capture did not return JSON') from exc
        rows = data if isinstance(data, list) else [data]
        if not rows or not all(
                isinstance(row, dict) and
                isinstance(row.get('InterfaceAlias'), str) and
                isinstance(row.get('ServerAddresses'), list) and
                all(isinstance(address, str)
                    for address in row['ServerAddresses'])
                for row in rows):
            raise RuntimeError('DNS capture has no valid interface observations')
        return raw

    def audit_diff(self, before):
        from fakenet.mcp.baseline import audit_compare

        # CHK-042: consume the shared directional schema straight from
        # audit_compare (fakenet_added / below_1024_removed). The former
        # re-narrowing here read the retired before/after keys, computed
        # an empty delta and silently POPPED real residue from the gate.
        # One schema, shared with the product's stop audit.
        return audit_compare(before, self.capture_sections())

    def vm_continuity(self):
        result = self.channel.powershell(
            '$ErrorActionPreference="Stop"; $os=Get-CimInstance Win32_OperatingSystem; '
            '$s=Get-CimInstance Win32_Service -Filter "Name=\'fakenetng-mcp\'"; '
            '$p=Get-Process -Id $s.ProcessId; '
            '@{computer=$env:COMPUTERNAME;boot=$os.LastBootUpTime.ToString("o");'
            'pid=$s.ProcessId;created=$p.StartTime.ToString("o");state=$s.State} | ConvertTo-Json -Compress', timeout=60)
        stamp = json.loads(result['output'])
        if stamp['computer'] != 'DESKTOP-3FI41GR' or stamp['state'] != 'Running':
            raise RuntimeError('VM/service identity not ready')
        return stamp

    def observe_round(self, action):
        """Cover the entire action, including baseline capture and cleanup."""
        identity = {field: getattr(self.args, field) for field in IDENTITY_FIELDS}
        self._capture_evidence = []
        before = self.vm_continuity()
        stop = threading.Event()
        timeline = []
        def sample():
            began = time.time()
            try:
                result = call(self.base, 'get_status', controller=None, timeout=1.5)
                ok = result.get('service') == 'fakenetng-mcp' and not result.get('error')
                detail = {'status': result}
            except Exception as exc:
                ok, detail = False, {'error': repr(exc)}
            timeline.append(dict(t=began, completed=time.time(), ok=ok, **detail))
        sample()
        start = time.time()
        def monitor():
            while not stop.wait(0.25):
                sample()
        thread = threading.Thread(target=monitor, daemon=True)
        thread.start()
        try:
            record = action()
        except Exception as exc:
            record = {'failure': repr(exc)}
        finally:
            end = time.time()
            stop.set()
            thread.join(3)
            if thread.is_alive():
                raise RuntimeError('probe worker did not terminate')
            sample()
        record.update(identity, vm_before=before, vm_after=self.vm_continuity(),
                      probe_window_start=start, probe_window_end=end,
                      probe_timeline=timeline,
                      capture_evidence=self._capture_evidence)
        issues = validate_round(record, identity)
        if issues:
            record['failure'] = '; '.join(issues) + ': ' + str(record.get('failure', ''))
        return record

    def ensure_custom_config(self):
        from evidence_integrity import custom_config_body
        builtin = call(self.base, 'read_config', {'name': DEFAULT_INI},
                       controller=None)
        content = builtin.get('content') or ''
        body = custom_config_body(content)
        version = call(self.base, 'get_status')['state_version']
        created = call(self.base, 'create_config',
                       {'name': CUSTOM_INI, 'content': body,
                        'command_id': unique_command('rel-cfg'),
                        'expected_state_version': version}, timeout=60)
        if created.get('error') and created['error'].get('code') != 'name_conflict':
            return False
        actual = call(self.base, 'read_config', {'name': CUSTOM_INI}, controller=None)
        return (actual.get('builtin') is False and
                actual.get('content', '').replace('\r\n', '\n') == body and
                hashlib.sha256(actual['content'].encode('utf-8')).hexdigest() == actual.get('sha256'))


    # -- one normal round --------------------------------------------------

    def config_lock_probe(self, index, during_run):
        """Try opening the exact active file for write without changing bytes."""
        snap = call(self.base, 'get_status', controller=None)
        identity = snap.get('config_identity') or {}
        name = identity.get('name', '')
        import re
        if not re.fullmatch(r'[A-Za-z0-9._-]+\.ini', name):
            raise RuntimeError('active configuration identity unavailable')
        root = (r'C:\Program Files\FakeNet-NG-MCP\configs' if identity.get('builtin')
                else r'C:\ProgramData\FakeNet-NG-MCP\configs\custom')
        path = root + '\\' + name
        raw = self.channel.powershell(
            "$ErrorActionPreference='Stop'; $path='" + path + "'; "
            "$before=(Get-FileHash $path -Algorithm SHA256).Hash.ToLower(); "
            "$opened=$false; $errorCode=0; $stream=$null; try { "
            "$stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite); "
            "$opened=$true } catch [IO.IOException] { $errorCode=$_.Exception.HResult -band 65535 } "
            "finally { if($stream){$stream.Dispose()} }; "
            "$after=(Get-FileHash $path -Algorithm SHA256).Hash.ToLower(); "
            "@{path=$path;opened=$opened;error_code=$errorCode;before=$before;after=$after} | ConvertTo-Json -Compress",
            timeout=30)
        observed = json.loads(raw['output'])
        if observed['before'] != identity.get('sha256') or observed['after'] != observed['before']:
            raise RuntimeError('configuration hash changed during lock probe')
        held = not observed['opened'] and observed['error_code'] == 32
        label = ('config_in_use' if held else 'lock_not_proven') if during_run else (
            'released' if observed['opened'] else 'still_locked')
        return label, dict(status=snap, file_probe=observed, raw=raw)

    def run_normal_round(self, index, config_name):
        return self.observe_round(lambda: self._normal_round(index, config_name))

    def _normal_round(self, index, config_name):
        record = {'round': index, 'config': config_name,
                  'started_at': now_iso(), 'vm': self.vm_continuity()}
        record['config_read'] = call(self.base, 'read_config', {'name': config_name}, controller=None)
        if config_name == CUSTOM_INI:
            record['builtin_config_read'] = call(self.base, 'read_config', {'name': DEFAULT_INI}, controller=None)
        before = self.capture_sections()
        version = call(self.base, 'get_status')['state_version']
        loaded = call(self.base, 'load_config',
                      {'name': config_name,
                       'command_id': unique_command('r%d-l' % index),
                       'expected_state_version': version}, timeout=60)
        if loaded.get('error'):
            record['failure'] = 'load: %s' % loaded['error']
            return record
        started = call(self.base, 'start',
                       {'command_id': unique_command('r%d-s' % index),
                        'expected_state_version': loaded['state_version']},
                       timeout=90)
        if started.get('error'):
            record['failure'] = 'start: %s' % started['error']
            self.stop_once()
            return record
        record['load_response'], record['start_response'] = loaded, started
        record['run_id'] = started['run_id']
        record['class'] = 'normal'
        ok, timeline = continuous_probe(self.base, 4)
        record['probe'] = {'all_ok': ok, 'samples': len(timeline)}
        if not ok:
            record['failure'] = 'link probe failed during round'
            record['probe_timeline'] = timeline
            self.stop_once()
            return record
        lock_label, lock_raw = self.config_lock_probe(index, during_run=True)
        record['lock_held_during_run'] = lock_label == 'config_in_use'
        record['lock_held_evidence'] = lock_raw
        stopped = self.stop_once()
        record['stop_state'] = stopped.get('state')
        final = wait_state(self.base,
                           lambda s: s.get('state') in ('stopped', 'failed'),
                           timeout=90)
        record['final_state'] = (final[1] or {}).get('state') if final \
            else None
        if final[1] is None or not final[0]:
            record['failure'] = 'no terminal state'
            return record
        if record['final_state'] != 'stopped':
            record['failure'] = 'final=%s' % record['final_state']
            return record
        release_label, release_raw = self.config_lock_probe(
            index, during_run=False)
        record['lock_released_after_stop'] = release_label == 'released'
        record['lock_released_evidence'] = release_raw
        if not record.get('lock_held_during_run') or not \
                record.get('lock_released_after_stop'):
            record['failure'] = 'config lock lifecycle violated: %s/%s' % (
                record.get('lock_held_during_run'),
                record.get('lock_released_after_stop'))
        diff = self.audit_diff(before)
        record['audit_diff'] = {k: True for k in diff} if diff else {}
        if diff:
            record['failure'] = 'environment drift: %s' % sorted(diff)
            record['audit_diff_detail'] = {
                key: (value if isinstance(value, dict) else str(value))
                for key, value in diff.items()}
        record['ended_at'] = now_iso()
        return record

    # -- one fault round ----------------------------------------------------
    def configure_fault_mode(self, enabled):
        from helpers import configure_fault_service
        result = configure_fault_service(self.channel, enabled, 5 if enabled else 60,
                                         allow_change=not (enabled and any(self.release.glob('fault-*.json'))))
        ready, state = wait_state(self.base, lambda x: x.get('state') == 'stopped', timeout=60)
        if not ready:
            raise RuntimeError('fault mode service not ready: %r' % state)
        self.vm_continuity()
        return result

    def run_fault_round(self, klass, index):
        from helpers import arm_fault_file
        armed = arm_fault_file(self.channel, klass)
        result = self.observe_round(lambda: self._fault_round(klass, index, armed['nonce']))
        result['fault_arm'] = armed
        return result

    def _fault_round(self, klass, index, nonce):
        record = {'class': klass, 'round': index, 'nonce': nonce, 'started_at': now_iso()}
        before = self.capture_sections()
        version = call(self.base, 'get_status')['state_version']
        loaded = call(self.base, 'load_config',
                      {'name': DEFAULT_INI, 'command_id': unique_command('fault-load'),
                       'expected_state_version': version}, timeout=60)
        if loaded.get('error'):
            return dict(record, failure='load rejected', loaded=loaded)
        started = call(self.base, 'start',
                       {'command_id': unique_command('fault-start'),
                        'expected_state_version': loaded['state_version']}, timeout=480)
        record['start_response'] = started
        if started.get('error'):
            return dict(record, failure='start rejected')
        record['run_id'] = started['run_id']
        if started.get('state') == 'healthy':
            stopped = self.stop_once()
            record['stop_response'] = stopped
        _, snap = wait_state(self.base, lambda s: s.get('state') in ('stopped', 'failed'), timeout=480)
        snap = snap or {}
        record['final_state'] = snap.get('state')
        record['last_run_outcome'] = snap.get('last_run_outcome')
        record['final_status'] = snap
        if record['final_state'] != 'stopped' or record['last_run_outcome'] != 'failed':
            record['failure'] = 'fault did not finish as real stopped/last_run_outcome failed'
        record['lock_released_after_stop'] = not snap.get('run_id') and not snap.get('controller')
        # A triggering receipt and real incident manifest must belong to the
        # exact fault nonce. Never substitute a hand-written converged label.
        detail = self.channel.powershell(
            "$ErrorActionPreference='Stop'; $root='C:\\ProgramData\\FakeNet-NG-MCP\\artifacts'; "
            "$receipts=@(Get-ChildItem (Join-Path $root 'runs') -Recurse -Filter fault-triggered.json | ForEach-Object { "
            "$r=Get-Content $_.FullName -Raw | ConvertFrom-Json; "
            "if($r.nonce -eq '" + nonce + "'){@{path=$_.FullName;receipt=$r;run_id=$_.Directory.Name}}}); "
            "if($receipts.Count -ne 1){throw 'fault receipt is not unique'}; "
            "$run=$receipts[0].run_id; $manifests=@(Get-ChildItem (Join-Path $root $run) -Recurse -Filter manifest.json | "
            "ForEach-Object {@{path=$_.FullName;manifest=(Get-Content $_.FullName -Raw | ConvertFrom-Json)}}); "
            "@{receipt=$receipts[0];incidents=$manifests} | ConvertTo-Json -Depth 12 -Compress", timeout=60)
        record['fault_evidence'] = json.loads(detail['output'])
        incidents = record['fault_evidence']['incidents']
        if (record['fault_evidence']['receipt']['receipt'] != {'fault': klass, 'nonce': nonce}
                or not incidents or any(not item['manifest'].get('complete') for item in incidents)):
            record['failure'] = 'fault receipt/incident incomplete'
        from helpers import export_incident_bundle
        import ntpath
        run_id = record['fault_evidence']['receipt']['run_id']
        if run_id != record['run_id']:
            record['failure'] = 'fault receipt belongs to another run'
            return record
        exports = []
        names = set()
        for item in incidents:
            name = ntpath.basename(ntpath.dirname(item['path']))
            if name in names:
                raise RuntimeError('duplicate incident directory')
            names.add(name)
            exported = export_incident_bundle(self.channel, run_id,
                      self.release / (name + '-' + run_id + '.zip'), incident_name=name)
            exports.append(exported)
        record['incident_exports'] = exports
        if (not exports or any(not item['complete'] for item in exports) or
                (klass in ('policy_pause', 'child_hang') and
                 not any('userdump.dmp' in item['verified_members'] for item in exports))):
            record['failure'] = 'verified incident content/dump incomplete'
        diff = self.audit_diff(before)
        record['audit_diff'] = diff
        if diff:
            record['failure'] = 'environment drift'
        record['ended_at'] = now_iso()
        return record

    # -- checkpoints ----------------------------------------------------------
    def round_path(self, prefix, index):
        return self.release / ('%s-%03d.json' % (prefix, index))

    def stop_once(self):
        snapshot = call(self.base, 'get_status')
        if snapshot.get('state') == 'stopped':
            return snapshot
        return call(self.base, 'stop', {'command_id': unique_command('release-stop'),
                    'expected_state_version': snapshot['state_version']}, timeout=1020)

    def record_round(self, path, record, writer):
        raw = (json.dumps(record, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
        with path.open('xb') as stream:
            stream.write(raw)
        writer.evidence.append({'name': path.stem, 'path': str(path),
                                'sha256': hashlib.sha256(raw).hexdigest(), 'size': len(raw)})
        writer.evidence.extend(record.get('capture_evidence', []))
        for exported in record.get('incident_exports', []):
            writer.evidence.append({key: exported[key] for key in ('path', 'size', 'sha256')})

    def saved_sample_issues(self):
        records = []
        for path in sorted(self.release.glob('*-*.json')):
            prefix, _, index = path.stem.rpartition('-')
            if not index.isdigit() or not prefix.startswith(('normal-', 'fault-')):
                continue
            records.append(json.loads(path.read_text(encoding='utf-8')))
        return validate_rounds(records)

    def prior_round(self, path, writer):
        if not path.exists():
            return False
        record = json.loads(path.read_text(encoding='utf-8'))
        issues = validate_round(record, {field: getattr(self.args, field) for field in IDENTITY_FIELDS}) + validate_sample_category(record, path.stem.rsplit('-', 1)[0])
        if issues or self.saved_sample_issues() or record['vm_after'] != self.vm_continuity():
            raise RuntimeError('prior round failed/incomplete or VM drift; preserve it and restart full counting in a new evidence directory')
        raw = path.read_bytes()
        writer.evidence.append({'name': path.stem, 'path': str(path),
                                'sha256': hashlib.sha256(raw).hexdigest(), 'size': len(raw)})
        writer.evidence.extend(record.get('capture_evidence', []))
        for exported in record.get('incident_exports', []):
            writer.evidence.append({key: exported[key] for key in ('path', 'size', 'sha256')})
        return True

    def done_rounds(self, prefix, total):
        done = []
        if self.saved_sample_issues():
            return done
        for index in range(1, total + 1):
            path = self.round_path(prefix, index)
            if path.is_file():
                try:
                    record = json.loads(path.read_text(encoding='utf-8'))
                    if not (validate_round(record, {field: getattr(self.args, field) for field in IDENTITY_FIELDS}) + validate_sample_category(record, prefix)):
                        done.append(index)
                except ValueError:
                    pass
        return done

    def mode_normal(self, writer):
        plans = [('builtin', DEFAULT_INI), ('custom', CUSTOM_INI)]
        if not self.ensure_custom_config():
            writer.blocker = {'reason': 'custom release config unavailable'}
            return EXIT_BLOCKED
        failures = []
        for group, config in plans:
            prefix = 'normal-%s' % group
            for index in range(1, NORMAL_ROUNDS_PER_CONFIG + 1):
                path = self.round_path(prefix, index)
                if self.prior_round(path, writer):
                    continue
                record = self.run_normal_round(index, config)
                category_issues = validate_sample_category(record, prefix)
                if category_issues:
                    record['failure'] = '; '.join(category_issues)
                self.record_round(path, record, writer)
                if record.get('failure'):
                    failures.append({'group': group, 'round': index,
                                     'failure': record['failure']})
                    writer.add_evidence('normal-first-failure', failures[0])
                    return EXIT_FAIL
        summary = {'builtin': len(self.done_rounds(
            'normal-builtin', NORMAL_ROUNDS_PER_CONFIG)),
            'custom': len(self.done_rounds(
                'normal-custom', NORMAL_ROUNDS_PER_CONFIG))}
        (self.release / 'normal-summary.json').write_text(
            json.dumps(summary, ensure_ascii=False, indent=1),
            encoding='utf-8')
        writer.add_evidence('normal-summary', summary)
        return EXIT_PASS if summary['builtin'] == NORMAL_ROUNDS_PER_CONFIG \
            and summary['custom'] == NORMAL_ROUNDS_PER_CONFIG else EXIT_FAIL

    def mode_fault(self, writer):
        writer.add_evidence('fault-mode-enabled', self.configure_fault_mode(True))
        failures = []
        for klass in FAULT_CLASSES:
            prefix = 'fault-%s' % klass
            for index in range(1, FAULT_ROUNDS_PER_CLASS + 1):
                path = self.round_path(prefix, index)
                if self.prior_round(path, writer):
                    continue
                record = self.run_fault_round(klass, index)
                category_issues = validate_sample_category(record, prefix)
                if category_issues:
                    record['failure'] = '; '.join(category_issues)
                self.record_round(path, record, writer)
                if record.get('failure'):
                    failures.append({'class': klass, 'round': index,
                                    'failure': record['failure']})
                    writer.add_evidence('fault-first-failure', failures[0])
                    return EXIT_FAIL
        summary = {klass: len(self.done_rounds(
            'fault-%s' % klass, FAULT_ROUNDS_PER_CLASS))
            for klass in FAULT_CLASSES}
        (self.release / 'fault-summary.json').write_text(
            json.dumps(summary, ensure_ascii=False, indent=1),
            encoding='utf-8')
        writer.add_evidence('fault-summary', summary)
        writer.add_evidence('fault-mode-disabled', self.configure_fault_mode(False))
        return EXIT_PASS if all(
            v == FAULT_ROUNDS_PER_CLASS for v in summary.values()) \
            else EXIT_FAIL

    def mode_final(self, writer):
        checks = {}
        checks['identity'] = self.channel.computer_name() == \
            'DESKTOP-3FI41GR'
        checks['vm'] = self.vm_continuity()
        # CHK-010: the final audit compares against the PRE-START baseline
        # (captured before the run, not after) so any drift the start/stop
        # cycle itself introduces is actually visible.
        before = self.capture_sections()
        version = call(self.base, 'get_status')['state_version']
        loaded = call(self.base, 'load_config',
                      {'name': DEFAULT_INI,
                       'command_id': unique_command('fin-l'),
                       'expected_state_version': version}, timeout=60)
        checks['load_ok'] = loaded.get('error') is None
        started = call(self.base, 'start',
                       {'command_id': unique_command('fin-s'),
                        'expected_state_version':
                            loaded.get('state_version', version)},
                       timeout=90)
        checks['start_ok'] = started.get('error') is None
        healthy, snap = wait_state(
            self.base, lambda s: s.get('state') == 'healthy', timeout=45)
        checks['healthy'] = healthy
        ok, _ = continuous_probe(self.base, 4)
        checks['link_during_run'] = ok
        stopped = self.stop_once()
        checks['stopped'] = stopped.get('state') == 'stopped'
        diff = self.audit_diff(before)
        checks['audit_clean'] = not diff
        os_version = self.channel.powershell(
            '[Environment]::OSVersion.Version.ToString()', timeout=60)
        checks['tested_windows_version'] = os_version['output'].strip()
        writer.add_evidence('final-checks', checks)
        passed = all(v for k, v in checks.items()
                     if k not in ('vm',))
        return EXIT_PASS if passed else EXIT_FAIL

    def mode_summary(self, writer):
        acc_index = {}
        integrity_failures = {}
        allowed_labels = {
            'ACC-001', 'ACC-002', 'ACC-003', 'ACC-005',
            'ACC-006', 'ACC-007', 'ACC-008', 'ACC-009', 'ACC-009-PRE',
            'ACC-010', 'ACC-011', 'ACC-012', 'ACC-013', 'ACC-014',
            'ACC-015', 'ACC-016', 'ACC-017', 'ACC-018', 'ACC-019',
            'FAULT-POINTS', 'P01-ENTRY',
            # ACC-004 runs as six independent scenario invocations (the
            # serial six-scenario form timed out on restart accumulation).
            'ACC-004-S1', 'ACC-004-S2', 'ACC-004-S3',
            'ACC-004-S4', 'ACC-004-S5', 'ACC-004-S6',
            # declared aggregate label (summary mode's own record; not an
            # ACC pass claim and never counted as one).
            'ACC-017-SUMMARY'}
        allowed_labels.update(CONTROL_CASE_LABELS)
        for path in sorted(self.root.glob('*/result.json')):
            try:
                result = json.loads(path.read_text(encoding='utf-8'))
            except ValueError:
                continue
            label = result.get('acc_id')
            if label == 'ACC-017-SUMMARY':
                continue
            if label not in allowed_labels:
                integrity_failures[str(path)] = 'undeclared label %r' % label
                continue
            issues = validate_result(result, {
                field: getattr(self.args, field) for field in IDENTITY_FIELDS}, self.root)
            if label in acc_index:
                issues.append('duplicate ACC label')
            if issues:
                integrity_failures[str(path)] = issues
            acc_index[label] = {
                'status': result.get('status'),
                'candidate_id': result.get('candidate_id')}
        expected = ['ACC-001', 'ACC-002', 'ACC-003', 'ACC-005',
                    'ACC-009-PRE', 'ACC-010', 'ACC-011',
                    'ACC-004-S1', 'ACC-004-S2', 'ACC-004-S3',
                    'ACC-004-S4', 'ACC-004-S5', 'ACC-004-S6',
                    'ACC-006', 'ACC-007', 'ACC-008', 'ACC-009',
                    'ACC-014', 'ACC-015', 'ACC-018', 'ACC-019',
                    'FAULT-POINTS', 'ACC-012', 'ACC-013', 'ACC-016',
                    'ACC-017', 'P01-ENTRY']
        expected.extend(CONTROL_CASE_LABELS)
        missing = [acc for acc in expected if acc not in acc_index]
        identity = {field: getattr(self.args, field) for field in IDENTITY_FIELDS}
        groups = [('normal-builtin', 50), ('normal-custom', 50)] + [
            ('fault-' + klass, 10) for klass in FAULT_CLASSES]
        samples = []
        required = {}
        for prefix, count in groups:
            required[prefix] = count
            for index in range(1, count + 1):
                path = self.round_path(prefix, index)
                try:
                    record = json.loads(path.read_text(encoding='utf-8'))
                except (OSError, ValueError, TypeError) as exc:
                    integrity_failures[str(path)] = [repr(exc)]
                    continue
                issues = validate_round(record, identity) + validate_sample_category(record, prefix)
                if issues:
                    integrity_failures[str(path)] = issues
                samples.append(dict(record, **{'class': prefix}))
        # Cross-round: unique runs with the required category counts, so a
        # repeated sample or a missing class cannot pass as 100+50.
        cross_round = validate_rounds(samples, required)
        if cross_round:
            integrity_failures['cross-round'] = cross_round
        wrong_candidate = {acc: row for acc, row in acc_index.items()
                          if row['candidate_id'] != self.cid}
        failures = {acc: row['status'] for acc, row in acc_index.items()
                    if row['status'] != 'pass'}
        os_version = None
        os_probe = self.root / 'ACC-017' / 'final-checks.json'
        if os_probe.is_file():
            try:
                os_version = json.loads(
                    os_probe.read_text(encoding='utf-8')).get(
                        'tested_windows_version')
            except ValueError:
                os_version = None
        import re
        if not isinstance(os_version, str) or not re.fullmatch(r'10\.0\.\d+\.\d+', os_version):
            integrity_failures['windows-version'] = ['actual Windows 10 version missing or invalid']
        else:
            try:
                final_result = json.loads((self.root / 'ACC-017' / 'result.json').read_text(encoding='utf-8'))
            except (OSError, ValueError):
                final_result = {}
            if not any(Path(item.get('path', '')).resolve() == os_probe.resolve()
                       for item in final_result.get('evidence', [])):
                integrity_failures['windows-version'] = ['OS probe not bound to final result evidence']
        manifest = {
            'schema': 'fakenet.mcp-release-manifest.v1',
            'candidate_id': self.cid,
            'source_commit': self.args.source_commit,
            'package_sha256': self.args.package_sha256,
            'os_version': os_version,
            'record_integrity_failures': integrity_failures,
            'acc_index': acc_index,
            'missing': missing,
            'wrong_candidate': list(wrong_candidate),
            'failures': failures,
        }
        (self.release / 'release-acc-index.json').write_text(
            json.dumps(manifest, ensure_ascii=False, indent=1),
            encoding='utf-8')
        dist = REPO_ROOT / 'dist' / ('%s-release' % self.cid)
        dist.mkdir(parents=True, exist_ok=True)
        (dist / 'release-manifest.json').write_text(
            json.dumps(manifest, ensure_ascii=False, indent=1),
            encoding='utf-8')
        writer.add_evidence('release-index', {
            'missing': missing, 'failures': list(failures),
            'wrong_candidate': list(wrong_candidate)})
        return EXIT_PASS if not missing and not failures \
            and not wrong_candidate and not integrity_failures \
            else EXIT_FAIL


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', required=True,
                        choices=['normal', 'fault', 'final', 'summary'])
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--package', required=True)
    parser.add_argument('--package-sha256', required=True)
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--requirements-blob', required=True)
    parser.add_argument('--master-plan-blob', required=True)
    parser.add_argument('--vm-identity', required=True)
    parser.add_argument('--config-identity', required=True)
    parser.add_argument('--candidate-id', required=True)
    parser.add_argument('--target-base-url',
                        default='http://192.168.204.149:28788')
    parser.add_argument('--win10vm-mcp',
                        default='http://192.168.204.149:28787/mcp')
    parser.add_argument('--output-root',
                        default=str(REPO_ROOT / 'Logs' / 'fakenetng-mcp'))
    args = parser.parse_args()

    started_at = now_iso()
    acc_for_mode = {'normal': 'ACC-012', 'fault': 'ACC-013',
                    'final': 'ACC-017', 'summary': 'ACC-017-SUMMARY'}
    out_dir = Path(args.output_root) / args.candidate_id / acc_for_mode[
        args.mode]
    writer = EvidenceWriter(out_dir, started_at)
    gate = ReleaseGate(args)
    exit_code = EXIT_TOOL_ERROR
    try:
        probed_identity = gate.channel.computer_name()
        if probed_identity != 'DESKTOP-3FI41GR':
            writer.blocker = {'reason': 'unexpected VM'}
            exit_code = EXIT_BLOCKED
        elif args.mode == 'normal':
            exit_code = gate.mode_normal(writer)
        elif args.mode == 'fault':
            exit_code = gate.mode_fault(writer)
        elif args.mode == 'final':
            exit_code = gate.mode_final(writer)
        elif args.mode == 'summary':
            exit_code = gate.mode_summary(writer)
    except Exception as exc:  # noqa: BLE001
        import traceback; traceback.print_exc()
        writer.blocker = {'reason': 'tool error: %r' % exc}
        exit_code = EXIT_TOOL_ERROR

    status_word = {EXIT_PASS: 'pass', EXIT_FAIL: 'fail',
                   EXIT_BLOCKED: 'blocked',
                   EXIT_TOOL_ERROR: 'tool-error'}[exit_code]
    writer.write_result(
        acc_id=acc_for_mode[args.mode], p_id='P05',
        candidate_id=args.candidate_id,
        source_commit=args.source_commit,
        package_sha256=args.package_sha256,
        requirements_blob=args.requirements_blob,
        master_plan_blob=args.master_plan_blob,
        environment_identity='%s@%s | config=%s' % (
            args.vm_identity, probed_identity, args.config_identity),
        status=status_word)
    print('%s: %s' % (args.mode, status_word))
    return exit_code


if __name__ == '__main__':
    sys.exit(main())
