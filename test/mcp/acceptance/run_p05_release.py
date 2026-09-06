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
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from helpers import (EXIT_BLOCKED, EXIT_FAIL, EXIT_PASS,  # noqa: E402
                     EXIT_TOOL_ERROR, EvidenceWriter, Win10VmChannel)
from run_p02_acc import VALID_INI, call, sha_of, status  # noqa: E402
from run_p03_acc import continuous_probe, stop_run, unique_command, wait_state  # noqa: E402
sys.path.insert(0, str(REPO_ROOT))
from fakenet.mcp.faultinject import FAULTS  # noqa: E402

DEFAULT_INI = 'default.ini'
CUSTOM_INI = 'release-custom.ini'
CUSTOM_BODY_DELTA = ('DumpPacketsFilePrefix = release-custom')

FAULT_CLASSES = ('policy_pause', 'listener_stop', 'diverter_stop',
                'child_hang', 'cleanup_error')
NORMAL_ROUNDS_PER_CONFIG = 50
FAULT_ROUNDS_PER_CLASS = 10


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
        # Every capture ends with a success marker so a native tool's
        # non-zero exit (e.g. tasklist /m with no matching module) cannot
        # fail the whole probe.
        out = {}
        out['routes'] = self.channel.powershell(
            'route print -4 | Out-String; "S"', timeout=60)['output']
        out['dns_servers'] = self.channel.powershell(
            'Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object '
            'InterfaceAlias,ServerAddresses | ConvertTo-Json -Compass 2>$null'
            '; "S"', timeout=60)['output'].replace(' -Compass ', ' -Compress ')
        out['windivert_processes'] = self.channel.powershell(
            'tasklist /m WinDivert*.sys 2>$null | Out-String; "S"',
            timeout=60)['output']
        out['listen_ports'] = self.channel.powershell(
            'netstat -ano | Out-String; "S"', timeout=60)['output']
        out['services'] = self.channel.powershell(
            'Get-Service dnscache,mpssvc | Select-Object Name,Status | '
            'ConvertTo-Json -Compress; "S"', timeout=60)['output']
        return out

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
            '$os = Get-CimInstance Win32_OperatingSystem; '
            '"boot={0} now={1}" -f $os.LastBootUpTime.ToString("s"), '
            '(Get-Date).ToString("s")', timeout=60)
        return result['output'].strip()

    def ensure_custom_config(self):
        builtin = call(self.base, 'read_config', {'name': DEFAULT_INI},
                       controller=None)
        content = builtin.get('content') or ''
        # semantic delta: no webroot dependency + dedicated prefix
        lines = []
        for line in content.splitlines():
            if 'DumpHTTPWebRoot' in line:
                line = 'DumpHTTPWebRoot: '
            if 'DumpPacketsFilePrefix' in line:
                line = CUSTOM_BODY_DELTA
            lines.append(line)
        body = '\n'.join(lines) + '\n'
        version = call(self.base, 'get_status')['state_version']
        created = call(self.base, 'create_config',
                       {'name': CUSTOM_INI, 'content': body,
                        'command_id': unique_command('rel-cfg'),
                        'expected_state_version': version}, timeout=60)
        return created.get('error') is None or \
            (created.get('error') or {}).get('code') == 'name_conflict'

    # -- one normal round --------------------------------------------------

    def config_lock_probe(self, index, during_run):
        """CHK-010: the activity lock tracks the run (run_id present =
        lock held; run_id cleared = lock released). Returns (label, raw)
        so a violated expectation carries its own evidence."""
        snap = call(self.base, 'get_status', controller=None)
        has_run = bool(snap.get('run_id'))
        if during_run:
            return ('config_in_use' if has_run else 'no_run_active'), snap
        return ('released' if not has_run else 'still_locked'), snap

    def run_normal_round(self, index, config_name):
        record = {'round': index, 'config': config_name,
                  'started_at': now_iso(), 'vm': self.vm_continuity()}
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
            stop_run(self.base)
            return record
        ok, timeline = continuous_probe(self.base, 4)
        record['probe'] = {'all_ok': ok, 'samples': len(timeline)}
        if not ok:
            record['failure'] = 'link probe failed during round'
            record['probe_timeline'] = timeline
            stop_run(self.base, attempts=2)
            return record
        lock_label, lock_raw = self.config_lock_probe(index, during_run=True)
        record['lock_held_during_run'] = lock_label == 'config_in_use'
        if not record['lock_held_during_run']:
            record['lock_probe_raw'] = lock_raw
        stopped = stop_run(self.base, attempts=4)
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
        if not record['lock_released_after_stop']:
            record['lock_probe_raw'] = release_raw
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
    def run_fault_round(self, klass, index):
        record = {'class': klass, 'round': index,
                  'started_at': now_iso(), 'vm': self.vm_continuity()}
        self.channel.powershell(
            "[Environment]::SetEnvironmentVariable("
            "'FAKENETNG_MCP_FAULT_INJECTION', '1', 'Machine'); "
            "[Environment]::SetEnvironmentVariable("
            "'FAKENETNG_MCP_ARMED_FAULT', '%s', 'Machine')" % klass,
            timeout=60)
        try:
            self.channel.powershell(
                'sc.exe stop fakenetng-mcp 2>&1 | Out-Null; Start-Sleep 3; '
                'sc.exe start fakenetng-mcp | Out-Null; "RESTARTED"',
                timeout=180)
            deadline = time.time() + 60
            while time.time() < deadline:
                try:
                    if call(self.base, 'get_status',
                            controller=None).get('state'):
                        break
                except Exception:  # noqa: BLE001
                    time.sleep(2)
            before = self.capture_sections()
            version = call(self.base, 'get_status')['state_version']
            loaded = call(self.base, 'load_config',
                          {'name': DEFAULT_INI,
                           'command_id': unique_command('f%d-l' % index),
                           'expected_state_version': version}, timeout=60)
            started = call(self.base, 'start',
                          {'command_id': unique_command('f%d-s' % index),
                           'expected_state_version':
                               loaded.get('state_version', version)},
                           timeout=90)
            if started.get('error'):
                record['failure'] = 'start: %s' % started['error']
                return record
            ok, timeline = continuous_probe(self.base, 4)
            record['probe'] = {'all_ok': ok, 'samples': len(timeline)}
            stopped = stop_run(self.base, attempts=4)
            record['stop_state'] = stopped.get('state')
            record['stop_error'] = (stopped.get('error') or {})
            final = wait_state(self.base,
                               lambda s: s.get('state') in
                               ('stopped', 'failed'), timeout=120)
            snap = final[1] or {}
            record['final_state'] = snap.get('state')
            record['failure_reason'] = snap.get('failure_reason')
            converged = record['final_state'] == 'stopped' or (
                record['final_state'] == 'failed' and
                record['failure_reason'] == 'stop grace exceeded')
            if not converged:
                record['failure'] = 'final=%s reason=%s' % (
                    record['final_state'], record['failure_reason'])
                return record
            fault_label, fault_raw = self.config_lock_probe(
                index + 9000, during_run=False)
            record['lock_released_after_stop'] = fault_label == 'released'
            if not record['lock_released_after_stop']:
                record['lock_probe_raw'] = fault_raw
            if not record.get('lock_released_after_stop'):
                record['failure'] = 'config lock leaked after fault stop'
            diff = self.audit_diff(before)
            record['audit_diff'] = sorted(diff) if diff else []
            if diff:
                record['failure'] = 'environment drift: %s' % sorted(diff)
            record['ended_at'] = now_iso()
            return record
        finally:
            self.channel.powershell(
                "[Environment]::SetEnvironmentVariable("
                "'FAKENETNG_MCP_ARMED_FAULT', $null, 'Machine')",
                timeout=60)

    # -- checkpoints ----------------------------------------------------------
    def round_path(self, prefix, index):
        return self.release / ('%s-%03d.json' % (prefix, index))

    def done_rounds(self, prefix, total):
        done = []
        for index in range(1, total + 1):
            path = self.round_path(prefix, index)
            if path.is_file():
                try:
                    record = json.loads(path.read_text(encoding='utf-8'))
                    if not record.get('failure'):
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
                if path.is_file() and not json.loads(
                        path.read_text(encoding='utf-8')).get('failure'):
                    continue
                record = self.run_normal_round(index, config)
                path.write_text(json.dumps(record, ensure_ascii=False,
                                          indent=1), encoding='utf-8')
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
        failures = []
        for klass in FAULT_CLASSES:
            prefix = 'fault-%s' % klass
            for index in range(1, FAULT_ROUNDS_PER_CLASS + 1):
                path = self.round_path(prefix, index)
                if path.is_file():
                    record = json.loads(path.read_text(encoding='utf-8'))
                    if not record.get('failure'):
                        continue
                record = self.run_fault_round(klass, index)
                path.write_text(json.dumps(record, ensure_ascii=False,
                                          indent=1), encoding='utf-8')
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
        stopped = stop_run(self.base)
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
        for path in sorted(self.root.glob('*/result.json')):
            try:
                result = json.loads(path.read_text(encoding='utf-8'))
            except ValueError:
                continue
            label = result.get('acc_id')
            if label not in allowed_labels:
                integrity_failures[str(path)] = 'undeclared label %r' % label
                continue
            # CHK-011: identity must be COMPLETE per record — a null
            # package_sha256 or a foreign candidate string must not
            # aggregate into a green manifest.
            for field in ('package_sha256', 'source_commit',
                          'candidate_id'):
                value = result.get(field)
                if not value or not isinstance(value, str):
                    integrity_failures[str(path)] = \
                        '%s missing/null in %s' % (field, label)
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
        missing = [acc for acc in expected if acc not in acc_index]
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
