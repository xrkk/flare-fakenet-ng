#!/usr/bin/env python3
# Copyright 2026 Google LLC
"""P04 ACC runner — master-plan §9.1 contract for ACC-014/015/018/019 plus
the ACC-012/013 fault-point stability proof (one trigger each; the formal
10x counts belong to P05). Exit codes 0/1/2/3+."""

import argparse
import datetime
import hashlib
import json
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from helpers import (EXIT_BLOCKED, EXIT_FAIL, EXIT_PASS,  # noqa: E402
                     EXIT_TOOL_ERROR, EvidenceWriter, StepError, Win10VmChannel)
from run_p02_acc import CONTROLLER_A, VALID_INI, call, sha_of, status, envelope  # noqa: E402
from pathlib import PureWindowsPath  # noqa: E402
from run_p03_acc import continuous_probe, load_and_start, stop_run, unique_command  # noqa: E402


def run_fault_point_proof(base, channel, writer, args):
    """Exercise the five actual hooks with attributed receipts and raw audits."""
    from types import SimpleNamespace
    from run_p05_release import ReleaseGate, FAULT_CLASSES
    from evidence_integrity import IDENTITY_FIELDS, validate_round
    settings = {field: getattr(args, field) for field in IDENTITY_FIELDS}
    gate = ReleaseGate(SimpleNamespace(**settings, target_base_url=base,
                       win10vm_mcp=args.win10vm_mcp,
                       output_root=str(writer.out_dir / 'fault-rounds')))
    gate.channel = channel
    writer.action('fault-points', 'five actual fixed-file fault hooks; no log fabrication')
    writer.add_evidence('fault-mode', gate.configure_fault_mode(True))
    writer.fault_records = []
    for klass in FAULT_CLASSES:
        record = gate.run_fault_round(klass, 1)
        writer.fault_records.append(record)
        writer.add_evidence('fault-' + klass, record)
        writer.evidence.extend(record.get('capture_evidence', []))
        for exported in record.get('incident_exports', []):
            writer.evidence.append({key: exported[key] for key in ('path', 'size', 'sha256')})
        if validate_round(record, settings):
            return EXIT_FAIL
    writer.add_evidence('fault-mode-restored', gate.configure_fault_mode(False))
    return EXIT_PASS


def collect_acc014_incident_integrity(base, channel, writer, args):
    """Collect and verify the original mechanical incident assertions only."""
    from helpers import export_incident_bundle
    from evidence_integrity import IDENTITY_FIELDS, validate_round
    from run_p05_release import FAULT_CLASSES
    identity = {field: getattr(args, field) for field in IDENTITY_FIELDS}
    if args.fault_record:
        records = [json.loads(Path(path).read_text(encoding='utf-8')) for path in args.fault_record]
    else:
        result = run_fault_point_proof(base, channel, writer, args)
        if result != EXIT_PASS:
            return result, {}, []
        records = writer.fault_records
    if set(FAULT_CLASSES) - {record.get('class') for record in records}:
        writer.blocker = {'reason': 'actual five-class incident coverage missing'}
        return EXIT_BLOCKED, {}, records
    bundles = {}
    for record in records:
        expected_diagnostic = record.get('expected_diagnostic')
        if expected_diagnostic is None:
            round_issues = validate_round(record, identity)
        else:
            round_issues = validate_round(record, identity, expected_diagnostic=expected_diagnostic)
        if round_issues:
            writer.add_evidence('rejected-fault-record', record)
            return EXIT_FAIL, {}, records
        run_id = record['fault_evidence']['receipt']['run_id']
        run_bundles = {}
        for exported in record['incident_exports']:
            name = exported['incident_name']
            if expected_diagnostic is None:
                bundle = export_incident_bundle(channel, run_id,
                         writer.out_dir / (name + '-' + run_id + '.zip'), incident_name=name)
            else:
                bundle = export_incident_bundle(channel, run_id,
                         writer.out_dir / (name + '-' + run_id + '.zip'), incident_name=name,
                         fault_round=True, expected_diagnostic=expected_diagnostic)
            writer.add_evidence(name + '-verified-' + run_id, bundle)
            writer.evidence.append({key: bundle[key] for key in ('path', 'sha256', 'size')})
            if expected_diagnostic is None:
                if not bundle['complete']:
                    return EXIT_FAIL, {}, records
            else:
                from evidence_integrity import assess_no_stack_export
                try:
                    assess_no_stack_export(bundle, run_id, expected_diagnostic)
                except (KeyError, TypeError, ValueError, RuntimeError, OSError):
                    return EXIT_FAIL, {}, records
            run_bundles[name] = bundle
        if record['class'] in ('policy_pause', 'child_hang', 'ipc_permanent_timeout',
                               'stacks_unavailable', 'native_crash', 'unknown_cause') and not any('userdump.dmp' in bundle['verified_members'] for bundle in run_bundles.values()):
            return EXIT_FAIL, {}, records
        bundles[run_id] = run_bundles
    return EXIT_PASS, bundles, records


def run_incident_integrity(base, channel, writer, args):
    """Mechanical slice; never grants package-only root-cause localization."""
    code, bundles, records = collect_acc014_incident_integrity(base, channel, writer, args)
    writer.add_evidence('incident-integrity-scope', {
        'capability': 'incident-integrity', 'complete_acc014': False,
        'run_ids': sorted(bundles),
        'fault_classes': sorted(record.get('class', '') for record in records),
        'root_cause_localization': 'not_evaluated',
    })
    return code


def run_acc014(base, channel, writer, args):
    """Preserve full package-only localization and terminal coverage contract."""
    from evidence_integrity import IDENTITY_FIELDS
    from run_p05_release import FAULT_CLASSES
    identity = {field: getattr(args, field) for field in IDENTITY_FIELDS}
    result, bundles, records = collect_acc014_incident_integrity(base, channel, writer, args)
    if result != EXIT_PASS:
        return result
    # A developer must actually inspect these packages. Presence of a stack
    # or a fabricated log line is never a localization conclusion.
    if not args.localization_record:
        writer.blocker = {'reason': 'package-only developer localization record required',
                          'run_ids': sorted(bundles)}
        return EXIT_BLOCKED
    localization = json.loads(Path(args.localization_record).read_text(encoding='utf-8'))
    if any(localization.get(field) != identity[field] for field in IDENTITY_FIELDS):
        return EXIT_FAIL
    import zipfile
    localized = set()
    for item in localization.get('incidents', []):
        run_id = item.get('run_id')
        if run_id not in bundles or not item.get('component') or not item.get('failure_chain') or not item.get('references'):
            return EXIT_FAIL
        for reference in item['references']:
            name = reference.get('incident_name')
            if name is None and len(bundles[run_id]) == 1:
                name = next(iter(bundles[run_id]))
            if name not in bundles[run_id]:
                return EXIT_FAIL
            with zipfile.ZipFile(bundles[run_id][name]['path']) as archive:
                quote = reference.get('quote')
                if not quote or quote not in archive.read(reference['member']).decode('utf-8', 'replace'):
                    return EXIT_FAIL
        localized.add(run_id)
    writer.add_evidence('package-only-localization', localization)
    # The required terminal IPC/native/no-stack matrix is not supplied by
    # the five-class stability proof alone. Preserve an explicit coverage
    # block until those real records accompany the packages.
    required = set(FAULT_CLASSES) | {'ipc_permanent_timeout', 'ipc_eof', 'ipc_wrong_run',
                                   'ipc_repeat', 'ipc_reverse', 'stacks_unavailable',
                                   'native_crash', 'unknown_cause'}
    missing = required - {record.get('class') for record in records}
    if missing:
        writer.blocker = {'reason': 'terminal failure/dump matrix incomplete', 'missing_cases': sorted(missing)}
        return EXIT_BLOCKED
    return EXIT_PASS if localized == set(bundles) else EXIT_FAIL


def _wait_terminal(base, timeout=90):
    from run_p03_acc import wait_state
    return wait_state(base, lambda s: s.get('state') in
                      ('failed', 'degraded', 'stopped'), timeout=timeout)


def run_acc015(base, channel, writer, allowed_client='192.168.204.149',
               programdata_root='C:/ProgramData/FakeNet-NG-MCP'):
    """Export actual incidents and a PCAP belonging to the same run."""
    from pathlib import PureWindowsPath
    import uuid
    from helpers import export_run_incidents
    from artifact_transfer import receive_artifact
    writer.action('acc015', 'metadata-only product API; actual incident and PCAP export')
    listing = call(base, 'list_artifacts', controller=None)
    writer.add_evidence('acc015-artifact-listing', listing)
    items = listing.get('artifacts') or []
    if not items or listing.get('error') or any(set(item) != {'path', 'type', 'size', 'complete', 'sha256'} for item in items):
        writer.blocker = {'reason': 'actual metadata-only artifact listing missing or invalid'}
        return EXIT_BLOCKED
    root = PureWindowsPath(programdata_root) / 'artifacts'
    incident_runs, pcaps = set(), []
    for item in items:
        path = PureWindowsPath(item['path'])
        if not path.is_relative_to(root) or '..' in path.parts:
            return EXIT_FAIL
        parts = path.relative_to(root).parts
        try:
            run_id = str(uuid.UUID(parts[1] if parts[0] == 'runs' else parts[0]))
        except (ValueError, IndexError):
            continue
        if len(parts) == 3 and parts[0] == run_id and parts[1].startswith('incident') and parts[-1] == 'manifest.json':
            incident_runs.add(run_id)
        if path.suffix.lower() == '.pcap' and item['complete'] and item['size'] > 24:
            pcaps.append((run_id, item))
    eligible = [(run_id, item) for run_id, item in pcaps if run_id in incident_runs]
    if not eligible:
        writer.blocker = {'reason': 'same-run actual incident and completed PCAP required'}
        return EXIT_BLOCKED
    run_id, artifact = sorted(eligible, key=lambda pair: pair[1]['path'])[0]
    bundles = export_run_incidents(channel, run_id, writer.out_dir)
    writer.add_evidence('acc015-actual-incidents', bundles)
    writer.evidence.extend({k: bundle[k] for k in ('path', 'size', 'sha256')} for bundle in bundles)
    exported = receive_artifact(channel, artifact,
                             writer.out_dir / ('runtime-' + run_id + '.pcap'),
                             allowed_client=allowed_client)
    writer.add_evidence('acc015-real-band-transfer', exported)
    writer.evidence.append({k: exported[k] for k in ('path', 'size', 'sha256')})
    # This negative check must receive an explicit unknown-tool response;
    # an unrelated HTTP error or unreachable service is not proof.
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                       'params': {'name': 'download_artifact', 'arguments': {'path': artifact['path']},
                                  '_meta': envelope()}}).encode()
    request = urllib.request.Request(base + '/mcp', data=body, method='POST', headers={
        'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream',
        'MCP-Protocol-Version': '2026-07-28', 'Mcp-Method': 'tools/call', 'Mcp-Name': 'download_artifact'})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            raw = response.read().decode('utf-8', 'replace')
            code = response.status
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode('utf-8', 'replace')
        code = exc.code
    writer.add_evidence('acc015-no-content-tool-response', {'http_status': code, 'body': raw})
    checks = {'actual_same_run_exported': bool(bundles),
              'pcap_dual_sha_match': exported['sha256'].lower() == artifact['sha256'].lower(),
              'receiver_closed': (exported['receiver']['socket_fileno'] == -1 and
                                  exported['receiver']['thread_stopped'] and
                                  not exported['receiver']['kernel_listeners'] and
                                  exported['closure']['output'].strip() in ('CLOSED', 'TIMEOUT')),
              'no_download_tool': 'unknown tool' in raw.lower()}
    writer.add_evidence('acc015-checks', checks)
    return EXIT_PASS if all(checks.values()) else EXIT_FAIL


def run_acc018(base, channel, writer, args=None):
    """Mechanical defect fix-retest chain (contract: 复现包、修复diff/源
    commit、新包SHA、快照和重测证据; aggregator must FAIL on any missing or
    identity-mismatched link)."""
    writer.action('acc018', 'defect fix-retest loop, mechanically bound')
    import subprocess

    repo = Path(__file__).resolve().parents[3]
    logs_root = repo / 'Logs' / 'fakenetng-mcp'

    # The gate-era defect chain: every entry names the reproducing candidate
    # (evidence directory), the fix commit, the successor package that
    # carried the fix, and the retest ACCs on the final candidate.
    defects = [
        ('CHK3 lifecycle race (ghost runs / leaked sockets / ACC-010 fail)',
         'mcp-cb32303e1-91355a36cacb', 'd8d1ca8',
         ['ACC-009-PRE', 'ACC-010', 'ACC-016']),
        ('HTTP bind getfqdn reverse-DNS stall under active divert',
         'mcp-cd8d1ca83-633d697d3829', 'eeab273', ['ACC-004', 'ACC-016']),
        ('Windows socketpair loopback handshake swallowed by divert',
         'mcp-ceeab2733-01200e6acc61', '069fdd0', ['ACC-004', 'ACC-009', 'ACC-016']),
        ('never-served shutdown deadlock + SSL wrapper GC cleanup race',
         'mcp-c069fdd04-3d0c5b75e95a', '2b04465',
         ['ACC-004', 'ACC-009', 'ACC-016']),
        ('grace-exceeded bounded stop missed listener socket sweep',
         'mcp-c2b04465c-4025246820d4', '03cc4d3',
         ['ACC-013', 'ACC-016']),
        # CHK-049: the r52 -> r58 gate-era chain, mechanically bound.
        ('rundll32 comsvcs self-dump left service threads suspended',
         'mcp-cc9cdea21-034f71f9916d', '97f8346',
         ['ACC-004-S3', 'ACC-014']),
        ('coordinator/supervisor ABBA lock inversion deadlocked the '
         'control link against the stop path',
         'mcp-c97f83468-176c37190d65', '038bf76',
         ['ACC-004-S3', 'ACC-006', 'ACC-011']),
        ('dynamic-port transient LISTENING rows failed stop audits',
         'mcp-c038bf76b-b8c4e6413382', '628cdee',
         ['ACC-012', 'ACC-013']),
        ('route metric auto-tuning flapped audits (adapter cycles)',
         'mcp-c628cdee7-8f13f2d6d6e8', 'cdb377b',
         ['ACC-012', 'ACC-013']),
        ('run-artifact registration re-copied every accumulated output',
         'mcp-c177fee91-aa8eab44f1d9', '177fee9',
         ['ACC-012', 'ACC-015', 'ACC-016']),
    ]
    final_candidate = None
    if (repo / 'dist').is_dir():
        final_candidate = getattr(args, 'candidate_id', None) if args else None

    rows = []
    checks = {'chain_complete': True}
    for name, repro_cand, fix_commit, retests in defects:
        row = {'defect': name, 'repro_candidate': repro_cand,
               'fix_commit': fix_commit, 'retests': retests}
        # fix commit exists in history
        probe = subprocess.run(
            ['git', 'cat-file', '-t', fix_commit], cwd=str(repo),
            capture_output=True, text=True)
        row['fix_commit_exists'] = probe.stdout.strip() == 'commit'
        # reproducing evidence directory exists with ACC results
        repro_dir = logs_root / repro_cand
        row['repro_evidence_dir'] = repro_dir.is_dir()
        # retest results exist on the final candidate and PASS
        row['retest_results'] = {}
        for acc in retests:
            # ACC-004 runs as six independent scenario invocations on
            # split candidates; the retest link is satisfied by all six
            # sub-results passing (legacy single record on pre-split
            # candidates also satisfies it).
            labels = ['ACC-004-S%d' % n for n in range(1, 7)] if \
                acc == 'ACC-004' else [acc]
            statuses = []
            for label in labels:
                path = logs_root / (final_candidate or '~none~') / label / \
                    'result.json'
                if path.is_file():
                    try:
                        result = json.loads(path.read_text(encoding='utf-8'))
                        statuses.append(result.get('status'))
                    except ValueError:
                        statuses.append('unreadable')
                else:
                    statuses.append('missing')
            row['retest_results'][acc] = 'pass' if all(
                value == 'pass' for value in statuses) else next(
                value for value in statuses if value != 'pass')
        link_ok = (row['fix_commit_exists'] and row['repro_evidence_dir']
                   and all(value == 'pass'
                           for value in row['retest_results'].values()))
        if not link_ok:
            checks['chain_complete'] = False
        rows.append(row)
    writer.add_evidence('acc018-defect-closure-table', rows)
    checks['final_candidate_defined'] = bool(final_candidate)
    checks['all_links_verified'] = checks['chain_complete'] and \
        final_candidate
    return EXIT_PASS if all(checks.values()) else EXIT_FAIL


def run_acc019(base, channel, writer, args=None):
    """Current-instance CLI stop, upgrade pre-stop, and online audit failure."""
    from controlled_exit_case import run
    return run(base, channel, writer, args)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--acc', required=True,
                        choices=['ACC-014', 'ACC-015', 'ACC-018', 'ACC-019',
                                 'FAULT-POINTS'])
    parser.add_argument('--fault-record', action='append', default=[])
    parser.add_argument('--localization-record', default='')
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

    started_at = datetime.datetime.now(
        datetime.timezone.utc).isoformat()
    out_dir = Path(args.output_root) / args.candidate_id / args.acc
    writer = EvidenceWriter(out_dir, started_at)
    channel = Win10VmChannel(args.win10vm_mcp)
    base = args.target_base_url
    exit_code = EXIT_TOOL_ERROR
    try:
        identity = channel.computer_name()
        # A previously blocked scenario may leave the Windows service
        # itself stopped (endpoint refused). CHK-019 family: bring it back
        # before any hygiene/state probing.
        try:
            status(base)
        except Exception:  # noqa: BLE001
            channel.powershell(
                'sc.exe start fakenetng-mcp 2>&1 | Out-Null; "SVC_START"',
                timeout=120)
            from run_p03_acc import wait_state
            wait_state(base, lambda s: s.get('state') is not None,
                       timeout=120)
        try:
            snap = status(base)
            if snap.get('run_id') or snap.get('state') not in ('stopped',):
                stop_run(base)
        except Exception:  # noqa: BLE001
            pass
        if 'DESKTOP-3FI41GR' not in identity:
            writer.blocker = {'reason': 'unexpected VM: %s' % identity}
            exit_code = EXIT_BLOCKED
        elif args.acc == 'ACC-014':
            exit_code = run_acc014(base, channel, writer, args)
        elif args.acc == 'ACC-015':
            guest = args.win10vm_mcp.replace('http://', '').rsplit(':', 1)[0]
            exit_code = run_acc015(base, channel, writer, allowed_client=guest)
        elif args.acc == 'ACC-018':
            exit_code = run_acc018(base, channel, writer, args)
        elif args.acc == 'ACC-019':
            exit_code = run_acc019(base, channel, writer, args)
        elif args.acc == 'FAULT-POINTS':
            exit_code = run_fault_point_proof(base, channel, writer, args)
    except StepError as exc:
        writer.blocker = {'reason': str(exc)}
        exit_code = EXIT_BLOCKED
    except Exception as exc:  # noqa: BLE001
        writer.blocker = {'reason': 'tool error: %r' % exc}
        exit_code = EXIT_TOOL_ERROR

    status_word = {EXIT_PASS: 'pass', EXIT_FAIL: 'fail',
                   EXIT_BLOCKED: 'blocked',
                   EXIT_TOOL_ERROR: 'tool-error'}[exit_code]
    writer.write_result(
        acc_id=args.acc, p_id='P04', candidate_id=args.candidate_id,
        source_commit=args.source_commit,
        package_sha256=args.package_sha256,
        requirements_blob=args.requirements_blob,
        master_plan_blob=args.master_plan_blob,
        environment_identity='%s@%s | config=%s' % (
            args.vm_identity, identity, args.config_identity),
        status=status_word)
    print('%s: %s (evidence: %s)' % (args.acc, status_word, out_dir))
    return exit_code


if __name__ == '__main__':
    sys.exit(main())
