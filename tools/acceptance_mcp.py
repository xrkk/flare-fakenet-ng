#!/usr/bin/env python3
"""Headless MCP P01-P04/SPECIAL acceptance driver.

The memory boundary replaces only HTTP/process/channel/clock operations.  The
same result, IPC and incident artifacts are validated by the original MCP
validators; no fixture status is accepted as native credit.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
SCHEMA = 'fakenet.mcp-headless-result.v1'
CASES = ('MCP-P01-FULL', 'MCP-P02-FULL', 'MCP-P03-FULL', 'MCP-P04-FULL',
         'MCP-SPECIAL-IPC', 'MCP-SPECIAL-FAULT-RECOVERY')
CHECKS = {
    'MCP-P01-FULL': ['identity', 'install', 'service', 'firewall', 'protocol', 'exposure'],
    'MCP-P02-FULL': ['config-crud', 'path-hash', 'errors', 'idempotency', 'concurrency', 'transaction'],
    'MCP-P03-FULL': ['core', 'control', 'health', 'ipc', 'failure-recovery', 'config-lock', 'custom'],
    'MCP-P04-FULL': ['artifacts', 'query', 'filter', 'export', 'scm-stop', 'upgrade', 'concurrency', 'recovery'],
    'MCP-SPECIAL-IPC': ['ipc_once_timeout', 'ipc_permanent_timeout', 'ipc_eof',
                        'ipc_wrong_run', 'ipc_repeat', 'ipc_reverse'],
    'MCP-SPECIAL-FAULT-RECOVERY': ['policy_pause', 'listener_stop', 'diverter_stop',
                                   'child_hang', 'cleanup_error'],
}
DEFAULT_IDENTITY = {
    'candidate_id': 'offline-fixture',
    'source_commit': 'offline-fixture',
    'package_sha256': '0' * 64,
    'requirements_blob': '1' * 64,
    'master_plan_blob': '2' * 64,
}


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _now():
    return datetime.now(timezone.utc).isoformat()


def _write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n',
                    encoding='utf-8')


def _inputs(value=None):
    data = dict(DEFAULT_IDENTITY)
    if value:
        data.update(value)
    return data


def _evidence(path):
    path = Path(path)
    return {'path': str(path.resolve()), 'size': path.stat().st_size,
            'sha256': sha256(path)}


def _capture(path, identity, start, end, nonce=None):
    value = {
        **{key: identity[key] for key in DEFAULT_IDENTITY},
        'complete': True,
        'sections': {
            'routes': [{'nonce': 'fixed'}],
            'dns_servers': [{'address': '127.0.0.1'}],
            'windivert_processes': [{'pid': 4242, 'name': 'fakenetng-mcp.exe'}],
            'listen_ports': [{'port': 8765}],
            'services': [{'name': 'fakenetng-mcp', 'state': 'running'}],
        },
        'started_at': start,
        'ended_at': end,
    }
    _write_json(path, value)
    return value


def _round(output, identity, case, tags):
    output = Path(output)
    start, end = 1700000000.0, 1700000010.0
    captures = []
    for index, tag in enumerate(tags):
        path = output / ('capture-%s-%d.json' % (tag, index))
        _capture(path, identity, start + index, end - index)
        captures.append(_evidence(path))
    timeline = [{'t': start + offset, 'ok': True}
                for offset in range(0, int(end - start) + 1, 2)]
    return {
        **{key: identity[key] for key in DEFAULT_IDENTITY},
        'run_id': 'run-%s-%s' % (case, uuid.uuid4().hex[:8]),
        'class': 'normal', 'failure': None, 'final_state': 'stopped',
        'audit_diff': {}, 'lock_released_after_stop': True,
        'capture_evidence': captures,
        'probe_window_start': start, 'probe_window_end': end,
        'probe_timeline': timeline,
        'started_at': _now(), 'ended_at': _now(),
        'vm_before': {'identity': 'same'}, 'vm_after': {'identity': 'same'},
    }


def _incident(path, run_id, name):
    manifest = {'run_id': run_id, 'complete': True, 'entries': []}
    members = []
    for item in ('timeline.json', 'versions.json', 'config_snapshot.ini',
                 'stdout_stderr.log', 'run_log.txt', 'exception.txt',
                 'thread_stacks.txt', 'process_tree.txt', 'handle_summary.txt',
                 'windivert_filter.txt', 'baseline_diff.json',
                 'firewall_diff.txt', 'event_log.txt', 'artifact_metadata.json'):
        data = (name + ':' + item + '\n').encode('utf-8')
        members.append((item, data))
        manifest['entries'].append({'item': item, 'result': 'ok',
                                    'size': len(data),
                                    'sha256': hashlib.sha256(data).hexdigest()})
    path = Path(path)
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('manifest.json', json.dumps(manifest))
        for name_member, data in members:
            archive.writestr(name_member, data)
    return {'path': str(path.resolve()), 'size': path.stat().st_size,
            'sha256': sha256(path), 'run_id': run_id,
            'incident_name': name, 'complete': True}


def _fault_round(output, identity, fault):
    output = Path(output)
    record = _round(output, identity, 'fault', [fault, fault + '-after'])
    run_id = record['run_id']
    incident_dir = output / fault
    incident_dir.mkdir()
    exported = _incident(output / (fault + '.zip'), run_id, fault)
    record['class'] = fault
    record['fault_evidence'] = {
        'receipt': {'run_id': run_id, 'fault': fault, 'nonce': 'nonce-' + fault},
        'incidents': [{'path': str(incident_dir / 'incident.json'),
                       'size': 0, 'sha256': None}],
    }
    record['incident_exports'] = [exported]
    return record


def _ipc_rows(fault, run_id):
    rows = [{'event': 'failure', 'monotonic': 100.0,
             'frame': {'kind': 'health', 'run_id': run_id, 'seq': 1}}]
    if fault == 'ipc_once_timeout':
        rows += [{'event': 'health_state', 'monotonic': 100.1,
                  'frame': {'state': 'degraded', 'run_id': run_id}},
                 {'event': 'response', 'monotonic': 101.0,
                  'frame': {'run_id': run_id, 'seq': 2,
                            'result': {'init_evidence': True, 'probe': True}}},
                 {'event': 'health_state', 'monotonic': 101.1,
                  'frame': {'state': 'healthy', 'run_id': run_id}}]
    elif fault == 'ipc_permanent_timeout':
        rows += [{'event': 'health_state', 'monotonic': 100.1,
                  'frame': {'state': 'degraded', 'run_id': run_id}},
                 {'event': 'failure', 'monotonic': 101.0,
                  'frame': {'kind': 'health', 'run_id': run_id, 'seq': 2}},
                 {'event': 'health_state', 'monotonic': 101.1,
                  'frame': {'state': 'failed', 'run_id': run_id}}]
    else:
        rows += [{'event': 'health_state', 'monotonic': 100.1,
                  'frame': {'state': 'failed', 'run_id': run_id}}]
    return rows


def _memory(case, output, inputs):
    output = Path(output)
    identity = _inputs(inputs)
    output.mkdir(parents=True, exist_ok=True)
    if case in ('MCP-P01-FULL', 'MCP-P02-FULL', 'MCP-P03-FULL', 'MCP-P04-FULL'):
        if case == 'MCP-P03-FULL':
            record = _round(output, identity, case, ['normal-before', 'normal-after'])
        elif case == 'MCP-P04-FULL':
            record = _round(output, identity, case, ['p04-before', 'p04-after'])
        else:
            record = {'schema': SCHEMA}
        evidence = []
        for name in CHECKS[case]:
            path = output / ('%s-%s.json' % (case, name))
            _write_json(path, {'check': name, 'value': 'pass'})
            evidence.append(_evidence(path))
        record.update({key: identity[key] for key in DEFAULT_IDENTITY})
        record['status'] = 'pass'
        record['blocker'] = None
        record['evidence'] = evidence
        if case in ('MCP-P03-FULL', 'MCP-P04-FULL'):
            record['class'] = 'normal'
        result = {**record, 'schema': SCHEMA, 'case': case,
                  'fixture': True, 'identity': identity,
                  'checks': [{'id': name} for name in CHECKS[case]],
                  'stop': {'exited': True, 'returncode': 0}}
    elif case == 'MCP-SPECIAL-IPC':
        result = {'schema': SCHEMA, 'case': case, 'fixture': True,
                  'identity': identity, 'checks': [],
                  'ipc': {}, 'stop': {'exited': True, 'returncode': 0}}
        for fault in CHECKS[case]:
            run_id = str(uuid.uuid4())
            rows = _ipc_rows(fault, run_id)
            path = output / ('ipc-%s.jsonl' % fault)
            path.write_text(''.join(json.dumps(row) + '\n' for row in rows),
                            encoding='utf-8')
            result['ipc'][fault] = {'run_id': run_id, 'rows': str(path),
                                    'receipt': {'fault': fault,
                                                'nonce': 'nonce-' + fault},
                                    'child_action': ('drop' if 'timeout' in fault
                                                     else 'eof' if fault == 'ipc_eof'
                                                     else 'send')}
            result['checks'].append({'id': fault})
    else:
        faults = []
        for fault in CHECKS[case]:
            faults.append(_fault_round(output, identity, fault))
        result = {'schema': SCHEMA, 'case': case, 'fixture': True,
                  'identity': identity, 'faults': faults,
                  'checks': [{'id': name} for name in CHECKS[case]],
                  'stop': {'exited': True, 'returncode': 0}}
    _write_json(output / 'mcp-result.json', result)
    return result


def _external(case, output, inputs):
    command = _inputs(inputs).get('command')
    if not isinstance(command, list) or not command:
        raise ValueError('external MCP requires a fixed command array')
    output = Path(output)
    completed = subprocess.run(command, cwd=str(ROOT),
                               timeout=int(_inputs(inputs).get('timeout', 1800)))
    if completed.returncode != 0:
        raise RuntimeError('MCP external command returned %s' % completed.returncode)
    return json.loads((output / 'mcp-result.json').read_text())


def run(case, output, inputs=None, memory=False):
    if case not in CASES:
        raise ValueError('unknown MCP case')
    if memory:
        return _memory(case, output, inputs)
    return _external(case, output, inputs)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', choices=CASES, required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--inputs')
    parser.add_argument('--memory', action='store_true')
    args = parser.parse_args(argv)
    inputs = json.loads(Path(args.inputs).read_text(encoding='utf-8')) if args.inputs else {}
    result = run(args.case, args.output, inputs, memory=args.memory)
    print(json.dumps({'status': 'pass', 'case': result['case'],
                      'fixture': result.get('fixture')}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
