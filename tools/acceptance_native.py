#!/usr/bin/env python3
"""Registered native acceptance drivers for the FakeNet v2 catalog.

A driver is a fixed argv array plus a fixed sub-check list and a single oracle.
Nothing here accepts a caller-supplied shell string.  Drivers that still need
the real VM/endpoints are registered as ``implemented: False`` with the exact
missing capability, so a full plan records them as blocked instead of silently
dropping them.

The current task may only run the offline fixture channel.  Native execution is
authorised by ``environment.allowed_actions`` containing ``native``; this
module never assumes that authority.
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
import subprocess
from pathlib import Path

NATIVE_SCHEMA = 'fakenet.native-driver.v1'


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def _read(path):
    return Path(path).read_text(encoding='utf-8', errors='replace')


def upstream_checks(root):
    """Static test-name table from test/test.py's ``t['name']`` assignments."""
    path = Path(root) / 'test' / 'test.py'
    if not path.is_file():
        return []
    tree = ast.parse(_read(path), filename=str(path))
    names = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if (isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name)
                and target.value.id == 't' and isinstance(target.slice, ast.Constant)
                and isinstance(target.slice.value, str)):
            names.append(target.slice.value)
    return names


def ps1_checks(path):
    text = _read(path)
    names = []
    for pattern in (r"Add-Result\s+'([^']+)'",
                    r"Add-Result\s+([A-Za-z0-9_-]+)\s+(?:PASS|FAIL|OBSERVED)",
                    r"Invoke-LoggedCommand\s+-Name\s+'([^']+)'"):
        names.extend(re.findall(pattern, text))
    seen = []
    for name in names:
        if name not in seen:
            seen.append(name)
    return seen


def mcp_checks(path):
    path = Path(path)
    if not path.is_file():
        return []
    tree = ast.parse(_read(path), filename=str(path))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not (isinstance(node.func, ast.Attribute) and node.func.attr == 'add_argument'):
            continue
        if not node.args or not (isinstance(node.args[0], ast.Constant)
                                 and node.args[0].value == '--acc'):
            continue
        for keyword in node.keywords:
            if keyword.arg == 'choices' and isinstance(keyword.value, (ast.List, ast.Tuple)):
                return [item.value for item in keyword.value.elts
                        if isinstance(item, ast.Constant)]
    return []


UPSTREAM_FILTERS = {
    'UPSTREAM-TCP-UDP': ('TCP ', 'UDP '),
    'UPSTREAM-DNS': ('DNS listener',),
    'UPSTREAM-HTTP-CUSTOM': ('HTTP ', 'HTTPS '),
    'UPSTREAM-FTP-POP-SMTP-IRC': ('FTP ', 'POP3 ', 'SMTP ', 'IRC '),
    'UPSTREAM-SMTP-SSL': ('SMTP SSL',),
    'UPSTREAM-PROXY-HIDDEN': ('Proxy ',),
    'UPSTREAM-BLACKLIST': ('blacklisted', 'blacklist'),
    'UPSTREAM-PROCESS-FILTERS': ('Global blacklisted', 'Global whitelisted'),
    'UPSTREAM-LISTENER-FILTERS': ('Listener process', 'Listener host'),
    'UPSTREAM-REDIRECTALL-OFF': ('RedirectAllTraffic',),
}

EGRESS_FILTERS = {
    'EGRESS-ALLOW-CHAIN': ('DnsAutoSelection', 'ExternalDnsServer', 'Dependencies',
                           'AllowedIPv4', 'positive-api-deepseek', 'Event-'),
    'EGRESS-NEGATIVES': ('negative-', 'Event-DROP_EXTERNAL', 'PolicyExceptions'),
    'EGRESS-RESTORE': ('FakeNetStop', 'IndependentCapture', 'DnsRestore',
                       'PolicyExceptions'),
}


def driver_table(root):
    root = Path(root)
    upstream = upstream_checks(root)
    egress_path = root / 'test/egress_control_vm/Run-EgressControlTests.ps1'
    ip_path = root / 'test/public_ipv4_allowlist_vm/Run-ReviewedIPv4Tests.ps1'
    exe_path = root / 'test/process_redirect_vm/Run-ProcessRedirectTests.ps1'
    egress = ps1_checks(egress_path) if egress_path.is_file() else []
    for event in ('EGRESS_CONTROL_READY', 'DNS_LEASE_ADD', 'REDIRECT_TLS_RELAY',
                  'TLS_SNI_ALLOW', 'ALLOW_INTERNAL_UPSTREAM', 'DROP_EXTERNAL',
                  'FakeNetStop', 'IndependentCaptureFile', 'DnsRestore',
                  'PolicyExceptions'):
        if event not in egress:
            egress.append('Event-' + event if event.isupper() else event)
    ipv4 = ps1_checks(ip_path) if ip_path.is_file() else []
    exe = ps1_checks(exe_path) if exe_path.is_file() else []
    drivers = {
        'upstream-singlehost': {
            'implemented': True,
            'platforms': ['windows', 'linux'],
            'modes': ['singlehost'],
            'argv': ['{python}', 'test/test.py', 'here', '--results',
                     '{output}/upstream.tsv', '--non-interactive'],
            'oracle': {'kind': 'tsv', 'artifact': 'upstream.tsv'},
            'checks': upstream,
            'check_filters': UPSTREAM_FILTERS,
            'requires': ['native'],
            'package_required': False,
            'cleanup': 'test.py writes only the run result file; stop handling is internal',
            'readiness': ['project interpreter', 'test/test.py dependencies'],
        },
        'upstream-multihost': {
            'implemented': False,
            'missing': 'MultiHost needs config transfer and a real remote ready channel',
            'platforms': ['linux'], 'modes': ['multihost'],
            'checks': upstream, 'requires': ['native'], 'package_required': False,
        },
        'egress-windows': {
            'implemented': True,
            'platforms': ['windows'], 'modes': ['singlehost'],
            'argv': ['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass',
                     '-File', 'test/egress_control_vm/Run-EgressControlTests.ps1',
                     '-PythonPath', '{python}'],
            'oracle': {'kind': 'tsv', 'artifact': 'results.tsv',
                       'discover': r'Plain logs available at:\s*(.+)'},
            'checks': egress, 'check_filters': EGRESS_FILTERS,
            'requires': ['native'], 'package_required': False,
            'cleanup': 'runner owns stop/pktmon/DNS snapshot restore',
            'readiness': ['Windows VM', 'administrator', 'pktmon', 'external DNS'],
        },
        'reviewed-ipv4-windows': {
            'implemented': True,
            'platforms': ['windows'], 'modes': ['singlehost'],
            'argv': ['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass',
                     '-File', 'test/public_ipv4_allowlist_vm/Run-ReviewedIPv4Tests.ps1',
                     '-PythonPath', '{python}'],
            'oracle': {'kind': 'tsv', 'artifact': 'results.tsv'},
            'checks': ipv4,
            'requires': ['native'], 'package_required': False,
            'cleanup': 'runner restores DNS/IP/route and keeps pcap',
            'readiness': ['Windows VM', 'administrator', 'pktmon', 'pinned DNS address'],
        },
        'process-redirect-windows': {
            'implemented': True,
            'platforms': ['windows'], 'modes': ['singlehost'],
            'argv': ['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass',
                     '-File', 'test/process_redirect_vm/Run-ProcessRedirectTests.ps1'],
            'oracle': {'kind': 'tsv', 'artifact': 'results.tsv'},
            'checks': exe,
            'requires': ['native'], 'package_required': True,
            'cleanup': 'runner stops clients/core and restores network',
            'readiness': ['Windows VM', 'administrator', 'sentinel', 'reviewed A/B'],
        },
        'pcap-windows-functional': {
            'implemented': False,
            'missing': 'Run-DualPcapTests.ps1 needs a -Functional switch that removes '
                       'unittest discover, benchmark and the interactive normal stop',
            'platforms': ['windows'], 'modes': ['singlehost'],
            'checks': [], 'requires': ['native'], 'package_required': True,
        },
        'pcap-linux-functional': {
            'implemented': False,
            'missing': 'run_tests.py needs a -Functional switch for normal/fault cases '
                       'without unit discovery and benchmark',
            'platforms': ['linux'], 'modes': ['singlehost', 'multihost'],
            'checks': [], 'requires': ['native'], 'package_required': True,
        },
        'policy-headless': {
            'implemented': False,
            'missing': 'headless policy driver (core INI + sink + no GUI config writer) '
                       'is not implemented in this round',
            'platforms': ['windows'], 'modes': ['singlehost'],
            'checks': [], 'requires': ['native'], 'package_required': True,
        },
        'payload-headless': {
            'implemented': False,
            'missing': 'headless payload driver (core + benign client + verifiers) '
                       'is not implemented in this round',
            'platforms': ['windows'], 'modes': ['singlehost'],
            'checks': [], 'requires': ['native'], 'package_required': True,
        },
        'mcp-p01': {
            'implemented': False,
            'missing': 'P01 needs candidate/package/plan/Vm identity arguments and a live MCP channel',
            'platforms': ['windows'], 'modes': ['native'],
            'checks': mcp_checks(root / 'test/mcp/acceptance/run_p01_acc.py'),
            'requires': ['native'], 'package_required': True,
        },
        'mcp-p02': {
            'implemented': False,
            'missing': 'P02 needs candidate/package/plan/Vm identity arguments and a live MCP channel',
            'platforms': ['windows'], 'modes': ['native'],
            'checks': mcp_checks(root / 'test/mcp/acceptance/run_p02_acc.py'),
            'requires': ['native'], 'package_required': True,
        },
        'mcp-p03': {
            'implemented': False,
            'missing': 'P03 still contains GUI co-control; headless split not implemented',
            'platforms': ['windows'], 'modes': ['native'],
            'checks': mcp_checks(root / 'test/mcp/acceptance/run_p03_acc.py'),
            'requires': ['native'], 'package_required': True,
        },
        'mcp-p04': {
            'implemented': False,
            'missing': 'P04 still imports the P05 release object for fault rounds',
            'platforms': ['windows'], 'modes': ['native'],
            'checks': mcp_checks(root / 'test/mcp/acceptance/run_p04_acc.py'),
            'requires': ['native'], 'package_required': True,
        },
        'mcp-special': {
            'implemented': False,
            'missing': 'SPECIAL IPC/control/init cases need live MCP channel and destructive-scope split',
            'platforms': ['windows'], 'modes': ['native'],
            'checks': [], 'requires': ['native'], 'package_required': True,
        },
        'linux-runtime': {
            'implemented': False,
            'missing': 'Linux SingleHost/MultiHost native driver and deploy/update driver not implemented',
            'platforms': ['linux'], 'modes': ['singlehost', 'multihost'],
            'checks': [], 'requires': ['native'], 'package_required': True,
        },
        'manual-headless': {
            'implemented': False,
            'missing': 'headless_manual.py feature drivers not implemented',
            'platforms': ['windows', 'linux'], 'modes': ['singlehost'],
            'checks': [], 'requires': ['native'], 'package_required': False,
        },
        'build-identity': {
            'implemented': True,
            'platforms': ['windows', 'linux'], 'modes': ['offline'],
            'argv': ['{python}', 'tools/acceptance_native.py', '--check-package',
                     '{package_manifest}', '{package_sha256}'],
            'oracle': {'kind': 'json', 'artifact': 'identity.json'},
            'checks': ['source_commit', 'package_manifest', 'package_sha256'],
            'requires': [], 'package_required': True,
            'cleanup': 'read-only identity check',
            'readiness': ['candidate package manifest'],
        },
    }
    return drivers


def select_checks(driver, case):
    checks = driver.get('checks') or []
    filters = (driver.get('check_filters') or {}).get(case['id'])
    if not filters:
        return list(checks)
    selected = [name for name in checks if any(token in name for token in filters)]
    return selected


def validate_case(case, root):
    drivers = driver_table(root)
    name = case.get('native_driver')
    if not name or name not in drivers:
        raise ValueError('%s has an unknown native driver' % case['id'])
    driver = drivers[name]
    if not driver.get('implemented'):
        return driver, []
    checks = select_checks(driver, case)
    if not checks:
        raise ValueError('%s driver has no declared checks' % case['id'])
    return driver, checks


def fixed_argv(driver, context):
    argv = []
    for item in driver['argv']:
        if not isinstance(item, str):
            raise ValueError('native driver argv must be strings')
        value = item
        for key, replacement in context.items():
            value = value.replace('{%s}' % key, str(replacement))
        if re.search(r'[<>|;&]', value):
            raise ValueError('native argv token contains a shell metacharacter: %r' % value)
        argv.append(value)
    return argv


def run_driver(root, case, plan, output_dir, python):
    root = Path(root)
    driver, checks = validate_case(case, root)
    if not driver.get('implemented'):
        raise ValueError(driver.get('missing') or 'driver is not implemented')
    candidate = plan.get('candidate') or {}
    if driver.get('package_required'):
        for key in ('package_manifest', 'package_sha256', 'deployed_identity'):
            if not candidate.get(key):
                raise ValueError('candidate.%s is required by %s' % (key, case['id']))
    context = {
        'python': python,
        'output': output_dir,
        'root': root,
        'package_manifest': candidate.get('package_manifest') or '',
        'package_sha256': candidate.get('package_sha256') or '',
    }
    argv = fixed_argv(driver, context)
    output_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = output_dir / 'stdout.log'
    stderr_path = output_dir / 'stderr.log'
    started = _now()
    try:
        with stdout_path.open('xb') as stdout, stderr_path.open('xb') as stderr:
            completed = subprocess.run(argv, cwd=root, stdout=stdout, stderr=stderr,
                                       timeout=case['timeout'], check=False)
            returncode = completed.returncode
    except subprocess.TimeoutExpired:
        returncode = None
    ended = _now()
    artifacts = []
    rows = []
    status = 'unknown'
    detail = ''
    oracle = driver['oracle']
    artifact = _discover_artifact(oracle, output_dir)
    if artifact is None:
        detail = 'oracle artifact was not produced'
    else:
        artifacts.append({'path': str(artifact.resolve()), 'sha256': sha256(artifact),
                          'format': oracle['kind']})
        try:
            rows = _read_oracle(oracle['kind'], artifact)
            evaluation = _judge_rows(rows, checks)
            status = evaluation['verdict']
            detail = json.dumps(evaluation, ensure_ascii=False)
        except (OSError, ValueError, json.JSONDecodeError) as error:
            detail = 'oracle parse failed: %s' % error
    if returncode not in (0, None) and status == 'pass':
        status = 'fail'
        detail = 'driver rc=%s; %s' % (returncode, detail)
    if returncode is None:
        status = 'unknown'
        detail = 'timeout after %ss' % case['timeout']
    artifacts.append({'path': str(stdout_path.resolve()), 'sha256': sha256(stdout_path),
                      'format': 'log'})
    artifacts.append({'path': str(stderr_path.resolve()), 'sha256': sha256(stderr_path),
                      'format': 'log'})
    return {
        'status': status,
        'detail': detail,
        'returncode': returncode,
        'command': argv,
        'started_at': started,
        'ended_at': ended,
        'duration_seconds': 0.0,
        'required_checks': checks,
        'artifacts': artifacts,
        'cleanup': {'source': 'driver', 'resources': [],
                    'process_exit': {'exited': True, 'returncode': returncode,
                                     'timed_out': returncode is None},
                    'temp_roots': [str(output_dir.resolve())]},
    }


def judge_driver(case, receipt, plan, root):
    driver, checks = validate_case(case, root)
    if not driver.get('implemented'):
        return {'status': 'blocked', 'reason': driver.get('missing') or 'not implemented'}
    if receipt.get('command') != fixed_argv(driver, {
            'python': plan['environment']['interpreters']['python'],
            'output': str(Path(plan['run_dir']) / 'results' / case['id']),
            'root': plan['run_dir'],
            'package_manifest': plan.get('candidate', {}).get('package_manifest') or '',
            'package_sha256': plan.get('candidate', {}).get('package_sha256') or ''}):
        return {'status': 'fail', 'reason': 'receipt argv differs from the registered driver'}
    if receipt.get('required_checks') != checks:
        return {'status': 'fail', 'reason': 'receipt checks differ from the registered table'}
    oracle = driver['oracle']
    oracle_paths = [item for item in receipt.get('artifacts') or []
                    if item.get('format') == oracle['kind']]
    if len(oracle_paths) != 1:
        return {'status': 'unknown', 'reason': 'expected exactly one native oracle artifact'}
    artifact = Path(oracle_paths[0]['path'])
    if not artifact.is_file() or sha256(artifact) != oracle_paths[0]['sha256']:
        return {'status': 'unknown', 'reason': 'native oracle artifact changed'}
    rows = _read_oracle(oracle['kind'], artifact)
    evaluation = _judge_rows(rows, checks)
    receipt_status = receipt.get('status')
    if evaluation['verdict'] == 'fail' or receipt_status == 'fail':
        status = 'fail'
    elif evaluation['verdict'] != 'pass' or receipt_status != 'pass':
        status = 'unknown'
    else:
        status = 'pass'
    if receipt.get('returncode') != 0:
        status = 'fail'
    cleanup = receipt.get('cleanup') or {}
    if (cleanup.get('source') != 'driver' or cleanup.get('resources') != []
            or (cleanup.get('process_exit') or {}).get('exited') is not True):
        if status == 'pass':
            status = 'unknown'
    return {'status': status, 'evaluation': evaluation}


def _now():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def _discover_artifact(oracle, output_dir):
    name = oracle.get('artifact')
    if not name:
        return None
    path = Path(output_dir) / name
    if path.is_file():
        return path
    pattern = oracle.get('discover')
    if pattern:
        log = Path(output_dir) / 'stdout.log'
        if log.is_file():
            match = re.search(pattern, _read(log))
            if match:
                candidate = Path(match.group(1).strip().strip('"')) / name
                if candidate.is_file():
                    return candidate
    return None


def _read_oracle(kind, path):
    if kind == 'tsv':
        rows = []
        for number, line in enumerate(_read(path).splitlines(), 1):
            if not line.strip():
                continue
            fields = line.split('\t')
            if len(fields) < 2:
                raise ValueError('invalid TSV line %d' % number)
            first, second = fields[:2]
            if first.lower() in ('pass', 'fail', 'unknown', 'not_run', 'blocked',
                                 'skip', 'observed') or first.upper() in ('FAILED', 'REFUSED'):
                status, name = first.lower(), second
            else:
                name, status = first, second.lower()
            status = {'failed': 'fail', 'refused': 'blocked'}.get(status, status)
            rows.append({'id': name, 'status': status})
        return rows
    if kind in ('json', 'native-json'):
        value = json.loads(_read(path))
        if not isinstance(value, dict):
            raise ValueError('native JSON oracle must be an object')
        return value.get('checks') or []
    raise ValueError('unknown native oracle kind: %r' % kind)


def _judge_rows(rows, required):
    if not required or len(required) != len(set(required)):
        raise ValueError('a nonempty unique native check list is required')
    by_id = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get('id'), str):
            raise ValueError('invalid native result row')
        by_id.setdefault(row['id'], []).append(row)
    missing = [key for key in required if key not in by_id]
    nonpass = [key for key in required if key in by_id
               and any(row.get('status') != 'pass' for row in by_id[key])]
    failed = sorted(key for key, values in by_id.items()
                    if any(row.get('status') == 'fail' for row in values))
    extra = sorted(set(by_id) - set(required))
    verdict = ('fail' if failed else 'unknown' if missing or nonpass or extra else 'pass')
    return {'verdict': verdict, 'missing': missing, 'nonpass': nonpass,
            'failed': failed, 'extra': extra}


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-package', nargs=2, metavar=('MANIFEST', 'SHA256'))
    args = parser.parse_args(argv)
    if args.check_package:
        manifest, expected = args.check_package
        path = Path(manifest)
        if not path.is_file() or sha256(path) != expected:
            return 1
        print(json.dumps({'source_commit': None, 'package_manifest': str(path),
                          'package_sha256': expected}))
        return 0
    parser.print_help()
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
