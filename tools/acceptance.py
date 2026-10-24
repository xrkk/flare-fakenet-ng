#!/usr/bin/env python3
"""Inventory, plan, execute and judge existing FakeNet regression facilities.

The v1 surface (inventory/check/plan/run/judge --result) remains readable and
byte-compatible with historical plans and receipts.  The v2 surface adds the
catalog cases, an explicit candidate/environment bound plan, offline execution
with original evidence, and a strict judge that recomputes verdicts from raw
results.

No inventory/plan operation imports a test driver.  Collection and execution
are code execution, so they only run registered adapters and only when the
environment explicitly authorises the action.  Original drivers keep their own
runtime checks, evidence and cleanup responsibility.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import re
import subprocess
import sys
import uuid
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parent))
import acceptance_scheduler
try:
    import acceptance_native
except ImportError:  # pragma: no cover - the module is shipped with this entry
    acceptance_native = None

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / 'docs' / 'acceptance' / 'catalog.json'
SCHEMA = 'fakenet.acceptance-inventory.v1'
CATALOG_V1 = 'fakenet.acceptance-catalog.v1'
CATALOG_V2 = 'fakenet.acceptance-catalog.v2'
PLAN_V1 = 'fakenet.acceptance-plan.v1'
PLAN_V2 = 'fakenet.acceptance-plan.v2'
RECEIPT_V2 = 'fakenet.acceptance-receipt.v2'
RESULTS_V2 = 'fakenet.acceptance-results.v2'
SUMMARY_V1 = 'fakenet.acceptance-summary.v1'
SUMMARY_V2 = 'fakenet.acceptance-summary.v2'
CANDIDATE_V2 = 'fakenet.acceptance-candidate.v2'
ENVIRONMENT_V2 = 'fakenet.acceptance-environment.v2'
STATUSES = {'pass', 'fail', 'unknown', 'not_run', 'blocked', 'skip', 'observed'}
CASE_STATUSES = {'pass', 'fail', 'not_run', 'unknown', 'blocked', 'not_applicable'}
ADAPTERS = {'offline-pytest', 'native', 'native-blocked', 'manual-blocked'}
ORACLES = {'junit', 'tsv', 'native-json', 'pcap', 'policy-result',
           'headless-result', 'mcp-result', 'manual', 'none'}
EXIT_OK, EXIT_FAIL, EXIT_INPUT, EXIT_TOOL = 0, 1, 2, 3


class InputError(ValueError):
    """Invalid operator input or unsupported schema; exit 2."""


class ToolError(RuntimeError):
    """Facility failure (collection, adapter, malformed raw result); exit 3."""


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise InputError('unreadable JSON %s: %s' % (path, error)) from error


def read_catalog(root=ROOT):
    root = Path(root)
    value = read_json(root / 'docs/acceptance/catalog.json')
    schema = value.get('schema')
    if schema not in (CATALOG_V1, CATALOG_V2):
        raise InputError('unknown catalog schema: %r' % schema)
    ids = [row['id'] for row in value['suites']]
    if len(ids) != len(set(ids)):
        raise ValueError('duplicate suite id')
    for row in value['suites']:
        for key in ('content', 'procedure', 'judgment', 'sources', 'limitations'):
            if not row.get(key):
                raise ValueError('%s missing %s' % (row['id'], key))
        for source in row['sources']:
            if not source or Path(source).is_absolute() or '..' in Path(source).parts:
                raise ValueError('unsafe catalog source')
            if not any(root.glob(source)):
                raise ValueError('%s missing source %s' % (row['id'], source))
    if schema == CATALOG_V2:
        validate_cases(value)
        if any(case.get('adapter') == 'native'
               for suite in value['suites'] for case in suite.get('cases') or []):
            if acceptance_native is None:
                raise ValueError('native adapter module is unavailable')
            drivers = acceptance_native.driver_table(root)
            for suite in value['suites']:
                for case in suite.get('cases') or []:
                    if case.get('adapter') == 'native' and case.get('native_driver') not in drivers:
                        raise ValueError('%s has an unknown native driver' % case['id'])
    return value


def validate_cases(catalog):
    cases = []
    for suite in catalog['suites']:
        for case in suite.get('cases') or []:
            cases.append((suite, case))
    ids = [case['id'] for unused, case in cases]
    if len(ids) != len(set(ids)):
        raise ValueError('duplicate case id')
    for suite, case in cases:
        required = ('id', 'suite_id', 'title', 'platforms', 'modes', 'input',
                    'steps', 'expected', 'oracle', 'resources', 'readiness',
                    'timeout', 'cleanup', 'dependencies', 'adapter')
        for key in required:
            if key not in case:
                raise ValueError('%s missing case field %s' % (case.get('id'), key))
            if key == 'dependencies':
                continue
            if case[key] in (None, '', []):
                raise ValueError('%s empty case field %s' % (case.get('id'), key))
        if case['suite_id'] != suite['id']:
            raise ValueError('%s suite_id mismatch' % case['id'])
        if not isinstance(case['platforms'], list) or not case['platforms']:
            raise ValueError('%s platforms must be a nonempty list' % case['id'])
        if not isinstance(case['modes'], list) or not case['modes']:
            raise ValueError('%s modes must be a nonempty list' % case['id'])
        if case['adapter'] not in ADAPTERS:
            raise ValueError('%s unknown adapter' % case['id'])
        oracle = case['oracle']
        if not isinstance(oracle, dict) or oracle.get('kind') not in ORACLES:
            raise ValueError('%s invalid oracle' % case['id'])
        if not isinstance(case['timeout'], int) or case['timeout'] <= 0:
            raise ValueError('%s timeout must be a positive integer' % case['id'])
        if not isinstance(case['dependencies'], list):
            raise ValueError('%s dependencies must be a list' % case['id'])
        if case.get('excluded') and not case.get('excluded_basis'):
            raise ValueError('%s excluded without basis' % case['id'])
        if case['adapter'] != 'offline-pytest' and case.get('required_for_full', True):
            if not case.get('blocked_reason'):
                raise ValueError('%s needs blocked_reason' % case['id'])
    known = set(ids)
    for unused, case in cases:
        for dependency in case['dependencies']:
            if dependency not in known:
                raise ValueError('%s unknown dependency %s' % (case['id'], dependency))
            if dependency == case['id']:
                raise ValueError('%s depends on itself' % case['id'])
    graph = {case['id']: list(case['dependencies']) for unused, case in cases}
    state = {}

    def visit(node):
        if state.get(node) == 2:
            return
        if state.get(node) == 1:
            raise ValueError('dependency cycle at %s' % node)
        state[node] = 1
        for child in graph.get(node, ()):
            visit(child)
        state[node] = 2

    for node in graph:
        visit(node)
    for entry in catalog.get('exclusions') or []:
        if not entry.get('id') or not entry.get('basis'):
            raise ValueError('exclusion needs id and basis')
    return cases


def all_cases(catalog):
    result = []
    for suite in catalog['suites']:
        for case in suite.get('cases') or []:
            record = dict(case)
            record['suite_id'] = suite['id']
            result.append(record)
    return result


def python_items(path, root):
    """Static extraction, including class context and original assertions."""
    text = path.read_text(encoding='utf-8-sig')
    tree = ast.parse(text, filename=str(path))
    items = []

    def visit(node, parents=()):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                visit(child, parents + (child.name,))
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                is_test = child.name.startswith(('test_', 'testGeneral', 'testNoRedirect',
                                                 'testBlacklistProcess', 'testWhitelistProcess'))
                if is_test:
                    checks = []
                    for part in ast.walk(child):
                        if isinstance(part, ast.Assert):
                            checks.append(ast.unparse(part.test))
                        elif isinstance(part, ast.Call) and isinstance(part.func, ast.Attribute):
                            if part.func.attr.startswith('assert') or part.func.attr == 'raises':
                                checks.append(ast.unparse(part))
                    items.append({'id': '::'.join((path.relative_to(root).as_posix(), *parents, child.name)),
                                  'line': child.lineno, 'description': ast.get_docstring(child) or '',
                                  'assertions': checks})
                visit(child, parents + (child.name,))
            else:
                visit(child, parents)
    visit(tree)
    # Native drivers generally use named result calls instead of pytest tests.
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in ('result', 'add_result') and node.args:
                label = node.args[0]
                if isinstance(label, ast.Constant) and isinstance(label.value, str):
                    items.append({'id': label.value, 'line': node.lineno,
                                  'kind': 'result_declaration', 'expression': ast.unparse(node)})
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Tuple):
            for target in node.targets:
                if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
                    if target.value.id == 't' and isinstance(target.slice, ast.Constant):
                        items.append({'id': str(target.slice.value), 'line': node.lineno,
                                      'kind': 'upstream_case', 'expression': ast.unparse(node.value)})
    return items


def native_items(path):
    items = []
    for line_number, line in enumerate(path.read_text(encoding='utf-8-sig', errors='replace').splitlines(), 1):
        if re.search(r'\bAdd-Result\s', line) and not line.lstrip().startswith('function'):
            items.append({'line': line_number, 'kind': 'result_declaration', 'expression': line.strip()})
    return items


def inventory(root=ROOT):
    root = Path(root)
    catalog = read_catalog(root)
    files = {}
    for suite in catalog['suites']:
        for pattern in suite['sources']:
            for path in sorted(root.glob(pattern)):
                if not path.is_file() or path.is_symlink():
                    continue
                relative = path.relative_to(root).as_posix()
                if relative not in files:
                    record = {'path': relative, 'sha256': sha256(path), 'suites': [], 'items': []}
                    if path.suffix == '.py':
                        record['items'] = python_items(path, root)
                    elif path.suffix.lower() == '.ps1':
                        record['items'] = native_items(path)
                    files[relative] = record
                files[relative]['suites'].append(suite['id'])
    # Every existing test module and native entry is accounted for, or fails check.
    discovered = set()
    for path in (root / 'test').rglob('*'):
        if any(part in ('Logs', '__pycache__', '.venv') for part in path.parts):
            continue
        if path.is_file() and (path.name.startswith('test_') and path.suffix == '.py'
                               or path.name.startswith(('Run-', 'run_'))
                               and path.suffix.lower() in ('.cmd', '.ps1', '.py', '.sh')):
            discovered.add(path.relative_to(root).as_posix())
    unclassified = sorted(discovered - set(files))
    file_list = sorted(files.values(), key=lambda row: row['path'])
    cases = all_cases(catalog) if catalog['schema'] == CATALOG_V2 else []
    return {'schema': SCHEMA, 'catalog_sha256': sha256(root / 'docs/acceptance/catalog.json'),
            'catalog_schema': catalog['schema'],
            'suites': catalog['suites'], 'files': file_list,
            'unclassified': unclassified,
            'counts': {'suites': len(catalog['suites']), 'files': len(files),
                       'declared_items': sum(len(row['items']) for row in file_list),
                       'cases': len(cases),
                       'required_cases': sum(1 for row in cases
                                             if row.get('required_for_full', True)
                                             and not row.get('stress'))},
            'qualification': 'not_run',
            'limits': ['Static declarations are not executed cases or pass credit.',
                       'Parameterized and dynamically generated cases require runtime collection.',
                       'Inventory coverage does not prove that a test asserts the required behavior.']}


def parse_tsv(path):
    rows = []
    for number, line in enumerate(Path(path).read_text(encoding='utf-8-sig').splitlines(), 1):
        if not line.strip():
            continue
        fields = line.split('\t')
        if len(fields) < 2:
            raise ValueError('invalid TSV line %d' % number)
        # Existing drivers use both status/name and name/status orders.
        first, second = fields[:2]
        if first.lower() in STATUSES or first.upper() in ('FAILED', 'REFUSED'):
            status, name = first, second
        elif second.lower() in STATUSES or second.upper() in ('FAILED', 'REFUSED'):
            name, status = first, second
        elif number == 1 and first.lower() in ('name', 'status', 'test', 'check'):
            continue
        else:
            raise ValueError('unknown TSV status at line %d' % number)
        status = {'failed': 'fail', 'refused': 'blocked'}.get(status.lower(), status.lower())
        rows.append({'id': name, 'status': status, 'detail': '\t'.join(fields[2:])})
    return rows


def parse_junit(path):
    tree = ET.parse(path)
    rows = []
    for case in tree.iter('testcase'):
        status = ('fail' if case.find('failure') is not None or case.find('error') is not None
                  else 'skip' if case.find('skipped') is not None else 'pass')
        rows.append({'id': case.get('classname', '') + '::' + case.get('name', ''), 'status': status})
    if any(int(node.get('errors', '0')) for node in tree.iter('testsuite')):
        rows.append({'id': '__collection_or_suite_error__', 'status': 'fail'})
    return rows


def junit_node(node):
    identity, bracket, parameters = node.partition('[')
    parts = identity.split('::')
    path_part = parts[0]
    if not path_part.startswith('test/'):
        marker = path_part.rfind('/test/')
        if marker >= 0:
            path_part = path_part[marker + 1:]
    module = path_part[:-3].replace('/', '.')
    classname = '.' + '.'.join(parts[1:-1]) if len(parts) > 2 else ''
    return module + classname + '::' + parts[-1] + bracket + parameters


def judge_rows(rows, required):
    """A missing/duplicate/observed/skip result cannot silently satisfy a case."""
    if (not isinstance(required, list) or not required
            or any(not isinstance(key, str) or not key for key in required)
            or len(required) != len(set(required))):
        raise ValueError('a nonempty unique planned case list is required')
    by_id = {}
    for row in rows:
        if row.get('status') not in STATUSES or not isinstance(row.get('id'), str):
            raise ValueError('invalid result row')
        by_id.setdefault(row['id'], []).append(row)
    duplicate = sorted(key for key, values in by_id.items() if len(values) != 1)
    missing = [key for key in required if key not in by_id]
    nonpass = [key for key in required if key in by_id
               and any(row['status'] != 'pass' for row in by_id[key])]
    failed = sorted(key for key, values in by_id.items()
                    if any(row['status'] == 'fail' for row in values))
    verdict = ('fail' if failed else 'unknown' if duplicate or missing or nonpass else 'pass')
    return {'verdict': verdict, 'required_count': len(required), 'observed_count': len(rows),
            'missing': missing, 'duplicate': duplicate, 'nonpass': nonpass, 'failed': failed}


def judge_rows_exact(rows, required):
    """v2: planned and observed node sets must be identical.

    Any extra node (for example an unplanned skipped testcase) invalidates the
    case even when every planned node passed.  A real failure anywhere still
    dominates, matching the v1 rule that a failure outside the required subset
    is never hidden.
    """
    base = judge_rows(rows, required)
    by_id = {}
    for row in rows:
        by_id.setdefault(row['id'], []).append(row)
    extra = sorted(set(by_id) - set(required))
    verdict = base['verdict']
    if verdict != 'fail' and extra:
        verdict = 'unknown'
    return {**base, 'extra': extra, 'verdict': verdict}


def judge_session(plan, results, root=ROOT):
    """Judge explicit source-bound receipts; never infer current credit from history."""
    catalog = read_catalog(root)
    suites = {suite['id']: suite for suite in catalog['suites']}
    if plan.get('catalog_sha256') != sha256(Path(root) / 'docs/acceptance/catalog.json'):
        raise ValueError('plan catalog identity changed')
    if plan.get('schema') != PLAN_V1:
        raise ValueError('unknown plan schema')
    required = plan.get('required_suites')
    if not isinstance(required, list) or not required or len(required) != len(set(required)):
        raise ValueError('invalid required suite list')
    if set(required) - set(suites):
        raise ValueError('unknown required suite')
    if not isinstance(plan.get('candidate'), dict) or not plan['candidate']:
        raise ValueError('explicit candidate identity required')
    receipts = {}
    for result in results:
        key = result.get('suite_id')
        if key not in required or key in receipts:
            raise ValueError('duplicate or unplanned suite result')
        receipts[key] = result
    outcomes = []
    for key in required:
        result = receipts.get(key)
        if result is None:
            outcomes.append({'id': key, 'status': 'not_run'})
            continue
        if result.get('candidate') != plan['candidate']:
            raise ValueError('candidate mismatch: ' + key)
        if result.get('execution_id') != plan.get('execution_id') or not plan.get('execution_id'):
            raise ValueError('execution mismatch: ' + key)
        expected_sources = plan.get('source_hashes', {}).get(key)
        if not isinstance(expected_sources, dict) or not expected_sources:
            raise ValueError('missing planned source bindings: ' + key)
        if result.get('source_hashes') != expected_sources:
            raise ValueError('source mismatch: ' + key)
        for name, digest in expected_sources.items():
            path = Path(root) / name
            if Path(name).is_absolute() or '..' in Path(name).parts or not path.is_file() or sha256(path) != digest:
                raise ValueError('current source changed: ' + name)
        checks = plan.get('required_checks', {}).get(key)
        if result.get('evidence_level') != suites[key]['evidence_level']:
            raise ValueError('evidence level mismatch: ' + key)
        if not isinstance(result.get('artifacts'), list) or not result['artifacts']:
            raise ValueError('original artifacts required: ' + key)
        parsed = []
        for artifact in result['artifacts']:
            path = Path(artifact['path'])
            if not path.is_absolute() or not path.is_file() or sha256(path) != artifact['sha256']:
                raise ValueError('missing or changed original artifact: ' + str(path))
            if artifact.get('format') == 'tsv':
                parsed.extend(parse_tsv(path))
            elif artifact.get('format') == 'junit':
                parsed.extend(parse_junit(path))
        # Recompute from explicitly bound raw result files. A hand-written
        # receipt's `checks` or `verdict` is never an acceptance authority.
        if not parsed:
            raise ValueError('no supported original result adapter: ' + key)
        evaluation = judge_rows(parsed, checks)
        status = evaluation['verdict']
        if result.get('returncode') != 0 and status == 'pass':
            status = 'fail'
        if result.get('cleanup_complete') is not True and status == 'pass':
            status = 'unknown'
        outcomes.append({'id': key, 'status': status, 'evaluation': evaluation})
    evaluation = judge_rows(outcomes, required)
    full_set = {row['id'] for row in catalog['suites'] if row.get('required_for_full')}
    full_coverage = full_set.issubset(set(required))
    pending = sorted(row['id'] for row in catalog['suites']
                     if row.get('required_for_full') and row.get('oracle_status') != 'ready')
    return {'schema': SUMMARY_V1, 'candidate': plan['candidate'],
            'execution_id': plan.get('execution_id'), 'suites': outcomes, **evaluation,
            'coverage': 'full_catalog' if full_coverage else 'selected',
            'full_catalog_pass': full_coverage and not pending and evaluation['verdict'] == 'pass',
            'unimplemented_or_incomplete_oracles': pending,
            'unselected': sorted(full_set - set(required)),
            'limitation': 'Checks cover the declared contract, not all possible future behavior.'}


def make_plan(root=ROOT):
    value = inventory(root)
    hashes = {}
    for suite in value['suites']:
        hashes[suite['id']] = {row['path']: row['sha256'] for row in value['files']
                               if suite['id'] in row['suites']}
    return {'schema': PLAN_V1, 'execution_id': str(uuid.uuid4()),
            'catalog_sha256': value['catalog_sha256'], 'candidate': {},
            'required_suites': [row['id'] for row in value['suites'] if row.get('required_for_full')],
            'source_hashes': hashes, 'required_checks': {}, 'qualification': 'not_run',
            'instructions': ['Fill actual candidate identity before executing any suite.',
                             'Freeze exact required case IDs from original runtime collection or reviewed native/manual plan.',
                             'Do not omit pending/manual requirements or convert OBSERVED into PASS.',
                             'Original runners retain environment authorization, cleanup and recovery ownership.']}


def launch(suite_id, arguments, output, root=ROOT, python=sys.executable):
    """Execute one registered original entry, never an implicit all-native run.

    The execution receipt deliberately contains no acceptance verdict. Original
    full evidence must be supplied to judge; native cleanup stays in that driver.
    """
    root = Path(root)
    catalog = read_catalog(root)
    suite = next((row for row in catalog['suites'] if row['id'] == suite_id), None)
    if suite is None or not suite.get('launch'):
        raise ValueError('suite has no automated entry; follow catalog procedure')
    launch_spec = suite['launch']
    if launch_spec.get('platform') == 'windows' and sys.platform != 'win32':
        raise ValueError('this original entry runs only inside the Windows VM')
    if launch_spec.get('platform') == 'windows':
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            raise ValueError('run the original Windows entry in an administrator VM terminal')
        probe = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command',
                                "$c=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop; "
                                "Write-Output ($c.Manufacturer+' '+$c.Model)"],
                               capture_output=True, text=True, timeout=30, check=False)
        if probe.returncode or not re.search(r'virtual|vmware|virtualbox|kvm|qemu|hyper-v|xen|parallels',
                                            probe.stdout, re.IGNORECASE):
            raise ValueError('known Windows VM identity required before invoking native driver')
    if launch_spec.get('platform') == 'linux-vm' and not sys.platform.startswith('linux'):
        raise ValueError('this original entry runs only inside the Linux VM')
    if not isinstance(arguments, list) or any(not isinstance(item, str) for item in arguments):
        raise ValueError('runner arguments must be a JSON string array')
    if any(re.search(r'(?i)(authorization|bearer|api[-_]?key|password|token)=|[\r\n]', item) for item in arguments):
        raise ValueError('use local authentication/config references, never inline credentials')
    if launch_spec.get('fixed_args') and arguments:
        raise ValueError('this formal entry does not accept partial/alternate arguments')
    command = [python if item == '{python}' else item for item in launch_spec['argv']]
    if command[0] in ('cmd.exe', 'cmd') and arguments:
        raise ValueError('shell entry accepts no extra arguments')
    command += arguments
    output = Path(output).resolve()
    logs = (root / 'Logs').resolve()
    if not output.is_relative_to(logs) or output == logs or output.exists():
        raise ValueError('use a new exact directory under repository Logs')
    output.mkdir(parents=True)
    before = {row['path']: row['sha256'] for row in inventory(root)['files'] if suite_id in row['suites']}
    (output / 'intent.json').write_text(json.dumps({'suite_id': suite_id, 'argv': command,
        'source_hashes': before, 'qualification': 'not_run'}, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    # No extra timeout/kill/retry is layered over native driver recovery.
    # Output remains bounded on disk rather than repeatedly entering AI context.
    try:
        with (output / 'stdout.log').open('xb') as stdout, (output / 'stderr.log').open('xb') as stderr:
            completed = subprocess.run(command, cwd=root / launch_spec.get('cwd', '.'),
                                       stdout=stdout, stderr=stderr, check=False)
    except (OSError, KeyboardInterrupt) as error:
        (output / 'execution-unknown.json').write_text(json.dumps({
            'suite_id': suite_id, 'qualification': 'unknown', 'cleanup_complete': None,
            'error_type': type(error).__name__,
            'instruction': 'Reconcile the original driver and its cleanup before any new execution.'}) + '\n', encoding='utf-8')
        raise
    changed = [name for name, digest in before.items() if not (root / name).is_file() or sha256(root / name) != digest]
    receipt = {'schema': 'fakenet.acceptance-execution.v1', 'suite_id': suite_id,
               'returncode': completed.returncode, 'source_hashes': before,
               'sources_changed': changed, 'qualification': 'unjudged',
               'cleanup_complete': None,
               'instruction': 'Bind original full results and cleanup evidence before judging. Exit zero is not a pass.'}
    (output / 'execution.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return receipt


def markdown(value):
    lines = ['# FakeNet 集中验收清单', '',
             '本清单来自当前源码静态盘点, 不表示任何用例已执行或验收通过.', '',
             '| 分组 | 验收内容 | 执行过程 | 结果判断 |', '| --- | --- | --- | --- |']
    for row in value['suites']:
        cols = [row['id'] + ': ' + row['title'], row['content'], row['procedure'], row['judgment']]
        lines.append('| ' + ' | '.join(str(c).replace('|', '\\|').replace('\n', ' ') for c in cols) + ' |')
    cases = all_cases(value) if value.get('schema') == CATALOG_V2 else []
    if cases:
        lines += ['', '## 功能用例与适用面', '',
                  '| 用例 | 分组 | 平台 | 适配器 | 进入full | 状态 |', '| --- | --- | --- | --- | --- | --- |']
        for case in cases:
            state = ('excluded' if case.get('excluded') else
                     'stress' if case.get('stress') else
                     'blocked' if case.get('adapter') != 'offline-pytest' else 'offline')
            lines.append('| `%s` | %s | %s | %s | %s | %s |' % (
                case['id'], case['suite_id'], ', '.join(case['platforms']),
                case['adapter'], 'no' if case.get('stress') or case.get('excluded') else 'yes',
                state))
    for suite in value['suites']:
        lines += ['', '## ' + suite['id'] + ' ' + suite['title'], '',
                  '证据级别: ' + suite['evidence_level'], '']
        if suite.get('s1_note'):
            lines += ['S1 处置: ' + suite['s1_note'], '']
        lines += ['前置条件: ' + suite['prerequisites'], '',
                  '原入口/来源: ' + ', '.join('`' + p + '`' for p in suite['sources']), '',
                  '结果与原件: ' + suite['outputs'], '',
                  '限制/待补: ' + suite['limitations']]
        if suite.get('disposition'):
            lines += ['', '范围处置: ' + suite['disposition']]
    lines += ['', '## 逐文件和逐项索引', '',
              '用 inventory --format json 导出源码位置、完整哈希、测试函数、断言及原生结果声明.', '',
              '| 文件 | 所属分组 | 静态声明数 |', '| --- | --- | --- |']
    for row in value['files']:
        lines.append('| `%s` | %s | %d |' % (row['path'], ', '.join(row['suites']), len(row['items'])))
    lines += ['', '未归类入口: ' + (', '.join(value['unclassified']) or '无'), '']
    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# v2: catalog cases, explicit candidate/environment plans, offline execution.
# ---------------------------------------------------------------------------


def git_head(root):
    root = Path(root).resolve()
    top = subprocess.run(['git', '-C', str(root), 'rev-parse', '--show-toplevel'],
                         capture_output=True, text=True, check=False)
    if top.returncode != 0 or Path(top.stdout.strip()).resolve() != root:
        raise InputError('root is not the top of a Git work tree: %s' % root)
    completed = subprocess.run(['git', '-C', str(root), 'rev-parse', 'HEAD'],
                               capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise InputError('cannot resolve product HEAD: %s' % completed.stderr.strip())
    return completed.stdout.strip()


def _resolve_source_commit(root, candidate):
    try:
        return git_head(root)
    except InputError:
        # Explicit fixture-only escape: a temporary product root used by the
        # facility self-tests has no Git history. The plan records that the
        # identity was declared, never that it was verified against Git.
        if candidate.get('offline_fixture') is True:
            return candidate['source_commit']
        raise


def load_candidate(path):
    value = read_json(path)
    if value.get('schema') != CANDIDATE_V2:
        raise InputError('unknown candidate schema: %r' % value.get('schema'))
    if not isinstance(value.get('source_commit'), str) or not value['source_commit']:
        raise InputError('candidate.source_commit is required')
    for key in ('package_manifest', 'package_sha256', 'deployed_identity'):
        value.setdefault(key, None)
    return value


def load_environment(path):
    value = read_json(path)
    if value.get('schema') != ENVIRONMENT_V2:
        raise InputError('unknown environment schema: %r' % value.get('schema'))
    interpreters = value.get('interpreters')
    if not isinstance(interpreters, dict) or not interpreters.get('python'):
        raise InputError('environment.interpreters.python is required')
    python = Path(interpreters['python'])
    if not python.is_file():
        raise InputError('environment interpreter is missing: %s' % python)
    work_root = value.get('work_root')
    if not isinstance(work_root, str) or not Path(work_root).is_absolute():
        raise InputError('environment.work_root must be an absolute path')
    actions = value.get('allowed_actions')
    if not isinstance(actions, list) or not actions:
        raise InputError('environment.allowed_actions is required')

    def scan(node, trail=()):
        if isinstance(node, dict):
            for key, child in node.items():
                lowered = str(key).lower()
                if any(word in lowered for word in ('password', 'secret', 'token', 'private_key')):
                    raise InputError('environment must not embed secrets: %s' % '.'.join(trail + (str(key),)))
                scan(child, trail + (str(key),))
        elif isinstance(node, list):
            for index, child in enumerate(node):
                scan(child, trail + (str(index),))

    scan(value)
    return value


def select_cases(catalog, mode, suite_ids, case_ids):
    cases = all_cases(catalog)
    if mode == 'full':
        selected = [case for case in cases
                    if case.get('required_for_full', True)
                    and not case.get('stress') and not case.get('excluded')]
        exclusions = [{'id': case['id'], 'basis': case.get('excluded_basis') or 'excluded'}
                      for case in cases if case.get('excluded')]
    elif mode == 'stress':
        selected = [case for case in cases if case.get('stress') and not case.get('excluded')]
        exclusions = []
    elif mode == 'selected':
        if not suite_ids and not case_ids:
            raise InputError('plan --mode selected requires --suite or --case')
        selected = [case for case in cases
                    if case['suite_id'] in set(suite_ids) or case['id'] in set(case_ids)]
        missing_suites = sorted(set(suite_ids) - {case['suite_id'] for case in cases})
        if missing_suites:
            raise InputError('unknown suite selection: %r' % missing_suites)
        missing_cases = sorted(set(case_ids) - {case['id'] for case in cases})
        if missing_cases:
            raise InputError('unknown case selection: %r' % missing_cases)
        if any(case.get('excluded') for case in selected):
            raise InputError('selected set contains an excluded case')
        exclusions = []
    else:
        raise InputError('unknown plan mode: %r' % mode)
    if not selected:
        raise InputError('selection is empty')
    return selected, exclusions


def case_sources(case):
    sources = case.get('sources')
    if not sources:
        data = case.get('input') or {}
        modules = data.get('modules') or ([data['module']] if data.get('module') else [])
        sources = list(modules)
    return [str(item) for item in sources]


CASE_IDENTITY_FIELDS = (
    'id', 'suite_id', 'title', 'platforms', 'modes', 'input', 'steps',
    'expected', 'oracle', 'resources', 'readiness', 'timeout', 'cleanup',
    'dependencies', 'adapter', 'native_driver', 'collection_safe', 'collection_profile',
    'required_for_full', 'stress', 'sources', 'blocked_reason',
)

# These are the only cases that may carry an old package source while the
# current harness is a different commit.  The set is intentionally closed:
# source, runtime and mixed selections must keep the original HEAD gate.
PACKAGE_LAYER_CASES = frozenset({
    'BUILD-PACKAGE-IDENTITY',
    'MCP-P01-FULL', 'MCP-P02-FULL', 'MCP-P03-FULL', 'MCP-P04-FULL',
    'MCP-SPECIAL-IPC', 'MCP-SPECIAL-FAULT-RECOVERY',
})


def case_identity(case):
    return {key: case.get(key) for key in CASE_IDENTITY_FIELDS}


def expected_case_ids(catalog, mode):
    cases = all_cases(catalog)
    if mode == 'full':
        return [case['id'] for case in cases
                if case.get('required_for_full', True)
                and not case.get('stress') and not case.get('excluded')]
    if mode == 'stress':
        return [case['id'] for case in cases
                if case.get('stress') and not case.get('excluded')]
    if mode == 'selected':
        return None
    raise InputError('unknown plan mode: %r' % mode)


def environment_platforms(environment):
    mapping = {
        'host-linux': 'linux', 'linux-vm': 'linux', 'linux': 'linux',
        'host-windows': 'windows', 'windows-vm': 'windows', 'windows': 'windows',
        'any': 'any',
    }
    targets = environment.get('targets')
    if not isinstance(targets, list) or not targets:
        raise InputError('environment.targets is required')
    platforms = set()
    for target in targets:
        if not isinstance(target, str) or target not in mapping:
            raise InputError('unknown environment target: %r' % (target,))
        platforms.add(mapping[target])
    return platforms


def case_applicable(case, platforms):
    declared = set(case.get('platforms') or [])
    return bool(declared & platforms) or 'any' in declared


def is_package_layer(root, cases, catalog, environment, candidate):
    """Return whether this exact registered selection is package-only.

    The check starts from the actual catalog registration, driver dispatch and
    expanded check selection.  A name, a directory or a stored plan flag can
    never create the exception by itself.  MCP cases additionally need the
    original input validator to accept the package/manifest/source/target
    identity; without that evidence the selection keeps the normal HEAD gate.
    """
    if acceptance_native is None or not isinstance(candidate, dict):
        return False
    ids = {case.get('id') for case in cases}
    if not ids or not ids.issubset(PACKAGE_LAYER_CASES):
        return False
    registered = {case['id']: case for case in all_cases(catalog)}
    drivers = acceptance_native.driver_table(root)
    for case in cases:
        if (case.get('adapter') != 'native' or case.get('id') not in registered
                or case_identity(case) != case_identity(registered[case['id']])):
            return False
        case_id = case.get('id')
        driver = drivers.get(case.get('native_driver'))
        if not isinstance(driver, dict) or not driver.get('implemented'):
            return False
        kind = driver.get('production_kind')
        if case_id == 'BUILD-PACKAGE-IDENTITY':
            if case.get('native_driver') != 'build-identity' or kind != 'package-identity':
                return False
            continue
        if case.get('native_driver') != 'mcp-headless' or kind != 'mcp-controller':
            return False
        try:
            unused, checks = acceptance_native.validate_case(case, root, environment)
            import acceptance_mcp
            inputs, selected = acceptance_mcp.validate_inputs(
                (environment or {}).get('mcp'), case_id, checks,
                fixture=candidate.get('offline_fixture') is True)
            identity = inputs.get('identity') or {}
            if (list(selected) != list(checks)
                    or identity.get('source_commit') != candidate.get('source_commit')
                    or identity.get('package_sha256') != candidate.get('package_sha256')
                    or Path(inputs.get('package', '')).resolve() != Path(candidate.get('package_path', '')).resolve()
                    or Path(inputs.get('manifest', '')).resolve() != Path(candidate.get('package_manifest', '')).resolve()):
                raise InputError('MCP package candidate differs from frozen input: ' + case_id)
            runtime_target = environment.get('native_runtime', {}).get('identity', {})
            if any(inputs['target'][key] != runtime_target.get(key)
                   for key in ('platform', 'hostname', 'vm_uuid')):
                raise InputError('MCP target differs from frozen Windows target: ' + case_id)
        except InputError:
            raise
        except (OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
            raise InputError('MCP package input refused: %s: %s' % (case_id, exc)) from exc
    return True


def _frozen_source_paths(plan, registered, required):
    paths = set()
    for case_id in required:
        paths.update(case_sources(registered[case_id]))
    pins = plan.get('native_source_hashes')
    if isinstance(pins, dict):
        paths.update(str(name) for name in pins)
    return sorted(paths)


def _git_objects_equal(root, source_commit, head, paths):
    if source_commit == head:
        return True
    if not paths:
        return False
    request = ''.join('%s:%s\n%s:%s\n' % (source_commit, name, head, name)
                      for name in paths)
    completed = subprocess.run(
        ['git', '-C', str(Path(root)), 'cat-file', '--batch-check'],
        input=request, capture_output=True, text=True, timeout=30, check=False)
    if completed.returncode != 0:
        return False
    lines = completed.stdout.splitlines()
    if len(lines) != 2 * len(paths):
        return False
    for index in range(0, len(lines), 2):
        left, right = lines[index].split(), lines[index + 1].split()
        if (len(left) < 2 or len(right) < 2 or left[1] != 'blob'
                or right[1] != 'blob' or left[0] != right[0]):
            return False
    return True


def source_plan_head_allowed(root, plan, candidate, registered=None):
    """Allow only unrelated-commit drift for an already frozen source plan."""
    source = plan.get('source_commit')
    if plan.get('source_reuse') is not None:
        import acceptance_source_identity as source_identity
        if not isinstance(registered, dict):
            return False
        return source_identity.validate_plan(root, plan, registered,
                                             plan.get('required_cases') or [])
    try:
        head = git_head(root)
    except InputError:
        # Preserve the existing explicit no-Git fixture branch.  It earns
        # fixture credit only; no real source identity is inferred.
        if isinstance(candidate, dict) and candidate.get('offline_fixture') is True:
            return True
        raise
    if source == head:
        return True
    pins = plan.get('native_source_hashes')
    if not isinstance(pins, dict) or not pins or not isinstance(registered, dict):
        return False
    paths = _frozen_source_paths(plan, registered, plan.get('required_cases') or [])
    return _git_objects_equal(root, str(source), head, paths)



# These cases are collection-safe only in the measured contained profiles.
# The ordinary boolean is deliberately false; it is never a caller bypass.
CONTAINED_COLLECTION_CASES = {
    'CORE-WINDOWS-OFFLINE': ('wine-contained-v1', (
        'test/test_windows_process_redirect.py',
        'test/test_windows_process_owner.py',
        'test/test_windows_egress_verdict.py')),
    'MCP-UNIT-PRODUCT': ('linux-contained-v1', (
        'test/mcp/test_command_status.py', 'test/mcp/test_capture_health.py')),
    'MCP-UNIT-TOOLING': ('linux-contained-v1', (
        'test/mcp/test_acceptance_evidence_writer.py', 'test/mcp/test_bounded_mcp.py')),
}
CONTAINED_IMAGE = 'sha256:1b33b518a7c71ecd13264f0d1c41faf254e301b8702e2da8ca11376cff700a5e'


def _contained_kernel(root, work_root):
    """Observe the live boundary, independently of supplied environment JSON."""
    import os
    if os.name != 'posix' or os.geteuid() == 0 or not Path('/.dockerenv').is_file():
        raise ValueError('contained collection requires a non-root container')
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines()
                  if ':' in line)
    if int(status.get('CapEff', '1').strip(), 16) or status.get('NoNewPrivs', '').strip() != '1':
        raise ValueError('container capabilities or privilege escalation are enabled')
    if {path.name for path in Path('/sys/class/net').iterdir()} != {'lo'}:
        raise ValueError('container has an external network interface')
    for path in (Path('/'), Path(root), Path('/run-control')):
        if not os.statvfs(path).f_flag & os.ST_RDONLY:
            raise ValueError('container root, source and controls must be read-only')
    work_root = Path(work_root)
    if (not work_root.is_absolute() or work_root.resolve() != work_root
            or not work_root.is_relative_to(Path('/out'))
            or work_root.is_relative_to(Path(root).resolve())
            or os.statvfs(work_root).f_flag & os.ST_RDONLY):
        raise ValueError('contained output is not a separate writable /out directory')
    return os.uname().nodename


def _read_containment_witness(profile):
    path = Path(profile['attestation'])
    if (not path.is_absolute() or path.resolve() != path
            or path.parent != Path('/run-control') or not path.is_file()):
        raise ValueError('attestation must be the read-only controller original')
    raw = path.read_bytes()
    if len(raw) > 2**20 or hashlib.sha256(raw).hexdigest() != profile['sha256']:
        raise ValueError('contained attestation changed')
    return json.loads(raw)


def contained_collection_context(case, root, environment):
    """Finite, source-bound exception; returns evidence, never global safety."""
    import os
    profile = (environment or {}).get('collection_profile')
    if not isinstance(profile, dict) or set(profile) != {'kind', 'attestation', 'sha256'}:
        raise ValueError('collection is not authorised for this case')
    expected = CONTAINED_COLLECTION_CASES.get(case.get('id'))
    modules = (case.get('input') or {}).get('modules')
    if (expected is None or case.get('collection_profile') != expected[0]
            or profile['kind'] != expected[0] or modules != list(expected[1])):
        raise ValueError('contained profile or exact module selection differs')
    required_platform = 'windows' if expected[0] == 'wine-contained-v1' else 'linux'
    if required_platform not in environment_platforms(environment):
        raise ValueError('contained profile does not match the target platform')
    root = Path(root).resolve()
    hostname = _contained_kernel(root, environment.get('work_root', ''))
    witness = _read_containment_witness(profile)
    if (witness.get('schema') != 'fakenet.contained-collection.v1'
            or witness.get('image') != CONTAINED_IMAGE
            or witness.get('container_id', '')[:12] != hostname
            or witness.get('source_root') != str(root)
            or witness.get('work_root') != environment['work_root']):
        raise ValueError('contained image, instance or source/output binding differs')
    source_hashes = witness.get('source_hashes')
    required_sources = set(modules) | {'tools/acceptance.py', 'docs/acceptance/catalog.json'}
    if acceptance_native is not None:
        required_sources.update(acceptance_native.native_source_pins(root))
    if (not isinstance(source_hashes, dict) or not source_hashes
            or not required_sources.issubset(source_hashes)):
        raise ValueError('contained source snapshot is incomplete')
    for name, digest in source_hashes.items():
        relative = Path(name)
        actual = root / relative
        if (relative.is_absolute() or '..' in relative.parts
                or actual.resolve() != actual or not actual.is_file()
                or sha256(actual) != digest):
            raise ValueError('contained source changed: ' + name)
    interpreter = Path(environment.get('interpreters', {}).get('python', ''))
    bound = witness.get('interpreters', {}).get(profile['kind'])
    if (profile['kind'] == 'linux-contained-v1'
            and interpreter.resolve() != Path(sys.executable).resolve()):
        raise ValueError('Linux collection must use the active pinned interpreter')
    if (not isinstance(bound, dict) or str(interpreter) != bound.get('path')
            or not interpreter.is_file() or sha256(interpreter) != bound.get('sha256')):
        raise ValueError('contained interpreter changed')
    dependencies = bound.get('dependencies')
    if not isinstance(dependencies, dict) or not dependencies:
        raise ValueError('contained interpreter dependencies are not pinned')
    for name, digest in dependencies.items():
        dependency = Path(name)
        if not dependency.is_absolute() or not dependency.is_file() or sha256(dependency) != digest:
            raise ValueError('contained dependency changed: ' + name)
    if profile['kind'] == 'wine-contained-v1':
        import zipfile
        wheel = root / 'wheelhouse/pydivert-2.1.0-py2.py3-none-any.whl'
        if (bound.get('pydivert_version') != '2.1.0'
                or sha256(wheel) != '382db488e3c37c03ec9ec94e061a0b24334d78dbaeebb7d4e4d32ce4355d9da1'):
            raise ValueError('contained Wine dependency must be the pinned pydivert 2.1.0')
        installed = Path(bound.get('pydivert_root', ''))
        if not installed.is_absolute() or not installed.is_relative_to(Path('/out')):
            raise ValueError('Wine dependencies must belong to this output prefix')
        with zipfile.ZipFile(wheel) as archive:
            for entry in archive.infolist():
                if entry.filename.startswith('pydivert/') and not entry.is_dir():
                    actual = installed / entry.filename.removeprefix('pydivert/')
                    if not actual.is_file() or sha256(actual) != hashlib.sha256(archive.read(entry)).hexdigest():
                        raise ValueError('installed pydivert differs from the pinned wheel')
    return {'profile': profile['kind'], 'container_id': witness['container_id'],
            'image': witness['image'], 'source_commit': witness['source_commit'],
            'attestation_sha256': profile['sha256'], 'interpreter_sha256': bound['sha256']}


def collection_authorized(case, root, environment):
    if case.get('collection_safe'):
        return True
    try:
        contained_collection_context(case, root, environment)
        return True
    except (ValueError, OSError, KeyError, TypeError):
        return False


def collection_context(case, root, environment):
    if case.get('collection_safe'):
        return None
    return contained_collection_context(case, root, environment)


def expected_block(case, actions, platforms, root=ROOT, environment=None, candidate=None):
    """Return the only admissible blocked reason, or None if runnable."""
    if case['adapter'] == 'native':
        if acceptance_native is None:
            return 'native adapter module is unavailable'
        drivers = acceptance_native.driver_table(root)
        name = case.get('native_driver')
        if not name or name not in drivers:
            return 'native driver is not registered'
        driver = drivers[name]
        if not driver.get('implemented'):
            return driver.get('missing') or 'native driver is not implemented'
        if driver.get('production_kind','').startswith('manual-') and (environment or {}).get('native_runtime',{}).get('transport')=='manual-loopback-fixture':
            return acceptance_native.manual_fixture_block(environment or {},candidate or {})
        if not case_applicable(case, platforms):
            return 'platform not available in environment'
        if driver.get('production_kind') == 'package-identity':
            try:
                __import__('acceptance_package').freeze_candidate({k:v for k,v in (candidate or {}).items() if k != 'package_identity_error'})
            except (OSError, ValueError, KeyError, TypeError) as exc:
                return 'package identity input unavailable: ' + str(exc)
            return None if ('offline-artifacts' in actions or 'native' in actions) else 'environment does not allow read-only offline-artifacts'
        if 'native' not in actions:
            return 'environment does not allow native execution'
        if driver.get('production_kind'):
            return acceptance_native.runtime_block(case,environment or {})
        return None
    if case['adapter'] != 'offline-pytest':
        return case.get('blocked_reason') or 'adapter is not implemented'
    if not collection_authorized(case, root, environment):
        return 'collection is not authorised for this case'
    if 'collection' not in actions:
        return 'environment does not allow collection'
    if not case_applicable(case, platforms):
        return 'platform not available in environment'
    if 'offline-pytest' not in actions:
        return 'environment does not allow offline-pytest execution'
    return None


def validate_plan_registry(root, plan, plan_path=None, require_execute_action=False):
    """Recompute the plan's registry, source and block state from the catalog.

    The plan is never trusted for its own mode, case set, adapter, oracle or
    blocked map.  This is the single validation used by execute and judge.
    """
    root = Path(root)
    catalog = read_catalog(root)
    if plan.get('schema') != PLAN_V2:
        raise InputError('expected plan v2, got %r' % plan.get('schema'))
    if plan.get('catalog_sha256') != sha256(root / 'docs/acceptance/catalog.json'):
        raise InputError('catalog changed since plan')
    mode = plan.get('mode')
    if mode not in ('full', 'selected', 'stress'):
        raise InputError('unknown plan mode: %r' % mode)
    registered = {case['id']: case for case in all_cases(catalog)}
    if plan.get('native_source_hashes') is not None and acceptance_native is not None:
        if plan['native_source_hashes']!=acceptance_native.native_source_pins(root):
            raise InputError('native candidate source changed since plan')
    required = plan.get('required_cases')
    if (not isinstance(required, list) or not required
            or any(not isinstance(item, str) or not item for item in required)):
        raise InputError('plan.required_cases must be a nonempty string list')
    if len(required) != len(set(required)):
        raise InputError('plan.required_cases contains duplicates')
    unknown = sorted(set(required) - set(registered))
    if unknown:
        raise InputError('plan contains unregistered cases: %r' % unknown)
    expected = expected_case_ids(catalog, mode)
    if mode == 'full' and set(required) != set(expected):
        raise InputError('full plan does not cover the catalog full set: missing=%r extra=%r'
                         % (sorted(set(expected) - set(required)),
                            sorted(set(required) - set(expected))))
    if mode == 'stress' and not set(required).issubset(set(expected)):
        raise InputError('stress plan contains non-stress cases: %r'
                         % sorted(set(required) - set(expected)))
    if mode == 'selected':
        if any(registered[item].get('stress') for item in required):
            raise InputError('selected plan contains stress-only cases')
        if any(registered[item].get('excluded') for item in required):
            raise InputError('selected plan contains excluded cases')
    __import__('acceptance_mcp_dependencies').validate_plan_order(plan)
    environment = plan.get('environment')
    if not isinstance(environment, dict):
        raise InputError('plan.environment is required')
    actions = environment.get('allowed_actions')
    if not isinstance(actions, list) or not actions:
        raise InputError('plan environment.allowed_actions is required')
    platforms = environment_platforms(environment)
    candidate = plan.get('candidate')
    if not isinstance(candidate, dict) or candidate.get('source_commit') != plan.get('source_commit'):
        raise InputError('plan candidate/source_commit mismatch')
    package_selection = is_package_layer(
        root, [registered[item] for item in required], catalog, environment, candidate)
    if not package_selection:
        deployed = candidate.get('deployed_identity')
        runtime = environment.get('native_runtime') or {}
        target = runtime.get('identity') if isinstance(runtime, dict) else None
        if isinstance(deployed, dict) and isinstance(target, dict) and deployed != target:
            raise InputError('source plan target differs from candidate deployed identity')
    if (set(required) & PACKAGE_LAYER_CASES
            and not isinstance(plan.get('native_source_hashes'), dict)):
        raise InputError('package execution requires complete native source pins')
    if package_selection:
        # Bind the package manifest as part of planning.  A blocked BUILD-only
        # input keeps its original blocked state; every runnable package-layer
        # selection must already carry the frozen manifest hash.
        build_selected = 'BUILD-PACKAGE-IDENTITY' in required
        rpc_cases = [item for item in required if item != 'BUILD-PACKAGE-IDENTITY']
        if rpc_cases or not build_selected:
            try:
                frozen = __import__('acceptance_package').freeze_candidate(candidate)
            except (OSError, ValueError, KeyError, TypeError) as exc:
                raise InputError('package identity input unavailable: %s' % exc) from exc
            if frozen != candidate:
                raise InputError('package candidate identity was not frozen at planning')
    else:
        if not source_plan_head_allowed(root, plan, candidate, registered):
            raise InputError('source plan is not valid for the current HEAD and frozen pins')
    for case_id in required:
        reference = registered[case_id]
        if reference.get('native_driver') != 'mcp-headless':
            continue
        try:
            unused, checks = acceptance_native.validate_case(reference, root, environment)
            import acceptance_mcp
            inputs, unused_selected = acceptance_mcp.validate_inputs(
                environment.get('mcp'), case_id, checks,
                fixture=candidate.get('offline_fixture') is True)
            identity = inputs.get('identity') or {}
            if (identity.get('source_commit') != candidate.get('source_commit')
                    or identity.get('package_sha256') != candidate.get('package_sha256')
                    or Path(inputs.get('package', '')).resolve() != Path(candidate.get('package_path', '')).resolve()
                    or Path(inputs.get('manifest', '')).resolve() != Path(candidate.get('package_manifest', '')).resolve()):
                raise InputError('MCP package candidate differs from the frozen input: ' + case_id)
        except InputError:
            raise
        except (OSError, ValueError, KeyError, TypeError, RuntimeError):
            # Full/mixed plans retain missing-environment blocked entries.
            # The registered blocked reason is rechecked below; a previously
            # runnable plan with changed input cannot reach a driver. Package-
            # only input errors already fail in is_package_layer above.
            continue
    if require_execute_action:
        has_offline = any(registered[item]['adapter'] == 'offline-pytest'
                          for item in required)
        blocked_now = plan.get('blocked') or {}
        has_native = any(registered[item]['adapter'] == 'native'
                         and registered[item].get('native_driver') != 'build-identity'
                         and item not in blocked_now for item in required)
        if has_offline and 'offline-pytest' not in actions:
            raise InputError('environment.allowed_actions does not permit offline-pytest execution')
        if has_native and 'native' not in actions:
            raise InputError('environment.allowed_actions does not permit native execution')
    cases = plan.get('cases')
    if not isinstance(cases, dict) or set(cases) != set(required):
        raise InputError('plan.cases does not match required_cases')
    blocked = plan.get('blocked')
    if not isinstance(blocked, dict) or not set(blocked).issubset(set(required)):
        raise InputError('plan.blocked is invalid')
    source_hashes = plan.get('source_hashes')
    checks = plan.get('required_checks')
    if not isinstance(source_hashes, dict) or set(source_hashes) != set(required):
        raise InputError('plan.source_hashes does not match required_cases')
    if not isinstance(checks, dict) or set(checks) != set(required):
        raise InputError('plan.required_checks does not match required_cases')
    for case_id in required:
        reference = registered[case_id]
        stored = cases[case_id]
        if not isinstance(stored, dict):
            raise InputError('planned case is not an object: %s' % case_id)
        if case_identity(stored) != case_identity(reference):
            raise InputError('planned case identity differs from catalog: %s' % case_id)
        expected_reason = expected_block(reference, actions, platforms, root, environment, candidate)
        if reference.get('collection_profile') and expected_reason is None:
            context = collection_context(reference, root, environment)
            if (stored.get('collection_context') != context
                    or context['source_commit'] != plan.get('harness_commit')):
                raise InputError('collection context differs from frozen plan: ' + case_id)
        actual_reason = blocked.get(case_id)
        if (expected_reason or None) != (actual_reason or None):
            raise InputError('blocked state differs from registry: %s expected=%r actual=%r'
                             % (case_id, expected_reason, actual_reason))
        sources = case_sources(reference)
        if set(source_hashes[case_id]) != set(sources):
            raise InputError('source set differs from catalog: %s' % case_id)
        for name, digest in source_hashes[case_id].items():
            path = root / name
            if not path.is_file() or sha256(path) != digest:
                raise InputError('source changed since plan: %s' % name)
        planned_checks = checks[case_id]
        run_nodes = stored.get('run_nodes') or []
        if not isinstance(planned_checks, list) or len(planned_checks) != len(set(planned_checks)):
            raise InputError('planned checks are not unique: %s' % case_id)
        if reference['adapter'] == 'native':
            unused_driver, expected_checks = acceptance_native.validate_case(reference, root, environment)
            if planned_checks != expected_checks:
                raise InputError('native checks differ from the registered table: %s' % case_id)
            if run_nodes:
                raise InputError('native case must not carry pytest run nodes: %s' % case_id)
        elif planned_checks:
            if not run_nodes:
                raise InputError('planned checks without run nodes: %s' % case_id)
            if [junit_node(node) for node in run_nodes] != planned_checks:
                raise InputError('planned checks differ from collected nodes: %s' % case_id)
            collection_log = stored.get('collection_log')
            collection_sha = stored.get('collection_sha256')
            if not collection_log or not collection_sha:
                raise InputError('collection evidence is missing: %s' % case_id)
            log_path = Path(collection_log)
            run_root = Path(plan.get('run_dir', '')).resolve()
            if not log_path.is_absolute() or not log_path.is_file():
                raise InputError('collection log is missing: %s' % case_id)
            if not log_path.resolve().is_relative_to(run_root):
                raise InputError('collection log escapes the run directory: %s' % case_id)
            if sha256(log_path) != collection_sha:
                raise InputError('collection log changed: %s' % case_id)
            log_text = log_path.read_text(encoding='utf-8', errors='replace')
            collected_nodes = collection_nodes(log_text)
            for node in run_nodes:
                if node not in collected_nodes:
                    raise InputError('planned node is absent from collection log: %s' % case_id)
            if run_nodes != collected_nodes:
                raise InputError('planned nodes differ from complete collection: %s' % case_id)
        elif stored.get('run_nodes'):
            raise InputError('run nodes without planned checks: %s' % case_id)
        if expected_reason is None and not planned_checks:
            raise InputError('runnable case has no planned checks: %s' % case_id)
    if plan_path is not None:
        if Path(plan.get('run_dir', '')).resolve() != Path(plan_path).parent.resolve():
            raise InputError('plan run_dir does not match plan location')
    return catalog, registered


def case_required_checks(case):
    # Native cases are not adapted in S1.  Their exact runtime node IDs are
    # not known before the adapter exists, so the plan records an empty check
    # list and a blocked reason instead of inventing a node identity.
    return list(case.get('declared_checks') or [])


def collection_nodes(text):
    """Read exact pytest node lines from live output or its saved transcript."""
    nodes = []
    for line in text.splitlines():
        node = line.strip()
        if node.startswith(('$ ', '[exit ')) or '::' not in node:
            continue
        if node.split('::', 1)[0].endswith('.py'):
            nodes.append(node)
    return nodes


def collect_nodes(root, case, python, tmp_dir, log_dir, environment=None):
    before = collection_context(case, root, environment)
    data = case.get('input') or {}
    modules = data.get('modules') or ([data['module']] if data.get('module') else [])
    if not modules:
        raise ToolError('%s has no collectable module' % case['id'])
    log_dir.mkdir(parents=True, exist_ok=True)
    tmp_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / (case['id'] + '-collection.log')
    env = _python_env(root, tmp_dir)
    command = [str(python), '-B', '-m', 'pytest', '--collect-only', '-q', '-p', 'no:cacheprovider',
               '--rootdir', str(root)] + [str(item) for item in modules]
    completed = subprocess.run(command, cwd=root, env=env, capture_output=True,
                               text=True, timeout=case['timeout'], check=False)
    log_path.write_text('$ %s\n[exit %d]\n%s\n%s' % (
        ' '.join(command), completed.returncode, completed.stdout, completed.stderr), encoding='utf-8')
    if collection_context(case, root, environment) != before:
        raise ToolError('collection context changed during collection')
    if completed.returncode != 0:
        raise ToolError('%s collection failed rc=%d log=%s' % (case['id'], completed.returncode, log_path))
    raw_nodes = collection_nodes(completed.stdout)
    if not raw_nodes:
        raise ToolError('%s collection returned no nodes' % case['id'])
    canonical = [junit_node(node) for node in raw_nodes]
    if len(canonical) != len(set(canonical)):
        raise ToolError('%s collection returned duplicate nodes' % case['id'])
    return canonical, raw_nodes, str(log_path)


def _python_env(root, tmp_dir):
    import os
    env = os.environ.copy()
    env['PYTHONPATH'] = str(root)
    env['FN_ACCEPTANCE_NESTED_DEPTH'] = str(acceptance_scheduler.depth_from_environment(env) + 1)
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    env['PYTHONIOENCODING'] = 'utf-8'
    env['TMPDIR'] = str(tmp_dir)
    env['TMP'] = str(tmp_dir)
    env['TEMP'] = str(tmp_dir)
    return env


def make_plan_v2(root, mode, candidate_path, environment_path, suite_ids, case_ids, output):
    root = Path(root)
    catalog = read_catalog(root)
    if catalog.get('schema') != CATALOG_V2:
        raise InputError('plan --mode requires catalog v2')
    candidate = load_candidate(candidate_path)
    environment = load_environment(environment_path)
    selected, exclusions = select_cases(catalog, mode, suite_ids, case_ids)
    # Expand ACC019's fixed predecessor before classifying the selection.  A
    # package-only plan may keep the old package source while the test harness
    # is at HEAD; every other selection retains the original HEAD gate.
    import acceptance_mcp_dependencies
    selected, environment = acceptance_mcp_dependencies.plan_selection(
        selected, catalog, environment, mode)
    package_selection = is_package_layer(root, selected, catalog, environment, candidate)
    current_head = _resolve_source_commit(root, candidate)
    source_reuse = None
    import acceptance_source_identity as source_identity
    try:
        reuse_requested = source_identity.candidate_enabled(candidate)
    except ValueError as exc:
        raise InputError(str(exc)) from exc
    if package_selection:
        head = candidate['source_commit']
    elif candidate['source_commit'] != current_head:
        import acceptance_source_identity as source_identity
        if not reuse_requested:
            raise InputError('candidate.source_commit %s does not match current HEAD %s'
                             % (candidate['source_commit'], current_head))
        selected_sources = [name for case in selected for name in case_sources(case)]
        harness_paths = source_identity.current_harness_paths(root)
        try:
            source_reuse = source_identity.prove(root, candidate['source_commit'],
                                                 selected_sources, current_head,
                                                 harness_paths)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            raise InputError('source reuse proof failed: %s' % exc) from exc
        head = candidate['source_commit']
    else:
        head = current_head
    if package_selection or any(case.get('native_driver') == 'build-identity' for case in selected):
        try:
            candidate = __import__('acceptance_package').freeze_candidate(candidate)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            if any(case.get('id') != 'BUILD-PACKAGE-IDENTITY' for case in selected):
                raise InputError('package identity input unavailable: %s' % exc) from exc
            candidate = dict(candidate, package_identity_error=str(exc))
    output = Path(output)
    run_dir = output.parent
    if output.exists():
        raise InputError('plan output already exists: %s' % output)
    if run_dir.exists() and any(run_dir.iterdir()):
        raise InputError('run directory is not empty: %s' % run_dir)
    work_root = Path(environment['work_root'])
    if not run_dir.resolve().is_relative_to(work_root.resolve()):
        raise InputError('run directory must be under environment.work_root')
    python = environment['interpreters']['python']
    actions = environment['allowed_actions']
    platforms = environment_platforms(environment)
    run_dir.mkdir(parents=True, exist_ok=True)
    tmp_dir = run_dir / 'tmp'
    case_records = {}
    source_hashes = {}
    required_checks = {}
    blocked = {}
    for case in selected:
        sources = case_sources(case)
        hashes = {}
        for name in sources:
            path = root / name
            if not path.is_file():
                raise InputError('%s source missing: %s' % (case['id'], name))
            hashes[name] = sha256(path)
        source_hashes[case['id']] = hashes
        record = dict(case)
        record['sources'] = sources
        reason = expected_block(case, actions, platforms, root, environment, candidate)
        collectable = (case['adapter'] == 'offline-pytest'
                       and collection_authorized(case, root, environment)
                       and 'collection' in actions
                       and case_applicable(case, platforms))
        if case['adapter'] == 'native' and acceptance_native is not None:
            unused, checks = acceptance_native.validate_case(case, root, environment)
            required_checks[case['id']] = list(checks)
            record['required_checks'] = list(checks)
            record['run_nodes'] = []
        elif collectable:
            record['collection_context'] = collection_context(case, root, environment)
            canonical, raw_nodes, log_path = collect_nodes(
                root, case, python, tmp_dir, run_dir / 'collection', environment=environment)
            required_checks[case['id']] = canonical
            record['required_checks'] = canonical
            record['run_nodes'] = raw_nodes
            record['collection_log'] = log_path
            record['collection_sha256'] = sha256(log_path)
        else:
            required_checks[case['id']] = []
            record['required_checks'] = []
            record['run_nodes'] = []
        if reason:
            blocked[case['id']] = reason
        case_records[case['id']] = record
    plan = {
        'native_source_hashes': acceptance_native.native_source_pins(root) if acceptance_native is not None else {},
        'schema': PLAN_V2,
        'execution_id': str(uuid.uuid4()),
        'mode': mode,
        'candidate': candidate,
        'environment': environment,
        'catalog_sha256': sha256(root / 'docs/acceptance/catalog.json'),
        'source_commit': head,
        'harness_commit': current_head,
        'source_reuse': source_reuse,
        'source_hashes': source_hashes,
        'required_cases': [case['id'] for case in selected],
        'required_checks': required_checks,
        'blocked': blocked,
        'exclusions': exclusions,
        'cases': case_records,
        'run_dir': str(run_dir.resolve()),
        'created_at': utc_now(),
    }
    validate_plan_registry(root, plan, output)
    with output.open('x', encoding='utf-8') as stream:
        stream.write(json.dumps(plan, ensure_ascii=False, indent=2) + '\n')
    return plan


def _write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as stream:
        stream.write(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def _hash_record(path, fmt):
    path = Path(path)
    return {'path': str(path.resolve()), 'sha256': sha256(path), 'format': fmt}


def execute_plan(root, plan_path):
    root, plan_path = Path(root), Path(plan_path)
    plan = read_json(plan_path)
    unused_catalog, registered = validate_plan_registry(root, plan, plan_path, require_execute_action=True)
    results_dir = plan_path.parent.resolve() / 'results'
    if results_dir.exists():
        raise InputError('results directory already exists: %s' % results_dir)
    results_dir.mkdir(parents=True)
    python = plan['environment']['interpreters']['python']
    receipts = {}

    def base_receipt(case):
        return {
            'schema': RECEIPT_V2, 'execution_id': plan['execution_id'],
            'suite_id': case['suite_id'], 'case_id': case['id'], 'attempt': 1,
            'adapter': case['adapter'], 'oracle_kind': case['oracle']['kind'],
            'candidate': plan['candidate'], 'environment': plan['environment'],
            'config_sha256': _sha256_json(case),
            'evidence_level': ('offline' if case['adapter'] == 'offline-pytest' else
                               'fixture' if case['adapter'] == 'native' and
                               (plan['candidate'].get('offline_fixture') is True or
                                acceptance_native.is_fixture(case, root)) else 'native'),
        }

    def run_case(case):
        directory = results_dir / case['id']
        directory.mkdir()
        receipt = base_receipt(case)
        try:
            if case['adapter'] == 'offline-pytest':
                receipt.update(_run_offline_case(root, plan, case, directory, python, directory / 'tmp'))
            elif case['adapter'] == 'native':
                receipt['native_driver'] = case.get('native_driver')
                receipt.update(acceptance_native.run_driver(root, case, plan, directory, python))
            else:
                raise ToolError('unregistered executable adapter: %s' % case['adapter'])
        except Exception as exc:
            error = {'type': type(exc).__name__, 'message': str(exc)}
            error_path = directory / 'facility-error.json'
            _write_json(error_path, error)
            receipt.update(status='unknown', returncode=None, command=None,
                           artifacts=[_hash_record(error_path, 'log')],
                           cleanup={'source': 'adapter', 'resources': [], 'process_exit': None},
                           ended_at=utc_now(), facility_error=error)
        return receipt

    def observe(case, receipt):
        # Each worker owns only case artifacts. This owner thread closes every
        # receipt and judges original artifacts before releasing its resources.
        path = results_dir / case['id'] / 'receipt.json'
        _write_json(path, receipt)
        receipts[case['id']] = receipt
        return _judge_execution_case(root, plan, registered[case['id']], receipt)

    cases = [plan['cases'][cid] for cid in plan['required_cases']]
    results, blocked = acceptance_scheduler.run_cases(
        cases, run_case, judge=observe, plan=plan, initial=plan['blocked'])
    for cid, reason in blocked.items():
        case = plan['cases'][cid]
        directory = results_dir / cid
        directory.mkdir()
        receipt = base_receipt(case)
        receipt.update(status='blocked', reason=reason, returncode=None, command=None,
                       started_at=None, ended_at=utc_now(), duration_seconds=0.0,
                       artifacts=[], cleanup={'source': 'adapter', 'resources': [],
                                              'process_exit': None, 'temp_roots': []})
        _write_json(directory / 'receipt.json', receipt)
        receipts[cid] = receipt
    entries = []
    for cid in plan['required_cases']:
        path = results_dir / cid / 'receipt.json'
        if cid not in receipts:
            raise ToolError('scheduler did not settle case: ' + cid)
        entries.append({'case_id': cid, 'path': str(path), 'sha256': sha256(path),
                        'status': receipts[cid]['status']})
    _write_json(results_dir / 'results.json', {
        'schema': RESULTS_V2, 'execution_id': plan['execution_id'],
        'plan': str(plan_path.resolve()), 'plan_sha256': sha256(plan_path), 'receipts': entries})
    summary = judge_v2(root, plan_path, results_dir, plan_path.parent / 'summary.json')
    summary['paths'] = {'plan': str(plan_path.resolve()), 'results': str(results_dir),
                        'summary': str((plan_path.parent / 'summary.json').resolve())}
    return summary


def _sha256_json(value):
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True).encode('utf-8')
    return hashlib.sha256(raw).hexdigest()


def _run_offline_case(root, plan, case, case_dir, python, tmp_dir):
    before = collection_context(case, root, plan['environment'])
    if before != case.get('collection_context'):
        raise ToolError('collection context changed before execution')
    started = datetime.now(timezone.utc)
    checks = case.get('required_checks') or []
    run_nodes = case.get('run_nodes') or []
    if not checks or not run_nodes:
        raise ToolError('%s has no collected nodes' % case['id'])
    junit_path = case_dir / 'junit.xml'
    stdout_path = case_dir / 'stdout.log'
    stderr_path = case_dir / 'stderr.log'
    tmp_dir = Path(tmp_dir)
    tmp_dir.mkdir(parents=True, exist_ok=True)
    command = [str(python), '-B', '-m', 'pytest', '-q', '-p', 'no:cacheprovider', '--disable-warnings',
               '--rootdir', str(root), '--junitxml', str(junit_path)] + list(run_nodes)
    env = _python_env(root, tmp_dir)
    with stdout_path.open('xb') as stdout, stderr_path.open('xb') as stderr:
        observation = acceptance_scheduler.run_owned_process(
            command, cwd=root, env=env, stdout=stdout, stderr=stderr, timeout=case['timeout'])
    if collection_context(case, root, plan['environment']) != before:
        raise ToolError('collection context changed during execution')
    returncode = observation['returncode']
    timed_out = observation['timed_out']
    process_path = case_dir / 'process.json'
    _write_json(process_path, observation)
    ended = datetime.now(timezone.utc)
    artifacts = []
    rows = []
    status = 'unknown'
    detail = ''
    if junit_path.is_file():
        artifacts.append(_hash_record(junit_path, 'junit'))
        try:
            rows = parse_junit(junit_path)
        except (ET.ParseError, ValueError) as error:
            detail = 'junit parse failed: %s' % error
            status = 'unknown'
        else:
            evaluation = judge_rows_exact(rows, checks)
            status = evaluation['verdict']
            detail = json.dumps(evaluation, ensure_ascii=False)
    else:
        detail = 'junit.xml was not produced'
    if timed_out:
        status = 'unknown'
        detail = 'timeout after %ss; %s' % (case['timeout'], detail)
    elif returncode != 0:
        status = 'fail'
        detail = 'pytest rc=%s; %s' % (returncode, detail)
    artifacts.append(_hash_record(stdout_path, 'log'))
    artifacts.append(_hash_record(stderr_path, 'log'))
    artifacts.append(_hash_record(process_path, 'log'))
    if observation['forced'] and not timed_out:
        status = 'unknown' if status == 'pass' else status
        detail = 'owned descendants required termination; ' + detail
    return {
        'status': status,
        'detail': detail,
        'returncode': returncode,
        'command': command,
        'started_at': started.isoformat(),
        'ended_at': ended.isoformat(),
        'duration_seconds': (ended - started).total_seconds(),
        'artifacts': artifacts,
        'cleanup': {
            'source': 'adapter',
            'resources': [],
            'process_exit': {'exited': observation['tree_exited'], 'returncode': returncode,
                             'timed_out': timed_out},
            'temp_roots': [str(case_dir.resolve())],
        },
    }


def _cleanup_derived(receipt, run_dir):
    cleanup = receipt.get('cleanup')
    if not isinstance(cleanup, dict):
        return False, 'cleanup record is missing'
    if cleanup.get('source') != 'adapter':
        return False, 'cleanup was not derived by the adapter'
    if cleanup.get('resources') != []:
        return False, 'offline adapter must not own external resources'
    process_exit = cleanup.get('process_exit')
    if not isinstance(process_exit, dict) or process_exit.get('exited') is not True:
        return False, 'subprocess exit was not observed'
    roots = cleanup.get('temp_roots')
    if not isinstance(roots, list) or not roots:
        return False, 'adapter temp roots are missing'
    base = Path(run_dir).resolve()
    for root in roots:
        path = Path(root)
        if not path.is_absolute() or not path.resolve().is_relative_to(base):
            return False, 'adapter temp root escapes the run directory'
    path = base / 'results' / receipt['case_id'] / 'process.json'
    matches = [item for item in receipt.get('artifacts', []) if item.get('path') == str(path)]
    if len(matches) != 1 or matches[0].get('format') != 'log' or not path.is_file():
        return False, 'owned process observation missing'
    if sha256(path) != matches[0].get('sha256'):
        return False, 'owned process observation changed'
    observed = read_json(path)
    if (observed.get('argv') != receipt.get('command') or
            observed.get('returncode') != process_exit.get('returncode') or
            observed.get('returncode') != receipt.get('returncode') or
            observed.get('timed_out') is not process_exit.get('timed_out')):
        return False, 'owned process observation differs from receipt'
    created = observed.get('created', {})
    pid = created.get('pid')
    if type(pid) is not int or pid <= 0 or observed.get('tree_exited') is not True:
        return False, 'owned process tree exit unconfirmed'
    if created.get('kind') == 'windows-job':
        if (type(created.get('birth_filetime')) is not int or created['birth_filetime'] <= 0 or
                observed.get('active_after_cleanup') != 0):
            return False, 'owned Job observation incomplete'
    else:
        final = observed.get('final_members')
        if (created.get('pgid') != pid or created.get('sid') != pid or
                type(created.get('birth_ticks')) is not int or not isinstance(final, list) or
                any(item.get('pgid') != pid or item.get('sid') != pid or
                    item.get('state') not in ('Z', 'X') for item in final)):
            return False, 'owned process group not quiescent'
        leader = [item for item in final if item.get('pid') == pid]
        if len(leader) != 1 or leader[0].get('birth_ticks') != created['birth_ticks']:
            return False, 'owned leader birth observation differs'
        children = observed.get('descendants_created')
        after = observed.get('descendants_after_cleanup')
        if not isinstance(children, list) or not isinstance(after, list):
            return False, 'owned descendant observations missing'
        before_ids = {(item.get('pid'), item.get('birth_ticks')) for item in children}
        after_ids = {(item.get('pid'), item.get('birth_ticks')) for item in after}
        if (len(before_ids) != len(children) or len(after_ids) != len(after) or
                before_ids != after_ids or
                any(item.get('state') not in ('Z', 'X', 'gone', 'reused') for item in after)):
            return False, 'owned descendant birth/exit observations differ'
    return True, ''


def _validate_execution_receipt(root, plan, reference, receipt):
    cid = reference['id']
    expected = {
        'schema': RECEIPT_V2, 'execution_id': plan['execution_id'],
        'suite_id': reference['suite_id'], 'case_id': cid,
        'adapter': reference['adapter'], 'oracle_kind': reference['oracle']['kind'],
        'candidate': plan['candidate'], 'environment': plan['environment'],
        'config_sha256': _sha256_json(plan['cases'][cid]),
        'evidence_level': ('offline' if reference['adapter'] == 'offline-pytest' else
                           'fixture' if reference['adapter'] == 'native' and
                           (plan['candidate'].get('offline_fixture') is True or
                            acceptance_native.is_fixture(reference, root)) else 'native'),
    }
    for name, value in expected.items():
        if receipt.get(name) != value:
            raise InputError('receipt %s mismatch: %s' % (name, cid))
    if receipt.get('status') not in CASE_STATUSES:
        raise InputError('invalid receipt status: ' + cid)


def _judge_execution_case(root, plan, reference, receipt):
    """Replay one closed case; no target actions and no recovery state machine."""
    _validate_execution_receipt(root, plan, reference, receipt)
    cid = reference['id']
    base = {'case_id': cid, 'suite_id': reference['suite_id']}
    if 'facility_error' in receipt:
        path = Path(plan['run_dir']) / 'results' / cid / 'facility-error.json'
        artifacts = receipt.get('artifacts', [])
        if (len(artifacts) != 1 or artifacts[0].get('path') != str(path) or
                artifacts[0].get('format') != 'log' or not path.is_file() or
                sha256(path) != artifacts[0].get('sha256') or
                read_json(path) != receipt['facility_error'] or receipt['status'] != 'unknown'):
            raise InputError('facility error original differs: ' + cid)
        return dict(base, status='unknown', cleanup_ok=False,
                    reason='facility error', facility_error=read_json(path))
    if reference['adapter'] == 'native':
        if receipt.get('native_driver') != reference.get('native_driver'):
            raise InputError('native driver mismatch: ' + cid)
        judged = acceptance_native.judge_driver(reference, receipt, plan, root)
        clean = judged.get('cleanup_ok') is True
        status = judged.get('status', 'unknown')
        if not clean and status == 'pass':
            status = 'unknown'
        return dict(base, status=status, cleanup_ok=clean,
                    reason=judged.get('reason', ''), evaluation=judged.get('evaluation'))
    if reference['adapter'] != 'offline-pytest':
        raise InputError('unregistered executed adapter: ' + cid)
    oracle_kind = reference['oracle']['kind']
    if oracle_kind not in ('junit', 'tsv'):
        raise InputError('offline oracle differs: ' + cid)
    parsed, paths, count = [], [], 0
    for artifact in receipt.get('artifacts') or []:
        path = Path(artifact.get('path', ''))
        if not path.is_absolute() or not path.is_file() or sha256(path) != artifact.get('sha256'):
            raise InputError('artifact changed or missing: ' + cid)
        paths.append(str(path))
        fmt = artifact.get('format')
        if fmt not in (oracle_kind, 'log'):
            raise InputError('unexpected artifact format for ' + cid)
        if fmt == oracle_kind:
            count += 1
            try:
                parsed.extend(parse_junit(path) if fmt == 'junit' else parse_tsv(path))
            except (ET.ParseError, ValueError, UnicodeError) as exc:
                raise ToolError('cannot parse original artifact for %s: %s' % (cid, exc)) from exc
    process_exit = (receipt.get('cleanup') or {}).get('process_exit') or {}
    if count != 1 and not (count == 0 and process_exit.get('timed_out') is True):
        raise InputError('expected exactly one %s artifact: %s' % (oracle_kind, cid))
    checks = plan['required_checks'].get(cid) or []
    if not checks:
        raise InputError('planned checks are empty: ' + cid)
    evaluation = judge_rows_exact(parsed, checks)
    status = ('fail' if evaluation['verdict'] == 'fail' or receipt['status'] == 'fail' else
              'pass' if evaluation['verdict'] == 'pass' and receipt['status'] == 'pass' else 'unknown')
    reason = ''
    rc = receipt.get('returncode')
    if type(rc) is not int:
        status = 'fail' if status == 'fail' else 'unknown'
        reason = 'process exit was not observed'
    elif rc != 0:
        status, reason = 'fail', 'process returncode %r' % rc
    if process_exit.get('timed_out') is True:
        status = 'fail' if status == 'fail' else 'unknown'
        reason = 'case timed out'
    clean, cleanup_reason = _cleanup_derived(receipt, plan['run_dir'])
    if not clean and status == 'pass':
        status, reason = 'unknown', cleanup_reason
    return dict(base, status=status, reason=reason, evaluation=evaluation,
                cleanup_ok=clean, artifacts=paths)


def judge_v2(root, plan_path, results_dir, output=None):
    root = Path(root)
    plan_path = Path(plan_path)
    plan = read_json(plan_path)
    catalog, registered = validate_plan_registry(root, plan, plan_path,
                                                 require_execute_action=False)
    if plan.get('mode') == 'full':
        expected = expected_case_ids(catalog, 'full')
        if set(plan['required_cases']) != set(expected):
            raise InputError('full plan is not the catalog full set')
    results_dir = Path(results_dir)
    index_path = results_dir / 'results.json'
    index = read_json(index_path)
    if index.get('schema') != RESULTS_V2:
        raise InputError('unknown results index schema')
    if index.get('execution_id') != plan['execution_id']:
        raise InputError('results execution_id does not match plan')
    if index.get('plan_sha256') != sha256(plan_path):
        raise InputError('results were produced for a different plan')
    entries = index.get('receipts')
    if not isinstance(entries, list):
        raise InputError('results index has no receipt list')
    entry_ids = [entry.get('case_id') for entry in entries]
    if len(entry_ids) != len(set(entry_ids)):
        raise InputError('results index contains duplicate receipts')
    if set(entry_ids) != set(plan['required_cases']):
        raise InputError('results do not cover the planned case set exactly: missing=%r extra=%r'
                         % (sorted(set(plan['required_cases']) - set(entry_ids)),
                            sorted(set(entry_ids) - set(plan['required_cases']))))
    receipts = {}
    for entry in entries:
        case_id = entry.get('case_id')
        path = Path(entry.get('path', ''))
        if not path.is_absolute() or not path.is_file() or sha256(path) != entry.get('sha256'):
            raise InputError('receipt changed or missing: %s' % case_id)
        receipt = read_json(path)
        if receipt.get('case_id') != case_id:
            raise InputError('receipt case_id differs from index: %s' % case_id)
        receipts[case_id] = receipt
    facts, taints = {}, {}
    cases = [plan['cases'][cid] for cid in plan['required_cases']]
    order, order_blocks = acceptance_scheduler.ordered_cases(cases, plan)
    initial = dict(order_blocks, **plan.get('blocked', {}))
    for cid in order + [item for item in plan['required_cases'] if item not in order]:
        reference, receipt = registered[cid], receipts[cid]
        _validate_execution_receipt(root, plan, reference, receipt)
        reason = acceptance_scheduler.block_reason(plan['cases'][cid], facts, taints,
                                                   plan=plan, initial=initial)
        if receipt['status'] == 'blocked':
            if not reason or receipt.get('reason') != reason:
                raise InputError('blocked receipt for an unblocked case or wrong reason: ' + cid)
            facts[cid] = {'case_id': cid, 'suite_id': reference['suite_id'],
                          'status': 'blocked', 'reason': reason}
        else:
            if reason:
                raise InputError('executed case had blocked dependency/resource: ' + cid)
            facts[cid] = _judge_execution_case(root, plan, reference, receipt)
            if facts[cid].get('cleanup_ok') is False:
                taints[cid] = acceptance_scheduler._resources(plan['cases'][cid], plan['environment'])
    outcomes = [facts[cid] for cid in plan['required_cases']]
    timings = [{'case_id': cid, 'seconds': receipts[cid]['duration_seconds']}
               for cid in plan['required_cases']
               if isinstance(receipts[cid].get('duration_seconds'), (int, float))]
    cleanup_results = [item['cleanup_ok'] for item in outcomes if 'cleanup_ok' in item]
    errors = [item['facility_error'] for item in outcomes if item.get('facility_error')]
    fixture_used = (plan['candidate'].get('offline_fixture') is True or
                    any(receipts[cid].get('evidence_level') == 'fixture' for cid in plan['required_cases']))
    passed = [row['case_id'] for row in outcomes if row['status'] == 'pass']
    failed = [row['case_id'] for row in outcomes if row['status'] == 'fail']
    unverified = [row['case_id'] for row in outcomes
                  if row['status'] in ('unknown', 'blocked', 'not_run')]
    if failed:
        verdict = 'fail'
    elif unverified:
        verdict = 'unknown'
    else:
        verdict = 'pass'
    coverage = ('full' if plan.get('mode') == 'full'
                else 'stress' if plan.get('mode') == 'stress' else 'selected')
    full_functional_pass = (plan.get('mode') == 'full' and verdict == 'pass'
                            and not unverified and not fixture_used)
    fixture_contract_pass = fixture_used and verdict == 'pass'
    cleanup_complete = bool(cleanup_results) and all(cleanup_results)
    blocked_count = sum(1 for row in outcomes if row['status'] == 'blocked')
    summary = {
        'schema': SUMMARY_V2,
        'candidate': plan['candidate'],
        'execution_id': plan['execution_id'],
        'mode': plan.get('mode'),
        'coverage': coverage,
        'checks': {'required': len(plan['required_cases']), 'passed': len(passed),
                   'failed': len(failed), 'unverified': len(unverified)},
        'cases': outcomes,
        'cleanup': {'complete': cleanup_complete, 'evaluated': len(cleanup_results),
                    'blocked': blocked_count},
        'verdict': verdict,
        'full_functional_pass': full_functional_pass,
        'fixture_contract_pass': fixture_contract_pass,
        'unverified': unverified,
        'failures': failed,
        'errors': errors,
        'timings': timings,
        'generated_at': utc_now(),
    }
    if output is not None:
        output = Path(output)
        if output.exists():
            raise InputError('summary output already exists: %s' % output)
        _write_json(output, summary)
    return summary


def exit_code_for(summary):
    if summary.get('errors'):
        return EXIT_TOOL
    if summary.get('verdict') == 'fail':
        return EXIT_FAIL
    if summary.get('verdict') == 'unknown':
        return EXIT_INPUT
    if summary.get('verdict') == 'pass':
        return EXIT_OK
    return EXIT_TOOL


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT, help=argparse.SUPPRESS)
    commands = parser.add_subparsers(dest='command', required=True)
    inv = commands.add_parser('inventory', help='read-only static inventory; never execute drivers')
    inv.add_argument('--format', choices=('json', 'markdown'), default='json')
    inv.add_argument('--output', type=Path)
    commands.add_parser('check', help='detect missing and unclassified source facilities')
    plan = commands.add_parser('plan', help='freeze source inventory or a v2 case plan; no VM calls')
    plan.add_argument('--output', type=Path, required=True)
    plan.add_argument('--mode', choices=('full', 'selected', 'stress'))
    plan.add_argument('--candidate', type=Path)
    plan.add_argument('--environment', type=Path)
    plan.add_argument('--suite', action='append', default=[])
    plan.add_argument('--case', action='append', default=[])
    run = commands.add_parser('run', help='execute one explicit original driver; no implicit all-native run')
    run.add_argument('--suite', required=True)
    run.add_argument('--args-json', type=Path)
    run.add_argument('--python', default=sys.executable)
    run.add_argument('--output', type=Path, required=True)
    execute = commands.add_parser('execute', help='execute a v2 plan through registered adapters')
    execute.add_argument('--plan', type=Path, required=True)
    judge = commands.add_parser('judge', help='recompute a session from explicit original results')
    judge.add_argument('--plan', type=Path, required=True)
    judge.add_argument('--result', type=Path, action='append', default=[])
    judge.add_argument('--results', type=Path)
    judge.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    root = Path(args.root)
    try:
        if args.command in ('check', 'inventory'):
            value = inventory(root)
            if args.command == 'check':
                print(json.dumps({'counts': value['counts'], 'unclassified': value['unclassified'],
                                  'schema': value.get('catalog_schema'),
                                  'qualification': 'not_run'}, ensure_ascii=False))
                return 1 if value['unclassified'] else 0
            text = markdown(value) if args.format == 'markdown' else json.dumps(value, ensure_ascii=False, indent=2) + '\n'
            code = 0
        elif args.command == 'plan':
            if args.mode:
                if not args.candidate or not args.environment:
                    raise InputError('plan --mode requires --candidate and --environment')
                value = make_plan_v2(root, args.mode, args.candidate, args.environment,
                                     args.suite, args.case, args.output)
                text = json.dumps({'schema': value['schema'], 'mode': value['mode'],
                                   'execution_id': value['execution_id'],
                                   'required_cases': value['required_cases'],
                                   'blocked': value['blocked'],
                                   'plan': str(args.output)}, ensure_ascii=False)
                code = 0
            else:
                text = json.dumps(make_plan(root), ensure_ascii=False, indent=2) + '\n'
                code = 0
            if args.output and args.mode is None:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                with args.output.open('x', encoding='utf-8') as stream:
                    stream.write(text)
                return code
            print(text)
            return code
        elif args.command == 'run':
            arguments = json.loads(args.args_json.read_text(encoding='utf-8')) if args.args_json else []
            value = launch(args.suite, arguments, args.output, root=root, python=args.python)
            print(json.dumps(value, ensure_ascii=False))
            return 0 if value['returncode'] == 0 and not value['sources_changed'] else 1
        elif args.command == 'execute':
            summary = execute_plan(root, args.plan)
            print(json.dumps({'verdict': summary['verdict'], 'coverage': summary['coverage'],
                              'checks': summary['checks'],
                              'full_functional_pass': summary['full_functional_pass'],
                              'paths': summary.get('paths')}, ensure_ascii=False))
            return exit_code_for(summary)
        else:
            if args.results:
                summary = judge_v2(root, args.plan, args.results, args.output)
                text = json.dumps(summary, ensure_ascii=False, indent=2) + '\n'
                if args.output is None:
                    print(text, end='')
                return exit_code_for(summary)
            value = judge_session(read_json(args.plan),
                                  [read_json(path) for path in args.result], root)
            text = json.dumps(value, ensure_ascii=False, indent=2) + '\n'
            code = 0 if value['verdict'] == 'pass' else 1
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                with args.output.open('x', encoding='utf-8') as stream:
                    stream.write(text)
            else:
                print(text, end='')
            return code
        if args.output:
            # Never overwrite a historical inventory, plan or result.
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open('x', encoding='utf-8') as stream:
                stream.write(text)
        else:
            print(text, end='')
        return code
    except InputError as error:
        print(json.dumps({'status': 'invalid', 'error': str(error)}, ensure_ascii=False), file=sys.stderr)
        return EXIT_INPUT
    except (ValueError, KeyError, OSError, SyntaxError, ET.ParseError) as error:
        print(json.dumps({'status': 'invalid', 'error': str(error)}, ensure_ascii=False), file=sys.stderr)
        return EXIT_INPUT
    except Exception as error:
        print(json.dumps({'status': 'tool_error', 'error': type(error).__name__ + ': ' + str(error)},
                         ensure_ascii=False), file=sys.stderr)
        return EXIT_TOOL


if __name__ == '__main__':
    raise SystemExit(main())
