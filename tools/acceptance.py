#!/usr/bin/env python3
"""Inventory, plan and judge existing FakeNet regression facilities.

This module never imports an acceptance driver. Inventory and planning perform
no network, VM, build or service operations. Original drivers remain owners of
their runtime checks, evidence and cleanup.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import uuid
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / 'docs' / 'acceptance' / 'catalog.json'
SCHEMA = 'fakenet.acceptance-inventory.v1'
STATUSES = {'pass', 'fail', 'unknown', 'not_run', 'blocked', 'skip', 'observed'}


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def read_catalog(root=ROOT):
    value = json.loads((Path(root) / 'docs/acceptance/catalog.json').read_text(encoding='utf-8'))
    if value.get('schema') != 'fakenet.acceptance-catalog.v1':
        raise ValueError('unknown catalog schema')
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
            if not any(Path(root).glob(source)):
                raise ValueError('%s missing source %s' % (row['id'], source))
    return value


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
    return {'schema': SCHEMA, 'catalog_sha256': sha256(root / 'docs/acceptance/catalog.json'),
            'suites': catalog['suites'], 'files': file_list,
            'unclassified': unclassified,
            'counts': {'suites': len(catalog['suites']), 'files': len(files),
                       'declared_items': sum(len(row['items']) for row in file_list)},
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


def judge_session(plan, results, root=ROOT):
    """Judge explicit source-bound receipts; never infer current credit from history."""
    catalog = read_catalog(root)
    suites = {suite['id']: suite for suite in catalog['suites']}
    if plan.get('catalog_sha256') != sha256(Path(root) / 'docs/acceptance/catalog.json'):
        raise ValueError('plan catalog identity changed')
    if plan.get('schema') != 'fakenet.acceptance-plan.v1':
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
    return {'schema': 'fakenet.acceptance-summary.v1', 'candidate': plan['candidate'],
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
    return {'schema': 'fakenet.acceptance-plan.v1', 'execution_id': str(uuid.uuid4()),
            'catalog_sha256': value['catalog_sha256'], 'candidate': {},
            'required_suites': [row['id'] for row in value['suites'] if row['required_for_full']],
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
    for suite in value['suites']:
        lines += ['', '## ' + suite['id'] + ' ' + suite['title'], '',
                  '证据级别: ' + suite['evidence_level'], '',
                  '前置条件: ' + suite['prerequisites'], '',
                  '原入口/来源: ' + ', '.join('`' + p + '`' for p in suite['sources']), '',
                  '结果与原件: ' + suite['outputs'], '',
                  '限制/待补: ' + suite['limitations']]
    lines += ['', '## 逐文件和逐项索引', '',
              '用 inventory --format json 导出源码位置、完整哈希、测试函数、断言及原生结果声明.', '',
              '| 文件 | 所属分组 | 静态声明数 |', '| --- | --- | --- |']
    for row in value['files']:
        lines.append('| `%s` | %s | %d |' % (row['path'], ', '.join(row['suites']), len(row['items'])))
    lines += ['', '未归类入口: ' + (', '.join(value['unclassified']) or '无'), '']
    return '\n'.join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    inv = commands.add_parser('inventory', help='read-only static inventory; never execute drivers')
    inv.add_argument('--format', choices=('json', 'markdown'), default='json')
    inv.add_argument('--output', type=Path)
    commands.add_parser('check', help='detect missing and unclassified source facilities')
    plan = commands.add_parser('plan', help='freeze source inventory and all required groups; no VM calls')
    plan.add_argument('--output', type=Path, required=True)
    run = commands.add_parser('run', help='execute one explicit original driver; no implicit all-native run')
    run.add_argument('--suite', required=True)
    run.add_argument('--args-json', type=Path)
    run.add_argument('--python', default=sys.executable)
    run.add_argument('--output', type=Path, required=True)
    judge = commands.add_parser('judge', help='recompute a source-bound session from explicit receipts')
    judge.add_argument('--plan', type=Path, required=True)
    judge.add_argument('--result', type=Path, action='append', default=[])
    judge.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command in ('check', 'inventory'):
            value = inventory()
            if args.command == 'check':
                print(json.dumps({'counts': value['counts'], 'unclassified': value['unclassified'],
                                  'qualification': 'not_run'}, ensure_ascii=False))
                return 1 if value['unclassified'] else 0
            text = markdown(value) if args.format == 'markdown' else json.dumps(value, ensure_ascii=False, indent=2) + '\n'
            code = 0
        elif args.command == 'plan':
            text = json.dumps(make_plan(), ensure_ascii=False, indent=2) + '\n'
            code = 0
        elif args.command == 'run':
            arguments = json.loads(args.args_json.read_text(encoding='utf-8')) if args.args_json else []
            value = launch(args.suite, arguments, args.output, python=args.python)
            print(json.dumps(value, ensure_ascii=False))
            return 0 if value['returncode'] == 0 and not value['sources_changed'] else 1
        else:
            value = judge_session(json.loads(args.plan.read_text(encoding='utf-8')),
                                  [json.loads(path.read_text(encoding='utf-8')) for path in args.result])
            text = json.dumps(value, ensure_ascii=False, indent=2) + '\n'
            code = 0 if value['verdict'] == 'pass' else 1
        if args.output:
            # Never overwrite a historical inventory, plan or result.
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open('x', encoding='utf-8') as stream:
                stream.write(text)
        else:
            print(text, end='')
        return code
    except (ValueError, KeyError, OSError, SyntaxError, ET.ParseError) as error:
        print(json.dumps({'status': 'invalid', 'error': str(error)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
