#!/usr/bin/env python3
"""Independent MCP oracle: reuse original validators on original bytes."""
from __future__ import annotations

import json
from pathlib import Path

CASES = ('MCP-P01-FULL', 'MCP-P02-FULL', 'MCP-P03-FULL', 'MCP-P04-FULL',
         'MCP-SPECIAL-IPC', 'MCP-SPECIAL-FAULT-RECOVERY')


def _load(root, relative):
    import importlib.util
    import sys
    root = str(Path(root).resolve())
    if root not in sys.path:
        sys.path.insert(0, root)
    spec = importlib.util.spec_from_file_location('mcp_original_' + Path(relative).stem,
                                                   Path(root) / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def evaluate(root, original, case, checks, expected_identity=None):
    original = Path(original)
    value = json.loads((original / 'mcp-result.json').read_text(encoding='utf-8'))
    if value.get('case') != case:
        raise ValueError('MCP result case mismatch')
    identity = value.get('identity') or {key: value.get(key) for key in
                                         ('candidate_id', 'source_commit',
                                          'package_sha256', 'requirements_blob',
                                          'master_plan_blob')}
    expected = dict(expected_identity or identity)
    evidence = _load(root, 'test/mcp/acceptance/evidence_integrity.py')
    rows = {}
    detail = {}
    try:
        if case in ('MCP-P01-FULL', 'MCP-P02-FULL'):
            failures = evidence.validate_result(value, expected, original)
            rows = {name: 'pass' if not failures else 'fail' for name in checks}
            detail['failures'] = failures
        elif case in ('MCP-P03-FULL', 'MCP-P04-FULL'):
            failures = evidence.validate_round(value, expected)
            rows = {name: 'pass' if not failures else 'fail' for name in checks}
            detail['failures'] = failures
        elif case == 'MCP-SPECIAL-IPC':
            ipc = _load(root, 'test/mcp/acceptance/ipc_evidence.py')
            for fault in checks:
                item = (value.get('ipc') or {}).get(fault) or {}
                rows_data = [json.loads(line) for line in
                             Path(item['rows']).read_text().splitlines()]
                failures = ipc.check_ipc_case(fault, item['run_id'], rows_data)
                rows[fault] = 'pass' if not failures else 'fail'
                detail[fault] = failures
        elif case == 'MCP-SPECIAL-FAULT-RECOVERY':
            by_class = {item.get('class'): item for item in value.get('faults') or []}
            for fault in checks:
                item = by_class.get(fault)
                failures = (['missing fault class'] if item is None else
                            evidence.validate_round(item, expected))
                rows[fault] = 'pass' if not failures else 'fail'
                detail[fault] = failures
    except Exception as exc:
        rows = {name: 'fail' for name in checks}
        detail['error'] = '%s: %s' % (type(exc).__name__, exc)
    out = [{'id': name, 'status': rows.get(name, 'fail')} for name in checks]
    clean = (all(row['status'] == 'pass' for row in out) and
             (value.get('stop') or {}).get('exited') is True and
             (value.get('stop') or {}).get('returncode') == 0)
    return out, clean, detail
