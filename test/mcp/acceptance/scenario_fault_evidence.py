#!/usr/bin/env python3
# Copyright 2026 Google LLC
"""Build and adjudicate one raw ``sst_fault_evidence`` case per scenario.

This adapter does not infer a pass from scenario state.  Its input is an
immutable capture descriptor naming the original VM files for one run; it
writes a byte-addressed case and invokes the independent adjudicator with the
candidate that the suite froze before execution.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterator

HERE = Path(__file__).resolve().parent
ADJUDICATOR = HERE / 'sst_fault_evidence.py'


def record(path: Path, root: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    return {'path': str(path.relative_to(root)), 'bytes': len(raw),
            'sha256': hashlib.sha256(raw).hexdigest()}


def ref(path: Path, root: Path, start: int = 0, end: int | None = None,
        key: str = 'json:') -> dict[str, Any]:
    raw = path.read_bytes()
    return {'path': str(path.relative_to(root)), 'byte_start': start,
            'byte_end': len(raw) if end is None else end, 'event_key': key}


def json_lines(path: Path, root: Path) -> Iterator[tuple[dict[str, Any], dict[str, Any]]]:
    offset = 0
    for line in path.read_bytes().splitlines(keepends=True):
        yield json.loads(line), ref(path, root, offset, offset + len(line))
        offset += len(line)


def text_lines(path: Path, root: Path) -> Iterator[tuple[str, dict[str, Any]]]:
    offset = 0
    for line in path.read_bytes().splitlines(keepends=True):
        yield line.decode('utf-8-sig'), ref(path, root, offset, offset + len(line), 'text')
        offset += len(line)


def exception_blocks(path: Path, root: Path) -> list[dict[str, Any]]:
    raw = path.read_bytes()
    starts = [m.start() for m in re.finditer(rb'^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d{3} ', raw, re.M)]
    starts.append(len(raw))
    return [ref(path, root, a, b, 'text') for a, b in zip(starts, starts[1:])
            if b'Unhandled exception' in raw[a:b] or b'Traceback (most recent call last)' in raw[a:b]]


def _relative(root: Path, raw: dict[str, Any], name: str) -> Path:
    value = raw.get(name)
    if not isinstance(value, str):
        raise ValueError('capture raw path missing: ' + name)
    path = (root / value).resolve()
    if not path.is_relative_to(root.resolve()) or not path.is_file():
        raise ValueError('capture raw file missing/escaping: ' + name)
    return path


def _packet_refs(path: Path, root: Path, src: str, dst: str) -> list[dict[str, Any]]:
    """Select complete pktmon records that carry this source tuple.

    Pktmon text begins UTF-16LE on current target builds.  Byte offsets remain
    into the source file, so the adjudicator independently decodes them.
    """
    raw = path.read_bytes()
    encoding = 'utf-16' if raw.startswith(b'\xff\xfe') else 'utf-8-sig'
    text = raw.decode(encoding)
    offset = 2 if raw.startswith(b'\xff\xfe') else 0
    header: int | None = None
    selected: list[dict[str, Any]] = []
    # Pktmon displays IPv4 endpoints as dotted ``ip.port`` values.  Match the
    # full directed connection, never a source-port substring or an unrelated
    # destination that happened to emit a FIN in the same capture.
    source = src.replace(':', '.')
    target = dst.replace(':', '.')
    # A remote FIN/RST is just as valid an end observation.  Keep only the
    # two exact orientations of this one connection, never a port prefix or
    # another destination in the same all-components capture.
    directed = re.compile(r'(?:' + re.escape(source) + r'\s*>\s*' + re.escape(target) +
                          r'|' + re.escape(target) + r'\s*>\s*' + re.escape(source) + r'):')
    for line in text.splitlines(keepends=True):
        encoded = line.encode('utf-16-le' if raw.startswith(b'\xff\xfe') else 'utf-8')
        if line.startswith('['):
            header = offset
        if header is not None and directed.search(line) and 'Flags [' in line:
            selected.append(ref(path, root, header, offset + len(encoded), 'text'))
        offset += len(encoded)
    return selected


def _latest_raw_ref(root: Path, refs: list[dict[str, Any]]) -> dict[str, Any]:
    """Choose a trigger upper bound from raw clocks, never caller ordering."""
    spec = importlib.util.spec_from_file_location('scenario_fault_clock', ADJUDICATOR)
    if spec is None or spec.loader is None:
        raise ValueError('fault adjudicator clock helper is unavailable')
    clock = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(clock)

    def observed(item: dict[str, Any]) -> Any:
        raw = (root / item['path']).read_bytes()[item['byte_start']:item['byte_end']]
        text = raw.decode('utf-16-le' if raw.startswith(b'\xff\xfe') else 'utf-8-sig').lstrip('\ufeff')
        return json.loads(text) if item['event_key'].startswith('json:') else text

    return max(refs, key=lambda item: clock.time_bounds(observed(item))[1])


def build_case(root: Path, capture: dict[str, Any]) -> dict[str, Any]:
    """Translate an explicit one-run capture descriptor into the stable case.

    ``capture['raw']`` must name complete original files.  Required names are
    receipt, receipt_metadata, ipc, run_log, probe, pktmon, baseline, recovery
    audit, recovery healthy state, cleanup state and terminal status.  Fault
    adapters additionally require the original native action observation.
    """
    root = root.resolve()
    raw = capture.get('raw')
    if not isinstance(raw, dict):
        raise ValueError('capture.raw must be an object')
    fault = capture['fault']
    run_id, nonce, candidate = capture['run_id'], capture['nonce'], capture['candidate_id']
    required = ('receipt', 'receipt_metadata', 'ipc', 'run_log', 'probe', 'pktmon',
                'baseline', 'recovery_audit', 'recovery_healthy', 'cleanup', 'terminal')
    files = {name: _relative(root, raw, name) for name in required}
    ipc = list(json_lines(files['ipc'], root))
    start = next(((event, item) for event, item in ipc
                  if event.get('event') == 'response' and event.get('frame', {}).get('seq') == 1), None)
    if start is None:
        raise ValueError('start IPC response seq=1 missing')
    receipt_meta = json.loads(files['receipt_metadata'].read_text(encoding='utf-8-sig'))
    if not isinstance(receipt_meta, list):
        raise ValueError('receipt metadata must be an array')
    meta_index = next((i for i, item in enumerate(receipt_meta)
                       if item.get('name') == 'fault-triggered.json'), None)
    if meta_index is None:
        raise ValueError('receipt metadata lacks fault-triggered.json')
    success: list[dict[str, Any]] = []
    action_upper = start[1]
    blocks = exception_blocks(files['run_log'], root)
    extras: list[Path] = []
    if fault == 'listener_stop':
        # The native L1 traceback proves the listener failure, while the
        # parent start IPC response supplies the other endpoint if it is later.
        # Select that upper bound by original timestamps, never list order.
        success = blocks + [start[1]]
        action_upper = _latest_raw_ref(root, success)
    elif fault == 'diverter_stop':
        action = _relative(root, raw, 'fault_action'); extras.append(action)
        action_upper = ref(action, root)
        success = [action_upper]
    elif fault == 'child_hang':
        native = _relative(root, raw, 'native_processes'); extras.append(native)
        process = json.loads(native.read_text(encoding='utf-8-sig'))
        rows = process.get('processes', [])
        child_index = next((i for i, item in enumerate(rows)
                            if item.get('Name') == 'fakenetng-mcp.exe'
                            and 'managed-fault-hang' in (item.get('CommandLine') or '')), None)
        if child_index is None:
            raise ValueError('native hanging child missing')
        action_upper = ref(native, root, key='json:/processes/%d/CreationDate' % child_index)
        success = [ref(native, root), action_upper]
    elif fault == 'policy_pause':
        stacks = _relative(root, raw, 'thread_stacks'); source = _relative(root, raw, 'fault_source')
        extras.extend((stacks, source)); action_upper = ref(stacks, root, key='text')
        success = [action_upper, ref(source, root, key='text')]
    elif fault == 'cleanup_error':
        rejected = [item for event, item in ipc if event.get('event') == 'response'
                    and event.get('frame', {}).get('error')]
        success = blocks + rejected
        if rejected:
            action_upper = rejected[-1]
    else:
        raise ValueError('unsupported fault: ' + str(fault))

    events = list(json_lines(files['probe'], root))
    established = next(((event, item) for event, item in events if event.get('event') == 'established'), None)
    if established is None:
        raise ValueError('probe established event missing')
    event, established_ref = established
    creation = next(((row, item) for row, item in events
                     if row.get('event') in ('ready', 'process_ready') and
                     row.get('nonce') == event.get('nonce') and row.get('pid') == event.get('pid') and
                     isinstance(row.get('creation_ticks'), int)), None)
    if creation is None:
        raise ValueError('probe child creation record missing')
    creation_event, _creation_ref = creation
    end = next(((row, item) for row, item in events
                if row.get('event') in ('eof', 'error', 'close') and
                all(row.get(k) == event.get(k) for k in ('pid', 'worker', 'seq', 'nonce'))), None)
    if end is None:
        raise ValueError('probe termination event missing')
    port = event['src'].rsplit(':', 1)[1]
    flow = next((item for text, item in text_lines(files['run_log'], root)
                 if 'PROCESS_FLOW ' in text and 'pid=%s ' % event['pid'] in text and
                 ('sport=%s ' % port in text or 'sport=%s\n' % port in text)), None)
    if flow is None:
        raise ValueError('run.log PROCESS_FLOW for probe missing')
    baseline = json.loads(files['baseline'].read_text(encoding='utf-8-sig'))
    if isinstance(baseline, list):
        baseline_index = next((i for i, item in enumerate(baseline) if item.get('run_id') == run_id), None)
        if baseline_index is None:
            raise ValueError('baseline missing run')
        baseline_ref = ref(files['baseline'], root, key='json:/%d/sections' % baseline_index)
    else:
        baseline_ref = ref(files['baseline'], root, key='json:/sections')
    audits = list(json_lines(files['recovery_audit'], root))
    if not audits:
        raise ValueError('recovery audit empty')
    audit_ref = dict(audits[-1][1]); audit_ref['event_key'] = 'json:/current'
    named = list(files.values()) + extras
    return {
        'schema': 'sst.fault-evidence.case.v1', 'synthetic': False,
        'case_id': str(capture.get('case_id') or ('scenario-' + capture['scenario_id'])),
        'candidate_id': candidate, 'run_id': run_id, 'fault': fault, 'nonce': nonce,
        'clock': {'domain': 'vm-utc', 'resolution_ns': int(capture.get('clock_resolution_ns', 15625000)), 'discontinuities': []},
        'receipt_ref': ref(files['receipt'], root),
        'trigger': {'kind': fault,
                    'lower_ref': ref(files['receipt_metadata'], root, key='json:/%d' % meta_index),
                    'upper_ref': action_upper, 'success_refs': success},
        'session': {'connection_id': '%s-%s-%s' % (event['pid'], event['worker'], event['seq']),
                    'probe_pid': event['pid'], 'probe_creation': creation_event['creation_ticks'],
                    'nonce': nonce, 'src': event['src'],
                    'dst': event.get('actual_dst') or event['dst'], 'protocol': 'TCP',
                    'established_ref': established_ref, 'managed_ref': flow, 'end_ref': end[1],
                    'packet_refs': _packet_refs(files['pktmon'], root, event['src'], event.get('actual_dst') or event['dst'])},
        'start_response_ref': start[1], 'health_refs': [], 'stop_refs': [ref(files['terminal'], root)],
        'recovery_refs': [baseline_ref, audit_ref, ref(files['recovery_healthy'], root, key='json:/health/0'), ref(files['cleanup'], root)],
        'exception_refs': blocks, 'files': [record(path, root) for path in named],
    }


def adjudicate(root: Path, capture: dict[str, Any], output: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    case = build_case(root, capture)
    case_path = output.with_suffix('.case.json')
    if case_path.exists() or output.exists():
        raise FileExistsError('case/result already exists')
    case_path.write_text(json.dumps(case, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    process = subprocess.run([sys.executable, str(ADJUDICATOR), '--expected-candidate', case['candidate_id'],
                              '--input', str(case_path), '--evidence-root', str(root), '--output', str(output)],
                             text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    output.with_suffix('.validator.stdout').write_text(process.stdout, encoding='utf-8')
    return case, json.loads(output.read_text(encoding='utf-8'))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence-root', required=True)
    parser.add_argument('--capture', required=True, help='immutable capture descriptor JSON')
    parser.add_argument('--output', required=True)
    args = parser.parse_args(argv)
    capture = json.loads(Path(args.capture).read_text(encoding='utf-8'))
    _, result = adjudicate(Path(args.evidence_root), capture, Path(args.output))
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result.get('passed') else 3


if __name__ == '__main__':
    raise SystemExit(main())
