"""A positive QPC proof must never waive original connection structure."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

import pytest

HERE = Path(__file__).parent / 'acceptance'
sys.path.insert(0, str(HERE))
import scenario_fault_evidence as adapter
import scenario_qpc_contract as contract
import sst_fault_evidence as oracle


def _base(root):
    spec = importlib.util.spec_from_file_location('qpc_structural_fixture',
        Path(__file__).with_name('test_sst_tcpip_events.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _, base = module.oracle_case(root)
    base['synthetic'] = False
    base['fault'] = 'diverter_stop'
    return base


def _rehash(root, base, name):
    raw = (root / name).read_bytes()
    next(item for item in base['files'] if item['path'] == name).update(
        bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def _append_probe(root, base, **changes):
    path = root / 'probe.jsonl'
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    row = dict(rows[-1], **changes)
    start = path.stat().st_size
    with path.open('ab') as stream:
        raw = (json.dumps(row) + '\n').encode()
        stream.write(raw)
    _rehash(root, base, 'probe.jsonl')
    return {'path': 'probe.jsonl', 'byte_start': start,
            'byte_end': start + len(raw), 'event_key': 'json:'}


def _check(base, root, monkeypatch):
    frozen = root / 'frozen.json'
    frozen.write_text(json.dumps(base) + '\n')
    for name in adapter.QPC_EXPORT_FILES:
        path = root / 'export' / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{}\n')
    descriptor = {'clock_evidence_mode': contract.MODE, 'fault': 'diverter_stop',
                  'base_case_path': 'frozen.json', 'qpc_export_prefix': 'export'}
    v3 = adapter.build_qpc_case(root, descriptor, base)
    monkeypatch.setattr(contract, 'evaluate', lambda *args, **kwargs: {
        'utc': {'passed': True}, 'native_qpc': {'passed': True}})
    old = oracle.assess(base, root, base['candidate_id'])
    new = oracle.assess(v3, root, base['candidate_id'])
    return old, new


@pytest.mark.parametrize('bad', [
    'end_is_established', 'wrong_pid', 'wrong_worker', 'wrong_seq',
    'wrong_nonce', 'wrong_connection_id', 'later_error_skips_first_eof',
    'probe_creation', 'managed_nonflow', 'later_matching_flow',
    'wrong_tuple', 'receipt_lower', 'upper_unbound', 'capture_mode',
    'capture_conversion', 'generation_refs',
])
def test_original_structure_shared_by_v2_and_v3_even_when_qpc_positive(
        tmp_path, monkeypatch, bad):
    base = _base(tmp_path)
    baseline = oracle.assess(base, tmp_path, base['candidate_id'])
    assert next(x for x in baseline['checks'] if x['id'] == 'connection_structure')['passed']
    session = base['session']
    if bad == 'end_is_established':
        session['end_ref'] = copy.deepcopy(session['established_ref'])
    elif bad.startswith('wrong_') and bad in ('wrong_pid', 'wrong_worker',
                                                'wrong_seq', 'wrong_nonce',
                                                'wrong_connection_id'):
        key = bad.removeprefix('wrong_')
        value = 'other' if key in ('nonce', 'connection_id') else 99999
        session['end_ref'] = _append_probe(tmp_path, base, **{key: value})
    elif bad == 'later_error_skips_first_eof':
        old_end = json.loads((tmp_path / 'probe.jsonl').read_text().splitlines()[-1])
        _append_probe(tmp_path, base, event='error', utc_ticks=old_end['utc_ticks'] - 10000)
    elif bad == 'probe_creation':
        session['probe_creation'] += 1
    elif bad == 'managed_nonflow':
        session['managed_ref'] = copy.deepcopy(base['trigger']['upper_ref'])
    elif bad == 'later_matching_flow':
        path = tmp_path / 'run.log'
        later = path.read_text().replace('55,201', '55,202')
        with path.open('a') as stream: stream.write(later)
        _rehash(tmp_path, base, 'run.log')
    elif bad == 'wrong_tuple':
        session['dst'] = '119.188.175.47:443'
    elif bad == 'receipt_lower':
        base['trigger']['lower_ref'] = copy.deepcopy(base['receipt_ref'])
    elif bad == 'upper_unbound':
        base['trigger']['upper_ref'] = copy.deepcopy(base['receipt_ref'])
    elif bad in ('capture_mode', 'capture_conversion'):
        path = tmp_path / 'meta.json'
        meta = json.loads(path.read_text())
        if bad == 'capture_mode': meta['capture_mode'] = 'packet-only'
        else: meta['conversion']['exit_code'] = 1
        raw = json.dumps(meta).encode()
        path.write_bytes(raw)
        session['connection_capture']['metadata_ref']['byte_end'] = len(raw)
        _rehash(tmp_path, base, 'meta.json')
    elif bad == 'generation_refs':
        session['connection_event_refs'].pop()
    old, new = _check(base, tmp_path, monkeypatch)
    assert not next(x for x in old['checks'] if x['id'] == 'connection_structure')['passed']
    assert not next(x for x in old['checks'] if x['id'] == 'overlap')['passed']
    assert not next(x for x in new['checks'] if x['id'] == 'connection_structure')['passed']
    assert next(x for x in new['checks'] if x['id'] == 'native_qpc_interval')['passed']
    assert not new['passed']
