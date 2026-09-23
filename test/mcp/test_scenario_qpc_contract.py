"""Self-contained explicit QPC contract tests; no guest or historical Logs."""
import copy
import hashlib
import json
from pathlib import Path
import sys

import pytest

HERE = Path(__file__).parent / 'acceptance'
sys.path.insert(0, str(HERE))
import scenario_qpc_contract as contract
import scenario_fault_evidence as adapter
import sst_fault_evidence as oracle


def _put(root, name, value):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(value) + '\n').encode()
    path.write_bytes(raw)
    return ({'path': name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()},
            {'path': name, 'byte_start': 0, 'byte_end': len(raw), 'event_key': 'json:'})


def _fixture(root):
    frequency, pid = 10_000_000, 404
    sample = lambda a, b: dict(supported=True, api='GetSystemTimePreciseAsFileTime',
                               pid=pid, thread_id=123, qpc_frequency=frequency,
                               qpc_before=a, qpc_after=b, filetime_100ns=a)
    capture = {'clock_before': {'q0': 1, 'q1': 2},
               'clock_after': {'q0': 98, 'q1': 100}}
    action = {'run_id': 'run', 'nonce': 'nonce', 'pid': pid,
              'clock_observations': {'before': sample(30, 31), 'after': sample(40, 41)}}
    files = []
    refs = {}
    for name, value in (('capture.json', capture), ('action.json', action),
                        ('end.json', {'time': '100'})):
        rec, ref = _put(root, name, value)
        files.append(rec); refs[name] = ref
    base = {'schema': 'sst.fault-evidence.case.v2', 'fault': 'diverter_stop',
            'run_id': 'run', 'nonce': 'nonce', 'synthetic': False,
            'candidate_id': 'candidate', 'clock': {'resolution_ns': 1},
            'session': {'observation_kind': 'tcpip_etw',
                        'connection_capture': {'metadata_ref': refs['capture.json']},
                        'end_ref': refs['end.json']},
            'trigger': {'upper_ref': refs['action.json']}, 'files': files}
    base_path = root / 'base.json'
    base_path.write_text(json.dumps(base) + '\n')
    derived = {'source_windows_status': 'COMPLETE_DIAGNOSTIC_ONLY',
               'identity': {'managed_pid': pid, 'qpc_frequency': frequency},
               'targets': [dict(kind='connect completed', terminal=False, seq=1, raw_qpc=20),
                           dict(kind='accept completed', terminal=False, seq=2, raw_qpc=22),
                           dict(kind='peer RST', terminal=True, seq=3, raw_qpc=50),
                           dict(kind='main close', terminal=True, seq=4, raw_qpc=52),
                           dict(kind='tuple abort', terminal=True, seq=5, raw_qpc=55)],
               'conservative_utc_bounds_ns': {'session_begin_upper': 10,
                                               'trigger_lower': 20, 'trigger_upper': 30}}
    return base_path, base, derived


def _evaluate(tmp_path, monkeypatch, derived):
    monkeypatch.setattr(contract.offline, 'derive', lambda *args: copy.deepcopy(derived))
    return contract.evaluate(tmp_path / 'base.json', tmp_path, tmp_path / 'export')


def test_qpc_full_interval_uses_earliest_of_all_terminals(tmp_path, monkeypatch):
    _, _, derived = _fixture(tmp_path)
    proof = _evaluate(tmp_path, monkeypatch, derived)
    assert proof['passed']
    assert proof['native_qpc']['latest_establishment'] == 22
    assert proof['native_qpc']['earliest_terminal'] == 50
    assert proof['native_qpc']['establishment_to_action_ticks'] == 8
    assert proof['native_qpc']['action_to_terminal_ticks'] == 9


@pytest.mark.parametrize('kind', ['peer RST', 'main close', 'tuple abort'])
@pytest.mark.parametrize('gap,passes', [(0, False), (1, False), (2, True), (-1, False)])
def test_every_terminal_exact_tick_boundary(tmp_path, monkeypatch, kind, gap, passes):
    _, _, derived = _fixture(tmp_path)
    for target in derived['targets']:
        if target['terminal']:
            target['raw_qpc'] = 90
        if target['kind'] == kind:
            target['raw_qpc'] = 41 + gap
    assert _evaluate(tmp_path, monkeypatch, derived)['native_qpc']['passed'] is passes


@pytest.mark.parametrize('gap,passes', [(0, False), (1, False), (2, True), (-1, False)])
def test_latest_establishment_exact_tick_boundary(tmp_path, monkeypatch, gap, passes):
    _, _, derived = _fixture(tmp_path)
    derived['targets'][1]['raw_qpc'] = 30 - gap
    assert _evaluate(tmp_path, monkeypatch, derived)['native_qpc']['passed'] is passes


@pytest.mark.parametrize('change', [
    lambda d: d.update(source_windows_status='INCOMPLETE'),
    lambda d: d['identity'].update(qpc_frequency=True),
    lambda d: d['identity'].update(managed_pid=0),
    lambda d: d['targets'][0].update(raw_qpc=101),
    lambda d: d['targets'][1].update(kind='connect completed'),
])
def test_incomplete_or_bad_clock_identity_fails(tmp_path, monkeypatch, change):
    _, _, derived = _fixture(tmp_path)
    change(derived)
    with pytest.raises(oracle.EvidenceError):
        _evaluate(tmp_path, monkeypatch, derived)


def test_utc_left_and_probe_end_remain_independent(tmp_path, monkeypatch):
    _, _, derived = _fixture(tmp_path)
    derived['conservative_utc_bounds_ns']['session_begin_upper'] = 21
    assert not _evaluate(tmp_path, monkeypatch, derived)['passed']
    derived['conservative_utc_bounds_ns']['session_begin_upper'] = 10
    derived['conservative_utc_bounds_ns']['trigger_upper'] = 10**30
    assert not _evaluate(tmp_path, monkeypatch, derived)['passed']


def test_action_brackets_and_capture_range_fail_closed(tmp_path, monkeypatch):
    _, _, derived = _fixture(tmp_path)
    path = tmp_path / 'action.json'
    action = json.loads(path.read_text())
    action['clock_observations']['after']['thread_id'] = 124
    _put(tmp_path, 'action.json', action)
    base = json.loads((tmp_path / 'base.json').read_text())
    base['files'][1] = adapter.record(path, tmp_path)
    (tmp_path / 'base.json').write_text(json.dumps(base) + '\n')
    with pytest.raises(oracle.EvidenceError, match='same-thread'):
        _evaluate(tmp_path, monkeypatch, derived)


def test_original_byte_change_and_missing_clock_rejected(tmp_path, monkeypatch):
    _, _, derived = _fixture(tmp_path)
    action_path = tmp_path / 'action.json'
    action_path.write_bytes(action_path.read_bytes() + b' ')
    with pytest.raises(oracle.EvidenceError, match='size/hash'):
        _evaluate(tmp_path, monkeypatch, derived)
    base = json.loads((tmp_path / 'base.json').read_text())
    base['files'][1] = adapter.record(action_path, tmp_path)
    (tmp_path / 'base.json').write_text(json.dumps(base) + '\n')
    action = json.loads(action_path.read_text())
    del action['clock_observations']['after']
    _put(tmp_path, 'action.json', action)
    base['files'][1] = adapter.record(action_path, tmp_path)
    (tmp_path / 'base.json').write_text(json.dumps(base) + '\n')
    with pytest.raises((KeyError, oracle.EvidenceError)):
        _evaluate(tmp_path, monkeypatch, derived)


def test_v2_never_implicitly_selects_qpc():
    with pytest.raises(oracle.EvidenceError, match='explicit case.v3'):
        oracle.assess({'schema': 'sst.fault-evidence.case.v2',
                       'clock_evidence_mode': contract.MODE}, Path('/not-used'))


def test_v3_requires_frozen_base_and_every_export_original(tmp_path):
    base_path, base, _ = _fixture(tmp_path)
    base['case_id'] = 'case'
    base_path.write_text(json.dumps(base) + '\n')
    descriptor = {'clock_evidence_mode': contract.MODE, 'fault': 'diverter_stop',
                  'base_case_path': 'base.json', 'qpc_export_prefix': 'export'}
    for name in adapter.QPC_EXPORT_FILES:
        _put(tmp_path, 'export/' + name, {})
    case = adapter.build_qpc_case(tmp_path, descriptor, base)
    assert case['schema'] == contract.SCHEMA
    assert len(case['files']) == len(base['files']) + 1 + len(adapter.QPC_EXPORT_FILES)
    changed = copy.deepcopy(base); changed['nonce'] = 'borrowed'
    with pytest.raises(ValueError, match='frozen base-v2'):
        adapter.build_qpc_case(tmp_path, descriptor, changed)
    (tmp_path / 'export/tdh/metadata.jsonl').unlink()
    with pytest.raises(ValueError, match='incomplete'):
        adapter.build_qpc_case(tmp_path, descriptor, base)
    descriptor['fault'] = 'listener_stop'
    with pytest.raises(ValueError, match='requires diverter_stop'):
        adapter.build_qpc_case(tmp_path, descriptor, base)


def test_v3_actual_case_shape_runs_legacy_and_new_checks(tmp_path, monkeypatch):
    # Reuse a native TCPIP/ETW fixture with byte addressed references. The
    # QPC exporter is replaced here; its full raw/TDH path has separate tests.
    import importlib.util
    spec = importlib.util.spec_from_file_location('tcpip_case_fixture',
        Path(__file__).with_name('test_sst_tcpip_events.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _, base = module.oracle_case(tmp_path)
    base['synthetic'] = False
    base['fault'] = 'diverter_stop'
    base_path = tmp_path / 'frozen.json'
    base_path.write_text(json.dumps(base) + '\n')
    for name in adapter.QPC_EXPORT_FILES:
        _put(tmp_path, 'export/' + name, {})
    descriptor = {'clock_evidence_mode': contract.MODE, 'fault': 'diverter_stop',
                  'base_case_path': 'frozen.json', 'qpc_export_prefix': 'export'}
    case = adapter.build_qpc_case(tmp_path, descriptor, base)
    proof = {'utc': {'passed': True}, 'native_qpc': {'passed': True}}
    monkeypatch.setattr(contract, 'evaluate', lambda *args, **kwargs: proof)
    result = oracle.assess(case, tmp_path, base['candidate_id'])
    assert result['legacy_utc_full_interval']['passed'] is True
    assert any(x['id'] == 'native_qpc_interval' and x['passed'] for x in result['checks'])
    assert any(x['id'] == 'trigger_success' and not x['passed'] for x in result['checks'])
    assert not result['passed']  # QPC does not waive the original action check.
    bad = copy.deepcopy(case); bad['nonce'] = 'other'
    assert not oracle.assess(bad, tmp_path, base['candidate_id'])['passed']
