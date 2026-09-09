import hashlib
import json
import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location('evidence_integrity',
    Path(__file__).parent / 'acceptance' / 'evidence_integrity.py')
integrity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(integrity)


@pytest.fixture
def identity():
    return dict(candidate_id='one', source_commit='a'*40, package_sha256='b'*64,
                requirements_blob='c'*40, master_plan_blob='d'*40)


def test_result_rejects_foreign_nonempty_source_and_tampered_bytes(tmp_path, identity):
    evidence = tmp_path / 'raw.json'
    evidence.write_bytes(b'actual')
    result = dict(identity, status='pass', evidence=[dict(path=str(evidence), size=6,
                  sha256=hashlib.sha256(b'actual').hexdigest())])
    assert integrity.validate_result(result, identity, tmp_path) == []
    result['source_commit'] = 'e'*40
    assert 'identity mismatch: source_commit' in integrity.validate_result(result, identity, tmp_path)
    result.update(identity)
    evidence.write_bytes(b'edited')
    assert integrity.validate_result(result, identity, tmp_path)


def test_round_rejects_summary_without_window_and_service_restart(identity, tmp_path):
    round = dict(identity, final_state='stopped', audit_diff={},
                 lock_released_after_stop=True, probe={'all_ok': True, 'samples': 8})
    assert integrity.validate_round(round, identity)
    round.update(probe_window_start=1.1, probe_window_end=2.9,
                 probe_timeline=[dict(t=1,ok=True),dict(t=2,ok=True),dict(t=3,ok=True)],
                 vm_before={'pid': 1, 'created': 123}, vm_after={'pid': 1, 'created': 123})
    captures = []
    for name in ('before', 'after'):
        path = tmp_path / (name + '.json')
        raw = json.dumps(dict(identity, complete=True, started_at=1.2, ended_at=2.8,
                             sections={key:'raw' for key in
            ('routes','dns_servers','windivert_processes','listen_ports','services')})).encode()
        path.write_bytes(raw)
        captures.append(dict(path=str(path), size=len(raw), sha256=hashlib.sha256(raw).hexdigest()))
    round['capture_evidence'] = captures
    assert integrity.validate_round(round, identity) == []
    original = Path(captures[0]['path']).read_bytes()
    Path(captures[0]['path']).write_bytes(original + b' ')
    assert 'environment capture hash/size mismatch' in integrity.validate_round(round, identity)
    Path(captures[0]['path']).write_bytes(original)
    round['vm_after'] = {'pid': 1, 'created': 456}
    assert 'VM/service identity drift' in integrity.validate_round(round, identity)
    round['vm_after'] = round['vm_before']
    round['probe_timeline'][1]['ok'] = False
    assert integrity.validate_round(round, identity)

