import importlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def release(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parent / 'acceptance'))
    return importlib.import_module('run_p05_release')


def test_file_lock_requires_sharing_violation_and_unchanged_bytes(release, monkeypatch):
    snap = {'run_id': 'active', 'config_identity': {
        'name': 'default.ini', 'builtin': True, 'sha256': 'a'*64}}
    monkeypatch.setattr(release, 'call', lambda *a, **k: snap)
    observed = dict(opened=False, error_code=32, before='a'*64, after='a'*64)
    gate = object.__new__(release.ReleaseGate)
    gate.base = 'unused'
    gate.channel = SimpleNamespace(powershell=lambda *a, **k: {'output': json.dumps(observed)})
    assert gate.config_lock_probe(1, True)[0] == 'config_in_use'
    observed['error_code'] = 5
    assert gate.config_lock_probe(1, True)[0] != 'config_in_use'
    observed.update(opened=True, error_code=0)
    assert gate.config_lock_probe(1, False)[0] == 'released'
    observed['after'] = 'b'*64
    with pytest.raises(RuntimeError, match='hash changed'):
        gate.config_lock_probe(1, False)


def test_matching_fault_mode_resume_does_not_restart_service(release, tmp_path, monkeypatch):
    commands = []
    gate = object.__new__(release.ReleaseGate)
    gate.release = tmp_path
    gate.base = 'unused'
    monkeypatch.setattr(release, 'wait_state', lambda *a, **k: (True, {'state': 'stopped'}))
    def powershell(command, **kwargs):
        commands.append(command)
        return {'output': json.dumps({'enabled': True, 'grace': 5})}
    gate.channel = SimpleNamespace(powershell=powershell)
    gate.vm_continuity = lambda: {'pid': 17, 'created': 'original'}
    assert gate.configure_fault_mode(True)['reused_service_instance']
    assert len(commands) == 1
    assert 'Start-Service' not in commands[0] and '& $exe stop' not in commands[0]


@pytest.mark.parametrize('outcome', ['failure', 'exception', 'enable_exception'])
def test_fault_mode_restored_on_unsuccessful_run(release, tmp_path, monkeypatch, outcome):
    gate = object.__new__(release.ReleaseGate)
    gate.args = SimpleNamespace()
    gate.release = tmp_path
    transitions, evidence = [], {}
    monkeypatch.setattr(release, 'matrix_counts', lambda *a: {'fault-policy_pause': 1})
    monkeypatch.setattr(release, 'FAULT_CLASSES', ('policy_pause',))
    monkeypatch.setattr(release, 'validate_sample_category', lambda *a: [])
    def configure(enabled):
        transitions.append(enabled)
        if enabled and outcome == 'enable_exception':
            raise RuntimeError('service readiness failed after enabling')
        return {'enabled': enabled}
    gate.configure_fault_mode = configure
    gate.round_path = lambda *a: tmp_path / 'round.json'
    gate.prior_round = lambda *a: False
    gate.record_round = lambda path, record, writer: evidence.update(round=record)
    def run(*args):
        if outcome == 'exception':
            raise RuntimeError('transport lost after arming')
        return {'failure': 'incident incomplete'}
    gate.run_fault_round = run
    writer = SimpleNamespace(add_evidence=lambda key, value: evidence.update({key: value}))
    if outcome == 'failure':
        assert gate.mode_fault(writer) == release.EXIT_FAIL
        assert evidence['round']['failure'] == 'incident incomplete'
    else:
        with pytest.raises(RuntimeError):
            gate.mode_fault(writer)
    assert transitions == [True, False]
    assert evidence['fault-mode-disabled'] == {'enabled': False}


@pytest.mark.parametrize('restore_fails', [False, True])
def test_fault_success_requires_successful_restore(release, tmp_path, monkeypatch, restore_fails):
    gate = object.__new__(release.ReleaseGate)
    gate.args = SimpleNamespace()
    gate.release = tmp_path
    transitions, evidence = [], {}
    monkeypatch.setattr(release, 'matrix_counts', lambda *a: {'fault-policy_pause': 1})
    monkeypatch.setattr(release, 'FAULT_CLASSES', ('policy_pause',))
    def configure(enabled):
        transitions.append(enabled)
        if not enabled and restore_fails:
            raise RuntimeError('restore failed')
        return {'enabled': enabled}
    gate.configure_fault_mode = configure
    gate.round_path = lambda *a: tmp_path / 'round.json'
    gate.prior_round = lambda *a: True
    gate.done_rounds = lambda *a: [1]
    writer = SimpleNamespace(add_evidence=lambda key, value: evidence.update({key: value}))
    if restore_fails:
        with pytest.raises(RuntimeError, match='restore failed'):
            gate.mode_fault(writer)
        assert 'fault-mode-restore-failure' in evidence
        assert 'fault-mode-disabled' not in evidence
    else:
        assert gate.mode_fault(writer) == release.EXIT_PASS
        assert evidence['fault-mode-disabled'] == {'enabled': False}
    assert transitions == [True, False]


@pytest.mark.parametrize('mode', ['normal', 'fault'])
def test_category_validation_preserves_original_round_failure(release, tmp_path, monkeypatch, mode):
    gate = object.__new__(release.ReleaseGate)
    gate.args = SimpleNamespace()
    gate.release = tmp_path
    monkeypatch.setattr(release, 'matrix_counts', lambda *a: {
        'normal-builtin': 1, 'normal-custom': 1, 'fault-policy_pause': 1})
    monkeypatch.setattr(release, 'FAULT_CLASSES', ('policy_pause',))
    monkeypatch.setattr(release, 'validate_sample_category', lambda *a: ['missing run identity'])
    gate.ensure_custom_config = lambda: True
    gate.configure_fault_mode = lambda enabled: {'enabled': enabled}
    gate.round_path = lambda *a: tmp_path / 'round.json'
    gate.prior_round = lambda *a: False
    captured = []
    gate.record_round = lambda path, record, writer: captured.append(record)
    gate.run_normal_round = lambda *a: {'failure': 'managed start failed: SystemExit(1)'}
    gate.run_fault_round = gate.run_normal_round
    writer = SimpleNamespace(add_evidence=lambda *a: None)
    assert getattr(gate, 'mode_' + mode)(writer) == release.EXIT_FAIL
    assert 'managed start failed: SystemExit(1)' in captured[0]['failure']
    assert 'missing run identity' in captured[0]['failure']
