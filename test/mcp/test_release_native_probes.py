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


def test_matching_fault_mode_resume_does_not_restart_service(release):
    commands = []
    gate = object.__new__(release.ReleaseGate)
    def powershell(command, **kwargs):
        commands.append(command)
        return {'output': json.dumps({'enabled': True, 'grace': 5})}
    gate.channel = SimpleNamespace(powershell=powershell)
    gate.vm_continuity = lambda: {'pid': 17, 'created': 'original'}
    assert gate.configure_fault_mode(True)['reused_service_instance']
    assert len(commands) == 1
    assert 'Start-Service' not in commands[0] and '& $exe stop' not in commands[0]
