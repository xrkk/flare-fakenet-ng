import importlib
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def modules(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parent / 'acceptance'))
    return importlib.import_module('run_p01_acc'), importlib.import_module('run_p03_acc')


def test_failed_prestop_prevents_any_deployment_or_force_kill(modules, monkeypatch):
    p01, _ = modules
    commands = []
    def reject(command, **kwargs):
        commands.append(command)
        raise p01.StepError('pre-stop not clean')
    channel = SimpleNamespace(powershell=reject)
    writer = SimpleNamespace(add_evidence=lambda *a: None)
    def forbidden(*a, **kw):
        raise AssertionError('transfer must not start after rejected stop')
    monkeypatch.setattr(p01, 'PackageServer', forbidden)
    with pytest.raises(p01.StepError, match='not clean'):
        p01._deploy_with_server(None, channel, writer, None, None, None, None)
    assert len(commands) == 1
    assert '& $exe stop' in commands[0]
    assert 'Stop-Process' not in commands[0] and 'sc.exe stop' not in commands[0]


def test_failed_start_and_failed_state_are_not_retried_or_restarted(modules, monkeypatch):
    _, p03 = modules
    calls = []
    monkeypatch.setattr(p03, 'status', lambda *a: {'state': 'failed', 'state_version': 3})
    def call(base, name, args, **kwargs):
        calls.append(name)
        return {'state': 'failed', 'state_version': 4, 'error': None}
    monkeypatch.setattr(p03, 'call', call)
    monkeypatch.setattr(p03.time, 'sleep', lambda *a: pytest.fail('unexpected retry wait'))
    assert p03.load_and_start('unused')['state'] == 'failed'
    assert calls == ['load_config', 'start']
    channel = SimpleNamespace(powershell=lambda *a, **kw: pytest.fail('must preserve failure'))
    assert p03.normalize_service('unused', channel) is False
