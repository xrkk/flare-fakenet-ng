import json
import traceback

import pytest

from fakenet.fakenet import Fakenet
from fakenet.mcp.faultinject import FaultInjector, _fault_file


def test_initialization_fault_runs_inside_actual_start(tmp_path, monkeypatch):
    monkeypatch.setenv('PROGRAMDATA', str(tmp_path / 'data'))
    monkeypatch.setenv('FAKENETNG_MCP_FAULT_INJECTION', '1')
    monkeypatch.chdir(tmp_path)
    instance = Fakenet()
    injector = FaultInjector()
    injector.arm('initialization_failure')
    armed = json.loads(_fault_file().read_text())
    assert injector.install_initialization_hook(instance)
    with pytest.raises(RuntimeError, match='injected managed initialization failure') as exc:
        instance.start()
    stack = traceback.extract_tb(exc.value.__traceback__)
    assert any(frame.name == 'start' and frame.filename.endswith('fakenet.py') for frame in stack)
    assert instance.diverter is None
    assert not instance.running_listener_providers
    assert json.loads((tmp_path / 'fault-triggered.json').read_text()) == armed
    assert not _fault_file().exists()


def test_initialization_fault_disabled_does_not_install_or_consume(tmp_path, monkeypatch):
    monkeypatch.setenv('PROGRAMDATA', str(tmp_path / 'data'))
    monkeypatch.delenv('FAKENETNG_MCP_FAULT_INJECTION', raising=False)
    instance = Fakenet()
    injector = FaultInjector()
    injector.arm('initialization_failure')
    assert not injector.install_initialization_hook(instance)
    assert not hasattr(instance, '_managed_initialization_hook')
    assert _fault_file().is_file()
