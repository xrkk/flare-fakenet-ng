import json
import threading
from types import SimpleNamespace

from fakenet.mcp.faultinject import FaultInjector, _fault_file


def test_capture_fault_is_consumed_only_in_selected_worker(tmp_path, monkeypatch):
    monkeypatch.setenv('PROGRAMDATA', str(tmp_path / 'data'))
    monkeypatch.setenv('FAKENETNG_MCP_FAULT_INJECTION', '1')
    monkeypatch.chdir(tmp_path)
    release = threading.Event()
    entered = threading.Event()
    errors = []
    diverter = SimpleNamespace(_check_recv_cycle_gap=lambda *args: True)
    def inbound():
        entered.set()
        if release.wait(3):
            try:
                diverter._check_recv_cycle_gap('inbound', None)
            except RuntimeError as exc:
                errors.append(str(exc))
    worker = threading.Thread(target=inbound)
    diverter.inbound_capture_thread = worker
    worker.start()
    try:
        assert entered.wait(1)
        injector = FaultInjector()
        assert injector.install_capture_exception_hook(diverter)
        injector.arm('capture_exception')
        nonce = json.loads(_fault_file().read_text())['nonce']
        assert diverter._check_recv_cycle_gap('main', None)
        assert _fault_file().exists()
        release.set()
        worker.join(2)
        assert errors == ['injected capture thread exception']
        assert json.loads((tmp_path / 'fault-triggered.json').read_text())['nonce'] == nonce
        assert json.loads((tmp_path / 'capture-exception-time.json').read_text())['thread_id'] == worker.ident
        assert not _fault_file().exists()
    finally:
        release.set()
        worker.join(2)


def test_disabled_capture_hook_does_not_change_worker(tmp_path, monkeypatch):
    monkeypatch.setenv('PROGRAMDATA', str(tmp_path))
    monkeypatch.delenv('FAKENETNG_MCP_FAULT_INJECTION', raising=False)
    original = lambda *args: True
    diverter = SimpleNamespace(_check_recv_cycle_gap=original,
                               inbound_capture_thread=threading.current_thread())
    assert not FaultInjector().install_capture_exception_hook(diverter)
    assert diverter._check_recv_cycle_gap is original
