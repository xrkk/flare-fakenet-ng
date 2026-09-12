"""Actual gate rendezvous and native handle observations for fault evidence."""
import json
import os
import threading
import time

import pytest

from fakenet.mcp import faultinject


def setup_gate(tmp_path, monkeypatch, ready=None):
    monkeypatch.setenv('PROGRAMDATA', str(tmp_path / 'data'))
    monkeypatch.setenv('FAKENETNG_MCP_FAULT_INJECTION', '1')
    run = tmp_path / 'run-identity'
    run.mkdir()
    monkeypatch.chdir(run)
    injector = faultinject.FaultInjector()
    injector.arm('child_hang')
    logs = faultinject._fault_file().parent
    arm = json.loads(faultinject._fault_file().read_text())
    (logs / 'fault-injection-gate.json').write_text(json.dumps(arm))
    if ready is not None:
        (logs / 'fault-injection-ready.json').write_text(json.dumps(dict(arm, **ready)))
    return injector, logs, arm


def test_start_gate_waits_for_matching_run_without_consuming_fault(tmp_path, monkeypatch):
    injector, logs, arm = setup_gate(tmp_path, monkeypatch)
    finished = threading.Event()
    def wait():
        injector.wait_for_start_gate(timeout=2)
        finished.set()
    worker = threading.Thread(target=wait)
    worker.start()
    assert not finished.wait(.05)
    (logs / 'fault-injection-ready.json').write_text(json.dumps(dict(arm, run_id='run-identity')))
    worker.join(3)
    assert finished.is_set()
    assert faultinject.armed_fault() == 'child_hang'
    assert not (logs / 'fault-injection-gate.json').exists()
    assert not (logs / 'fault-injection-ready.json').exists()
    assert not (tmp_path / 'run-identity' / 'fault-triggered.json').exists()


def test_gate_rejects_wrong_run_and_timeout(tmp_path, monkeypatch):
    injector, logs, arm = setup_gate(tmp_path, monkeypatch, {'run_id': 'other-run'})
    with pytest.raises(ValueError, match='identity'):
        injector.wait_for_start_gate(timeout=.05)
    (logs / 'fault-injection-ready.json').unlink()
    with pytest.raises(TimeoutError, match='gate'):
        injector.wait_for_start_gate(timeout=.05)
    assert faultinject.armed_fault() == 'child_hang'


def test_no_gate_or_disabled_fault_mode_has_no_wait(tmp_path, monkeypatch):
    injector, logs, arm = setup_gate(tmp_path, monkeypatch)
    monkeypatch.delenv('FAKENETNG_MCP_FAULT_INJECTION')
    assert injector.wait_for_start_gate(timeout=0) is False
    monkeypatch.setenv('FAKENETNG_MCP_FAULT_INJECTION', '1')
    (logs / 'fault-injection-gate.json').unlink()
    assert injector.wait_for_start_gate(timeout=0) is False


@pytest.mark.skipif(os.name != 'nt', reason='native Windows kernel handle required')
def test_native_handle_query_distinguishes_open_and_closed_handle():
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateEventW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
    kernel.CreateEventW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    handle = kernel.CreateEventW(None, False, False, None)
    assert handle
    try:
        before = faultinject.native_handle_observation(handle)
        assert before['api'] == 'GetHandleInformation' and before['return_code'] == 1
    finally:
        assert kernel.CloseHandle(handle)
    after = faultinject.native_handle_observation(handle)
    assert after['return_code'] == 0 and after['last_error'] == 6
