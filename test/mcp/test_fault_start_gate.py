"""Actual gate rendezvous and native handle observations for fault evidence."""
import json
import os
from pathlib import Path
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


@pytest.mark.skipif(os.name != 'nt', reason='Windows last-error semantics required')
def test_diverter_fault_clears_stale_error_and_preserves_action(tmp_path, monkeypatch):
    import ctypes
    from fakenet.diverters.windows import Diverter

    injector, logs, arm = setup_gate(tmp_path, monkeypatch)
    faultinject._fault_file().unlink()
    injector.arm('diverter_stop')
    closed = []

    class Handle:
        _handle = 123

        def close(self):
            # PyDivert 2.1.0's wrapper checks last-error even after success.
            closed.append(True)
            if ctypes.windll.kernel32.GetLastError():
                raise ctypes.WinError()

    diverter = Diverter.__new__(Diverter)
    diverter.handle = Handle()
    monkeypatch.setattr(faultinject, 'native_handle_observation', lambda raw: {
        'handle': raw, 'return_code': 0 if closed else 1,
        'last_error': 6 if closed else 0})
    # clear() includes filesystem operations which can leave ERROR_FILE_NOT_FOUND.
    original_clear = faultinject.clear
    def clear_with_stale_error():
        original_clear()
        ctypes.windll.kernel32.SetLastError(2)
    monkeypatch.setattr(faultinject, 'clear', clear_with_stale_error)

    assert injector.inject_diverter_stop(diverter)
    action = json.loads((tmp_path / 'run-identity' / 'fault-action.json').read_text())
    assert closed == [True]
    assert diverter.handle is None
    assert action['before']['return_code'] == 1
    assert action['after']['last_error'] == 6
    assert action['fault'] == 'diverter_stop'
    assert action['start_time_ns'] <= action['end_time_ns']


@pytest.mark.parametrize('supported', [True, False])
def test_action_clock_samples_bracket_close_without_replacing_utc(tmp_path, monkeypatch, supported):
    injector, _, _ = setup_gate(tmp_path, monkeypatch)
    faultinject._fault_file().unlink()
    injector.arm('diverter_stop')
    order = []

    class Handle:
        _handle = 123

    class Diverter:
        handle = Handle()

        def _close_windivert_handle(self):
            order.append('close')

    def observe_clock():
        order.append('clock')
        return dict(supported=supported, sample=len(order))

    monkeypatch.setattr(faultinject, 'native_handle_observation', lambda _: {})
    monkeypatch.setattr(faultinject, 'native_clock_observation', observe_clock)
    assert injector.inject_diverter_stop(Diverter())
    action = json.loads((tmp_path / 'run-identity' / 'fault-action.json').read_text())
    assert order == ['clock', 'close', 'clock']
    assert action['clock_observations'] == {
        'before': dict(supported=supported, sample=1),
        'after': dict(supported=supported, sample=3)}
    assert action['start_time_ns'] <= action['end_time_ns']
    assert action['schema'] == 'fakenet.fault-action.v1'


def test_identity_diagnostic_failure_does_not_skip_close(tmp_path, monkeypatch):
    injector, _, _ = setup_gate(tmp_path, monkeypatch)
    faultinject._fault_file().unlink()
    injector.arm('diverter_stop')
    closed = []

    class Diverter:
        handle = type('Handle', (), {'_handle': 123})()

        def _close_windivert_handle(self):
            closed.append(True)

    monkeypatch.setattr(faultinject, 'native_handle_observation', lambda _: {})
    monkeypatch.setattr(faultinject, 'native_clock_observation',
                        lambda: {'supported': False})
    monkeypatch.setattr('fakenet.mcp.native_provenance.native_identity',
                        lambda: (_ for _ in ()).throw(OSError('diagnostic failure')))
    assert injector.inject_diverter_stop(Diverter())
    result = json.loads((tmp_path / 'run-identity' / 'fault-action.json').read_text())
    assert closed == [True]
    assert result['native_identity']['before']['supported'] is False
    assert result['native_identity']['after']['supported'] is False
    assert 'diagnostic failure' in result['native_identity']['before']['error']


@pytest.mark.skipif(os.name != 'nt', reason='native Windows clock APIs required')
def test_native_precise_clock_records_ordered_raw_samples():
    first = faultinject.native_clock_observation()
    second = faultinject.native_clock_observation()
    assert first['supported'] and second['supported']
    assert first['qpc_before'] <= first['qpc_after'] <= second['qpc_before'] <= second['qpc_after']
    assert first['qpc_frequency'] == second['qpc_frequency'] > 0
    assert first['filetime_100ns'] > 0 and second['filetime_100ns'] > 0
    assert first['pid'] == second['pid'] == os.getpid()
    assert first['thread_id'] == second['thread_id'] == threading.get_native_id()


def test_in_child_gate_waits_for_probe_flow_and_own_log(tmp_path, monkeypatch):
    """diverter_stop: the gate with a probe key waits in-child (no ready file)."""
    injector, logs, arm = setup_gate(tmp_path, monkeypatch)
    faultinject._fault_file().unlink()
    (logs / 'fault-injection-gate.json').unlink(missing_ok=True)
    injector.arm('diverter_stop')
    arm = json.loads(faultinject._fault_file().read_text())
    probe = tmp_path / 'probe.jsonl'
    (logs / 'fault-injection-gate.json').write_text(
        json.dumps(dict(arm, probe=str(probe))))
    (Path('run.log')).write_text(
        'PROCESS_FLOW disposition=REDIRECT_TLS_RELAY domain=d dport=443 '
        'dst=198.51.100.77 pid=4242 process=powershell.exe proto=TCP '
        'sport=50444 src=192.168.204.233\n')
    probe.write_text(json.dumps({'event': 'ready', 'nonce': arm['nonce']}) + '\n')
    with pytest.raises(TimeoutError, match='probe-traffic'):
        injector.wait_for_start_gate(timeout=.05)  # no established yet
    probe.write_text(
        json.dumps({'event': 'established', 'nonce': arm['nonce'],
                    'pid': 4242, 'src': '192.168.204.233:50444'}) + '\n')
    assert injector.wait_for_start_gate(timeout=.3) is True
    assert not (logs / 'fault-injection-ready.json').exists()
    assert not (logs / 'fault-injection-gate.json').exists(), \
        'a stale gate blocks the next scenario arm'


def test_in_child_gate_rejects_unmapped_flow(tmp_path, monkeypatch):
    injector, logs, arm = setup_gate(tmp_path, monkeypatch)
    faultinject._fault_file().unlink()
    (logs / 'fault-injection-gate.json').unlink(missing_ok=True)
    injector.arm('diverter_stop')
    arm = json.loads(faultinject._fault_file().read_text())
    probe = tmp_path / 'probe.jsonl'
    (logs / 'fault-injection-gate.json').write_text(
        json.dumps(dict(arm, probe=str(probe))))
    (Path('run.log')).write_text('PROCESS_FLOW pid=9999 sport=1 src=1.2.3.4\n')
    probe.write_text(json.dumps({'event': 'established', 'nonce': arm['nonce'],
                                 'pid': 4242, 'src': '192.168.204.233:50444'}) + '\n')
    with pytest.raises(TimeoutError, match='probe-traffic'):
        injector.wait_for_start_gate(timeout=.05)


def test_in_child_gate_identity_mismatch_raises(tmp_path, monkeypatch):
    injector, logs, arm = setup_gate(tmp_path, monkeypatch)
    faultinject._fault_file().unlink()
    (logs / 'fault-injection-gate.json').unlink(missing_ok=True)
    injector.arm('diverter_stop')
    (logs / 'fault-injection-gate.json').write_text(
        json.dumps({'fault': 'diverter_stop', 'nonce': 'other', 'probe': 'x'}))
    with pytest.raises(ValueError, match='identity'):
        injector.wait_for_start_gate(timeout=.05)


def test_in_child_gate_requires_session_liveness(tmp_path, monkeypatch):
    """The release waits until the product-side session is still active.

    candidate15 sst-002: the relay worker tore the session down before the
    probe's established event, so the injected action (its native record
    write included) landed after the session's own end.  The liveness
    callable must hold the release until the mapping serves the tuple.
    """
    injector, logs, arm = setup_gate(tmp_path, monkeypatch)
    faultinject._fault_file().unlink()
    (logs / 'fault-injection-gate.json').unlink(missing_ok=True)
    injector.arm('diverter_stop')
    arm = json.loads(faultinject._fault_file().read_text())
    probe = tmp_path / 'probe.jsonl'
    (logs / 'fault-injection-gate.json').write_text(
        json.dumps(dict(arm, probe=str(probe))))
    (Path('run.log')).write_text(
        'PROCESS_FLOW disposition=REDIRECT_TLS_RELAY pid=4242 sport=50444 '
        'src=192.168.204.233\n')
    probe.write_text(json.dumps({'event': 'established', 'nonce': arm['nonce'],
                                 'pid': 4242, 'src': '192.168.204.233:50444'}) + '\n')
    state = {'live': False}
    injector.set_start_gate_liveness(lambda row: state['live'])
    with pytest.raises(TimeoutError, match='probe-traffic'):
        injector.wait_for_start_gate(timeout=.08)  # dead session never releases
    state['live'] = True
    assert injector.wait_for_start_gate(timeout=.3) is True
    assert not (logs / 'fault-injection-gate.json').exists()
