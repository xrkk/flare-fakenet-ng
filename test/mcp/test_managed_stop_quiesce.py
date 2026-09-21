"""A failed managed stop must quiesce redirected client flows.

Counter-example built from candidate10 sst-004 (run dd2c7b7e): the injected
cleanup error skipped instance.stop(), the supervisor's Job termination
released the WinDivert handle at 13:38:54.8092, kernel handle cleanup aborted
the relay socket at 13:38:54.8110 when no rewrite could translate the abort
RST, and the probe's kernel TCB retransmitted its unacknowledged 141-byte
request onto the physical NIC on the original tuple at 13:38:54.9172.  These
tests pin the fail-safe: the failed-stop path resets relayed flows while the
diverter filter is still open, and the orderly path is unchanged.
"""
import ctypes
import io
import json
import logging
import sys
import threading
from types import SimpleNamespace

import pytest

from fakenet.mcp import managed, service_stop


class _FakeRelayListener:
    def __init__(self, fail_quiesce=None):
        self.calls = []
        self.fail_quiesce = fail_quiesce

    def quiesce(self, reason):
        self.calls.append(reason)
        if self.fail_quiesce:
            raise self.fail_quiesce


class _FakeInstance:
    def __init__(self, stop_error=None, quiesce_error=None):
        self.stop_error = stop_error
        self.quiesce_error = quiesce_error
        self.stop_calls = 0
        self.quiesce_calls = []
        self.running_listener_providers = []
        self.diverter = SimpleNamespace(handle=None, diverter_thread=None)

    def parse_config(self, path):
        pass

    @property
    def fakenet_config(self):
        return {}

    @property
    def diverter_config(self):
        return {}

    def start(self):
        pass

    def stop(self):
        self.stop_calls += 1
        if self.stop_error:
            raise self.stop_error

    def quiesce_redirected_flows(self, reason):
        self.quiesce_calls.append(reason)
        if self.quiesce_error:
            raise self.quiesce_error


def _child_harness(monkeypatch, tmp_path, requests, instance):
    def in_job(process, job, result):
        ctypes.cast(result, ctypes.POINTER(ctypes.wintypes.BOOL)).contents.value = True
        return True
    kernel = SimpleNamespace(GetCurrentProcess=lambda: 1,
                             IsProcessInJob=in_job)
    monkeypatch.setattr(ctypes, 'WinDLL', lambda *a, **k: kernel, raising=False)
    monkeypatch.delenv('FAKENETNG_MCP_FAULT_INJECTION', raising=False)
    monkeypatch.setenv('PROGRAMDATA', str(tmp_path))
    monkeypatch.setattr(logging, 'basicConfig', lambda **k: None)
    logging.getLogger().addHandler(logging.NullHandler())
    monkeypatch.setattr(managed, 'install_thread_exception_logging', lambda: None)
    monkeypatch.setattr(service_stop, 'process_identity',
                        lambda pid: {'pid': 42, 'creation_time': '123'})
    monkeypatch.setitem(sys.modules, 'fakenet.fakenet',
                        SimpleNamespace(Fakenet=lambda: instance))
    output = io.BytesIO()
    monkeypatch.setattr(managed, 'redirect_child_streams', lambda path: (
        io.BytesIO(b''.join(json.dumps(x).encode() + b'\n' for x in requests)),
        output, io.StringIO()))
    return output


def _start_then_stop_requests():
    return [dict(run_id='current', seq=1, kind='ready', payload={}),
            dict(run_id='current', seq=2, kind='start',
                 payload={'config_path': 'x', 'fakenet_config': {},
                          'diverter_config': {}}),
            dict(run_id='current', seq=3, kind='stop', payload={})]


def test_failed_stop_quiesces_redirected_flows_once(monkeypatch, tmp_path):
    stop_error = RuntimeError('injected cleanup error')
    instance = _FakeInstance(stop_error=stop_error)
    output = _child_harness(monkeypatch, tmp_path, _start_then_stop_requests(),
                            instance)
    # A failed stop keeps the child alive: the loop only exits through the
    # protocol stream ending, so child_main returns 1, not the stop exit 0.
    assert managed.child_main('current', tmp_path) == 1
    responses = [json.loads(x) for x in output.getvalue().splitlines()]
    stop_response = responses[-1]
    assert stop_response['error'] and 'injected cleanup error' in stop_response['error']
    assert instance.stop_calls == 1
    assert instance.quiesce_calls == ['managed_stop_failed']


def test_successful_stop_never_quiesces(monkeypatch, tmp_path):
    instance = _FakeInstance()
    output = _child_harness(monkeypatch, tmp_path, _start_then_stop_requests(),
                            instance)
    assert managed.child_main('current', tmp_path) == 0
    responses = [json.loads(x) for x in output.getvalue().splitlines()]
    assert responses[-1]['result'] == {'stopped': True}
    assert instance.stop_calls == 1
    assert instance.quiesce_calls == []


def test_quiesce_failure_does_not_mask_stop_error(monkeypatch, tmp_path):
    stop_error = RuntimeError('injected cleanup error')
    instance = _FakeInstance(stop_error=stop_error,
                             quiesce_error=OSError('quiesce socket failure'))
    output = _child_harness(monkeypatch, tmp_path, _start_then_stop_requests(),
                            instance)
    assert managed.child_main('current', tmp_path) == 1
    responses = [json.loads(x) for x in output.getvalue().splitlines()]
    assert 'injected cleanup error' in responses[-1]['error']
    assert 'quiesce socket failure' not in responses[-1]['error']
    assert instance.quiesce_calls == ['managed_stop_failed']


def test_stop_without_instance_does_not_quiesce(monkeypatch, tmp_path):
    instance = _FakeInstance()
    requests = [dict(run_id='current', seq=1, kind='ready', payload={}),
                dict(run_id='current', seq=2, kind='stop', payload={})]
    output = _child_harness(monkeypatch, tmp_path, requests, instance)
    assert managed.child_main('current', tmp_path) == 0
    responses = [json.loads(x) for x in output.getvalue().splitlines()]
    assert responses[-1]['result'] == {'stopped': True}
    assert instance.stop_calls == 0 and instance.quiesce_calls == []
