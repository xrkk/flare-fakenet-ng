"""Exercise the production request validator over actual anonymous pipes."""
import json
import os
import queue
import threading
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from fakenet.mcp.faultinject import FaultInjector, _fault_file
from fakenet.mcp.managed import ManagedProcess


@contextmanager
def transport(tmp_path, monkeypatch, fault):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('PROGRAMDATA', str(tmp_path))
    monkeypatch.setenv('FAKENETNG_MCP_FAULT_INJECTION', '1')
    injector = FaultInjector()
    injector.arm(fault)
    child_in, parent_out = os.pipe()
    parent_in, child_out = os.pipe()
    managed = object.__new__(ManagedProcess)
    managed.run_id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
    managed.run_dir = tmp_path
    managed.pid = 1
    managed._sequence = 0
    managed._write_failed = False
    managed._lock = threading.Lock()
    managed._responses = queue.Queue(maxsize=64)
    managed._send = os.fdopen(parent_out, 'wb', buffering=0)
    managed._receive = os.fdopen(parent_in, 'rb', buffering=0)
    managed.job = SimpleNamespace(poll=lambda: None, members=lambda: [1])
    def child():
        with os.fdopen(child_in, 'rb', buffering=0) as source, os.fdopen(child_out, 'wb', buffering=0) as sink:
            for raw in source:
                request = json.loads(raw)
                response = dict(run_id=request['run_id'], seq=request['seq'], result={'probe': True})
                action, response = injector.ipc_response(request, response)
                if action == 'eof':
                    return
                if action == 'send':
                    sink.write(json.dumps(response).encode() + b'\n')
    worker = threading.Thread(target=child, daemon=True)
    reader = threading.Thread(target=managed._read, daemon=True)
    worker.start()
    reader.start()
    try:
        yield managed
    finally:
        managed._send.close()
        worker.join(2)
        reader.join(2)
        managed._receive.close()
        assert not worker.is_alive() and not reader.is_alive()


def test_dropped_single_response_recovers_only_on_next_sequence(tmp_path, monkeypatch):
    with transport(tmp_path, monkeypatch, 'ipc_once_timeout') as managed:
        with pytest.raises(TimeoutError):
            managed.request('health', timeout=0.1)
        assert managed.request('health', timeout=1) == {'probe': True}
        assert managed._sequence == 2
    rows = [json.loads(x) for x in (tmp_path / 'ipc-parent.jsonl').read_text().splitlines()]
    assert [x['frame']['seq'] for x in rows if x['event'] == 'response'] == [2]
    assert json.loads((tmp_path / 'fault-triggered.json').read_text())['fault'] == 'ipc_once_timeout'
    assert not _fault_file().exists()


def test_permanent_health_loss_keeps_fixed_stack_channel_available(tmp_path, monkeypatch):
    with transport(tmp_path, monkeypatch, 'ipc_permanent_timeout') as managed:
        for _ in range(2):
            with pytest.raises(TimeoutError):
                managed.request('health', timeout=0.1)
        assert managed.request('stacks', timeout=1) == {'probe': True}


@pytest.mark.parametrize('fault,exception', [
    ('ipc_eof', EOFError), ('ipc_wrong_run', RuntimeError),
    ('ipc_repeat', RuntimeError), ('ipc_reverse', RuntimeError),
])
def test_terminal_wire_faults_are_rejected(tmp_path, monkeypatch, fault, exception):
    with transport(tmp_path, monkeypatch, fault) as managed:
        with pytest.raises(exception):
            managed.request('health', timeout=1)


def test_disabled_fault_cannot_consume_file_or_change_response(tmp_path, monkeypatch):
    monkeypatch.setenv('PROGRAMDATA', str(tmp_path))
    monkeypatch.delenv('FAKENETNG_MCP_FAULT_INJECTION', raising=False)
    fault = FaultInjector()
    fault.arm('ipc_eof')
    response = {'run_id': 'run', 'seq': 2, 'result': {}}
    assert fault.ipc_response({'kind': 'health'}, response) == ('send', response)
    assert _fault_file().exists()


@pytest.mark.parametrize('permanent', [False, True])
def test_health_timeout_uses_two_second_request_period(tmp_path, monkeypatch, permanent):
    from fakenet.mcp import supervisor as module
    clock = SimpleNamespace(now=0.0, stopped=False)
    monkeypatch.setattr(module, 'time', SimpleNamespace(monotonic=lambda: clock.now))
    def wait(delay):
        if clock.stopped:
            return True
        clock.now += delay
        return False
    requests, states = [], []
    def request(kind, timeout):
        requests.append(clock.now)
        assert kind == 'health' and timeout == 1
        if permanent or len(requests) == 1:
            clock.now += 1
            raise TimeoutError('managed IPC response timeout')
        return {'init_evidence': True, 'probe': True}
    instance = object.__new__(module.RealSupervisor)
    instance._health_stop = SimpleNamespace(wait=wait)
    instance._fakenet = SimpleNamespace(request=request, alive=lambda: True, identity={'pid': 1})
    instance._run_dir = tmp_path
    instance._health_cache = {'probe': True}
    instance._coordinator = SimpleNamespace(wait_for_idle=lambda timeout: False,
                                            recover_when_idle=lambda action: None,
                                            record_terminal_failure=lambda reason: None)
    instance._collect_incident = lambda reason: None
    def publish(child, state, evidence, reason=None):
        states.append((state, clock.now))
        if state in ('healthy', 'failed'):
            clock.stopped = True
        return True
    instance._publish_health = publish
    instance._health_loop()
    assert requests == [2, 4]
    assert states == ([('degraded', 3), ('failed', 5)] if permanent else
                      [('degraded', 3), ('healthy', 4)])


def test_ipc_evidence_rejects_cached_response_as_timeout_recovery(monkeypatch):
    from pathlib import Path
    monkeypatch.syspath_prepend(str(Path(__file__).parent / 'acceptance'))
    from ipc_evidence import check_ipc_case
    rows = [
        {'event': 'failure', 'monotonic': 3, 'frame': {'run_id': 'run', 'seq': 2, 'kind': 'health'}},
        {'event': 'health_state', 'monotonic': 3.01, 'frame': {'run_id': 'run', 'state': 'degraded'}},
        {'event': 'response', 'monotonic': 4, 'frame': {'run_id': 'run', 'seq': 1,
            'result': {'init_evidence': True, 'probe': True}}},
        {'event': 'health_state', 'monotonic': 4.01, 'frame': {'run_id': 'run', 'state': 'healthy'}},
    ]
    assert check_ipc_case('ipc_once_timeout', 'run', rows)
    rows[2]['frame']['seq'] = 3
    assert check_ipc_case('ipc_once_timeout', 'run', rows) == []
    rows[2]['frame']['run_id'] = 'previous-run'
    assert check_ipc_case('ipc_once_timeout', 'run', rows)


def test_eof_is_terminal_for_subsequent_requests_not_a_new_timeout(tmp_path, monkeypatch):
    with transport(tmp_path, monkeypatch, 'ipc_eof') as managed:
        with pytest.raises(EOFError):
            managed.request('health', timeout=1)
        with pytest.raises(EOFError, match='managed IPC EOF'):
            managed.request('stacks', timeout=0.01)


@pytest.mark.parametrize('fault', ['ipc_wrong_run', 'ipc_repeat', 'ipc_reverse'])
def test_mismatched_channel_cannot_send_later_lifecycle_requests(tmp_path, monkeypatch, fault):
    with transport(tmp_path, monkeypatch, fault) as managed:
        with pytest.raises(RuntimeError, match='run/sequence mismatch'):
            managed.request('health', timeout=1)
        original = managed._send
        def forbidden_write(data):
            raise AssertionError('terminally mismatched channel was reused')
        monkeypatch.setattr(managed, '_send', SimpleNamespace(
            write=forbidden_write, close=original.close))
        for kind in ('stacks', 'stop', 'health'):
            with pytest.raises(RuntimeError, match='run/sequence mismatch'):
                managed.request(kind, timeout=0.1)
