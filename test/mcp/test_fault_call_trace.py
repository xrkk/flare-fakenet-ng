"""Supplemental fault trace preserves calls and never replaces formal clocks."""
import json
import pytest
from fakenet.mcp import faulttrace as trace

@pytest.fixture(autouse=True)
def reset(monkeypatch):
    trace.finish()
    monkeypatch.setenv('FAKENETNG_MCP_FAULT_INJECTION', '1')
    monkeypatch.setattr(trace, 'native_clock_sample', lambda: {'supported': True, 'qpc_before': 1, 'qpc_after': 2})
    yield
    trace.finish()

def test_disabled_has_no_clock_or_trace(monkeypatch):
    monkeypatch.delenv('FAKENETNG_MCP_FAULT_INJECTION')
    monkeypatch.setattr(trace, 'native_clock_sample', lambda: pytest.fail('disabled sampled'))
    trace.begin('run', 'nonce')
    assert trace.call('recv', lambda: b'secret') == b'secret'
    assert trace.finish() is None

def test_calls_unique_identity_no_payload_and_original_error():
    trace.begin('run', 'nonce')
    assert trace.call('recv', lambda: b'secret') == b'secret'
    exc = OSError(123, 'original')
    def fail(): raise exc
    with pytest.raises(OSError) as caught: trace.call('close', fail)
    assert caught.value is exc
    value = trace.finish()
    assert [e['call_id'] for e in value['events']] == [1, 1, 2, 2]
    assert [e['phase'] for e in value['events']] == ['enter', 'return', 'enter', 'raise']
    assert value['events'][1]['result_count'] == 6
    assert 'secret' not in json.dumps(value)
    assert value['events'][3]['errno'] == 123

def test_midcall_enable_records_unknown_entry_not_invented_boundary():
    def operation():
        trace.begin('run', 'nonce')
        return 3
    assert trace.call('send', operation) == 3
    event, = trace.finish()['events']
    assert event['phase'] == 'return'
    assert event['entry_observed'] is False and event['call_id'] is None

def test_finish_during_call_leaves_enter_only():
    trace.begin('run', 'nonce')
    value = trace.call('recv', trace.finish)
    assert [e['phase'] for e in value['events']] == ['enter']

def test_capacity_and_sampler_failure_do_not_change_io(monkeypatch):
    monkeypatch.setattr(trace, '_LIMIT', 2)
    trace.begin('run', 'nonce')
    for _ in range(3): assert trace.call('send', lambda: 4) == 4
    value = trace.finish()
    assert len(value['events']) == 2 and value['dropped'] == 4
    trace.begin('run', 'nonce')
    def broken(): raise RuntimeError('sample')
    monkeypatch.setattr(trace, 'native_clock_sample', broken)
    assert trace.call('close', lambda: 7) == 7
    assert trace.finish()['events'] == []


def test_inflight_socket_identity_is_labeled_return_time():
    class Socket:
        def fileno(self): return 23
        def getsockname(self): return ('127.0.0.1', 1234)
        def getpeername(self): return ('127.0.0.1', 4321)
        def recv(self, count):
            trace.begin('run', 'nonce')
            return b'payload'
    assert trace.socket_call(Socket(), 'recv', 99, role='client') == b'payload'
    event, = trace.finish()['events']
    assert event['entry_observed'] is False
    assert event['identity_observed'] == 'return'
    assert event['fd'] == 23 and event['peer'] == ('127.0.0.1', 4321)
    assert event['role'] == 'client' and event['result_count'] == 7
