"""Observe real ManagedProcess termination control flow, without changing it."""
from types import SimpleNamespace
import pytest
from fakenet.mcp import managed, faultinject


def setup(monkeypatch, tmp_path, job):
    monkeypatch.setenv('FAKENETNG_MCP_FAULT_INJECTION', '1')
    rows = []
    monkeypatch.setattr(managed, 'record_ipc', lambda path, side, event, frame: rows.append((event, frame)))
    monkeypatch.setattr(faultinject, 'native_clock_observation', lambda: {'supported': True, 'filetime_100ns': 123})
    process = object.__new__(managed.ManagedProcess)
    process.job = job
    process.run_dir = tmp_path
    process.run_id = 'run-a'
    process.identity = {'pid': 42, 'creation_time': '1234'}
    return process, rows


def test_termination_evidence_follows_confirmed_empty_job(monkeypatch, tmp_path):
    calls = []
    members = iter([[43], []])
    job = SimpleNamespace(terminate=lambda deadline: calls.append('terminate'),
                          poll=lambda: 1, members=lambda: next(members))
    process, rows = setup(monkeypatch, tmp_path, job)
    monkeypatch.setattr(managed.time, 'sleep', lambda seconds: calls.append('wait'))
    process.terminate(float('inf'))
    assert calls == ['terminate', 'wait']
    assert [r[0] for r in rows] == ['job-terminate-begin', 'job-terminate-returned', 'job-empty-confirmed']
    assert all(r[1]['identity'] == process.identity and r[1]['run_id'] == 'run-a' for r in rows)
    assert all(r[1]['native_clock']['filetime_100ns'] == 123 for r in rows)


def test_termination_error_preserved_without_false_empty_evidence(monkeypatch, tmp_path):
    error = TimeoutError('actual job timeout')
    def fail(deadline): raise error
    process, rows = setup(monkeypatch, tmp_path, SimpleNamespace(terminate=fail))
    with pytest.raises(TimeoutError) as caught: process.terminate(10)
    assert caught.value is error
    assert [r[0] for r in rows] == ['job-terminate-begin', 'job-terminate-error']


def test_diagnostic_write_failure_does_not_block_termination(monkeypatch, tmp_path):
    calls = []
    job = SimpleNamespace(terminate=lambda deadline: calls.append(deadline), poll=lambda: 1, members=lambda: [])
    process, _ = setup(monkeypatch, tmp_path, job)
    def fail(*args): raise OSError('disk full')
    monkeypatch.setattr(managed, 'record_ipc', fail)
    process.terminate(10)
    assert calls == [10]


def test_live_job_after_native_return_never_records_empty(monkeypatch, tmp_path):
    job = SimpleNamespace(terminate=lambda deadline: None, poll=lambda: None)
    process, rows = setup(monkeypatch, tmp_path, job)
    with pytest.raises(TimeoutError, match='end unconfirmed'): process.terminate(0)
    assert [r[0] for r in rows] == ['job-terminate-begin', 'job-terminate-returned', 'job-terminate-error']


def test_disabled_evidence_does_not_sample_clock(monkeypatch, tmp_path):
    job = SimpleNamespace(terminate=lambda deadline: None, poll=lambda: 1, members=lambda: [])
    process, rows = setup(monkeypatch, tmp_path, job)
    monkeypatch.delenv('FAKENETNG_MCP_FAULT_INJECTION')
    def fail(): raise AssertionError('disabled clock sampled')
    monkeypatch.setattr(faultinject, 'native_clock_observation', fail)
    process.terminate(10)
    assert rows == []
