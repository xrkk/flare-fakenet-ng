# Copyright 2026 Google LLC
import threading
import time
import os

import pytest

from fakenet.mcp.coordination import Coordinator
from fakenet.mcp.service_stop import ServiceStop, read_result, replace_result
from fakenet.mcp.testdouble import LifecycleDouble


@pytest.mark.skipif(os.name != 'nt', reason='Windows delete sharing')
def test_result_reader_allows_atomic_replacement_while_handle_open(tmp_path, monkeypatch):
    import win32file
    path = tmp_path / 'result.json'
    replacement = tmp_path / 'next.json'
    path.write_text('{"phase":"draining"}', encoding='utf-8')
    replacement.write_text('{"phase":"failed"}', encoding='utf-8')
    original = win32file.ReadFile
    observed = []
    def read_while_replacing(handle, size):
        try:
            replace_result(replacement, path)
        except OSError as exc:
            observed.append(repr(exc))
            raise
        observed.append(True)
        return original(handle, size)
    with monkeypatch.context() as patch:
        patch.setattr(win32file, 'ReadFile', read_while_replacing)
        assert read_result(path) == {'phase': 'draining'}, observed
    assert observed == [True]
    assert read_result(path) == {'phase': 'failed'}
    assert read_result(tmp_path / 'missing.json') is None


def wait_done(stop):
    stop._worker.join(2)
    assert not stop._worker.is_alive()
    return read_result(stop.path)


def test_failure_stays_online_and_retry_publishes_scm_before_success(tmp_path):
    coord = Coordinator(LifecycleDouble())
    observations = []
    def ready():
        observations.append(read_result(stop.path)['phase'])
    stop = ServiceStop(coord, lambda deadline: {'state': 'failed'}, ready,
                       tmp_path / 'stop.json', identity={'pid': 1, 'creation_time': 'x'})
    stop.request()
    assert wait_done(stop)['phase'] == 'failed'
    assert not stop.ready and coord.draining
    assert coord.snapshot()['state'] == 'failed'
    assert observations == []
    def converged(deadline):
        return coord.submit(command_id='cleanup',
                            expected_version=coord.snapshot()['state_version'],
                            controller=None, controller_valid=True,
                            kind='service_stop', describe={}, internal=True,
                            execute=lambda c: {'state': 'stopped',
                                               'release_controller': True})
    stop.converge = converged
    stop.request()
    assert wait_done(stop)['phase'] == 'succeeded'
    assert observations == ['draining']
    assert coord.draining


def test_inflight_timeout_cannot_be_undone_by_late_start(tmp_path):
    coord = Coordinator(LifecycleDouble())
    entered, release = threading.Event(), threading.Event()
    def execute(c):
        entered.set()
        release.wait(2)
        return {'state': 'healthy', 'run_id': 'late-run', 'controller': 'owner'}
    thread = threading.Thread(target=lambda: coord.submit(
        command_id='start', expected_version=1, controller='owner',
        controller_valid=True, kind='start', describe={}, execute=execute))
    thread.start()
    assert entered.wait(1)
    calls = []
    stop = ServiceStop(coord, lambda d: calls.append(d), lambda: None,
                       tmp_path / 'stop.json', identity={'pid': 1},
                       inflight_limit=0.01)
    try:
        stop.request()
        result = wait_done(stop)
        assert result['reason'] == 'inflight_timeout'
        assert stop.request()['attempt'] == 1
        release.set()
        thread.join(2)
        current = coord.snapshot()
        assert current['state'] == 'failed'
        assert current['run_id'] == 'late-run'
        assert current['controller'] == 'owner'
        coord.update_health_state('healthy')
        assert coord.snapshot()['state'] == 'failed'
        assert not calls
    finally:
        release.set()
        thread.join(2)


def test_repeated_prestop_shares_active_attempt(tmp_path):
    coord = Coordinator(LifecycleDouble())
    entered, release = threading.Event(), threading.Event()
    def converge(deadline):
        entered.set()
        release.wait(1)
        return {'state': 'failed', 'failure_reason': 'injected'}
    stop = ServiceStop(coord, converge, lambda: None, tmp_path / 'stop.json',
                       identity={'pid': 1})
    stop.request()
    assert entered.wait(1)
    assert stop.request()['attempt'] == 1
    release.set()
    assert wait_done(stop)['attempt'] == 1


def test_total_deadline_reports_failure_while_worker_remains_fenced(tmp_path):
    coord = Coordinator(LifecycleDouble())
    entered, release = threading.Event(), threading.Event()
    published = []
    def converge(deadline):
        def execute(c):
            entered.set()
            release.wait(2)
            return {'state': 'stopped', 'release_controller': True}
        return coord.submit(command_id='converge', expected_version=1,
                            controller=None, controller_valid=True,
                            kind='service_stop', describe={}, internal=True,
                            execute=execute)
    stop = ServiceStop(coord, converge, lambda: published.append(True),
                       tmp_path / 'stop.json', identity={'pid': 1})
    stop.budget = 0.05
    stop.request()
    assert entered.wait(1)
    try:
        limit = time.monotonic() + 1
        while read_result(stop.path)['phase'] != 'failed' and time.monotonic() < limit:
            time.sleep(0.01)
        assert read_result(stop.path)['phase'] == 'failed'
        assert stop._worker.is_alive()
        assert stop.request()['attempt'] == 1
    finally:
        release.set()
    assert wait_done(stop)['phase'] == 'failed'
    assert coord.snapshot()['state'] == 'failed'
    assert not stop.ready and published == []
