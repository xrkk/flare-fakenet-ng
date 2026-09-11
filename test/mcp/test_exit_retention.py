import threading
import time

import pytest

from fakenet.mcp.exit_retention import ExitRetention


def test_helper_wait_releases_all_recursive_lifecycle_lock_levels():
    owner = ExitRetention.__new__(ExitRetention)
    owner.done = threading.Event()
    owner.result = {'complete': True}
    lock = threading.RLock()
    condition = threading.Condition(lock)
    acquired = threading.Event()
    def finish():
        with lock:
            acquired.set()
            owner.done.set()
    with lock:
        with lock:
            worker = threading.Thread(target=finish)
            worker.start()
            assert owner.wait(condition, time.monotonic() + 2) == owner.result
            assert acquired.is_set()
    worker.join(timeout=1)
    assert not worker.is_alive()


def test_retained_target_cannot_close_on_helper_self_report_alone():
    owner = ExitRetention.__new__(ExitRetention)
    class Helper:
        def exited(self):
            return False
    owner._helper = Helper()
    with pytest.raises(RuntimeError, match='has not ended'):
        owner._finish({'complete': True, 'target_handle_closed': True})


def test_current_owner_rejects_result_from_other_run():
    owner = ExitRetention.__new__(ExitRetention)
    owner.record = {'run_id': 'current'}
    owner._helper_identity = {'pid': 40, 'creation_time': '1234'}
    with pytest.raises(RuntimeError, match='identity mismatch'):
        owner._check_result(dict(schema='fakenet.exit-result.v1',
                                target={'run_id': 'old'}, helper=owner._helper_identity))


class _Handle:
    def __init__(self, name, closed):
        self.name = name
        self._closed = closed

    def exited(self):
        return True

    def close(self):
        self._closed.append(self.name)


def _owner_with_handles(closed):
    owner = ExitRetention.__new__(ExitRetention)
    owner._helper = _Handle('helper', closed)
    owner._target = _Handle('target', closed)
    owner.package = '.'
    owner.record = {'run_id': 'current'}
    def diagnostic(operation, payload, deadline=None):
        if operation == 'exit-scan':
            from fakenet.mcp.exit_installation import assert_no_helpers
            return assert_no_helpers(owner.package)
        if operation == 'exit-publish':
            from fakenet.mcp.exit_files import publish
            return publish(owner.directory / payload['name'], payload['record'])
        raise AssertionError('unexpected diagnostic operation')
    owner._call = diagnostic
    owner.deadline = time.monotonic() + 30
    return owner


def test_retained_target_handle_survives_a_failed_residual_check(monkeypatch):
    """CHK-069: a failed residual check must not release the target handle."""
    closed = []
    owner = _owner_with_handles(closed)

    def refuse(*_args, **_kwargs):
        raise RuntimeError('exit helper still active: 1')

    monkeypatch.setattr('fakenet.mcp.exit_installation.assert_no_helpers', refuse)
    with pytest.raises(RuntimeError, match='still active'):
        owner._finish({'complete': True})
    assert closed == ['helper']
    assert owner._target is not None


def test_retained_target_handle_closes_after_a_passing_residual_check(monkeypatch, tmp_path):
    closed = []
    owner = _owner_with_handles(closed)
    owner.directory = tmp_path
    owner.intent = type('Intent', (), {'invalidate': lambda self: closed.append('intent')})()
    monkeypatch.setattr('fakenet.mcp.exit_installation.assert_no_helpers',
                        lambda *_args, **_kwargs: None)
    report = {'complete': True}
    owner._finish(report)
    assert closed == ['helper', 'intent', 'target']
    assert report['helper_ended'] is True
    assert report['retained_target_handle_closed'] is True


def test_helper_end_cannot_release_a_still_live_target():
    closed = []
    owner = _owner_with_handles(closed)
    owner._target.exited = lambda: False
    with pytest.raises(RuntimeError, match='managed target still active'):
        owner._finish({'complete': True})
    assert closed == ['helper']
    assert owner._target is not None


def test_settle_keeps_responsibility_while_target_object_is_live(tmp_path):
    """CHK-069: a returned watcher thread never drops the retained target."""
    closed = []
    owner = _owner_with_handles(closed)
    owner.directory = tmp_path
    owner.intent = type('Intent', (), {'invalidate': lambda self: closed.append('intent')})()
    owner.done = threading.Event()
    owner.result = {'complete': False, 'helper_ended': False,
                    'retained_target_handle_closed': False, 'cleanup_error': 'earlier failure'}
    owner._target.exited = lambda: False
    assert owner.settle(time.monotonic() + 0.2) is owner.result
    assert owner.settle(time.monotonic() + 0.2)['retained_target_handle_closed'] is False
    assert closed == []


def test_settle_finishes_release_once_objects_actually_end(monkeypatch, tmp_path):
    closed = []
    owner = _owner_with_handles(closed)
    owner.directory = tmp_path
    owner.intent = type('Intent', (), {'invalidate': lambda self: closed.append('intent')})()
    owner.done = threading.Event()
    owner.done.set()
    owner.result = {'complete': False, 'helper_ended': False,
                    'retained_target_handle_closed': False, 'cleanup_error': 'earlier failure'}
    monkeypatch.setattr('fakenet.mcp.exit_installation.assert_no_helpers',
                        lambda *_args, **_kwargs: None)
    report = owner.settle(time.monotonic() + 2)
    assert closed == ['helper', 'intent', 'target']
    assert report['helper_ended'] is True
    assert report['retained_target_handle_closed'] is True


def test_settle_waits_for_a_still_live_helper_before_finishing(monkeypatch, tmp_path):
    closed = []
    owner = _owner_with_handles(closed)
    owner.directory = tmp_path
    owner.intent = type('Intent', (), {'invalidate': lambda self: closed.append('intent')})()
    owner.done = threading.Event()
    owner.done.set()
    owner.result = {'complete': False, 'helper_ended': False,
                    'retained_target_handle_closed': False}
    owner._helper.exited = lambda: False
    monkeypatch.setattr('fakenet.mcp.exit_installation.assert_no_helpers',
                        lambda *_args, **_kwargs: None)
    report = owner.settle(time.monotonic() + 0.2)
    assert report['retained_target_handle_closed'] is False
    assert closed == []


def test_released_target_handle_reports_ended_not_invalid():
    """A partially failed finalization may leave a released handle; later
    ownership continuation (wait/settle/collect) must never fail on it."""
    from fakenet.mcp.exit_native import TargetHandle
    handle = TargetHandle.__new__(TargetHandle)
    handle.handle = None
    handle.pid = 4242
    assert handle.exited() is True
