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


def test_owner_dump_public_collector_targets_live_process_only(monkeypatch):
    from fakenet.mcp import exit_guard
    flight_state = {"held": False}
    class Flight:
        def acquire(self):
            flight_state["held"] = True
            return True
        def close(self): flight_state["held"] = False
    monkeypatch.setattr(exit_guard, "SingleFlight", Flight)
    import threading
    owner = ExitRetention.__new__(ExitRetention)
    owner._helper = None
    owner.owner_dump = None
    owner._call_lock = threading.RLock()
    class Target:
        def exited(self):
            return False
        def identity(self):
            return {"pid": 4242, "creation_time": "123"}
    owner._target = Target()
    owner.deadline = time.monotonic() + 40  # remaining collection window
    owner.record = {'run_id': 'run', 'pid': 4242, 'creation_time': '123'}
    class Dir:
        def __truediv__(self, name):
            class P:
                exists = staticmethod(lambda: False)
                def read_bytes(self):
                    return b'x' * 10
            return P()
    owner.directory = Dir()
    def verify(*a, **k):
        assert not flight_state['held'], 'verification child must acquire its own flight'
        return {'size': 10, 'sha256': 'a' * 64}
    owner._call = verify
    owner._publish = lambda name, record: None
    def fake_collect(pid, creation, target, deadline, quota=None):
        assert flight_state['held'], 'dump writer requires exclusive flight'
        assert time.monotonic() < deadline <= owner.deadline
    import unittest.mock as mock
    with mock.patch('fakenet.mcp.dumpworker.collect_dump', fake_collect):
        info = owner.collect_owner_dump(budget=45)
    assert info == {'name': 'target.dmp', 'size': 10, 'sha256': 'a' * 64}
    assert owner.owner_dump == info
    # a dead or helper-served target collects nothing
    owner._target.exited = lambda: True
    assert owner.collect_owner_dump() is None


def test_helper_admission_winerror_records_exact_native_stage(monkeypatch, tmp_path):
    """P05 must identify a late/open/admission failure without certifying it.

    The exported P05 result has a real WinError 87 and no owner ACK.  A future
    run must distinguish ``OpenProcess`` from the two native admission calls;
    the failure remains incomplete until the helper result is independently
    verified.
    """
    from types import SimpleNamespace
    from fakenet.mcp import exit_retention, jobobject

    owner = ExitRetention.__new__(ExitRetention)
    owner.record = {'run_id': 'current'}
    owner.done = threading.Event()
    owner.deadline = None
    owner._target = SimpleNamespace(exited=lambda: True)
    owner._cancel = threading.Event()
    owner._helper = None
    owner._helper_job = None
    owner.intent = SimpleNamespace(invalidate=lambda: None)
    owner.helper_image = tmp_path / 'exit-helper' / 'fakenetng-mcp-exit-monitor.exe'
    owner.directory = tmp_path
    helper = {'pid': 84, 'creation_time': '456'}
    entry = {'target': owner.record, 'helper': helper, 'acquired': True}
    owner._read_optional = lambda name: entry if name == 'entry.json' else None
    owner._end_helpers = lambda _deadline: None
    owner._finish = lambda report: setattr(owner, 'result', report)

    class Handle:
        def __init__(self, pid, **_kwargs):
            assert pid == helper['pid']
            self.handle = 0x1234

        def identity(self):
            return dict(helper, image=str(owner.helper_image))

        def terminate_helper(self):
            return None

        def exited(self):
            return True

    class Job:
        def adopt_notification(self, handle, observe=None):
            assert handle == 0x1234 and observe is not None
            observe('AssignProcessToJobObject')
            raise OSError(22, 'The parameter is incorrect.', None, 87)

    monkeypatch.setattr(exit_retention, 'TargetHandle', Handle)
    monkeypatch.setattr(jobobject, 'ManagedJob', Job)
    owner._watch()

    assert owner.done.is_set()
    assert owner.result['complete'] is False
    assert owner.result['failure_stage'] == 'open exit helper'
    assert owner.result['native_api'] == 'AssignProcessToJobObject'
    assert '87' in owner.result['error']
    observation = owner.result['owner_observation']
    assert observation['entry_read_attempts'] == 1
    assert observation['entry_read_diagnostic_errors'] == 0
    assert observation['helper_creation_time'] == helper['creation_time']
    assert observation['entry_observed_monotonic'] > 0
    assert 'ack_attempted_monotonic' not in observation


def test_missing_helper_result_keeps_failure_observations_when_cleanup_fails():
    """A cleanup retry must preserve the original failed stage and ACK timing."""
    from types import SimpleNamespace
    owner = ExitRetention.__new__(ExitRetention)
    owner.record = {'run_id': 'current'}
    owner.done = threading.Event()
    owner.deadline = time.monotonic() + 60
    owner._target = SimpleNamespace(exited=lambda: True)
    owner._cancel = threading.Event()
    owner._helper = SimpleNamespace(exited=lambda: True)
    owner.intent = SimpleNamespace(invalidate=lambda: None)
    owner._ack_published_monotonic = 123.5
    owner._read_optional = lambda name: None
    def cleanup(_deadline):
        raise RuntimeError('managed target still active')
    owner._end_helpers = cleanup
    owner._watch()
    assert owner.done.is_set()
    assert owner.result['complete'] is False
    assert 'helper ended without final result' in owner.result['error']
    assert owner.result['failure_stage'] == 'read exit helper result'
    assert owner.result['owner_observation']['ack_published_monotonic'] == 123.5
    assert 'managed target still active' in owner.result['cleanup_error']
    assert owner.result['retained_target_handle_closed'] is False


def test_owner_dump_yields_to_existing_exit_helper_without_taking_protocol_lock(monkeypatch, tmp_path):
    from types import SimpleNamespace
    from fakenet.mcp import exit_guard, dumpworker
    owner = ExitRetention.__new__(ExitRetention)
    owner._target = SimpleNamespace(exited=lambda: False)
    owner._helper = None
    owner.record = {'run_id': 'current'}
    owner.owner_dump = None
    owner.directory = tmp_path
    owner.deadline = None
    owner._read_optional = lambda name: {'target': owner.record, 'acquired': True}
    class Flight:
        def acquire(self): return False
        def close(self): pass
    class ProtocolLock:
        def acquire(self): pytest.fail('must not block helper ACK behind owner dump')
    owner._call_lock = ProtocolLock()
    monkeypatch.setattr(exit_guard, 'SingleFlight', Flight)
    monkeypatch.setattr(dumpworker, 'collect_dump', lambda *a, **k: pytest.fail('helper already owns dump flight'))
    assert owner.collect_owner_dump() is None


def test_owner_dump_existing_artifact_never_acquires_protocol_lock(tmp_path):
    from types import SimpleNamespace
    owner = ExitRetention.__new__(ExitRetention)
    owner._target = SimpleNamespace(exited=lambda: False)
    owner._helper = None
    owner.owner_dump = None
    owner.directory = tmp_path
    (tmp_path / 'target.dmp').write_bytes(b'existing evidence')
    assert owner.collect_owner_dump() is None
    assert (tmp_path / 'target.dmp').read_bytes() == b'existing evidence'


def test_forced_owner_dump_busy_flight_keeps_deadline_and_does_not_write(monkeypatch, tmp_path):
    from types import SimpleNamespace
    from fakenet.mcp import exit_guard, dumpworker
    owner = ExitRetention.__new__(ExitRetention)
    owner._target = SimpleNamespace(exited=lambda: False)
    owner._helper = object()
    owner.owner_dump = None
    owner.directory = tmp_path
    owner.deadline = None
    class Flight:
        def acquire(self): return False
    monkeypatch.setattr(exit_guard, 'SingleFlight', Flight)
    monkeypatch.setattr(dumpworker, 'collect_dump', lambda *a, **k: pytest.fail('concurrent dump'))
    with pytest.raises(TimeoutError, match='collection window expired'):
        owner.collect_owner_dump(budget=0, force=True)
    assert not list(tmp_path.iterdir())


def test_failed_helper_scan_remains_required_on_same_owner_reentry(monkeypatch, tmp_path):
    closed = []
    owner = _owner_with_handles(closed)
    owner.directory = tmp_path
    owner.intent = type('Intent', (), {'invalidate': lambda self: None})()
    scans = []
    def reject(*a, **k):
        scans.append('scan')
        raise RuntimeError('helper scan unconfirmed')
    monkeypatch.setattr('fakenet.mcp.exit_installation.assert_no_helpers', reject)
    for _ in range(2):
        with pytest.raises(RuntimeError, match='scan unconfirmed'):
            owner._finish({'complete': False})
    assert scans == ['scan', 'scan'] and closed == ['helper']
    assert owner._target is not None
