"""Deadline revokes success while retaining a delayed native owner."""
import threading
import time

import pytest

from fakenet.mcp.diagnostic_process import DiagnosticOwner, DiagnosticCall, DiagnosticError


def test_timed_out_owner_cannot_accept_a_late_success_or_second_task(monkeypatch, tmp_path):
    release = threading.Event()
    entered = threading.Event()
    def blocked_native_call(self):
        entered.set()
        release.wait(2)
        self.result = {'late': True}
        self.done.set()
        self.ended.set()
    monkeypatch.setattr(DiagnosticCall, '_run', blocked_native_call)
    owner = DiagnosticOwner(tmp_path)
    try:
        with pytest.raises(DiagnosticError, match='deadline'):
            owner.call('exit-scan', {}, time.monotonic() + .05)
        assert entered.is_set() and owner.pending()
        assert owner.last['platform_blocked'] is False
        original = owner.active
        with pytest.raises(DiagnosticError, match='ownership'):
            owner.call('exit-scan', {}, time.monotonic() + 1)
        assert owner.active is original
        release.set()
        original.worker.join(1)
        assert not owner.pending()
        assert owner.last['error'] == 'deadline exceeded; end unconfirmed'
    finally:
        release.set()


def test_exit_of_leader_is_not_exit_of_the_whole_job(tmp_path):
    call = DiagnosticCall(tmp_path, 'exit-scan', {}, time.monotonic() + 1)
    class Job:
        process = 42
        closed = False
        remaining = [99]
        def poll(self): return 0
        def members(self): return self.remaining
        def close(self): self.closed = True
    call.job = Job()
    call.retained_streams = []
    call.retained_descriptors = []
    call.retained_inherited = []
    call.pipe_workers = []
    call._release_if_ended()
    assert not call.ended.is_set() and not call.job.closed
    call.job.remaining = []
    call._release_if_ended()
    assert call.ended.is_set() and call.job.closed


def test_task_vocabulary_cannot_address_arbitrary_files(monkeypatch, tmp_path):
    from fakenet.mcp import diagnostic_tasks, exit_files
    monkeypatch.setattr(exit_files, 'root', lambda: tmp_path)
    with pytest.raises(ValueError, match='unknown exit'):
        diagnostic_tasks.execute('exit-read', {'name': '../state/state.json'}, time.monotonic()+1)
    with pytest.raises(ValueError, match='unknown diagnostic operation'):
        diagnostic_tasks.execute('shell', {'command': 'whoami'}, time.monotonic()+1)


def test_revocation_does_not_wait_for_slow_intent_publication(tmp_path):
    from fakenet.mcp.exit_intent import StopIntent, IDENTITY_FIELDS
    entered, release, ended = threading.Event(), threading.Event(), threading.Event()
    failures = []
    identity = {key: 'identity' for key in IDENTITY_FIELDS}
    def io(operation, record, deadline):
        if operation == 'publish':
            entered.set()
            release.wait(2)
    intent = StopIntent(tmp_path, identity, io=io)
    def publish():
        try: intent.publish(time.monotonic() + 3)
        except RuntimeError as exc: failures.append(str(exc))
        finally: ended.set()
    worker = threading.Thread(target=publish)
    worker.start()
    try:
        assert entered.wait(1)
        intent.invalidate()
        assert intent.current is None and intent._publishing is None
        release.set()
        assert ended.wait(1)
        assert failures == ['stop intent publication revoked/expired']
        assert intent.current is None
    finally:
        release.set()
        worker.join(2)


@pytest.mark.skipif(__import__('os').name != 'nt', reason='native Windows diagnostic Job/pipe')
def test_windows_fixed_task_uses_job_and_returns_bounded_result():
    from pathlib import Path
    import uuid
    owner = DiagnosticOwner(Path(__file__).resolve().parents[2])
    result = owner.call('exit-read', dict(run_id=str(uuid.uuid4()), name='entry.json'),
                        time.monotonic() + 15)
    assert result is None
    assert owner.active.ended.is_set()
    assert owner.last['native'][0]['event'] == 'created'
    assert owner.last['platform_blocked'] is False


def test_native_import_failure_is_reported_without_waiting_for_deadline(monkeypatch, tmp_path):
    import builtins
    original = builtins.__import__
    def fail_native(name, *args, **kwargs):
        if name == 'msvcrt':
            raise ImportError('injected native import failure')
        return original(name, *args, **kwargs)
    monkeypatch.setattr(builtins, '__import__', fail_native)
    owner = DiagnosticOwner(tmp_path)
    started = time.monotonic()
    with pytest.raises(DiagnosticError, match='injected native import failure'):
        owner.call('exit-read', {}, started + 5)
    assert time.monotonic() - started < 1
    assert owner.active.ended.is_set()
    assert not owner.pending()


def test_short_protocol_watchdog_does_not_consume_collection_reserve(monkeypatch):
    from fakenet.mcp import diagnostic_tasks
    terminated = threading.Event()
    monkeypatch.setattr(diagnostic_tasks.os, '_exit', lambda code: terminated.set())
    watchdog = diagnostic_tasks.ItemWatchdog(time.monotonic() + 1)
    try:
        assert not terminated.wait(.05)
        watchdog.deadline = time.monotonic() - .01
        assert terminated.wait(.2)
    finally:
        watchdog.done.set()
        watchdog.thread.join(1)


class _FakeJob:
    def __init__(self, listed, alive=()):
        self.listed = list(listed)
        self.alive = set(alive)
        self.terminations = 0

    def poll(self):
        return 0

    def members(self):
        return list(self.listed)

    def member_alive(self, pid):
        return pid in self.alive

    def terminate(self, deadline):
        self.terminations += 1
        self.listed = []


def _call_with_job(job):
    from fakenet.mcp.diagnostic_process import DiagnosticCall
    call = DiagnosticCall.__new__(DiagnosticCall)
    call.job = job
    call.deadline = time.monotonic() + 5
    call.cancel = threading.Event()
    call._terminate = lambda deadline=None: job.terminate(deadline)
    return call


def test_listed_dead_member_after_leader_exit_is_not_a_descendant_error():
    """The kernel can keep a terminated PID in the Job list until its
    process object is destroyed; that transient listing must not fail a
    completed diagnostic call."""
    job = _FakeJob(listed=[4242])  # the leader itself, already exited
    call = _call_with_job(job)
    # The list drains on its own shortly after termination.
    def drain_after_first_look(pid):
        if job.listed == [4242]:
            job.listed = []
        return False
    job.member_alive = drain_after_first_look
    call._await_job_end()
    assert job.terminations == 0


def test_live_member_after_leader_exit_fails_after_bounded_terminate():
    job = _FakeJob(listed=[4242, 999], alive={999})
    call = _call_with_job(job)
    with pytest.raises(DiagnosticError, match='remaining descendants'):
        call._await_job_end()
    assert job.terminations == 1
    assert call.cancel.is_set()
