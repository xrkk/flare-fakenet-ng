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
