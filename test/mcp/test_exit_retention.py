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
