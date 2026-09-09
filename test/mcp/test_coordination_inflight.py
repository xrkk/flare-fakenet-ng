"""CHK-056: accepted commands remain individually tracked until completion."""
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from fakenet.mcp import errors
from fakenet.mcp.coordination import Coordinator
from fakenet.mcp.testdouble import LifecycleDouble


def submit(c, cid, action, names=None, kind='edit', owner='A', version=None):
    return c.submit(command_id=cid, expected_version=(
        c.snapshot()['state_version'] if version is None else version),
        controller=owner, controller_valid=True, kind=kind, describe={},
        execute=action, conflict_names=names)


def test_other_config_completion_does_not_release_first_operation():
    c = Coordinator(LifecycleDouble())
    entered, release = threading.Event(), threading.Event()

    def slow(_):
        entered.set()
        assert release.wait(3)
        return {'changed': True}

    with ThreadPoolExecutor() as pool:
        first = pool.submit(submit, c, 'first', slow, ['a.ini'])
        try:
            assert entered.wait(3)
            submit(c, 'second', lambda _: {}, ['b.ini'])
            with pytest.raises(errors.McpError) as exc:
                submit(c, 'start', lambda _: {}, kind='start')
            assert exc.value.code == errors.OPERATION_BUSY
        finally:
            release.set()
        first.result(3)


def test_running_different_configs_are_serial():
    c = Coordinator(LifecycleDouble())
    submit(c, 'start', lambda _: {'state': 'healthy', 'run_id': 'run',
                                'controller': 'A'}, kind='start')
    entered, release = threading.Event(), threading.Event()
    def slow(_):
        entered.set()
        assert release.wait(3)
        return {}
    with ThreadPoolExecutor() as pool:
        first = pool.submit(submit, c, 'a', slow, ['a.ini'])
        try:
            assert entered.wait(3)
            with pytest.raises(errors.McpError) as exc:
                submit(c, 'b', lambda _: {}, ['b.ini'])
            assert exc.value.code == errors.OPERATION_BUSY
        finally:
            release.set()
        first.result(3)


def test_acceptance_changes_version_and_duplicate_returns_inflight():
    c = Coordinator(LifecycleDouble())
    entered, release = threading.Event(), threading.Event()
    calls = []
    def slow(_):
        calls.append(1)
        entered.set()
        assert release.wait(3)
        return {}
    with ThreadPoolExecutor() as pool:
        first = pool.submit(submit, c, 'same', slow, ['a.ini'], version=1)
        try:
            assert entered.wait(3)
            assert c.snapshot()['state_version'] == 2
            replay = submit(c, 'same', slow, ['a.ini'], version=1)
            assert replay['command_id'] == 'same'
            assert replay['replayed'] is True
            assert replay['in_progress'] is True
            assert calls == [1]
        finally:
            release.set()
        result = first.result(3)
    assert result['state_version'] == 2
    assert not result.get('in_progress')


def test_failed_execution_is_not_reexecuted_on_retry():
    c = Coordinator(LifecycleDouble())
    calls = []
    def broken(_):
        calls.append(1)
        raise errors.McpError(errors.VALIDATION_FAILED, 'invalid')
    for _ in range(2):
        with pytest.raises(errors.McpError):
            submit(c, 'same', broken, ['a.ini'], version=1)
    assert calls == [1]
    assert c.snapshot()['state_version'] == 2
