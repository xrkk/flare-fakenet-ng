"""Cross-process single-flight and persisted intent recovery."""
import json
import multiprocessing
from pathlib import Path

import pytest

from fakenet.mcp.host_state import HostStateError, HostStateStore


def _hold(root, ready, release):
    store = HostStateStore(root)
    with store.lock_target('target-1'):
        ready.set()
        release.wait(10)


def test_target_lock_is_cross_process(tmp_path):
    ready = multiprocessing.Event()
    release = multiprocessing.Event()
    process = multiprocessing.Process(
        target=_hold, args=(str(tmp_path), ready, release))
    process.start()
    try:
        assert ready.wait(5)
        store = HostStateStore(str(tmp_path))
        with pytest.raises(HostStateError) as excinfo:
            with store.lock_target('target-1'):
                pass
        assert str(excinfo.value) == 'target_busy'
    finally:
        release.set()
        process.join(10)
        if process.is_alive():
            process.terminate()
            process.join(5)


def test_active_target_intent_is_reported_after_restart(tmp_path):
    store = HostStateStore(str(tmp_path))
    command_id = '00000000-0000-4000-8000-000000000001'
    store.create(command_id, {
        'command_id': command_id, 'target_key': 'target-1',
        'stage': 'running', 'verification_id': 'v'})
    active = store.find_active_target('target-1')
    assert active is not None
    assert active['command_id'] == command_id
    assert store.find_active_target('other') is None
