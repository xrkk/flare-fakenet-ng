# Copyright 2026 Google LLC
"""Single-instance guard semantics (P01 IMP-P01-03)."""

import os

import pytest

from fakenet.mcp import singleinstance


@pytest.mark.skipif(os.name == 'nt', reason='posix flock path tested here')
def test_second_acquire_fails(tmp_path):
    first = singleinstance.acquire(tmp_path)
    try:
        with pytest.raises(singleinstance.SingleInstanceError):
            singleinstance.acquire(tmp_path)
    finally:
        del first


@pytest.mark.skipif(os.name == 'nt', reason='posix flock path tested here')
def test_acquire_or_exit_exits_with_3(tmp_path, capsys):
    guard = singleinstance.acquire(tmp_path)
    try:
        with pytest.raises(SystemExit) as excinfo:
            singleinstance.acquire_or_exit(tmp_path)
        assert excinfo.value.code == 3
        assert 'another fakenetng-mcp' in capsys.readouterr().err
    finally:
        del guard


@pytest.mark.skipif(os.name == 'nt', reason='posix flock path tested here')
def test_shared_operator_mutex_conflict_reports_gui(tmp_path):
    """CHK-002: a held sole-operator lock (the GUI side) refuses MCP start."""
    import fcntl

    holder = open(tmp_path / 'sole-operator.lock', 'a+')
    fcntl.flock(holder.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        with pytest.raises(singleinstance.SingleInstanceError) as excinfo:
            singleinstance.acquire(tmp_path)
        assert 'GUI' in str(excinfo.value)
        assert 'mutually exclusive' in str(excinfo.value)
    finally:
        fcntl.flock(holder.fileno(), fcntl.LOCK_UN)
        holder.close()


@pytest.mark.skipif(os.name == 'nt', reason='posix flock path tested here')
def test_guard_holds_both_locks(tmp_path):
    guard = singleinstance.acquire(tmp_path)
    assert len(guard.handles) == 2
    del guard
