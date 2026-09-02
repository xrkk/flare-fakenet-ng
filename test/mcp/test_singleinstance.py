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
