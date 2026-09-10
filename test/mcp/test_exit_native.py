"""Reject truncated and wrong-target output even if a tool reported success."""
import struct
import pytest
from fakenet.mcp.exit_native import verify_dump


def dump_bytes(pid):
    # Minimal directory + actual MINIDUMP_MISC_INFO identity fields.
    data = bytearray(56)
    struct.pack_into('<IIII', data, 0, 0x504d444d, 0xa793, 1, 32)
    struct.pack_into('<III', data, 32, 15, 12, 44)
    struct.pack_into('<III', data, 44, 12, 1, pid)
    return data


def test_partial_dump_is_not_publishable(tmp_path):
    path = tmp_path / 'partial.dmp'; path.write_bytes(dump_bytes(42)[:-1])
    with pytest.raises(RuntimeError, match='exceeds'):
        verify_dump(path, 42)


def test_dump_of_other_pid_is_rejected(tmp_path):
    path = tmp_path / 'foreign.dmp'; path.write_bytes(dump_bytes(43))
    with pytest.raises(RuntimeError, match='identity mismatch'):
        verify_dump(path, 42)


def test_identity_stream_must_actually_contain_pid(tmp_path):
    data = dump_bytes(42); struct.pack_into('<I', data, 48, 0)
    path = tmp_path / 'no-pid.dmp'; path.write_bytes(data)
    with pytest.raises(RuntimeError, match='identity mismatch'):
        verify_dump(path, 42)
