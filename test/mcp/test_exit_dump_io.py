import pytest
from fakenet.mcp.exit_dump_io import DumpIO


def test_quota_checked_before_write_and_seek(tmp_path):
    path = tmp_path / 'partial.dmp'
    with path.open('xb', buffering=0) as stream:
        writer = DumpIO(stream, 8, 20, clock=lambda: 10)
        writer.write(0, b'1234')
        with pytest.raises(RuntimeError, match='quota'):
            writer.write(7, b'xx')
        assert stream.tell() == 4
        assert path.stat().st_size == 4
        writer.write(6, b'78')
        writer.write(0, b'ab')
        assert writer.high_water == 8
    assert path.read_bytes() == b'ab34' + bytes(2) + b'78'


def test_expired_io_cannot_extend_file(tmp_path):
    path = tmp_path / 'partial.dmp'
    with path.open('xb', buffering=0) as stream:
        writer = DumpIO(stream, 8, 20, clock=lambda: 20)
        with pytest.raises(TimeoutError):
            writer.write(0, b'1234')
    assert path.stat().st_size == 0
