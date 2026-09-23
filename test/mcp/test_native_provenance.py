"""ABI and fail-closed diagnostics; the real Win10 call is checked by Wine/VM."""
import ctypes
from types import SimpleNamespace
import uuid

import pytest

from fakenet.mcp import native_provenance as provenance


def test_boot_environment_win10_x64_layout_and_exact_result():
    provenance.validate_boot_layout()
    assert ctypes.sizeof(provenance.BootEnvironment) == 32
    guid = uuid.UUID('b2598c2b-7186-4ae2-8ad7-5f49855a026a')
    raw = guid.bytes_le + (2).to_bytes(4, 'little') + bytes(4) + (9).to_bytes(8, 'little')
    result = provenance.decode_boot_result(0, 32, raw)
    assert result['boot_identifier'] == str(guid)
    assert result['firmware_type'] == 2 and result['boot_flags'] == 9
    assert result['raw_hex'] == raw.hex() and result['return_length'] == 32
    for status, length, data in ((-1, 32, raw), (0, 24, raw),
                                 (0, 32, raw[:24]), (0, 40, raw + bytes(8)),
                                 (0, 32, bytes(16) + raw[16:])):
        with pytest.raises(ValueError):
            provenance.decode_boot_result(status, length, data)


def test_nonwindows_identity_is_explicitly_unsupported(monkeypatch):
    monkeypatch.setattr(provenance, 'os', SimpleNamespace(name='posix'))
    value = provenance.native_identity()
    assert value['supported'] is False
    assert value['boot_class'] == 90 and value['error'] == 'native Windows required'
