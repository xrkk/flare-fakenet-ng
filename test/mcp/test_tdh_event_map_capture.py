"""Opaque TDH map export tests; these bytes are not an enum interpretation."""
import base64
import ctypes as C
import hashlib
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent / 'acceptance'))
import tdh_metadata as tdh  # noqa: E402


class MapApi:
    def __init__(self, blob, second_status=0):
        self.blob = blob
        self.second_status = second_status
        self.calls = []

    def TdhGetEventMapInformation(self, ptr, name, buffer, size_ptr):
        self.calls.append((ptr, name, buffer is None))
        C.cast(size_ptr, C.POINTER(C.c_uint32)).contents.value = len(self.blob)
        if buffer is None:
            return tdh.ERROR_INSUFFICIENT_BUFFER
        if self.second_status:
            return self.second_status
        C.memmove(buffer, self.blob, len(self.blob))
        return 0


def test_reason_map_bytes_and_api_status_are_preserved_without_enum_guess():
    blob = b'opaque-event-map!'  # minimum size, content deliberately not parsed
    api = MapApi(blob)
    result = tdh.capture_event_map(None, api, 'TCP_RST_SEND_REASON_ValueMap')
    assert [call[1:] for call in api.calls] == [
        ('TCP_RST_SEND_REASON_ValueMap', True),
        ('TCP_RST_SEND_REASON_ValueMap', False)]
    assert result == {'name': 'TCP_RST_SEND_REASON_ValueMap', 'api_available': True,
                      'first_status': 122, 'required_size': len(blob),
                      'second_status': 0,
                      'buffer_sha256': hashlib.sha256(blob).hexdigest(),
                      'buffer_base64': base64.b64encode(blob).decode()}


def test_missing_or_failed_map_is_explicit_and_has_no_raw_buffer():
    unavailable = tdh.capture_event_map(None, object(), 'ReasonMap')
    assert unavailable['api_available'] is False
    assert unavailable['buffer_base64'] is None
    failed = tdh.capture_event_map(None, MapApi(b'opaque-event-map!', 1168), 'ReasonMap')
    assert failed['second_status'] == 1168
    assert failed['buffer_base64'] is None
