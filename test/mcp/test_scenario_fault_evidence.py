"""Byte-reference construction must not reread a capture per matching row."""
import importlib.util
from pathlib import Path
import sys

_SPEC = importlib.util.spec_from_file_location(
    'fault_adapter_reference_test', Path(__file__).parent / 'acceptance/scenario_fault_evidence.py')
adapter = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = adapter
_SPEC.loader.exec_module(adapter)


def test_packet_refs_read_capture_once_and_preserve_utf16_offsets(tmp_path, monkeypatch):
    path = tmp_path / 'pktmon.txt'
    header = '[01] capture record\r\n'
    packet = '192.0.2.1.1234 > 198.51.100.2.443: Flags [P.]\r\n'
    text = (header + packet) * 20
    raw = b'\xff\xfe' + text.encode('utf-16-le')
    path.write_bytes(raw)
    original = Path.read_bytes
    reads = []

    def counted(p):
        if p == path:
            reads.append(p)
        return original(p)

    monkeypatch.setattr(Path, 'read_bytes', counted)
    refs = adapter._packet_refs(path, tmp_path, '192.0.2.1:1234', '198.51.100.2:443')
    assert len(refs) == 20
    size = len((header + packet).encode('utf-16-le'))
    assert refs == [dict(path='pktmon.txt', byte_start=2 + i * size,
                         byte_end=2 + (i + 1) * size, event_key='text') for i in range(20)]
    assert all(raw[r['byte_start']:r['byte_end']].decode('utf-16-le') == header + packet for r in refs)
    assert len(reads) == 1


def test_full_file_reference_keeps_exact_size(tmp_path):
    path = tmp_path / 'raw.json'
    path.write_bytes(b'{"text":"\xe4\xb8\xad"}\n')
    assert adapter.ref(path, tmp_path)['byte_end'] == len(path.read_bytes())
