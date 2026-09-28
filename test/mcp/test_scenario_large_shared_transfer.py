"""The shared PktMon text is larger than ordinary guest evidence."""
import base64
import hashlib
from pathlib import Path
import re
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent / 'acceptance'))
import scenario_suite as suite


class FakeVm:
    def __init__(self, payload):
        self.payload = payload
        self.calls = []

    def powershell(self, command, timeout):
        offset = int(re.search(r'\$s.Seek\((\d+),', command).group(1))
        length = int(re.search(r'New-Object byte\[\] (\d+)', command).group(1))
        self.calls.append((offset, length))
        return {'output': base64.b64encode(self.payload[offset:offset + length]).decode()}


@pytest.fixture
def transfer(tmp_path, monkeypatch):
    monkeypatch.setattr(suite, 'MAX_GUEST_TRANSFER', 8)
    monkeypatch.setattr(suite, 'MAX_SHARED_PKTMON_TEXT_TRANSFER', 24)
    obj = object.__new__(suite.Suite)
    obj.vm = FakeVm(b'abcdefghijklmnop')
    obj.root = tmp_path
    obj.capture_contract = 'scenario-shared-v2'
    obj.guest_work_root = r'E:\work'
    return obj


def test_shared_text_can_exceed_ordinary_bound(transfer, tmp_path):
    source = r'E:\work\scenario-suite-20260912\case-a1\run-01\pktmon.txt'
    destination = tmp_path / 'run-01' / 'pktmon.txt'
    expected = hashlib.sha256(transfer.vm.payload).hexdigest()
    record = transfer._transfer_guest_file(source, 16, expected, destination)
    assert record == {'path': str(Path('run-01') / 'pktmon.txt'),
                      'size': 16, 'sha256': expected}
    assert destination.read_bytes() == transfer.vm.payload
    assert transfer.vm.calls == [(0, 16)]


def test_ordinary_small_evidence_keeps_existing_limit(transfer, tmp_path):
    transfer.vm.payload = b'normal'
    expected = hashlib.sha256(transfer.vm.payload).hexdigest()
    record = transfer._transfer_guest_file(r'E:\work\case\probe.jsonl', 6, expected,
                                           tmp_path / 'run-01' / 'probe.jsonl')
    assert record['size'] == 6 and record['sha256'] == expected


@pytest.mark.parametrize('source,destination', [
    (r'E:\work\scenario-suite-20260912\case-a1\run-02\pktmon.txt', 'pktmon.txt'),
    (r'E:\work\scenario-suite-20260912\case-a1\run-01\other.txt', 'pktmon.txt'),
    (r'E:\work\scenario-suite-20260912\case-a1\run-01\pktmon.txt', 'other.txt'),
    (r'E:\elsewhere\scenario-suite-20260912\case-a1\run-01\pktmon.txt', 'pktmon.txt'),
])
def test_exception_applies_only_to_first_shared_physical_text(transfer, tmp_path, source, destination):
    with pytest.raises(suite.SuiteError, match='outside transfer bound'):
        transfer._transfer_guest_file(source, 16, '0' * 64, tmp_path / destination)


def test_above_shared_bound_and_digest_mismatch_rejected(transfer, tmp_path):
    source = r'E:\work\scenario-suite-20260912\case-a1\run-01\pktmon.txt'
    with pytest.raises(suite.SuiteError, match='outside transfer bound'):
        transfer._transfer_guest_file(source, 25, '0' * 64, tmp_path / 'large' / 'run-01' / 'pktmon.txt')
    with pytest.raises(suite.SuiteError, match='SHA-256 mismatch'):
        transfer._transfer_guest_file(source, 16, '0' * 64, tmp_path / 'mismatch' / 'run-01' / 'pktmon.txt')
    assert not (tmp_path / 'mismatch' / 'run-01' / 'pktmon.txt').exists()


def test_outside_destination_and_traversal_rejected(transfer, tmp_path):
    source = r'E:\work\scenario-suite-20260912\case-a1\run-01\pktmon.txt'
    with pytest.raises(suite.SuiteError, match='outside transfer scope'):
        transfer._transfer_guest_file(source, 16, '0' * 64, tmp_path.parent / 'pktmon.txt')
    with pytest.raises(suite.SuiteError, match='outside transfer scope'):
        transfer._transfer_guest_file(r'E:\work\..\elsewhere\pktmon.txt', 16, '0' * 64,
                                      tmp_path / 'pktmon.txt')


def test_middle_block_failure_cannot_return_complete_record(transfer, tmp_path, monkeypatch):
    source = r'E:\work\scenario-suite-20260912\case-a1\run-01\pktmon.txt'
    monkeypatch.setattr(suite, 'MAX_SHARED_PKTMON_TEXT_TRANSFER', 2 * 1024 * 1024)
    transfer.vm.payload = b'a' * (1024 * 1024 + 1)
    original = transfer.vm.powershell
    def fail_second(command, timeout):
        if '$s.Seek(1048576,' in command:
            raise OSError('guest read interrupted')
        return original(command, timeout)
    transfer.vm.powershell = fail_second
    with pytest.raises(OSError, match='interrupted'):
        transfer._transfer_guest_file(source, len(transfer.vm.payload),
                                      hashlib.sha256(transfer.vm.payload).hexdigest(),
                                      tmp_path / 'run-01' / 'pktmon.txt')
    assert not (tmp_path / 'run-01' / 'pktmon.txt').exists()
    assert not list((tmp_path / 'run-01').glob('*.transfer-*'))


def test_file_record_streams_without_read_bytes(tmp_path, monkeypatch):
    path = tmp_path / 'pktmon.txt'
    path.write_bytes(b'x' * 1048583)
    original = Path.read_bytes
    monkeypatch.setattr(Path, 'read_bytes', lambda self: (_ for _ in ()).throw(AssertionError('whole read')))
    assert suite.file_record(path, tmp_path) == {
        'path': 'pktmon.txt', 'size': 1048583,
        'sha256': hashlib.sha256(b'x' * 1048583).hexdigest()}
    monkeypatch.setattr(Path, 'read_bytes', original)
