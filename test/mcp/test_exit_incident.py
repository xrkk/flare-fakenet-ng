"""Synthetic dump envelopes exercise assembly; native evidence is separate."""
import hashlib
import struct
import time

import pytest

from fakenet.mcp import incident


@pytest.fixture
def assembly(tmp_path):
    source = tmp_path / 'target.dmp'
    payload = (struct.pack('<IIII', 0x504d444d, 0, 1, 32) + bytes(16)
               + struct.pack('<III', 15, 12, 44) + struct.pack('<III', 12, 1, 42))
    source.write_bytes(payload)
    collector = incident.IncidentCollector(tmp_path / 'artifacts', 'current-run')
    evidence = dict(path=source, identity=dict(run_id='current-run', pid=42),
                    dump=dict(size=len(payload), sha256=hashlib.sha256(payload).hexdigest()))
    return collector, evidence, collector.root / 'userdump.dmp', payload


def test_verified_exit_dump_is_copied_without_new_process_collection(assembly):
    collector, evidence, target, payload = assembly
    collector._copy_exit_dump(evidence, target)
    assert target.read_bytes() == payload
    assert evidence['path'].read_bytes() == payload
    assert not target.with_suffix('.dmp.partial').exists()


def test_modified_completed_dump_cannot_be_reused(assembly):
    collector, evidence, target, payload = assembly
    changed = bytearray(payload)
    changed[20] = 1
    evidence['path'].write_bytes(changed)
    with pytest.raises(RuntimeError, match='changed'):
        collector._copy_exit_dump(evidence, target)
    assert not target.exists()
    assert target.with_suffix('.dmp.partial').exists()


def test_other_run_dump_cannot_satisfy_current_incident(assembly):
    collector, evidence, target, payload = assembly
    evidence['identity']['run_id'] = 'other-run'
    with pytest.raises(RuntimeError, match='another run'):
        collector._copy_exit_dump(evidence, target)
    assert not target.exists()


def test_remaining_incident_quota_applies_before_copy(assembly, monkeypatch):
    collector, evidence, target, payload = assembly
    monkeypatch.setattr(incident, 'DISK_QUOTA_BYTES', len(payload) - 1)
    with pytest.raises(RuntimeError, match='quota'):
        collector._copy_exit_dump(evidence, target)
    assert not target.with_suffix('.dmp.partial').exists()


def test_expired_incident_cannot_publish_dump(assembly):
    collector, evidence, target, payload = assembly
    collector.deadline = time.time() - 1
    with pytest.raises(TimeoutError):
        collector._copy_exit_dump(evidence, target)
    assert not target.exists()
