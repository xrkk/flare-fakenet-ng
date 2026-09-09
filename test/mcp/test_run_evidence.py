import hashlib
import uuid

import pytest

from fakenet.mcp.run_evidence import prepare_run_evidence, locate_run_evidence


def test_actual_config_and_zero_byte_streams_survive_new_instance(tmp_path):
    run_id = str(uuid.uuid4())
    root = tmp_path / 'artifacts'
    directory = root / 'runs' / run_id
    directory.mkdir(parents=True)
    source = tmp_path / 'config.ini'
    source.write_bytes(b'[FakeNet]\nDivertTraffic: Yes\n')
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    prepare_run_evidence(directory, source, digest)
    source.write_bytes(b'changed after crash')
    found, copied = locate_run_evidence(root, {'run_id': run_id, 'config_sha256': digest})
    assert found == directory
    assert hashlib.sha256(copied.read_bytes()).hexdigest() == digest
    assert (found / 'stdout_stderr.log').read_bytes() == b''
    assert (found / 'run.log').read_bytes() == b''
    copied.write_bytes(b'corrupted evidence')
    assert locate_run_evidence(root, {'run_id': run_id, 'config_sha256': digest}) == (directory, None)


def test_mismatched_source_is_not_registered(tmp_path):
    source = tmp_path / 'source.ini'
    source.write_bytes(b'actual')
    directory = tmp_path / 'run'
    directory.mkdir()
    with pytest.raises(RuntimeError, match='changed'):
        prepare_run_evidence(directory, source, '0' * 64)
    assert list(directory.iterdir()) == []


def test_existing_run_evidence_is_not_overwritten(tmp_path):
    source = tmp_path / 'source.ini'
    source.write_bytes(b'actual')
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    with pytest.raises(FileExistsError):
        prepare_run_evidence(tmp_path, source, digest)
        prepare_run_evidence(tmp_path, source, digest)
    assert (tmp_path / 'active-config.ini').read_bytes() == b'actual'
