import importlib
from pathlib import Path

import pytest


def test_acceptance_failure_and_raw_evidence_cannot_be_overwritten(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parent / 'acceptance'))
    writer_type = importlib.import_module('helpers').EvidenceWriter
    writer = writer_type(tmp_path, 'now')
    path = writer.add_evidence('raw', {'failed': True})
    original = path.read_bytes()
    with pytest.raises(FileExistsError):
        writer.add_evidence('raw', {'failed': False})
    assert path.read_bytes() == original
    args = dict(acc_id='ACC-013', p_id='P05', candidate_id='one', source_commit='a'*40,
                package_sha256='b'*64, requirements_blob='c'*40, master_plan_blob='d'*40,
                environment_identity='VM', status='fail')
    writer.write_result(**args)
    previous = (tmp_path / 'result.json').read_bytes()
    with pytest.raises(FileExistsError):
        writer.write_result(**dict(args, status='pass'))
    with pytest.raises(FileExistsError):
        writer_type(tmp_path, 'later')
    assert (tmp_path / 'result.json').read_bytes() == previous
