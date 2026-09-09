# Copyright 2026 Google LLC
import json
from types import SimpleNamespace

import pytest

from fakenet.mcp import creation_evidence, faultinject, service_stop


@pytest.fixture
def scene(tmp_path, monkeypatch):
    monkeypatch.setenv('PROGRAMDATA', str(tmp_path / 'data'))
    monkeypatch.setattr(service_stop, 'process_identity',
                        lambda pid: {'pid': pid, 'creation_time': str(pid + 1000)})
    directory = tmp_path / 'run'
    directory.mkdir()
    return directory, SimpleNamespace(pid=123, members=lambda: [123, 456])


def test_disabled_creation_fault_does_not_pause_or_consume(scene, monkeypatch):
    directory, job = scene
    monkeypatch.delenv('FAKENETNG_MCP_FAULT_INJECTION', raising=False)
    faultinject.FaultInjector().arm('create_after_api')
    monkeypatch.setattr(creation_evidence.time, 'sleep',
                        lambda _: pytest.fail('production path must not pause'))
    creation_evidence.observe_creation('run', directory, job, 'after_api')
    assert faultinject._fault_file().is_file()
    assert not (directory / 'creation-fault-triggered.json').exists()
    event = json.loads((directory / 'creation.jsonl').read_text())
    assert event['job_members'] == [123, 456]
    assert event['child'] == {'pid': 123, 'creation_time': '1123'}


def test_creation_pause_expires_fail_closed_and_preserves_nonce(scene, monkeypatch):
    directory, job = scene
    monkeypatch.setenv('FAKENETNG_MCP_FAULT_INJECTION', '1')
    faultinject.FaultInjector().arm('create_after_api')
    armed = json.loads(faultinject._fault_file().read_text())
    now = [1.0]
    monkeypatch.setattr(creation_evidence.time, 'monotonic', lambda: now[0])
    monkeypatch.setattr(creation_evidence.time, 'sleep', lambda _: now.__setitem__(0, now[0] + 30))
    with pytest.raises(TimeoutError, match='expired'):
        creation_evidence.observe_creation('run', directory, job, 'after_api')
    receipt = json.loads((directory / 'creation-fault-triggered.json').read_text())
    assert receipt['nonce'] == armed['nonce']
    assert receipt['observation']['stage'] == 'after_api'
    assert not faultinject._fault_file().exists()


def test_other_creation_stage_is_not_consumed(scene, monkeypatch):
    directory, job = scene
    monkeypatch.setenv('FAKENETNG_MCP_FAULT_INJECTION', '1')
    faultinject.FaultInjector().arm('create_before_start')
    monkeypatch.setattr(creation_evidence.time, 'sleep',
                        lambda _: pytest.fail('wrong window must not pause'))
    creation_evidence.observe_creation('run', directory, job, 'after_api')
    assert faultinject._fault_file().is_file()
