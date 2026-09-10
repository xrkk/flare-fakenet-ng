import json
import hashlib
from collections import deque
from pathlib import Path
from types import SimpleNamespace

import pytest

from fakenet.mcp.endpoint_observation import EndpointObservation
from fakenet.mcp.endpoint_trace import owned_trace_sessions


RUN = '11111111-2222-4333-8444-555555555555'


def stats(path):
    return {'Code': 0, 'SessionGuid': RUN, 'LogFileName': str(path),
            'LogFileMode': 0x00400001, 'MaximumFileSize': 16,
            'EventsLost': 0, 'LogBuffersLost': 0, 'RealTimeBuffersLost': 0}


def test_complete_trace_retains_raw_events_and_is_finalized_once(tmp_path):
    active = tmp_path / 'udp.etl.part'
    active.write_bytes(b'raw ETL fixture')
    info = stats(active)
    replies = deque([info, [], info, info, {'Code': 4201}, [], []])
    calls = []
    def execute(script, deadline):
        calls.append(script)
        return replies.popleft()
    trace = EndpointObservation(tmp_path, RUN, execute)
    trace.start()
    report = trace.finish()
    assert report['complete'] and report['absent']
    assert not active.exists()
    assert (tmp_path / 'udp.etl').read_bytes() == b'raw ETL fixture'
    assert json.loads((tmp_path / 'endpoint-events.json').read_text())['run_id'] == RUN
    assert trace.finish() is report
    assert len(calls) == 7 and not replies


def test_missing_start_evidence_does_not_prevent_owned_session_cleanup(tmp_path):
    active = tmp_path / 'udp.etl.part'
    active.write_bytes(b'raw ETL fixture')
    info = stats(active)
    replies = deque([info, info, {'Code': 4201}])
    trace = EndpointObservation(tmp_path, RUN, lambda *_: replies.popleft())
    report = trace.finish()
    assert report['absent'] and not report['complete']
    assert (tmp_path / 'udp.etl').is_file()
    assert 'FileNotFoundError' in report['failure']


def test_failed_stop_remains_unverified_and_preserves_partial_file(tmp_path):
    active = tmp_path / 'udp.etl.part'
    active.write_bytes(b'raw ETL fixture')
    calls = []
    def execute(script, deadline):
        calls.append(script)
        if len(calls) == 1:
            return stats(active)
        raise RuntimeError('live ownership mismatch')
    trace = EndpointObservation(tmp_path, RUN, execute)
    report = trace.finish()
    assert not report['absent'] and not report['complete']
    assert active.is_file() and not (tmp_path / 'udp.etl').exists()
    assert trace.finished is None


@pytest.mark.parametrize('change', ['guid', 'name', 'path', 'mode', 'excluded'])
def test_orphan_selection_requires_all_live_ownership_facts(change):
    root = r'C:\ProgramData\FakeNet-NG-MCP\artifacts'
    path = root + '\\runs\\' + RUN + '\\udp.etl.part'
    row = dict(stats(path), SessionName='fakenetng-mcp-udp-' + RUN)
    assert owned_trace_sessions([row], root) == [{'run_id': RUN, 'path': path}]
    if change == 'guid':
        row['SessionGuid'] = 'foreign'
    elif change == 'name':
        row['SessionName'] = 'foreign-' + RUN
    elif change == 'path':
        row['LogFileName'] = r'C:\unrelated\udp.etl.part'
    elif change == 'mode':
        row['LogFileMode'] = 2
    assert not owned_trace_sessions([row], root, RUN if change == 'excluded' else None)


def test_service_restart_does_not_reopen_completed_run_evidence(tmp_path, monkeypatch):
    from fakenet.mcp import supervisor, endpoint_observation
    directory = tmp_path / 'artifacts' / 'runs' / RUN
    directory.mkdir(parents=True)
    (directory / 'active-config.ini').write_bytes(b'completed configuration')
    marker = {'run_id': RUN, 'needs_recovery': False,
              'config_sha256': hashlib.sha256(b'completed configuration').hexdigest()}
    monkeypatch.setattr(supervisor, 'os', SimpleNamespace(name='nt'))
    exclusions = []
    monkeypatch.setattr(endpoint_observation, 'stop_orphan_observers',
                        lambda root, exclude: exclusions.append(exclude) or [])
    def reopen(*args):
        raise AssertionError('completed run must not receive new trace evidence')
    monkeypatch.setattr(endpoint_observation, 'EndpointObservation', reopen)
    instance = supervisor.RealSupervisor(
        snapshot=SimpleNamespace(read=lambda: (marker, False)),
        baseline_store=SimpleNamespace(root=tmp_path / 'baselines'),
        artifacts_root=tmp_path / 'artifacts')
    instance.stop = lambda coordinator: {'state': 'stopped'}
    coordinator = SimpleNamespace(restore_responsibility=lambda *args: None)
    assert instance.recover(coordinator) == 'stopped'
    assert exclusions == [None]
    assert list(directory.iterdir()) == [directory / 'active-config.ini']
