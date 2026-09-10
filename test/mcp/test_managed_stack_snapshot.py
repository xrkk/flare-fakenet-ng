import json

import pytest

from fakenet.mcp.managed_stacks import read_stacks, save_stacks
from fakenet.mcp.incident import IncidentCollector


def test_actual_stack_observation_has_identity_and_is_explicitly_not_live(tmp_path):
    identity = {'pid': 42, 'creation_time': '123'}
    save_stacks(tmp_path, 'run', identity, IncidentCollector._thread_stacks())
    content = read_stacks(tmp_path, 'run', identity)
    assert 'test_actual_stack_observation' in content
    assert 'NOT A LIVE IPC RESPONSE' in content
    assert 'time_ns=' in content
    assert list(tmp_path.glob('.managed-stacks-*')) == []
    save_stacks(tmp_path, 'run', identity, 'later observation')
    assert read_stacks(tmp_path, 'run', identity).endswith('later observation')


@pytest.mark.parametrize('change', [{'run_id': 'different'}, {'identity': {'pid': 42, 'creation_time': '456'}},
                                  {'stacks': ''}, {'time_ns': 0}, {'time_ns': True}])
def test_cross_run_reused_pid_or_missing_observation_is_refused(tmp_path, change):
    identity = {'pid': 42, 'creation_time': '123'}
    save_stacks(tmp_path, 'run', identity, 'actual stacks')
    p = tmp_path/'managed-thread-stacks.json'
    data = json.loads(p.read_text());data.update(change);p.write_text(json.dumps(data))
    assert read_stacks(tmp_path, 'run', identity) is None


def test_snapshot_fallback_still_requires_fresh_live_target_dump(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from fakenet.mcp import baseline, incident, service_stop
    from fakenet.mcp.supervisor import RealSupervisor
    identity = {'pid': 42, 'creation_time': '123'}
    save_stacks(tmp_path, 'run', identity, 'Thread 42: observed managed frames')
    runner = RealSupervisor(artifacts_root=tmp_path)
    runner._run_dir = tmp_path
    runner._marker = {'run_id': 'run', 'config_sha256': 'a'*64}
    runner._baseline_store = SimpleNamespace(load=lambda run: {'sections': {}})
    runner._coordinator = SimpleNamespace(events=lambda count: [])
    def disconnected(*a, **kw): raise EOFError('managed IPC EOF')
    runner._fakenet = SimpleNamespace(identity=identity, pid=42, request=disconnected,
        alive=lambda: True, job=SimpleNamespace(poll=lambda: None, members=lambda: [42]))
    monkeypatch.setattr(baseline, 'capture', lambda deadline: {})
    monkeypatch.setattr(service_stop, 'process_identity', lambda pid: identity)
    contexts = []
    class Collector:
        def __init__(self, *args):
            self.root = tmp_path/'incident';self.deadline = float('inf');self.manifest = []
        def collect(self, context): contexts.append(context)
    monkeypatch.setattr(incident, 'IncidentCollector', Collector)
    runner._collect_incident_impl('managed IPC EOF')
    assert len(contexts) == 1
    assert contexts[0]['dump_reason'] == 'live managed IPC stacks unavailable'
    assert contexts[0]['dump_target_pid'] == 42
    assert contexts[0]['dump_target_creation'] == '123'
    assert 'NOT A LIVE IPC RESPONSE' in contexts[0]['managed_thread_stacks']
