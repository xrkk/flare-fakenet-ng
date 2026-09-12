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
    run_dir = tmp_path/'runs'/'run'
    run_dir.mkdir(parents=True)
    save_stacks(run_dir, 'run', identity, 'Thread 42: observed managed frames')
    runner = RealSupervisor(artifacts_root=tmp_path)
    runner._run_dir = run_dir
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
        def __init__(self, *args, **kwargs):
            self.root = tmp_path/'incident';self.deadline = float('inf');self.manifest = []
        def collect(self, context): contexts.append(context)
    monkeypatch.setattr(incident, 'IncidentCollector', Collector)
    from fakenet.mcp import incident_task, exit_files
    monkeypatch.setattr(exit_files, 'root', lambda: tmp_path/'exit-evidence')
    monkeypatch.setattr(baseline.BaselineStore, 'load', lambda self, run: {'sections': {}})
    directories = {'artifacts': tmp_path, 'baselines': tmp_path/'baselines'}
    def diagnostic_call(operation, payload, deadline):
        if operation == 'incident-prepare':
            return incident_task.prepare_stage(payload, directories, tmp_path, deadline)
        return incident_task.collect_stage(payload, directories, tmp_path, deadline)
    runner._diagnostic_call = diagnostic_call
    runner._collect_incident_impl('managed IPC EOF')
    assert len(contexts) == 1
    assert contexts[0]['dump_reason'] == 'live managed IPC stacks unavailable'
    assert contexts[0]['dump_target_pid'] == 42
    assert contexts[0]['dump_target_creation'] == '123'
    assert 'NOT A LIVE IPC RESPONSE' in contexts[0]['managed_thread_stacks']


@pytest.mark.parametrize('reason,supervisor_dump', [
    ('environment restoration audit failed', True),
    ('managed process exited', False),
])
def test_post_job_audit_retains_managed_observation_and_dumps_actual_auditor(
        tmp_path, monkeypatch, reason, supervisor_dump):
    import os
    from types import SimpleNamespace
    from fakenet.mcp import baseline, incident, service_stop
    from fakenet.mcp.supervisor import RealSupervisor
    identity = {'pid': 42, 'creation_time': '123'}
    run_dir = tmp_path/'runs'/'run'
    run_dir.mkdir(parents=True)
    save_stacks(run_dir, 'run', identity, 'Thread 42: last actual managed frames')
    runner = RealSupervisor(artifacts_root=tmp_path)
    runner._run_dir = run_dir
    runner._marker = {'run_id': 'run', 'config_sha256': 'a'*64}
    runner._baseline_store = SimpleNamespace(load=lambda run: {'sections': {}})
    runner._coordinator = SimpleNamespace(events=lambda count: [])
    runner._last_managed_process = dict(identity=identity, exit_code=1, job_members=[])
    monkeypatch.setattr(baseline, 'capture', lambda deadline: {})
    monkeypatch.setattr(service_stop, 'process_identity',
                        lambda pid: {'pid': pid, 'creation_time': '456'})
    contexts = []
    class Collector:
        def __init__(self, *args, **kwargs):
            self.root = tmp_path/'incident';self.deadline = float('inf');self.manifest = []
        def collect(self, context): contexts.append(context)
    monkeypatch.setattr(incident, 'IncidentCollector', Collector)
    from fakenet.mcp import incident_task, exit_files
    monkeypatch.setattr(exit_files, 'root', lambda: tmp_path/'exit-evidence')
    monkeypatch.setattr(baseline.BaselineStore, 'load', lambda self, run: {'sections': {}})
    directories = {'artifacts': tmp_path, 'baselines': tmp_path/'baselines'}
    def diagnostic_call(operation, payload, deadline):
        if operation == 'incident-prepare':
            return incident_task.prepare_stage(payload, directories, tmp_path, deadline)
        return incident_task.collect_stage(payload, directories, tmp_path, deadline)
    runner._diagnostic_call = diagnostic_call
    runner._collect_incident_impl(reason)
    context = contexts[0]
    assert 'last actual managed frames' in context['managed_thread_stacks']
    assert 'NOT A LIVE IPC RESPONSE' in context['managed_thread_stacks']
    if supervisor_dump:
        assert context['dump_target_pid'] == os.getpid()
        assert context['dump_target_creation'] == '456'
        assert context['versions']['dump_target']['role'] == 'supervisor'
        assert context['dump_reason'] == 'restoration audit failure after verified managed Job exit'
    else:
        assert context['dump_target_pid'] is None
        # A retained stack snapshot documents the exited process, but cannot
        # authorize a fresh dump after the managed Job is empty.
        assert context['dump_reason'] is None


def test_start_response_already_has_identified_stack_observation(tmp_path, monkeypatch):
    import ctypes
    import io
    import logging
    import sys
    from types import SimpleNamespace
    from fakenet.mcp import managed, service_stop
    identity = {'pid': 42, 'creation_time': '123'}
    class NativeCall:
        def __init__(self, fn): self.fn = fn
        def __call__(self, *args): return self.fn(*args)
    def in_job(process, job, result):
        ctypes.cast(result, ctypes.POINTER(ctypes.wintypes.BOOL)).contents.value = True
        return True
    kernel = SimpleNamespace(GetCurrentProcess=NativeCall(lambda: 1),
                             IsProcessInJob=NativeCall(in_job))
    monkeypatch.setattr(ctypes, 'WinDLL', lambda *a, **kw: kernel, raising=False)
    monkeypatch.delenv('FAKENETNG_MCP_FAULT_INJECTION', raising=False)
    monkeypatch.setenv('PROGRAMDATA', str(tmp_path))
    monkeypatch.setattr(logging, 'basicConfig', lambda **kw: None)
    monkeypatch.setattr(logging, 'FileHandler', lambda *a, **kw: None)
    monkeypatch.setattr(logging, 'StreamHandler', lambda *a, **kw: None)
    monkeypatch.setattr(managed, 'install_thread_exception_logging', lambda: None)
    monkeypatch.setattr(service_stop, 'process_identity', lambda pid: identity)
    fake = SimpleNamespace(fakenet_config={}, diverter_config={},
        running_listener_providers=[], diverter=None, parse_config=lambda path: None,
        start=lambda: None)
    monkeypatch.setitem(sys.modules, 'fakenet.fakenet', SimpleNamespace(Fakenet=lambda: fake))
    monkeypatch.setattr(managed, 'probe_instance', lambda instance: {'init_evidence': True, 'probe': True})
    request = {'run_id': 'run', 'seq': 1, 'kind': 'start',
               'payload': {'config_path': 'unused', 'fakenet_config': {}, 'diverter_config': {}}}
    class Response(io.BytesIO):
        def write(self, raw):
            observation = read_stacks(tmp_path, 'run', identity)
            assert observation and 'child_main' in observation, 'first ready response escaped before stack capture'
            return super().write(raw)
    response = Response()
    monkeypatch.setattr(managed, 'redirect_child_streams', lambda path: (
        io.BytesIO(json.dumps(request).encode() + b'\n'), response, io.StringIO()))
    assert managed.child_main('run', tmp_path) == 1
    assert json.loads(response.getvalue())['result']['probe'] is True
