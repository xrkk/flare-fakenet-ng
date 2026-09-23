"""Initialization ownership and readiness at the actual production boundaries."""
import ctypes
import io
import json
import logging
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from fakenet.mcp import managed, service_stop
from fakenet.mcp.exit_retention import ExitRetention


class NativeCall:
    def __init__(self, fn): self.fn = fn
    def __call__(self, *args): return self.fn(*args)


def test_ready_then_stacks_and_cold_stop_do_not_construct_engine(monkeypatch, tmp_path):
    def in_job(process, job, result):
        ctypes.cast(result, ctypes.POINTER(ctypes.wintypes.BOOL)).contents.value = True
        return True
    kernel = SimpleNamespace(GetCurrentProcess=NativeCall(lambda: 1),
                             IsProcessInJob=NativeCall(in_job))
    monkeypatch.setattr(ctypes, 'WinDLL', lambda *a, **k: kernel, raising=False)
    monkeypatch.delenv('FAKENETNG_MCP_FAULT_INJECTION', raising=False)
    monkeypatch.setenv('PROGRAMDATA', str(tmp_path))
    monkeypatch.setattr(logging, 'basicConfig', lambda **k: None)
    monkeypatch.setattr(logging, 'FileHandler', lambda *a, **k: None)
    monkeypatch.setattr(logging, 'StreamHandler', lambda *a, **k: None)
    monkeypatch.setattr(managed, 'install_thread_exception_logging', lambda: None)
    monkeypatch.setattr(service_stop, 'process_identity',
                        lambda pid: {'pid': 42, 'creation_time': '123'})
    monkeypatch.setitem(sys.modules, 'fakenet.fakenet',
                        SimpleNamespace(Fakenet=lambda: pytest.fail('cold engine construction')))
    requests = [dict(run_id='current', seq=i + 1, kind=kind, payload={})
                for i, kind in enumerate(('ready', 'stacks', 'stop'))]
    output = io.BytesIO()
    monkeypatch.setattr(managed, 'redirect_child_streams', lambda path: (
        io.BytesIO(b''.join(json.dumps(x).encode() + b'\n' for x in requests)),
        output, io.StringIO()))
    assert managed.child_main('current', tmp_path) == 0
    responses = [json.loads(x) for x in output.getvalue().splitlines()]
    assert responses[0]['result'] == dict(ready=True, identity=dict(pid=42, creation_time='123'))
    assert responses[-1]['result'] == {'stopped': True}


@pytest.mark.parametrize('failure', ['exit-init', 'worker', 'identity'])
def test_partial_retention_remains_owned_until_all_objects_end(monkeypatch, tmp_path, failure):
    from fakenet.mcp import exit_retention as module, diagnostic_process
    events = []
    live = {'target': True, 'diagnostic': True}
    class Target:
        def __init__(self, pid): events.append('open')
        def identity(self):
            if failure == 'identity': raise OSError('identity failure')
            return dict(pid=42, creation_time='123', image=str(tmp_path / 'fakenetng-mcp-managed.exe'))
        def command_line(self): return 'managed-child current'
        def exited(self): return live['target'] is False
        def close(self):
            assert not live['target']
            events.append('close')
    class Diagnostic:
        def __init__(self, package): self.active = None
        def pending(self): return self.active is not None and not self.active.ended.is_set()
        def call(self, operation, payload, deadline):
            self.active = SimpleNamespace(ended=threading.Event(), cancel=threading.Event())
            if failure == 'exit-init':
                raise diagnostic_process.DiagnosticError('diagnostic deadline; ownership retained')
            self.active.ended.set()
    monkeypatch.setattr(module, 'TargetHandle', Target)
    monkeypatch.setattr(module, 'root', lambda: tmp_path)
    monkeypatch.setattr(diagnostic_process, 'DiagnosticOwner', Diagnostic)
    if failure == 'worker':
        monkeypatch.setattr(threading.Thread, 'start', lambda self: (_ for _ in ()).throw(RuntimeError('worker failure')))
    # The supervisor's slot is populated before initialize acquires anything.
    supervisor = SimpleNamespace(retained=ExitRetention(
        '11111111-1111-4111-8111-111111111111', dict(pid=42, creation_time='123'),
        dict(pid=1, creation_time='1'), 'instance', tmp_path))
    owner = supervisor.retained
    assert events == [] and owner._target is None
    with pytest.raises((OSError, RuntimeError)):
        owner.initialize()
    assert supervisor.retained is owner and owner.done.is_set()
    assert not owner.resources_ended()
    original = owner.result['error']
    owner.settle(time.monotonic())
    assert 'close' not in events and owner.result['error'] == original
    live['target'] = False
    owner.settle(time.monotonic())
    if failure == 'exit-init':
        assert 'close' not in events
        assert owner._diagnostics.active.cancel.is_set()
        owner._diagnostics.active.ended.set()
    owner.settle(time.monotonic() + 1)
    assert owner.resources_ended() and events.count('close') == 1
    assert owner.result['complete'] is False and owner.result['error'] == original


@pytest.mark.parametrize('stage', ['identity', 'after_api'])
def test_spawn_failure_keeps_pre_registered_job_until_observed_end(monkeypatch, tmp_path, stage):
    from fakenet.mcp import jobobject, creation_evidence
    original_os = managed.os
    monkeypatch.setattr(managed, 'os', SimpleNamespace(
        pipe=original_os.pipe, fdopen=original_os.fdopen, close=original_os.close,
        set_handle_inheritable=lambda *a: None))
    monkeypatch.setitem(sys.modules, 'msvcrt', SimpleNamespace(get_osfhandle=lambda fd: fd))
    state = {'live': True, 'closed': False}
    class Job:
        pid = process = None
        def spawn(self, command, cwd, handles, observe):
            self.pid, self.process = 42, 42
            observe('after_api')
            return self.pid
        def terminate(self, deadline):
            if state['live']: raise TimeoutError('end unconfirmed')
        def poll(self): return None if state['live'] else 1
        def members(self): return [42] if state['live'] else []
        def close(self):
            assert not state['live']
            state['closed'] = True
    monkeypatch.setattr(jobobject, 'ManagedJob', Job)
    def observe(run, directory, job, current):
        if stage == current: raise OSError('observation failure')
    monkeypatch.setattr(creation_evidence, 'observe_creation', observe)
    monkeypatch.setattr(service_stop, 'process_identity',
                        lambda pid: (_ for _ in ()).throw(OSError('identity failure')))
    supervisor = SimpleNamespace(child=managed.ManagedProcess('current', tmp_path, tmp_path))
    child = supervisor.child
    assert child.job is None
    with pytest.raises(OSError): child.initialize()
    assert supervisor.child is child and child.job.pid == 42 and child.identity is None
    assert not child.cleanup(time.monotonic())
    assert child.failure and child.cleanup_errors and not state['closed']
    state['live'] = False
    assert child.cleanup(time.monotonic() + 1)
    assert state['closed'] and child.job is None
    assert child.failure and child.cleanup_errors


def test_diagnostic_error_retry_cannot_cross_collection_deadline(monkeypatch, tmp_path):
    from fakenet.mcp import exit_retention as module
    from fakenet.mcp.diagnostic_process import DiagnosticError
    clock = SimpleNamespace(now=0.0)
    owner = ExitRetention('11111111-1111-4111-8111-111111111111', {}, {}, 'instance', tmp_path)
    owner.deadline = 1.0
    owner.record = {'run_id': 'current'}
    owner.directory = tmp_path
    closed, reads = [], []
    owner._target = SimpleNamespace(exited=lambda: True, close=lambda: closed.append('target'))
    owner.intent = SimpleNamespace(invalidate=lambda: None, invalidate_local=lambda: None)
    def read(name):
        reads.append(clock.now)
        if clock.now > 3: pytest.fail('watcher bypassed three budgets')
        raise DiagnosticError('read ownership pending')
    owner._read_optional = read
    def sleep(seconds): clock.now += seconds
    monkeypatch.setattr(module, 'time', SimpleNamespace(monotonic=lambda: clock.now,
        time=lambda: clock.now, sleep=sleep))
    owner._watch()
    assert reads == [0.0, 0.5] and clock.now == 1.0
    assert closed == ['target'] and owner.done.is_set()
    assert owner.result['complete'] is False


def test_single_diagnostic_error_recovers_within_original_deadline(monkeypatch, tmp_path):
    from fakenet.mcp import exit_retention as module
    from fakenet.mcp.diagnostic_process import DiagnosticError
    clock = SimpleNamespace(now=0.0)
    owner = ExitRetention('11111111-1111-4111-8111-111111111111', {}, {}, 'instance', tmp_path)
    owner.deadline, owner.directory = 1.0, tmp_path
    owner.record = {'run_id': 'current', 'pid': 42, 'creation_time': '123'}
    closed, calls = [], []
    owner._target = SimpleNamespace(exited=lambda: True, close=lambda: closed.append('target'))
    owner.intent = SimpleNamespace(normal_is_valid=lambda claim: True,
        invalidate=lambda: closed.append('intent'), invalidate_local=lambda: None)
    filetime = str(int((1000000 + 11644473600) * 10000000))
    helper_identity = {'pid': 99, 'creation_time': filetime}
    def read(name):
        calls.append((name, clock.now))
        if name == 'entry.json' and len([x for x in calls if x[0] == name]) == 1:
            raise DiagnosticError('one transient diagnostic child failure')
        if name == 'entry.json':
            return {'target': owner.record, 'helper': helper_identity, 'acquired': True}
        if name == 'normal-claim.json':
            return None
        if name == 'result.json':
            return dict(schema='fakenet.exit-result.v1', target=owner.record,
                        helper=helper_identity, classification='controlled_normal_exit',
                        stop_intent_claim='valid', complete=True,
                        completed_monotonic=clock.now, target_handle_closed=True)
        raise AssertionError(name)
    owner._read_optional = read
    owner._open_helper = lambda identity: SimpleNamespace(
        exited=lambda: True, close=lambda: closed.append('helper'))
    owner._publish = lambda name, record: closed.append(name)
    owner._call = lambda operation, payload, deadline=None: calls.append((operation, clock.now))
    monkeypatch.setattr(module, 'time', SimpleNamespace(monotonic=lambda: clock.now,
        time=lambda: 1000000.0, sleep=lambda seconds: setattr(clock, 'now', clock.now + seconds)))
    owner._watch()
    assert owner.done.is_set() and owner.result['complete'] is True
    assert owner._entry_read_attempts == 2 and owner._entry_read_diagnostic_errors == 1
    assert calls[0] == ('entry.json', 0.0) and calls[1] == ('entry.json', 0.5)
    assert all(at <= owner.deadline for _, at in calls)
    assert closed.count('target') == closed.count('helper') == 1


def test_helperless_deadline_keeps_live_target_without_new_dump(tmp_path):
    owner = ExitRetention('11111111-1111-4111-8111-111111111111', {}, {}, 'instance', tmp_path)
    owner.deadline = time.monotonic() - 1
    owner.record, owner.directory = {'run_id': 'current'}, tmp_path
    owner.intent = SimpleNamespace(invalidate=lambda: None, invalidate_local=lambda: None)
    owner._target = SimpleNamespace(exited=lambda: False, close=lambda: pytest.fail('live target closed'))
    owner._read_optional = lambda name: pytest.fail('new read after deadline')
    owner.collect_owner_dump = lambda **kw: pytest.fail('new dump after deadline')
    owner._watch()
    assert owner.done.is_set() and owner.result['complete'] is False
    assert owner.result['retained_target_handle_closed'] is False
    assert 'target still active' in owner.result['cleanup_error']


def test_ready_identity_rejection_does_not_retry(tmp_path):
    child = managed.ManagedProcess('current', tmp_path, tmp_path)
    child.identity = dict(pid=42, creation_time='123')
    calls = []
    def request(kind, timeout):
        calls.append(kind)
        return dict(ready=True, identity=dict(pid=42, creation_time='different'))
    child.request = request
    with pytest.raises(RuntimeError, match='readiness identity'):
        child.wait_ready()
    assert calls == ['ready']


def test_real_supervisor_no_marker_stop_and_start_gate_keep_internal_diagnostic_owner(tmp_path):
    from fakenet.mcp.exit_capability import NativeCapabilityOwner
    from fakenet.mcp.supervisor import RealSupervisor, SupervisorStartError
    supervisor = RealSupervisor(snapshot=SimpleNamespace(read=lambda: (None, False)))
    capability = NativeCapabilityOwner(tmp_path, {}, 'instance')
    supervisor._capability_owner = capability
    capability.failure = 'original exit-init failure'
    closed = []
    capability.job = SimpleNamespace(process=1, poll=lambda: 1, members=lambda: [],
        terminate=lambda deadline: None, close=lambda: closed.append('job'))
    retained = ExitRetention('11111111-1111-4111-8111-111111111111', {}, {}, 'instance', tmp_path)
    capability.retained = retained
    retained._initialization_failed = True
    retained.result = dict(complete=False, error=capability.failure,
        helper_ended=False, retained_target_handle_closed=False)
    retained.done.set()
    pending = SimpleNamespace(ended=threading.Event(), cancel=threading.Event())
    retained._diagnostics.active = pending
    with pytest.raises(SupervisorStartError, match='ownership unresolved'):
        supervisor._ensure_exit_capability()
    result = supervisor.stop(SimpleNamespace(), deadline=time.monotonic() + 0.01)
    assert result['state'] == 'failed' and not result['release_controller']
    assert supervisor._capability_owner is capability and closed == []
    assert pending.cancel.is_set()
    assert supervisor._last_exit_evidence['error'] == capability.failure
    pending.ended.set()
    result = supervisor.stop(SimpleNamespace(), deadline=time.monotonic() + 1)
    assert result['state'] == 'stopped' and result['last_run_outcome'] == 'failed'
    assert supervisor._capability_owner is None and closed == ['job']
    assert supervisor._last_exit_evidence['error'] == 'original exit-init failure'


@pytest.mark.parametrize('native_result,accepted', [(1, True), (0, False), (258, False), (0xffffffff, False)])
def test_native_event_gate_uses_process_first_and_remaining_original_budget(monkeypatch, tmp_path, native_result, accepted):
    from ctypes import wintypes
    from fakenet.mcp import exit_capability as module
    owner = module.NativeCapabilityOwner(tmp_path, {}, 'instance')
    owner.deadline, owner.event = 105.0, 22
    calls, closed = [], []
    def wait(count, handles, all_objects, timeout):
        calls.append((count, tuple(handles), all_objects, timeout))
        return native_result
    owner.job = SimpleNamespace(c=ctypes, w=wintypes, process=11,
        _bind=lambda *a: wait, kernel=SimpleNamespace(CloseHandle=lambda handle: closed.append(handle) or True))
    monkeypatch.setattr(module, 'time', SimpleNamespace(monotonic=lambda: 100.0))
    if accepted:
        owner.wait_ready()
    else:
        with pytest.raises(RuntimeError, match='readiness failed'):
            owner.wait_ready()
    assert calls == [(2, (11, 22), False, 5000)]
    assert closed == [22] and owner.event is None


def test_native_selftest_actual_initialize_failure_keeps_job_and_original_error(monkeypatch, tmp_path):
    from ctypes import wintypes
    from fakenet.mcp import exit_capability as module, jobobject, exit_retention, exit_files
    from fakenet.mcp import supervisor as supervisor_module, exit_installation
    from fakenet.mcp.supervisor import RealSupervisor, SupervisorStartError
    real_os = module.os
    monkeypatch.setattr(module, 'os', SimpleNamespace(devnull=real_os.devnull,
        O_RDWR=real_os.O_RDWR, O_BINARY=0, open=real_os.open, close=real_os.close,
        set_handle_inheritable=lambda *a: None))
    monkeypatch.setitem(sys.modules, 'msvcrt', SimpleNamespace(get_osfhandle=lambda fd: fd))
    live, closed = {'value': True}, []
    class Job:
        c, w = ctypes, wintypes
        pid = process = None
        kernel = SimpleNamespace(CloseHandle=lambda handle: True)
        def __init__(self):
            assert isinstance(runner._capability_owner, module.NativeCapabilityOwner)
            assert runner._capability_owner.job is None
        def _bind(self, name, *args):
            return (lambda *a: 22) if name == 'CreateEventW' else (lambda *a: 1)
        def spawn(self, *a):
            self.pid = self.process = 42
            return 42
        def terminate(self, deadline):
            if live['value']: raise TimeoutError('target still active')
        def poll(self): return None if live['value'] else 1
        def members(self): return [42] if live['value'] else []
        def close(self):
            assert not live['value']
            closed.append('job')
    class Target:
        def __init__(self, pid): pass
        def identity(self): raise OSError('original identity failure')
        def exited(self): return not live['value']
        def close(self):
            assert not live['value']
            closed.append('target')
    monkeypatch.setattr(jobobject, 'ManagedJob', Job)
    monkeypatch.setattr(exit_retention, 'TargetHandle', Target)
    monkeypatch.setattr(exit_files, 'root', lambda: tmp_path)
    monkeypatch.setattr(service_stop, 'process_identity',
        lambda pid=None: dict(pid=pid or 1, creation_time='123' if pid else '1'))
    monkeypatch.setattr(exit_installation, 'verify', lambda package: None)
    monkeypatch.setattr(supervisor_module, 'os', SimpleNamespace(name='nt'))
    runner = RealSupervisor(snapshot=SimpleNamespace(read=lambda: (None, False)))
    with pytest.raises(OSError, match='original identity failure') as caught:
        runner.start(SimpleNamespace(), 'controller', {})
    owner = runner._capability_owner
    assert caught.value.owner is owner
    assert owner.retained is not None and owner.failure and owner.cleanup_errors
    assert closed == [] and not owner.ended()
    failed = runner.stop(SimpleNamespace(), deadline=time.monotonic() + .02)
    assert failed['state'] == 'failed' and runner._capability_owner is owner
    with pytest.raises(SupervisorStartError, match='ownership unresolved'):
        runner.start(SimpleNamespace(), 'controller', {})
    assert runner._capability_owner is owner and closed == []
    live['value'] = False
    stopped = runner.stop(SimpleNamespace(), deadline=time.monotonic() + 1)
    assert stopped['state'] == 'stopped' and runner._capability_owner is None
    assert closed == ['target', 'job'] and owner.ended()
    assert 'original identity failure' in owner.failure


@pytest.mark.parametrize('stage', ['job', 'second_pipe', 'first_fdopen'])
def test_real_start_registers_managed_owner_before_first_job_allocation(monkeypatch, tmp_path, stage):
    import hashlib
    from fakenet.mcp import supervisor as module, baseline, configlock, endpoint_observation, jobobject
    from fakenet.mcp import exit_installation
    config = tmp_path / 'config.ini'
    config.write_text('[FakeNet]\n')
    run_id = '11111111-1111-4111-8111-111111111111'
    events = []
    class Snapshot:
        marker = None
        def read(self): return self.marker, False
        def write(self, **value): self.marker = value
        def clear_recovery(self, **value): self.marker = dict(value, needs_recovery=False)
    class Baselines:
        root = tmp_path / 'baselines'
        def save(self, run): return {'path': str(self.root / (run + '.json'))}
        def compensate(self, *a): events.append('restore')
        def full_audit_diff(self, *a, **k): return {}
    class Lock:
        def __init__(self, path): pass
        def acquire(self): return self
        def release(self): events.append('unlock')
    class Observation:
        def __init__(self, *a): pass
        def start(self): pass
        def finish(self, deadline=None): return {'absent': True}
    coordinator = SimpleNamespace(current_command_id='start', operation_fenced=False,
        new_run_id=lambda: run_id, snapshot=lambda: dict(state_version=1, state='failed'),
        restore_responsibility=lambda *a: None, update_health_state=lambda *a: None,
        record_terminal_failure=lambda reason: events.append(reason))
    runner = module.RealSupervisor(snapshot=Snapshot(), baseline_store=Baselines(),
        config_path_resolver=lambda *a: config, artifacts_root=tmp_path / 'artifacts')
    runner._exit_capability = {'passed': True}
    runner._collect_incident_impl = lambda reason, deadline=None: events.append(reason)
    runner._diagnostic_call = lambda *args: events.append('register-artifacts')
    monkeypatch.setattr(module, 'os', SimpleNamespace(name='nt', path=__import__('os').path))
    monkeypatch.setattr(exit_installation, 'verify', lambda package: None)
    monkeypatch.setattr(configlock, 'ActivityLock', Lock)
    monkeypatch.setattr(endpoint_observation, 'EndpointObservation', Observation)
    monkeypatch.setattr(baseline, 'settle_dead_socket_rows', lambda: None)
    monkeypatch.setitem(sys.modules, 'msvcrt', SimpleNamespace())
    monkeypatch.setattr('fakenet.mcp.creation_evidence.observe_creation', lambda *a: None)
    native_os = managed.os
    opened = []
    pipe_calls = []
    def pipe():
        pipe_calls.append(True)
        if stage == 'second_pipe' and len(pipe_calls) == 2:
            raise OSError('second pipe allocation failure')
        pair = native_os.pipe()
        opened.extend(pair)
        return pair
    def fdopen(fd, *args, **kwargs):
        if stage == 'first_fdopen':
            raise OSError('first fdopen acquisition failure')
        return native_os.fdopen(fd, *args, **kwargs)
    monkeypatch.setattr(managed, 'os', SimpleNamespace(
        pipe=pipe, fdopen=fdopen, close=native_os.close,
        set_handle_inheritable=lambda *args: None))
    class Job:
        pid = process = None
        def close(self): events.append('job-close')
    def allocate():
        assert isinstance(runner._fakenet, managed.ManagedProcess)
        assert runner._fakenet.job is None
        events.append('owner-before-job')
        if stage == 'job':
            raise OSError('first job allocation failure')
        return Job()
    monkeypatch.setattr(jobobject, 'ManagedJob', allocate)
    result = runner.start(coordinator, 'controller', dict(name='config.ini', builtin=True,
        sha256=hashlib.sha256(config.read_bytes()).hexdigest()))
    assert result['last_run_outcome'] == 'failed'
    expected = {'job': 'first job allocation failure',
                'second_pipe': 'second pipe allocation failure',
                'first_fdopen': 'first fdopen acquisition failure'}[stage]
    assert expected in result['failure_reason']
    assert events.index('owner-before-job') < events.index('restore') < events.index('unlock')
    assert runner._fakenet is None and not runner._snapshot.marker['needs_recovery']
    for fd in opened:
        with pytest.raises(OSError):
            native_os.fstat(fd)
    if stage != 'job':
        assert 'job-close' in events


@pytest.mark.parametrize('stage', ['identity', 'observe_after_api'])
def test_real_start_keeps_spawn_failure_owner_until_job_ends(monkeypatch, tmp_path, stage):
    """RealSupervisor must retain the same ManagedProcess slot across retries."""
    import hashlib
    from fakenet.mcp import supervisor as module, baseline, configlock, endpoint_observation, jobobject
    from fakenet.mcp import exit_installation
    from fakenet.mcp.supervisor import SupervisorStartError

    config = tmp_path / 'config.ini'
    config.write_text('[FakeNet]\n')
    run_id = '11111111-1111-4111-8111-111111111111'
    events, jobs = [], []
    live = {'value': True}
    class Snapshot:
        marker = None
        def read(self): return self.marker, False
        def write(self, **value): self.marker = value
        def clear_recovery(self, **value): self.marker = dict(value, needs_recovery=False)
    class Baselines:
        root = tmp_path / 'baselines'
        def save(self, run): return {'path': str(self.root / (run + '.json'))}
        def compensate(self, *args): events.append('restore')
        def full_audit_diff(self, *args, **kwargs): return {}
    class Lock:
        def __init__(self, path): pass
        def acquire(self): return self
        def release(self): events.append('unlock')
    class Observation:
        def __init__(self, *args): pass
        def start(self): pass
        def finish(self, deadline=None): return {'absent': True}
    class Job:
        pid = process = None
        def __init__(self): jobs.append(self)
        def spawn(self, command, cwd, handles, observe):
            self.pid = self.process = 42
            observe('after_api')
            return self.pid
        def terminate(self, deadline):
            if live['value']:
                raise TimeoutError('native Job end unconfirmed')
        def poll(self): return None if live['value'] else 1
        def members(self): return [42] if live['value'] else []
        def close(self):
            assert not live['value']
            events.append('job-close')
    coordinator = SimpleNamespace(current_command_id='start', operation_fenced=False,
        new_run_id=lambda: run_id, snapshot=lambda: dict(state_version=1, state='failed'),
        restore_responsibility=lambda *args: None, update_health_state=lambda *args: None,
        record_terminal_failure=lambda reason: events.append(reason))
    runner = module.RealSupervisor(snapshot=Snapshot(), baseline_store=Baselines(),
        config_path_resolver=lambda *args: config, artifacts_root=tmp_path / 'artifacts',
        stop_grace_seconds=0.01)
    runner._exit_capability = {'passed': True}
    runner._collect_incident_impl = lambda reason, deadline=None: events.append('incident')
    runner._diagnostic_call = lambda *args: events.append('register-artifacts')
    monkeypatch.setattr(module, 'os', SimpleNamespace(name='nt', path=__import__('os').path))
    monkeypatch.setattr(exit_installation, 'verify', lambda package: None)
    monkeypatch.setattr(configlock, 'ActivityLock', Lock)
    monkeypatch.setattr(endpoint_observation, 'EndpointObservation', Observation)
    monkeypatch.setattr(baseline, 'settle_dead_socket_rows', lambda: None)
    monkeypatch.setattr(jobobject, 'ManagedJob', Job)
    native_os = managed.os
    monkeypatch.setattr(managed, 'os', SimpleNamespace(
        pipe=native_os.pipe, fdopen=native_os.fdopen, close=native_os.close,
        set_handle_inheritable=lambda *args: None))
    monkeypatch.setitem(sys.modules, 'msvcrt', SimpleNamespace(get_osfhandle=lambda fd: fd))
    def observe(run, directory, job, current):
        if stage == 'observe_after_api' and current == 'after_api':
            raise OSError('original observation failure')
    monkeypatch.setattr('fakenet.mcp.creation_evidence.observe_creation', observe)
    monkeypatch.setattr(service_stop, 'process_identity',
        lambda pid: (_ for _ in ()).throw(OSError('original identity failure')))

    result = runner.start(coordinator, 'controller', dict(name='config.ini', builtin=True,
        sha256=hashlib.sha256(config.read_bytes()).hexdigest()))
    child = runner._fakenet
    assert result['state'] == 'failed' and child is not None
    assert isinstance(child, managed.ManagedProcess) and child.job is jobs[0]
    assert child.job.process == 42 and child.failure and child.cleanup_errors
    original = child.failure
    assert not runner.stop(coordinator, deadline=time.monotonic() + .02)['state'] == 'stopped'
    assert runner._fakenet is child and not runner._snapshot.marker.get('needs_recovery') is False
    with pytest.raises(SupervisorStartError):
        runner.start(coordinator, 'controller', dict(name='config.ini', builtin=True,
            sha256=hashlib.sha256(config.read_bytes()).hexdigest()))
    assert runner._fakenet is child and len(jobs) == 1
    live['value'] = False
    result = runner.stop(coordinator, deadline=time.monotonic() + 2)
    assert result['state'] == 'stopped' and result['last_run_outcome'] == 'failed', result
    assert runner._fakenet is None and events.count('job-close') == 1
    assert child.failure == original and child.cleanup_errors


@pytest.mark.parametrize('stage', ['exit_init_pending', 'worker_start', 'record_identity'])
def test_real_start_keeps_exit_retention_slot_across_initialization_failure(
        monkeypatch, tmp_path, stage):
    """Run the real supervisor/managed/retention constructors with native facts replaced."""
    import hashlib
    import os
    from fakenet.mcp import supervisor as supervisor_module, baseline, configlock
    from fakenet.mcp import endpoint_observation, exit_retention, jobobject, diagnostic_process
    from fakenet.mcp import exit_installation
    from fakenet.mcp.supervisor import SupervisorStartError

    config = tmp_path / 'config.ini'
    config.write_text('[FakeNet]\n')
    run_id = '11111111-1111-4111-8111-111111111111'
    live = {'value': True}
    events, jobs, targets, diagnostics = [], [], [], []
    class Snapshot:
        marker = None
        def read(self): return self.marker, False
        def write(self, **value): self.marker = value
        def clear_recovery(self, **value): self.marker = dict(value, needs_recovery=False)
    class Baselines:
        root = tmp_path / 'baselines'
        def save(self, run): return {'path': str(self.root / (run + '.json'))}
        def compensate(self, *args): events.append('restore')
        def full_audit_diff(self, *args, **kwargs): return {}
    class Lock:
        def __init__(self, path): pass
        def acquire(self): return self
        def release(self): events.append('unlock')
    class Observation:
        def __init__(self, *args): pass
        def start(self): pass
        def finish(self, deadline=None): return {'absent': True}
    class Job:
        pid = process = None
        def __init__(self): jobs.append(self)
        def spawn(self, command, cwd, handles, observe):
            self.pid = self.process = 42
            input_fd, output_fd = os.dup(handles[0]), os.dup(handles[1])
            def child_wire():
                with os.fdopen(input_fd, 'rb', buffering=0) as source, \
                        os.fdopen(output_fd, 'wb', buffering=0) as sink:
                    for raw in source:
                        request = json.loads(raw)
                        kind = request['kind']
                        response = dict(run_id=request['run_id'], seq=request['seq'],
                                        result=({'ready': True, 'identity':
                                                 {'pid': 42, 'creation_time': '123'}}
                                                if kind == 'ready' else {'stacks': []}))
                        if kind == 'stacks':
                            response['error'] = 'simulated stack channel failure'
                        sink.write(json.dumps(response).encode() + b'\n')
                        if kind == 'stacks':
                            return
            self.wire = threading.Thread(target=child_wire, name='test-native-wire', daemon=True)
            self.wire.start()
            observe('after_api')
            return self.pid
        def terminate(self, deadline):
            if live['value']:
                raise TimeoutError('native Job end unconfirmed')
        def poll(self): return None if live['value'] else 1
        def members(self): return [42] if live['value'] else []
        def close(self):
            assert not live['value']
            self.wire.join(2)
            assert not self.wire.is_alive()
            events.append('job-close')
    class Target:
        def __init__(self, pid):
            assert isinstance(runner._exit_retention, ExitRetention)
            assert runner._exit_retention._target is None
            targets.append(self)
        def identity(self):
            if stage == 'record_identity':
                raise OSError('original retention identity failure')
            return dict(pid=42, creation_time='123',
                image=str(runner._exit_retention.package / 'fakenetng-mcp-managed.exe'))
        def command_line(self): return 'managed-child current'
        def exited(self): return not live['value']
        def close(self):
            assert not live['value']
            events.append('target-close')
    class Diagnostic:
        def __init__(self, package):
            self.active = None
            diagnostics.append(self)
        def pending(self): return self.active is not None and not self.active.ended.is_set()
        def call(self, operation, payload, deadline):
            if operation == 'exit-init' and stage == 'exit_init_pending':
                self.active = SimpleNamespace(ended=threading.Event(), cancel=threading.Event())
                raise diagnostic_process.DiagnosticError('original exit-init deadline')
            return {}

    coordinator = SimpleNamespace(current_command_id='start', operation_fenced=False,
        new_run_id=lambda: run_id, snapshot=lambda: dict(state_version=1, state='failed'),
        restore_responsibility=lambda *args: None, update_health_state=lambda *args: None,
        record_terminal_failure=lambda reason: events.append(reason))
    runner = supervisor_module.RealSupervisor(snapshot=Snapshot(), baseline_store=Baselines(),
        config_path_resolver=lambda *args: config, artifacts_root=tmp_path / 'artifacts',
        stop_grace_seconds=5)
    runner._exit_capability = {'passed': True}
    runner._collect_incident_impl = lambda reason, deadline=None: events.append('incident')
    runner._diagnostic_call = lambda *args: events.append('register-artifacts')
    monkeypatch.setattr(supervisor_module, 'os', SimpleNamespace(name='nt', path=os.path))
    monkeypatch.setattr(exit_installation, 'verify', lambda package: None)
    monkeypatch.setattr(configlock, 'ActivityLock', Lock)
    monkeypatch.setattr(endpoint_observation, 'EndpointObservation', Observation)
    monkeypatch.setattr(baseline, 'settle_dead_socket_rows', lambda: None)
    monkeypatch.setattr(jobobject, 'ManagedJob', Job)
    monkeypatch.setattr(exit_retention, 'TargetHandle', Target)
    monkeypatch.setattr(exit_retention, 'root', lambda: tmp_path)
    monkeypatch.setattr(diagnostic_process, 'DiagnosticOwner', Diagnostic)
    native_os = managed.os
    class OSBoundary:
        def __getattr__(self, name): return getattr(native_os, name)
        def set_handle_inheritable(self, *args): pass
    monkeypatch.setattr(managed, 'os', OSBoundary())
    monkeypatch.setitem(sys.modules, 'msvcrt', SimpleNamespace(get_osfhandle=lambda fd: fd))
    monkeypatch.setattr('fakenet.mcp.creation_evidence.observe_creation', lambda *args: None)
    monkeypatch.setattr(service_stop, 'process_identity',
        lambda pid=None: dict(pid=pid or 1, creation_time='123' if pid else '1'))
    native_thread_start = threading.Thread.start
    def start_thread(thread):
        if stage == 'worker_start' and thread.name == 'managed-exit-evidence':
            raise RuntimeError('original worker start failure')
        return native_thread_start(thread)
    monkeypatch.setattr(threading.Thread, 'start', start_thread)

    result = runner.start(coordinator, 'controller', dict(name='config.ini', builtin=True,
        sha256=hashlib.sha256(config.read_bytes()).hexdigest()))
    child, owner = runner._fakenet, runner._exit_retention
    assert result['state'] == 'failed' and child is not None and owner is not None, result
    assert isinstance(owner, ExitRetention) and owner.done.is_set()
    assert owner._target is targets[0] and owner.result['complete'] is False
    assert not owner.resources_ended() and live['value']
    original = owner.result['error']
    if stage == 'record_identity':
        assert owner.record is None and owner.intent is None
    if stage == 'exit_init_pending':
        assert owner._diagnostics.pending() and owner._diagnostics.active.cancel.is_set(), (
            owner._diagnostics.active, owner.result, events)
    assert runner.stop(coordinator, deadline=time.monotonic() + 2)['state'] == 'failed'
    assert runner._fakenet is child and runner._exit_retention is owner
    with pytest.raises(SupervisorStartError):
        runner.start(coordinator, 'controller', dict(name='config.ini', builtin=True,
            sha256=hashlib.sha256(config.read_bytes()).hexdigest()))
    assert len(jobs) == 1 and runner._exit_retention is owner
    live['value'] = False
    if stage == 'exit_init_pending':
        pending = runner.stop(coordinator, deadline=time.monotonic() + 2)
        assert pending['state'] == 'failed' and runner._exit_retention is owner
        assert not owner.resources_ended() and events.count('target-close') == 0
        assert runner._snapshot.marker['needs_recovery'] is True
        with pytest.raises(SupervisorStartError):
            runner.start(coordinator, 'controller', dict(name='config.ini', builtin=True,
                sha256=hashlib.sha256(config.read_bytes()).hexdigest()))
        owner._diagnostics.active.ended.set()
    result = runner.stop(coordinator, deadline=time.monotonic() + 2)
    assert result['state'] == 'stopped' and result['last_run_outcome'] == 'failed', result
    assert owner.resources_ended() and runner._exit_retention is owner
    assert owner.result['error'] == original and owner.result['complete'] is False
    assert events.count('target-close') == events.count('job-close') == 1


def test_cancel_before_selftest_initialization_forbids_later_resource_creation(monkeypatch, tmp_path):
    from fakenet.mcp.exit_capability import NativeCapabilityOwner
    owner = NativeCapabilityOwner(tmp_path, {}, 'instance')
    assert not owner.ended(), 'empty slots alone do not finish a scheduled attempt'
    assert owner.cleanup(time.monotonic() + 1)
    monkeypatch.setattr(owner, '_verify_attempt', lambda: pytest.fail('cancelled setup created resources'))
    with pytest.raises(RuntimeError, match='cancelled before initialization'):
        owner.verify()
    assert owner.ended()


def test_cleanup_deadline_does_not_release_an_inflight_initialization(tmp_path):
    from fakenet.mcp.exit_capability import NativeCapabilityOwner
    owner = NativeCapabilityOwner(tmp_path, {}, 'instance')
    entered, release = threading.Event(), threading.Event()
    def operation():
        with owner._attempt_lock:
            owner.attempted = True
            entered.set()
            release.wait(2)
            owner._execution_done = True
    worker = threading.Thread(target=operation)
    worker.start()
    try:
        assert entered.wait(1)
        assert not owner.cleanup(time.monotonic() + 0.01)
        assert not owner.ended() and owner.cleanup_errors
    finally:
        release.set()
        worker.join(2)
    assert owner.cleanup(time.monotonic() + 1) and owner.ended()


@pytest.mark.parametrize('inject', [True, False])
def test_cleanup_fault_precedes_resource_release_and_retry_stops(monkeypatch, tmp_path, inject):
    from contextlib import nullcontext
    from fakenet.mcp.faultinject import FaultInjector
    import fakenet.mcp.managed_stacks as stacks

    def in_job(process, job, result):
        ctypes.cast(result, ctypes.POINTER(ctypes.wintypes.BOOL)).contents.value = True
        return True
    kernel = SimpleNamespace(GetCurrentProcess=NativeCall(lambda: 1),
                             IsProcessInJob=NativeCall(in_job))
    monkeypatch.setattr(ctypes, 'WinDLL', lambda *a, **k: kernel, raising=False)
    monkeypatch.setenv('PROGRAMDATA', str(tmp_path / 'data'))
    monkeypatch.chdir(tmp_path)
    if inject:
        monkeypatch.setenv('FAKENETNG_MCP_FAULT_INJECTION', '1')
        FaultInjector().arm('cleanup_error')
    else:
        monkeypatch.delenv('FAKENETNG_MCP_FAULT_INJECTION', raising=False)
    monkeypatch.setattr(logging.getLogger('managed'), 'error', lambda *a: None)
    monkeypatch.setattr(logging, 'basicConfig', lambda **k: None)
    monkeypatch.setattr(logging, 'FileHandler', lambda *a, **k: None)
    monkeypatch.setattr(logging, 'StreamHandler', lambda *a, **k: None)
    monkeypatch.setattr(managed, 'install_thread_exception_logging', lambda: None)
    monkeypatch.setattr(service_stop, 'process_identity', lambda pid: dict(pid=42, creation_time='123'))
    monkeypatch.setattr(stacks, 'save_stacks', lambda *a: None)
    monkeypatch.setattr(managed, 'capture_stop_stacks', lambda *a: nullcontext())
    stopped = []
    instance = SimpleNamespace(parse_config=lambda path: None, fakenet_config={},
                               diverter_config={}, start=lambda: None,
                               running_listener_providers=[], diverter=None,
                               stop=lambda: stopped.append('released'))
    monkeypatch.setitem(sys.modules, 'fakenet.fakenet', SimpleNamespace(Fakenet=lambda: instance))
    monkeypatch.setattr(managed, 'probe_instance', lambda instance: {'probe': True})
    requests = [dict(run_id='cleanup-run', seq=1, kind='start',
                     payload=dict(config_path='fixture', fakenet_config={}, diverter_config={})),
                dict(run_id='cleanup-run', seq=2, kind='stop')]
    if inject:
        requests.append(dict(run_id='cleanup-run', seq=3, kind='stop'))

    class Output(io.BytesIO):
        def write(self, value):
            frame = json.loads(value)
            if frame['seq'] == 2:
                if inject:
                    assert stopped == [], 'cleanup fault arrived after resource release'
                    assert 'injected cleanup error' in frame['error']
                    assert json.loads((tmp_path / 'fault-triggered.json').read_text())['fault'] == 'cleanup_error'
                else:
                    assert stopped == ['released']
                    assert frame['result'] == {'stopped': True}
            return super().write(value)

    output = Output()
    monkeypatch.setattr(managed, 'redirect_child_streams', lambda path: (
        io.BytesIO(b''.join(json.dumps(x).encode() + b'\n' for x in requests)), output, io.StringIO()))
    assert managed.child_main('cleanup-run', tmp_path) == 0
    assert stopped == ['released']
    assert json.loads(output.getvalue().splitlines()[-1])['result'] == {'stopped': True}
    if not inject:
        assert not (tmp_path / 'fault-triggered.json').exists()
