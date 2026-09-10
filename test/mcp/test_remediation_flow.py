"""Cross-layer regressions from the 5f25fb9 main-session review."""
import json
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from fakenet.mcp.supervisor import RealSupervisor
from fakenet.mcp.coordination import Coordinator
from fakenet.mcp.testdouble import LifecycleDouble
from fakenet.mcp.service_stop import ServiceStop, read_result


def test_one_observed_log_exception_cannot_become_healthy_again(tmp_path):
    supervisor = RealSupervisor.__new__(RealSupervisor)
    supervisor._run_dir = tmp_path
    supervisor._log_offset, supervisor._log_tail = 0, b''
    (tmp_path / 'run.log').write_bytes(b'Traceback (most recent call last):\n' + b'x' * 70000)
    class ProbeGate:
        calls = 0
        def wait(self, timeout):
            self.calls += 1
            return self.calls > 2
    supervisor._health_stop = ProbeGate()
    supervisor._fakenet = SimpleNamespace(
        request=lambda *a, **k: dict(init_evidence=True, probe=True),
        alive=lambda: True, identity={})
    states, stopped, reasons = [], [], []
    supervisor._publish_health = lambda child, state, evidence, reason=None: states.append(state) or True
    supervisor._health_cache = {}
    supervisor._collect_incident = reasons.append
    supervisor._submit_protective_stop = lambda: stopped.append(True)
    supervisor._coordinator = SimpleNamespace(wait_for_idle=lambda t: True,
                                              record_terminal_failure=lambda r: None)
    supervisor._health_loop()
    assert states == ['failed']
    assert stopped and 'unhandled exception' in reasons[0]


def test_cleanup_responsibility_survives_late_operation_completion():
    coord = Coordinator(LifecycleDouble())
    entered, release, cleaned = threading.Event(), threading.Event(), threading.Event()
    def operation(c):
        entered.set()
        assert release.wait(2)
        return dict(changed=True)
    worker = threading.Thread(target=lambda: coord.submit(
        command_id='config', expected_version=1, controller='owner',
        controller_valid=True, kind='edit_config', describe={}, execute=operation))
    worker.start()
    try:
        assert entered.wait(1)
        coord.recover_when_idle(cleaned.set)
        assert not cleaned.is_set()
        release.set()
        worker.join(2)
        assert cleaned.wait(1)
    finally:
        release.set()
        worker.join(2)


def test_expired_success_is_never_a_stop_authorization(monkeypatch, tmp_path):
    from fakenet.mcp import service_stop
    clock = [100.0]
    monkeypatch.setattr(service_stop.time, 'monotonic', lambda: clock[0])
    stop = ServiceStop(Coordinator(LifecycleDouble()), lambda d: {'state': 'stopped'},
                       lambda: None, tmp_path / 'stop.json', identity={'pid': 1})
    stop.budget = 10
    original, observations = stop._write, []
    def write(phase, reason=None):
        if phase == 'succeeded':
            clock[0] += 11
        original(phase, reason)
        if phase == 'succeeded':
            observations.append((read_result(stop.path)['phase'], stop.stop_authorized()))
    stop._write = write
    stop._run()
    assert observations == [('failed', False)]
    assert read_result(stop.path)['phase'] == 'failed'


def test_dump_timeout_stops_writer_before_removing_staging(monkeypatch, tmp_path):
    from fakenet.mcp import dumpworker, jobobject
    clock = [100.0]
    target = tmp_path / 'target.dmp'
    staging = target.with_name(target.name + '.part')
    events = []
    class Job:
        def spawn(self, command, *a):
            assert command[-2] == '64'
            Path(command[-3]).write_bytes(b'partial')
            clock[0] = 102.0
        def poll(self): return None
        def terminate(self, deadline): pass
        def close(self): events.append(staging.exists())
    monkeypatch.setattr(jobobject, 'ManagedJob', Job)
    monkeypatch.setitem(__import__('sys').modules, 'msvcrt', SimpleNamespace(get_osfhandle=lambda h: h))
    monkeypatch.setattr(dumpworker.os, 'set_handle_inheritable', lambda *a: None, raising=False)
    monkeypatch.setattr(dumpworker.time, 'monotonic', lambda: clock[0])
    with pytest.raises(TimeoutError):
        dumpworker.collect_dump(10, '100', target, 101.0, quota=4160)
    assert events == [True]
    assert not target.exists() and not staging.exists()


def test_incident_publishes_successful_conditional_outputs(monkeypatch, tmp_path):
    from fakenet.mcp import incident
    from fakenet.mcp.artifacts import completion
    collector = incident.IncidentCollector(tmp_path, 'run')
    monkeypatch.setattr(incident, 'BASIC_ITEMS', ())
    def conditional(context):
        target = collector.root / 'userdump.dmp'
        target.write_bytes(b'output of already verified collector')
        collector._record('userdump.dmp', 'ok', dump_path=target)
    collector._conditional_dump = conditional
    collector.collect({'exit_evidence': {'complete': True}})
    for name in ('userdump.dmp', 'managed-exit.json', 'manifest.json'):
        assert completion(collector.root / name, collector.root)


def test_failed_helper_observation_never_closes_unacquired_target(monkeypatch, tmp_path):
    from fakenet.mcp.exit_retention import ExitRetention
    from fakenet.mcp import exit_installation
    owner = ExitRetention.__new__(ExitRetention)
    closed = []
    owner.deadline = time.monotonic() + 60
    owner._target = SimpleNamespace(exited=lambda: False, close=lambda: closed.append(True))
    owner._cancel, owner.done = threading.Event(), threading.Event()
    owner._helper = None
    owner.intent = SimpleNamespace(invalidate=lambda: None)
    owner.package, owner.record = tmp_path, {}
    owner._read_optional = lambda name: (_ for _ in ()).throw(RuntimeError('entry unavailable'))
    monkeypatch.setattr(exit_installation, 'end_helpers',
                        lambda *a: (_ for _ in ()).throw(RuntimeError('helper still alive')))
    owner._watch()
    assert not closed
    assert owner.result['helper_ended'] is False
    assert owner.result['retained_target_handle_closed'] is False


def test_real_normal_round_produces_identity_used_by_summary(monkeypatch, tmp_path):
    import importlib.util
    import sys
    root = Path(__file__).resolve().parent / 'acceptance'
    monkeypatch.syspath_prepend(str(root))
    spec = importlib.util.spec_from_file_location('release_flow_under_test', root / 'run_p05_release.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    gate = module.ReleaseGate.__new__(module.ReleaseGate)
    gate.base = 'unused'
    gate.vm_continuity = lambda: {}
    gate.capture_sections = lambda: {}
    import hashlib
    config = dict(name='default.ini', builtin=True, content='test', sha256=hashlib.sha256(b'test').hexdigest())
    identity = {key: config[key] for key in ('name', 'builtin', 'sha256')}
    gate.config_lock_probe = lambda i, during_run: ('config_in_use' if during_run else 'released',
        dict(status=dict(run_id='actual-started-run', config_identity=identity),
             file_probe=dict(before=identity['sha256'], after=identity['sha256'])))
    gate.stop_once = lambda: {'state': 'stopped'}
    gate.audit_diff = lambda before: {}
    monkeypatch.setattr(module, 'call', lambda base, tool, *a, **k:
                        config if tool == 'read_config' else {'state_version': 2, 'run_id': 'actual-started-run', 'config_identity': identity})
    monkeypatch.setattr(module, 'continuous_probe', lambda *a: (True, [True]))
    monkeypatch.setattr(module, 'wait_state', lambda *a, **k: (True, {'state': 'stopped'}))
    record = gate._normal_round(1, module.DEFAULT_INI)
    assert record['run_id'] == 'actual-started-run'
    assert module.validate_sample_category(record, 'normal-builtin') == []
    assert module.validate_sample_category(record, 'normal-custom')
    assert module.validate_rounds([
        {'run_id': record['run_id'], 'class': 'normal-builtin'},
        {'run_id': record['run_id'], 'class': 'fault-child_hang'}])

    # Exercise the persisted producer record through the actual summary reader.
    gate.root, gate.release, gate.cid = tmp_path, tmp_path / 'release', 'candidate'
    gate.release.mkdir()
    expected = {field: field for field in module.IDENTITY_FIELDS}
    gate.args = SimpleNamespace(**expected)
    monkeypatch.setattr(module, 'REPO_ROOT', tmp_path)
    record.update(expected, vm_before={'pid': 1}, vm_after={'pid': 1},
                  probe_window_start=1, probe_window_end=2,
                  probe_timeline=[dict(t=1, ok=True), dict(t=2, ok=True)])
    captures = []
    for name in ('before', 'after'):
        path = tmp_path / (name + '.json')
        raw = json.dumps(dict(expected, complete=True, started_at=1, ended_at=2,
            sections={key:'raw' for key in ('routes', 'dns_servers', 'windivert_processes', 'listen_ports', 'services')})).encode()
        path.write_bytes(raw)
        captures.append(dict(path=str(path), size=len(raw), sha256=hashlib.sha256(raw).hexdigest()))
    record['capture_evidence'] = captures
    writer = SimpleNamespace(evidence=[], add_evidence=lambda *a: None)
    path = gate.round_path('normal-builtin', 1)
    gate.record_round(path, record, writer)
    gate.mode_summary(writer)
    failures = json.loads((gate.release / 'release-acc-index.json').read_text())['record_integrity_failures']
    assert str(path) not in failures
    assert 'windows-version' in failures
    record['run_id'] = 'forged-new-run'
    path.write_text(json.dumps(record))
    gate.mode_summary(writer)
    failures = json.loads((gate.release / 'release-acc-index.json').read_text())['record_integrity_failures']
    assert any('actual run/config identity mismatch' in item for item in failures[str(path)])


def test_cleanup_exports_bytes_and_refuses_foreign_baselines(monkeypatch, tmp_path):
    import base64
    import hashlib
    import sys
    import uuid
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parent / 'acceptance'))
    import helpers
    owned, foreign = str(uuid.uuid4()), str(uuid.uuid4())
    def row(name, body):
        return dict(path='C:\\ProgramData\\FakeNet-NG-MCP\\baselines\\' + name + '.json',
                    size=len(body), sha256=hashlib.sha256(body).hexdigest(),
                    body=base64.b64encode(body).decode())
    records = [row(owned, b'owned bytes'), row(foreign, b'foreign bytes')]
    calls = []
    channel = SimpleNamespace(powershell=lambda command, **k:
        calls.append(command) or {'output': json.dumps(records)})
    writer = helpers.EvidenceWriter(tmp_path, 'now')
    with pytest.raises(helpers.StepError, match='foreign baseline'):
        helpers.preserve_owned_state(channel, writer, [owned])
    assert len(calls) == 1 and not writer.evidence
    records.pop()
    helpers.preserve_owned_state(channel, writer, [owned])
    exported = json.loads(Path(writer.evidence[0]['path']).read_text())
    assert base64.b64decode(exported[0]['body']) == b'owned bytes'
    assert 'Remove-Item -LiteralPath' in calls[-1]


def test_cli_standard_stop_has_its_own_thirty_second_limit(monkeypatch, tmp_path):
    import sys
    from fakenet.mcp import service_stop, snapshot
    clock = [0.0]
    phase = {'prestop': False, 'stop': False}
    scm = SimpleNamespace(
        SC_MANAGER_CONNECT=1, SERVICE_QUERY_STATUS=4, SERVICE_STOP=32,
        SERVICE_START=16, SERVICE_USER_DEFINED_CONTROL=256, SERVICE_STOPPED=1,
        SERVICE_RUNNING=4, SERVICE_ACCEPT_STOP=1, SERVICE_CONTROL_STOP=1,
        OpenSCManager=lambda *a: 1, OpenService=lambda *a: 2,
        CloseServiceHandle=lambda h: None)
    scm.QueryServiceStatusEx = lambda h: dict(CurrentState=3 if phase['stop'] else 4,
                                             ProcessId=42, ControlsAccepted=1)
    def control(handle, code):
        phase['prestop' if code == 128 else 'stop'] = True
    scm.ControlService = control
    monkeypatch.setitem(sys.modules, 'win32service', scm)
    monkeypatch.setattr(service_stop, 'time', SimpleNamespace(
        monotonic=lambda: clock[0], sleep=lambda delay: clock.__setitem__(0, clock[0] + delay)))
    monkeypatch.setattr(service_stop, 'process_identity', lambda *a: dict(pid=42, creation_time='1'))
    monkeypatch.setattr(service_stop, 'read_result', lambda p: dict(
        pid=42, creation_time='1', instance_id='instance',
        attempt=1 if phase['prestop'] else 0,
        phase='succeeded' if phase['prestop'] else 'idle', deadline_monotonic=100.0))
    monkeypatch.setattr(snapshot.StateSnapshot, 'read', lambda s: (None, False))
    with pytest.raises(TimeoutError, match='STOPPED'):
        service_stop.stop_installed_service(SimpleNamespace(stop_grace_seconds=60),
                                             tmp_path / 'stop.json', tmp_path / 'state.json')
    assert phase['stop'] and 30 <= clock[0] < 31


def test_run_end_publishes_fixed_producer_files_in_both_locations(tmp_path, monkeypatch):
    from fakenet.mcp.artifacts import ArtifactRegistry, RUN_EVIDENCE_FILES
    root = tmp_path / 'artifacts'
    run_id = 'fe75426a-e047-4557-a2f1-7ba0f6d2ac73'
    run = root / 'runs' / run_id
    run.mkdir(parents=True)
    for name in RUN_EVIDENCE_FILES:
        (run / name).write_bytes(name.encode())
    (run / 'unowned.bin').write_bytes(b'not a declared producer')
    supervisor = RealSupervisor.__new__(RealSupervisor)
    supervisor._artifacts_root, supervisor._run_dir = root, run
    from fakenet.mcp import diagnostic_tasks, paths
    monkeypatch.setattr(paths, 'data_directories', lambda: {'artifacts': root})
    supervisor._diagnostic_call = diagnostic_tasks.execute
    supervisor._register_run_artifacts(run_id)
    metadata = {Path(item['path']): item for item in ArtifactRegistry(root).metadata()}
    for name in RUN_EVIDENCE_FILES:
        assert metadata[run / name]['complete']
        assert metadata[root / run_id / name]['complete']
    assert metadata[run / 'unowned.bin']['complete'] is False


def test_dump_tool_failure_body_is_bounded_and_preserved(monkeypatch, tmp_path):
    from fakenet.mcp import dumpworker, exit_native
    class Target:
        def __init__(self, pid): raise OSError('native failure ' + 'x' * 10000)
    monkeypatch.setattr(exit_native, 'TargetHandle', Target)
    assert dumpworker.dump_main(42, '100', tmp_path / 'userdump.dmp.part') == 1
    raw = (tmp_path / 'dump-tool.json').read_bytes()
    result = json.loads(raw)
    assert len(raw) <= 4096 and 'native failure' in result['error']
    assert result['complete'] is False and result['exception_type'] == 'OSError'


def test_final_incident_metadata_fits_reserved_quota(monkeypatch, tmp_path):
    from fakenet.mcp import incident
    monkeypatch.setattr(incident, 'DISK_QUOTA_BYTES', incident.METADATA_RESERVE_BYTES + 64)
    monkeypatch.setattr(incident, 'BASIC_ITEMS', (('timeline.json', 'timeline'),))
    collector = incident.IncidentCollector(tmp_path, 'run')
    collector._collect_item = lambda *a: b'x' * 64
    collector.collect({})
    assert (collector.root / 'timeline.json').stat().st_size == 64
    assert sum(p.stat().st_size for p in collector.root.iterdir()) <= incident.DISK_QUOTA_BYTES
    assert (collector.root / 'published.json').is_file()


def test_cross_round_captures_cannot_be_relabelled(monkeypatch, tmp_path):
    monkeypatch.syspath_prepend(str(Path(__file__).parent / 'acceptance'))
    from evidence_integrity import validate_rounds
    capture = dict(path=str(tmp_path / 'same-capture.json'))
    issues = validate_rounds([dict(run_id='one', **{'class': 'normal'}, capture_evidence=[capture]),
                              dict(run_id='two', **{'class': 'normal'}, capture_evidence=[capture])])
    assert any('capture reused across rounds' in item for item in issues)


def test_custom_name_conflict_requires_actual_semantic_delta(monkeypatch):
    import hashlib
    import importlib.util
    root = Path(__file__).parent / 'acceptance'
    monkeypatch.syspath_prepend(str(root))
    spec = importlib.util.spec_from_file_location('release_custom_test', root / 'run_p05_release.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    gate = module.ReleaseGate.__new__(module.ReleaseGate)
    gate.base = 'unused'
    body = 'DumpHTTPWebRoot: webroot\nDumpPacketsFilePrefix = packets\n'
    actual = [body]
    def call(base, tool, args=None, **kw):
        if tool == 'get_status': return {'state_version': 1}
        if tool == 'create_config': return {'error': {'code': 'name_conflict'}}
        builtin = args['name'] == 'default.ini'
        text = body if builtin else actual[0]
        return dict(name=args['name'], content=text, builtin=builtin,
                    sha256=hashlib.sha256(text.encode()).hexdigest())
    monkeypatch.setattr(module, 'call', call)
    assert gate.ensure_custom_config() is False
    from evidence_integrity import custom_config_body
    actual[0] = custom_config_body(body)
    assert gate.ensure_custom_config() is True
