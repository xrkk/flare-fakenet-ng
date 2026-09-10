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
        dumpworker.collect_dump(10, '100', target, 101.0, quota=64)
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


def test_real_normal_round_produces_identity_used_by_summary(monkeypatch):
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
    gate.config_lock_probe = lambda i, during_run: ('config_in_use' if during_run else 'released', {})
    gate.stop_once = lambda: {'state': 'stopped'}
    gate.audit_diff = lambda before: {}
    monkeypatch.setattr(module, 'call', lambda base, tool, *a, **k:
                        {'state_version': 2, 'run_id': 'actual-started-run'})
    monkeypatch.setattr(module, 'continuous_probe', lambda *a: (True, [True]))
    monkeypatch.setattr(module, 'wait_state', lambda *a, **k: (True, {'state': 'stopped'}))
    record = gate._normal_round(1, module.DEFAULT_INI)
    assert record['run_id'] == 'actual-started-run'
    assert module.validate_sample_category(record, 'normal-builtin') == []
    assert module.validate_sample_category(record, 'normal-custom')
    assert module.validate_rounds([
        {'run_id': record['run_id'], 'class': 'normal-builtin'},
        {'run_id': record['run_id'], 'class': 'fault-child_hang'}])


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
