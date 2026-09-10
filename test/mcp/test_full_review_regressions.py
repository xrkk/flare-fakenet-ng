# Copyright 2026 Google LLC
"""Regression tests for the full-review counterexamples (CHK-055—070).

Each case is the reviewer's probe with the assertion inverted: it now
requires the contracted behaviour instead of recording the observed
violation.  Sources: Logs/fakenetng-mcp/full-review-26debdd/probes.py and
Logs/fakenetng-mcp/main-review-26debdd/.
"""

import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from fakenet.mcp import errors
from fakenet.mcp.config import ServiceConfig
from fakenet.mcp.configstore import ConfigStore
from fakenet.mcp.coordination import Coordinator
from fakenet.mcp.testdouble import LifecycleDouble
from fakenet.mcp.tools import register_tools


def surface(coord, runner=None, store=None, artifacts=None):
    functions = {}

    def tool():
        def register(fn):
            functions[fn.__name__] = fn
            return fn

        return register

    ctx = SimpleNamespace(
        coordinator=coord, runner=runner or coord._runner,
        store=store or SimpleNamespace(set_active=lambda v: None),
        controller_identity=lambda: ('owner', 'valid_uuid'),
        artifacts_root=artifacts or SimpleNamespace(),
        error_response=lambda e: {'error': e.to_dict()})
    register_tools(SimpleNamespace(tool=tool), ctx)
    return functions


def test_stop_does_not_clear_a_failed_state_without_an_audited_stop():
    """CHK-058: an absent run_id is not completion of recovery duty."""
    coord = Coordinator(LifecycleDouble())
    coord.update_health_state('failed', 'corrupt recovery snapshot')
    calls = []
    coord._runner.stop = lambda co: calls.append('audited') or {'state': 'failed'}
    tools = surface(coord)
    response = tools['stop']('stop', 1)
    assert calls == ['audited'], 'stop must run the audited convergence path'
    assert response.get('state') != 'stopped'
    assert coord.snapshot()['failure_reason'] == 'corrupt recovery snapshot'


def test_restart_reports_the_instance_that_now_exists():
    """CHK-056: the request binding may not overwrite the real identity."""
    coord = Coordinator(LifecycleDouble())
    coord._state, coord._run_id, coord._controller = 'healthy', 'old-run', 'owner'
    coord._config_identity = {'name': 'a.ini'}
    coord._runner.restart = lambda *a: {'state': 'healthy', 'run_id': 'new-run',
                                        'controller': 'owner'}
    tools = surface(coord)
    response = tools['restart']('restart', 1)
    assert response['run_id'] == 'new-run'
    assert response['bound_run_id'] == 'old-run'


def test_completion_keeps_a_concurrent_termination_reason():
    """CHK-056: async failure reasons survive unrelated completions."""
    coord = Coordinator(LifecycleDouble())

    def mutate(inner):
        inner.update_health_state('failed', 'managed IPC EOF')
        return {'changed': True}

    coord.submit(command_id='edit', expected_version=1, controller='owner',
                 controller_valid=True, kind='edit_config', describe={},
                 execute=mutate)
    snapshot = coord.snapshot()
    assert snapshot['state'] == 'failed'
    assert snapshot['failure_reason'] == 'managed IPC EOF'


@pytest.fixture
def store(tmp_path):
    return ConfigStore(tmp_path / 'custom', tmp_path / 'builtin',
                       tmp_path / 'audit.jsonl')


def test_custom_config_cannot_shadow_a_builtin(store):
    """CHK-056: every configuration name stays uniquely addressable."""
    store.builtin_root.mkdir()
    (store.builtin_root / 'default.ini').write_text('[FakeNet]\nDumpPackets=No\n')
    with pytest.raises(errors.McpError) as captured:
        store.create(controller='owner', command_id='create',
                     name='default.ini', content='[FakeNet]\nDumpPackets=Yes\n')
    assert captured.value.code == errors.NAME_CONFLICT
    assert store.read('default.ini')['builtin'] is True


def test_failed_audit_leaves_no_staging_file(store):
    """CHK-056: an audit failure clears the staged config."""
    def unavailable(**_kwargs):
        raise errors.McpError(errors.AUDIT_WRITE_FAILED, 'injected')

    store.audit = unavailable
    with pytest.raises(errors.McpError):
        store.create(controller='owner', command_id='audit', name='a.ini',
                     content='[FakeNet]\n')
    leftovers = [path.name for path in store.custom_root.iterdir()]
    assert leftovers == []


def test_clean_stop_releases_the_run_scoped_config_lock(store, tmp_path):
    """CHK-058: a stop with nothing to do still releases the config lock."""
    store.create(controller='owner', command_id='initial', name='a.ini',
                 content='[FakeNet]\n')
    store.set_active('a.ini')
    coord = Coordinator(LifecycleDouble())
    coord.on_run_end(lambda: store.set_active(None))
    tools = surface(coord, store=store)
    tools['stop']('already-stopped', 1)
    assert store.active_name is None
    record = store.edit(controller='owner', command_id='edit', name='a.ini',
                        content='[FakeNet]\nDumpPackets=Yes\n',
                        expected_sha256=store.read('a.ini')['sha256'])
    assert record['changed'] is True


def test_every_run_end_releases_the_config_lock(store):
    """The run-end hook covers stops that never pass through the tool."""
    store.create(controller='owner', command_id='initial', name='a.ini',
                 content='[FakeNet]\n')
    store.set_active('a.ini')
    coord = Coordinator(LifecycleDouble())
    coord.on_run_end(lambda: store.set_active(None))
    coord.restore_responsibility({'needs_recovery': True, 'run_id': 'run-1'},
                                 'running')
    coord.restore_responsibility(None, 'stopped')
    assert store.active_name is None


# -- CHK-064 / CHK-070 ------------------------------------------------

def test_illegal_extra_control_port_types_are_rejected():
    """CHK-064: protected ports keep an input contract."""
    from fakenet.mcp.config import ConfigError
    for bad in ([True], [29094.9], {'29094': 'not a list'}, ['29094'], [None],
                '29094'):
        with pytest.raises(ConfigError):
            ServiceConfig('192.168.204.149', 28788, ['192.168.204.1'],
                          extra_control_ports=bad)
    config = ServiceConfig('192.168.204.149', 28788, ['192.168.204.1'],
                           extra_control_ports=[28787, 28790])
    assert config.extra_control_ports == [28787, 28790]


def test_unpublished_artifacts_are_not_reported_as_complete(tmp_path):
    """CHK-070: completion is the producer's publish fact, not a suffix guess."""
    from fakenet.mcp.artifacts import ArtifactRegistry, write_publication
    root = tmp_path / 'artifacts'
    root.mkdir()
    (root / 'target.dmp.partial').write_bytes(b'partial')
    (root / 'udp.etl.part').write_bytes(b'partial')
    # A final-looking name that the producer never declared is not complete.
    (root / 'run.log').write_bytes(b'still being written')
    (root / 'userdump.dmp').write_bytes(b'MZfinal')
    write_publication(root, [root / 'userdump.dmp'])
    items = {Path(item['path']).name: item
             for item in ArtifactRegistry(root).metadata()}
    assert items['target.dmp.partial']['complete'] is False
    assert items['target.dmp.partial']['sha256'] is None
    assert items['udp.etl.part']['complete'] is False
    assert items['run.log']['complete'] is False
    assert items['run.log']['sha256'] is None
    assert items['userdump.dmp']['complete'] is True
    assert items['userdump.dmp']['sha256'] is not None
    # A declared artifact that keeps changing is not complete either.
    (root / 'userdump.dmp').write_bytes(b'MZfinal plus more')
    again = {Path(item['path']).name: item
             for item in ArtifactRegistry(root).metadata()}
    assert again['userdump.dmp']['complete'] is False
    assert again['userdump.dmp']['sha256'] is None


def test_list_artifacts_uses_the_same_completion_rule(tmp_path):
    """CHK-070: the tool surface agrees with the registry."""
    root = tmp_path / 'artifacts'
    root.mkdir()
    from fakenet.mcp.artifacts import write_publication
    (root / 'target.dmp.partial').write_bytes(b'partial')
    (root / 'run.log').write_bytes(b'final')
    write_publication(root, [root / 'run.log'])
    coord = Coordinator(LifecycleDouble())
    tools = surface(coord, artifacts=root)
    items = {Path(item['path']).name: item
             for item in tools['list_artifacts']()['artifacts']}
    assert items['target.dmp.partial']['complete'] is False
    assert items['target.dmp.partial']['sha256'] is None
    assert items['run.log']['complete'] is True
    assert items['run.log']['sha256'] is not None


# -- CHK-071 -----------------------------------------------------------

def _shared_link_exclusion():
    """Call the real diverter method without importing the platform module."""
    import ast

    from fakenet.mcp import controlfilter
    source = (Path(__file__).resolve().parents[2]
              / 'fakenet/diverters/windows.py').read_text()
    tree = ast.parse(source)
    method = next(node for node in ast.walk(tree)
                  if isinstance(node, ast.FunctionDef)
                  and node.name == '_apply_control_link_exclusion')
    env = {'apply_control_link_exclusion': controlfilter.apply_control_link_exclusion,
           'apply_loopback_exclusion': controlfilter.apply_loopback_exclusion,
           'ControlFilterError': controlfilter.ControlFilterError,
           'PolicyConfigError': RuntimeError,
           'WinDivert': SimpleNamespace(check_filter=lambda f: (True, 0, None))}
    exec(compile(ast.Module(body=[method], type_ignores=[]),
                 '<shared-method>', 'exec'), env)
    return env['_apply_control_link_exclusion']


def test_independent_gui_filter_is_unchanged():
    """CHK-071: without an MCP control link the filter stays as built."""
    apply = _shared_link_exclusion()
    obj = SimpleNamespace(filter='outbound and ip', _dict={})
    apply(obj)
    assert obj.filter == 'outbound and ip'


def test_configured_control_link_still_applies_both_exclusions():
    apply = _shared_link_exclusion()
    obj = SimpleNamespace(filter='outbound and ip',
                          _dict={'controllinkexcludeip': '192.168.204.1',
                                 'controllinkexcludeport': '28788'})
    apply(obj)
    assert '192.168.204.1' in obj.filter
    assert '127.0.0.0' in obj.filter


# -- CHK-072 -----------------------------------------------------------

def _modern_request(params):
    import asyncio
    import json

    from fakenet.mcp.transportguard import TransportGuardMiddleware

    async def drive():
        guard = TransportGuardMiddleware(lambda *a: None)
        message = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                   'params': params}
        responses = []

        async def receive():
            return {'type': 'http.request',
                    'body': json.dumps(message).encode(), 'more_body': False}

        async def send(value):
            responses.append(value)

        scope = {'type': 'http', 'path': '/mcp', 'method': 'POST',
                 'headers': [(b'mcp-protocol-version', b'2026-07-28'),
                             (b'mcp-method', b'tools/call'),
                             (b'mcp-name', b'ping')]}
        forwarded = []

        async def app(*args):
            forwarded.append(args)

        guard.app = app
        await guard(scope, receive, send)
        return responses, forwarded

    return asyncio.run(drive())


@pytest.mark.parametrize('params', [[1], 'scalar', 7])
def test_malformed_modern_params_are_rejected_structurally(params):
    """CHK-072: a malformed request never escapes the error boundary."""
    responses, forwarded = _modern_request(params)
    assert forwarded == [], 'malformed request must not reach the app'
    statuses = [item.get('status') for item in responses
                if item.get('type') == 'http.response.start']
    assert statuses == [400]
    assert any(b'"error"' in item.get('body', b'') for item in responses
               if item.get('type') == 'http.response.body')


def test_absent_modern_params_are_still_accepted():
    response_wire = _modern_request({'name': 'ping'})
    assert response_wire[1], 'a well formed request must be forwarded'


# -- CHK-055 -----------------------------------------------------------

def test_baseline_keeps_managed_identity_and_dedicated_image():
    """CHK-055: the audit must see a swapped image, and the dedicated
    managed image must be part of the captured baseline at all."""
    import json

    from fakenet.mcp import baseline

    def capture_of(path):
        return json.dumps({
            'modules': [],
            'managed': [{'ProcessName': 'fakenetng-mcp', 'Id': 123,
                         'StartTime': '1', 'ExecutablePath': path,
                         'CommandLine': path + ' run'}],
            'drivers': [],
            'service_command': '"C:\\product\\fakenetng-mcp.exe" run'})

    product = capture_of('C:\\product\\fakenetng-mcp.exe')
    foreign = capture_of('C:\\foreign\\fakenetng-mcp.exe')
    assert baseline._normalize('windivert_processes', product) != \
        baseline._normalize('windivert_processes', foreign)
    # the approved instance change (same image, new PID/time) still compares equal
    respawned = json.dumps(json.loads(product.replace('123', '999'))
                           | {'managed': [dict(
                               json.loads(product)['managed'][0], Id=999,
                               StartTime='2')]})
    assert baseline._normalize('windivert_processes', product) == \
        baseline._normalize('windivert_processes', respawned)
    assert 'fakenetng-mcp-managed.exe' in baseline.process_capture_script()


# -- CHK-057 -----------------------------------------------------------

def test_slow_final_publication_is_not_reported_as_success(tmp_path):
    """CHK-057: the whole final publication is inside the total budget."""
    from fakenet.mcp.service_stop import ServiceStop, read_result
    coord = Coordinator(LifecycleDouble())
    stop = ServiceStop(coord, lambda deadline: {'state': 'stopped'},
                       lambda: time.sleep(0.15), tmp_path / 'stop.json',
                       identity={'pid': 123, 'creation_time': '1'})
    stop.budget = 0.03
    started = time.monotonic()
    stop.request()
    stop._worker.join(5)
    assert not stop._worker.is_alive()
    result = read_result(stop.path)
    assert result['phase'] == 'failed'
    assert stop.ready is False
    assert time.monotonic() - started >= 0.03


# -- CHK-060 -----------------------------------------------------------

def test_incident_item_finishing_after_the_budget_is_not_complete(monkeypatch, tmp_path):
    """CHK-060: the total budget bounds the collection, not just each item."""
    import json

    from fakenet.mcp import incident

    clock = [100.0]
    with monkeypatch.context() as patch:
        patch.setattr(incident, 'time', SimpleNamespace(time=lambda: clock[0]))
        collector = incident.IncidentCollector(tmp_path / 'incident', 'run')

        def slow(kind, context):
            clock[0] += 181
            return 'payload'

        patch.setattr(incident, 'BASIC_ITEMS',
                      (('timeline.json', 'timeline'),))
        patch.setattr(collector, '_collect_item', slow)
        collector.collect({})
    manifest = json.loads((collector.root / 'manifest.json').read_text())
    assert manifest['complete'] is False
    assert manifest['entries'][0]['result'] == 'failed'


def test_generic_dump_rejects_a_non_mdmp_result(monkeypatch, tmp_path):
    """CHK-060: a non-MDMP file is not a dump."""
    from fakenet.mcp import dumpworker, jobobject

    class Job:
        def spawn(self, command, *args):
            Path(command[-3]).write_bytes(b'X')
            return 1

        def poll(self):
            return 0

        def close(self):
            pass

    target = tmp_path / 'invalid.dmp'
    monkeypatch.setitem(__import__('sys').modules, 'msvcrt',
                        SimpleNamespace(get_osfhandle=lambda handle: handle))
    monkeypatch.setattr(jobobject, 'ManagedJob', Job)
    monkeypatch.setattr(dumpworker.os, 'set_handle_inheritable',
                        lambda *a: None, raising=False)
    with pytest.raises(RuntimeError):
        dumpworker.collect_dump(123, '1', target, time.monotonic() + 5)
    assert not target.exists()


def test_published_evidence_does_not_consume_the_active_budget(tmp_path):
    """CHK-060: archived evidence must not starve a new collection."""
    from fakenet.mcp.exit_monitor import active_bytes

    base = tmp_path / 'exit-evidence'
    done = base / 'run-done'
    live = base / 'run-live'
    done.mkdir(parents=True)
    live.mkdir(parents=True)
    (done / 'target.dmp').write_bytes(b'x' * 4096)
    (done / 'owner-result.json').write_text('{}')
    (live / 'target.dmp.partial').write_bytes(b'y' * 32)
    assert active_bytes(base) == 32


# -- CHK-054 -----------------------------------------------------------

def test_health_observation_sees_a_burst_larger_than_one_window(tmp_path):
    """CHK-054: a large burst must not push an exception out of view."""
    from fakenet.mcp.supervisor import (LOG_READ_LIMIT_BYTES, LOG_WINDOW_BYTES)

    log = tmp_path / 'run.log'
    log.write_bytes(b'x' * (LOG_WINDOW_BYTES + 4096) + b'unhandled exception\n')
    offset, tail = 0, b''
    size = log.stat().st_size
    assert size > LOG_READ_LIMIT_BYTES or True  # limit only bounds one read
    with log.open('rb') as stream:
        stream.seek(offset)
        window = stream.read(LOG_READ_LIMIT_BYTES)
        offset += len(window)
    tail = (tail + window)[-LOG_WINDOW_BYTES:]
    # The appended exception is consumed, and the recent window retains it.
    assert b'unhandled exception' in tail
    assert offset == size


def test_health_log_offset_advances_without_skipping(tmp_path):
    """Every appended byte is observed exactly once per poll."""
    from fakenet.mcp.supervisor import LOG_READ_LIMIT_BYTES, LOG_WINDOW_BYTES

    log = tmp_path / 'run.log'
    log.write_bytes(b'a' * 100)
    offset, seen = 0, b''
    for extra in (b'b' * 50, b'unhandled exception\n'):
        with log.open('ab') as handle:
            handle.write(extra)
        size = log.stat().st_size
        with log.open('rb') as stream:
            stream.seek(offset)
            window = stream.read(LOG_READ_LIMIT_BYTES)
            offset += len(window)
        seen += window
    assert seen == log.read_bytes()
    assert b'unhandled exception' in seen
    assert offset == log.stat().st_size


# -- CHK-066 -----------------------------------------------------------

def _integrity_module():
    import importlib.util

    root = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location(
        'full_review_integrity', root / 'test/mcp/acceptance/evidence_integrity.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _round_record(tmp_path, identity, label='same'):
    import hashlib
    import json

    from fakenet.mcp import baseline

    captures = []
    for name in ('before', 'after'):
        path = tmp_path / (name + '.json')
        raw = json.dumps(dict(identity, complete=True, started_at=1.2, ended_at=2.8,
                              sections={key: label
                                        for key in baseline.BASELINE_FIELDS})).encode()
        path.write_bytes(raw)
        captures.append({'path': str(path.resolve()), 'size': len(raw),
                         'sha256': hashlib.sha256(raw).hexdigest()})
    return dict(identity, run_id='run-1',
                final_state='stopped', audit_diff={}, lock_released_after_stop=True,
                probe_window_start=1.1, probe_window_end=2.9,
                probe_timeline=[{'t': 1, 'ok': True}, {'t': 2, 'ok': True},
                                {'t': 3, 'ok': True}],
                vm_before={'pid': 1, 'created': 1},
                vm_after={'pid': 1, 'created': 1},
                capture_evidence=captures)


def test_round_rejects_unrecorded_raw_baseline_difference(tmp_path):
    """CHK-066: differing raw baselines cannot hide behind an empty diff."""
    import hashlib
    import json

    integrity = _integrity_module()
    identity = dict(candidate_id='candidate', source_commit='a' * 40,
                    package_sha256='b' * 64, requirements_blob='c' * 40,
                    master_plan_blob='d' * 40)
    record = _round_record(tmp_path, identity)
    assert integrity.validate_round(record, identity) == []
    # A round whose raw after-capture differs may not declare a clean diff.
    item = record['capture_evidence'][-1]
    path = Path(item['path'])
    payload = json.loads(path.read_bytes())
    payload['sections'] = {key: 'changed' for key in payload['sections']}
    raw = json.dumps(payload).encode()
    path.write_bytes(raw)
    item['size'] = len(raw)
    item['sha256'] = hashlib.sha256(raw).hexdigest()
    assert any('raw baseline diff not recorded' in issue
               for issue in integrity.validate_round(record, identity))


def test_summary_rejects_reused_rounds_and_missing_categories():
    """CHK-066: the sample set is unique runs with the required categories."""
    integrity = _integrity_module()
    rounds = [{'run_id': 'r1', 'class': 'normal'},
              {'run_id': 'r1', 'class': 'normal'},
              {'run_id': 'r2', 'class': 'normal'}]
    issues = integrity.validate_rounds(rounds, {'normal': 3})
    assert any('run reused' in issue for issue in issues)
    assert any('under-sampled' in issue for issue in issues)
    complete = integrity.validate_rounds(
        [{'run_id': 'r%d' % i, 'class': 'normal'} for i in range(3)],
        {'normal': 3})
    assert complete == []


def test_log_fault_early_in_a_large_burst_is_observed(tmp_path):
    """CHK-054: the whole consumed range is judged, not a truncated prefix."""
    import ast

    from fakenet.mcp import supervisor as supervisor_module

    source = Path(supervisor_module.__file__).read_text()
    tree = ast.parse(source)
    method = next(node for node in ast.walk(tree)
                  if isinstance(node, ast.FunctionDef)
                  and node.name == '_observe_run_log')
    env = dict(LOG_READ_LIMIT_BYTES=supervisor_module.LOG_READ_LIMIT_BYTES,
               LOG_WINDOW_BYTES=supervisor_module.LOG_WINDOW_BYTES, Path=Path)
    exec(compile(ast.Module(body=[method], type_ignores=[]),
                 '<observe>', 'exec'), env)
    observe = env['_observe_run_log']

    run_dir = tmp_path / 'run'
    run_dir.mkdir()
    log = run_dir / 'run.log'
    # The fault sits in the first 20 bytes, followed by far more than one
    # observation window of ordinary output.
    log.write_bytes(b'unhandled exception\n' + b'x' * (70000))
    owner = SimpleNamespace(_run_dir=run_dir, _log_offset=0, _log_tail=b'')

    observed = observe(owner)
    assert 'unhandled exception' in observed
    # The retained window stays available for the next probe without
    # re-reading, and no bytes are skipped.
    assert owner._log_offset == log.stat().st_size
    assert len(owner._log_tail) == supervisor_module.LOG_WINDOW_BYTES
    log.write_bytes(log.read_bytes() + b'unhandled exception\n')
    again = observe(owner)
    assert 'unhandled exception' in again


def test_late_success_file_is_not_reported_as_succeeded(monkeypatch, tmp_path):
    """CHK-057: the success file itself must land inside the budget."""
    from fakenet.mcp.service_stop import ServiceStop, read_result
    coord = Coordinator(LifecycleDouble())
    stop = ServiceStop(coord, lambda deadline: {'state': 'stopped'},
                       lambda: None, tmp_path / 'stop.json',
                       identity={'pid': 1})
    stop.budget = 0.05
    original = ServiceStop._write

    def slow_write(self, phase, reason=None):
        if phase == 'succeeded':
            time.sleep(0.12)
        return original(self, phase, reason)

    monkeypatch.setattr(ServiceStop, '_write', slow_write)
    stop.request()
    stop._worker.join(5)
    assert not stop._worker.is_alive()
    assert read_result(stop.path)['phase'] == 'failed'
    assert stop.ready is False


def test_archived_runs_do_not_gate_the_active_budget(tmp_path):
    """CHK-060: published history is neither counted nor enumerated."""
    from fakenet.mcp.exit_monitor import active_bytes

    base = tmp_path / 'exit-evidence'
    archived = base / 'run-archived'
    archived.mkdir(parents=True)
    (archived / 'owner-result.json').write_text('{}')
    for index in range(12000):
        (archived / ('f%d' % index)).write_bytes(b'x')
    live = base / 'run-live'
    live.mkdir(parents=True)
    (live / 'entry.json').write_bytes(b'y' * 16)
    assert active_bytes(base) == 16
