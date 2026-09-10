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
    from fakenet.mcp.artifacts import ArtifactRegistry
    root = tmp_path / 'artifacts'
    root.mkdir()
    (root / 'target.dmp.partial').write_bytes(b'partial')
    (root / 'udp.etl.part').write_bytes(b'partial')
    (root / 'userdump.dmp').write_bytes(b'MZfinal')
    items = {item['path'].rsplit('/', 1)[-1]: item
             for item in ArtifactRegistry(root).metadata()}
    assert items['target.dmp.partial']['complete'] is False
    assert items['target.dmp.partial']['sha256'] is None
    assert items['udp.etl.part']['complete'] is False
    assert items['userdump.dmp']['complete'] is True
    assert items['userdump.dmp']['sha256'] is not None


def test_list_artifacts_uses_the_same_completion_rule(tmp_path):
    """CHK-070: the tool surface agrees with the registry."""
    root = tmp_path / 'artifacts'
    root.mkdir()
    (root / 'target.dmp.partial').write_bytes(b'partial')
    (root / 'run.log').write_bytes(b'final')
    coord = Coordinator(LifecycleDouble())
    tools = surface(coord, artifacts=root)
    items = {item['path'].rsplit('/', 1)[-1]: item
             for item in tools['list_artifacts']()['artifacts']}
    assert items['target.dmp.partial']['complete'] is False
    assert items['target.dmp.partial']['sha256'] is None
    assert items['run.log']['complete'] is True


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
