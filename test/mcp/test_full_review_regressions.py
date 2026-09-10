# Copyright 2026 Google LLC
"""Regression tests for the full-review counterexamples (CHK-055—070).

Each case is the reviewer's probe with the assertion inverted: it now
requires the contracted behaviour instead of recording the observed
violation.  Sources: Logs/fakenetng-mcp/full-review-26debdd/probes.py and
Logs/fakenetng-mcp/main-review-26debdd/.
"""

import threading
import time
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
