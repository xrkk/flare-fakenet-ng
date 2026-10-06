# Copyright 2026 Google LLC
"""get_command_status reconciliation over the real Coordinator cache.

A controllable blocking action runs on its own thread while the query
reconciles: in_progress while accepted (execute counted exactly once),
completed after release, failed with the command's own error (McpError
shape or a safe internal_error summary), unknown outside this process
cache. Queries are side-effect free and identity-gated on both the
current run's controller and the cached record's owner.
"""

import threading

import pytest

from fakenet.mcp.coordination import COMMAND_CACHE_LIMIT, Coordinator
from fakenet.mcp.errors import McpError
from fakenet.mcp.testdouble import LifecycleDouble

OWNER = '11111111-2222-4333-8444-555555555555'
OTHER = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'


def submit_async(coordinator, command_id, execute, owner=OWNER,
                 version=None):
    """Submit on the calling thread; execute runs under the coordinator."""
    return coordinator.submit(
        command_id=command_id,
        expected_version=(coordinator.snapshot()['state_version']
                          if version is None else version),
        controller=owner, controller_valid=True, kind='edit',
        describe={}, execute=execute)


def query(coordinator, command_id, owner=OWNER, valid=True):
    return coordinator.command_status(
        command_id=command_id, controller=owner, controller_valid=valid)


class BlockedAction:
    """A real submitted execute that blocks until released."""

    def __init__(self):
        self.release = threading.Event()
        self.entered = threading.Event()
        self.calls = 0
        self.result = {'changed': True, 'state': 'stopped'}

    def __call__(self, coord):
        self.calls += 1
        self.entered.set()
        assert self.release.wait(timeout=30)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def run_blocked(coordinator, command_id, action):
    outcome = {}

    def worker():
        try:
            outcome['response'] = submit_async(coordinator, command_id,
                                               action)
        except BaseException as exc:  # the failure path re-raises here
            outcome['exception'] = exc

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    assert action.entered.wait(timeout=10)
    return thread, outcome


def test_in_progress_then_completed_with_single_execute():
    coordinator = Coordinator(LifecycleDouble())
    action = BlockedAction()
    thread, outcome = run_blocked(coordinator, 'cmd-block', action)
    try:
        version_before = coordinator.snapshot()['state_version']
        status = query(coordinator, 'cmd-block')
        assert status['status'] == 'in_progress'
        assert status['response']['in_progress'] is True
        assert status['command_error'] is None
        assert status['cache_scope'] == 'process'
        assert status['persistent'] is False
        assert status['cache_epoch'] == coordinator._cache_epoch
        assert status['error'] is None
        assert action.calls == 1
        assert coordinator.snapshot()['state_version'] == version_before
    finally:
        action.release.set()
    thread.join(timeout=10)
    assert 'response' in outcome
    status = query(coordinator, 'cmd-block')
    assert status['status'] == 'completed'
    assert status['response']['changed'] is True
    assert status['response'].get('in_progress') is None
    assert status['command_error'] is None
    assert action.calls == 1


def test_mcperror_failure_reports_original_error_shape():
    coordinator = Coordinator(LifecycleDouble())
    action = BlockedAction()
    action.result = McpError('validation_failed', 'rejected by test')
    thread, outcome = run_blocked(coordinator, 'cmd-mcp', action)
    action.release.set()
    thread.join(timeout=10)
    assert isinstance(outcome.get('exception'), McpError)
    status = query(coordinator, 'cmd-mcp')
    assert status['status'] == 'failed'
    assert status['command_error']['code'] == 'validation_failed'
    assert status['response'] is None
    # failed outranks any stale in_progress placeholder.
    assert status['status'] != 'in_progress'


def test_arbitrary_exception_reports_safe_internal_summary():
    coordinator = Coordinator(LifecycleDouble())
    action = BlockedAction()
    action.result = RuntimeError('secret /var/lib detail')
    thread, _ = run_blocked(coordinator, 'cmd-boom', action)
    action.release.set()
    thread.join(timeout=10)
    status = query(coordinator, 'cmd-boom')
    assert status['status'] == 'failed'
    assert status['command_error']['code'] == 'internal_error'
    assert 'secret' not in str(status['command_error'])
    assert status['command_error'].get('traceback') is None


def test_identity_and_controller_gates():
    coordinator = Coordinator(LifecycleDouble())
    submit_async(coordinator, 'cmd-owned', lambda coord: {'changed': False})
    # Invalid identity never sees the cache.
    with pytest.raises(McpError) as excinfo:
        query(coordinator, 'cmd-owned', valid=False)
    assert excinfo.value.code == 'controller_identity_missing'
    # Another valid controller cannot read the owner's record.
    with pytest.raises(McpError) as excinfo:
        query(coordinator, 'cmd-owned', owner=OTHER)
    assert excinfo.value.code == 'controller_conflict'
    # Invalid command ids are parameter errors.
    for bad in (None, '', 7):
        with pytest.raises(McpError) as excinfo:
            query(coordinator, bad)
        assert excinfo.value.code == 'invalid_request'


def test_run_controller_gate_distinct_from_cache_owner_gate():
    coordinator = Coordinator(LifecycleDouble())
    # OTHER submits a start through the lifecycle double: it becomes the
    # run owner (the double reports a run_id and the controller).
    def start_execute(coord):
        return {'state': 'healthy', 'changed': True,
                'run_id': coord.new_run_id(), 'controller': OTHER}
    submit_async(coordinator, 'cmd-start-other', start_execute, owner=OTHER)
    assert coordinator.snapshot()['controller'] == OTHER
    # The cache owner itself (OTHER) can still query its own command...
    status = query(coordinator, 'cmd-start-other', owner=OTHER)
    assert status['status'] == 'completed'
    # ...but even the record owner is rejected while another run controller
    # owns the run? No — OTHER is the run owner; a THIRD caller is gated by
    # the run-controller check before any cache access.
    THIRD = '99999999-9999-4999-8999-999999999999'
    with pytest.raises(McpError) as excinfo:
        query(coordinator, 'cmd-start-other', owner=THIRD)
    assert excinfo.value.code == 'controller_conflict'


def test_unknown_is_process_scoped_with_no_replay_hint():
    coordinator = Coordinator(LifecycleDouble())
    status = query(coordinator, 'never-submitted')
    assert status['status'] == 'unknown'
    assert status['response'] is None and status['command_error'] is None
    assert 'not in this process cache' in status['unknown_detail']
    text = str(status).lower()
    assert 'did not run' not in text and 'safe to replay' not in text


def test_lru_eviction_and_forget_commands_make_records_unknown():
    coordinator = Coordinator(LifecycleDouble())
    submit_async(coordinator, 'cmd-old', lambda coord: {'changed': False})
    assert query(coordinator, 'cmd-old')['status'] == 'completed'
    # Repeated queries must not refresh the LRU position: after enough
    # newer completions the old record still evicts.
    for index in range(COMMAND_CACHE_LIMIT):
        submit_async(coordinator, 'cmd-%03d' % index,
                     lambda coord: {'changed': False})
    assert query(coordinator, 'cmd-old')['status'] == 'unknown'
    # forget_commands simulates restart semantics: everything unknown.
    submit_async(coordinator, 'cmd-fresh', lambda coord: {'changed': False})
    coordinator.forget_commands()
    assert query(coordinator, 'cmd-fresh')['status'] == 'unknown'


def test_new_coordinator_is_a_new_cache_epoch():
    first = Coordinator(LifecycleDouble())
    submit_async(first, 'cmd-x', lambda coord: {'changed': False})
    second = Coordinator(LifecycleDouble())
    assert first._cache_epoch != second._cache_epoch
    assert query(first, 'cmd-x')['status'] == 'completed'
    assert query(second, 'cmd-x')['status'] == 'unknown'
    assert query(second, 'cmd-x')['cache_epoch'] == second._cache_epoch


def test_query_result_is_isolated_from_cache_and_replay():
    coordinator = Coordinator(LifecycleDouble())
    submit_async(coordinator, 'cmd-iso', lambda coord: {'changed': True})
    first = query(coordinator, 'cmd-iso')
    # Mutate every level of the returned copy: value and nested dict.
    first['response']['changed'] = False
    first['response']['state'] = 'poisoned'
    first['response']['extra'] = {'deep': True}
    second = query(coordinator, 'cmd-iso')
    assert second['response']['changed'] is True
    assert second['response']['state'] == 'stopped'
    assert 'extra' not in second['response']
    # The replayed mutation result is equally untouched.
    replay = submit_async(coordinator, 'cmd-iso', lambda coord: {
        'changed': False}, version=999999)
    assert replay['replayed'] is True
    assert replay['changed'] is True
    assert 'extra' not in replay and replay['state'] == 'stopped'
