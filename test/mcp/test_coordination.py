# Copyright 2026 Google LLC
"""Coordinator semantics: serial, versioned, idempotent, identity-gated."""

import threading

import pytest

from fakenet.mcp import errors
from fakenet.mcp.coordination import Coordinator
from fakenet.mcp.testdouble import LifecycleDouble


def make_coord():
    return Coordinator(LifecycleDouble())


def test_identity_required_before_anything():
    coord = make_coord()
    with pytest.raises(errors.McpError) as excinfo:
        coord.submit(command_id='c1', expected_version=1, controller=None,
                     controller_valid=False, kind='start', describe={},
                     execute=lambda c: {'state': 'stopped'})
    assert excinfo.value.code == errors.CONTROLLER_IDENTITY_MISSING


def test_controller_conflict_for_second_controller():
    coord = make_coord()

    def start(c):
        return {'state': 'healthy', 'run_id': 'r1', 'controller': 'A',
                'changed': True}

    coord.submit(command_id='c1', expected_version=1, controller='A',
                 controller_valid=True, kind='start', describe={},
                 execute=start)
    with pytest.raises(errors.McpError) as excinfo:
        coord.submit(command_id='c2', expected_version=2, controller='B',
                     controller_valid=True, kind='stop', describe={},
                     execute=lambda c: {})
    assert excinfo.value.code == errors.CONTROLLER_CONFLICT


def test_replay_same_controller_returns_original():
    coord = make_coord()
    calls = []

    def mutate(c):
        calls.append(1)
        return {'state': 'stopped', 'changed': True}

    first = coord.submit(command_id='cmd-1', expected_version=1,
                         controller='A', controller_valid=True, kind='x',
                         describe={}, execute=mutate)
    second = coord.submit(command_id='cmd-1', expected_version=99,
                          controller='A', controller_valid=True, kind='x',
                          describe={}, execute=mutate)
    assert len(calls) == 1
    assert second['replayed'] is True
    assert second['state_version'] == first['state_version']


def test_replay_other_controller_is_conflict_not_replay():
    coord = make_coord()
    coord.submit(command_id='cmd-1', expected_version=1, controller='A',
                 controller_valid=True, kind='x', describe={},
                 execute=lambda c: {'state': 'stopped', 'changed': True})
    with pytest.raises(errors.McpError) as excinfo:
        coord.submit(command_id='cmd-1', expected_version=2, controller='B',
                     controller_valid=True, kind='x', describe={},
                     execute=lambda c: {})
    assert excinfo.value.code == errors.CONTROLLER_CONFLICT


def test_state_version_mismatch_rejected():
    coord = make_coord()
    with pytest.raises(errors.McpError) as excinfo:
        coord.submit(command_id='c1', expected_version=7, controller='A',
                     controller_valid=True, kind='x', describe={},
                     execute=lambda c: {})
    assert excinfo.value.code == errors.STATE_CONFLICT
    assert excinfo.value.detail['current'] == 1


def test_version_bumps_on_each_accepted_mutation():
    coord = make_coord()
    for index in range(3):
        response = coord.submit(
            command_id='c%d' % index, expected_version=1 + index,
            controller='A', controller_valid=True, kind='x', describe={},
            execute=lambda c: {'state': 'stopped'})
        assert response['state_version'] == 2 + index


def test_forget_commands_simulates_restart():
    coord = make_coord()
    coord.submit(command_id='c1', expected_version=1, controller='A',
                 controller_valid=True, kind='x', describe={},
                 execute=lambda c: {'state': 'stopped'})
    coord.forget_commands()
    # A post-restart retry carries the caller's original (now stale)
    # expectation; with the cache gone it must surface as state_conflict
    # instead of being masked by a replay.
    with pytest.raises(errors.McpError) as excinfo:
        coord.submit(command_id='c1', expected_version=1, controller='A',
                     controller_valid=True, kind='x', describe={},
                     execute=lambda c: {'state': 'stopped'})
    assert excinfo.value.code == errors.STATE_CONFLICT


def test_serial_execution_under_threads():
    coord = make_coord()
    coord.submit(command_id='own', expected_version=1, controller='A',
                 controller_valid=True, kind='start', describe={},
                 execute=lambda c: {'state': 'healthy', 'run_id': 'r1',
                                    'controller': 'A'})
    outcomes = []
    lock = threading.Lock()

    def worker(index):
        try:
            coord.submit(
                command_id='w%d' % index, expected_version=2,
                controller='A', controller_valid=True, kind='x',
                describe={}, execute=lambda c: {'state': 'healthy'})
        except errors.McpError as exc:
            with lock:
                outcomes.append(exc.code)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    # Exactly one thread wins the version race; the rest get state_conflict.
    assert len(outcomes) == len(threads) - 1
    assert outcomes.count(errors.STATE_CONFLICT) == len(outcomes)
    assert coord.snapshot()['state_version'] == 3


def test_no_timers_ownership_persists():
    coord = make_coord()
    coord.submit(command_id='c1', expected_version=1, controller='A',
                 controller_valid=True, kind='start', describe={},
                 execute=lambda c: {'state': 'healthy', 'run_id': 'r1',
                                    'controller': 'A'})
    import time

    time.sleep(0.2)
    with pytest.raises(errors.McpError) as excinfo:
        coord.submit(command_id='c2', expected_version=2, controller='B',
                     controller_valid=True, kind='stop', describe={},
                     execute=lambda c: {})
    assert excinfo.value.code == errors.CONTROLLER_CONFLICT


def test_snapshot_no_lock_inversion_deadlock():
    """Regression (r53 ACC-004-S3 py-spy evidence): coordinator.snapshot
    must not call runner.health_detail under the metadata lock. The stop
    path holds the supervisor (runner) lock across its snapshot call, so
    the old in-lock nesting produced a classic ABBA deadlock - stop held
    the supervisor lock waiting for the metadata lock while a concurrent
    snapshot held the metadata lock waiting for the supervisor lock, and
    every get_status hung forever."""
    import threading

    import fakenet.mcp.coordination as coordination_mod

    entered = threading.Event()  # reader reached health_detail
    release = threading.Event()  # stop path may proceed to its snapshot

    class SupervisedRunner:

        def __init__(self):
            self.lock = threading.RLock()

        def health_detail(self, state):
            entered.set()  # about to take the runner lock
            with self.lock:  # mirrors Supervisor.health_detail
                return {'process_alive': True}

    runner = SupervisedRunner()
    coord = coordination_mod.Coordinator(runner)

    def stop_path():  # supervisor.stop: runner lock held across snapshot
        with runner.lock:
            release.wait(5)
            coord.snapshot()

    def reader_path():  # concurrent read (terminal-failure path)
        coord.snapshot()

    stop_thread = threading.Thread(target=stop_path, daemon=True)
    reader_thread = threading.Thread(target=reader_path, daemon=True)
    stop_thread.start()
    reader_thread.start()
    assert entered.wait(5), 'reader never reached health_detail'
    release.set()
    stop_thread.join(5)
    reader_thread.join(5)
    assert not stop_thread.is_alive() and not reader_thread.is_alive(), \
        'coordinator.snapshot deadlocks against the runner lock'
