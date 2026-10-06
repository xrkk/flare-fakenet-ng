# Copyright 2026 Google LLC
"""wait_status: bounded single-RPC waits over deterministic seams.

The wait loop runs against injected observe/sleep/monotonic seams for
deterministic clock control, plus real-Coordinator cases with genuine
async waiting: health transitions that never bump the version, delayed
accepted mutations, exact AND semantics, timeout-0 single observations,
validation rejections and cancellation stopping observations immediately.
"""

import asyncio
import threading
import time

import pytest

from fakenet.mcp import queries
from fakenet.mcp.coordination import Coordinator
from fakenet.mcp.errors import McpError
from fakenet.mcp.testdouble import LifecycleDouble

OWNER = '11111111-2222-4333-8444-555555555555'


class FakeClock:
    """Deterministic monotonic clock the waiter advances explicitly."""

    def __init__(self):
        self.now = 1000.0
        self.slept = []

    def monotonic(self):
        return self.now

    async def sleep(self, seconds):
        self.slept.append(seconds)
        self.now += seconds


class ObservationScript:
    """observe() replays a scripted snapshot sequence and counts calls."""

    def __init__(self, snapshots):
        self.snapshots = list(snapshots)
        self.calls = 0

    def __call__(self):
        index = min(self.calls, len(self.snapshots) - 1)
        self.calls += 1
        return self.snapshots[index]


def run(coro):
    return asyncio.run(coro)


def test_validation_rejections():
    from fakenet.mcp.queries import InvalidWaitRequest as Bad
    with pytest.raises(Bad):
        queries.validate_wait_request(None, None, 10)
    for bad_states in ([], ['bogus'], 'healthy', [['healthy']],
                       ['healthy', 'nope']):
        with pytest.raises(Bad):
            queries.validate_wait_request(bad_states, None, 10)
    for bad_version in (True, -1, 1.5, '3'):
        with pytest.raises(Bad):
            queries.validate_wait_request(None, bad_version, 10)
    for bad_timeout in (-1, 31, float('nan'), float('inf'), float('-inf'),
                        True, '10'):
        with pytest.raises(Bad):
            queries.validate_wait_request(['healthy'], 1, bad_timeout)
    # Boundary values are all legal.
    assert queries.validate_wait_request(['healthy'], 0, 0) is None
    assert queries.validate_wait_request(['stopped'], None, 30) is None


def test_immediate_match_with_zero_timeout():
    script = ObservationScript([{'state': 'healthy', 'state_version': 4}])
    clock = FakeClock()
    result = run(queries.wait_for_status(
        observe=script, states=['healthy'], timeout_seconds=0,
        sleep=clock.sleep, monotonic=clock.monotonic))
    assert result['matched'] is True and result['timed_out'] is False
    assert result['elapsed_seconds'] == 0.0
    assert script.calls == 1
    assert result['observation']['state_version'] == 4


def test_timeout_zero_observes_once_then_times_out():
    script = ObservationScript([{'state': 'stopped', 'state_version': 4}])
    clock = FakeClock()
    result = run(queries.wait_for_status(
        observe=script, states=['healthy'], timeout_seconds=0,
        sleep=clock.sleep, monotonic=clock.monotonic))
    assert result['matched'] is False and result['timed_out'] is True
    assert script.calls == 1
    assert result['observation']['state'] == 'stopped'


def test_delayed_state_transition_matches_within_budget():
    script = ObservationScript([
        {'state': 'stopped', 'state_version': 4},
        {'state': 'stopped', 'state_version': 4},
        {'state': 'healthy', 'state_version': 4},  # health change, no bump
    ])
    clock = FakeClock()
    result = run(queries.wait_for_status(
        observe=script, states=['healthy'], timeout_seconds=5,
        sleep=clock.sleep, monotonic=clock.monotonic))
    assert result['matched'] is True
    assert script.calls == 3
    assert result['elapsed_seconds'] == pytest.approx(0.2)
    assert clock.slept == [0.1, 0.1]


def test_version_only_wait_ignores_health_changes():
    script = ObservationScript([
        {'state': 'stopped', 'state_version': 4},
        {'state': 'degraded', 'state_version': 4},  # health moved, no bump
        {'state': 'degraded', 'state_version': 5},  # accepted mutation
    ])
    clock = FakeClock()
    result = run(queries.wait_for_status(
        observe=script, after_state_version=4, timeout_seconds=5,
        sleep=clock.sleep, monotonic=clock.monotonic))
    assert result['matched'] is True
    assert result['observation']['state'] == 'degraded'
    assert result['observation']['state_version'] == 5


def test_and_semantics_require_both_conditions():
    script = ObservationScript([
        {'state': 'healthy', 'state_version': 4},  # state ok, version not
        {'state': 'degraded', 'state_version': 5},  # version ok, state not
        {'state': 'healthy', 'state_version': 5},  # both
    ])
    clock = FakeClock()
    result = run(queries.wait_for_status(
        observe=script, states=['healthy'], after_state_version=4,
        timeout_seconds=5, sleep=clock.sleep, monotonic=clock.monotonic))
    assert result['matched'] is True
    assert script.calls == 3


def test_timeout_is_normal_outcome_with_final_observation():
    script = ObservationScript([{'state': 'stopped', 'state_version': 4}])
    clock = FakeClock()
    result = run(queries.wait_for_status(
        observe=script, states=['healthy'], timeout_seconds=0.25,
        sleep=clock.sleep, monotonic=clock.monotonic))
    assert result['matched'] is False and result['timed_out'] is True
    assert result['elapsed_seconds'] == pytest.approx(0.25)
    # The reply carries exactly the last observation used for the decision.
    assert result['observation']['state'] == 'stopped'
    assert script.calls == 4  # observations at t=0, .1, .2, .25(final poll)


def test_cancellation_stops_observations_immediately():
    released = threading.Event()

    def observe():
        # The first observation blocks until the test releases it; the
        # waiter is cancelled while inside this call and must not observe
        # again afterwards.
        released.wait(timeout=10)
        return {'state': 'stopped', 'state_version': 1}

    async def scenario():
        waiter = asyncio.ensure_future(queries.wait_for_status(
            observe=observe, states=['healthy'], timeout_seconds=30))
        await asyncio.sleep(0.05)
        assert not waiter.done()
        waiter.cancel()
        released.set()
        with pytest.raises(asyncio.CancelledError):
            await waiter

    run(scenario())
    # Nothing keeps running after the loop ends: the waiter task completed
    # (cancelled) inside scenario().


def test_real_coordinator_health_wait_without_version_bump():
    coordinator = Coordinator(LifecycleDouble())
    before = coordinator.snapshot()['state_version']

    def flip():
        time.sleep(0.15)
        coordinator.update_health_state('failed', 'fixture transition')

    thread = threading.Thread(target=flip, daemon=True)
    thread.start()
    result = run(queries.wait_for_status(
        observe=coordinator.snapshot, states=['failed'],
        timeout_seconds=5))
    thread.join(timeout=5)
    assert result['matched'] is True
    assert result['observation']['state'] == 'failed'
    assert result['elapsed_seconds'] >= 0.1
    # Health transitions never grow the accepted-mutation version.
    assert coordinator.snapshot()['state_version'] == before


def test_real_coordinator_version_wait_for_delayed_mutation():
    coordinator = Coordinator(LifecycleDouble())
    version_before = coordinator.snapshot()['state_version']

    def mutate():
        time.sleep(0.15)
        coordinator.submit(
            command_id='wait-mut', expected_version=(
                coordinator.snapshot()['state_version']),
            controller=OWNER, controller_valid=True, kind='edit',
            describe={}, execute=lambda coord: {'changed': True})

    thread = threading.Thread(target=mutate, daemon=True)
    thread.start()
    result = run(queries.wait_for_status(
        observe=coordinator.snapshot, after_state_version=version_before,
        timeout_seconds=5))
    thread.join(timeout=5)
    assert result['matched'] is True
    assert result['observation']['state_version'] == version_before + 1
    assert result['elapsed_seconds'] >= 0.1
