# Copyright 2026 Google LLC
"""Regression boundary for a transient native adapter state before start."""

import hashlib
from types import SimpleNamespace

import pytest


def test_native_network_prerequisite_is_checked_before_baseline_marker_or_job(
        tmp_path, monkeypatch):
    """A native no-active-Ethernet observation must not poison a baseline.

    This reaches ``RealSupervisor.start`` through the same ordering used by a
    Windows run.  The observed c208 failure had a successful route command
    but no active adapter in FakeNet's later native check, so the test keeps
    the decision on the existing native prerequisite rather than route text.
    """
    from fakenet.mcp import baseline, configlock, endpoint_observation, supervisor
    from fakenet import fakenet as fakenet_module

    config = tmp_path / 'default.ini'
    config.write_text('[FakeNet]\n', encoding='utf-8')
    config_sha256 = hashlib.sha256(config.read_bytes()).hexdigest()
    events = []

    class Snapshot:
        def read(self):
            return None, False

        def write(self, **marker):
            raise AssertionError('network rejection must not write a marker')

    class Baselines:
        root = tmp_path / 'baselines'

        def save(self, run_id):
            raise AssertionError('network rejection must not save a baseline')

    class ParsedFakeNet:
        def parse_config(self, path):
            self.fakenet_config = {'diverttraffic': 'yes'}
            self.diverter_config = {}

    class Lock:
        def __init__(self, path):
            self.path = path

        def acquire(self):
            events.append('lock-acquired')
            return self

        def release(self):
            events.append('lock-released')

    class Observation:
        def __init__(self, directory, run_id):
            self.directory = directory
            self.run_id = run_id

        def start(self):
            events.append('observer-started')

        def finish(self, deadline=None):
            events.append('observer-finished')
            return {'absent': True}

    class Coordinator:
        current_command_id = 'start-c208-regression'

        def new_run_id(self):
            return 'c2081505-7794-442f-961e-a8560126d5e4'

        def snapshot(self):
            return {'state_version': 11}

        def restore_responsibility(self, *args):
            raise AssertionError('network rejection must not acquire recovery responsibility')

        def update_health_state(self, state, reason):
            events.append(('health', state))

    def native_prerequisite(run_id, parsed, diagnostic_call):
        events.append(('native-prerequisite', run_id))
        raise supervisor.SupervisorStartError(
            'pre-start native network prerequisite unavailable: no active Ethernet')

    monkeypatch.setattr(supervisor, 'os', SimpleNamespace(name='nt'))
    monkeypatch.setattr(fakenet_module, 'Fakenet', ParsedFakeNet)
    monkeypatch.setattr(configlock, 'ActivityLock', Lock)
    monkeypatch.setattr(endpoint_observation, 'EndpointObservation', Observation)
    monkeypatch.setattr(baseline, 'settle_dead_socket_rows', lambda: None)
    # The implementation must call this module-local boundary between starting
    # the observer and saving the baseline.  ``raising=False`` makes the test
    # red against the pre-fix implementation, where the boundary is absent.
    monkeypatch.setattr(supervisor, '_assert_startup_network_ready',
                        native_prerequisite, raising=False)

    runner = supervisor.RealSupervisor(
        snapshot=Snapshot(), baseline_store=Baselines(),
        config_path_resolver=lambda name, builtin: config,
        artifacts_root=tmp_path / 'artifacts')
    runner._ensure_exit_capability = lambda: None

    with pytest.raises(supervisor.SupervisorStartError,
                       match='no active Ethernet'):
        runner.start(Coordinator(), 'controller', {
            'name': 'default.ini', 'builtin': True, 'sha256': config_sha256})

    assert events == [
        'lock-acquired', 'observer-started',
        ('native-prerequisite', 'c2081505-7794-442f-961e-a8560126d5e4'),
        ('health', 'failed'),
        'lock-released', 'observer-finished',
    ]
