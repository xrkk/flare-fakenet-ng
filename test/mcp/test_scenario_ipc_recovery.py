"""Batch IPC evidence recovery responsibility around the real run/resume flow.

Stubs replace only the VM boundary (``_ipc_evidence_mode``, and selective
``replace_json`` disk failures); the tested control flow is the real
``Suite.run``/``Suite.resume``.  Contract: the attempt is registered before
arming, every exit path attempts exactly one controlled disable with an
independent recovery record, scenario execution requires a proven arming,
and ``passed`` requires both scenario success and IPC recovery success.
"""

import importlib.util
import json
from pathlib import Path
import sys

import pytest

PATH = Path(__file__).parent / 'acceptance' / 'scenario_suite.py'
SPEC = importlib.util.spec_from_file_location('scenario_suite_ipc_recovery_module', PATH)
suite = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = suite
SPEC.loader.exec_module(suite)


class Recorder:
    """Builds a Suite stub whose boundaries can fail on demand."""

    def __init__(self, root, command, *, mode_error=None, enabled_write_error=None,
                 disabled_mode_error=None, run_one=None, stop_on_first_failure=True):
        self.runner = suite.Suite.__new__(suite.Suite)
        self.runner.vm = object()
        self.runner.root = root
        self.runner.root.mkdir(parents=True, exist_ok=True)
        self.runner.args = type('Args', (), {'stop_on_first_failure': stop_on_first_failure})()
        self.command = command
        self.order = []
        self.mode_error = mode_error
        self.disabled_mode_error = disabled_mode_error
        self.run_one = run_one or (lambda scenario, attempt: {'state': 'pass'})
        self._real_replace_json = suite.replace_json
        self._enabled_write_error = enabled_write_error
        self.runner._ipc_evidence_mode = self._mode
        self.runner._run_one = self._fake_run_one
        self.runner.manifest = lambda: {'scenarios': [
            {'scenario_id': 'sst-a', 'fault_class': None},
            {'scenario_id': 'sst-b', 'fault_class': None}]}
        self.runner.require_clients = lambda: None
        self.runner._require_preflight = lambda: None
        self.runner._require_fault_spike = lambda: None
        self.runner._continuation_gate = lambda: {'vm': {}}
        self.runner._result_path = (lambda sid: self.runner.root / ('result-' + sid + '.json'))

        def state_path(sid):
            path = self.runner.root / ('state-' + sid + '.json')
            if not path.exists():
                self._real_replace_json(path, {'phase': 'pending', 'attempt': 0})
            return path
        self.runner._state_path = state_path

    def _mode(self, enabled):
        self.order.append('arm' if enabled else 'restore')
        if enabled and self.mode_error is not None:
            raise self.mode_error
        if not enabled and self.disabled_mode_error is not None:
            raise self.disabled_mode_error
        return {'enabled': enabled, 'recorded': True}

    def _fake_run_one(self, scenario, attempt):
        self.order.append('scenario:' + scenario['scenario_id'])
        outcome = self.run_one(scenario, attempt)
        if isinstance(outcome, dict) and outcome.get('state'):
            outcome = dict(outcome, scenario_id=scenario['scenario_id'])
            self._real_replace_json(self.runner._result_path(scenario['scenario_id']), outcome)
        return outcome

    def replace_json(self, path, value):
        if self._enabled_write_error is not None and path.name.endswith('-enabled.json'):
            raise self._enabled_write_error
        return self._real_replace_json(path, value)

    def invoke(self):
        if self.command == 'run':
            return self.runner.run('benign'), 'ipc-evidence-benign-enabled.json', 'ipc-evidence-benign-disabled.json'
        return self.runner.resume(), 'ipc-evidence-resume-enabled.json', 'ipc-evidence-resume-disabled.json'

    def attach(self, monkeypatch):
        monkeypatch.setattr(suite, 'replace_json', self.replace_json)


@pytest.fixture
def roots(tmp_path):
    return tmp_path


@pytest.mark.parametrize('command', ['run', 'resume'])
def test_partial_enable_failure_disables_once_without_scenarios(roots, monkeypatch, command):
    recorder = Recorder(roots / (command + '-enable-fail'), command,
                        mode_error=suite.SuiteError('arm changed state then failed'))
    recorder.attach(monkeypatch)
    result, enabled_name, disabled_name = recorder.invoke()
    assert recorder.order == ['arm', 'restore']
    assert not any(step.startswith('scenario:') for step in recorder.order)
    assert result['passed'] is False
    assert result['ipc_evidence']['attempted'] is True
    assert 'error' in result['ipc_evidence']['enabled']
    assert 'arm changed state then failed' in result['ipc_evidence']['enabled']['error']
    assert (recorder.runner.root / disabled_name).is_file()


@pytest.mark.parametrize('command', ['run', 'resume'])
def test_enabled_record_write_failure_still_disables_and_keeps_both_errors(roots, monkeypatch, command):
    recorder = Recorder(roots / (command + '-write-fail'), command,
                        enabled_write_error=OSError('evidence volume full'),
                        disabled_mode_error=suite.SuiteError('restore failed too'))
    recorder.attach(monkeypatch)
    result, _, disabled_name = recorder.invoke()
    assert recorder.order == ['arm', 'restore']
    assert not any(step.startswith('scenario:') for step in recorder.order)
    ipc = result['ipc_evidence']
    assert result['passed'] is False
    assert ipc['enabled'] == {'enabled': True, 'recorded': True}
    assert 'evidence volume full' in ipc['enabled_write_error']
    assert 'restore failed too' in ipc['disabled']['error']
    assert (recorder.runner.root / disabled_name).is_file()


@pytest.mark.parametrize('command', ['run', 'resume'])
def test_disable_failure_never_reports_passed(roots, monkeypatch, command):
    recorder = Recorder(roots / (command + '-disable-fail'), command,
                        disabled_mode_error=suite.SuiteError('controlled stop failed'))
    recorder.attach(monkeypatch)
    result, enabled_name, disabled_name = recorder.invoke()
    assert recorder.order == ['arm', 'scenario:sst-a', 'scenario:sst-b', 'restore']
    assert result['passed'] is False
    assert 'controlled stop failed' in result['ipc_evidence']['disabled']['error']
    assert (recorder.runner.root / enabled_name).is_file()
    assert (recorder.runner.root / disabled_name).is_file()


@pytest.mark.parametrize('command', ['run', 'resume'])
def test_scenario_exception_propagates_after_single_disable(roots, monkeypatch, command):
    def run_one(scenario, attempt):
        raise suite.Blocked('gate rejected the scene')
    recorder = Recorder(roots / (command + '-scenario-raise'), command, run_one=run_one)
    recorder.attach(monkeypatch)
    with pytest.raises(suite.Blocked):
        recorder.invoke()
    assert recorder.order == ['arm', 'scenario:sst-a', 'restore']
    assert recorder.order.count('restore') == 1
    disabled_name = ('ipc-evidence-benign-disabled.json' if command == 'run'
                     else 'ipc-evidence-resume-disabled.json')
    assert (recorder.runner.root / disabled_name).is_file()


def test_first_scenario_failure_stops_the_next_one(roots, monkeypatch):
    def run_one(scenario, attempt):
        return {'state': 'fail'} if scenario['scenario_id'] == 'sst-a' else {'state': 'pass'}
    recorder = Recorder(roots / 'run-first-fail', 'run', run_one=run_one,
                        stop_on_first_failure=True)
    recorder.attach(monkeypatch)
    result, _, _ = recorder.invoke()
    assert recorder.order == ['arm', 'scenario:sst-a', 'restore']
    assert result['passed'] is False


def test_full_success_still_passes(roots, monkeypatch):
    recorder = Recorder(roots / 'run-ok', 'run')
    recorder.attach(monkeypatch)
    result, enabled_name, disabled_name = recorder.invoke()
    assert recorder.order == ['arm', 'scenario:sst-a', 'scenario:sst-b', 'restore']
    assert result['passed'] is True
    assert result['count'] == 2
    assert (recorder.runner.root / enabled_name).is_file()
    assert (recorder.runner.root / disabled_name).is_file()


def test_ipc_disable_command_is_controlled_stop_only():
    runner = suite.Suite.__new__(suite.Suite)
    runner.vm = object()
    commands = []

    def fake_vm_json(command, timeout):
        commands.append(command)
        armed = 'FAKENETNG_MCP_FAULT_INJECTION=1' in command and 'enabled=$true' in command
        if armed:
            return {'enabled': True, 'backup': 'b', 'state': 'Running'}, 'raw'
        return {'enabled': False, 'backup': 'b', 'environment_restored': True,
                'stop_path': 'controlled', 'state': 'Running'}, 'raw'
    runner._vm_json = fake_vm_json
    runner._status = lambda timeout=30: {'state': 'stopped', 'run_id': None, 'controller': None}
    runner._ipc_evidence_mode(True)
    assert runner._ipc_evidence_mode(False)['enabled'] is False
    disable = commands[-1]
    # The disable path is the controlled product stop: a nonzero exit must
    # fail immediately.  No SCM force, no masking restart after a failed stop.
    assert 'Stop-Service' not in disable
    assert 'scm-forced' not in disable
    assert "if($LASTEXITCODE -ne 0){throw" in disable
    # Exact environment restoration evidence stays part of the same command.
    assert 'Import-Clixml $envbackup' in disable
    assert 'Compare-Object @($saved.values) $current' in disable
    assert 'environment_restored=$same' in disable
