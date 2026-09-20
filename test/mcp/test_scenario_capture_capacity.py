"""Explicit pktmon capture capacity: CLI, validation, real command shape.

The capacity value is a capture setting, not a scenario dimension: the two
values already exercised by the master's capacity contrast (128 default,
1024) become an explicit frozen argv field instead of ad-hoc command string
substitution.  Tests drive the REAL parse_args validation and the REAL
_start_capture_and_probe command construction through a recording fake VM
(offline seam), and the manifest content must stay byte-identical for both
values (generate only, no VM).
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

import pytest

ACCEPT = Path(__file__).parent / 'acceptance'


def _load():
    spec = importlib.util.spec_from_file_location('suite_capacity_test', ACCEPT / 'scenario_suite.py')
    suite = importlib.util.module_from_spec(spec)
    sys.modules['suite_capacity_test'] = suite
    spec.loader.exec_module(suite)
    return suite


suite = _load()

BASE_ARGS = ['generate', '--candidate-id', 'c', '--source-commit', 's',
             '--package-sha256', 'p']


# ---- A01: parse_args accepts exactly the frozen choices -----------------

def test_parse_args_default_is_128():
    args = suite.parse_args(BASE_ARGS)
    assert args.pktmon_file_size_mib == 128


@pytest.mark.parametrize('value', ['128', '1024'])
def test_parse_args_accepts_frozen_choices(value):
    args = suite.parse_args(BASE_ARGS + ['--pktmon-file-size-mib', value])
    assert args.pktmon_file_size_mib == int(value)


@pytest.mark.parametrize('value', ['0', '-1', '256', '12.5', '128;rm', ''])
def test_parse_args_rejects_other_values_before_any_vm(value):
    with pytest.raises(SystemExit):
        suite.parse_args(BASE_ARGS + ['--pktmon-file-size-mib', value])


# ---- A01: direct Namespace construction obeys the same contract ---------

def _namespace(tmp_path, **overrides):
    args = argparse.Namespace(
        suite_root=str(tmp_path), candidate_id='c', source_commit='s',
        package_sha256='p', seed=20260912, count=100,
        target_base_url=None, win10vm_mcp=None, regen_check=False)
    for key, value in overrides.items():
        setattr(args, key, value)
    return args


def test_direct_namespace_defaults_to_128(tmp_path):
    instance = suite.Suite(_namespace(tmp_path))
    assert instance.pktmon_file_size_mib == 128


@pytest.mark.parametrize('bad', [0, -1, 256, 12.5, '128;rm', True, None])
def test_direct_namespace_rejects_bad_values_before_clients(tmp_path, bad):
    with pytest.raises(suite.SuiteError):
        suite.Suite(_namespace(tmp_path, pktmon_file_size_mib=bad))


# ---- A01/A02: real command construction through the recording seam ------

OFFLINE_PROFILE = {
    'bucket': 'default', 'tempo': 'steady', 'variant': 'main', 'interleave': 'none',
    'cadence_ms': 1000, 'connection_window_seconds': 70,
    'probe_target': {'host': '198.51.100.77', 'port': 1337, 'protocol': 'tcp',
                     'process_mode': 'match', 'tls_server_name': '', 'fnpr_role': ''},
    'negative_cases': [], 'probe_cases': [], 'startup_retry_seconds': 70,
}


class LaunchCaptureVM:
    def __init__(self):
        self.commands = []
        self.kernel_stops = 0

    def powershell(self, command, timeout=120):
        self.commands.append(command)
        if 'logman start' in command:
            return {'output': json.dumps({'session_name': 'SST-Kernel-x',
                                          'metadata': 'C:/m.json', 'guest': 'C:/g',
                                          'start_output': ''})}
        if 'pktmon start --capture --comp all' in command:
            raise _LaunchCaptured(self, command)
        if 'logman stop' in command or 'logman query' in command:
            self.kernel_stops += 1
        return {'output': json.dumps({'files': [], 'session_present': False})}


class _LaunchCaptured(Exception):
    def __init__(self, vm, command):
        super().__init__('launch captured')
        self.vm = vm
        self.command = command


@pytest.mark.parametrize('file_size,expected_flag', [(None, '--file-size 128'),
                                                     (128, '--file-size 128'),
                                                     (1024, '--file-size 1024')])
def test_real_command_carries_the_frozen_value(tmp_path, file_size, expected_flag):
    overrides = {} if file_size is None else {'pktmon_file_size_mib': file_size}
    instance = suite.Suite(_namespace(tmp_path, **overrides))
    vm = LaunchCaptureVM()
    instance.vm = vm
    captured = {}
    try:
        instance._start_capture_and_probe('C:/guest', OFFLINE_PROFILE, 'n', 'run-01')
    except _LaunchCaptured as exc:
        captured['command'] = exc.command
    assert captured, 'launch command must be the one that reaches the VM'
    assert ('--file-size ' + str(instance.pktmon_file_size_mib) + '|') in captured['command']
    assert expected_flag + '|' in captured['command']
    # The stale literal 128 never appears when 1024 is requested.
    if instance.pktmon_file_size_mib == 1024:
        assert '--file-size 128' not in captured['command']


def test_capture_return_records_requested_file_size(tmp_path):
    class ReturnVM(LaunchCaptureVM):
        def powershell(self, command, timeout=120):
            self.commands.append(command)
            if 'pktmon start --capture --comp all' in command:
                # minimal success shape for the start call
                return {'output': json.dumps({
                    'guest': 'C:/g/run-01', 'run_label': 'run-01', 'pid': 7,
                    'etl': 'C:/g/run-01/pktmon.etl', 'probe': 'C:/g/run-01/probe.jsonl',
                    'start': 'C:/g/run-01/probe.start', 'case': 'C:/g/run-01/probe.cases',
                    'stop': 'C:/g/run-01/probe.stop', 'pktmon_nic': 'C:/g/run-01/pktmon-nic.json',
                    'probe_creation_ticks': 1, 'stdout': 'C:/o', 'stderr': 'C:/e',
                    'capture_scope': 'all-components',
                    'requested_file_size_mib': 1024,
                    'tempo': 'steady', 'cadence_ms': 1000,
                    'startup_retry_seconds': 70, 'variant': 'main',
                    'probe_target': '{"host":"198.51.100.77","port":1337,"protocol":"tcp"}',
                    'interleave': 'none', 'started': '2026-09-21T00:00:00Z'})}
            return super().powershell(command, timeout)

    instance = suite.Suite(_namespace(tmp_path, pktmon_file_size_mib=1024))
    vm = ReturnVM()
    instance.vm = vm
    capture = instance._start_capture_and_probe('C:/guest', OFFLINE_PROFILE, 'n', 'run-01')
    assert capture['requested_file_size_mib'] == 1024


def test_launch_failure_still_runs_kernel_cleanup(tmp_path):
    instance = suite.Suite(_namespace(tmp_path, pktmon_file_size_mib=1024))
    vm = LaunchCaptureVM()
    instance.vm = vm
    with pytest.raises(Exception):
        instance._start_capture_and_probe('C:/guest', OFFLINE_PROFILE, 'n', 'run-01')
    # The launch VM call failed: the kernel cleanup path still ran.
    assert vm.kernel_stops >= 1


# ---- A03: manifest identity is independent of the capacity value --------

FROZEN_MANIFEST_SHA = '62b3ac46e8ce193765908eb0fd590efa106a888ca8ca8928143ba49abe5787be'


@pytest.mark.parametrize('file_size', [128, 1024])
def test_generate_manifest_identical_for_both_values(tmp_path, file_size):
    instance = suite.Suite(_namespace(tmp_path, pktmon_file_size_mib=file_size))
    instance.generate()
    manifest_bytes = (tmp_path / 'scenario-manifest.json').read_bytes()
    digest = hashlib.sha256(manifest_bytes).hexdigest()
    assert digest == FROZEN_MANIFEST_SHA, digest
    manifest = json.loads(manifest_bytes)
    assert len(manifest['scenarios']) == 100
