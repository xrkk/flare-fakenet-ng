"""Offline calls through the real scenario executor capture boundary."""
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest


SPEC = importlib.util.spec_from_file_location(
    'scenario_owner_test_suite', Path(__file__).parent / 'acceptance/scenario_suite.py')
suite = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = suite
SPEC.loader.exec_module(suite)


class EndTrace(BaseException):
    pass


def executor_trace(tmp_path, interleave):
    args = suite.parse_args(['generate', '--candidate-id', 'c', '--source-commit', 's',
                             '--package-sha256', 'p', '--suite-root', str(tmp_path),
                             '--capture-contract', 'scenario-shared-v2'])
    runner = suite.Suite(args)
    scenario = next(row for row in suite.build_manifest(20260912)['scenarios']
                    if row['scenario_id'] == 'sst-012')
    scenario['config_profile']['interleave'] = interleave
    trace = []
    runner.require_clients = lambda: None
    runner._require_preflight = lambda: {'api_ipv4': '192.168.204.233',
                                          'external_dns_server': '8.8.8.8'}
    runner._continuation_gate = lambda: {}
    runner._capture_sections = lambda: ({}, {})
    runner._prune_scenario_configs = lambda _: {}
    runner._run_auxiliary_cases = lambda *args: None
    runner._release_probe = lambda capture, phase: {'phase': phase, 'released_utc': '2026-09-27T00:00:00Z'}
    version = [2]
    runner._status = lambda: {'state': 'stopped', 'state_version': version[0], 'run_id': None,
                              'controller': None}
    runner._outcome_code = lambda outcome: 'state_conflict'

    def fake_tool(name, args=None, timeout=120):
        stale = name == 'create_config' and str((args or {}).get('name', '')).endswith('-stale')
        if name == 'create_config' and not stale:
            version[0] += 1
        value = ({'state': 'healthy', 'run_id': 'run-01'} if name == 'start' else
                 {'state': 'healthy', 'run_id': 'run-02'} if name == 'restart' else
                 {'sha256': 'a' * 64} if name == 'read_config' else {})
        return {'ok': not stale, 'value': value, 'response': {},
                'sent_arguments': args or {}, 'response_headers': {},
                'error': {'code': 'state_conflict'} if stale else None}

    runner.service = SimpleNamespace(controller_id='owner-test', tool_outcome=fake_tool)

    def start(_guest, _profile, _nonce, label):
        trace.append('start:' + label)
        if label == 'run-02':
            raise EndTrace
        return {'run_label': label, 'pid': 1, 'probe_creation_ticks': 123,
                'probe': 'C:/probe', 'start': 'C:/start', 'stop': 'C:/stop',
                'etl': 'C:/pktmon.etl', 'pktmon_nic': 'C:/pktmon-nic.json',
                'kernel_capture': {}}

    runner._start_capture_and_probe = start
    def shared(_guest, _profile, _nonce, label, owner):
        trace.append('shared-probe:' + label)
        assert owner['run_label'] == 'run-01'
        raise EndTrace
    runner._start_probe_on_shared_capture = shared
    runner._stop_capture_and_probe = lambda capture: (trace.append('stop:' + capture['run_label']) or
                                                       {'files': []})
    if interleave == 'stop-window':
        runner._run_recovery_sections = lambda *args: ({}, {})
        runner._section_difference = lambda *args: {}
        runner._restart_baseline = lambda *args: {}
        def transfer(guest, size, digest, local):
            local.parent.mkdir(parents=True, exist_ok=True)
            local.write_bytes(b'{}')
            return suite.file_record(local, runner.root)
        runner._transfer_guest_file = transfer
        runner._stop_capture_and_probe = lambda capture: (
            trace.append('stop:' + capture['run_label']) or {'files': [
                {'path': 'C:/pktmon-nic.json', 'bytes': 2, 'sha256': 'x'},
                {'path': 'C:/pktmon.txt', 'bytes': 2, 'sha256': 'x'}]})
        suite.pktmon_capture_issues = lambda *args: []
        suite.pktmon_nic_binding = lambda *args: {'component_ids': [1]}
    with pytest.raises(EndTrace):
        result = runner._run_one(scenario, 1)
        pytest.fail('executor returned before second capture: %r %r' % (result['failure'], trace))
    return trace


@pytest.mark.parametrize('interleave', ['restart-window', 'after-healthy'])
def test_restart_chain_has_one_physical_capture_owner(tmp_path, interleave):
    trace = executor_trace(tmp_path, interleave)
    assert trace[:2] == ['start:run-01', 'shared-probe:run-02']
    assert 'start:run-02' not in trace


def test_stop_window_existing_order_remains(tmp_path):
    trace = executor_trace(tmp_path, 'stop-window')
    assert trace.index('stop:run-01') < trace.index('start:run-02')


def test_shared_owner_retains_writer_when_probe_did_not_exit():
    runner = suite.Suite.__new__(suite.Suite)
    runner.vm = object()
    commands = []
    runner._vm_json = lambda command, timeout: (
        commands.append(command) or
        ({'coop': {'cooperative_exit': 'timeout', 'errors': []}}, '{}'))
    runner._stop_kernel_capture = lambda capture: pytest.fail('kernel writer stopped')
    capture = {'physical_owner_id': 'nonce:pktmon', 'pid': 123,
               'probe_creation_ticks': 456, 'probe': 'E:/probe.jsonl',
               'stop': 'E:/probe.stop', 'kernel_capture': {}}
    with pytest.raises(suite.SuiteError, match='did not cooperatively exit'):
        runner._stop_capture_and_probe(capture)
    assert len(commands) == 1
    assert 'pktmon stop' not in commands[0]


def test_unknown_shared_probe_start_retains_both_writers():
    runner = suite.Suite.__new__(suite.Suite)
    runner.vm = object()
    runner.guest_work_root = suite.E_GUEST_WORK_ROOT
    runner.native_clock_diagnostic = False
    runner.identity = SimpleNamespace(candidate_id='candidate')
    runner._start_kernel_capture = lambda root: {'session_name': 'kernel-owned'}
    runner._stop_kernel_capture = lambda capture: pytest.fail('kernel writer stopped')
    runner._vm_json = lambda command, timeout: (_ for _ in ()).throw(
        TimeoutError('unknown launch response'))
    profile = {'bucket': 'B1', 'tempo': 'normal', 'variant': 'v',
               'interleave': 'restart-window', 'cadence_ms': 100,
               'connection_window_seconds': 10,
               'probe_target': {'host': 'test.local', 'port': 80, 'protocol': 'tcp'}}
    owner = {'run_label': 'run-01', 'etl': 'E:/pktmon.etl',
             'pktmon_nic': 'E:/pktmon-nic.json',
             'physical_owner_id': 'nonce:pktmon'}
    with pytest.raises(suite.UnsettledCaptureStart, match='response uncertain'):
        runner._start_probe_on_shared_capture('E:/scenario', profile,
                                              'nonce', 'run-02', owner)


def test_unknown_shared_probe_with_exact_identity_recovers_its_own_writer():
    runner = suite.Suite.__new__(suite.Suite)
    runner.vm = object()
    runner.guest_work_root = suite.E_GUEST_WORK_ROOT
    runner.native_clock_diagnostic = True
    runner.identity = SimpleNamespace(candidate_id='candidate')
    runner._start_kernel_capture = lambda root: {'session_name': 'kernel-owned'}
    runner._vm_json = lambda command, timeout: (_ for _ in ()).throw(
        TimeoutError('unknown launch response'))
    runner._capture_start_snapshot = lambda *args: {
        'identity_match': True,
        'value': {'probe_ready': {'pid': 321, 'creation_ticks': 456},
                  'etl_exists': True, 'pktmon_exit': 0,
                  'pktmon_status': 'Running'}}
    stopped = []
    runner._stop_capture_and_probe = lambda capture: (
        stopped.append(capture) or {'files': []})
    profile = {'bucket': 'B1', 'tempo': 'normal', 'variant': 'v',
               'interleave': 'restart-window', 'cadence_ms': 100,
               'connection_window_seconds': 10,
               'probe_target': {'host': 'test.local', 'port': 80, 'protocol': 'tcp'}}
    owner = {'run_label': 'run-01', 'etl': 'E:/pktmon.etl',
             'pktmon_nic': 'E:/pktmon-nic.json',
             'physical_owner_id': 'nonce:pktmon'}
    with pytest.raises(suite.RecoveredCaptureStart) as recovered:
        runner._start_probe_on_shared_capture('E:/scenario', profile,
                                              'nonce', 'run-02', owner)
    assert len(stopped) == 1
    assert stopped[0]['shared_physical'] is True
    assert stopped[0]['physical_owner_id'] == 'nonce:pktmon'
    assert recovered.value.record['stop'] == {'files': []}


def test_guest_work_root_default_and_e_gate(tmp_path):
    base = ['generate', '--candidate-id', 'c', '--source-commit', 's',
            '--package-sha256', 'p', '--suite-root', str(tmp_path)]
    default = suite.Suite(suite.parse_args(base))
    assert default.guest_work_root == suite.GUEST_ROOT
    assert default._guest_scenario_root('sst-012', 1).startswith(suite.GUEST_ROOT)
    selected = suite.Suite(suite.parse_args(base + [
        '--guest-work-root', suite.E_GUEST_WORK_ROOT]))
    assert selected._guest_scenario_root('sst-012', 1).startswith(
        suite.E_GUEST_WORK_ROOT)
    selected._vm_json = lambda command, timeout: ({
        'computer': 'DESKTOP-3FI41GR', 'root': suite.E_GUEST_WORK_ROOT,
        'c_free': 3 * 2**30, 'e_free': 4 * 2**30,
        'e_drive_type': 3}, command)
    assert selected._guest_work_root_gate()['value']['e_free'] == 4 * 2**30
    selected._vm_json = lambda command, timeout: ({
        'computer': 'DESKTOP-3FI41GR', 'root': suite.E_GUEST_WORK_ROOT,
        'c_free': 1 * 2**30, 'e_free': 4 * 2**30,
        'e_drive_type': 3}, command)
    with pytest.raises(suite.Blocked, match='space gate'):
        selected._guest_work_root_gate()
    with pytest.raises(SystemExit):
        suite.parse_args(base + ['--guest-work-root', r'E:\Wrong'])


def test_kernel_work_root_rejects_collision_and_reparse_before_start():
    runner = suite.Suite.__new__(suite.Suite)
    command = []
    runner._vm_json = lambda body, timeout: (
        command.append(body) or
        ({'session_name': 'owned'}, '{}'))
    runner._start_kernel_capture(r'E:\FakeNet-NG-MCP-test-work\scope\run-01')
    assert len(command) == 1
    assert command[0].index('kernel run root collision') < command[0].index('logman start')
    assert command[0].index('reparse run ancestor') < command[0].index('logman start')


def test_new_root_preflight_freezes_tool_identity(tmp_path):
    args = suite.parse_args(['generate', '--candidate-id', 'c',
        '--source-commit', 's', '--package-sha256', 'p',
        '--suite-root', str(tmp_path), '--capture-contract', 'scenario-shared-v2',
        '--guest-work-root', suite.E_GUEST_WORK_ROOT])
    runner = suite.Suite(args)
    frozen = {'passed': True, 'identity': runner.identity.as_dict(),
              'guest_work_root': suite.E_GUEST_WORK_ROOT,
              'capture_contract': 'scenario-shared-v2',
              'tool_identity': runner._tool_identity(),
              'external_dns_server': '8.8.8.8', 'api_ipv4': '192.168.204.233'}
    runner.preflight_path.parent.mkdir(parents=True, exist_ok=True)
    runner.preflight_path.write_text(json.dumps(frozen))
    assert runner._require_preflight()['tool_identity'] == frozen['tool_identity']
    frozen['tool_identity']['sha256'] = 'wrong'
    runner.preflight_path.write_text(json.dumps(frozen))
    with pytest.raises(suite.Blocked, match='tool source identity'):
        runner._require_preflight()
