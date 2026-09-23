"""Admission must fail before a mutating executor sees unqualified evidence."""
import importlib.util
import json
from pathlib import Path
import sys

import pytest

_SPEC = importlib.util.spec_from_file_location('spike_gate_suite',
    Path(__file__).parent / 'acceptance' / 'scenario_suite.py')
suite = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = suite
_SPEC.loader.exec_module(suite)


def make_suite(tmp_path):
    args = suite.parse_args(['generate', '--candidate-id', 'current',
        '--source-commit', 'a' * 40, '--package-sha256', 'b' * 64,
        '--suite-root', str(tmp_path / 'matrix'), '--stop-on-first-failure'])
    runner = suite.Suite(args)
    runner.generate()
    return runner


@pytest.mark.parametrize('input', [{}, {'passed': True},
    {'schema': 'sst.fault-spike.v1', 'passed': True, 'identity': {'candidate_id': 'old'}},
    {'schema': 'sst.fault-spike.v1', 'passed': True, 'synthetic': True}])
@pytest.mark.parametrize('entry', ['run', 'resume'])
def test_unbound_input_rejected_before_clients_or_mutation(tmp_path, input, entry):
    runner = make_suite(tmp_path)
    spike = tmp_path / 'spike.json'
    spike.write_text(json.dumps(input))
    runner.args.fault_spike_result = str(spike)
    runner.require_clients = lambda: pytest.fail('must reject before touching clients')
    runner._run_one = lambda *a: pytest.fail('unqualified fault dispatched')
    if entry == 'resume':
        case = next(row for row in runner.manifest()['scenarios'] if row['fault_class'])
        path = runner._state_path(case['scenario_id'])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({'phase': 'pending'}))
    with pytest.raises(suite.Blocked, match='Spike'):
        runner.run('fault') if entry == 'run' else runner.resume()


@pytest.mark.parametrize('kind', ['missing-class', 'duplicate-class', 'manifest-tamper', 'escape', 'missing-result'])
def test_structural_or_byte_corruption_is_rejected(tmp_path, kind):
    runner = make_suite(tmp_path)
    root = tmp_path / 'spike'
    root.mkdir()
    manifest = root / 'scenario-manifest.json'
    manifest.write_bytes(runner.manifest_path.read_bytes())
    report = dict(schema='sst.fault-spike.v1', passed=True,
        identity=runner.identity.as_dict(), manifest=suite.file_record(manifest, root),
        five_classes=list(suite.FAULTS), cases=[dict(fault_class=fault) for fault in suite.FAULTS])
    if kind == 'missing-class': report['cases'].pop()
    elif kind == 'duplicate-class': report['cases'][-1]['fault_class'] = suite.FAULTS[0]
    elif kind == 'manifest-tamper': manifest.write_bytes(b'{}')
    elif kind == 'escape': report['manifest']['path'] = '../matrix/scenario-manifest.json'
    path = root / 'fault-spike-result.json'
    path.write_text(json.dumps(report))
    with pytest.raises(suite.Blocked): runner._validate_fault_spike(path)


@pytest.mark.parametrize('entry', ['run', 'resume'])
def test_first_failure_stops_dispatch_without_invoking_next_gate(tmp_path, entry):
    runner = make_suite(tmp_path)
    benign = [row for row in runner.manifest()['scenarios'] if row['fault_class'] is None]
    if entry == 'resume':
        for case in benign[:2]:
            path = runner._state_path(case['scenario_id'])
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(dict(phase='pending', attempt=0)))
    runner.require_clients = runner._require_preflight = lambda: None
    # The dispatch-stop contract under test does not cover batch-level IPC
    # evidence arming; stub the VM interaction it now performs.
    runner._ipc_evidence_mode = lambda enabled: {'enabled': enabled, 'recorded': True}
    gates, calls = [], []
    runner._continuation_gate = lambda: gates.append('gate')
    def execute(case, attempt):
        calls.append(case['scenario_id'])
        return dict(scenario_id=case['scenario_id'], state='fail')
    runner._run_one = execute
    result = runner.run('benign') if entry == 'run' else runner.resume()
    assert result['passed'] is False and calls == [benign[0]['scenario_id']]
    assert len(gates) == (1 if entry == 'resume' else 0)


def test_direct_script_imports_baseline_without_pythonpath(tmp_path):
    """Match direct-file CLI sys.path, then reach the real lazy import seam."""
    import os
    import subprocess
    script = Path(suite.__file__).resolve()
    probe = '''import runpy,sys
from pathlib import Path
p=Path(sys.argv[1])
sys.path[:]=[str(p.parent)]+[x for x in sys.path if x and Path(x).resolve()!=p.parents[3]]
m=runpy.run_path(str(p),run_name='offline_import_probe')
r=object.__new__(m['Suite'])
r._vm_json=lambda *a,**k: ({}, {})
r._capture_sections()
'''
    env = dict(os.environ)
    env.pop('PYTHONPATH', None)
    result = subprocess.run([sys.executable, '-B', '-c', probe, str(script)],
                            cwd=tmp_path, env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize('stage', ['before-enable', 'enable-partial', 'after-enable'])
def test_fault_cleanup_only_after_enable_attempt(tmp_path, stage):
    from types import SimpleNamespace
    runner = make_suite(tmp_path)
    row = next(x for x in runner.manifest()['scenarios'] if x['fault_class'])
    runner.require_clients = lambda: None
    runner._require_preflight = lambda: {'api_ipv4': '1.1.1.1', 'external_dns_server': '8.8.8.8'}
    runner._continuation_gate = lambda: {}
    runner._status = lambda: {'state': 'stopped', 'last_run_outcome': 'failed'}
    runner.service = SimpleNamespace(controller_id='test',
        tool_outcome=lambda *a, **k: {'ok': False})
    def capture():
        if stage == 'before-enable':
            raise RuntimeError('before enable failure')
        return {}, {}
    runner._capture_sections = capture
    runner._section_difference = lambda *a: {}
    toggles = []
    def mode(enabled):
        toggles.append(enabled)
        if not enabled:
            runner._status = lambda: {'state': 'stopped', 'last_run_outcome': None}
        if enabled and stage == 'enable-partial':
            raise RuntimeError('partial enable failure')
        return {'enabled': enabled}
    runner._fault_mode = mode
    # Fail the first interface operation after successful enable.
    runner.service.tool_outcome = lambda *a, **k: {'ok': False, 'value': {}}
    result = runner._run_one(row, 1)
    assert result['state'] == 'fail'
    for item in result['traffic_evidence']['capture_views']:
        assert (runner.root / item['path']).is_file()
    assert result['verdict']['continuous_health'] is True
    assert result['verdict']['fault_oracle'] is False
    assert toggles == ([] if stage == 'before-enable' else [True, False])
    if stage != 'before-enable':
        assert result['fault_evidence']['terminal_status']['last_run_outcome'] == 'failed'
        assert result['recovery']['final_status']['last_run_outcome'] is None


@pytest.mark.parametrize('enabled', [True, False])
def test_fault_restart_waits_for_endpoint_and_stopped(tmp_path, monkeypatch, enabled):
    import urllib.error
    runner = make_suite(tmp_path)
    runner.vm = object()
    runner._vm_json = lambda *a: ({'state': 'Running', 'config_bytes_restored': True,
                                   'environment_restored': True}, {})
    states = iter([urllib.error.URLError(ConnectionRefusedError(111, 'refused')),
                   {'state': 'recovering'},
                   {'state': 'stopped', 'run_id': None, 'controller': None}])
    observed = []
    def status(**kwargs):
        value = next(states)
        observed.append(value)
        if isinstance(value, Exception): raise value
        return value
    runner._status = status
    monkeypatch.setattr(suite.time, 'sleep', lambda _: None)
    result = runner._fault_mode(enabled)
    assert len(observed) == 3
    assert result['endpoint_status']['state'] == 'stopped'


def test_fault_restart_unavailable_is_bounded_failure(tmp_path, monkeypatch):
    import urllib.error
    runner = make_suite(tmp_path)
    runner.vm = object()
    runner._vm_json = lambda *a: ({'state': 'Running'}, {})
    def unavailable(**kwargs): raise urllib.error.URLError('refused')
    runner._status = unavailable
    clock = iter([0, 0, 0, 61])
    monkeypatch.setattr(suite.time, 'monotonic', lambda: next(clock))
    monkeypatch.setattr(suite.time, 'sleep', lambda _: None)
    with pytest.raises(suite.SuiteError, match='endpoint'):
        runner._fault_mode(True)


def test_probe_launch_preserves_parameter_boundaries_and_owns_failure(tmp_path):
    import base64
    import re
    runner = make_suite(tmp_path)
    runner.vm = object()
    row = runner.manifest()['scenarios'][0]
    commands = []
    def command(text, timeout):
        commands.append(text)
        return {'startup_failed': True, 'cleanup_errors': [], 'error': 'probe failed'}, {}
    runner._vm_json = command
    cleanup=[]
    runner._start_kernel_capture=lambda root: {'session_name':'owned'}
    runner._stop_kernel_capture=lambda owned: cleanup.append(owned)
    with pytest.raises(suite.SuiteError, match='probe failed'):
        runner._start_capture_and_probe(r'C:\evidence with spaces', row['config_profile'], 'nonce', 'run-01')
    assert cleanup == [{'session_name':'owned'}]
    text = commands[0]
    encoded = re.search(r"\$encoded='([^']+)'", text).group(1)
    child = base64.b64decode(encoded).decode('utf-16le')
    assert "HoldSeconds=90" in child
    assert "TlsServerName=''" in child and "FnprRole=''" in child
    assert '"expectation":"deny"' in child
    assert '@parameters' in child and 'evidence with spaces' in child
    assert 'Win32_Process' in text and 'probe.stderr' in child
    assert 'if($captureStarted)' in text and 'pktmon stop' in text


def test_guest_attempt_directories_do_not_collide_across_suites(tmp_path):
    first = make_suite(tmp_path / 'first')
    second = make_suite(tmp_path / 'second')
    assert first._guest_scenario_root('sst-001', 1) != second._guest_scenario_root('sst-001', 1)


def test_empty_diagnostic_file_is_bound_and_hashed(tmp_path):
    import hashlib
    runner = make_suite(tmp_path)
    runner.vm = object()
    target = runner.root / 'empty.stdout'
    result = runner._transfer_guest_file(r'C:\empty.stdout', 0, hashlib.sha256(b'').hexdigest(), target)
    assert result['size'] == 0 and target.read_bytes() == b''
