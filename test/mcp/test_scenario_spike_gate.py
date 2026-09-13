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
    gates, calls = [], []
    runner._continuation_gate = lambda: gates.append('gate')
    def execute(case, attempt):
        calls.append(case['scenario_id'])
        return dict(scenario_id=case['scenario_id'], state='fail')
    runner._run_one = execute
    result = runner.run('benign') if entry == 'run' else runner.resume()
    assert result['passed'] is False and calls == [benign[0]['scenario_id']]
    assert len(gates) == (1 if entry == 'resume' else 0)
