"""The formal one-to-five row scheduler applies the raw recheck per row."""

import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest


DRIVER = Path(__file__).parent / 'acceptance' / 'formal_batch_v3.py'
SPEC = importlib.util.spec_from_file_location('formal_batch_v3_test_module', DRIVER)
batch = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = batch
SPEC.loader.exec_module(batch)


@pytest.mark.parametrize('recheck_error', [False, True])
def test_first_online_pass_raw_recheck_rejects_next_formal_row(tmp_path, recheck_error):
    root = tmp_path / 'suite'
    root.mkdir()
    argv = tmp_path / 'argv.json'
    argv.write_text('{}')
    manifest_path = root / 'manifest.json'
    manifest_path.write_text('{"scenarios":[]}', encoding='utf-8')
    preflight_path = root / 'preflight.json'
    preflight_path.write_text('{"passed":true}', encoding='utf-8')
    order = []
    runner = SimpleNamespace(root=root, manifest_path=manifest_path,
                             preflight_path=preflight_path,
                             identity=SimpleNamespace(as_dict=lambda: {'candidate': 'test'}))
    runner._result_path = lambda sid: root / ('result-' + sid + '.json')
    runner._ipc_evidence_mode = lambda enabled: order.append('arm' if enabled else 'restore') or {'enabled': enabled}
    runner._continuation_gate = lambda: order.append('gate') or {'ok': True}

    def run_one(row, attempt):
        sid = row['scenario_id']
        order.append('scenario:' + sid)
        result = {'scenario_id': sid, 'state': 'pass'}
        runner._result_path(sid).write_text(json.dumps(result), encoding='utf-8')
        return result

    def recheck(result, row):
        order.append('recheck:' + row['scenario_id'])
        if recheck_error:
            raise ValueError('raw evidence unavailable')
        return ['raw traffic disagrees']

    runner._run_one = run_one
    runner._traffic_recheck_issues = recheck
    selected = [{'scenario_id': 'sst-a'}, {'scenario_id': 'sst-b'}]
    terminal = batch.run_batch(runner, SimpleNamespace(filter='benign'), argv,
                               'batch-one', selected, {}, {'passed': True})
    assert order.count('restore') == 1
    assert order[:4] == ['arm', 'gate', 'scenario:sst-a', 'recheck:sst-a']
    assert 'scenario:sst-b' not in order
    assert terminal['passed'] is False
    assert terminal['not_executed'] == ['sst-b']
    assert json.loads(runner._result_path('sst-a').read_text())['state'] == 'pass'
    if recheck_error:
        assert 'raw evidence unavailable' in terminal['stop_reason']
    else:
        assert terminal['events'][0]['traffic_recheck_issues'] == ['raw traffic disagrees']
