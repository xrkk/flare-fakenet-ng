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


def gated_runner(tmp_path):
    root=tmp_path/'suite';root.mkdir();argv=tmp_path/'argv.json';argv.write_text('{}')
    manifest=root/'scenario-manifest.json';manifest.write_text('{"scenarios":[]}')
    preflight=root/'preflight.json';preflight.write_text('{"passed":true}')
    order=[]
    runner=SimpleNamespace(root=root,manifest_path=manifest,preflight_path=preflight,identity=SimpleNamespace(as_dict=lambda:{'candidate':'test'}))
    runner._result_path=lambda sid:root/('result-'+sid+'.json')
    runner._ipc_evidence_mode=lambda enabled:order.append('enable' if enabled else 'disable') or {'enabled':enabled}
    runner._require_preflight=lambda:order.append('current-preflight') or {'passed':True}
    runner._continuation_gate=lambda:order.append('continuation') or {}
    runner._traffic_recheck_issues=lambda result,row:[]
    def run(row,attempt):
        order.append('business:'+row['scenario_id']);v={'state':'pass'};runner._result_path(row['scenario_id']).write_text(json.dumps(v));return v
    runner._run_one=run
    return runner,argv,order


@pytest.mark.parametrize('gate_result',['raise','false','malformed'])
def test_enabled_instance_gate_failure_has_zero_formal_business_and_one_restore(tmp_path,gate_result):
    runner,argv,order=gated_runner(tmp_path)
    def gate(runner,phase,ipc):
        order.append('native:'+phase)
        if phase=='enabled':
            if gate_result=='raise':raise RuntimeError('fresh native originals missing')
            return {'passed':False} if gate_result=='false' else None
        return {'passed':True}
    terminal=batch.run_batch(runner,SimpleNamespace(filter='benign'),argv,'gated',[{'scenario_id':'sst-058'},{'scenario_id':'sst-072'}],{}, {'passed':False,'deferred_until_enabled_instance':True},instance_gate=gate)
    assert not any(x.startswith('business:') for x in order)
    assert order==['enable','native:enabled','disable','native:disabled']
    assert not terminal['passed'] and terminal['not_executed']==['sst-058','sst-072']
    assert (runner.root/'formal-batches/gated/recovery.json').exists()


def test_native_preflight_and_restored_instance_are_required_in_order(tmp_path):
    runner,argv,order=gated_runner(tmp_path)
    def gate(runner,phase,ipc):order.append('native:'+phase);return {'passed':True}
    terminal=batch.run_batch(runner,SimpleNamespace(filter='benign'),argv,'gated',[{'scenario_id':'sst-058'}],{}, {'passed':False,'deferred_until_enabled_instance':True},instance_gate=gate)
    assert terminal['passed']
    assert order==['enable','native:enabled','current-preflight','continuation','business:sst-058','continuation','disable','native:disabled']


def test_unresolved_ipc_enable_does_not_blindly_send_finally_mutation(tmp_path):
    runner,argv,order=gated_runner(tmp_path)
    def ipc(enabled):order.append('enable' if enabled else 'disable');raise RuntimeError('native receipt unresolved')
    runner._ipc_evidence_mode=ipc;runner._ipc_restore_allowed=lambda:False
    terminal=batch.run_batch(runner,SimpleNamespace(filter='benign'),argv,'gated',[{'scenario_id':'sst-058'}],{}, {'passed':True})
    assert order==['enable'] and not terminal['passed']
    assert 'blind restore mutation withheld' in terminal['ipc_evidence']['disabled']['error']


def test_restored_native_failure_cannot_make_formal_batch_pass(tmp_path):
    runner,argv,order=gated_runner(tmp_path)
    def gate(runner,phase,ipc):
        if phase=='disabled':raise RuntimeError('restored native gate failed')
        return {'passed':True}
    terminal=batch.run_batch(runner,SimpleNamespace(filter='benign'),argv,'gated',[{'scenario_id':'sst-058'}],{}, {'passed':True},instance_gate=gate)
    assert not terminal['passed'] and order.count('disable')==1
    assert 'restored native gate failed' in terminal['stop_reason']
