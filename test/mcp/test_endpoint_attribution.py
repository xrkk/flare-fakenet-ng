import copy
import json
from pathlib import Path

import pytest

from fakenet.mcp.endpoint_attribution import closed_udp_removals, event_ns
from fakenet.mcp.baseline import BASELINE_FIELDS


def case():
    source = json.loads((Path(__file__).parent/'fixtures/native_afd_udp_52623.json').read_text())
    run = source['run_id']
    sections = {k: 'unchanged' for k in BASELINE_FIELDS}
    sections.update(listen_ports='UDP 192.168.204.149:52623 *:* 7916',
                    windivert_processes=json.dumps({'managed': []}))
    ns = lambda text: event_ns('2026-09-10T03:39:' + text + 'Z')
    baseline = {'run_id': run, 'sections': sections,
                'observation_windows': {'listen_ports': {'start_ns': ns('13.0000000'), 'end_ns': ns('13.1000000')}}}
    sample = {'run_id': run, 'current': dict(sections, listen_ports=''),
              'observation_windows': {'listen_ports': {'start_ns': ns('20.0000000'), 'end_ns': ns('20.1000000')}}}
    identities = [{'ProcessId': 7916, 'CreationTime': '134334835921289150'}]
    proof = dict(source, start={'run_id': run, 'time_ns': ns('11.0000000'), 'processes': identities},
                 end={'run_id': run, 'time_ns': ns('21.0000000'), 'complete': True, 'absent': True, 'processes': identities})
    return baseline, sample, proof


def test_complete_native_lifetime_explains_only_removed_udp_and_preserves_raw_input():
    args = case()
    original = copy.deepcopy(args)
    result = closed_udp_removals(*args)
    assert result['accepted'], result
    assert result['attributed'][0]['port'] == 52623
    assert args == original


@pytest.mark.parametrize('problem', ['loss', 'pid_reuse', 'managed', 'missing_window',
    'window_before_bind', 'window_over_close', 'other_section', 'addition', 'missing_close',
    'missing_send_completion', 'duplicate', 'wrong_run', 'failed_capture'])
def test_unknown_or_unrelated_difference_cannot_be_waived(problem):
    base, sample, proof = copy.deepcopy(case())
    if problem == 'loss': proof['end']['complete'] = False
    elif problem == 'pid_reuse': proof['end']['processes'] = [{'ProcessId': 7916, 'CreationTime': '134334845921289150'}]
    elif problem == 'managed': base['sections']['windivert_processes'] = sample['current']['windivert_processes'] = json.dumps({'managed': [{'Id': 7916}]})
    elif problem == 'missing_window': base.pop('observation_windows')
    elif problem == 'window_before_bind': base['observation_windows']['listen_ports']['start_ns'] -= 10**9
    elif problem == 'window_over_close': base['observation_windows']['listen_ports']['end_ns'] += 6*10**9
    elif problem == 'other_section': sample['current']['routes'] = 'changed'
    elif problem == 'addition': sample['current']['listen_ports'] = 'UDP 0.0.0.0:60000 *:* 7916'
    elif problem == 'missing_close': proof['events'] = [e for e in proof['events'] if e['id'] != 1001]
    elif problem == 'missing_send_completion': proof['events'] = [e for e in proof['events'] if not (e['id'] in (1007, 1013) and "<Data Name='EnterExit'>1</Data>" in e['xml'])]
    elif problem == 'duplicate': base['sections']['listen_ports'] += '\n' + base['sections']['listen_ports']
    elif problem == 'wrong_run': sample['run_id'] = 'different'
    elif problem == 'failed_capture': sample['current']['dns_servers'] = '__COLLECTION_FAILED__'
    assert not closed_udp_removals(base, sample, proof)['accepted']


@pytest.mark.parametrize('complete', [True, False])
def test_full_audit_preserves_raw_difference_and_requires_two_complete_proofs(tmp_path, monkeypatch, complete):
    from types import SimpleNamespace
    from fakenet.mcp import baseline as module
    base, sample, proof = case()
    proof['end']['complete'] = complete
    sections = module.CapturedSections(base['sections'])
    sections.windows = base['observation_windows']
    store = module.BaselineStore(tmp_path / 'baselines')
    store.save(base['run_id'], sections)
    current = module.CapturedSections(sample['current'])
    current.windows = sample['observation_windows']
    monkeypatch.setattr(module, 'capture', lambda deadline: current)
    monkeypatch.setattr(module.time, 'sleep', lambda seconds: None)
    observed = SimpleNamespace(audit_proof=lambda deadline: proof)
    result = store.full_audit_diff(base['run_id'], settle_seconds=0.02, observation=observed)
    assert (result == {}) is complete
    log = next((tmp_path/'logs').glob('*.jsonl'))
    rows = [json.loads(x) for x in log.read_text().splitlines()]
    assert len(rows) >= 2
    assert all(row['differences']['listen_ports'] for row in rows)
    assert all(row['current'] == current for row in rows)
    decision = json.loads(log.with_suffix('.attribution.json').read_text())
    assert decision['accepted'] is complete
