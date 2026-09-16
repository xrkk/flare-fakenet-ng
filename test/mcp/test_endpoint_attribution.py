import copy
import ipaddress
import json
from pathlib import Path

import pytest

from fakenet.mcp.endpoint_attribution import (closed_udp_changes, event_ns,
                                              foreign_udp_owner_changes,
                                              restarted_service_udp_changes)
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
    result = closed_udp_changes(*args)
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
    assert not closed_udp_changes(base, sample, proof)['accepted']


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


def dual_case():
    return json.loads((Path(__file__).parent/'fixtures/native_afd_closed_dual_udp.json').read_text(encoding='utf-8'))


def test_native_dual_udp_addition_closed_after_sample_has_complete_proof():
    data = dual_case()
    result = closed_udp_changes(data['baseline'], data['sample'], data['proof'])
    assert result['accepted'], result
    row = result['attributed'][0]
    assert row['direction'] == 'added'
    assert set(row['addresses']) == {'0.0.0.0', '::'}
    assert row['pid'] == 2128 and row['port'] == 56095


@pytest.mark.parametrize('problem', ['not_closed', 'mapped_send_failed', 'competing_bind',
                                    'not_born_after_baseline', 'close_outside_trace'])
def test_dual_projection_requires_unique_bind_success_and_observed_close(problem):
    data = dual_case()
    proof = data['proof']
    if problem == 'not_closed':
        proof['events'] = [e for e in proof['events'] if e['id'] != 1001]
    elif problem == 'mapped_send_failed':
        for e in proof['events']:
            if e['id'] in (1007, 1013) and "<Data Name='EnterExit'>1</Data>" in e['xml']:
                e['xml'] = e['xml'].replace("<Data Name='Status'>0</Data>", "<Data Name='Status'>1</Data>")
    elif problem == 'competing_bind':
        event = next(e for e in proof['events'] if e['id'] == 1030 and
                     "<Data Name='EnterExit'>1</Data>" in e['xml'] and '0xffffb904605879d0' in e['xml'])
        other = copy.deepcopy(event)
        other['xml'] = other['xml'].replace('0xffffb904605879d0', '0xffffb90400000001')
        proof['events'].append(other)
    elif problem == 'not_born_after_baseline':
        data['baseline']['observation_windows']['listen_ports']['end_ns'] = data['sample']['observation_windows']['listen_ports']['start_ns'] - 1
    elif problem == 'close_outside_trace':
        proof['end']['time_ns'] = data['sample']['observation_windows']['listen_ports']['end_ns']
    assert not closed_udp_changes(data['baseline'], data['sample'], proof)['accepted']


def foreign_case():
    run = 'run-foreign-1'
    sections = {k: 'unchanged' for k in BASELINE_FIELDS}
    sections.update(listen_ports='UDP 192.168.204.233:52496 *:* 1624',
                    windivert_processes=json.dumps({'managed': []}))
    ns = lambda text: event_ns('2026-09-13T12:00:' + text + 'Z')
    baseline = {'run_id': run, 'sections': sections,
                'observation_windows': {'listen_ports': {'start_ns': ns('13.0000000'), 'end_ns': ns('13.1000000')}}}
    sample = {'run_id': run, 'current': dict(sections, listen_ports=''),
              'observation_windows': {'listen_ports': {'start_ns': ns('20.0000000'), 'end_ns': ns('20.1000000')}}}
    identities = [{'ProcessId': 1624, 'CreationTime': '134334000000000000'},
                  {'ProcessId': 7296, 'CreationTime': '134334000000000001'}]
    proof = {'run_id': run,
             'start': {'run_id': run, 'time_ns': ns('11.0000000'), 'processes': identities},
             'end': {'run_id': run, 'time_ns': ns('21.0000000'), 'complete': True,
                     'absent': True, 'processes': identities}}
    return baseline, sample, proof


def test_foreign_preexisting_udp_owner_change_is_accepted():
    baseline, sample, proof = foreign_case()
    result = foreign_udp_owner_changes(baseline, sample, proof)
    assert result['accepted'], result
    assert result['attributed'][0]['pid'] == 1624


@pytest.mark.parametrize('problem', ['managed_owner', 'owner_created_during_run',
    'added_foreign_socket', 'non_udp_row', 'missing_owner_identity',
    'other_section_changed', 'incomplete_proof'])
def test_foreign_owner_attribution_fails_closed(problem):
    baseline, sample, proof = foreign_case()
    if problem == 'managed_owner':
        baseline['sections']['windivert_processes'] = json.dumps({'managed': [{'Id': 1624}]})
        sample['current']['windivert_processes'] = baseline['sections']['windivert_processes']
    elif problem == 'owner_created_during_run':
        proof['start']['processes'] = [{'ProcessId': 7296, 'CreationTime': '134334000000000001'}]
    elif problem == 'added_foreign_socket':
        # A socket first owned by a process created during the run is refused.
        baseline['sections']['listen_ports'] = ''
        sample['current']['listen_ports'] = 'UDP 192.168.204.233:53000 *:* 4242'
    elif problem == 'non_udp_row':
        baseline['sections']['listen_ports'] = ('UDP 192.168.204.233:52496 *:* 1624\n'
                                                'TCP 0.0.0.0:55999 0.0.0.0:0 LISTENING 1624')
        sample['current']['listen_ports'] = ''
    elif problem == 'missing_owner_identity':
        baseline['sections']['listen_ports'] = 'UDP 192.168.204.233:52496 *:*'
    elif problem == 'other_section_changed':
        sample['current']['routes'] = 'changed'
    elif problem == 'incomplete_proof':
        proof['end']['complete'] = False
    result = foreign_udp_owner_changes(baseline, sample, proof)
    assert not result['accepted'], result


def test_foreign_preexisting_udp_addition_is_also_environmental():
    baseline, sample, proof = foreign_case()
    baseline['sections']['listen_ports'] = ''
    sample['current']['listen_ports'] = 'UDP 192.168.204.233:53000 *:* 1624'
    result = foreign_udp_owner_changes(baseline, sample, proof)
    assert result['accepted'], result
    assert result['attributed'][0]['direction'] == 'added'


def test_full_audit_accepts_foreign_preexisting_udp_owner(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from fakenet.mcp import baseline as module
    baseline, sample, proof = foreign_case()
    sections = module.CapturedSections(baseline['sections'])
    sections.windows = baseline['observation_windows']
    store = module.BaselineStore(tmp_path / 'baselines')
    store.save(baseline['run_id'], sections)
    current = module.CapturedSections(sample['current'])
    current.windows = sample['observation_windows']
    monkeypatch.setattr(module, 'capture', lambda deadline: current)
    monkeypatch.setattr(module.time, 'sleep', lambda seconds: None)
    observed = SimpleNamespace(audit_proof=lambda deadline: proof)
    result = store.full_audit_diff(baseline['run_id'], settle_seconds=0.02, observation=observed)
    assert result == {}
    decision = json.loads(next((tmp_path/'logs').glob('*.attribution.json')).read_text())
    assert decision['accepted'] is True
    assert decision['foreign_owner_samples']


def test_foreign_owner_survives_recovery_reaudit_after_trace_end():
    baseline, sample, proof = foreign_case()
    # A recovery re-audit samples long after the endpoint trace closed; the
    # baseline window stays inside the proof, so attribution still holds.
    sample['observation_windows']['listen_ports'] = {
        'start_ns': proof['end']['time_ns'] + 3600 * 10**9,
        'end_ns': proof['end']['time_ns'] + 3600 * 10**9 + 10**8}
    result = foreign_udp_owner_changes(baseline, sample, proof)
    assert result['accepted'], result


def test_foreign_owner_requires_baseline_window_inside_proof():
    baseline, sample, proof = foreign_case()
    baseline['observation_windows']['listen_ports'] = {
        'start_ns': proof['start']['time_ns'] - 10**9,
        'end_ns': proof['start']['time_ns']}
    result = foreign_udp_owner_changes(baseline, sample, proof)
    assert not result['accepted']


def test_foreign_owner_accepts_start_only_proof_after_failed_observation():
    baseline, sample, proof = foreign_case()
    start_only = {'run_id': proof['run_id'], 'start': proof['start']}
    result = foreign_udp_owner_changes(baseline, sample, start_only)
    assert result['accepted'], result


def test_foreign_owner_still_refuses_incomplete_end_marker():
    baseline, sample, proof = foreign_case()
    broken = dict(proof, end=dict(proof['end'], complete=False))
    result = foreign_udp_owner_changes(baseline, sample, broken)
    assert not result['accepted']


def test_full_audit_uses_start_only_proof_when_audit_proof_fails(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from fakenet.mcp import baseline as module
    baseline, sample, proof = foreign_case()
    sections = module.CapturedSections(baseline['sections'])
    sections.windows = baseline['observation_windows']
    store = module.BaselineStore(tmp_path / 'baselines')
    store.save(baseline['run_id'], sections)
    current = module.CapturedSections(sample['current'])
    current.windows = sample['observation_windows']
    monkeypatch.setattr(module, 'capture', lambda deadline: current)
    monkeypatch.setattr(module.time, 'sleep', lambda seconds: None)

    def broken_audit_proof(deadline):
        raise ValueError('endpoint observation is incomplete')
    observed = SimpleNamespace(audit_proof=broken_audit_proof,
                               start_proof=lambda: {'run_id': proof['run_id'],
                                                    'start': proof['start']})
    result = store.full_audit_diff(baseline['run_id'], settle_seconds=0.02, observation=observed)
    assert result == {}
    decision = json.loads(next((tmp_path/'logs').glob('*.attribution.json')).read_text())
    assert decision['proof_mode'] == 'start-only'
    assert decision['accepted'] is True


def rehost_case():
    """A Dnscache service-host rebind across a run (discovery100 evidence shape)."""
    run = 'run-rehost-1'
    sections = {k: 'unchanged' for k in BASELINE_FIELDS}
    sections.update(
        listen_ports=('UDP 127.0.0.1:63445 *:* 8464\n'
                      'UDP 192.168.204.233:63444 *:* 8464\n'
                      'UDP [::1]:63443 *:* 8464\n'
                      'UDP [fe80::9787:5bf7:10b3:bec8%11]:63442 *:* 8464'),
        windivert_processes=json.dumps({'managed': []}))
    base = event_ns('2026-09-16T20:56:00.0000000Z')
    ns = lambda second: base + int(float(second) * 10**9)
    baseline = {'run_id': run, 'sections': sections,
                'observation_windows': {'listen_ports': {'start_ns': ns('06.0000000'), 'end_ns': ns('18.0000000')}}}
    sample = {'run_id': run,
              'current': dict(sections,
                              listen_ports=('UDP 127.0.0.1:51383 *:* 2336\n'
                                            'UDP 192.168.204.233:51382 *:* 2336\n'
                                            'UDP [::1]:51381 *:* 2336\n'
                                            'UDP [fe80::9787:5bf7:10b3:bec8%11]:51380 *:* 2336')),
              'observation_windows': {'listen_ports': {'start_ns': ns('31.0000000'), 'end_ns': ns('43.0000000')}}}
    identities = [{'ProcessId': 8464, 'CreationTime': '134340356119962930'}]
    proof = {'run_id': run,
             'start': {'run_id': run, 'time_ns': ns('04.0000000'), 'processes': identities},
             'end': {'run_id': run, 'time_ns': ns('60.0000000'), 'complete': True,
                     'absent': True, 'processes': identities}}
    return baseline, sample, proof


def test_restarted_service_rebind_with_new_host_pid_is_accepted():
    baseline, sample, proof = rehost_case()
    result = restarted_service_udp_changes(baseline, sample, proof,
                                           service_identity=lambda: (2336, True))
    assert result['accepted'], result
    assert result['attributed'][0]['service'] == 'Dnscache'
    assert result['attributed'][0]['previous_host_pid'] == 8464
    assert result['attributed'][0]['current_host_pid'] == 2336
    assert len(result['attributed']) == 8


@pytest.mark.parametrize('problem', ['not_the_service', 'service_stopped',
    'old_host_not_at_start', 'managed_old_owner', 'managed_new_owner',
    'address_set_mismatch', 'non_udp_row', 'other_section', 'removed_only',
    'mixed_new_owners', 'same_host'])
def test_restarted_service_attribution_fails_closed(problem):
    baseline, sample, proof = rehost_case()
    identity = lambda: (2336, True)
    if problem == 'not_the_service':
        identity = lambda: (4242, True)
    elif problem == 'service_stopped':
        identity = lambda: (2336, False)
    elif problem == 'old_host_not_at_start':
        proof['start']['processes'] = [{'ProcessId': 2336, 'CreationTime': '134340356119962930'}]
    elif problem == 'managed_old_owner':
        baseline['sections']['windivert_processes'] = json.dumps({'managed': [{'Id': 8464}]})
    elif problem == 'managed_new_owner':
        baseline['sections']['windivert_processes'] = json.dumps({'managed': [{'Id': 2336}]})
    elif problem == 'address_set_mismatch':
        sample['current']['listen_ports'] = sample['current']['listen_ports'].replace(
            '[fe80::9787:5bf7:10b3:bec8%11]:51380', '[fe80::1]:51380')
    elif problem == 'non_udp_row':
        sample['current']['listen_ports'] = ('TCP 192.168.204.233:139 0.0.0.0:0 LISTENING 4\n' +
                                             sample['current']['listen_ports'])
    elif problem == 'other_section':
        sample['current']['routes'] = 'changed'
    elif problem == 'removed_only':
        sample['current']['listen_ports'] = ''
    elif problem == 'mixed_new_owners':
        sample['current']['listen_ports'] = sample['current']['listen_ports'].replace(
            'UDP [::1]:51381 *:* 2336', 'UDP [::1]:51381 *:* 4242')
    elif problem == 'same_host':
        # Same-host rebind keeps a pre-existing owner; the foreign-owner rule
        # owns that decision and this rule must not double-cover it.
        sample['current']['listen_ports'] = sample['current']['listen_ports'].replace('2336', '8464')
    result = restarted_service_udp_changes(baseline, sample, proof,
                                           service_identity=identity)
    assert not result['accepted'], result


def test_full_audit_accepts_restarted_service_rebind(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from fakenet.mcp import baseline as module
    from fakenet.mcp import endpoint_attribution
    baseline, sample, proof = rehost_case()
    sections = module.CapturedSections(baseline['sections'])
    sections.windows = baseline['observation_windows']
    store = module.BaselineStore(tmp_path / 'baselines')
    store.save(baseline['run_id'], sections)
    current = module.CapturedSections(sample['current'])
    current.windows = sample['observation_windows']
    monkeypatch.setattr(module, 'capture', lambda deadline: current)
    monkeypatch.setattr(module.time, 'sleep', lambda seconds: None)
    monkeypatch.setattr(endpoint_attribution, 'dnscache_host_pid',
                        lambda: (2336, True))
    observed = SimpleNamespace(audit_proof=lambda deadline: proof)
    result = store.full_audit_diff(baseline['run_id'], settle_seconds=0.02, observation=observed)
    assert result == {}
    decision = json.loads(next((tmp_path/'logs').glob('*.attribution.json')).read_text())
    assert decision['accepted'] is True
    assert decision['restarted_service_samples']
    assert all(row['accepted'] for row in decision['restarted_service_samples'])


def test_rfc5737_documentation_targets_are_valid_original_redirects():
    from fakenet.diverters.processredirect import _global_ipv4
    assert _global_ipv4('198.51.100.77') == '198.51.100.77'
    assert _global_ipv4('192.0.2.1') == '192.0.2.1'
    assert _global_ipv4('203.0.113.9') == '203.0.113.9'
    assert _global_ipv4('123.125.246.121') == '123.125.246.121'
    assert _global_ipv4('10.0.0.5') is None
    assert _global_ipv4('127.0.0.1') is None
    assert _global_ipv4('0.0.0.0') is None


def test_diagnostic_result_frame_accommodates_full_matrix_artifacts():
    from fakenet.mcp.diagnostic_process import MAX_FRAME
    # Hundreds of acceptance runs with per-file metadata must stay within
    # one diagnostic frame (discovery100-09 exceeded the previous 1 MiB).
    assert MAX_FRAME >= 8 * 1024 * 1024


def test_runtime_baseline_refuses_route_table_without_default_route(tmp_path, monkeypatch):
    from fakenet.mcp import baseline as module
    monkeypatch.setattr(module, '_run', lambda command, timeout=None: 'evidence')
    store = module.BaselineStore(tmp_path / 'baselines')
    good = {field: 'x' for field in module.BASELINE_FIELDS}
    good['routes'] = 'active routes:\n 0.0.0.0  0.0.0.0  192.168.204.2  192.168.204.233  26\n'
    monkeypatch.setattr(module, 'capture', lambda deadline=None: module.CapturedSections(good))
    store.save('run-guard-1')  # runtime capture accepts a routable snapshot

    dipped = dict(good, routes='active routes:\n 127.0.0.1  127.0.0.1  on-link  331\n')
    monkeypatch.setattr(module, 'capture', lambda deadline=None: module.CapturedSections(dipped))
    try:
        store.save('run-guard-2')
    except RuntimeError as exc:
        assert 'no default route' in str(exc)
    else:
        raise AssertionError('dip snapshot was accepted')
    assert store.load('run-guard-2') is None
