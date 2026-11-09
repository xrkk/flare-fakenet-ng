"""Sanitized reproduction of the 2026-11-05 recovery audit, without VM mutation."""
import copy
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from fakenet.mcp import baseline as module, reboot_recovery as recovery
from fakenet.mcp.coordination import Coordinator
from fakenet.mcp.endpoint_attribution import foreign_udp_owner_changes
from fakenet.mcp.service_stop import ServiceStop, read_result
from fakenet.mcp.snapshot import StateSnapshot
from fakenet.mcp.supervisor import RealSupervisor

spec = importlib.util.spec_from_file_location(
    'deadlock_fixtures', Path(__file__).with_name('test_endpoint_attribution.py'))
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)


def case():
    """PID 4 TCP stays present; native birth retains digits missing from CIM."""
    base, sample, proof = fixtures.foreign_case()
    base['observation_windows']['listen_ports'] = {
        'start_ns': 1793597717610684500, 'end_ns': 1793597724956993200}
    sample['observation_windows']['listen_ports'] = {
        'start_ns': 1793885040061873900, 'end_ns': 1793885047744147100}
    proof['start']['time_ns'] = base['observation_windows']['listen_ports']['start_ns'] - 10**9
    proof.pop('end')  # The documented incomplete observation uses start-only proof.
    births = {1740: '134380710533160753', 2096: '134380710318692894',
              7924: '134380710562391532'}
    proof['start']['processes'] = [
        {'ProcessId': pid, 'CreationTime': str(int(birth) // 10 * 10)}
        for pid, birth in births.items()]
    tcp = 'TCP 192.168.204.149:15101 0.0.0.0:0 LISTENING 4\n'
    base['sections']['listen_ports'] = tcp + (
        'UDP 127.0.0.1:64618 *:* 1740\nUDP 0.0.0.0:5353 *:* 2096')
    sample['current']['listen_ports'] = tcp + (
        'UDP 127.0.0.1:60469 *:* 1740\n'
        'UDP 0.0.0.0:5353 *:* 2096\nUDP 0.0.0.0:5353 *:* 7924')
    current = module.CapturedSections(sample['current'])
    current.windows = sample['observation_windows']
    context = fixtures.same_boot_context(current, proof)
    for owner in context['owners']:
        if owner['pid'] in births:
            owner['birth_ticks'] = births[owner['pid']]
    sample['reboot_context'] = context
    return base, sample, proof


def store_case(tmp_path, monkeypatch, base, sample):
    sections = module.CapturedSections(base['sections'])
    sections.windows = base['observation_windows']
    store = module.BaselineStore(tmp_path / 'baselines')
    store.save(base['run_id'], sections)
    current = module.CapturedSections(sample['current'])
    current.windows = sample['observation_windows']
    current.reboot_context = sample['reboot_context']
    fixtures.capture_two_samples(monkeypatch, module, current)
    return store


def observation(proof):
    def incomplete(deadline):
        raise ValueError('endpoint observation is incomplete')
    return SimpleNamespace(start_proof=lambda: proof, audit_proof=incomplete,
                           finish=lambda deadline: {'absent': True})


def test_native_precision_and_shared_udp_recovers_without_rewriting_evidence(tmp_path, monkeypatch):
    base, sample, proof = case()
    original = copy.deepcopy((base, sample, proof))
    store = store_case(tmp_path, monkeypatch, base, sample)
    path = store.root / (base['run_id'] + '.json')
    raw = path.read_bytes()
    assert store.full_audit_diff(base['run_id'], settle_seconds=.02,
                                 observation=observation(proof)) == {}
    assert path.read_bytes() == raw
    assert (base, sample, proof) == original
    audit = [json.loads(row) for row in next((tmp_path/'logs').glob('*.jsonl')).read_text().splitlines()]
    assert all(row['differences']['listen_ports'] for row in audit)
    assert all('15101' in row['current']['listen_ports'] for row in audit)
    decision = json.loads(next((tmp_path/'logs').glob('*.attribution.json')).read_text())
    assert decision['accepted'] and decision['proof_mode'] == 'start-only'
    assert {row['pid'] for row in decision['foreign_owner_samples'][-1]['attributed']} == {1740, 2096, 7924}


@pytest.mark.parametrize('native,cim,expected', [
    ('134380710533160753', '134380710533160750', True),
    ('134380710318692894', '134380710318692890', True),
    ('134380710562391532', '134380710562391530', True),
    ('134380710533160759', '134380710533160750', True),
    ('134380710533160760', '134380710533160750', False),
    ('134380710533160749', '134380710533160750', False),
    ('134380710533160753', '134380710533160753', True),
    ('134380710533160754', '134380710533160753', False),
    ('134380710533160753', '134380710533160700', False),
    ('0', '0', False),
])
def test_cim_microsecond_interval_has_exact_boundaries(native, cim, expected):
    assert recovery.cim_creation_matches(native, cim) is expected


@pytest.mark.parametrize('problem', [
    'missing_tcp', 'unknown_tcp', 'routes', 'dns', 'drivers', 'services', 'collection',
    'unknown_shared_owner', 'managed_shared_owner', 'reused_pid', 'owner_error',
    'owner_dead', 'wrong_boot', 'missing_owner', 'duplicate_row', 'incomplete_end'])
def test_audit_keeps_unknown_residue_and_other_sections_blocked(tmp_path, monkeypatch, problem):
    base, sample, proof = case()
    context = sample['reboot_context']
    if problem == 'missing_tcp':
        sample['current']['listen_ports'] = '\n'.join(sample['current']['listen_ports'].splitlines()[1:])
    elif problem == 'unknown_tcp':
        sample['current']['listen_ports'] += '\nTCP 0.0.0.0:5555 0.0.0.0:0 LISTENING 9999'
    elif problem in ('routes', 'dns', 'drivers', 'services', 'collection'):
        section = {'dns': 'dns_servers', 'drivers': 'windivert_processes',
                   'collection': 'services'}.get(problem, problem)
        sample['current'][section] = module.COLLECTION_FAILED if problem == 'collection' else 'changed'
    elif problem == 'unknown_shared_owner':
        sample['current']['listen_ports'] += '\nUDP 0.0.0.0:5353 *:* 9999'
    elif problem == 'managed_shared_owner':
        base['sections']['windivert_processes'] = sample['current']['windivert_processes'] = json.dumps({'managed': [{'Id': 7924}]})
    elif problem == 'reused_pid': context['owners'][1]['birth_ticks'] = str(int(context['owners'][1]['birth_ticks']) + 10)
    elif problem == 'owner_error': context['owners'][1]['error'] = 'incomplete'
    elif problem == 'owner_dead': context['owners'][1]['alive'] = False
    elif problem == 'missing_owner': context['owners'].pop()
    elif problem == 'wrong_boot': context['boot']['start_ns'] = sample['observation_windows']['listen_ports']['start_ns'] - 1
    elif problem == 'duplicate_row': sample['current']['listen_ports'] += '\n' + sample['current']['listen_ports'].splitlines()[-1]
    elif problem == 'incomplete_end': proof['end'] = {'run_id': base['run_id'], 'complete': False, 'absent': True}
    store = store_case(tmp_path, monkeypatch, base, sample)
    obs = observation(proof)
    if problem == 'incomplete_end':
        obs.audit_proof = lambda deadline: proof
    assert store.full_audit_diff(base['run_id'], settle_seconds=.02, observation=obs)


@pytest.mark.parametrize('first_unknown', [False, True])
def test_every_shared_udp_owner_is_checked_regardless_of_row_order(first_unknown):
    base, sample, proof = case()
    shared = ['UDP 0.0.0.0:5353 *:* 2096', 'UDP 0.0.0.0:5353 *:* 9999']
    if first_unknown:
        shared.reverse()
    sample['current']['listen_ports'] = '\n'.join(shared)
    base['sections']['listen_ports'] = 'UDP 0.0.0.0:5353 *:* 2096'
    assert not foreign_udp_owner_changes(base, sample, proof)['accepted']


@pytest.mark.parametrize('dirty', [False, True])
def test_admin_pre_stop_retains_old_controller_until_audit_passes(tmp_path, monkeypatch, dirty):
    base, sample, proof = case()
    if dirty:
        sample['current']['routes'] = 'unrestored'
    store = store_case(tmp_path, monkeypatch, base, sample)
    audit = store.full_audit_diff
    store.full_audit_diff = lambda run, **kwargs: audit(run, settle_seconds=.02, observation=kwargs['observation'])
    store.compensate = lambda *args: None
    snapshot = StateSnapshot(tmp_path/'state.json')
    marker = dict(run_id=base['run_id'], controller_id='old-controller', state_version=2,
                  command_id='old-start', config_sha256='a'*64,
                  baseline_path=str(store.root/(base['run_id']+'.json')), needs_recovery=True)
    snapshot.write(**marker)
    runner = RealSupervisor(snapshot=snapshot, baseline_store=store)
    runner._endpoint_observation = observation(proof)
    runner._collect_incident = lambda *args, **kwargs: None
    coord = Coordinator(runner)
    coord.restore_responsibility(marker, 'failed', last_run_outcome='failed')
    runner._last_run_outcome = 'failed'
    def converge(deadline):
        return coord.submit(command_id='admin-stop', expected_version=coord.snapshot()['state_version'],
                            controller=coord.controller, controller_valid=True,
                            kind='service_controlled_stop', describe={}, internal=True,
                            execute=lambda c: runner.stop(c, deadline=deadline))
    stop = ServiceStop(coord, converge, lambda: None, tmp_path/'prestop.json', identity={'pid': 1})
    stop.request()
    stop._worker.join(2)
    assert not stop._worker.is_alive()
    assert read_result(stop.path)['phase'] == ('failed' if dirty else 'succeeded')
    assert snapshot.read()[0]['needs_recovery'] is dirty
    assert coord.snapshot()['controller'] == ('old-controller' if dirty else None)
    assert coord.snapshot()['last_run_outcome'] == 'failed'
