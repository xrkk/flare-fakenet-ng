"""Controller acceptance: real parser/merge and facade, mocked OS boundaries."""
import copy
from datetime import datetime, timezone, timedelta
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import pytest
from fakenet.mcp import egress_contract as contract, host_probe, host_merge
from fakenet.mcp import host_stdio, running_observation as observation

def load(name, filename):
    path = Path(__file__).parent / filename
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
sf = load('b04_stdio_fixture', 'test_host_stdio.py')
mf = load('b04_merge_fixture', 'test_host_merge.py')
pf = load('b04_packet_fixture', 'test_running_observation.py')
cf = load('b04_contract_fixture', 'test_egress_contract.py')

def actual_ipv4_result(tmp_path, *, guard=None, drops=0):
    expected = host_probe.expected_steps(random_tcp_port=50001, random_udp_port=50002, nonce='nonce')
    p = mf.probe_result(expected)
    p['instance'] = {'pid': 1, 'creation_ticks': 2, 'script_hash': 'fixed'}
    p['ipv6_exposure'] = guard or cf._loopback_exposure()
    route = {'source': '192.0.2.10', 'interface': '1', 'next_hop': '192.0.2.1'}
    for row in p['steps']:
        definition = expected[row['id']]
        row.update(definition)
        row.update(probe_pid=1, probe_birth_ticks=2, script_hash='fixed', started=pf.stamp(pf.T - 4), ended=pf.stamp(pf.T - 3))
        if definition['family'] == 'ipv6':
            row.update(received='', sent=0, route=None)
        else:
            row['route'] = route
            if definition['kind'] == 'icmp':
                row.update(status='Success', responder=route['source'], remote_endpoint=route['source'])
    p['completed_at'] = pf.stamp(pf.T - 3)
    host, _, receipt, capture = pf.material(tmp_path)
    base = json.loads(Path(receipt['probe']['path']).read_text())
    base['identity'] = dict(mf.IDENTITY)
    receipt['probe'] = pf.ref(tmp_path, 'identity-matched-baseline.json', base)
    if drops:
        capture = pf.pcap(drops=drops)
    report = pf.evaluate(tmp_path, host, p, receipt, capture)
    p['running_observation'] = report
    result = host_merge.build_host_result(command_id='00000000-0000-4000-8000-000000000002', request=mf.REQUEST, guest_result=mf.guest_result(), host_snapshot=host, probe_result=p, expected_map=expected, config={'sample_context': mf.SAMPLE}, channels={'windows_mcp': True, 'fakenet_mcp': True, 'velo_mcp': True}, host_evidence={'path': '/host', 'sha256': 'a' * 64}, probe_evidence={'path': '/probe', 'sha256': 'b' * 64})
    return (result, report)

def test_real_parser_ipv4_only_merge_positive(tmp_path):
    result, report = actual_ipv4_result(tmp_path)
    assert report['common_complete'] is True, report
    assert report['families']['ipv4']['value'] is True, report
    assert report['families']['ipv6']['value'] is None
    assert result['verdict'] == 'pass', result['conclusion']
    assert result['conclusion']['sample_path_qualified'] is True
    assert result['coverage']['families']['ipv4']['outcomes']['pass'] == 15
    assert result['coverage']['families']['ipv6']['outcomes']['unknown'] == 15

def test_actual_ipv4_success_with_ll_remains_unknown(tmp_path):
    facts = cf._loopback_exposure()
    facts['os_map'][0]['type'] = 'Ethernet'
    result, report = actual_ipv4_result(tmp_path, guard=facts)
    assert report['families']['ipv4']['value'] is True
    assert result['coverage']['families']['ipv4']['outcomes']['pass'] == 15
    assert result['scope_guard']['value'] is None
    assert result['verdict'] == 'unknown'
    assert result['conclusion']['sample_path_qualified'] is False

def test_common_capture_loss_cannot_qualify(tmp_path):
    result, report = actual_ipv4_result(tmp_path, drops=1)
    assert report['common_complete'] is False
    assert result['verdict'] != 'pass'

def test_unconfirmed_common_evidence_cannot_qualify_blocked_rows():
    expected = {k: v for k, v in host_probe.expected_steps(bypass_udp=(443,)).items() if k == 'ipv4_udp_443'}
    definition = expected['ipv4_udp_443']
    row = dict(definition, received='', sent=8, send_completed=True, local_endpoint='192.0.2.10:40000', route={'source': '192.0.2.10', 'interface': '1', 'next_hop': '192.0.2.1'}, probe_pid=1, probe_birth_ticks=2, script_hash='fixed')
    probe = {'matrix_run': True, 'steps': [row], 'instance': {'pid': 1, 'creation_ticks': 2, 'script_hash': 'fixed'}, 'running_observation': {'value': None, 'common_complete': False, 'families': {'ipv4': {'value': True}}}}
    assert host_merge._matrix_steps(probe, expected)[0]['outcome'] != 'pass'

def test_missing_required_scope_in_completeness_cannot_qualify():
    plan, observed = contract._base_material()
    observed['verification_completeness'] = {'schema': 'fakenetng.verification-completeness.v1', 'complete': True, 'status': 'complete', 'planned': 30, 'observed': 30, 'missing_steps': [], 'unknown_steps': [], 'failed_steps': []}
    result = contract.evaluate_interception_qualification(plan, observed)
    assert result['sample_path_qualified'] is False

def cache_material(tmp_path, monkeypatch):
    config = sf.config_for(tmp_path)
    source = Path(config['probe_authorization']['source_ref'])
    scope = json.loads(source.read_text())
    scope['actions'].append('passive_observe')
    source.write_text(json.dumps(scope))
    config['probe_authorization']['source_sha256'] = hashlib.sha256(source.read_bytes()).hexdigest()
    binary = tmp_path / 'fixed-benign-capture-binary'
    binary.write_bytes(b'capture-identity-v1')
    capture_id = {'binary': str(binary), 'sha256': hashlib.sha256(binary.read_bytes()).hexdigest()}
    dependencies = {key: pf.ref(tmp_path, key + '.json', {'identity': key}) for key in ['guest_status', 'probe', 'capture']}
    now = datetime.now(timezone.utc)
    receipt = dict(dependencies, schema='fakenetng.egress-visibility.v1', created_at=now.isoformat(), expires_at=(now + timedelta(seconds=60)).isoformat(), probe_template_sha256=host_probe.script_sha256(host_probe.PROBE_TEMPLATE), capture_identity=capture_id)
    calibration = pf.ref(tmp_path, 'calibration.json', receipt)
    config['passive_observation'] = {'enabled': True, 'calibration_ref': calibration}

    class Capture:
        promiscuous = False

        def __init__(self, directory, *args, **kw):
            directory.mkdir(parents=True, exist_ok=True)
            self.path = directory / 'capture.pcapng'
            self.path.write_bytes(b'OS-capture-boundary-mock')

        def start(self):
            pass

        def finish(self):
            return {'complete': True, 'started': 1, 'ended': 2, 'identity': capture_id, 'path': str(self.path), 'sha256': hashlib.sha256(self.path.read_bytes()).hexdigest()}

    def evaluate(*args, **kwargs):
        return {'value': None, 'common_complete': True, 'reason': 'ipv6_path_unknown', 'families': {'ipv4': {'value': True}, 'ipv6': {'value': None}}, 'calibration': {'ref': calibration, 'expires_at': receipt['expires_at'], 'probe_template_sha256': receipt['probe_template_sha256'], 'capture_identity': capture_id}, 'leaks': []}
    monkeypatch.setattr(observation, 'evaluate_capture', evaluate)
    fakenet = sf.FakeFakeNet()
    windows = sf.FakeWindows()
    facade = host_stdio.HostFacade(config, provider=sf.FakeProvider(), fakenet_client=fakenet, windows_client=windows, velo_client=sf.FakeVelo(), capture_factory=Capture)
    first = facade.verify(sf.COMMAND_ID)
    assert first['error'] is None, first.get('error')
    return (facade, first, fakenet, windows, receipt, binary)

@pytest.mark.parametrize('change', ['none', 'expired', 'binary', 'dependency'])
def test_actual_facade_cached_observation_binding(tmp_path, monkeypatch, change):
    facade, first, fakenet, windows, receipt, binary = cache_material(tmp_path, monkeypatch)
    old_calls = fakenet.calls.count('verify_egress')
    if change == 'expired':

        class Future(datetime):

            @classmethod
            def now(cls, tz=None):
                return datetime.now(tz) + timedelta(seconds=120)
        monkeypatch.setattr(host_stdio, 'datetime', Future)
    elif change == 'binary':
        binary.write_bytes(b'capture-identity-v2')
    elif change == 'dependency':
        Path(receipt['probe']['path']).write_bytes(b'changed')
    second = facade.verify(sf.COMMAND_ID)
    assert fakenet.calls.count('verify_egress') == old_calls
    assert windows.positive_flags.count(True) == 1
    if change == 'none':
        assert second['error'] is None, second.get('error')
        assert second['verification_id'] == first['verification_id']
    else:
        assert second['error'] and second['error']['code'] == 'stale_result', second.get('error')

def test_completeness_is_mandatory_in_shared_helper():
    plan, observed = contract._base_material()
    observed.pop('verification_completeness')
    assert not contract.evaluate_interception_qualification(plan, observed)['sample_path_qualified']

def test_acceptance_runner_accepts_real_ipv4_profile_with_unknown_diagnostics(tmp_path):
    runner = load('b04_acceptance_runner', 'acceptance/run_egress_verification.py')
    result, report = actual_ipv4_result(tmp_path)
    result['artifact'] = {'sha256': 'a' * 64}
    assert runner.expectation('normal', result) is True
    broken = copy.deepcopy(result)
    matrix = next((row for row in broken['steps'] if row['id'] == 'ipv4_tcp_80'))
    matrix['id'] = 'unplanned'
    assert runner.expectation('normal', broken) is False

@pytest.mark.parametrize('change', ['schema', 'address_duplicate', 'route_duplicate', 'map_duplicate', 'state_missing', 'too_many', 'field_type'])
def test_raw_exposure_cannot_hide_missing_or_ambiguous_facts(change):
    facts = cf._loopback_exposure()
    if change == 'schema':
        facts['schema'] = 'old'
    elif change == 'address_duplicate':
        facts['addresses'].append(dict(facts['addresses'][0]))
    elif change == 'route_duplicate':
        facts['routes'].append(dict(facts['routes'][0]))
    elif change == 'map_duplicate':
        facts['os_map'].append(dict(facts['os_map'][0]))
    elif change == 'state_missing':
        facts['interfaces'][0].pop('connection_state')
    elif change == 'too_many':
        facts['interfaces'] *= 257
    else:
        facts['interfaces'][0]['index'] = True
    assert contract.normalize_ipv6_exposure(facts)['value'] is None

@pytest.mark.parametrize('phase', ['final', 'reuse'])
def test_completeness_lost_during_final_or_reuse_is_not_accepted(tmp_path, phase):

    class Windows(sf.FakeWindows):

        def probe(self, *args, **kwargs):
            result, raw = super().probe(*args, **kwargs)
            if self.calls == (3 if phase == 'final' else 4):
                result['ipv6_exposure']['complete'] = False
            return (result, raw)
    windows = Windows()
    fakenet = sf.FakeFakeNet()
    facade = host_stdio.HostFacade(sf.config_for(tmp_path), provider=sf.FakeProvider(), fakenet_client=fakenet, windows_client=windows, velo_client=sf.FakeVelo())
    first = facade.verify(sf.COMMAND_ID)
    if phase == 'final':
        assert first['coverage']['final_consistency'] is not True
        assert not first['conclusion']['sample_path_qualified']
    else:
        assert first['coverage']['final_consistency'] is True
        old = fakenet.calls.count('verify_egress')
        second = facade.verify(sf.COMMAND_ID)
        assert second['error']['code'] == 'stale_result'
        assert fakenet.calls.count('verify_egress') == old
        assert windows.positive_flags.count(True) == 1

def test_guest_v1_wire_and_initial_raw_evidence_are_retained(tmp_path):

    class Guest(sf.FakeFakeNet):

        def verify_egress(self, command_id, expected_state_version, request, timeout=None):
            assert not {'qualification_profile', 'required_matrix_ids', 'diagnostic_matrix_ids'} & set(request)
            return super().verify_egress(command_id, expected_state_version, request, timeout=timeout)
    guest = Guest()
    facade = host_stdio.HostFacade(sf.config_for(tmp_path), provider=sf.FakeProvider(), fakenet_client=guest, windows_client=sf.FakeWindows(), velo_client=sf.FakeVelo())
    result = facade.verify(sf.COMMAND_ID)
    assert result['error'] is None
    entries = result['manifest']['entries']
    initial = next((entry for entry in entries if entry.get('kind') == 'windows-identity-probe'))
    raw = Path(initial['path']).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == initial['sha256']
    assert 'ipv6_exposure' in json.loads(raw)['probe']
