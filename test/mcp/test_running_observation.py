"""Benign synthetic packets test evidence semantics, not live containment."""
import copy
import hashlib
import ipaddress
import json
import struct
from datetime import datetime, timezone

import pytest

from fakenet.mcp import running_observation as observation, host_probe, egress_contract, egress_lifecycle

T = 1792548000
MAC = '00:0c:29:4c:fd:c0'


def stamp(t):
    return datetime.fromtimestamp(t, timezone.utc).isoformat()


def block(kind, body):
    body += b'\0' * (-len(body) % 4)
    length = len(body) + 12
    return struct.pack('<II', kind, length) + body + struct.pack('<I', length)


def opt(code, value):
    return struct.pack('<HH', code, len(value)) + value + b'\0' * (-len(value) % 4)


def frame(family, destination, *, port=50002, payload=b'', heartbeat=False):
    source = '192.0.2.10' if family == 'ipv4' else '2001:db8::10'
    address = ipaddress.ip_address(destination)
    protocol = 6 if heartbeat else 17
    wire = struct.pack('!HHHH', 28787 if heartbeat else 40000, port, len(payload) + 8, 0) + payload
    if family == 'ipv4':
        header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(wire), 0, 0, 64, protocol, 0, ipaddress.ip_address(source).packed, address.packed)
        ethertype = b'\x08\x00'
    else:
        header = struct.pack('!IHBB16s16s', 6 << 28, len(wire), protocol, 64, ipaddress.ip_address(source).packed, address.packed)
        ethertype = b'\x86\xdd'
    return bytes.fromhex('005056c00008' + MAC.replace(':', '')) + ethertype + header + wire


def pcap(packets=(), *, drops=0, interface='vmnet8'):
    raw = block(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1))
    raw += block(1, struct.pack('<HHI', 1, 0, 65535) + opt(2, interface.encode()) + b'\0' * 4)
    for timestamp, data in packets:
        ticks = int(timestamp * 1000000)
        raw += block(6, struct.pack('<IIIII', 0, ticks >> 32, ticks & 0xffffffff, len(data), len(data)) + data)
    raw += block(5, struct.pack('<III', 0, 0, 0) + opt(5, struct.pack('<Q', drops)) + b'\0' * 4)
    return raw


def ref(tmp, name, value):
    raw = value if isinstance(value, bytes) else json.dumps(value).encode()
    path = tmp / name
    path.write_bytes(raw)
    return {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest()}


def material(tmp):
    host = {'vmx': {'uuid': 'vm', 'nics': [{'present': True, 'start_connected': True, 'interface_present': True, 'interface': 'vmnet8', 'mac': MAC}]}, 'network_type': 'nat'}
    routes = {'ipv4': {'source': '192.0.2.10', 'interface': '1', 'next_hop': '192.0.2.1'}, 'ipv6': {'source': '2001:db8::10', 'interface': '1', 'next_hop': '2001:db8::1'}}
    identity = dict(vm_uuid='vm', boot_id='boot', account='LAB\\user', sid='SID', session=1, token_integrity_level='high')
    probe = {'identity': identity, 'completed_at': stamp(T-3), 'steps': [{'family': family, 'route': route, 'started': stamp(T-4), 'ended': stamp(T-3)} for family, route in routes.items()]}
    base = copy.deepcopy(probe)
    rows=[row for row in host_probe.matrix_steps(50001,50002,'baseline-nonce') if row['id'] in ('ipv4_udp_random','ipv6_udp_random')]
    payload=host_probe.probe_payload('baseline-nonce',rows,positive_enabled=False,calibration_mode=True)
    base['steps']=[dict(row,route=routes[row['family']],send_completed=True,local_endpoint=routes[row['family']]['source']+':40000') for row in rows]
    base.update(schema=host_probe.PROBE_SCHEMA,nonce='baseline-nonce',matrix_run=True,instance={'pid':1,'creation_ticks':2,'nonce':'baseline-nonce','script_hash':hashlib.sha256(json.dumps(payload,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()).hexdigest()},completed_at=stamp(T-31))
    for row in base['steps']:
        row.update(started=stamp(T-35), ended=stamp(T-32))
    packets = [(T-34, frame(family, destination, payload=b'baseline-nonce')) for family, destination in zip(routes, ('198.51.100.77', '2001:db8::77'))]
    receipt = {'schema': 'fakenetng.egress-visibility.v1', 'created_at': stamp(T-30), 'expires_at': stamp(T+300), 'capture_identity': {'fixed': True}, 'topology': observation.topology(host), 'guest_status': ref(tmp, 'status.json', {'state': 'stopped', 'run_id': None}), 'probe': ref(tmp, 'probe.json', base), 'capture': ref(tmp, 'baseline.pcapng', pcap(packets)), 'probe_payload':payload, 'probe_template_sha256': host_probe.script_sha256(host_probe.PROBE_TEMPLATE)}
    capture = pcap([(T-2, frame('ipv4', '192.0.2.1', heartbeat=True))])
    return host, probe, receipt, capture


def evaluate(tmp, host, probe, receipt, capture):
    return observation.evaluate_capture(capture, probe, host, ref(tmp, 'receipt.json', receipt), started=T-5, ended=T-1, heartbeat_port=28787, capture_identity={'fixed': True}, now=T)


def test_same_path_dual_stack_calibration_and_current_window_can_qualify(tmp_path):
    host, probe, receipt, capture = material(tmp_path)
    result = evaluate(tmp_path, host, probe, receipt, capture)
    assert result['value'] is True, result
    assert len(result['paths']) == 2


@pytest.mark.parametrize('change', ['missing_heartbeat', 'drops', 'other_interface', 'other_nic', 'expired', 'route_changed', 'missing_ipv6', 'tampered_calibration', 'old_template'])
def test_absence_and_one_control_heartbeat_do_not_hide_unknown_paths(tmp_path, change):
    host, probe, receipt, capture = material(tmp_path)
    if change == 'missing_heartbeat': capture = pcap()
    elif change == 'drops': capture = pcap(drops=1)
    elif change == 'other_interface': capture = pcap(interface='vmnet1')
    elif change == 'other_nic': host['vmx']['nics'].append(dict(host['vmx']['nics'][0], interface='vmnet1'))
    elif change == 'expired': receipt['expires_at'] = stamp(T-1)
    elif change == 'route_changed': probe['steps'][0]['route']['next_hop'] = '192.0.2.99'
    elif change == 'missing_ipv6': receipt['capture'] = ref(tmp_path, 'ipv4-only.pcapng', pcap([(T-34, frame('ipv4', '198.51.100.77', payload=b'baseline-nonce'))]))
    elif change == 'tampered_calibration': receipt['capture']['sha256'] = '0' * 64
    elif change == 'old_template': receipt['probe_template_sha256'] = '0' * 64
    assert evaluate(tmp_path, host, probe, receipt, capture)['value'] is None


@pytest.mark.parametrize('family,destination', [('ipv4', '198.51.100.77'), ('ipv6', '2001:db8::77')])
def test_seen_egress_fails_even_without_calibration_or_with_capture_loss(tmp_path, family, destination):
    host, probe, receipt, _ = material(tmp_path)
    capture = pcap([(T-3, frame(family, destination))], drops=2)
    result = evaluate(tmp_path, host, probe, {}, capture)
    assert result['value'] is False
    assert result['leaks']


def test_extra_drop_and_fake_sent_do_not_prove_interception():
    step = dict(kind='udp', family='ipv4', destination='198.51.100.77', port=53)
    row = dict(received='', sent=12, send_completed=False, route=dict(source='192.0.2.10', interface='1', next_hop='192.0.2.1'), local_endpoint='192.0.2.10:40000')
    assert host_probe.classify_step(step, row, 'blocked', boundary_verified=True, drop_evidence=True)[0] == 'unknown'
    assert host_probe.classify_step(step, row, 'blocked', containment_observed=True, execution_verified=True)[0] == 'unknown'
    row['send_completed'] = True
    assert host_probe.classify_step(step, row, 'blocked', containment_observed=True, execution_verified=True)[0] == 'pass'


def test_tcp_local_error_is_not_effective_attempt_but_timed_wait_with_evidence_is():
    step = dict(kind='tcp', family='ipv4', destination='198.51.100.77', port=443)
    row = dict(received='', sent=0, route=dict(source='192.0.2.10', interface='1', next_hop='192.0.2.1'), local_endpoint='192.0.2.10:40000', bound_local_endpoint='192.0.2.10:40000', exclusive=True, attempted=True, connect_called=True, connect_completed=False, connect_wait_timed_out=False, connect_error='network unreachable')
    args = dict(containment_observed=True, execution_verified=True)
    assert host_probe.classify_step(step, row, 'blocked', **args)[0] == 'unknown'
    row.update(connect_wait_timed_out=True, connect_error='connect timeout')
    assert host_probe.classify_step(step, row, 'blocked', **args)[0] == 'pass'


def phases():
    plan, observed = egress_contract._base_material()
    base = dict(vm_epoch='epoch', network_identity='nat-original', execution_context_identity='context', endpoint=dict(address='1.1.1.1', port=443), second_blocker_used=False, evidence_refs=['fixture#hash'], started_at=stamp(T), ended_at=stamp(T+1))
    before = dict(base, phase='before', engine_state='stopped', run_id=None, connected=True, peer=base['endpoint'])
    running = dict(base, phase='running', started_at=stamp(T+2), ended_at=stamp(T+3), verification={'authorized':False, 'phase':'running', 'contract_version':2, 'verdict':'pass', 'helper_input':{'plan':plan,'observation':observed}, 'coverage':{'completeness':{'complete':True}}})
    after = dict(before, phase='after', started_at=stamp(T+4), ended_at=stamp(T+5))
    return before, running, after


def test_lifecycle_normal_stopped_online_running_contained_stopped_restored():
    result = egress_lifecycle.evaluate_lifecycle(*phases())
    assert result['verdict'] == 'pass', result
    assert result['authorized'] is False


@pytest.mark.parametrize('failure', ['not_online_before', 'not_restored', 'extra_blocker', 'old_contract', 'binding_changed', 'phase_order', 'test_net_endpoint'])
def test_lifecycle_rejects_wrong_requirement_and_incomplete_proofs(failure):
    before, running, after = phases()
    if failure == 'not_online_before': before['connected'] = False
    elif failure == 'not_restored': after['connected'] = False
    elif failure == 'extra_blocker': running['second_blocker_used'] = True
    elif failure == 'old_contract': running['verification']['contract_version'] = 1
    elif failure == 'binding_changed': after['network_identity'] = 'changed'
    elif failure == 'phase_order': after['started_at'] = stamp(T-1)
    elif failure == 'test_net_endpoint':
        for record in (before,running,after): record['endpoint'] = dict(address='198.51.100.77', port=443)
    assert egress_lifecycle.evaluate_lifecycle(before,running,after)['verdict'] != 'pass'


def test_phase_recorder_only_connects_with_explicit_scope_and_never_controls_engine(tmp_path):
    from importlib.util import spec_from_file_location, module_from_spec
    from pathlib import Path
    path = Path(__file__).resolve().parents[2] / 'tools/verify_egress_lifecycle.py'
    spec = spec_from_file_location('lifecycle_operator_test', path)
    helper = module_from_spec(spec)
    spec.loader.exec_module(helper)
    endpoint = {'address':'1.1.1.1','port':443}
    calls=[]
    class Guest:
        def get_status(self, timeout=None):
            calls.append('status')
            return dict(state='stopped',run_id=None,state_version=1,controller=None)
    class Windows:
        def probe(self, script, timeout=None):
            calls.append('connect')
            assert "Parse('1.1.1.1')" in script
            assert 'Start-Process' not in script
            return {'connected':True,'peer':endpoint,'identity':dict(vm_uuid='vm',boot_id='boot',account='LAB\\user',sid='SID',session=1),'started_at':stamp(T),'ended_at':stamp(T+1)},'bounded benign raw'
    class Facade:
        output_root=tmp_path
        config={'connectivity_endpoint':endpoint}
        def _authorization(self, action):
            assert action=='lifecycle_connectivity'
            return {'scope':{'connectivity_endpoints':[endpoint], 'lifecycle_script_sha256':hashlib.sha256(helper.CONNECT_TEMPLATE.encode()).hexdigest()}}
        def _fakenet(self):return Guest()
        def _windows(self):return Windows()
        def _host_snapshot(self, deadline):return material(tmp_path)[0]
    result=helper.record(Facade(),'before')
    record=json.loads(Path(result['path']).read_text())
    assert record['connected'] is True and record['engine_state']=='stopped'
    assert record['authorized'] is False
    assert calls==['status','connect','status']
    class MissingScope(Facade):
        def _authorization(self, action):return {'scope':{}}
    with pytest.raises(ValueError,match='explicitly authorized'):
        helper.record(MissingScope(),'after')
    assert calls==['status','connect','status']


def test_current_contract_refuses_old_independent_block_even_if_claimed_true():
    plan, observed=egress_contract._base_material()
    observed['checks']['independent_egress_blocked']=observed['checks'].pop('running_egress_contained')
    observed.pop('contract_version')
    result=egress_contract.evaluate_interception_qualification(plan,observed)
    assert result['status']=='underdetermined'
    assert 'running_egress_contained' in result['unknown_checks']
    assert 'qualification_contract_version' in result['unknown_checks']


def test_passive_capture_owns_one_bounded_nonprivileged_child_and_confirms_exit(tmp_path, monkeypatch):
    host, _, _, _=material(tmp_path)
    calls=[]
    class Process:
        returncode=None
        def poll(self):return self.returncode
        def send_signal(self, value):calls.append('signal');self.returncode=0
        def wait(self, timeout):calls.append(('wait',timeout));return self.returncode
        def kill(self):calls.append('kill');self.returncode=-9
    def popen(argv, **kwargs):
        calls.append(argv)
        kwargs['stderr'].write(b'Capturing on vmnet8\n');kwargs['stderr'].flush()
        return Process()
    monkeypatch.setattr(observation.subprocess,'Popen',popen)
    capture=observation.PassiveCapture(tmp_path/'own',host,seconds=500)
    capture.start()
    result=capture.finish()
    assert result['complete'] is True
    argv=calls[0]
    assert argv[0]=='/usr/bin/dumpcap' and '-p' in argv and 'duration:35' in argv and 'filesize:4096' in argv
    assert 'sudo' not in argv
    assert calls[1]=='signal'


def test_no_passive_scope_does_not_create_capture_or_skip_authorized_matrix(tmp_path):
    from test.mcp import test_host_stdio as fixture
    config=fixture.config_for(tmp_path)
    config['passive_observation']={'enabled':True}
    def forbidden(*args,**kwargs):raise AssertionError('capture without scope')
    facade=fixture.HostFacade(config,provider=fixture.FakeProvider(),fakenet_client=fixture.FakeFakeNet(),windows_client=fixture.FakeWindows(),velo_client=fixture.FakeVelo(),capture_factory=forbidden)
    result=facade.verify(fixture.COMMAND_ID)
    assert result['coverage']['matrix_executed']==30
    assert result['verdict']=='unknown'
    step=next(row for row in result['steps'] if row['id']=='host_running_observation')
    assert step['observed']['reason']=='passive_observation_not_authorized'
