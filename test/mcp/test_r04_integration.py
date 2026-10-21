"""R04 host->generated guest payload->guest parser->host helper chain."""
from datetime import datetime
import importlib.util
import json
import time
from pathlib import Path

from fakenet.mcp import egress_verification


def load(name, relative):
    path = Path(__file__).parent / relative
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fixture = load('r04_host_fixture', 'test_host_stdio.py')
CONTROLLER = fixture.CONTROLLER
RUN_ID = fixture.RUN_ID
COMMAND_ID = fixture.COMMAND_ID


class GuestFromActual(fixture.FakeFakeNet):
    def __init__(self, artifacts, bad_tuple=False):
        super().__init__()
        self.artifacts = Path(artifacts)
        self.bad_tuple = bad_tuple

    def verify_egress(self, command_id, expected_state_version, request,
                      timeout=None):
        self.calls.append('verify_egress')
        log = self.artifacts / 'runs' / RUN_ID / 'run.log'
        log.parent.mkdir(parents=True, exist_ok=True)
        started = datetime.fromisoformat(request['host_probe_started'])
        ended = datetime.fromisoformat(request['host_probe_ended'])
        source = '192.0.2.55' if self.bad_tuple else request[
            'host_probe_source']
        sport = 49999 if self.bad_tuple else request['host_probe_source_port']
        proto = 'UDP' if self.bad_tuple else request['host_probe_protocol']
        log.write_text(
            'DIVERT_FAKE_PROBE pid=%s creation=%s probe_nonce=%s '
            'src=%s sport=%s dst=%s dport=%s proto=%s process=fixture '
            'epoch=%d\n' % (
                request['host_probe_pid'], request['host_probe_creation'],
                request['probe_nonce'], source, sport,
                request['host_probe_destination'], request['host_probe_port'],
                proto, int((started.timestamp() + ended.timestamp()) / 2)),
            encoding='utf-8')
        producer = egress_verification._producer_match(RUN_ID, request)
        evidence = self.artifacts / 'guest-evidence.json'
        evidence.write_text('{"guest":true}\n', encoding='utf-8')
        import hashlib
        child = {
            'firewall': {'available': True, 'profiles': [
                {'name': 'Domain', 'enabled': False},
                {'name': 'Private', 'enabled': False},
                {'name': 'Public', 'enabled': False}]},
            'route4': {'available': True, 'stdout': 'route'},
            'route6': {'available': True, 'stdout': 'route6'},
            'adapters': {'available': True, 'stdout': 'adapter'},
            'netstat': {'available': True, 'stdout': 'netstat'},
            'local_echo': {'available': True, 'sent': 24,
                           'received': 'MALTRACE-EGRESS-' +
                                       request['probe_nonce'],
                           'nonce_match': True, 'error': None},
            'producer_match': producer,
            'evidence': {'path': str(evidence),
                         'sha256': hashlib.sha256(
                             evidence.read_bytes()).hexdigest(),
                         'size': evidence.stat().st_size},
        }
        health = {
            'process_alive': True, 'init_evidence': True, 'probe': True,
            'capture_threads_alive': True, 'capture_error': None,
            'final_filter': ('(ip.DstAddr != 192.168.204.1 or '
                             '(tcp.SrcPort != 28787 and tcp.SrcPort != 28788 '
                             'and tcp.SrcPort != 28790))'),
            'inbound_capture_filter': 'inbound and (ip or ipv6)',
            'inbound_capture_flags': 'SNIFF',
            'inbound_capture_active': True, 'capture_mode': 'sniff',
        }
        snapshot = {'state': 'healthy', 'run_id': RUN_ID,
                    'controller': CONTROLLER,
                    'config_identity': {'name': 'fixture.ini',
                                        'sha256': 'c' * 64,
                                        'builtin': False}}
        result = egress_verification.build_guest_result(
            command_id=command_id, request=request, snapshot=snapshot,
            health=health, child=child)
        return {'verification': result, 'error': None}


def test_real_facade_generated_guest_parser_normal_chain(tmp_path, monkeypatch):
    artifacts = tmp_path / 'artifacts'
    monkeypatch.setattr(egress_verification.paths, 'data_directories',
                        lambda: {'artifacts': str(artifacts)})
    facade = fixture.HostFacade(
        fixture.config_for(tmp_path), provider=fixture.FakeProvider(),
        fakenet_client=GuestFromActual(artifacts),
        windows_client=fixture.FakeWindows(), velo_client=fixture.FakeVelo())
    result = facade.verify(COMMAND_ID)
    assert result['error'] is None, result
    assert result['verdict'] == 'unknown', result['conclusion']
    assert result['producer_match'] is True
    assert result['conclusion']['matrix_completeness']['complete'] is False


def test_wrong_full_source_tuple_is_rejected_end_to_end(tmp_path, monkeypatch):
    artifacts = tmp_path / 'artifacts'
    monkeypatch.setattr(egress_verification.paths, 'data_directories',
                        lambda: {'artifacts': str(artifacts)})
    facade = fixture.HostFacade(
        fixture.config_for(tmp_path), provider=fixture.FakeProvider(),
        fakenet_client=GuestFromActual(artifacts, bad_tuple=True),
        windows_client=fixture.FakeWindows(), velo_client=fixture.FakeVelo())
    result = facade.verify(COMMAND_ID)
    assert result['verdict'] != 'pass'
    assert result['producer_match'] is not True


def test_pending_same_id_reconciles_guest_without_rerun(tmp_path, monkeypatch):
    artifacts = tmp_path / 'artifacts'
    monkeypatch.setattr(egress_verification.paths, 'data_directories',
                        lambda: {'artifacts': str(artifacts)})
    guest = GuestFromActual(artifacts)
    guest.get_command_status = lambda command_id, timeout=None: {
        'status': 'completed', 'command_id': command_id,
        'response': {'verification': {'verification_id': 'guest-v'}}}
    facade = fixture.HostFacade(
        fixture.config_for(tmp_path), provider=fixture.FakeProvider(),
        fakenet_client=guest, windows_client=fixture.FakeWindows(),
        velo_client=fixture.FakeVelo())
    first = facade.verify(COMMAND_ID)
    assert first['verdict'] == 'unknown'
    record = facade.state.load(COMMAND_ID)
    record['stage'] = 'running'
    facade.state.update(COMMAND_ID, record)
    before = guest.calls.count('verify_egress')
    pending = facade.verify(COMMAND_ID)
    assert pending['error']['code'] in ('ownership_unknown', 'running')
    assert pending['reconciliation']['available'] is True
    assert guest.calls.count('verify_egress') == before
    other = '66666666-7777-4888-9999-aaaaaaaaaaaa'
    blocked = facade.verify(other)
    assert blocked['error']['code'] == 'ownership_unknown'


def test_medium_observations_and_long_provenance_stay_compact(tmp_path, monkeypatch):
    root = tmp_path / ('native-provenance-' + 'x' * 150)
    root.mkdir()
    artifacts = root / 'artifacts'
    monkeypatch.setattr(egress_verification.paths, 'data_directories',
                        lambda: {'artifacts': str(artifacts)})
    facade = fixture.HostFacade(
        fixture.config_for(root), provider=fixture.FakeProvider(),
        fakenet_client=GuestFromActual(artifacts),
        windows_client=fixture.FakeWindows(), velo_client=fixture.FakeVelo())
    result = facade.verify(COMMAND_ID)
    assert result['error'] is None
    assert result['producer_match'] is True
    assert result['coverage']['matrix_executed'] == 30
    assert len(json.dumps(result, ensure_ascii=False).encode()) <= 65536
