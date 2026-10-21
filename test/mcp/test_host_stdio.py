"""Host facade orchestration with fixed fake clients (no VM or network)."""
import base64
import hashlib
import json
from pathlib import Path
import re
import sys

import pytest

from fakenet.mcp import host_probe, host_merge
from fakenet.mcp.host_stdio import HostFacade


CONTROLLER = '11111111-2222-4333-8444-555555555555'
RUN_ID = '22222222-3333-4444-8555-666666666666'
VERIFICATION_ID = '33333333-4444-4555-8666-777777777777'
COMMAND_ID = '44444444-5555-4666-8777-888888888888'
VM_UUID = '56 4d e0 b3 b2 3d 3d 9f-4d 52 3e c2 2c 4c fd c0'
COMPUTER = 'DESKTOP-3FI41GR'
ACCOUNT = 'DESKTOP-3FI41GR\\analyst'
SID = 'S-1-5-21-1-2-3-1001'
IMAGE_PATH = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
IMAGE_SHA = 'a' * 64


class FakeProvider:
    def snapshot(self, deadline=None):
        return {
            'schema': 'fixture',
            'vmx': {'available': True, 'uuid': VM_UUID,
                    'sha256': 'b' * 64, 'connection_type': 'hostonly',
                    'nics': [{'interface': 'vmnet1',
                              'connection_type': 'hostonly'}]},
            'networking': {'available': True, 'nat': False},
            'nat': {'available': True, 'host.ip': '192.168.204.2'},
            'route_to_guest': {'returncode': 0, 'stdout': 'dev vmnet1'},
            'forwarding': {'ipv4': 0, 'ipv4_all': 0, 'ipv6_all': 0},
            'firewall': {'known': True},
            'boundary': {'value': True, 'reason': 'fixture_boundary'},
        }


class FakeFakeNet:
    def __init__(self):
        self.calls = []

    def list_tools(self, timeout=None):
        self.calls.append('list_tools')
        return []

    def get_status(self, timeout=None):
        self.calls.append('get_status')
        return {'state': 'healthy', 'state_version': 1, 'run_id': RUN_ID,
                'controller': CONTROLLER,
                'config_identity': {'name': 'fixture.ini',
                                    'sha256': 'c' * 64, 'builtin': False}}

    def read_config(self, name, timeout=None):
        self.calls.append('read_config')
        return {'name': name, 'sha256': 'c' * 64,
                'content': '[Diverter]\nRedirectAllTraffic=Yes\n'
                           'BlackListPortsTCP=139,443\n'
                           'BlackListPortsUDP=53,443\n'
                           '[RawTCPListener]\nEnabled=True\nPort=1337\n'
                           'Listener=RawListener\n'}

    def verify_egress(self, command_id, expected_state_version, request,
                      timeout=None):
        self.calls.append('verify_egress')
        checks = {
            key: {'value': value, 'evidence_refs': ['fixture-evidence']}
            for key, value in {
                'firewall_disabled': True,
                'fakenet_running_healthy': True,
                'mcp_control_exclusions_effective': True,
                'blocked_before_interception': False,
                'control_channels_reachable': True,
                'local_interception_observed': True,
                'running_egress_contained': True,
                'sample_path_equivalent': True}.items()}
        return {'verification': {
            'schema_version': 'fakenetng.egress-verification.v1',
            'verification_id': request['verification_id'],
            'command_id': command_id,
            'lifecycle': {'state': 'completed'},
            'verdict': 'unknown',
            'bindings': {
                'run_id': RUN_ID, 'vm_epoch': request['vm_epoch'],
                'policy_identity': request['policy_identity'],
                'execution_context_identity': request[
                    'execution_context_identity'],
                'probe_nonce': request['probe_nonce'],
                'response_nonce': request['probe_nonce'],
                'required_control_ports': request['required_control_ports'],
                'effective_control_exclusion_ports': [28787, 28788, 28790],
                'config_identity': {'name': 'fixture.ini',
                                    'sha256': 'c' * 64, 'builtin': False},
                'final_filter_sha256': 'd' * 64,
                'guest_evidence_sha256': 'e' * 64,
                'controller_identity': CONTROLLER,
                'facade_version': 'fixture',
                'matrix_version': 'v1',
            },
            'steps': [],
            'checks': checks,
            'helper_input': {},
            'conclusion': {'status': 'underdetermined', 'verdict': 'unknown',
                           'failed_checks': [],
                           'unknown_checks': ['host'], 'authorized': False},
            'coverage': {}, 'manifest': {'entries': []},
            'invalidation_conditions': [], 'limitations': [],
            'authorized': False, 'error': None, 'producer_match': True,
        }, 'error': None}


class FakeWindows:
    def __init__(self):
        self.calls = 0
        self.positive_flags = []

    def list_tools(self, timeout=None):
        return {}

    def probe(self, script, timeout=None):
        self.calls += 1
        match = re.search(r"FromBase64String\('([^']+)'\)", script)
        payload = json.loads(base64.b64decode(match.group(1)).decode('utf-8'))
        self.positive_flags.append(payload.get('positive_enabled'))
        matrix = payload['steps']
        steps = []
        for row in matrix:
            common = {
                'id': row['id'], 'outcome': 'no_response', 'sent': 1,
                'received': '', 'error': 'fixture-timeout',
                'response_type': 'tcp', 'status': None,
                'nonce_match': False, 'address_family':
                    'InterNetwork' if row.get('family') == 'ipv4'
                    else 'InterNetworkV6',
                'remote_endpoint': '%s:%s' % (row.get('destination'),
                                              row.get('port')),
                'local_endpoint': '192.0.2.10:50000', 'elapsed_ms': 2,
                'started': 'now', 'ended': 'now',
            }
            kind = row.get('kind')
            port = row.get('port')
            probe_kind = row.get('probe_kind')
            blocked = (kind == 'icmp' or
                       (kind == 'tcp' and port in (139, 443)) or
                       (kind == 'udp' and port in (53, 443)))
            if blocked:
                steps.append(common)
                continue
            if probe_kind == 'tcp_raw':
                common.update({'outcome': 'response', 'sent': 24,
                               'received': 'MALTRACE-EGRESS-' +
                                           payload['nonce'],
                               'response_type': 'tcp_nonce', 'status': None,
                               'nonce_match': True})
            elif probe_kind == 'tcp_tls':
                common.update({'outcome': 'response', 'sent': 48,
                               'received': 'HTTP/1.1 200 OK\\r\\n\\r\\n' +
                                           payload['nonce'],
                               'response_type': 'tls_http', 'status': 200,
                               'nonce_match': True})
            elif probe_kind == 'tcp_http':
                common.update({'outcome': 'response', 'sent': 48,
                               'received': 'HTTP/1.1 200 OK\\r\\n\\r\\n' +
                                           payload['nonce'],
                               'response_type': 'http', 'status': 200,
                               'nonce_match': True})
            elif probe_kind == 'udp_raw':
                common.update({'outcome': 'response', 'sent': 12,
                               'received': 'MALTRACE-EGRESS-' +
                                           payload['nonce'],
                               'response_type': 'udp_nonce',
                               'nonce_match': True})
            elif probe_kind == 'dns':
                common.update({'outcome': 'response', 'sent': 30,
                               'received': 'dns-bytes=40',
                               'response_type': 'dns',
                               'transaction_id': row.get('dns_txid'),
                               'question': row.get('question'),
                               'qtype': 1, 'qclass': 1,
                               'qr': True, 'rcode': 0,
                               'nonce_match': True})
            else:
                common.update({'outcome': 'response', 'sent': 32,
                               'received': 'MALTRACE-' + payload['nonce'],
                               'response_type': 'icmp_echo',
                               'responder': row.get('destination'),
                               'nonce_match': True})
            steps.append(common)
        value = {
            'schema': host_probe.PROBE_SCHEMA, 'nonce': payload['nonce'],
            'instance': {'pid': 1234, 'creation_ticks': 100,
                         'nonce': payload['nonce'],
                         'script_hash': payload.get('script_hash')},
            'matrix_run': bool(matrix),
            'identity': {
                'pid': 1234, 'creation_ticks': 100, 'account': ACCOUNT,
                'sid': SID, 'session': 3, 'image_path': IMAGE_PATH,
                'image_sha256': IMAGE_SHA, 'vm_uuid': VM_UUID,
                'boot_id': 'boot', 'computer': COMPUTER,
                'token_integrity_level': 'S-1-16-12288',
                'policy_scope': 'applocker:fixture',
                'protocol_class': 'mixed-v1',
            },
            'firewall': [{'name': 'Domain', 'enabled': False},
                         {'name': 'Private', 'enabled': False},
                         {'name': 'Public', 'enabled': False}],
            'firewall_error': None,
            'ipv6_exposure': {
                'schema': 'fakenetng.ipv6-exposure.v1', 'complete': True,
                'interfaces': [{'index': 1, 'forwarding': 'Disabled',
                                'connection_state': 'Up'}],
                'addresses': [{'interface_index': 1, 'address': '::1',
                               'prefix_length': 128, 'state': 'Preferred'}],
                'routes': [{'interface_index': 1, 'prefix': '::1/128',
                            'next_hop': '::'},
                           {'interface_index': 1, 'prefix': 'ff00::/8',
                            'next_hop': '::'}],
                'os_map': [{'index': 1, 'type': 'Loopback'}],
                'errors': []},
            'positive': ({'id': 'local_interception_positive',
                          'nonce_match': True,
                          'destination': '198.51.100.77',
                          'port': 1337,
                          'local_endpoint': '192.0.2.10:40000',
                          'remote_endpoint': '198.51.100.77:1337',
                          'protocol': 'TCP',
                          'started': '2026-10-20T03:00:00+00:00',
                          'ended': '2026-10-20T03:00:02+00:00'}
                         if payload.get('positive_enabled', True) else None),
            'steps': steps,
            'completed_at': 'now',
        }
        return value, 'raw-windows-probe'


class FakeVelo:
    def probe(self, timeout=None):
        return True, {'tool': 'fixture'}


def scope_for(tmp_path, output_root, state_root):
    return {
        'schema': 'fakenetng.probe-scope.v1',
        'version': 1,
        'scope_id': 'fixture-benign',
        'qualification_profile': 'ipv4-v1',
        'mode': 'probe',
        'authorization': 'granted',
        'revoked': False,
        'not_before': '2020-01-01T00:00:00+00:00',
        'expires_at': '2099-01-01T00:00:00+00:00',
        'actions': ['host_provider', 'windows_probe', 'matrix_probe',
                    'guest_verify', 'velo_probe'],
        'vm': {'uuid': VM_UUID, 'computer': COMPUTER},
        'objects': {'vmx_path': str(tmp_path / 'fixture.vmx'),
                    'guest_ip': '192.168.204.149',
                    'config_name': 'fixture.ini'},
        'paths': {'output_root': output_root, 'state_root': state_root},
        'tools': {'fakenet': ['get_status', 'read_config',
                              'verify_egress_isolation'],
                  'windows': ['PowerShell'], 'velo': ['fixture']},
        'probe': {'script_sha256': host_probe.script_sha256(
                      host_probe.PROBE_TEMPLATE),
                  'destinations': ['198.51.100.77', '2001:db8::77'],
                  'echo_destination': '198.51.100.77', 'echo_port': 1337,
                  'matrix_versions': ['v1'], 'allow_random_ports': True,
                  'guest_echo_allowed': True},
        'control_ports': [28787, 28788, 28790],
        'budget': {'total_ms': 50000, 'finish_ms': 5000},
        'sample_context': {
            'account': ACCOUNT, 'sid': SID, 'session': 3,
            'token_integrity_level': 'S-1-16-12288',
            'launcher_path': 'E:\\sample.exe',
            'launcher_sha256': 'f' * 64,
            'policy_scope': 'applocker:fixture',
            'protocol_class': 'mixed-v1',
        },
    }


def config_for(tmp_path):
    output = str(tmp_path / 'output')
    state = str(tmp_path / 'state')
    source = tmp_path / 'scope.json'
    source.write_text(json.dumps(scope_for(tmp_path, output, state),
                                 ensure_ascii=False, indent=2) + '\n',
                      encoding='utf-8')
    return {
        'schema': 'fakenetng-host-mcp.config.v1',
        'fakenet_mcp': {'url': 'http://127.0.0.1:9/mcp',
                        'controller_id': CONTROLLER,
                        'config_name': 'fixture.ini',
                        'timeout_seconds': 5},
        'windows_mcp': {'url': 'http://127.0.0.1:9/mcp',
                        'timeout_seconds': 5},
        'velo_mcp': {'url': 'http://127.0.0.1:9/mcp',
                     'tool': 'fixture', 'arguments': {},
                     'allowed_tools': ['fixture'],
                     'timeout_seconds': 5},
        'vmx': {'path': str(tmp_path / 'fixture.vmx'),
                'expected_uuid': VM_UUID, 'expected_computer': COMPUTER},
        'guest_ip': '192.168.204.149',
        'vmware_networking_path': str(tmp_path / 'networking'),
        'nat_conf_path': str(tmp_path / 'nat.conf'),
        'interface': 'vmnet1',
        'sample_context': {
            'account': ACCOUNT, 'sid': SID, 'session': 3,
            'token_integrity_level': 'S-1-16-12288',
            'launcher_path': 'E:\\sample.exe',
            'launcher_sha256': 'f' * 64,
            'policy_scope': 'applocker:fixture',
            'protocol_class': 'mixed-v1',
        },
        'probe_authorization': {
            'authorized': True, 'source_ref': str(source),
            'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
            'scope': 'fixture-benign',
            'expected_vmx_uuid': VM_UUID,
            'expected_computer': COMPUTER},
        'policy': {'qualification_profile': 'ipv4-v1',
                   'required_control_ports': [28787, 28788, 28790],
                   'matrix_version': 'v1',
                   'probe_script_sha256': host_probe.script_sha256(
                       host_probe.PROBE_TEMPLATE),
                   'guest_budget_ms': 1000,
                   'output_compact_limit_bytes': 65536},
        'output_root': output,
        'state_root': state,
    }


def test_host_facade_fake_normal_call_and_replay(tmp_path):
    fake_fakenet = FakeFakeNet()
    windows = FakeWindows()
    facade = HostFacade(
        config_for(tmp_path), provider=FakeProvider(),
        fakenet_client=fake_fakenet, windows_client=windows,
        velo_client=FakeVelo())
    first = facade.verify(COMMAND_ID)
    assert first['error'] is None
    assert first['verdict'] == 'unknown'
    assert first['conclusion']['status'] == 'underdetermined'
    assert first['conclusion']['matrix_completeness']['complete'] is False
    assert first['authorized'] is False
    assert first['coverage']['matrix_planned'] == 30
    assert first['artifact']['path'].endswith('result.json')
    assert fake_fakenet.calls.count('verify_egress') == 1
    assert windows.positive_flags == [False, True, False]
    second = facade.verify(COMMAND_ID)
    assert second['verdict'] == 'unknown'
    assert fake_fakenet.calls.count('verify_egress') == 1
    assert second['verification_id'] == first['verification_id']


def test_host_facade_rejects_missing_authorization(tmp_path):
    config = config_for(tmp_path)
    config['probe_authorization']['authorized'] = False
    facade = HostFacade(config, provider=FakeProvider(),
                        fakenet_client=FakeFakeNet(),
                        windows_client=FakeWindows(), velo_client=FakeVelo())
    result = facade.verify(COMMAND_ID)
    assert result['error']['code'] == 'invalid_request'
    assert result['verdict'] == 'unknown'


def test_host_facade_rejects_revoked_scope(tmp_path):
    config = config_for(tmp_path)
    source = Path(config['probe_authorization']['source_ref'])
    scope = json.loads(source.read_text(encoding='utf-8'))
    scope['revoked'] = True
    source.write_text(json.dumps(scope) + '\n', encoding='utf-8')
    config['probe_authorization']['source_sha256'] = hashlib.sha256(
        source.read_bytes()).hexdigest()
    facade = HostFacade(config, provider=FakeProvider(),
                        fakenet_client=FakeFakeNet(),
                        windows_client=FakeWindows(), velo_client=FakeVelo())
    result = facade.verify(COMMAND_ID)
    assert result['error']['code'] == 'invalid_request'
    assert 'revoked' in result['error']['message']


def test_host_facade_math_and_expected_map():
    expected = host_probe.expected_steps(bypass_tcp=[139], bypass_udp=[443],
                                         mapped_ports=[1337, 80, 53],
                                         redirect_all=True,
                                         random_tcp_port=50001,
                                         random_udp_port=50002)
    assert len(expected) == 30
    assert expected['ipv4_tcp_139']['expected'] == 'blocked'
    assert expected['ipv4_udp_443']['expected'] == 'blocked'
    assert expected['ipv4_tcp_80']['expected'] == 'local_fake'
    assert expected['ipv4_dns_nonce_invalid']['expected'] == 'local_fake'
    assert expected['ipv4_icmp']['expected'] == 'local_fake'


def test_host_stdio_tool_surface(tmp_path):
    import anyio
    from mcp import Client
    from mcp.client.stdio import StdioServerParameters, stdio_client

    root = Path(__file__).resolve().parents[2]
    child = tmp_path / 'host_child.py'
    child.write_text(
        'import sys\n'
        'sys.path.insert(0, %r)\n'
        'from fakenet.mcp import host_stdio, schemas\n'
        'class Fake:\n'
        '    def verify(self, command_id):\n'
        '        return schemas.VerificationResult(\n'
        '            schema_version="fakenetng.egress-verification.v1",\n'
        '            verification_id="33333333-4444-4555-8666-777777777777",\n'
        '            command_id=command_id, verdict="unknown",\n'
        '            lifecycle=schemas.VerificationLifecycle(state="completed"),\n'
        '            authorized=False).model_dump(mode="json")\n'
        'host_stdio.build_server(Fake()).run(transport="stdio")\n'
        % str(root), encoding='utf-8')

    async def run():
        params = StdioServerParameters(command=sys.executable,
                                       args=[str(child)])
        with (tmp_path / 'host-stderr.txt').open('w', encoding='utf-8') as errlog:
            async with Client(stdio_client(params, errlog=errlog),
                              read_timeout_seconds=20) as client:
                tools = await client.list_tools()
                assert [tool.name for tool in tools.tools] == [
                    'verify_egress_isolation']
                schema = tools.tools[0].input_schema
                assert set(schema.get('properties', {})) == {'command_id'}
                result = await client.call_tool(
                    'verify_egress_isolation',
                    {'command_id': COMMAND_ID})
                assert result.is_error is False
                assert result.structured_content['verification_id'] == VERIFICATION_ID
                assert result.structured_content['authorized'] is False

    try:
        anyio.run(run)
    except BaseException:
        print((tmp_path / 'host-stderr.txt').read_text(encoding='utf-8'))
        raise


def test_nat_unknown_boundary_runs_matrix_but_requires_passive_observation(tmp_path):
    class UnknownBoundaryProvider(FakeProvider):
        def snapshot(self, deadline=None):
            value = super().snapshot(deadline=deadline)
            value['boundary'] = {'value': None, 'reason': 'nat_rules_unknown'}
            return value
    windows = FakeWindows()
    facade = HostFacade(
        config_for(tmp_path), provider=UnknownBoundaryProvider(),
        fakenet_client=FakeFakeNet(), windows_client=windows,
        velo_client=FakeVelo())
    result = facade.verify(COMMAND_ID)
    assert result['verdict'] == 'unknown'
    assert result['conclusion']['status'] == 'underdetermined'
    assert result['coverage']['matrix_planned'] == 30
    assert result['coverage']['matrix_not_run'] == []
    assert result['coverage']['matrix_executed'] == 30
    assert result['checks']['running_egress_contained']['value'] is None
    assert windows.calls == 3  # identity, actual matrix, final identity


def test_identity_mismatch_stops_before_guest_or_matrix(tmp_path):
    class WrongIdentityWindows(FakeWindows):
        def probe(self, script, timeout=None):
            value, raw = super().probe(script, timeout)
            value['identity']['vm_uuid'] = 'different'
            return value, raw
    fake_fakenet = FakeFakeNet()
    facade = HostFacade(
        config_for(tmp_path), provider=FakeProvider(),
        fakenet_client=fake_fakenet, windows_client=WrongIdentityWindows(),
        velo_client=FakeVelo())
    result = facade.verify(COMMAND_ID)
    assert result['error']['code'] == 'state_conflict'
    assert 'verify_egress' not in fake_fakenet.calls


def test_output_limit_error_replays_same_error_not_old_pass(tmp_path):
    config = config_for(tmp_path)
    config['policy']['output_compact_limit_bytes'] = 1000
    fake_fakenet = FakeFakeNet()
    facade = HostFacade(config, provider=FakeProvider(),
                        fakenet_client=fake_fakenet,
                        windows_client=FakeWindows(), velo_client=FakeVelo())
    first = facade.verify(COMMAND_ID)
    assert first['error']['code'] == 'output_limit'
    assert first['artifact']['path'].endswith('result.full.json')
    assert first['lifecycle']['state'] == 'completed'
    second = facade.verify(COMMAND_ID)
    assert second['error']['code'] == 'output_limit'
    assert second['artifact']['sha256'] == first['artifact']['sha256']
    assert fake_fakenet.calls.count('verify_egress') == 1


def test_host_facade_rejects_expired_scope(tmp_path):
    config = config_for(tmp_path)
    source = Path(config['probe_authorization']['source_ref'])
    scope = json.loads(source.read_text(encoding='utf-8'))
    scope['expires_at'] = '1970-01-01T00:00:00+00:00'
    source.write_text(json.dumps(scope) + '\n', encoding='utf-8')
    config['probe_authorization']['source_sha256'] = hashlib.sha256(
        source.read_bytes()).hexdigest()
    facade = HostFacade(config, provider=FakeProvider(),
                        fakenet_client=FakeFakeNet(),
                        windows_client=FakeWindows(), velo_client=FakeVelo())
    result = facade.verify(COMMAND_ID)
    assert result['error']['code'] == 'invalid_request'
    assert 'expired' in result['error']['message']


def test_tampered_completed_result_is_not_replayed_as_pass(tmp_path):
    facade = HostFacade(config_for(tmp_path), provider=FakeProvider(),
                        fakenet_client=FakeFakeNet(),
                        windows_client=FakeWindows(), velo_client=FakeVelo())
    first = facade.verify(COMMAND_ID)
    assert first['verdict'] == 'unknown'
    record = facade.state.load(COMMAND_ID)
    path = Path(record['result_path'])
    cached = json.loads(path.read_text(encoding='utf-8'))
    cached['verification_id'] = 'TAMPERED'
    path.write_text(json.dumps(cached), encoding='utf-8')
    replay = facade.verify(COMMAND_ID)
    assert replay['error']['code'] == 'integrity_error'
    assert replay['verdict'] != 'pass'


def test_ownership_unknown_blocks_new_target_command(tmp_path):
    facade = HostFacade(config_for(tmp_path), provider=FakeProvider(),
                        fakenet_client=FakeFakeNet(),
                        windows_client=FakeWindows(), velo_client=FakeVelo())
    first = facade.verify(COMMAND_ID)
    assert first['verdict'] == 'unknown'
    record = facade.state.load(COMMAND_ID)
    record['stage'] = 'ownership_unknown'
    facade.state.update(COMMAND_ID, record)
    assert facade.state.find_active_target(record['target_key']) is not None
    other = '55555555-6666-4777-8888-999999999999'
    blocked = facade.verify(other)
    assert blocked['error']['code'] == 'ownership_unknown'


def test_host_facade_passes_distinct_observer_context_and_reuses_cache(tmp_path):
    class ContextProvider(FakeProvider):
        def __init__(self):
            self.contexts = []
            self.snapshots = 0

        def set_observer_context(self, command_id, phase, challenge):
            self.contexts.append((command_id, phase, challenge))

        def snapshot(self, deadline=None):
            self.snapshots += 1
            return super().snapshot(deadline=deadline)

    provider = ContextProvider()
    fake = FakeFakeNet()
    facade = HostFacade(config_for(tmp_path), provider=provider,
                        fakenet_client=fake, windows_client=FakeWindows(),
                        velo_client=FakeVelo())
    first = facade.verify(COMMAND_ID)
    assert first['verdict'] == 'unknown'
    phases = [item[1] for item in provider.contexts]
    assert phases.count('pre') >= 1
    assert phases.count('final') >= 1
    assert len({item[2] for item in provider.contexts}) >= 2
    before = fake.calls.count('verify_egress')
    second = facade.verify(COMMAND_ID)
    assert second['verdict'] == 'unknown'
    assert fake.calls.count('verify_egress') == before
    assert provider.contexts[-1][1] == 'final'  # replay validates full current facts


def test_preprobe_failure_replays_without_permanent_target_lock(tmp_path):
    from fakenet.mcp.host_stdio import HostFacadeError

    class UnavailableGuest(FakeFakeNet):
        def list_tools(self, timeout=None):
            raise HostFacadeError('guest_transport_error', 'guest MCP HTTP status 400')

    windows = FakeWindows()
    facade = HostFacade(config_for(tmp_path), provider=FakeProvider(),
                        fakenet_client=UnavailableGuest(), windows_client=windows,
                        velo_client=FakeVelo())
    first = facade.verify(COMMAND_ID)
    assert first['error']['code'] == 'guest_transport_error'
    assert windows.calls == 0
    record = facade.state.load(COMMAND_ID)
    assert facade.state.find_active_target(record['target_key']) is None
    assert facade.verify(COMMAND_ID) == first
    other = facade.verify('55555555-6666-4777-8888-999999999999')
    assert other['error']['code'] == 'guest_transport_error'
    assert windows.calls == 0


def test_windows_submission_timeout_keeps_target_owned(tmp_path):
    from fakenet.mcp.host_stdio import HostFacadeError

    class TimedOutWindows(FakeWindows):
        def probe(self, script, timeout=None):
            raise HostFacadeError('windows_timeout', 'submission outcome unknown')

    facade = HostFacade(config_for(tmp_path), provider=FakeProvider(),
                        fakenet_client=FakeFakeNet(), windows_client=TimedOutWindows(),
                        velo_client=FakeVelo())
    first = facade.verify(COMMAND_ID)
    assert first['error']['code'] == 'windows_timeout'
    record = facade.state.load(COMMAND_ID)
    assert facade.state.find_active_target(record['target_key']) is not None
    other = facade.verify('55555555-6666-4777-8888-999999999999')
    assert other['error']['code'] == 'ownership_unknown'


def test_large_raw_step_keeps_one_call_result_and_integrity(tmp_path, monkeypatch):
    original = host_merge.build_host_result

    def with_large_adapter_observation(**kwargs):
        result = original(**kwargs)
        result['steps'][0]['observed'] = {'returncode': 0, 'stdout': 'adapter details ' * 10000}
        return result

    monkeypatch.setattr(host_merge, 'build_host_result', with_large_adapter_observation)
    facade = HostFacade(config_for(tmp_path), provider=FakeProvider(),
                        fakenet_client=FakeFakeNet(), windows_client=FakeWindows(),
                        velo_client=FakeVelo())
    result = facade.verify(COMMAND_ID)
    assert result.get('error') is None
    assert result['verdict'] == 'unknown'
    assert len(json.dumps(result).encode()) <= 65536
    from fakenet.mcp.schemas import VerificationResult
    VerificationResult.model_validate(result)
    assert result['steps'][0]['observed']['summary']['returncode'] == 0
    assert result['steps'][0]['observed']['raw_observation_ref'].endswith('/steps/0/observed')
    raw = next(e for e in result['manifest']['entries'] if e.get('id') == 'unabridged-result')
    raw_path = Path(raw['path'])
    assert hashlib.sha256(raw_path.read_bytes()).hexdigest() == raw['sha256']
    full = json.loads(raw_path.read_text())
    assert full['steps'][0]['observed']['stdout'] == 'adapter details ' * 10000
    assert [(s['id'], s['outcome'], s.get('reason_code')) for s in result['steps']] == [
        (s['id'], s['outcome'], s.get('reason_code')) for s in full['steps']]
    assert result['checks'] == full['checks']
    assert result['conclusion'] == full['conclusion']
    assert facade.verify(COMMAND_ID)['verdict'] == 'unknown'
    raw_path.write_text('{}')
    assert facade.verify(COMMAND_ID)['error']['code'] == 'stale_result'


def test_repeated_long_evidence_keeps_native_fail_and_all_steps(tmp_path, monkeypatch):
    """Native-sized provenance must not turn an executed fail into not_run."""
    original = host_merge.build_host_result
    unabridged = {}

    class NativeFailWindows(FakeWindows):
        def probe(self, script, timeout=None):
            value, raw = super().probe(script, timeout=timeout)
            for row in value.get('steps', []):
                if row['id'] == 'ipv4_tcp_139':
                    row.update(received='unexpected echo', outcome='response')
            return value, raw

    def with_repeated_evidence(**kwargs):
        result = original(**kwargs)
        refs = []
        for index in range(4):
            path = tmp_path / ('native-evidence-' + 'x' * 150) / str(index)
            path.parent.mkdir(exist_ok=True)
            path.write_text('benign reference')
            refs.append({'side': 'host', 'path': str(path),
                         'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                         'kind': 'native-provenance'})
        result['manifest']['entries'].extend(refs)
        for step in result['steps']:
            step['evidence_refs'] = [dict(ref) for ref in refs]
        assert any(step['outcome'] == 'fail' for step in result['steps'])
        assert result['verdict'] == 'fail'
        unabridged.update(json.loads(json.dumps(result)))
        return result

    monkeypatch.setattr(host_merge, 'build_host_result', with_repeated_evidence)
    facade = HostFacade(config_for(tmp_path), provider=FakeProvider(),
                        fakenet_client=FakeFakeNet(), windows_client=NativeFailWindows(),
                        velo_client=FakeVelo())
    result = facade.verify(COMMAND_ID)
    assert result.get('error') is None
    assert len(json.dumps(result, ensure_ascii=False).encode()) <= 65536
    assert result['verdict'] == unabridged['verdict'] == 'fail'
    assert result['coverage'] == unabridged['coverage']
    assert result['helper_input'] == unabridged['helper_input']
    assert result['checks'] == unabridged['checks']
    assert [(s['id'], s['outcome'], s['expected'], s['reason_code'],
             s['started_at'], s['ended_at']) for s in result['steps']] == [
        (s['id'], s['outcome'], s['expected'], s['reason_code'],
         s['started_at'], s['ended_at']) for s in unabridged['steps']]
    entries = {e['id']: e for e in result['manifest']['entries'] if e.get('id')}
    for step in result['steps']:
        for ref in step['evidence_refs']:
            if ref.get('json_pointer'):
                continue
            entry = entries[ref['id']]
            assert Path(entry['path']).is_file()
            assert hashlib.sha256(Path(entry['path']).read_bytes()).hexdigest() == entry['sha256']
    from fakenet.mcp.schemas import VerificationResult
    VerificationResult.model_validate(result)
    replay = facade.verify(COMMAND_ID)
    assert replay['verdict'] == 'fail'
    assert replay['steps'] == result['steps']


def test_listener_usessl_selects_tls_probe():
    content = ('[Diverter]\nRedirectAllTraffic = Yes\n'
               '[HTTPListener443]\nEnabled = True\nPort = 443\n'
               'Protocol = TCP\nListener = HTTPListener\nUseSSL = Yes\n')
    from fakenet.mcp.host_stdio import parse_fakenet_config
    parsed = parse_fakenet_config(content)
    rows = host_probe.expected_steps(
        mapped_ports=parsed['mapped_ports'],
        listener_map=parsed['listener_map'], nonce='nonce')
    assert parsed['listener_map'][443] == 'httplistener:tls'
    assert rows['ipv4_tcp_443']['probe_kind'] == 'tcp_tls'


def test_listener_usessl_no_keeps_plain_http_even_with_legacy_ssl_yes():
    from fakenet.mcp.host_stdio import parse_fakenet_config
    parsed = parse_fakenet_config(
        '[HTTP]\nEnabled = True\nPort = 80\nListener = HTTPListener\n'
        'UseSSL = No\nSSL = Yes\n')
    assert parsed['listener_map'][80] == 'httplistener'


@pytest.mark.parametrize('change', ['name', 'sha256', 'missing'])
def test_actual_loaded_config_must_match_read_configuration_before_probe(tmp_path, change):
    class OtherConfig(FakeFakeNet):
        def get_status(self, timeout=None):
            value = super().get_status(timeout)
            if change == 'missing':
                value.pop('config_identity')
            else:
                value['config_identity'][change] = 'other.ini' if change == 'name' else 'd' * 64
            return value
    windows = FakeWindows()
    result = HostFacade(config_for(tmp_path), provider=FakeProvider(),
                        fakenet_client=OtherConfig(), windows_client=windows,
                        velo_client=FakeVelo()).verify(COMMAND_ID)
    assert result['error']['code'] == 'state_conflict'
    assert windows.calls == 0


@pytest.mark.parametrize('change', ['active_config', 'read_config', 'nic', 'session'])
def test_replay_revalidates_actual_config_network_and_execution_context(tmp_path, change):
    class CurrentConfig(FakeFakeNet):
        changed = False
        def get_status(self, timeout=None):
            value = super().get_status(timeout)
            if self.changed and change == 'active_config':
                value['config_identity']['sha256'] = 'd' * 64
            return value
        def read_config(self, name, timeout=None):
            value = super().read_config(name, timeout)
            if self.changed and change == 'read_config': value['sha256'] = 'd' * 64
            return value
    class CurrentProvider(FakeProvider):
        changed = False
        def snapshot(self, deadline=None):
            value = super().snapshot(deadline)
            if self.changed and change == 'nic': value['vmx']['nics'][0]['interface'] = 'vmnet8'
            return value
    class CurrentWindows(FakeWindows):
        changed = False
        def probe(self, script, timeout=None):
            value, raw = super().probe(script, timeout)
            if self.changed and change == 'session': value['identity']['session'] = 7
            return value, raw
    fakenet, provider, windows = CurrentConfig(), CurrentProvider(), CurrentWindows()
    facade = HostFacade(config_for(tmp_path), provider=provider,
                        fakenet_client=fakenet, windows_client=windows, velo_client=FakeVelo())
    first = facade.verify(COMMAND_ID)
    assert first['error'] is None
    fakenet.changed = provider.changed = windows.changed = True
    replay = facade.verify(COMMAND_ID)
    assert replay['error']['code'] == 'stale_result'
    assert fakenet.calls.count('verify_egress') == 1


@pytest.mark.parametrize('matches', [False, True])
def test_modified_analysis_config_requires_matching_guest_subset(tmp_path, matches):
    config = config_for(tmp_path)
    config['fakenet_mcp']['config_name'] = 'sample-analysis.ini'
    source = Path(config['probe_authorization']['source_ref'])
    scope = json.loads(source.read_text())
    scope['objects']['config_name'] = 'sample-analysis.ini'
    source.write_text(json.dumps(scope))
    config['probe_authorization']['source_sha256'] = hashlib.sha256(source.read_bytes()).hexdigest()
    class AnalysisConfig(FakeFakeNet):
        def get_status(self, timeout=None):
            value = super().get_status(timeout)
            value['config_identity']['name'] = 'sample-analysis.ini'
            return value
        def verify_egress(self, command_id, expected_state_version, request, timeout=None):
            value = super().verify_egress(command_id, expected_state_version, request, timeout)
            if matches:
                value['verification']['bindings']['config_identity']['name'] = 'sample-analysis.ini'
            return value
    client = AnalysisConfig()
    result = HostFacade(config, provider=FakeProvider(), fakenet_client=client,
                        windows_client=FakeWindows(), velo_client=FakeVelo()).verify(COMMAND_ID)
    if matches:
        assert result['error'] is None and result['coverage']['matrix_executed'] == 30
        assert result['bindings']['config_identity']['name'] == 'sample-analysis.ini'
    else:
        assert result['error']['code'] == 'state_conflict'
