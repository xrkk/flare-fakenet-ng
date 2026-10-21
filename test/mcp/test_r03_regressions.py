"""R03 regressions for the eight R02 review facts and helper consistency."""
import importlib.util
import json
from pathlib import Path

from fakenet.mcp import egress_contract, egress_verification, host_probe


def load(name, relative):
    path = Path(__file__).parent / relative
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


host_merge_fixture = load('r03_merge_fixture', 'test_host_merge.py')
facade_fixture = load('r03_facade_fixture', 'test_host_stdio.py')


def test_r2_01_helper_recomputes_the_same_incomplete_status():
    expected = host_probe.expected_steps(nonce='nonce')
    probe = host_merge_fixture.probe_result(expected, matrix_run=False)
    probe['steps'] = []
    result = host_merge_fixture.build(probe, expected)
    helper = egress_contract.evaluate_interception_qualification(
        **result['helper_input'])
    assert result['verdict'] != 'pass'
    assert helper['status'] == 'underdetermined'
    assert helper['sample_path_qualified'] is False
    assert result['conclusion']['status'] == helper['status']


def test_r2_02_sample_context_requires_token_policy_and_launcher_facts():
    identity = dict(host_merge_fixture.IDENTITY)
    sample = dict(host_merge_fixture.SAMPLE)
    assert egress_contract.sample_context_matches(identity, sample) is True
    for key in ('token_integrity_level', 'launcher_path', 'launcher_sha256',
                'protocol_class'):
        broken = dict(sample)
        broken.pop(key)
        assert egress_contract.sample_context_matches(
            identity, broken) is None
    sample['image_path'] = 'E:\\different-sample.exe'
    sample['image_sha256'] = 'z' * 64
    assert egress_contract.sample_context_matches(identity, sample) is True
    # AppLocker/other policy_scope is optional and not a substitute for
    # FakeNet process rules.
    sample.pop('policy_scope', None)
    assert egress_contract.sample_context_matches(identity, sample) is True


def dns_observation(step, question):
    return {
        'id': step['id'], 'outcome': 'response', 'sent': 30,
        'received': 'dns-bytes=40', 'error': None,
        'response_type': 'dns', 'status': None, 'nonce_match': True,
        'address_family': 'InterNetwork', 'remote_endpoint':
            '%s:53' % step['destination'], 'local_endpoint': '192.0.2.10:1',
        'transaction_id': step['dns_txid'], 'question': question,
        'qtype': 1, 'qclass': 1, 'qr': True, 'rcode': 0,
    }


def test_r2_03_dns_question_is_parsed_not_trusted_from_request():
    step = next(item for item in host_probe.expected_steps(
        nonce='nonce').values() if item['kind'] == 'dns')
    wrong = dns_observation(step, 'UNRELATED.invalid')
    outcome, reason = host_probe.classify_step(step, wrong, 'local_fake')
    assert outcome != 'pass'
    assert reason == 'dns_question_mismatch'
    exact = dns_observation(step, step['question'])
    outcome, reason = host_probe.classify_step(step, exact, 'local_fake')
    assert (outcome, reason) == ('pass', 'strict_dns_transaction_response')


def test_r2_07_udp_and_dns_scripts_set_local_endpoint():
    script = host_probe.probe_script(
        'nonce', host_probe.matrix_steps(1, 2, 'nonce'))
    assert script.count('$result.local_endpoint=[string]$client.Client.LocalEndPoint') >= 2
    step = next(item for item in host_probe.expected_steps(
        nonce='nonce').values() if item['kind'] == 'udp')
    valid = {
        'id': step['id'], 'outcome': 'response', 'sent': 12,
        'received': 'MALTRACE-EGRESS-nonce', 'error': None,
        'response_type': 'udp_nonce', 'status': None, 'nonce_match': True,
        'address_family': 'InterNetwork',
        'remote_endpoint': '%s:%s' % (step['destination'], step['port']),
        'local_endpoint': '192.0.2.10:50000', 'elapsed_ms': 2,
    }
    assert host_probe.classify_step(step, valid, 'local_fake')[0] == 'pass'
    missing = dict(valid, local_endpoint='')
    assert host_probe.classify_step(step, missing, 'local_fake')[0] != 'pass'


def test_r2_08_filter_outer_or_and_not_cannot_bypass_control_ports(tmp_path):
    bad = egress_verification.parse_control_filter(
        'outbound and tcp.SrcPort != 28787 and tcp.SrcPort != 28788 '
        'and tcp.SrcPort != 28790 or true')
    assert bad['ok'] is False
    negated = egress_verification.parse_control_filter(
        'not (tcp.SrcPort != 28787 and tcp.SrcPort != 28788 '
        'and tcp.SrcPort != 28790)')
    assert negated['ok'] is False
    real = egress_verification.parse_control_filter(
        '(ip.DstAddr != 192.168.204.1 or '
        '(tcp.SrcPort != 28787 and tcp.SrcPort != 28788 '
        'and tcp.SrcPort != 28790))')
    assert real['ok'] is True
    assert real['ports'] == [28787, 28788, 28790]


def test_r2_06_stale_wrong_nonce_or_creation_never_matches(tmp_path, monkeypatch):
    import time
    from datetime import datetime, timezone, timedelta
    artifacts = tmp_path / 'artifacts'
    log = artifacts / 'runs' / 'run-1' / 'run.log'
    log.parent.mkdir(parents=True)
    now = time.time()
    log.write_text(
        '10/20/26 11:00:00 AM DIVERT_FAKE pid=777 creation=999 '
        'probe_nonce=NEW src=192.0.2.10 sport=40000 dst=198.51.100.77 '
        'dport=1337 proto=TCP process=powershell.exe epoch=%d\n' % int(now),
        encoding='utf-8')
    started = (datetime.now(timezone.utc) - timedelta(seconds=2)).isoformat()
    ended = (datetime.now(timezone.utc) + timedelta(seconds=2)).isoformat()
    monkeypatch.setattr(egress_verification.paths, 'data_directories',
                        lambda: {'artifacts': str(artifacts)})
    payload = {
        'host_probe_pid': 777, 'host_probe_creation': 999,
        'probe_nonce': 'NEW', 'host_probe_started': started,
        'host_probe_ended': ended,
        'host_probe_destination': '198.51.100.77', 'host_probe_port': 1337,
        'host_probe_source': '192.0.2.10',
        'host_probe_source_port': 40000, 'host_probe_protocol': 'TCP',
    }
    assert egress_verification._producer_match('run-1', payload)['value'] is True
    outside = dict(payload, host_probe_started=(
        datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
        host_probe_ended=(datetime.now(timezone.utc) - timedelta(minutes=59)))
    assert egress_verification._producer_match('run-1', outside)['value'] is False
    old = dict(payload, host_probe_creation=1)
    assert egress_verification._producer_match('run-1', old)['value'] is False
    wrong_nonce = dict(payload, probe_nonce='OLD')
    assert egress_verification._producer_match(
        'run-1', wrong_nonce)['value'] is False
    wrong_source = dict(payload, host_probe_source='192.0.2.55',
                        host_probe_source_port=49999,
                        host_probe_protocol='UDP')
    assert egress_verification._producer_match(
        'run-1', wrong_source)['value'] is False


def test_r2_02_rejected_authorization_still_returns_fixed_matrix_plan(tmp_path):
    from fakenet.mcp.host_stdio import HostFacade
    config = facade_fixture.config_for(tmp_path)
    config['probe_authorization']['authorized'] = False
    facade = HostFacade(config, provider=facade_fixture.FakeProvider(),
                        fakenet_client=facade_fixture.FakeFakeNet(),
                        windows_client=facade_fixture.FakeWindows(),
                        velo_client=facade_fixture.FakeVelo())
    result = facade.verify(facade_fixture.COMMAND_ID)
    assert result['error']['code'] == 'invalid_request'
    assert len(result['steps']) == 30
    assert result['coverage']['matrix_planned'] == 30
    assert all(step['outcome'] == 'not_run' for step in result['steps'])
    assert not (Path(config['state_root']) / (facade_fixture.COMMAND_ID +
                                              '.json')).exists()


def test_listener_specific_probe_kinds_are_not_http_or_same_udp():
    rows = host_probe.expected_steps(
        mapped_ports=[80, 53], redirect_all=False, nonce='nonce',
        listener_map={80: 'httplistener', 53: 'dnslistener'})
    assert rows['ipv4_tcp_80']['probe_kind'] == 'tcp_http'
    assert rows['ipv4_dns_nonce_invalid']['probe_kind'] == 'dns'
    assert rows['ipv4_tcp_443']['probe_kind'] == 'unknown'
    assert rows['ipv4_tcp_443']['expected'] == 'unknown'
    raw = host_probe.expected_steps(
        redirect_all=True, nonce='nonce', listener_map={})
    assert raw['ipv4_tcp_80']['probe_kind'] == 'tcp_raw'
    assert raw['ipv4_udp_53']['probe_kind'] == 'udp_raw'


def test_r3_01_applocker_unavailable_is_not_a_normal_blocker(tmp_path):
    class UnknownPolicy(facade_fixture.FakeWindows):
        def probe(self, script, timeout=None):
            value, raw = super().probe(script, timeout)
            value['identity']['policy_scope'] = 'unknown'
            return value, raw
    facade = facade_fixture.HostFacade(
        facade_fixture.config_for(tmp_path),
        provider=facade_fixture.FakeProvider(),
        fakenet_client=facade_fixture.FakeFakeNet(),
        windows_client=UnknownPolicy(), velo_client=facade_fixture.FakeVelo())
    result = facade.verify(facade_fixture.COMMAND_ID)
    assert result['error'] is None
    assert result['verdict'] == 'unknown'
    assert result['checks']['sample_path_equivalent']['value'] is True


def test_r3_process_rules_cover_sample_and_probe():
    empty = {'global': {'white': [], 'black': [], 'host_white': [],
                        'host_black': []}, 'listeners': {}}
    assert egress_contract.process_rules_match(
        'E:\\sample.exe', 'C:\\powershell.exe', empty) is True
    no_global = {'global': {'white': [], 'black': ['sample.exe'],
                            'host_white': [], 'host_black': []},
                 'listeners': {}}
    assert egress_contract.process_rules_match(
        'E:\\sample.exe', 'C:\\powershell.exe', no_global) is False
    listener_black = {'global': empty['global'], 'listeners': {1337: {
        'white': [], 'black': ['sample.exe'], 'host_white': [],
        'host_black': []}}}
    assert egress_contract.process_rules_match(
        'E:\\sample.exe', 'C:\\powershell.exe', listener_black) is False


def test_r3_04_positive_starts_before_send_and_early_stop_partial():
    script = host_probe.probe_script(
        'a' * 32, host_probe.matrix_steps(50001, 50002, 'a' * 32))
    assert script.index('$positiveStarted=') < script.index('$ar=$echoClient.BeginConnect')
    assert 'AsyncWaitHandle.Dispose' in script
    assert 'stop_remaining' in script
    ids = [row['id'] for row in host_probe.matrix_steps(50001, 50002)]
    value = {
        'schema': host_probe.PROBE_SCHEMA, 'nonce': 'a' * 32,
        'instance': {'pid': 1, 'creation_ticks': 2, 'nonce': 'a' * 32,
                     'script_hash': 'x'},
        'identity': {}, 'positive': None, 'matrix_run': True,
        'stop_remaining': True, 'steps': [{'id': ids[0], 'outcome': 'response'}],
    }
    host_probe.validate_probe_result(
        value, ids, nonce='a' * 32, positive_required=False)
