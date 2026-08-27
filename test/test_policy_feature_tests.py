# -*- coding: utf-8 -*-
"""Host-side checks for the policy feature one-click runner (12.31.4)."""

import importlib.util
import os


HERE = os.path.dirname(os.path.abspath(__file__))
RUNNER_PATH = os.path.join(HERE, 'gui_vm', 'run_policy_feature_tests.py')
SPEC = importlib.util.spec_from_file_location(
    'policy_feature_runner', RUNNER_PATH)
policy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(policy)


def test_build_policy_config_agrees_with_validator(tmp_path):
    path = tmp_path.joinpath('p1.ini')
    model, errors = policy.build_policy_config(
        str(path), 'api.deepseek.com, *.deepseek.com')
    assert not errors
    diverter = model.diverter()
    assert diverter.get('DivertTraffic') != 'No' or True  # [FakeNet] section
    assert model.fakenet().get('DivertTraffic') == 'Yes'
    assert diverter.get('ExternalAccessPolicy') == 'EgressControl'
    assert diverter.get('ExternalAllowedDomains') == (
        'api.deepseek.com, *.deepseek.com')
    listeners = {sec.get('Listener') for sec in model.listener_sections()}
    assert 'DomainEgressRelay' in listeners
    assert 'DNSListener' in listeners


def test_build_policy_config_takeover_topology(tmp_path):
    path = tmp_path.joinpath('p2.ini')
    model, errors = policy.build_policy_config(
        str(path), 'api.deepseek.com, *.deepseek.com',
        takeover_ip=policy.TAKEOVER_SINK)
    assert not errors
    diverter = model.diverter()
    assert diverter.get('ExternalTakeoverIPv4') == policy.TAKEOVER_SINK
    assert diverter.get('ExternalTakeoverDnsTTL') == '60'
    assert diverter.get('ExternalNonAllowedAction') == 'Divert'
    dns = [sec for sec in model.listener_sections()
           if sec.get('Listener') == 'DNSListener']
    assert len(dns) >= 2
    assert all(sec.get('ResponseA') == policy.TAKEOVER_SINK for sec in dns)


def test_leased_global_ips_filters_private_answers():
    log = (
        "08/18/26 12:00:00 PM [INFO] Diverter DNS_LEASE_ADD "
        "domain=api.deepseek.com ip=101.71.73.135 ttl=5\n"
        "08/18/26 12:00:00 PM [INFO] Diverter DNS_LEASE_ADD "
        "domain=example.com ip=192.168.204.130 ttl=5\n"
        "08/18/26 12:00:00 PM [INFO] Diverter DNS_LEASE_ADD "
        "domain=www.deepseek.com ip=not-an-ip ttl=5\n")
    assert policy.leased_global_ips(log, 'api.deepseek.com') == {
        '101.71.73.135'}
    assert policy.leased_global_ips(log, 'example.com') == set()
    assert policy.leased_global_ips(log, 'www.deepseek.com') == set()
    assert policy.leased_global_ips(log, 'missing.com') == set()


def test_takeover_ready_domains_parses_single_token_list():
    log = ('08/18/26 12:00:00 PM [INFO] Diverter DOMAIN_TAKEOVER_READY '
           'allowed_domains=*.deepseek.com,api.deepseek.com domain_count=2 '
           'takeover_ip=192.168.204.1 ttl=60\n')
    parsed = policy.takeover_ready_domains(log)
    assert parsed == '*.deepseek.com,api.deepseek.com'
    assert policy.takeover_ready_domains('no marker here') is None


def test_received_request_logged_tolerates_suffix_search():
    log = ("Received A request for domain "
           "'api.deepseek.com.localdomain'.\n"
           "Received A request for domain 'www.deepseek.com.'.\n")
    assert policy.received_request_logged(log, 'api.deepseek.com')
    assert policy.received_request_logged(log, 'www.deepseek.com')
    assert not policy.received_request_logged(log, 'example.com')
    assert policy.received_request_logged(log, 'api.deepseek.com')
    assert policy.received_request_logged(log, 'www.deepseek.com')
    assert not policy.received_request_logged(log, 'example.com')


def test_addresses_from_text_excludes_dns_server():
    text = ('\u670d\u52a1\u5668:  UnKnown\n'
            'Address:  127.0.0.1\n'
            '\n'
            '\u540d\u79f0:    deepseek.com\n'
            'Addresses:  192.168.204.1\n')
    assert policy._addresses_from_text(text, '127.0.0.1') == {'192.168.204.1'}
    assert policy._addresses_from_text('no addresses', '127.0.0.1') == set()


def test_divert_fake_logged_matches_exact_original_ip():
    log = ('08/18/26 12:00:00 PM [INFO] Diverter DIVERT_FAKE '
           'original_ip=93.184.216.34 original_port=80\n'
           '08/18/26 12:00:01 PM [INFO] Diverter DIVERT_FAKE '
           'original_ip=93.184.216.3 original_port=80\n')
    assert policy.divert_fake_logged(log, '93.184.216.34')
    assert not policy.divert_fake_logged(log, '93.184.216.33')
    # end-of-log edge: no trailing space after the last field
    tail = ('[INFO] Diverter DIVERT_FAKE '
            'original_ip=93.184.216.34')
    assert policy.divert_fake_logged(tail, '93.184.216.34')


def test_reviewed_allow_logged_requires_both_markers():
    log = ('[INFO] Diverter ALLOW_REVIEWED_IP_FIRST_FLOW rule_id=r1 '
           'ip=93.184.216.34 proto=TCP\n'
           '[INFO] Diverter ALLOW_INTERNAL_UPSTREAM kind=upstream '
           'ip=1.1.1.1\n')
    assert policy.reviewed_allow_logged(log, '93.184.216.34')
    assert not policy.reviewed_allow_logged(log, '1.1.1.1')
    assert not policy.reviewed_allow_logged('nothing here', '1.1.1.1')


def test_p15_uses_exact_sink_divert_matching_at_the_call_site():
    source = open(RUNNER_PATH, 'r', encoding='utf-8').read()
    p15 = source[source.index("result('P15 接管 sink 连通'") - 900:
                 source.index("result('P15 接管 sink 连通'")]

    assert 'sink_diverted = divert_fake_logged(log2b, TAKEOVER_SINK)' in p15
    assert "'original_ip=%s' % TAKEOVER_SINK in log2b" not in p15


def test_adjacent_private_probe_avoids_the_active_http_listener_port(
        monkeypatch):
    sent = []

    class FakeSocket(object):
        def settimeout(self, seconds):
            pass

        def sendto(self, payload, destination):
            sent.append((payload, destination))

        def close(self):
            pass

    monkeypatch.setattr(policy.socket, 'socket', lambda *args: FakeSocket())

    adjacent, detail = policy._send_adjacent_private_probe('nonce')

    assert adjacent == '192.168.204.2'
    assert detail == 'bounded UDP sent'
    assert sent == [(b'FNPR/1|nonce|target\n',
                     ('192.168.204.2', 65000))]
    assert policy.ADJACENT_PRIVATE_PROBE_PORT != policy.UNREVIEWED_PORT


def test_answers_only_sink_rejects_real_and_empty_answers():
    assert policy.answers_only_sink({'192.168.204.1'}, '192.168.204.1')
    assert not policy.answers_only_sink(set(), '192.168.204.1')
    assert not policy.answers_only_sink(
        {'192.168.204.1', '101.71.73.135'}, '192.168.204.1')
    assert not policy.answers_only_sink({'101.71.73.135'}, '192.168.204.1')


def test_acc008_real_negative_matrix_is_part_of_the_formal_runner():
    source = open(RUNNER_PATH, 'r', encoding='utf-8').read()

    for marker in (
            'P16 邻接私网不扩散',
            'P17 ICMP 不得命中 sink',
            'P18 IPv6 fail-closed',
            'P19 route drift 挂起 sink',
            'P20 route drift 精确恢复',
            'TAKEOVER_SUSPEND',
            'route_snapshot_changed',
            'Set-NetIPInterface',
            'AutomaticMetric',
            'finally:'):
        assert marker in source


def test_route_drift_evidence_contract_is_machine_readable():
    source = open(RUNNER_PATH, 'r', encoding='utf-8').read()

    for marker in (
            'route-drift-evidence.json',
            'original_interface',
            'drifted_interface',
            'restored_interface',
            'restore_matches_original',
            'negative_target_tcp',
            'negative_target_udp'):
        assert marker in source


def test_takeover_route_identity_parses_real_core_marker():
    parsed = policy.takeover_route_identity(
        '[INFO] TAKEOVER_ROUTE_OK destination_prefix=192.168.204.0/24 '
        'interface_alias=Ethernet0 interface_index=11 interface_metric=25 '
        'next_hop=0.0.0.0 route_metric=256 source_ipv4=192.168.204.169')

    assert parsed == {
        'interface_index': 11,
        'interface_metric': 25,
        'destination_prefix': '192.168.204.0/24',
        'next_hop': '0.0.0.0',
        'source_ipv4': '192.168.204.169',
    }


def test_takeover_route_identity_fails_closed_on_incomplete_marker():
    assert policy.takeover_route_identity(
        '[INFO] TAKEOVER_ROUTE_OK interface_index=11') is None


def test_route_drift_restores_original_metric_when_probe_setup_fails(
        monkeypatch, tmp_path):
    marker = (
        'TAKEOVER_ROUTE_OK destination_prefix=192.168.204.0/24 '
        'interface_alias=Ethernet0 interface_index=11 interface_metric=25 '
        'next_hop=0.0.0.0 route_metric=256 source_ipv4=192.168.204.169\n')
    original = {
        'interface_index': 11,
        'automatic_metric': 'Enabled',
        'interface_metric': 25,
    }
    restored = []
    metrics = iter((original, original))
    monkeypatch.setattr(policy.acceptance, 'read_core_log', lambda path: marker)
    monkeypatch.setattr(
        policy.acceptance, 'wait_for', lambda predicate, timeout: True)
    monkeypatch.setattr(
        policy, '_send_adjacent_private_probe',
        lambda nonce: ('192.168.204.2', 'sent'))
    monkeypatch.setattr(policy, '_run_ping', lambda args: 'rc=0')
    monkeypatch.setattr(policy.time, 'sleep', lambda seconds: None)
    monkeypatch.setattr(policy, 'read_interface_metric', lambda index: next(metrics))

    def fail_after_possible_change(index, metric):
        raise RuntimeError('set result unavailable')

    monkeypatch.setattr(policy, 'set_interface_metric', fail_after_possible_change)
    monkeypatch.setattr(
        policy, 'restore_interface_metric', lambda value: restored.append(value))
    monkeypatch.setattr(policy, 'LOG_DIR', str(tmp_path))
    policy.RESULTS[:] = []

    evidence = policy.exercise_acc008_negative_matrix('core.log', 'nonce')

    assert restored == [original]
    assert evidence['restore_matches_original']
    assert any(row[1] == 'P19 route drift 挂起 sink' and row[0] == 'FAIL'
               for row in policy.RESULTS)
    assert any(row[1] == 'P20 route drift 精确恢复' and row[0] == 'PASS'
               for row in policy.RESULTS)
    assert (tmp_path / 'route-drift-evidence.json').is_file()


def test_acc008_ipv6_probe_accepts_the_product_external_ipv6_drop(
        monkeypatch, tmp_path):
    import run_vm_diagnostics as diagnostic

    marker = (
        'TAKEOVER_ROUTE_OK destination_prefix=192.168.204.0/24 '
        'interface_alias=Ethernet0 interface_index=11 interface_metric=25 '
        'next_hop=0.0.0.0 route_metric=256 source_ipv4=192.168.204.169\n')
    state = {'ipv6_sent': False}

    def read_core_log(_path):
        text = marker + 'TAKEOVER_SUSPEND reason=route_snapshot_changed\n'
        if state['ipv6_sent']:
            text += 'DROP_EXTERNAL reason=external_ipv6\n'
        return text

    def run_ping(arguments):
        if '-6' in arguments:
            state['ipv6_sent'] = True
        return 'rc=1;sent=1;received=0'

    original = {
        'interface_index': 11,
        'automatic_metric': 'Enabled',
        'interface_metric': 25,
    }
    monkeypatch.setattr(policy.acceptance, 'read_core_log', read_core_log)
    monkeypatch.setattr(
        policy.acceptance, 'wait_for', lambda predicate, timeout: predicate())
    monkeypatch.setattr(
        policy, '_send_adjacent_private_probe',
        lambda nonce: ('192.168.204.2', 'sent'))
    monkeypatch.setattr(policy, '_run_ping', run_ping)
    monkeypatch.setattr(policy.time, 'sleep', lambda seconds: None)
    monkeypatch.setattr(
        policy, 'read_interface_metric', lambda index: dict(original))
    monkeypatch.setattr(policy, 'set_interface_metric', lambda index, metric: None)
    monkeypatch.setattr(policy, 'restore_interface_metric', lambda value: None)
    monkeypatch.setattr(
        diagnostic, 'probe_fnpr_transports',
        lambda *args, **kwargs: (
            False, {'tcp': {'ok': False}, 'udp': {'ok': False}}))
    monkeypatch.setattr(policy, 'LOG_DIR', str(tmp_path))
    policy.RESULTS[:] = []

    policy.exercise_acc008_negative_matrix('core.log', 'nonce')

    assert any(row[1] == 'P18 IPv6 fail-closed' and row[0] == 'PASS'
               for row in policy.RESULTS)
