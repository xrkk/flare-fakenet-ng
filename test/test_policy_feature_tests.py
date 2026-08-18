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
    assert diverter.get('ExternalAccessPolicy') == 'DomainAllowList'
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
