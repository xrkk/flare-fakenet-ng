# -*- coding: utf-8 -*-
"""Validator rule tests (plan v0.2 §5.3)."""

import hashlib
import os

import pytest

from fakenet.gui import configmodel, schema, validator

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIGS = os.path.join(REPO, 'fakenet', 'configs')


def build():
    """A model shaped like default.ini (all shipped sections present)."""
    model = configmodel.ConfigModel.load(os.path.join(CONFIGS, 'default.ini'))
    return model


def errors(model):
    return [i for i in validator.validate(model) if i.level ==
            validator.ERROR]


def warnings(model):
    return [i for i in validator.validate(model) if i.level ==
            validator.WARNING]


def by_key(issues, key):
    return [i for i in issues if i.key.lower() == key.lower()]


# -- Rule 1: section naming -------------------------------------------------

def test_section_name_case_error():
    model = build()
    model.rename_section('FakeNet', 'fakenet')
    errs = errors(model)
    assert any('段名大小写错误' in i.message for i in errs)


# -- Rule 2: listener structure ----------------------------------------------

def test_missing_enabled_port_protocol():
    model = build()
    sec = model.ensure_section('Bare')
    errs = errors(model)
    assert by_key(errs, 'Enabled') and by_key(errs, 'Port') and \
        by_key(errs, 'Protocol')


def test_bad_enabled_literal():
    model = build()
    model.section('DNS Server').set('Enabled', 'enable')
    assert by_key(errors(model), 'Enabled')


def test_bad_protocol_and_listener_class():
    model = build()
    model.section('DNS Server').set('Protocol', 'ICMP')
    model.section('DNS Server').set('Listener', 'dnslistener')  # case
    errs = errors(model)
    assert by_key(errs, 'Protocol') and by_key(errs, 'Listener')


def test_port_out_of_range():
    model = build()
    model.section('DNS Server').set('Port', '70000')
    assert by_key(errors(model), 'Port')


def test_protocol_port_duplicate_binding():
    model = build()
    sec = model.ensure_section('Second53')
    sec.set('Enabled', 'True')
    sec.set('Port', '53')
    sec.set('Protocol', 'UDP')
    sec.set('Listener', 'DNSListener')
    errs = by_key(errors(model), 'Port')
    assert any('重复绑定' in i.message for i in errs)


def test_expansion_name_collision():
    model = build()
    sec = model.ensure_section('FTPListenerPASV_60000')  # collides with the
    sec.set('Enabled', 'False')                          # expanded instance
    sec.set('Port', '1234')
    sec.set('Protocol', 'TCP')
    errs = by_key(errors(model), 'Port')
    assert any('冲突' in i.message for i in errs)


# -- Rule 3: exclusivity / redirect defaults / [FakeNet] --------------------

def test_process_list_exclusivity():
    model = build()
    model.diverter().set('ProcessWhiteList', 'a.exe')
    model.diverter().set('ProcessBlackList', 'b.exe')
    errs = errors(model)
    assert any('进程白/黑名单互斥' in i.message for i in errs)


def test_host_list_exclusivity_listener_level():
    model = build()
    model.section('Forwarder').set('Enabled', 'True')
    model.section('Forwarder').set('HostWhiteList', '1.1.1.1')
    model.section('Forwarder').set('HostBlackList', '2.2.2.2')
    errs = errors(model)
    assert any('主机白/黑名单互斥' in i.message for i in errs)


def test_redirect_default_listener_must_exist():
    model = build()
    model.diverter().set('DefaultUDPListener', 'NoSuchSection')
    assert any('不是已存在的监听器段名' in i.message for i in errors(model))


def test_diverttraffic_requires_networkmode():
    model = build()
    model.diverter().delete('NetworkMode')
    assert by_key(errors(model), 'NetworkMode')


# -- Rule 4: policy core ------------------------------------------------------

def enable_policy(model):
    model.fakenet().set('DivertTraffic', 'Yes')
    model.diverter().set('ExternalAccessPolicy', 'DomainAllowList')
    model.diverter().set('ExternalAllowedDomains', 'api.deepseek.com')
    model.diverter().set('ExternalDnsServer', '8.8.8.8')
    return model


def test_policy_requires_diverttraffic_yes():
    model = build()
    enable_policy(model)
    model.fakenet().set('DivertTraffic', 'true')  # not literal yes
    assert by_key(errors(model), 'DivertTraffic')


def test_locked_resource_value_rejected():
    model = build()
    enable_policy(model)
    model.diverter().set('ExternalMaxPendingFlows', '512')
    errs = by_key(errors(model), 'ExternalMaxPendingFlows')
    assert any('代码强制' in i.message for i in errs)


def test_policy_topology_missing_pieces():
    model = build()
    enable_policy(model)
    # default.ini has relay disabled and DNS TCP disabled.
    errs = errors(model)
    assert any('DomainEgressRelay 监听器段' in i.message for i in errs)
    assert any('DNSListener 监听器' in i.message for i in errs)


def test_policy_topology_after_autofix():
    model = build()
    enable_policy(model)
    validator.ensure_domain_allowlist_topology(model)
    assert not by_key(errors(model), 'ExternalAccessPolicy')
    assert not by_key(errors(model), 'Port')


def test_relay_port_occupied_by_other_listener():
    model = build()
    enable_policy(model)
    validator.ensure_domain_allowlist_topology(model)
    model.section('RawTCPListener').set('Port', '38927')
    assert any('不得占用 TLS 中继端口' in i.message for i in errors(model))


def test_bad_upstream_dns():
    model = build()
    enable_policy(model)
    model.diverter().set('ExternalDnsServer', '127.0.0.1')
    assert by_key(errors(model), 'ExternalDnsServer')


def test_bad_domain_name():
    model = build()
    enable_policy(model)
    model.diverter().set('ExternalAllowedDomains', 'http://x.com')
    assert by_key(errors(model), 'ExternalAllowedDomains')


# -- Rule 5: takeover ---------------------------------------------------------

def enable_takeover(model, sink='192.168.204.1', domains=None):
    enable_policy(model)
    validator.ensure_domain_allowlist_topology(model)
    model.diverter().set('ExternalTakeoverIPv4', sink)
    model.diverter().set('ExternalTakeoverDnsTTL', '60')
    if domains:
        model.diverter().set('ExternalAllowedDomains', domains)
    return model


def test_takeover_requires_rfc1918():
    model = enable_takeover(build(), sink='8.8.8.8')
    assert by_key(errors(model), 'ExternalTakeoverIPv4')


def test_takeover_ttl_range():
    model = enable_takeover(build())
    model.diverter().set('ExternalTakeoverDnsTTL', '999')
    assert by_key(errors(model), 'ExternalTakeoverDnsTTL')


def test_takeover_domain_lock():
    model = enable_takeover(build(), domains='example.com')
    assert any('仅允许 api.deepseek.com' in i.message
               for i in errors(model))


def test_takeover_action_lock():
    model = enable_takeover(build())
    model.diverter().set('ExternalNonAllowedAction', 'Drop')
    assert by_key(errors(model), 'ExternalNonAllowedAction')


def test_takeover_responsea_coupling():
    model = enable_takeover(build())
    model.section('DNS Server').set('ResponseA', '10.0.0.1')
    assert by_key(errors(model), 'ResponseA')


def test_takeover_sink_equals_dns_rejected():
    model = enable_takeover(build())
    model.diverter().set('ExternalDnsServer', '192.168.204.1')
    assert by_key(errors(model), 'ExternalTakeoverIPv4')


def test_autofix_fills_responsea_from_sink():
    model = build()
    enable_policy(model)
    model.diverter().set('ExternalTakeoverIPv4', '192.168.204.1')
    model.diverter().set('ExternalTakeoverDnsTTL', '60')
    # Autofix only fills empty ResponseA values (plan: 已有值不动).
    model.section('DNS Server').set('ResponseA', '')
    model.section('DNS TCP Server').set('ResponseA', '')
    changes = validator.ensure_domain_allowlist_topology(model)
    assert model.section('DNS Server').get('ResponseA') == '192.168.204.1'
    assert model.section('DNS TCP Server').get('ResponseA') == '192.168.204.1'
    assert changes


# -- Rule 6: reviewed IPv4 rules ----------------------------------------------

def test_reviewed_rules_present_but_empty():
    model = build()
    enable_policy(model)
    model.diverter().set('ExternalAllowedIPv4Rules', '')
    assert any('键存在但为空' in i.message for i in errors(model))


def test_reviewed_rules_reject_private_ip():
    model = build()
    enable_policy(model)
    model.diverter().set('ExternalAllowedIPv4Rules', 'TCP/192.168.1.1/443')
    assert any('全球单播' in i.message for i in errors(model))


def test_reviewed_rules_syntax_and_port():
    model = build()
    enable_policy(model)
    model.diverter().set('ExternalAllowedIPv4Rules',
                         'TCP/110.242.69.21/99999')
    assert any('端口须为' in i.message for i in errors(model))


def test_reviewed_rules_count_limits():
    model = build()
    enable_policy(model)
    rules = ','.join('TCP/110.242.69.%d/443' % (i + 1) for i in range(17))
    model.diverter().set('ExternalAllowedIPv4Rules', rules)
    errs = errors(model)
    assert any('最多 16 个不同 IPv4' in i.message for i in errs)


# -- Rule 7: process redirect --------------------------------------------------

def enable_process_redirect(model, path=None, sha=None, a='110.242.69.21',
                            b='192.168.204.1'):
    enable_policy(model)
    validator.ensure_domain_allowlist_topology(model)
    model.diverter().set('ExternalTakeoverIPv4', '192.168.204.100')
    model.diverter().set('ExternalTakeoverDnsTTL', '60')
    model.diverter().set('ExternalProcessRedirectEnabled', 'Yes')
    model.diverter().set('ExternalProcessRedirectProtocol', 'TCP')
    if path is None:
        path = os.path.join(CONFIGS, 'default.ini')
    model.diverter().set('ExternalProcessRedirectImagePath', path)
    if sha is None:
        if os.path.isfile(path):
            with open(path, 'rb') as handle:
                sha = hashlib.sha256(handle.read()).hexdigest()
        else:
            sha = 'a' * 64
    model.diverter().set('ExternalProcessRedirectImageSHA256', sha)
    model.diverter().set('ExternalProcessRedirectOriginalIPv4', a)
    model.diverter().set('ExternalProcessRedirectTargetIPv4', b)
    return model


def test_process_redirect_valid_config_clean():
    model = enable_process_redirect(build())
    assert not by_key(errors(model), 'ExternalProcessRedirectImagePath')
    assert not by_key(errors(model), 'ExternalProcessRedirectOriginalIPv4')
    assert not by_key(errors(model), 'ExternalProcessRedirectTargetIPv4')


def test_process_redirect_missing_fields():
    model = build()
    enable_policy(model)
    model.diverter().set('ExternalProcessRedirectEnabled', 'Yes')
    errs = errors(model)
    assert by_key(errs, 'ExternalProcessRedirectImagePath')
    assert by_key(errs, 'ExternalProcessRedirectImageSHA256')


def test_process_redirect_relative_path_rejected():
    model = enable_process_redirect(build(), path='relative/x.exe')
    assert by_key(errors(model), 'ExternalProcessRedirectImagePath')


def test_process_redirect_bad_sha():
    model = enable_process_redirect(build(), sha='deadbeef')
    assert by_key(errors(model), 'ExternalProcessRedirectImageSHA256')


def test_process_redirect_ip_classes():
    model = enable_process_redirect(build(), a='192.168.1.1')
    assert by_key(errors(model), 'ExternalProcessRedirectOriginalIPv4')
    model = enable_process_redirect(build(), b='8.8.8.8')
    assert by_key(errors(model), 'ExternalProcessRedirectTargetIPv4')
    model = enable_process_redirect(build(), b='110.242.69.21')
    assert any('B 不得等于' in i.message or '不得等于' in i.message
               for i in by_key(errors(model),
                               'ExternalProcessRedirectTargetIPv4'))


def test_process_redirect_conflicts_with_takeover_sink():
    model = enable_process_redirect(build(), b='192.168.204.100')
    assert by_key(errors(model), 'ExternalProcessRedirectTargetIPv4')


# -- Rule 8: general ------------------------------------------------------------

def test_placeholder_detection():
    model = build()
    model.diverter().set('ExternalDnsServer', '__EXTERNAL_DNS__')
    errs = errors(model)
    assert any('占位符' in i.message for i in errs)


def test_execute_cmd_bad_token():
    model = build()
    model.section('DNS Server').set('ExecuteCmd', 'cmd {bad_token}')
    assert any('占位符' in i.message and 'bad_token' in i.message
               for i in errors(model))


def test_bare_percent_warning():
    model = build()
    model.diverter().set('DumpPacketsFilePrefix', 'a%b')
    assert any('%' in i.message for i in warnings(model))


def test_non_ascii_warning():
    model = build()
    model.section('DNS Server').set('ResponseTXT', '横幅')
    assert any('非 ASCII' in i.message for i in warnings(model))


def test_missing_path_warning_only():
    model = build()
    model.section('HTTPListener80').set('Webroot', 'no_such_dir/')
    issues = warnings(model)
    assert any('路径不存在' in i.message for i in issues)
    assert not by_key(errors(model), 'Webroot')


# -- custom response file --------------------------------------------------------

def test_custom_response_validation():
    model = configmodel.ConfigModel.load(
        os.path.join(CONFIGS, 'sample_custom_response.ini'))
    model.kind = 'custom'
    assert not errors(model)

    bad = configmodel.ConfigModel.new_config()
    bad.kind = 'custom'
    sec = bad.ensure_section('ExampleBad')
    sec.set('ListenerType', 'HTTP')
    errs = errors(bad)
    assert any('至少其一' in i.message for i in errs)
    assert any('恰好选一' in i.message for i in errs)

    sec.set('HttpStaticString', 'x')
    sec.set('HttpRawFile', 'y')
    sec.set('HttpURIs', '/a')
    errs = errors(bad)
    assert any('恰好选一' in i.message for i in errs)
