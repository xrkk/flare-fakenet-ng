# Copyright 2026 Google LLC
"""Firewall command construction (P01 IMP-P01-05; no netsh executed here)."""

from fakenet.mcp import firewall


def test_add_command_shape():
    command = firewall.build_add_command(28788, ['192.168.204.1'])
    assert command[:6] == ['netsh', 'advfirewall', 'firewall', 'add',
                           'rule', 'name=FakeNet-NG MCP']
    rest = command[6:]
    assert 'dir=in' in rest
    assert 'action=allow' in rest
    assert 'protocol=TCP' in rest
    assert 'localport=28788' in rest
    assert 'remoteip=192.168.204.1' in rest


def test_add_command_multiple_hosts():
    command = firewall.build_add_command(1234, ['10.0.0.1', '10.0.0.2'])
    assert 'remoteip=10.0.0.1,10.0.0.2' in command
    assert 'localport=1234' in command


def test_delete_and_show_command_shape():
    delete = firewall.build_delete_command()
    assert delete[:6] == ['netsh', 'advfirewall', 'firewall', 'delete',
                          'rule', 'name=FakeNet-NG MCP']
    show = firewall.build_show_command()
    assert show[:6] == ['netsh', 'advfirewall', 'firewall', 'show',
                        'rule', 'name=FakeNet-NG MCP']
    assert 'verbose' in show
