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


def test_verify_rule_rejects_wider_disabled_or_wrong_direction(monkeypatch):
    import json
    from types import SimpleNamespace
    good = dict(Enabled='True', Direction='Inbound', Action='Allow',
                Profile='Any', Protocol='TCP', LocalPort=['28788'],
                RemotePort=['Any'], RemoteAddress=['192.168.204.1'])
    def check(row):
        monkeypatch.setattr(firewall, '_run', lambda _: SimpleNamespace(
            returncode=0, stdout=json.dumps(row), stderr=''))
        return firewall.verify_rule(28788, ['192.168.204.1'])[0]
    assert check(good)
    for field, value in [('Enabled', 'False'), ('Direction', 'Outbound'),
                         ('Action', 'Block'), ('Protocol', 'UDP'),
                         ('Profile', 'Private'),
                         ('LocalPort', ['28788', '80']),
                         ('RemoteAddress', ['192.168.204.1', 'Any'])]:
        assert not check(dict(good, **{field: value})), field
    assert not check([good, good])
