"""P05 must compare DNS observations, never an empty success marker."""

import importlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def release_module(monkeypatch):
    pytest.importorskip('mcp')
    monkeypatch.syspath_prepend(str(Path(__file__).parent / 'acceptance'))
    return importlib.import_module('run_p05_release')


class Channel:
    def __init__(self, dns):
        self.dns = dns

    def powershell(self, command, timeout):
        if 'Get-DnsClientServerAddress' in command:
            # Recorded Win10 behavior for the old misspelled command:
            # its error is hidden and the final success marker is returned.
            if '-Compass' in command:
                return {'output': 'S', 'exit_code': 0}
            return {'output': self.dns, 'exit_code': 0}
        return {'output': 'S', 'exit_code': 0}


def gate_for(module, dns, root):
    gate = module.ReleaseGate.__new__(module.ReleaseGate)
    gate.channel = Channel(dns)
    gate.release = root
    gate.args = SimpleNamespace(**{field: field for field in module.IDENTITY_FIELDS})
    return gate


@pytest.mark.parametrize('addresses', [['192.168.204.1'], ['8.8.8.8'], []])
def test_dns_capture_preserves_actual_server_addresses(release_module, addresses, tmp_path):
    observed = {'InterfaceAlias': 'Ethernet0', 'ServerAddresses': addresses}
    sections = gate_for(release_module, json.dumps(observed), tmp_path).capture_sections()
    assert json.loads(sections['dns_servers']) == observed


@pytest.mark.parametrize('invalid', ['S', '', 'null', '{}', '[]',
                                    '{"InterfaceAlias":"Ethernet0"}'])
def test_missing_dns_observation_cannot_be_an_audit_baseline(
        release_module, invalid, tmp_path):
    with pytest.raises(RuntimeError, match='DNS'):
        gate_for(release_module, invalid, tmp_path).capture_sections()


def test_dns_command_failure_propagates(release_module, tmp_path):
    gate = gate_for(release_module, '{}', tmp_path)

    class FailingChannel(Channel):
        def powershell(self, command, timeout):
            if 'Get-DnsClientServerAddress' in command:
                raise RuntimeError('DNS command failed')
            return super().powershell(command, timeout)

    gate.channel = FailingChannel('{}')
    with pytest.raises(RuntimeError, match='DNS command failed'):
        gate.capture_sections()
