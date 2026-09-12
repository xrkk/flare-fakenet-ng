# Copyright 2026 Google LLC
"""Unit coverage for the pre-baseline native prerequisite snapshot."""

import json
import time
from types import SimpleNamespace

import pytest

from fakenet.mcp.startup_network import (StartupNetworkError,
                                         persist_and_assert)


class _Probe:
    def __init__(self, adapters, infos):
        self.adapters = adapters
        self.infos = infos
        self._last_get_adapters_addresses = {'sizing_result': 111,
                                             'buffer_size': 64, 'result': 0}
        self._last_get_adapters_info = {'sizing_result': 111,
                                        'buffer_size': 64, 'result': 0}

    def get_adapters_addresses(self):
        return iter(self.adapters)

    def get_adapters_info(self):
        return iter(self.infos)

    def get_ipaddresses(self, adapter):
        return iter(adapter.addresses)


def _adapter(index=11, if_type=6, status=1, name=b'ethernet0',
             friendly='Ethernet0', addresses=('192.168.204.233',)):
    return SimpleNamespace(IfIndex=index, IfType=if_type, OperStatus=status,
                           AdapterName=name, FriendlyName=friendly,
                           addresses=addresses)


def test_no_active_ethernet_is_persisted_then_refused_without_route_inference(tmp_path):
    probe = _Probe([_adapter(status=2)], [_adapter(addresses=('192.168.204.233',))])
    with pytest.raises(StartupNetworkError, match='no active Ethernet'):
        persist_and_assert(tmp_path, probe)
    record = json.loads((tmp_path / 'pre-start-native-network.json').read_text())
    assert record['active_ethernet'] == []
    assert record['nonzero_ipv4'] == [
        {'adapter_name': 'ethernet0', 'address': '192.168.204.233'}]


def test_active_ethernet_and_nonzero_ipv4_pass_without_a_default_route(tmp_path):
    probe = _Probe([_adapter()], [_adapter(addresses=('192.168.204.233',))])
    record = persist_and_assert(tmp_path, probe)
    assert record['active_ethernet'][0]['if_index'] == 11
    assert record['nonzero_ipv4'][0]['address'] == '192.168.204.233'


def test_diversion_disabled_skips_native_prerequisite(monkeypatch):
    from fakenet.mcp import supervisor
    called = []
    monkeypatch.setattr('fakenet.mcp.startup_network.persist_and_assert',
                        lambda _: called.append(True))
    parsed = SimpleNamespace(fakenet_config={'diverttraffic': 'no'})
    assert supervisor._assert_startup_network_ready(
        'unused', parsed, lambda *args: called.append('diagnostic')) is None
    assert not called


def test_diversion_uses_bounded_diagnostic_owner_for_native_observation():
    from fakenet.mcp import supervisor
    calls = []

    def diagnostic(operation, payload, deadline):
        calls.append((operation, payload, deadline))
        return {'active_ethernet': [{'if_index': 11}]}

    before = time.monotonic()
    result = supervisor._assert_startup_network_ready(
        'c2081505-7794-442f-961e-a8560126d5e4',
        SimpleNamespace(fakenet_config={'diverttraffic': 'yes'}), diagnostic)
    after = time.monotonic()
    assert result == {'active_ethernet': [{'if_index': 11}]}
    assert calls[0][:2] == (
        'pre-start-native-network',
        {'run_id': 'c2081505-7794-442f-961e-a8560126d5e4'})
    assert before + supervisor.STARTUP_NETWORK_DEADLINE_SECONDS <= calls[0][2] <= \
        after + supervisor.STARTUP_NETWORK_DEADLINE_SECONDS


def test_diagnostic_task_writes_only_the_fixed_run_directory(tmp_path, monkeypatch):
    from fakenet.mcp import diagnostic_tasks, paths, startup_network
    run_id = 'c2081505-7794-442f-961e-a8560126d5e4'
    run_dir = tmp_path / 'artifacts' / 'runs' / run_id
    run_dir.mkdir(parents=True)
    observed = []
    monkeypatch.setattr(paths, 'data_directories',
                        lambda: {'artifacts': tmp_path / 'artifacts'})
    monkeypatch.setattr(startup_network, 'persist_and_assert',
                        lambda path: observed.append(path) or {'ready': True})
    result = diagnostic_tasks.execute(
        'pre-start-native-network', {'run_id': run_id},
        time.monotonic() + 5)
    assert result == {'ready': True}
    assert observed == [run_dir.resolve()]
