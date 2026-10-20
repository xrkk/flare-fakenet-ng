"""Actual filter builder and managed observations must meet verifier inputs."""
from types import SimpleNamespace

from fakenet.mcp.controlfilter import (
    apply_control_link_exclusion, apply_loopback_exclusion)
from fakenet.mcp.egress_verification import parse_control_filter, _inbound_safe
from fakenet.mcp.managed import probe_instance
from fakenet.mcp.coordination import Coordinator
from fakenet.mcp.testdouble import LifecycleDouble
import pytest


@pytest.mark.parametrize('base', ['outbound and ip', 'outbound and (ip or ipv6)'])
def test_actual_filter_builder_accepts_control_target_and_rejects_bypass(base):
    actual = apply_loopback_exclusion(apply_control_link_exclusion(
        base, '192.168.204.1', '28787,28788,28790'))
    parsed = parse_control_filter(actual, '192.168.204.1')
    assert parsed['ok'], (actual, parsed)
    assert parsed['ports'] == [28787, 28788, 28790]
    assert not parse_control_filter(actual + ' or true', '192.168.204.1')['ok']
    assert not parse_control_filter(actual, '192.168.204.2')['ok']


def test_live_inbound_sniff_contract_uses_actual_flags():
    from pydivert import Flag
    alive = SimpleNamespace(is_alive=lambda: True)
    inbound = SimpleNamespace(_flags=Flag.SNIFF,
                              _filter=b'inbound and (ip or ipv6)')
    diverter = SimpleNamespace(
        handle=SimpleNamespace(is_open=True), diverter_thread=alive,
        inbound_capture_thread=alive, capture_failure=None,
        _inbound_capture_handle=inbound, filter='outbound and ip')
    provider = SimpleNamespace(health_snapshot=lambda: {'handles': [1], 'alive': True})
    instance = SimpleNamespace(diverter=diverter,
                               running_listener_providers=[provider],
                               diverter_config={'controllinkexcludeip': '192.168.204.1'})
    health = probe_instance(instance)
    assert _inbound_safe(health)[0]
    assert health['control_link_exclude_ip'] == '192.168.204.1'
    inbound._flags = Flag.DROP
    assert not _inbound_safe(probe_instance(instance))[0]


def test_old_operations_keep_cross_kind_replay_compatibility():
    coord = Coordinator(LifecycleDouble())
    first = coord.submit(command_id='legacy', expected_version=1,
                         controller='A', controller_valid=True, kind='old-a',
                         describe={}, execute=lambda c: {'state': 'stopped'})
    replay = coord.submit(command_id='legacy', expected_version=99,
                          controller='A', controller_valid=True, kind='old-b',
                          describe={}, execute=lambda c: pytest.fail('re-executed'))
    assert replay['replayed'] is True
    assert replay['state_version'] == first['state_version']
