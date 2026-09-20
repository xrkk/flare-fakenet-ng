"""Failure-local evidence for check_active_ethernet_adapters.

The child diverter once exited with 'No active ethernet interfaces detected'
while an independent pre-start snapshot saw a healthy adapter: only a
cross-moment observation, nothing from the failing call itself. These tests
drive the REAL WinUtilMixin.check_active_ethernet_adapters entry through a
fake IP Helper that materializes genuine ctypes IP_ADAPTER_ADDRESSES chains,
so the traversal, the same-call scalar copies and the structured failure
line are all exercised against production code (business code is unchanged
for Linux; only the winreg import is stubbed where the OS lacks it).

Case map (per the round contract):
* healthy ethernet -> True, no diagnostic line, no second enumeration;
* loopback-only / OperStatus-down -> False + one structured line
  classifying 'api-success-no-qualifying-adapter' with the same-call rows;
* native API failure -> False + 'native-error' carrying the REAL return
  code (never misattributed as 'adapter down');
* success-then-failure -> the second line contains only second-call data
  (no stale rows or stale native metadata from the successful probe);
* scalars are plain Python ints copied during iteration (buffer may be
  recycled once the generator is gone);
* the line lands through the diverter-style logger (run.log chain), once.
"""
import ctypes
import json
import logging
import sys
import types

import pytest

# Import-time-only winreg stub for non-Windows runners (the module body
# references registry constants by name). It is removed right after the
# winutil import so no other test in the session ever sees a fake winreg.
try:
    import winreg  # Use the real Windows module even if not imported yet.
except ModuleNotFoundError:
    _WINREG_STUBBED = True
else:
    _WINREG_STUBBED = False
if _WINREG_STUBBED:
    _winreg_stub = types.ModuleType('winreg')
    for _name in ('KEY_READ', 'KEY_WRITE', 'KEY_ALL_ACCESS', 'KEY_QUERY_VALUE',
                  'KEY_SET_VALUE', 'KEY_ENUMERATE_SUB_KEYS',
                  'HKEY_LOCAL_MACHINE', 'HKEY_CURRENT_USER', 'HKEY_CLASSES_ROOT',
                  'REG_SZ', 'REG_MULTI_SZ', 'REG_DWORD', 'REG_EXPAND_SZ',
                  'REG_OPTION_NON_VOLATILE', 'KEY_CREATE_SUB_KEY'):
        setattr(_winreg_stub, _name, 0)
    sys.modules['winreg'] = _winreg_stub

from fakenet.diverters import winutil  # noqa: E402
from fakenet.diverters.winutil import (  # noqa: E402
    IP_ADAPTER_ADDRESSES, MIB_IF_TYPE_ETHERNET, IFOPERSTATUSUP)

if _WINREG_STUBBED:
    del sys.modules['winreg']


class FakeIphlpapi:
    """Populates REAL ctypes adapter chains; records every API call."""

    def __init__(self, rows, fail_second_call_with=None):
        self.rows = rows                      # [(IfIndex, IfType, OperStatus)]
        self.calls = []
        self.fail_with = fail_second_call_with
        self.chains = []                      # keep buffers alive per call

    def _build_chain(self):
        # Every node stays referenced for the lifetime of the fake so the
        # linked traversal only ever reads live memory.
        nodes = []
        for index, if_type, oper in self.rows:
            node = IP_ADAPTER_ADDRESSES()
            node.IfIndex = index
            node.IfType = if_type
            node.OperStatus = oper
            nodes.append(node)
        for previous, current in zip(nodes, nodes[1:]):
            previous.Next = ctypes.pointer(current)
        self.chains.extend(nodes)
        return nodes[0] if nodes else None

    def GetAdaptersAddresses(self, family, flags, reserved, adapter_addresses, size_pointer):
        size_ref = ctypes.cast(size_pointer, ctypes.POINTER(winutil.ULONG))
        self.calls.append({'kind': 'size' if not adapter_addresses else 'fill',
                           'size': size_ref.contents.value})
        if not adapter_addresses:
            size_ref.contents.value = 4096
            return 111  # ERROR_BUFFER_OVERFLOW, the normal sizing outcome
        if self.fail_with is not None and len(self.calls) >= 2:
            return self.fail_with
        source = self._build_chain()
        if source is None:
            return 0  # API success with an empty adapter list
        ctypes.memmove(adapter_addresses, ctypes.byref(source), ctypes.sizeof(source))
        return 0


class FakeWindll:
    def __init__(self, iphlpapi):
        self.iphlpapi = iphlpapi


def make_util(monkeypatch, rows, fail_second_call_with=None):
    api = FakeIphlpapi(rows, fail_second_call_with)
    instance = winutil.WinUtilMixin.__new__(winutil.WinUtilMixin)
    instance.logger = logging.getLogger('fakenetng-mcp.test.winutil')
    monkeypatch.setattr(winutil, 'windll', FakeWindll(api), raising=False)
    return instance, api


def marker_records(caplog):
    return [r for r in caplog.records
            if r.getMessage().startswith(winutil.WinUtilMixin.ACTIVE_ETHERNET_DIAGNOSTIC_MARKER)]


def parse_diagnostic(record):
    marker = winutil.WinUtilMixin.ACTIVE_ETHERNET_DIAGNOSTIC_MARKER
    return json.loads(record.getMessage()[len(marker) + 1:])


def test_healthy_ethernet_true_without_diagnostic_or_extra_calls(caplog, monkeypatch):
    util, api = make_util(monkeypatch, [(11, MIB_IF_TYPE_ETHERNET, IFOPERSTATUSUP)])
    caplog.set_level(logging.DEBUG)
    assert util.check_active_ethernet_adapters() is True
    assert marker_records(caplog) == []
    # sizing + fill for exactly one enumeration; no second probe happened.
    assert [c['kind'] for c in api.calls] == ['size', 'fill']


def test_loopback_and_down_only_false_with_same_call_diagnostic(caplog, monkeypatch):
    rows = [(1, 24, IFOPERSTATUSUP), (7, MIB_IF_TYPE_ETHERNET, 2)]
    util, api = make_util(monkeypatch, rows)
    caplog.set_level(logging.DEBUG)
    assert util.check_active_ethernet_adapters() is False
    records = marker_records(caplog)
    assert len(records) == 1
    payload = parse_diagnostic(records[0])
    assert payload['schema'] == winutil.WinUtilMixin.ACTIVE_ETHERNET_DIAGNOSTIC_SCHEMA
    assert payload['classification'] == 'api-success-no-qualifying-adapter'
    assert payload['native_get_adapters_addresses']['result'] == 0
    assert payload['native_get_adapters_addresses']['sizing_result'] == 111
    assert payload['native_get_adapters_addresses']['buffer_size'] == 4096
    # Same-call rows, copied as plain Python scalars, in enumeration order.
    assert payload['adapters_seen'] == [
        {'IfIndex': 1, 'IfType': 24, 'OperStatus': IFOPERSTATUSUP},
        {'IfIndex': 7, 'IfType': MIB_IF_TYPE_ETHERNET, 'OperStatus': 2}]
    assert all(isinstance(v, int) for row in payload['adapters_seen'] for v in row.values())
    assert payload['qualifying_adapters'] == 0
    assert isinstance(payload['pid'], int) and isinstance(payload['sampled_utc'], float)
    # The diagnostic itself must not re-enumerate.
    assert [c['kind'] for c in api.calls] == ['size', 'fill']


def test_native_failure_reports_real_return_code_not_adapter_down(caplog, monkeypatch):
    util, api = make_util(monkeypatch, [(11, MIB_IF_TYPE_ETHERNET, IFOPERSTATUSUP)],
                          fail_second_call_with=1168)
    caplog.set_level(logging.DEBUG)
    assert util.check_active_ethernet_adapters() is False
    payload = parse_diagnostic(marker_records(caplog)[0])
    assert payload['classification'] == 'native-error'
    assert payload['native_get_adapters_addresses']['result'] == 1168
    # The fill call failed: no rows were seen, and none are fabricated.
    assert payload['adapters_seen'] == []


def test_success_then_failure_has_no_stale_metadata(caplog, monkeypatch):
    rows_ok = [(11, MIB_IF_TYPE_ETHERNET, IFOPERSTATUSUP)]
    util, api = make_util(monkeypatch, rows_ok)
    caplog.set_level(logging.DEBUG)
    assert util.check_active_ethernet_adapters() is True
    assert marker_records(caplog) == []
    # Same instance, next call: only a loopback is enumerated now.
    api.rows = [(1, 24, IFOPERSTATUSUP)]
    assert util.check_active_ethernet_adapters() is False
    records = marker_records(caplog)
    assert len(records) == 1
    payload = parse_diagnostic(records[0])
    assert payload['adapters_seen'] == [{'IfIndex': 1, 'IfType': 24,
                                         'OperStatus': IFOPERSTATUSUP}]
    assert payload['native_get_adapters_addresses']['result'] == 0
    # No leftover rows or native metadata from the successful first probe.
    assert all(row['IfIndex'] != 11 for row in payload['adapters_seen'])
    assert payload['native_get_adapters_addresses']['sizing_result'] == 111


def test_predicate_unchanged_only_type6_oper1_qualifies(monkeypatch):
    for rows, expected in (
            ([(5, 6, 1)], True), ([(5, 6, 2)], False), ([(5, 24, 1)], False),
            ([(5, 6, 2), (6, 6, 1)], True), ([], False)):
        util, _api = make_util(monkeypatch, rows)
        assert util.check_active_ethernet_adapters() is expected, rows


def test_buffer_lifetime_scalars_survive_recycled_chain(caplog, monkeypatch):
    util, api = make_util(monkeypatch, [(9, 6, 2)])
    caplog.set_level(logging.DEBUG)
    assert util.check_active_ethernet_adapters() is False
    payload = parse_diagnostic(marker_records(caplog)[0])
    # Drop every ctypes buffer the fake API built; the diagnostic payload
    # must already hold copied ints, not structure views into freed memory.
    api.chains.clear()
    assert payload['adapters_seen'] == [{'IfIndex': 9, 'IfType': 6, 'OperStatus': 2}]


def test_diverter_style_logger_receives_the_line(tmp_path, monkeypatch):
    """The record flows through the same logging chain run.log captures."""
    import logging.handlers
    log_file = tmp_path / 'run.log'
    handler = logging.FileHandler(log_file, encoding='utf-8')
    handler.setFormatter(logging.Formatter('%(levelname)s %(name)s %(message)s'))
    diverter_logger = logging.getLogger('fakenet.diverters.fakenetng')
    diverter_logger.addHandler(handler)
    try:
        api = FakeIphlpapi([(1, 24, IFOPERSTATUSUP)])
        instance = winutil.WinUtilMixin.__new__(winutil.WinUtilMixin)
        instance.logger = diverter_logger
        monkeypatch.setattr(winutil, 'windll', FakeWindll(api), raising=False)
        assert instance.check_active_ethernet_adapters() is False
    finally:
        diverter_logger.removeHandler(handler)
        handler.close()
    line = log_file.read_text(encoding='utf-8')
    assert winutil.WinUtilMixin.ACTIVE_ETHERNET_DIAGNOSTIC_MARKER in line
    assert 'ERROR' in line
