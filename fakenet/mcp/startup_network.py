# Copyright 2026 Google LLC
"""Observe FakeNet's existing Windows network prerequisites before a run.

The resulting file is diagnostic evidence only.  It is not a recovery-audit
section and it never authorizes a route, adapter, DNS, or service change.
"""

import json
import logging
import os
from pathlib import Path


class StartupNetworkError(RuntimeError):
    """A prerequisite already enforced by the Windows diverter is absent."""


def _text(value):
    if isinstance(value, bytes):
        return value.split(b'\0', 1)[0].decode('utf-8', 'replace')
    return str(value or '')


def _probe():
    """Create a native reader only; this does not construct a diverter."""
    from fakenet.diverters.winutil import WinUtilMixin

    class Probe(WinUtilMixin):
        def __init__(self):
            self.logger = logging.getLogger('fakenetng-mcp.startup_network')

    return Probe()


def observe_native_prerequisites(probe=None):
    """Read the same two native predicates used by the Windows diverter."""
    if os.name != 'nt' and probe is None:
        raise StartupNetworkError('native startup network observation requires Windows')
    if probe is None:
        probe = _probe()
    try:
        from fakenet.diverters.winutil import (MIB_IF_TYPE_ETHERNET,
                                                IFOPERSTATUSUP)
    except ModuleNotFoundError:
        # A supplied unit-test probe has no Windows DLL or registry dependency.
        # These are the fixed IP Helper ABI values used by WinUtil.
        if probe is None:
            raise
        MIB_IF_TYPE_ETHERNET, IFOPERSTATUSUP = 6, 1

    # Convert fields while each generator still owns the ctypes backing
    # buffer.  Retaining its structure views after generator exhaustion could
    # read freed IP Helper memory.
    adapter_rows = []
    for adapter in probe.get_adapters_addresses() or ():
        adapter_rows.append(dict(
            if_index=int(adapter.IfIndex), if_type=int(adapter.IfType),
            oper_status=int(adapter.OperStatus),
            adapter_name=_text(adapter.AdapterName),
            friendly_name=_text(adapter.FriendlyName)))
    active = [row for row in adapter_rows
              if row['if_type'] == MIB_IF_TYPE_ETHERNET and
              row['oper_status'] == IFOPERSTATUSUP]

    ipv4_rows = []
    for adapter in probe.get_adapters_info() or ():
        name = _text(getattr(adapter, 'AdapterName', ''))
        for address in probe.get_ipaddresses(adapter):
            address = _text(address)
            if address and address != '0.0.0.0':
                ipv4_rows.append(dict(adapter_name=name, address=address))
    return dict(
        schema='fakenet.mcp.pre-start-native-network.v1',
        get_adapters_addresses=dict(
            getattr(probe, '_last_get_adapters_addresses', {})),
        adapters=adapter_rows,
        active_ethernet=active,
        get_adapters_info=dict(getattr(probe, '_last_get_adapters_info', {})),
        nonzero_ipv4=ipv4_rows,
    )


def persist_and_assert(run_dir, probe=None):
    """Preserve one immutable snapshot, then enforce no new requirement."""
    record = observe_native_prerequisites(probe)
    path = Path(run_dir) / 'pre-start-native-network.json'
    raw = (json.dumps(record, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode('utf-8')
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    addresses = record['get_adapters_addresses']
    if addresses.get('result') not in (0, None):
        raise StartupNetworkError(
            'pre-start native network prerequisite unavailable: '
            'GetAdaptersAddresses error %s' % addresses['result'])
    if not record['active_ethernet']:
        raise StartupNetworkError(
            'pre-start native network prerequisite unavailable: no active Ethernet')
    infos = record['get_adapters_info']
    if infos.get('result') not in (0, None):
        raise StartupNetworkError(
            'pre-start native network prerequisite unavailable: '
            'GetAdaptersInfo error %s' % infos['result'])
    if not record['nonzero_ipv4']:
        raise StartupNetworkError(
            'pre-start native network prerequisite unavailable: no non-zero IPv4 address')
    return record
