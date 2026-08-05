# Copyright 2025 Google LLC

# Diverter for Windows implemented using WinDivert library

import logging
import ctypes
from collections import Counter, OrderedDict

from pydivert.windivert import *

import socket

import os
import dpkt
from . import fnpacket

import time
import threading
import platform

from .winutil import *
from .diverterbase import *

import subprocess
import ipaddress
import json
import struct

_TAKEOVER_ROUTE_SCRIPT = r'''
$ErrorActionPreference = 'Stop'
$target = '__TARGET__'

function Test-IPv4PrefixContains {
    param([string]$Address, [string]$Prefix)
    $parts = $Prefix.Split('/')
    if ($parts.Count -ne 2) { return $false }
    $length = [int]$parts[1]
    if ($length -lt 0 -or $length -gt 32) { return $false }
    $addressBytes = ([Net.IPAddress]::Parse($Address)).GetAddressBytes()
    $networkBytes = ([Net.IPAddress]::Parse($parts[0])).GetAddressBytes()
    $whole = [Math]::Floor($length / 8)
    for ($index = 0; $index -lt $whole; $index++) {
        if ($addressBytes[$index] -ne $networkBytes[$index]) {
            return $false
        }
    }
    $remainder = $length % 8
    if ($remainder -eq 0) { return $true }
    $mask = [int](256 - [Math]::Pow(2, 8 - $remainder))
    return (($addressBytes[$whole] -band $mask) -eq
        ($networkBytes[$whole] -band $mask))
}

$interfaces = @{}
Get-NetIPInterface -AddressFamily IPv4 -ErrorAction Stop |
    Where-Object ConnectionState -eq 'Connected' |
    ForEach-Object { $interfaces[[int]$_.InterfaceIndex] = $_ }

$matches = @(
    Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore `
            -ErrorAction Stop |
        ForEach-Object {
            $index = [int]$_.InterfaceIndex
            if ($interfaces.ContainsKey($index) -and
                    (Test-IPv4PrefixContains $target $_.DestinationPrefix)) {
                $prefixLength = [int]$_.DestinationPrefix.Split('/')[1]
                [PSCustomObject]@{
                    Route = $_
                    PrefixLength = $prefixLength
                    TotalMetric = [uint64]$_.RouteMetric +
                        [uint64]$interfaces[$index].InterfaceMetric
                }
            }
        }
)
if ($matches.Count -eq 0) { throw 'No matching active IPv4 route' }
$bestPrefix = ($matches | Measure-Object PrefixLength -Maximum).Maximum
$prefixMatches = @($matches | Where-Object PrefixLength -eq $bestPrefix)
$bestMetric = ($prefixMatches | Measure-Object TotalMetric -Minimum).Minimum
$best = @($prefixMatches | Where-Object TotalMetric -eq $bestMetric)
if ($best.Count -ne 1) { throw 'Ambiguous best IPv4 route' }
$selected = $best[0]
$route = $selected.Route
if ($selected.PrefixLength -eq 0) { throw 'Default route is not permitted' }
if ([string]$route.NextHop -ne '0.0.0.0') {
    throw 'Gateway route is not permitted'
}

$sourceAddresses = @(
    Get-NetIPAddress -AddressFamily IPv4 `
            -InterfaceIndex $route.InterfaceIndex -ErrorAction Stop |
        Where-Object {
            $_.AddressState -eq 'Preferred' -and
            -not $_.SkipAsSource -and
            [string]$_.IPAddress -ne $target
        } | Select-Object -ExpandProperty IPAddress
)
$socket = New-Object Net.Sockets.Socket(
    [Net.Sockets.AddressFamily]::InterNetwork,
    [Net.Sockets.SocketType]::Dgram,
    [Net.Sockets.ProtocolType]::Udp)
try {
    $socket.Connect([Net.IPAddress]::Parse($target), 9)
    $source = [string]$socket.LocalEndPoint.Address
} finally {
    $socket.Dispose()
}
if ($source -notin $sourceAddresses) {
    throw 'Selected source is not assigned to the best-route interface'
}

[PSCustomObject]@{
    interface_index = [int]$route.InterfaceIndex
    interface_alias = [string]$interfaces[[int]$route.InterfaceIndex].InterfaceAlias
    source_ipv4 = $source
    destination_prefix = [string]$route.DestinationPrefix
    next_hop = [string]$route.NextHop
    route_metric = [uint64]$route.RouteMetric
    interface_metric = [uint64]$interfaces[[int]$route.InterfaceIndex].InterfaceMetric
} | ConvertTo-Json -Compress
'''

ROUTE_PROBE_UDP_PORT = 9
_REVIEWED_ROUTE_QUERY_TIMEOUT_SECONDS = 2
_REVIEWED_ROUTE_SCRIPT = r'''
$ErrorActionPreference = 'Stop'
$targets = @(ConvertFrom-Json -InputObject '__TARGETS_JSON__')

function Test-IPv4PrefixContains {
    param([string]$Address, [string]$Prefix)
    $parts = $Prefix.Split('/')
    if ($parts.Count -ne 2) { return $false }
    $length = [int]$parts[1]
    if ($length -lt 0 -or $length -gt 32) { return $false }
    $addressBytes = ([Net.IPAddress]::Parse($Address)).GetAddressBytes()
    $networkBytes = ([Net.IPAddress]::Parse($parts[0])).GetAddressBytes()
    $whole = [Math]::Floor($length / 8)
    for ($index = 0; $index -lt $whole; $index++) {
        if ($addressBytes[$index] -ne $networkBytes[$index]) { return $false }
    }
    $remainder = $length % 8
    if ($remainder -eq 0) { return $true }
    $mask = [int](256 - [Math]::Pow(2, 8 - $remainder))
    return (($addressBytes[$whole] -band $mask) -eq
        ($networkBytes[$whole] -band $mask))
}

$interfaces = @{}
Get-NetIPInterface -AddressFamily IPv4 -ErrorAction Stop |
    Where-Object ConnectionState -eq 'Connected' |
    ForEach-Object { $interfaces[[int]$_.InterfaceIndex] = $_ }
$routes = @(Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore `
    -ErrorAction Stop)
$results = @()

foreach ($target in $targets) {
    $target = [string]$target
    $matches = @(
        $routes | ForEach-Object {
            $index = [int]$_.InterfaceIndex
            if ($interfaces.ContainsKey($index) -and
                    (Test-IPv4PrefixContains $target $_.DestinationPrefix)) {
                $prefixLength = [int]$_.DestinationPrefix.Split('/')[1]
                [PSCustomObject]@{
                    Route = $_
                    PrefixLength = $prefixLength
                    TotalMetric = [uint64]$_.RouteMetric +
                        [uint64]$interfaces[$index].InterfaceMetric
                }
            }
        }
    )
    if ($matches.Count -eq 0) { throw "No route for $target" }
    $bestPrefix = ($matches | Measure-Object PrefixLength -Maximum).Maximum
    $prefixMatches = @($matches | Where-Object PrefixLength -eq $bestPrefix)
    $bestMetric = ($prefixMatches | Measure-Object TotalMetric -Minimum).Minimum
    $best = @($prefixMatches | Where-Object TotalMetric -eq $bestMetric)
    if ($best.Count -ne 1) { throw "Ambiguous route for $target" }
    $selected = $best[0]
    $route = $selected.Route
    $sourceAddresses = @(
        Get-NetIPAddress -AddressFamily IPv4 `
                -InterfaceIndex $route.InterfaceIndex -ErrorAction Stop |
            Where-Object {
                $_.AddressState -eq 'Preferred' -and -not $_.SkipAsSource
            } | Select-Object -ExpandProperty IPAddress
    )
    $socket = New-Object Net.Sockets.Socket(
        [Net.Sockets.AddressFamily]::InterNetwork,
        [Net.Sockets.SocketType]::Dgram,
        [Net.Sockets.ProtocolType]::Udp)
    try {
        $socket.Connect([Net.IPAddress]::Parse($target),
            __ROUTE_PROBE_UDP_PORT__)
        $source = [string]$socket.LocalEndPoint.Address
    } finally {
        $socket.Dispose()
    }
    if ($source -notin $sourceAddresses) {
        throw "Selected source is not on the best interface for $target"
    }
    $results += [PSCustomObject]@{
        target_ipv4 = $target
        interface_index = [int]$route.InterfaceIndex
        interface_alias = [string]$interfaces[[int]$route.InterfaceIndex].InterfaceAlias
        source_ipv4 = $source
        destination_prefix = [string]$route.DestinationPrefix
        next_hop = [string]$route.NextHop
        route_metric = [uint64]$route.RouteMetric
        interface_metric = [uint64]$interfaces[[int]$route.InterfaceIndex].InterfaceMetric
    }
}
@($results) | ConvertTo-Json -Compress
'''

from .egresspolicy import (EgressPolicy, PolicyConfigError,
                           ReviewedPacketTuple, Verdict)


class ReviewedIpFlowAudit(object):
    MAX_ENTRIES = 4096
    FLOW_TTL_SECONDS = 60
    SUMMARY_SECONDS = 60
    PRESSURE_SECONDS = 60

    def __init__(self, clock=None, rule_ids=()):
        self._clock = clock or time.monotonic
        self._lock = threading.Lock()
        self._rule_ids = frozenset(rule_ids)
        self._flows = OrderedDict()
        self._packets = Counter()
        self._new_flows = Counter()
        self._evictions = Counter()
        self._last_summary = self._clock()
        self._last_pressure = -self.PRESSURE_SECONDS

    def observe(self, rule, packet):
        now = self._clock()
        key = (rule.rule_id, packet.protocol, packet.source_ipv4,
               packet.source_port, packet.target_ipv4, packet.target_port)
        with self._lock:
            self._packets[rule.rule_id] += 1
            while self._flows:
                oldest_key, oldest_seen = next(iter(self._flows.items()))
                if now - oldest_seen < self.FLOW_TTL_SECONDS:
                    break
                self._flows.pop(oldest_key, None)
            previous = self._flows.get(key)
            first = previous is None or now - previous >= self.FLOW_TTL_SECONDS
            pressure = False
            if first:
                if key in self._flows:
                    self._flows.pop(key, None)
                while len(self._flows) >= self.MAX_ENTRIES:
                    evicted_key, unused = self._flows.popitem(last=False)
                    self._evictions[evicted_key[0]] += 1
                    if now - self._last_pressure >= self.PRESSURE_SECONDS:
                        pressure = True
                        self._last_pressure = now
                self._flows[key] = now
                self._new_flows[rule.rule_id] += 1
            return first, pressure, len(self._flows)

    def summaries(self, force=False):
        now = self._clock()
        with self._lock:
            if not force and now - self._last_summary < self.SUMMARY_SECONDS:
                return ()
            rule_ids = set(self._rule_ids).union(self._packets).union(
                self._new_flows, self._evictions)
            result = tuple(
                (rule_id, self._packets[rule_id],
                 self._new_flows[rule_id], self._evictions[rule_id])
                for rule_id in sorted(rule_ids))
            self._packets.clear()
            self._new_flows.clear()
            self._evictions.clear()
            self._last_summary = now
            return result


class WindowsPacketCtx(fnpacket.PacketCtx):
    def __init__(self, lbl, wdpkt):
        self.wdpkt = wdpkt
        interface = getattr(wdpkt, 'interface', (-1, -1))
        try:
            self.interface_index = int(interface[0])
            self.subinterface_index = int(interface[1])
        except (TypeError, ValueError, IndexError):
            self.interface_index = -1
            self.subinterface_index = -1
        self.is_outbound = bool(getattr(wdpkt, 'is_outbound', False))
        raw = wdpkt.raw.tobytes()

        super(WindowsPacketCtx, self).__init__(lbl, raw)

    # Packet mangling properties are extended here to also write the data to
    # the pydivert.Packet object. This is because there appears to be no way to
    # populate the pydivert.Packet object with plain octets unless you can also
    # provide @interface and @direction arguments which do not appear at a
    # glance to be directly available as attributes of pydivert.Packet,
    # according to https://ffalcinelli.github.io/pydivert/
    #
    # Perhaps we can get these from wd_addr?

    # src_ip overrides

    @property
    def src_ip(self):
        return self._src_ip

    @src_ip.setter
    def src_ip(self, new_srcip):
        super(self.__class__, self.__class__).src_ip.fset(self, new_srcip)
        self.wdpkt.src_addr = new_srcip

    # dst_ip overrides

    @property
    def dst_ip(self):
        return self._dst_ip

    @dst_ip.setter
    def dst_ip(self, new_dstip):
        super(self.__class__, self.__class__).dst_ip.fset(self, new_dstip)
        self.wdpkt.dst_addr = new_dstip

    # sport overrides

    @property
    def sport(self):
        return self._sport

    @sport.setter
    def sport(self, new_sport):
        super(self.__class__, self.__class__).sport.fset(self, new_sport)
        if self.proto:
            self.wdpkt.src_port = new_sport

    # dport overrides

    @property
    def dport(self):
        return self._dport

    @dport.setter
    def dport(self, new_dport):
        super(self.__class__, self.__class__).dport.fset(self, new_dport)
        if self.proto:
            self.wdpkt.dst_port = new_dport


class Diverter(DiverterBase, WinUtilMixin):

    def __init__(self, diverter_config, listeners_config, ip_addrs,
                 logging_level=logging.INFO):

        # Populated by winutil and used to restore modified Interfaces back to
        # DHCP
        self.adapters_dhcp_restore = list()
        self.adapters_dns_restore = list()

        super(Diverter, self).__init__(diverter_config, listeners_config,
                                       ip_addrs, logging_level)

        self.running_on_windows = True

        if not self.single_host_mode:
            self.logger.critical('Windows diverter currently only supports '
                                 'SingleHost mode')
            sys.exit(1)

        # Used (by winutil) for caching of DNS server names prior to changing
        self.adapters_dns_server_backup = dict()

        # Configure external and loopback IP addresses
        self.external_ip = self.get_best_ipaddress()
        if not self.external_ip:
            self.external_ip = self.get_ip_with_gateway()
        if not self.external_ip:
            self.external_ip = socket.gethostbyname(socket.gethostname())

        self.logger.debug('External IP: %s Loopback IP: %s' %
                          (self.external_ip, self.loopback_ip))

        #######################################################################
        # Initialize filter and WinDivert driver

        self.domain_allowlist_mode = (
            self.external_access_policy == 'domainallowlist')
        self.handle = None
        self._stopping = threading.Event()
        self._diverter_exited = threading.Event()
        self._network_restore_lock = threading.Lock()
        self._network_restored = False
        self._dns_modified = False
        self._dns_service_stopped = False
        self._drop_log_state = {}
        self._policy_listeners = []
        self._takeover_route_snapshot = None
        self._reviewed_route_snapshots = ()
        self._reviewed_target_protocols = frozenset()
        self._reviewed_ip_audit = ReviewedIpFlowAudit()

        # DomainAllowList expands capture to IPv6 and delays opening WinDivert
        # until every listener and callback is ready.  Disabled mode preserves
        # the legacy constructor-time open behavior.
        self.filter = ('outbound and (ip or ipv6)'
                       if self.domain_allowlist_mode else 'outbound and ip')

        if self.domain_allowlist_mode:
            dns_server = self._select_external_dns_server()
            try:
                self.egress_policy = EgressPolicy(
                    self._dict,
                    set(self.ip_addrs.get(4, [])).union([self.external_ip]),
                    self.ip_addrs.get(6, []),
                    dns_server)
            except (PolicyConfigError, ValueError) as exc:
                self.logger.critical('Invalid DomainAllowList configuration: %s', exc)
                raise
            self._validate_policy_listeners()
            reviewed = self.egress_policy.reviewed_ip_settings()
            self._reviewed_ip_audit = ReviewedIpFlowAudit(
                rule.rule_id for rule in reviewed['rules'])
            self._reviewed_target_protocols = reviewed['target_protocols']
            if reviewed['enabled']:
                self._reviewed_route_snapshots = (
                    self._read_reviewed_ip_route_snapshots())
                self.egress_policy.activate_reviewed_ip_routes(
                    self._reviewed_route_snapshots)
                for snapshot in self._reviewed_route_snapshots:
                    self.log_egress_event('IP_ALLOW_ROUTE_OK', **snapshot)
                for rule in reviewed['rules']:
                    if rule.port_scope == 'all':
                        self.log_egress_event(
                            'IP_ALLOW_RISK_ACK', rule_id=rule.rule_id,
                            risk='all_ports_includes_dns_proxy_tunnel')
                self.log_egress_event(
                    'IP_ALLOW_READY', rule_count=len(reviewed['rules']),
                    ip_count=len(reviewed['rule_ids_by_ip']),
                    config_sha256=reviewed['config_sha256'])
            if self.egress_policy.takeover_enabled:
                self._takeover_route_snapshot = (
                    self._read_takeover_route_snapshot())
                self.log_egress_event(
                    'TAKEOVER_ROUTE_OK',
                    **self._takeover_route_snapshot)
        else:
            self._open_windivert_handle()

    def _select_external_dns_server(self):
        configured = str(self.getconfigval('ExternalDnsServer', 'Auto')).strip()
        candidates = []
        if configured.lower() == 'auto':
            for value in self.get_dns_servers() or []:
                if isinstance(value, bytes):
                    value = value.split(b'\x00', 1)[0].decode('ascii', 'ignore')
                candidates.append(str(value))
        else:
            candidates.append(configured)

        local = set(self.ip_addrs.get(4, [])).union(
            [self.external_ip, self.loopback_ip, '0.0.0.0'])
        for candidate in candidates:
            try:
                address = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if (address.version == 4 and str(address) not in local and
                    not address.is_loopback and not address.is_link_local and
                    not address.is_multicast and not address.is_unspecified and
                    not address.is_reserved):
                return str(address)
        raise PolicyConfigError(
            'ExternalDnsServer=Auto found no usable non-local IPv4 resolver')

    def _validate_policy_listeners(self):
        relay_port = self.egress_policy.relay_port
        relay_sections = [
            cfg for cfg in self.listeners_config.values()
            if cfg.get('listener', '').lower() == 'domainegressrelay'
        ]
        if len(relay_sections) != 1:
            raise PolicyConfigError(
                'DomainAllowList requires exactly one DomainEgressRelay listener')
        relay = relay_sections[0]
        if relay.get('protocol', '').lower() != 'tcp' or int(relay['port']) != relay_port:
            raise PolicyConfigError('DomainEgressRelay protocol/port mismatch')
        dns_sections = [
            cfg for cfg in self.listeners_config.values()
            if (cfg.get('listener', '').lower() == 'dnslistener' and
                int(cfg.get('port', 0)) == 53)
        ]
        dns_protocols = {
            cfg.get('protocol', '').lower() for cfg in dns_sections
        }
        if dns_protocols != {'udp', 'tcp'} or len(dns_sections) != 2:
            raise PolicyConfigError(
                'DomainAllowList requires one UDP/53 and one TCP/53 DNS listener')
        if self.egress_policy.takeover_enabled:
            for cfg in dns_sections:
                if str(cfg.get('responsea', '')).strip() != (
                        self.egress_policy.takeover_ipv4):
                    raise PolicyConfigError(
                        'takeover DNS ResponseA must match ExternalTakeoverIPv4')
        for cfg in self.listeners_config.values():
            if (int(cfg.get('port', 0)) == relay_port and
                    cfg.get('listener', '').lower() != 'domainegressrelay'):
                raise PolicyConfigError('ExternalRelayPort conflicts with another listener')

    def _read_takeover_route_snapshot(self):
        if not self.egress_policy.takeover_enabled:
            return None
        script = _TAKEOVER_ROUTE_SCRIPT.replace(
            '__TARGET__', self.egress_policy.takeover_ipv4)
        completed = subprocess.run(
            ['powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive',
             '-ExecutionPolicy', 'Bypass', '-Command', script],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=10,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()
            raise PolicyConfigError(
                'takeover route preflight failed: %s' % (
                    detail or 'PowerShell returned no diagnostic'))
        lines = [line for line in completed.stdout.splitlines() if line.strip()]
        if not lines:
            raise PolicyConfigError(
                'takeover route preflight returned no route snapshot')
        try:
            snapshot = json.loads(lines[-1])
        except (TypeError, ValueError) as exc:
            raise PolicyConfigError(
                'takeover route preflight returned invalid JSON') from exc
        required = {
            'interface_index', 'interface_alias', 'source_ipv4',
            'destination_prefix', 'next_hop', 'route_metric',
            'interface_metric'}
        if set(snapshot) != required:
            raise PolicyConfigError(
                'takeover route snapshot fields do not match the contract')
        if (str(snapshot['next_hop']) != '0.0.0.0' or
                str(snapshot['destination_prefix']) == '0.0.0.0/0' or
                not self.egress_policy.is_exact_local_ipv4(
                    snapshot['source_ipv4']) or
                str(snapshot['source_ipv4']) ==
                self.egress_policy.takeover_ipv4):
            raise PolicyConfigError(
                'takeover route snapshot failed final validation')
        snapshot['interface_index'] = int(snapshot['interface_index'])
        snapshot['route_metric'] = int(snapshot['route_metric'])
        snapshot['interface_metric'] = int(snapshot['interface_metric'])
        return snapshot

    def _read_reviewed_ip_route_snapshots(self):
        settings = self.egress_policy.reviewed_ip_settings()
        targets = sorted({rule.ipv4 for rule in settings['rules']})
        if not targets:
            return ()
        script = _REVIEWED_ROUTE_SCRIPT.replace(
            '__TARGETS_JSON__', json.dumps(targets, separators=(',', ':')))
        script = script.replace(
            '__ROUTE_PROBE_UDP_PORT__', str(ROUTE_PROBE_UDP_PORT))
        try:
            completed = subprocess.run(
                ['powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive',
                 '-ExecutionPolicy', 'Bypass', '-Command', script],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, timeout=_REVIEWED_ROUTE_QUERY_TIMEOUT_SECONDS,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        except subprocess.TimeoutExpired as exc:
            raise PolicyConfigError(
                'reviewed IPv4 route query exceeded 2 seconds') from exc
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()
            raise PolicyConfigError(
                'reviewed IPv4 route preflight failed: %s' % (
                    detail or 'PowerShell returned no diagnostic'))
        lines = [line for line in completed.stdout.splitlines()
                 if line.strip()]
        if not lines:
            raise PolicyConfigError(
                'reviewed IPv4 route preflight returned no snapshot')
        try:
            decoded = json.loads(lines[-1])
        except (TypeError, ValueError) as exc:
            raise PolicyConfigError(
                'reviewed IPv4 route preflight returned invalid JSON') from exc
        if isinstance(decoded, dict):
            decoded = [decoded]
        if not isinstance(decoded, list):
            raise PolicyConfigError(
                'reviewed IPv4 route preflight returned an invalid collection')
        required = {
            'target_ipv4', 'interface_index', 'interface_alias',
            'source_ipv4', 'destination_prefix', 'next_hop',
            'route_metric', 'interface_metric'}
        normalized = []
        for snapshot in decoded:
            if not isinstance(snapshot, dict) or set(snapshot) != required:
                raise PolicyConfigError(
                    'reviewed IPv4 route snapshot fields do not match')
            item = dict(snapshot)
            item['target_ipv4'] = str(item['target_ipv4'])
            item['source_ipv4'] = str(item['source_ipv4'])
            item['interface_alias'] = str(item['interface_alias'])
            item['destination_prefix'] = str(item['destination_prefix'])
            item['next_hop'] = str(item['next_hop'])
            try:
                item['interface_index'] = int(item['interface_index'])
                item['route_metric'] = int(item['route_metric'])
                item['interface_metric'] = int(item['interface_metric'])
            except (TypeError, ValueError) as exc:
                raise PolicyConfigError(
                    'reviewed IPv4 route snapshot has invalid numbers') from exc
            if (item['target_ipv4'] not in targets or
                    item['interface_index'] <= 0 or
                    item['route_metric'] < 0 or
                    item['interface_metric'] < 0 or
                    not self.egress_policy.is_exact_local_ipv4(
                        item['source_ipv4'])):
                raise PolicyConfigError(
                    'reviewed IPv4 route snapshot failed validation')
            normalized.append(item)
        normalized.sort(key=lambda item: item['target_ipv4'])
        if ([item['target_ipv4'] for item in normalized] != targets or
                len({item['target_ipv4'] for item in normalized}) !=
                len(targets)):
            raise PolicyConfigError(
                'reviewed IPv4 route snapshots do not match configured targets')
        return tuple(normalized)

    def _open_windivert_handle(self):
        if self.handle is not None:
            return
        try:
            self.handle = WinDivert(filter=self.filter)
            self.handle.open()
        except WindowsError as e:
            if e.winerror == 5:
                self.logger.critical('ERROR: Insufficient privileges to run '
                                     'windows diverter.')
                self.logger.critical('       Please restart with '
                                     'Administrator privileges.')
            elif e.winerror == 3:
                self.logger.critical('ERROR: Could not locate WinDivert DLL '
                                     'or one of its components.')
                self.logger.critical('       Please make sure you have copied '
                                     'FakeNet-NG to the C: drive.')
            else:
                self.logger.critical('ERROR: Failed to open a handle to the '
                                     'WinDivert driver: %s', e)
            self.handle = None
            raise

    def _close_windivert_handle(self):
        """Close WinDivert without inheriting a stale Windows last-error.

        PyDivert 2.1.0 checks GetLastError after WinDivertClose even when the
        close succeeds. Clear the previous error first so only a close error
        can be reported.
        """
        if self.handle is None:
            return
        ctypes.windll.kernel32.SetLastError(0)
        self.handle.close()
        self.handle = None

    def configure_policy_runtime(self, listeners):
        if self.domain_allowlist_mode:
            self._policy_listeners = list(listeners)

    def suspend_policy(self):
        if self.domain_allowlist_mode:
            # FakeNet calls this at the beginning of an orderly stop, before
            # listeners are drained.  Mark the whole diverter as stopping so
            # watchdog/refresh workers cannot misclassify that drain window.
            self._stopping.set()
            if self.egress_policy:
                self.egress_policy.suspend()

    ###########################################################################
    # Diverter controller functions

    def startCallback(self):
        if self.domain_allowlist_mode:
            self._open_windivert_handle()

        self.logger.debug('Diverting ports: ')
        self._stopping.clear()
        self._diverter_exited.clear()
        self.diverter_thread = threading.Thread(
            target=self.divert_thread, name='WinDivert')
        self.diverter_thread.daemon = True
        self.diverter_thread.start()

        if self.domain_allowlist_mode:
            # Fail before changing DNS if the receiver did not become live.
            self.diverter_thread.join(0.05)
            if not self.diverter_thread.is_alive():
                if self.handle:
                    self._close_windivert_handle()
                raise RuntimeError('WinDivert receiver thread failed to start')

        try:
            # Set local DNS only after policy listeners and WinDivert are
            # ready. Mark it first so a partial registry update is restored.
            if self.is_set('modifylocaldns'):
                self._dns_modified = True
                self.set_dns_server(self.external_ip)
                if self.domain_allowlist_mode:
                    observed = set()
                    for value in self.get_dns_servers() or []:
                        if isinstance(value, bytes):
                            value = value.split(b'\x00', 1)[0].decode(
                                'ascii', 'ignore')
                        observed.add(str(value))
                    if self.external_ip not in observed:
                        raise RuntimeError(
                            'local DNS redirection could not be verified')

            if self.is_set('stopdnsservice'):
                self._dns_service_stopped = True
                self.stop_service_helper('Dnscache')

            self.flush_dns()
        except Exception:
            if self.domain_allowlist_mode:
                self.egress_policy.suspend()
            self._stopping.set()
            try:
                self._restore_network_settings()
            except Exception:
                self.logger.exception(
                    'Network restoration failed during startup rollback')
            finally:
                if self.handle:
                    self._close_windivert_handle()
            self.diverter_thread.join(5)
            raise

        if self.domain_allowlist_mode:
            self.watchdog_thread = threading.Thread(
                target=self._watch_diverter_thread,
                name='WinDivertWatchdog', daemon=True)
            self.watchdog_thread.start()
            self.address_refresh_thread = threading.Thread(
                target=self._refresh_local_addresses,
                name='LocalAddressSnapshot', daemon=True)
            self.address_refresh_thread.start()
            if self.egress_policy.takeover_enabled:
                self.log_egress_event(
                    'DOMAIN_TAKEOVER_READY',
                    allowed_domain='api.deepseek.com',
                    takeover_ip=self.egress_policy.takeover_ipv4,
                    ttl=self.egress_policy.takeover_dns_ttl)
            else:
                self.log_egress_event(
                    'DOMAIN_ALLOWLIST_READY',
                    dns=self.egress_policy.external_dns_server,
                    relay_port=self.egress_policy.relay_port)

        return True

    def divert_thread(self):
        try:
            while not self._stopping.is_set():
                wdpkt = self.handle.recv()

                if wdpkt is None:
                    self.logger.error('ERROR: Can\'t handle packet.')
                    continue

                if self.domain_allowlist_mode:
                    self._handle_policy_packet(wdpkt)
                else:
                    self._handle_legacy_packet(wdpkt)

        except WindowsError as e:
            if e.winerror in [4, 6, 995]:
                return
            else:
                raise
        except Exception:
            self.logger.exception('WinDivert receiver terminated unexpectedly')
        finally:
            self._diverter_exited.set()

    def _callbacks(self):
        return ([self.check_log_icmp, self.redirIcmpIpUnconditionally],
                [self.maybe_redir_port, self.maybe_fixup_sport,
                 self.maybe_redir_ip, self.maybe_fixup_srcip])

    def _handle_legacy_packet(self, wdpkt):
        pkt = WindowsPacketCtx('divert_thread', wdpkt)
        cb3, cb4 = self._callbacks()
        self.handle_pkt(pkt, cb3, cb4)
        self._send_packet(pkt)

    def _handle_policy_packet(self, wdpkt):
        raw = wdpkt.raw.tobytes()
        if not raw:
            self.log_egress_event('DROP_EXTERNAL', reason='empty_packet')
            return
        version = (raw[0] & 0xf0) >> 4
        ipv6_verdict = self.classify_ipv6_preparse(
            raw, bool(getattr(wdpkt, 'is_loopback', False)))
        if ipv6_verdict is not None:
            if ipv6_verdict == Verdict.REINJECT_LOCAL:
                self._send_windivert_packet(
                    wdpkt, 'IPv6 loopback reinjection')
            else:
                self.log_egress_event('DROP_EXTERNAL',
                                      reason='external_ipv6')
            return
        if version != 4:
            self.log_egress_event('DROP_EXTERNAL', reason='unknown_ip_version')
            return
        fragment = self.classify_reviewed_ipv4_fragment(
            raw, self._reviewed_target_protocols)
        if fragment:
            protocol, target_ipv4 = fragment
            self.log_egress_event(
                'DROP_EXTERNAL', reason='reviewed_ip_fragment',
                proto=protocol, ip=target_ipv4)
            return

        new_mapping_generation = None
        try:
            pkt = WindowsPacketCtx('domain_allowlist', wdpkt)
            self.write_pcap(pkt)
            original = (pkt.proto, pkt.src_ip0, pkt.sport0,
                        pkt.dst_ip0, pkt.dport0)

            if pkt.proto:
                permit = self.egress_policy.match_control_flow(*original)
                if permit:
                    verdict = self.finalize_egress_verdict(
                        pkt, permit=permit)
                    if verdict == Verdict.ALLOW_INTERNAL_UPSTREAM:
                        self.log_egress_event(
                            'ALLOW_INTERNAL_UPSTREAM', kind=permit.kind,
                            ip=pkt.dst_ip0, port=pkt.dport0,
                            sport=pkt.sport0)
                        self._send_packet(pkt)
                    return

            mapping = self.apply_domain_relay_return_fixup(pkt, original)
            if mapping:
                verdict = self.finalize_egress_verdict(
                    pkt, relay_return_fixed=True)
                if verdict != Verdict.REINJECT_LOCAL:
                    self.log_egress_event(
                        'DROP_EXTERNAL', reason='stale_relay_return',
                        original_ip=pkt.dst_ip0,
                        original_port=pkt.dport0)
                    self.egress_policy.close_relay_mapping(
                        mapping.generation)
                    return
                self.write_pcap(pkt)
                if not self._send_packet(pkt):
                    self.egress_policy.close_relay_mapping(
                        mapping.generation)
                return

            if (pkt.proto and
                    self.egress_policy.matches_takeover_sink(*original)):
                verdict = self.finalize_egress_verdict(
                    pkt, takeover_sink=True)
                if verdict != Verdict.ALLOW_TAKEOVER_SINK:
                    self.log_egress_event(
                        'DROP_EXTERNAL', reason='takeover_revalidation_failed',
                        original_ip=pkt.dst_ip0,
                        original_port=pkt.dport0)
                    return
                self.log_egress_event(
                    'ALLOW_TAKEOVER_SINK', ip=pkt.dst_ip0,
                    proto=pkt.proto, sport=pkt.sport0, dport=pkt.dport0)
                self._send_packet(pkt)
                return

            redirected = False
            if pkt.proto:
                mapping = self.apply_domain_relay_forward_redirect(
                    pkt, original)
                if mapping:
                    redirected = True
                elif self._is_new_tcp_syn(pkt):
                    mapping, lease = self.redirect_domain_tls_syn(pkt)
                    if mapping:
                        new_mapping_generation = mapping.generation
                        redirected = True
                        self.log_egress_event(
                            'REDIRECT_TLS_RELAY', domain=lease.domain,
                            original_ip=pkt.dst_ip0,
                            relay_port=self.egress_policy.relay_port)

            if not redirected and pkt.proto:
                reviewed_packet = self._reviewed_packet_tuple(pkt)
                reviewed_rule = self.egress_policy.match_reviewed_ip(
                    reviewed_packet)
                if reviewed_rule:
                    verdict = self.finalize_egress_verdict(
                        pkt, reviewed_rule=reviewed_rule)
                    if verdict != Verdict.ALLOW_REVIEWED_IP:
                        self.log_egress_event(
                            'DROP_EXTERNAL',
                            reason='reviewed_ip_revalidation_failed',
                            ip=pkt.dst_ip0, proto=pkt.proto,
                            dport=pkt.dport0)
                        return
                    if self._send_packet(pkt):
                        self._record_reviewed_ip_allow(
                            pkt, reviewed_packet, reviewed_rule)
                    return

            handled_by_base = False
            if (not redirected and
                    self.egress_policy.non_allowed_action == 'divert'):
                cb3, cb4 = self._callbacks()
                self.handle_pkt(pkt, cb3, cb4,
                                raw_already_captured=True)
                handled_by_base = True

            verdict = self.finalize_egress_verdict(pkt, redirected)
            if verdict == Verdict.DROP_EXTERNAL:
                self.log_egress_event(
                    'DROP_EXTERNAL', reason='no_authorized_route',
                    original_ip=pkt.dst_ip0, original_port=pkt.dport0)
                if mapping:
                    self.egress_policy.close_relay_mapping(
                        mapping.generation)
                return
            if pkt.mangled and not handled_by_base:
                self.write_pcap(pkt)
            if verdict == Verdict.DIVERT_FAKE:
                self.log_egress_event(
                    'DIVERT_FAKE', original_ip=pkt.dst_ip0,
                    original_port=pkt.dport0)
            if not self._send_packet(pkt) and mapping:
                self.egress_policy.close_relay_mapping(mapping.generation)
        except Exception as exc:
            if new_mapping_generation:
                self.egress_policy.close_relay_mapping(
                    new_mapping_generation)
            self.log_egress_event('DROP_EXTERNAL', reason='policy_exception',
                                  error=type(exc).__name__)
            self.logger.exception('DomainAllowList packet failed closed')

    def _is_new_tcp_syn(self, pkt):
        return bool(pkt.proto == 'TCP' and
                    (pkt.hdr.data.flags & dpkt.tcp.TH_SYN) and
                     not (pkt.hdr.data.flags & dpkt.tcp.TH_ACK))

    @staticmethod
    def classify_ipv6_preparse(raw, is_loopback):
        if raw and ((raw[0] & 0xf0) >> 4) == 6:
            return (Verdict.REINJECT_LOCAL if is_loopback else
                    Verdict.DROP_EXTERNAL)
        return None

    @staticmethod
    def classify_reviewed_ipv4_fragment(raw, target_protocols):
        if not raw or len(raw) < 20 or ((raw[0] & 0xf0) >> 4) != 4:
            return None
        header_length = (raw[0] & 0x0f) * 4
        if header_length < 20 or len(raw) < header_length:
            return None
        protocol = {6: 'TCP', 17: 'UDP'}.get(raw[9])
        if not protocol:
            return None
        target_ipv4 = socket.inet_ntoa(raw[16:20])
        fragment_bits = struct.unpack('!H', raw[6:8])[0]
        if (fragment_bits & 0x3fff and
                (protocol, target_ipv4) in target_protocols):
            return protocol, target_ipv4
        return None

    @staticmethod
    def _reviewed_packet_tuple(pkt):
        return ReviewedPacketTuple(
            protocol=pkt.proto,
            source_ipv4=pkt.src_ip,
            source_port=pkt.sport,
            target_ipv4=pkt.dst_ip,
            target_port=pkt.dport,
            interface_index=getattr(pkt, 'interface_index', -1),
            subinterface_index=getattr(pkt, 'subinterface_index', -1),
            outbound=bool(getattr(pkt, 'is_outbound', False)))

    def _record_reviewed_ip_allow(self, pkt, packet, rule):
        try:
            first, pressure, entries = self._reviewed_ip_audit.observe(
                rule, packet)
            if first:
                pid = None
                process = None
                try:
                    pid, process = self.get_pid_comm(pkt)
                except Exception:
                    pid = None
                    process = None
                self.log_egress_event(
                    'ALLOW_REVIEWED_IP_FIRST_FLOW',
                    rule_id=rule.rule_id, src=packet.source_ipv4,
                    sport=packet.source_port, ip=packet.target_ipv4,
                    proto=packet.protocol, dport=packet.target_port,
                    port_scope=rule.port_scope,
                    interface_index=packet.interface_index,
                    subinterface_index=packet.subinterface_index,
                    pid=pid if pid is not None else 'unknown',
                    process=(str(process).replace(' ', '_')
                             if process else 'unknown'))
            if pressure:
                self.log_egress_event(
                    'IP_ALLOW_AUDIT_PRESSURE', entries=entries,
                    evictions=1)
            self._flush_reviewed_ip_audit()
        except Exception:
            self.logger.exception(
                'Reviewed IPv4 observability failed without changing verdict')

    def _flush_reviewed_ip_audit(self, force=False):
        for rule_id, packets, flows, evictions in (
                self._reviewed_ip_audit.summaries(force=force)):
            self.log_egress_event(
                'IP_ALLOW_AUDIT_SUMMARY', rule_id=rule_id,
                allowed_packets=packets, observed_flows=flows,
                evictions=evictions)

    def apply_domain_relay_return_fixup(self, pkt, original):
        if not pkt.proto:
            return None
        mapping = self.egress_policy.match_relay_reverse(*original)
        if mapping:
            pkt.src_ip = mapping.server_ip
            pkt.sport = mapping.server_port
        return mapping

    def apply_domain_relay_forward_redirect(self, pkt, original):
        if not pkt.proto:
            return None
        mapping = self.egress_policy.match_relay_forward(*original)
        if mapping:
            pkt.dst_ip = mapping.relay_ip
            pkt.dport = mapping.relay_port
        return mapping

    def redirect_domain_tls_syn(self, pkt):
        lease = self.egress_policy.lease_for(pkt.dst_ip0, pkt.dport0)
        if not lease:
            return None, None
        # The relay listens on the IPv4 wildcard address. Target the exact
        # local address that originated this flow, not Diverter.external_ip:
        # on a multi-homed VM the latter may belong to another adapter and a
        # reinjected SYN can be captured and diverted a second time.
        relay_ip = pkt.src_ip0
        mapping = self.egress_policy.create_relay_mapping(
            pkt.src_ip0, pkt.sport0, pkt.dst_ip0, pkt.dport0,
            relay_ip, self.egress_policy.relay_port)
        pkt.dst_ip = relay_ip
        pkt.dport = self.egress_policy.relay_port
        return mapping, lease

    def finalize_egress_verdict(self, pkt, relay_redirected=False,
                                 permit=None, relay_return_fixed=False,
                                 takeover_sink=False, reviewed_rule=None):
        if permit is not None:
            return Verdict.ALLOW_INTERNAL_UPSTREAM
        if relay_return_fixed:
            return (Verdict.REINJECT_LOCAL
                    if self.egress_policy.is_exact_local_ipv4(pkt.dst_ip)
                    else Verdict.DROP_EXTERNAL)
        if takeover_sink:
            return (Verdict.ALLOW_TAKEOVER_SINK
                    if self.egress_policy.matches_takeover_sink(
                        pkt.proto, pkt.src_ip, pkt.sport,
                        pkt.dst_ip, pkt.dport) else
                    Verdict.DROP_EXTERNAL)
        if relay_redirected:
            if (pkt.proto == 'TCP' and
                    pkt.dport == self.egress_policy.relay_port and
                    self.egress_policy.is_exact_local_ipv4(pkt.dst_ip) and
                    self.listener_ports.isListener(pkt.proto, pkt.dport)):
                return Verdict.REDIRECT_TLS_RELAY
            return Verdict.DROP_EXTERNAL
        if reviewed_rule is not None:
            current = self.egress_policy.match_reviewed_ip(
                self._reviewed_packet_tuple(pkt))
            return (Verdict.ALLOW_REVIEWED_IP
                    if current and current.rule_id == reviewed_rule.rule_id
                    else Verdict.DROP_EXTERNAL)
        if self.egress_policy.is_exact_local_ipv4(pkt.dst_ip):
            if pkt.proto and self.listener_ports.isListener(pkt.proto,
                                                            pkt.dport):
                return Verdict.DIVERT_FAKE
            return Verdict.REINJECT_LOCAL
        return Verdict.DROP_EXTERNAL

    def _send_packet(self, pkt):
        if self._send_windivert_packet(pkt.wdpkt, 'packet reinjection'):
            return True
        protocol = pkt.proto or ('ICMP' if pkt.is_icmp else 'Unknown')
        self.logger.error('ERROR: Failed to send %s %s %s packet',
                          self.pktDirectionStr(pkt),
                          self.pktInterfaceStr(pkt), protocol)
        self.logger.error('  %s', pkt.hdrToStr())
        return False

    def _send_windivert_packet(self, wdpkt, description):
        self.setLastErrorNull()
        try:
            self.handle.send(wdpkt)
            return True
        except Exception as exc:
            self.logger.error('ERROR: %s failed: %s', description, exc)
            return False

    def select_source_ipv4(self, target_ip, target_port):
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect((str(target_ip), int(target_port)))
            source_ip = probe.getsockname()[0]
        finally:
            probe.close()
        if not self.egress_policy.is_exact_local_ipv4(source_ip):
            raise RuntimeError('route selected a non-local source address')
        return source_ip

    def log_egress_event(self, event, **fields):
        now = time.monotonic()
        signature = (event, tuple(sorted(fields.items())))
        if (event == 'DROP_EXTERNAL' or event.endswith('_DENY') or
                event == 'DNS_SERVFAIL'):
            previous = self._drop_log_state.get(signature, 0)
            if now - previous < 1:
                return
            self._drop_log_state[signature] = now
            if len(self._drop_log_state) > 1024:
                self._drop_log_state = {
                    key: stamp for key, stamp in self._drop_log_state.items()
                    if now - stamp < 60}
        suffix = ' '.join('%s=%s' % item for item in sorted(fields.items()))
        self.logger.info('%s%s', event, (' ' + suffix) if suffix else '')

    def _watch_diverter_thread(self):
        self._diverter_exited.wait()
        if not self._stopping.is_set():
            self.logger.critical(
                'WinDivert receiver exited; closing capture and restoring network')
            try:
                self.egress_policy.suspend()
                for listener in reversed(self._policy_listeners):
                    try:
                        listener.stop()
                        listener._policy_stopped = True
                    except Exception:
                        self.logger.exception(
                            'Failed stopping listener after WinDivert exit')
            finally:
                try:
                    self._restore_network_settings()
                except Exception:
                    self.logger.exception(
                        'Network restoration failed after receiver exit')
                finally:
                    if self.handle:
                        self._close_windivert_handle()

    def _refresh_local_addresses(self):
        while not self._stopping.wait(5):
            try:
                addresses = set()
                for adapter in self.get_adapters_info():
                    addresses.update(self.get_ipaddresses(adapter))
                if self.external_ip:
                    addresses.add(self.external_ip)
                # An orderly stop may begin while this worker is already
                # between its timed wait and snapshot update.  Do not report
                # that deliberate suspension as an unsafe address change.
                if self._stopping.is_set():
                    return
                takeover_was_available = (
                    self.egress_policy.takeover_available())
                if not self.egress_policy.update_local_ipv4(addresses):
                    if self._stopping.is_set():
                        return
                    self.logger.critical(
                        'DomainAllowList suspended after unsafe address change')
                    return
                if (takeover_was_available and
                        not self.egress_policy.takeover_available()):
                    settings = self.egress_policy.takeover_settings()
                    self.log_egress_event(
                        'TAKEOVER_SUSPEND',
                        reason=settings['suspend_reason'] or
                        'address_snapshot_changed')
                if self.egress_policy.takeover_available():
                    try:
                        route = self._read_takeover_route_snapshot()
                        if route != self._takeover_route_snapshot:
                            raise RuntimeError(
                                'takeover route snapshot changed')
                    except Exception as exc:
                        if self.egress_policy.suspend_takeover(
                                'route_snapshot_changed'):
                            self.log_egress_event(
                                'TAKEOVER_SUSPEND',
                                reason='route_snapshot_changed',
                                error=type(exc).__name__)
                if self.egress_policy.reviewed_ipv4_enabled:
                    try:
                        routes = self._read_reviewed_ip_route_snapshots()
                        if routes != self._reviewed_route_snapshots:
                            raise RuntimeError(
                                'reviewed IPv4 route snapshot changed')
                    except Exception as exc:
                        self.egress_policy.suspend()
                        if isinstance(
                                getattr(exc, '__cause__', None),
                                subprocess.TimeoutExpired):
                            reason = 'route_query_timeout'
                        elif isinstance(exc, RuntimeError):
                            reason = 'route_snapshot_changed'
                        else:
                            reason = 'route_query_failed'
                        self.log_egress_event(
                            'IP_ALLOW_ROUTE_SUSPEND',
                            reason=reason, error=type(exc).__name__,
                            detail=str(exc).replace(' ', '_')[:160])
                        self.logger.critical(
                            'DomainAllowList suspended after reviewed IPv4 '
                            'route failure')
                        return
                for domain, ip in self.egress_policy.drain_expired_leases():
                    self.log_egress_event(
                        'DNS_LEASE_EXPIRE', domain=domain, ip=ip)
                self._flush_reviewed_ip_audit()
            except Exception:
                self.logger.exception('Failed refreshing local address snapshot')
                self.egress_policy.suspend()
                self.logger.critical(
                    'DomainAllowList suspended after address refresh failure')
                return

    def stopCallback(self):
        self._stopping.set()
        try:
            self._flush_reviewed_ip_audit(force=True)
        except Exception:
            self.logger.exception(
                'Failed flushing reviewed IPv4 audit summary during stop')
        if self.domain_allowlist_mode:
            # Keep capture fail-closed while restoring DNS. Once the original
            # network settings are back, closing WinDivert is the final step.
            if self.egress_policy:
                self.egress_policy.suspend()
            try:
                self._restore_network_settings()
            except Exception:
                self.logger.exception('Network restoration failed during stop')
            finally:
                if self.handle:
                    try:
                        self._close_windivert_handle()
                    except Exception:
                        self.logger.exception('Failed closing WinDivert handle')
        elif self.handle:
            try:
                self._close_windivert_handle()
            except Exception:
                self.logger.exception('Failed closing WinDivert handle')
        if (getattr(self, 'diverter_thread', None) and
                self.diverter_thread is not threading.current_thread()):
            self.diverter_thread.join(5)
        if (getattr(self, 'address_refresh_thread', None) and
                self.address_refresh_thread is not threading.current_thread()):
            self.address_refresh_thread.join(5)
        if (getattr(self, 'watchdog_thread', None) and
                self.watchdog_thread is not threading.current_thread()):
            self.watchdog_thread.join(5)
        if self.pcap:
            self.pcap.close()
            self.pcap = None
        if not self.domain_allowlist_mode:
            self._restore_network_settings()
        if self.egress_policy:
            self.egress_policy.close()
        return True

    def _restore_network_settings(self):
        with self._network_restore_lock:
            if self._network_restored:
                return
            self._network_restored = True
        # Restore DHCP adapter settings
        for interface_name in self.adapters_dhcp_restore:

            cmd_set_dhcp = ('netsh interface ip set address name="%s" dhcp' %
                            interface_name)

            # Restore DHCP on interface
            try:
                subprocess.check_call(cmd_set_dhcp, shell=True,
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)
            except subprocess.CalledProcessError as e:
                self.logger.error('Failed to restore DHCP on interface %s.' %
                                  interface_name)
            else:
                self.logger.info('Restored DHCP on interface %s' %
                                 interface_name)

        # Restore DHCP adapter settings
        for interface_name in self.adapters_dns_restore:

            cmd_del_dns = ('netsh interface ip delete dns name="%s" all' %
                           interface_name)
            cmd_set_dns_dhcp = ('netsh interface ip set dns "%s" dhcp' %
                                interface_name)

            # Restore DNS on interface
            try:
                subprocess.check_call(cmd_del_dns, shell=True,
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)
                subprocess.check_call(cmd_set_dns_dhcp, shell=True,
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)
            except subprocess.CalledProcessError as e:
                self.logger.error("Failed to restore DNS on interface %s." %
                                  interface_name)
            else:
                self.logger.info("Restored DNS on interface %s" %
                                 interface_name)

        # Restore DNS server
        if self._dns_modified:
            self.restore_dns_server()
            self._dns_modified = False

        # Restart DNS service
        if self._dns_service_stopped:
            self.start_service_helper('Dnscache')
            self._dns_service_stopped = False

        self.flush_dns()

    def pktInterfaceStr(self, pkt):
        """WinDivert provides is_loopback which Windows Diverter uses to
        display information about the disposition of packets it is
        processing during error and other cases.
        """
        return 'loopback' if pkt.wdpkt.is_loopback else 'external'

    def pktDirectionStr(self, pkt):
        """WinDivert provides is_inbound which Windows Diverter uses to
        display information about the disposition of packets it is
        processing during error and other cases.
        """
        return 'inbound' if pkt.wdpkt.is_inbound else 'outbound'

    def redirIcmpIpUnconditionally(self, crit, pkt):
        """Redirect ICMP to loopback or external IP if necessary.

        On Windows, we can't conveniently use an iptables REDIRECT rule to get
        ICMP packets sent back home for free, so here is some code.
        """
        if (pkt.is_icmp and
                pkt.icmp_id not in self.blacklist_ids["ICMP"] and
                pkt.dst_ip not in [self.loopback_ip, self.external_ip]):
            self.logger.info('Modifying ICMP packet (type %d, code %d):' %
                             (pkt.icmp_type, pkt.icmp_code))
            self.logger.info('  from: %s' % (pkt.hdrToStr()))
            pkt.dst_ip = self.getNewDestinationIp(pkt.src_ip)
            self.logger.info('  to:   %s' % (pkt.hdrToStr()))

        return pkt


def main():

    diverter_config = {'redirectalltraffic': 'no',
                       'defaultlistener': 'DefaultListener',
                       'dumppackets': 'no'}
    listeners_config = {'DefaultListener': {'port': '1337', 'protocol': 'TCP'}}

    diverter = Diverter(diverter_config, listeners_config)
    diverter.start()

    ###########################################################################
    # Run processing
    import time

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        diverter.stop()

    ###########################################################################
    # Run tests
    # TODO

if __name__ == '__main__':
    main()
