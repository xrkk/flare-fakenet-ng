# Copyright 2026 Google LLC

"""Pure policy and state primitives for Windows process redirection.

The module deliberately does not import PyDivert, ctypes, PowerShell, or any
Windows DLL. Windows-specific identity and route work enters through injected
adapters so tests and the packet path share the same small interface.
"""

from dataclasses import dataclass
from collections import Counter
from enum import Enum
import ipaddress
import ntpath
import re
import threading
import time


_RFC1918_NETWORKS = (
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
)

_NON_GLOBAL_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
    '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24',
    '192.0.2.0/24', '192.88.99.0/24', '192.168.0.0/16',
    '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24',
    '224.0.0.0/4', '240.0.0.0/4'))


@dataclass(frozen=True)
class FrozenFileIdentity:
    final_path: str
    volume_serial: int
    file_id: int
    sha256: str


@dataclass(frozen=True)
class ProcessRedirectRule:
    protocol: str
    image_path: str
    image_sha256: str
    original_ipv4: str
    target_ipv4: str
    file_identity: FrozenFileIdentity


class OwnerResolutionStatus(Enum):
    RESOLVED = 'RESOLVED'
    NOT_FOUND = 'NOT_FOUND'
    AMBIGUOUS = 'AMBIGUOUS'
    ERROR = 'ERROR'


@dataclass(frozen=True)
class ProcessOwnerIdentity:
    pid: int
    creation_time: int
    final_path: str
    volume_serial: int
    file_id: int


@dataclass(frozen=True)
class OwnerResolution:
    status: OwnerResolutionStatus
    identity: object = None
    detail: str = ''


@dataclass(frozen=True)
class PacketTuple:
    direction: str
    ipv4_version: int
    fragmented: bool
    protocol: str
    tcp_flags: int
    source_ipv4: str
    source_port: int
    target_ipv4: str
    target_port: int
    interface_index: int
    subinterface_index: int
    packet_size: int = 0


class ProcessRedirectAction(Enum):
    NOT_APPLICABLE = 'NOT_APPLICABLE'
    PASS_UNCHANGED = 'PASS_UNCHANGED'
    REWRITE_OUTBOUND = 'REWRITE_OUTBOUND'
    REWRITE_INBOUND = 'REWRITE_INBOUND'
    DROP = 'DROP'


@dataclass(frozen=True)
class ProcessRedirectDecision:
    action: ProcessRedirectAction
    reason: str
    generation: object = None
    rewrite_target_ipv4: object = None
    rewrite_target_port: object = None
    rewrite_source_ipv4: object = None
    rewrite_source_port: object = None
    pid: object = None
    process_creation_time: object = None
    process_file_id: object = None


@dataclass(frozen=True)
class PreparedRedirect:
    decision: ProcessRedirectDecision
    token: object = None


@dataclass
class _Mapping:
    generation: int
    local_ipv4: str
    local_port: int
    original_port: int
    interface_index: int
    subinterface_index: int
    pid: int
    process_creation_time: int
    created_at: float
    last_seen_at: float
    client_fin_seen: bool = False
    server_fin_seen: bool = False
    half_closed_at: object = None

    def forward_key(self, original_ipv4):
        return ('TCP', self.local_ipv4, self.local_port,
                original_ipv4, self.original_port,
                self.interface_index, self.subinterface_index)

    def reverse_key(self, target_ipv4):
        return ('TCP', target_ipv4, self.original_port,
                self.local_ipv4, self.local_port,
                self.interface_index, self.subinterface_index)

    def client_key(self):
        return ('TCP', self.local_ipv4, self.local_port,
                self.interface_index, self.subinterface_index)


@dataclass
class _Transaction:
    token: int
    mapping: _Mapping
    packet: PacketTuple
    new_mapping: bool
    created_at: float


class ProcessRedirectEngine(object):
    """Thread-safe, fail-closed stateful NAT decision module."""

    _TH_FIN = 0x01
    _TH_SYN = 0x02
    _TH_RST = 0x04
    _TH_ACK = 0x10

    def __init__(self, rule, owner_resolver, route_guard, clock=None):
        self.rule = rule
        self._owner_resolver = owner_resolver
        self._route_guard = route_guard
        self._clock = clock or time.monotonic
        self._lock = threading.RLock()
        self._closed = False
        self._suspended = False
        self._suspend_reason = None
        self._generation = 0
        self._token = 0
        self._forward = {}
        self._reverse = {}
        self._client = {}
        self._transactions = {}
        self._reservations = set()
        self._tombstones = {}
        self._query_tokens = 16.0
        self._query_refill_at = self._clock()
        self._syn_query_cache = {}
        self._audit = Counter()
        self._audit_started_at = self._clock()
        self._last_audit_drain = self._audit_started_at

    @staticmethod
    def _drop(reason):
        return PreparedRedirect(ProcessRedirectDecision(
            ProcessRedirectAction.DROP, reason))

    @staticmethod
    def _not_applicable(reason='not_applicable'):
        return PreparedRedirect(ProcessRedirectDecision(
            ProcessRedirectAction.NOT_APPLICABLE, reason))

    @staticmethod
    def _pass(reason):
        return PreparedRedirect(ProcessRedirectDecision(
            ProcessRedirectAction.PASS_UNCHANGED, reason))

    def _forward_key(self, packet):
        return (packet.protocol, packet.source_ipv4, packet.source_port,
                packet.target_ipv4, packet.target_port,
                packet.interface_index, packet.subinterface_index)

    def _reverse_key(self, packet):
        return (packet.protocol, packet.source_ipv4, packet.source_port,
                packet.target_ipv4, packet.target_port,
                packet.interface_index, packet.subinterface_index)

    def _new_transaction_locked(self, mapping, packet, new_mapping):
        self._token += 1
        transaction = _Transaction(
            self._token, mapping, packet, new_mapping, self._clock())
        self._transactions[transaction.token] = transaction
        return transaction.token

    def _purge_tombstones_locked(self, now):
        for key, item in list(self._tombstones.items()):
            if item[0] <= now:
                self._tombstones.pop(key, None)

    def _add_tombstone_locked(self, mapping, seconds, reason):
        expires_at = self._clock() + seconds
        self._tombstones[mapping.forward_key(
            self.rule.original_ipv4)] = (expires_at, reason)
        self._tombstones[mapping.reverse_key(
            self.rule.target_ipv4)] = (expires_at, reason)

    def _remove_mapping_locked(self, mapping):
        self._forward.pop(mapping.forward_key(
            self.rule.original_ipv4), None)
        self._reverse.pop(mapping.reverse_key(
            self.rule.target_ipv4), None)
        if self._client.get(mapping.client_key()) is mapping:
            self._client.pop(mapping.client_key(), None)

    def _observe_tcp_locked(self, mapping, packet):
        if packet.tcp_flags & self._TH_RST:
            self._remove_mapping_locked(mapping)
            self._add_tombstone_locked(mapping, 240, 'normal_close')
            self._audit['closed_normal_rst'] += 1
            return 'normal_rst'
        if packet.tcp_flags & self._TH_FIN:
            if packet.direction == 'outbound':
                mapping.client_fin_seen = True
            else:
                mapping.server_fin_seen = True
            if mapping.half_closed_at is None:
                mapping.half_closed_at = self._clock()
            if mapping.client_fin_seen and mapping.server_fin_seen:
                self._remove_mapping_locked(mapping)
                self._add_tombstone_locked(mapping, 240, 'normal_close')
                self._audit['closed_normal_fin'] += 1
                return 'normal_fin'
        return None

    def _cleanup_locked(self, now):
        self._purge_tombstones_locked(now)
        for key, item in list(self._syn_query_cache.items()):
            if item[0] <= now:
                self._syn_query_cache.pop(key, None)
        for token, transaction in list(self._transactions.items()):
            if now - transaction.created_at >= 2:
                self._transactions.pop(token, None)
                if transaction.new_mapping:
                    self._add_tombstone_locked(
                        transaction.mapping, 3, 'pending_timeout')
        seen = set()
        for mapping in list(self._forward.values()):
            if id(mapping) in seen:
                continue
            seen.add(id(mapping))
            reason = None
            if (mapping.half_closed_at is not None and
                    now - mapping.half_closed_at >= 120):
                reason = 'half_close_timeout'
            elif now - mapping.last_seen_at >= 1800:
                reason = 'idle_timeout'
            if reason:
                self._remove_mapping_locked(mapping)
                self._add_tombstone_locked(mapping, 240, reason)
                self._audit['closed_' + reason] += 1

    def _consume_query_budget_locked(self, now):
        elapsed = max(0.0, now - self._query_refill_at)
        self._query_tokens = min(
            16.0, self._query_tokens + elapsed * 32.0)
        self._query_refill_at = now
        if self._query_tokens < 1.0:
            return False
        self._query_tokens -= 1.0
        return True

    def _owner_matches_rule(self, owner):
        frozen = self.rule.file_identity
        return bool(
            isinstance(owner, ProcessOwnerIdentity) and
            ntpath.normcase(ntpath.normpath(owner.final_path)) ==
            ntpath.normcase(ntpath.normpath(frozen.final_path)) and
            int(owner.volume_serial) == int(frozen.volume_serial) and
            int(owner.file_id) == int(frozen.file_id))

    def prepare(self, packet):
        if not isinstance(packet, PacketTuple):
            return self._drop('invalid_packet_tuple')
        if packet.ipv4_version != 4 or packet.protocol != 'TCP':
            return self._not_applicable()
        if packet.direction == 'inbound':
            return self._prepare_inbound(packet)
        if packet.direction != 'outbound':
            return self._drop('invalid_direction')
        if packet.target_ipv4 != self.rule.original_ipv4:
            return self._not_applicable()
        if packet.fragmented:
            return self._drop('process_redirect_fragment')

        key = self._forward_key(packet)
        cached_resolution = None
        with self._lock:
            self._cleanup_locked(self._clock())
            if self._closed or self._suspended:
                return self._drop('process_redirect_unavailable')
            tombstone = self._tombstones.get(key)
            if tombstone is not None:
                return self._drop(tombstone[1] + '_tombstone')
            mapping = self._forward.get(key)
            if mapping is not None:
                if len(self._transactions) >= 128:
                    return self._drop('pending_transaction_capacity')
                token = self._new_transaction_locked(
                    mapping, packet, False)
                return PreparedRedirect(ProcessRedirectDecision(
                    ProcessRedirectAction.REWRITE_OUTBOUND,
                    'existing_mapping', mapping.generation,
                    rewrite_target_ipv4=self.rule.target_ipv4,
                    rewrite_target_port=packet.target_port), token)
            new_syn = bool(
                packet.tcp_flags & self._TH_SYN and
                not packet.tcp_flags & self._TH_ACK)
            if not new_syn:
                return self._drop('unmapped_a_flow')
            if key in self._reservations:
                return self._drop('owner_query_pending')
            if len(self._reservations) + len(self._transactions) >= 128:
                return self._drop('pending_transaction_capacity')
            for transaction in self._transactions.values():
                if (transaction.new_mapping and
                        transaction.mapping.forward_key(
                            self.rule.original_ipv4) == key):
                    return self._drop('mapping_pending')
            cached = self._syn_query_cache.get(key)
            if cached is not None:
                cached_resolution = cached[1]
            else:
                if len(self._syn_query_cache) >= 4096:
                    self._audit['owner_query_cache_full'] += 1
                    return self._drop('owner_query_cache_full')
                if not self._consume_query_budget_locked(self._clock()):
                    self._audit['owner_query_budget_exhausted'] += 1
                    return self._drop('owner_query_budget_exhausted')
            self._reservations.add(key)

        try:
            resolution = cached_resolution
            if resolution is None:
                resolution = self._owner_resolver.resolve_tcp_owner(packet)
                with self._lock:
                    self._syn_query_cache[key] = (
                        self._clock() + 3, resolution)
            if not isinstance(resolution, OwnerResolution):
                return self._drop('owner_result_invalid')
            if resolution.status != OwnerResolutionStatus.RESOLVED:
                with self._lock:
                    self._audit[
                        'owner_' + resolution.status.value.lower()] += 1
                return self._drop('owner_' + resolution.status.value.lower())
            if not self._owner_matches_rule(resolution.identity):
                with self._lock:
                    self._audit['non_target_compatibility_pass'] += 1
                return self._pass('resolved_non_target_process')
            with self._lock:
                self._audit['owner_resolved_target'] += 1
            try:
                route_current = self._route_guard.is_current(packet)
            except Exception:
                self.suspend('route_query_failed')
                return self._drop('route_query_failed')
            if not route_current:
                reason = getattr(
                    self._route_guard, 'failure_reason', None) or (
                        'route_snapshot_changed')
                self.suspend(reason)
                return self._drop(reason)
            if not self._owner_resolver.revalidate_process_identity(
                    resolution.identity):
                return self._drop('process_identity_changed')

            with self._lock:
                if self._closed or self._suspended:
                    return self._drop('process_redirect_unavailable')
                if key in self._forward:
                    return self._drop('mapping_race')
                pending_new = [
                    item.mapping for item in self._transactions.values()
                    if item.new_mapping]
                if len(self._forward) + len(pending_new) >= 1024:
                    return self._drop('global_mapping_capacity')
                pid_count = sum(
                    1 for mapping in self._forward.values()
                    if mapping.pid == resolution.identity.pid)
                pid_count += sum(
                    1 for mapping in pending_new
                    if mapping.pid == resolution.identity.pid)
                if pid_count >= 256:
                    return self._drop('per_pid_mapping_capacity')
                self._generation += 1
                now = self._clock()
                mapping = _Mapping(
                    self._generation, packet.source_ipv4,
                    packet.source_port, packet.target_port,
                    packet.interface_index, packet.subinterface_index,
                    resolution.identity.pid,
                    resolution.identity.creation_time, now, now)
                if (mapping.client_key() in self._client or
                        any(item.client_key() == mapping.client_key()
                            for item in pending_new)):
                    return self._drop('client_endpoint_conflict')
                token = self._new_transaction_locked(mapping, packet, True)
                return PreparedRedirect(ProcessRedirectDecision(
                    ProcessRedirectAction.REWRITE_OUTBOUND,
                    'new_mapping', mapping.generation,
                    rewrite_target_ipv4=self.rule.target_ipv4,
                    rewrite_target_port=packet.target_port,
                    pid=mapping.pid,
                    process_creation_time=mapping.process_creation_time,
                    process_file_id=resolution.identity.file_id), token)
        except Exception:
            return self._drop('owner_query_error')
        finally:
            with self._lock:
                self._reservations.discard(key)

    def _prepare_inbound(self, packet):
        if (packet.source_ipv4 != self.rule.target_ipv4 or
                packet.target_ipv4 == self.rule.target_ipv4):
            return self._not_applicable()
        if packet.fragmented:
            return self._drop('process_redirect_fragment')
        with self._lock:
            self._cleanup_locked(self._clock())
            if self._closed or self._suspended:
                return self._drop('process_redirect_unavailable')
            key = self._reverse_key(packet)
            tombstone = self._tombstones.get(key)
            if tombstone is not None:
                return self._drop(tombstone[1] + '_tombstone')
            mapping = self._reverse.get(key)
            if mapping is None:
                self._audit['unmapped_target_compatibility_pass'] += 1
                return self._pass('unmapped_target_ingress')
            if len(self._transactions) >= 128:
                return self._drop('pending_transaction_capacity')
            token = self._new_transaction_locked(mapping, packet, False)
            return PreparedRedirect(ProcessRedirectDecision(
                ProcessRedirectAction.REWRITE_INBOUND,
                'reverse_mapping', mapping.generation,
                rewrite_source_ipv4=self.rule.original_ipv4,
                rewrite_source_port=packet.source_port), token)

    def commit(self, token, outcome):
        with self._lock:
            transaction = self._transactions.pop(token, None)
            if transaction is None:
                raise RuntimeError('unknown or already completed token')
            if not outcome:
                self._remove_mapping_locked(transaction.mapping)
                self._add_tombstone_locked(
                    transaction.mapping, 3, 'injection_failure')
                self._audit['injection_failures'] += 1
                return False
            mapping = transaction.mapping
            if transaction.new_mapping:
                self._forward[mapping.forward_key(
                    self.rule.original_ipv4)] = mapping
                self._reverse[mapping.reverse_key(
                    self.rule.target_ipv4)] = mapping
                self._client[mapping.client_key()] = mapping
                self._audit['mappings_created'] += 1
            mapping.last_seen_at = self._clock()
            direction = ('forward' if
                         transaction.packet.direction == 'outbound' else
                         'reverse')
            self._audit[direction + '_packets'] += 1
            self._audit[direction + '_bytes'] += max(
                0, int(transaction.packet.packet_size))
            self._observe_tcp_locked(mapping, transaction.packet)
            return True

    def abort(self, token, reason):
        del reason
        with self._lock:
            transaction = self._transactions.pop(token, None)
            if transaction is None:
                raise RuntimeError('unknown or already completed token')
            self._remove_mapping_locked(transaction.mapping)
            self._add_tombstone_locked(
                transaction.mapping, 3, 'injection_failure')
            self._audit['aborted_transactions'] += 1
            return False

    def close(self, reason='closed'):
        del reason
        with self._lock:
            self._closed = True
            self._transactions.clear()
            self._reservations.clear()
            self._forward.clear()
            self._reverse.clear()
            self._client.clear()
            self._tombstones.clear()
            self._syn_query_cache.clear()
            self._audit['engine_closed'] += 1

    def suspend(self, reason):
        with self._lock:
            if self._closed:
                return False
            changed = not self._suspended
            self._suspended = True
            if self._suspend_reason is None:
                self._suspend_reason = str(reason)
            for mapping in list(self._forward.values()):
                self._remove_mapping_locked(mapping)
                self._add_tombstone_locked(mapping, 240, 'suspended')
            self._transactions.clear()
            self._reservations.clear()
            if changed:
                self._audit['engine_suspended'] += 1
            return changed

    def resume(self):
        try:
            if not self._route_guard.validate_resume():
                return False
            if not self._owner_resolver.revalidate_rule_file(
                    self.rule.file_identity):
                return False
        except Exception:
            return False
        with self._lock:
            if self._closed:
                return False
            self._suspended = False
            self._suspend_reason = None
            self._generation += 1
            self._audit['engine_resumed'] += 1
            return True

    def drain_audit_summary(self, force=False):
        with self._lock:
            now = self._clock()
            if not force and now - self._last_audit_drain < 60:
                return None
            if not self._audit and not force:
                self._last_audit_drain = now
                return None
            summary = dict(self._audit)
            summary.update({
                'window_seconds': max(0.0, now - self._last_audit_drain),
                'active_mappings': len(self._forward),
                'pending_transactions': len(self._transactions),
                'available': not self._closed and not self._suspended,
            })
            self._audit.clear()
            self._last_audit_drain = now
            return summary

    def settings(self):
        with self._lock:
            return {
                'enabled': True,
                'available': not self._closed and not self._suspended,
                'suspend_reason': self._suspend_reason,
                'active_mappings': len(self._forward),
                'pending_transactions': len(self._transactions),
                'audit_counters': dict(self._audit),
            }


def _enabled_value(value):
    normalized = str(value).strip().lower()
    if normalized in ('yes', 'true', 'on', 'enabled'):
        return True
    if normalized in ('no', 'false', 'off', 'disabled'):
        return False
    raise ValueError('ExternalProcessRedirectEnabled must be Yes or No')


def _canonical_windows_path(value):
    raw = str(value).strip()
    if (not raw or '%' in raw or '*' in raw or '?' in raw or
            raw.startswith(('\\\\', '\\??\\')) or not ntpath.isabs(raw)):
        raise ValueError(
            'ExternalProcessRedirectImagePath must be an absolute drive path')
    drive, tail = ntpath.splitdrive(raw)
    if (not re.match(r'^[A-Za-z]:$', drive) or ':' in tail or
            tail.endswith(('\\', '/'))):
        raise ValueError(
            'ExternalProcessRedirectImagePath must name a file without ADS')
    normalized = ntpath.normpath(raw)
    if normalized in (drive + '\\', drive + '/'):
        raise ValueError('ExternalProcessRedirectImagePath must name a file')
    return raw


def _global_ipv4(value):
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    if (address.version != 4 or str(address) != str(value).strip() or
            not address.is_global or address.is_multicast or
            address.is_reserved or address.is_unspecified or
            address.is_loopback or address.is_link_local or
            any(address in network for network in _NON_GLOBAL_NETWORKS)):
        return None
    return str(address)


def _rfc1918_ipv4(value):
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    if address.version != 4 or str(address) != str(value).strip():
        return None
    if not any(
            address in network and
            address not in (network.network_address,
                            network.broadcast_address)
            for network in _RFC1918_NETWORKS):
        return None
    if (address.is_loopback or address.is_link_local or address.is_multicast or
            address.is_unspecified or address.is_reserved):
        return None
    return str(address)


def parse_process_redirect_rule(config, local_ipv4, external_dns_server,
                                takeover_ipv4, reviewed_ipv4,
                                process_rule_reviewer, platform_name):
    """Return a reviewed immutable rule, or ``None`` when disabled."""
    enabled = _enabled_value(config.get(
        'externalprocessredirectenabled', 'No'))
    if not enabled:
        return None
    if str(platform_name).lower() != 'windows':
        raise ValueError('ExternalProcessRedirect is supported only on Windows')
    if process_rule_reviewer is None:
        raise ValueError(
            'ExternalProcessRedirect requires a Windows file reviewer')

    names = (
        'externalprocessredirectprotocol',
        'externalprocessredirectimagepath',
        'externalprocessredirectimagesha256',
        'externalprocessredirectoriginalipv4',
        'externalprocessredirecttargetipv4',
    )
    missing = [name for name in names
               if name not in config or not str(config[name]).strip()]
    if missing:
        raise ValueError('missing process redirect fields: %s' %
                         ','.join(missing))

    protocol = str(config[names[0]]).strip()
    if protocol != 'TCP':
        raise ValueError('ExternalProcessRedirectProtocol must be TCP')
    image_path = _canonical_windows_path(config[names[1]])
    image_sha256 = str(config[names[2]]).strip().lower()
    if not re.match(r'^[0-9a-f]{64}$', image_sha256):
        raise ValueError(
            'ExternalProcessRedirectImageSHA256 must contain 64 hex digits')
    original_ipv4 = _global_ipv4(config[names[3]])
    if original_ipv4 is None:
        raise ValueError(
            'ExternalProcessRedirectOriginalIPv4 must be global unicast')
    target_ipv4 = _rfc1918_ipv4(config[names[4]])
    if target_ipv4 is None:
        raise ValueError(
            'ExternalProcessRedirectTargetIPv4 must be usable RFC1918')

    protected = set(str(value) for value in local_ipv4)
    protected.add(str(external_dns_server))
    if original_ipv4 in protected or target_ipv4 in protected:
        raise ValueError('process redirect address conflicts with local/DNS')
    if takeover_ipv4 and target_ipv4 == str(takeover_ipv4):
        raise ValueError('process redirect target conflicts with takeover')
    if original_ipv4 in set(str(value) for value in reviewed_ipv4):
        raise ValueError('process redirect original conflicts with reviewed IP')

    identity = process_rule_reviewer.review_rule_file(
        image_path, image_sha256)
    if not isinstance(identity, FrozenFileIdentity):
        raise ValueError('Windows file reviewer returned an invalid identity')
    if identity.sha256.lower() != image_sha256:
        raise ValueError('reviewed process image SHA-256 changed')
    return ProcessRedirectRule(
        protocol='TCP', image_path=identity.final_path,
        image_sha256=image_sha256, original_ipv4=original_ipv4,
        target_ipv4=target_ipv4, file_identity=identity)
