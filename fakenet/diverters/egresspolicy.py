# Copyright 2026 Google LLC

"""Fail-closed domain egress policy primitives.

This module deliberately has no WinDivert or socket dependency.  The Windows
diverter, DNS listener and TLS relay share this state through a restricted
callback facade.
"""

from collections import Counter, deque
from dataclasses import dataclass
from enum import Enum
import ipaddress
import re
import secrets
import threading
import time


class PolicyConfigError(ValueError):
    pass


class Verdict(Enum):
    REDIRECT_TLS_RELAY = "REDIRECT_TLS_RELAY"
    ALLOW_INTERNAL_UPSTREAM = "ALLOW_INTERNAL_UPSTREAM"
    DIVERT_FAKE = "DIVERT_FAKE"
    REINJECT_LOCAL = "REINJECT_LOCAL"
    DROP_EXTERNAL = "DROP_EXTERNAL"


def normalize_hostname(value):
    if not isinstance(value, str):
        raise PolicyConfigError("domain must be a string")
    value = value.strip()
    if (not value or "://" in value or "/" in value or "*" in value or
            ":" in value or any(ch.isspace() for ch in value)):
        raise PolicyConfigError("domain must be a hostname without scheme, port, path or wildcard")
    if value.endswith("."):
        value = value[:-1]
    try:
        result = value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise PolicyConfigError("domain is not valid IDNA") from exc
    labels = result.split(".")
    if (len(result) > 253 or any(
            not label or len(label) > 63 or
            not re.match(r'^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$', label)
            for label in labels)):
        raise PolicyConfigError("domain has invalid labels")
    return result


def _split_csv(value):
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [item.strip() for item in str(value).split(",") if item.strip()]


def _flow_key(proto, src_ip, sport, dst_ip, dport):
    return (str(proto).upper(), str(src_ip), int(sport), str(dst_ip), int(dport))


def is_global_ipv4(value):
    try:
        address = ipaddress.ip_address(str(value))
    except ValueError:
        return False
    return address.version == 4 and address.is_global


def _local_ipv4_snapshot(values):
    result = {'127.0.0.1'}
    for value in values:
        try:
            address = ipaddress.ip_address(str(value))
        except ValueError:
            continue
        if (address.version == 4 and not address.is_unspecified and
                not address.is_multicast and str(address) != '255.255.255.255'):
            result.add(str(address))
    return frozenset(result)


@dataclass
class Lease:
    domain: str
    ip: str
    expires_at: float


@dataclass
class ControlPermit:
    token: str
    kind: str
    key: tuple
    domain: str
    expires_at: float


@dataclass
class RelayNatMapping:
    generation: int
    domain: str
    sample_ip: str
    sample_port: int
    server_ip: str
    server_port: int
    relay_ip: str
    relay_port: int
    created_at: float
    expires_at: float
    consumed: bool = False
    active: bool = False

    @property
    def forward_key(self):
        return _flow_key("TCP", self.sample_ip, self.sample_port,
                         self.server_ip, self.server_port)

    @property
    def reverse_key(self):
        return _flow_key("TCP", self.relay_ip, self.relay_port,
                         self.sample_ip, self.sample_port)

    @property
    def client_key(self):
        return (self.sample_ip, self.sample_port)


class EgressPolicy(object):
    """Thread-safe state for DomainAllowList mode."""

    RELAY_TOMBSTONE_SECONDS = 120

    def __init__(self, config, local_ipv4, local_ipv6, external_dns_server,
                 clock=None):
        self._clock = clock or time.monotonic
        self._lock = threading.RLock()
        self._generation = 0
        self._closed = False
        self._egress_suspended = False

        self.allowed_domains = frozenset(
            normalize_hostname(item)
            for item in _split_csv(config.get("externalalloweddomains", ""))
        )
        self.allowed_tcp_ports = frozenset(
            int(item) for item in _split_csv(
                config.get("externalallowedtcpports", ""))
        )
        if not self.allowed_domains:
            raise PolicyConfigError("ExternalAllowedDomains is required")
        if self.allowed_tcp_ports != frozenset([443]):
            raise PolicyConfigError("reviewed Windows mode only permits ExternalAllowedTCPPorts=443")
        if str(config.get("externalverifytlssni", "yes")).lower() not in (
                "yes", "true", "on", "enabled"):
            raise PolicyConfigError("ExternalVerifyTLSSNI must be Yes")
        if str(config.get("externalblockexternalipv6", "yes")).lower() not in (
                "yes", "true", "on", "enabled"):
            raise PolicyConfigError("ExternalBlockExternalIPv6 must be Yes")
        if str(config.get("externalblockquic", "yes")).lower() not in (
                "yes", "true", "on", "enabled"):
            raise PolicyConfigError("ExternalBlockQUIC must be Yes")

        action = str(config.get("externalnonallowedaction", "divert")).lower()
        if action not in ("divert", "drop"):
            raise PolicyConfigError("ExternalNonAllowedAction must be Divert or Drop")
        self.non_allowed_action = action

        self.relay_port = int(config.get("externalrelayport", 38927))
        if not 1 <= self.relay_port <= 65535:
            raise PolicyConfigError("ExternalRelayPort is invalid")
        self.dns_timeout = int(config.get("externaldnstimeout", 3))
        if not 1 <= self.dns_timeout <= 30:
            raise PolicyConfigError("ExternalDnsTimeout must be between 1 and 30 seconds")
        self.hello_timeout = int(config.get("externaltlshellotimeout", 5))
        self.hello_max_bytes = int(config.get("externaltlshellomaxbytes", 65536))
        self.max_pending = int(config.get("externalmaxpendingflows", 256))
        self.max_pending_per_source = int(
            config.get("externalmaxpendingpersource", 32))
        self.max_active = int(config.get("externalmaxactiverelays", 128))
        self.max_active_per_source = int(
            config.get("externalmaxactivepersource", 16))
        self.relay_idle_timeout = int(
            config.get("externalrelayidletimeout", 300))
        self.relay_buffer_bytes = int(
            config.get("externalrelaybufferbytes", 1048576))
        fixed = (self.hello_timeout, self.hello_max_bytes, self.max_pending,
                 self.max_pending_per_source, self.max_active,
                 self.max_active_per_source, self.relay_idle_timeout,
                 self.relay_buffer_bytes)
        expected = (5, 65536, 256, 32, 128, 16, 300, 1048576)
        if fixed != expected:
            raise PolicyConfigError(
                "Windows resource limits must match the reviewed values")

        try:
            dns_ip = ipaddress.ip_address(str(external_dns_server))
        except ValueError as exc:
            raise PolicyConfigError("ExternalDnsServer must resolve to IPv4") from exc
        if dns_ip.version != 4:
            raise PolicyConfigError("ExternalDnsServer must be IPv4")
        if (dns_ip.is_loopback or dns_ip.is_link_local or
                dns_ip.is_multicast or dns_ip.is_unspecified or
                dns_ip.is_reserved):
            raise PolicyConfigError("ExternalDnsServer must be a usable unicast IPv4 address")
        self.external_dns_server = str(dns_ip)

        self.local_ipv4 = _local_ipv4_snapshot(local_ipv4)
        self.local_ipv6 = frozenset(str(item).split("%")[0].lower()
                                    for item in local_ipv6)
        self.local_ipv6 = self.local_ipv6.union(["::1"])
        if self.external_dns_server in self.local_ipv4:
            raise PolicyConfigError("ExternalDnsServer cannot be a local address")

        self._leases = {domain: {} for domain in self.allowed_domains}
        self._aliases = {}
        self._permits_by_key = {}
        self._permits_by_token = {}
        self._nat_forward = {}
        self._nat_reverse = {}
        self._nat_client = {}
        self._nat_generation = {}
        self._nat_pending = 0
        self._nat_pending_by_source = Counter()
        self._nat_active = 0
        self._nat_active_by_source = Counter()
        self._tombstones = {}
        self._client_tombstones = {}
        self._expired_lease_events = deque(maxlen=1024)

    def _now(self):
        return self._clock()

    def _ensure_open(self):
        if self._closed:
            raise RuntimeError("egress policy is closed")
        if self._egress_suspended:
            raise RuntimeError("egress policy is suspended after address change")

    def update_local_ipv4(self, addresses):
        snapshot = _local_ipv4_snapshot(addresses)
        with self._lock:
            self.local_ipv4 = snapshot
            if self.external_dns_server in snapshot:
                self._suspend_locked()
                return False
            for token, permit in list(self._permits_by_token.items()):
                if permit.key[1] not in snapshot:
                    self._permits_by_token.pop(token, None)
                    if self._permits_by_key.get(permit.key) is permit:
                        self._permits_by_key.pop(permit.key, None)
            now = self._now()
            for mapping in list(self._nat_generation.values()):
                if (mapping.sample_ip not in snapshot or
                        mapping.relay_ip not in snapshot):
                    self._remove_mapping_locked(mapping, now)
            return not self._egress_suspended

    def suspend(self):
        with self._lock:
            self._suspend_locked()

    def _suspend_locked(self):
        self._egress_suspended = True
        self._leases = {domain: {} for domain in self.allowed_domains}
        self._aliases.clear()
        self._permits_by_key.clear()
        self._permits_by_token.clear()
        self._nat_forward.clear()
        self._nat_reverse.clear()
        self._nat_client.clear()
        self._nat_generation.clear()
        self._nat_pending = 0
        self._nat_pending_by_source.clear()
        self._nat_active = 0
        self._nat_active_by_source.clear()

    def is_local_address(self, value):
        value = str(value).split("%")[0].lower()
        if value in self.local_ipv4 or value in self.local_ipv6:
            return True
        try:
            return ipaddress.ip_address(value).is_loopback
        except ValueError:
            return False

    def is_exact_local_ipv4(self, value):
        value = str(value)
        if value in self.local_ipv4:
            return True
        try:
            address = ipaddress.ip_address(value)
            return address.version == 4 and address.is_loopback
        except ValueError:
            return False

    def resolve_dns_rule(self, qname):
        qname = normalize_hostname(qname)
        now = self._now()
        with self._lock:
            self._cleanup_locked(now)
            if qname in self.allowed_domains:
                return qname
            alias = self._aliases.get(qname)
            return alias[0] if alias and alias[1] > now else None

    def register_alias(self, domain, alias, ttl):
        domain = normalize_hostname(domain)
        alias = normalize_hostname(alias)
        ttl = int(ttl)
        if domain not in self.allowed_domains or ttl <= 0:
            return False
        with self._lock:
            self._ensure_open()
            self._aliases[alias] = (domain, self._now() + ttl)
        return True

    def replace_leases(self, domain, records):
        domain = normalize_hostname(domain)
        if domain not in self.allowed_domains:
            raise ValueError("lease domain is not allowed")
        now = self._now()
        replacement = {}
        for ip, ttl in records:
            ttl = int(ttl)
            if ttl > 0 and is_global_ipv4(ip):
                ip = str(ip)
                expires_at = now + ttl
                previous = replacement.get(ip)
                if previous:
                    expires_at = min(expires_at, previous.expires_at)
                replacement[ip] = Lease(domain, ip, expires_at)
        with self._lock:
            self._ensure_open()
            self._leases[domain] = replacement
            self._aliases = {
                name: entry for name, entry in self._aliases.items()
                if entry[0] != domain
            }
        return tuple(sorted(replacement))

    def lease_for(self, ip, port):
        if int(port) not in self.allowed_tcp_ports:
            return None
        now = self._now()
        with self._lock:
            if self._closed or self._egress_suspended:
                return None
            self._cleanup_locked(now)
            for domain, leases in self._leases.items():
                lease = leases.get(str(ip))
                if lease and lease.expires_at > now:
                    return lease
        return None

    def register_control_flow(self, kind, proto, src_ip, sport, dst_ip,
                              dport, domain=None, ttl=10, generation=None):
        self._ensure_open()
        kind = str(kind).lower()
        proto = str(proto).upper()
        src_ip = str(src_ip)
        dst_ip = str(dst_ip)
        dport = int(dport)
        if not self.is_exact_local_ipv4(src_ip):
            raise ValueError("control flow source must be a local IPv4 address")
        if kind == "dns":
            if dst_ip != self.external_dns_server or dport != 53 or proto not in ("UDP", "TCP"):
                raise ValueError("invalid DNS control flow")
            permit_domain = ""
        elif kind == "tls_relay":
            permit_domain = normalize_hostname(domain) if domain else ""
            with self._lock:
                self._ensure_open()
                self._cleanup_locked(self._now())
                mapping = self._nat_generation.get(int(generation or 0))
                if (proto != "TCP" or not mapping or not mapping.consumed or
                        mapping.domain != permit_domain or
                        mapping.server_ip != dst_ip or
                        mapping.server_port != dport):
                    raise ValueError("invalid TLS relay control flow")
        else:
            raise ValueError("unknown control flow kind")
        key = _flow_key(proto, src_ip, sport, dst_ip, dport)
        token = secrets.token_hex(16)
        permit = ControlPermit(token, kind, key, permit_domain,
                                self._now() + max(1, int(ttl)))
        with self._lock:
            self._ensure_open()
            if kind == 'tls_relay' and self._nat_generation.get(
                    int(generation or 0)) is not mapping:
                raise ValueError("relay mapping expired during registration")
            previous = self._permits_by_key.get(key)
            if (previous is None and len(self._permits_by_key) >=
                    self.max_pending + self.max_active):
                raise RuntimeError("control flow permit table is full")
            if previous:
                self._permits_by_token.pop(previous.token, None)
            self._permits_by_key[key] = permit
            self._permits_by_token[token] = permit
        return token

    def match_control_flow(self, proto, src_ip, sport, dst_ip, dport):
        key = _flow_key(proto, src_ip, sport, dst_ip, dport)
        now = self._now()
        with self._lock:
            if self._closed or self._egress_suspended:
                return None
            self._cleanup_locked(now)
            permit = self._permits_by_key.get(key)
            if permit and permit.expires_at > now:
                if permit.kind == 'tls_relay':
                    permit.expires_at = now + self.relay_idle_timeout + 30
                return permit
            return None

    def revoke_control_flow(self, token):
        with self._lock:
            permit = self._permits_by_token.pop(token, None)
            if permit and self._permits_by_key.get(permit.key) is permit:
                self._permits_by_key.pop(permit.key, None)

    def create_relay_mapping(self, sample_ip, sample_port, server_ip,
                             server_port, relay_ip, relay_port):
        sample_ip = str(sample_ip)
        server_ip = str(server_ip)
        relay_ip = str(relay_ip)
        sample_port = int(sample_port)
        server_port = int(server_port)
        relay_port = int(relay_port)
        lease = self.lease_for(server_ip, server_port)
        if not lease:
            raise ValueError("no current DNS lease for relay target")
        if not self.is_exact_local_ipv4(sample_ip) or not self.is_exact_local_ipv4(relay_ip):
            raise ValueError("relay mapping endpoints must be local IPv4 addresses")
        if relay_port != self.relay_port:
            raise ValueError("unexpected relay port")
        now = self._now()
        forward_key = _flow_key("TCP", sample_ip, sample_port,
                                server_ip, server_port)
        client_key = (sample_ip, sample_port)
        with self._lock:
            self._ensure_open()
            self._cleanup_locked(now)
            current_lease = self._leases.get(lease.domain, {}).get(server_ip)
            if not current_lease or current_lease.expires_at <= now:
                raise ValueError("DNS lease expired while creating relay mapping")
            if forward_key in self._nat_forward or client_key in self._nat_client:
                raise ValueError("relay mapping already exists")
            if (self._tombstones.get(forward_key, 0) > now or
                    self._client_tombstones.get(client_key, 0) > now):
                raise ValueError("relay mapping is tombstoned")
            if (self._nat_pending >= self.max_pending or
                    self._nat_pending_by_source[sample_ip] >=
                    self.max_pending_per_source):
                raise RuntimeError("relay mapping pending quota exceeded")
            self._generation += 1
            mapping = RelayNatMapping(
                self._generation, lease.domain, sample_ip, sample_port,
                server_ip, server_port, relay_ip, relay_port, now,
                now + self.hello_timeout + 5)
            if mapping.reverse_key in self._nat_reverse:
                raise ValueError("relay reverse mapping collision")
            self._nat_forward[mapping.forward_key] = mapping
            self._nat_reverse[mapping.reverse_key] = mapping
            self._nat_client[mapping.client_key] = mapping
            self._nat_generation[mapping.generation] = mapping
            self._nat_pending += 1
            self._nat_pending_by_source[sample_ip] += 1
            return mapping

    def match_relay_forward(self, proto, src_ip, sport, dst_ip, dport):
        key = _flow_key(proto, src_ip, sport, dst_ip, dport)
        return self._match_nat(self._nat_forward, key)

    def match_relay_reverse(self, proto, src_ip, sport, dst_ip, dport):
        key = _flow_key(proto, src_ip, sport, dst_ip, dport)
        return self._match_nat(self._nat_reverse, key)

    def _match_nat(self, table, key):
        now = self._now()
        with self._lock:
            if self._closed or self._egress_suspended:
                return None
            self._cleanup_locked(now)
            mapping = table.get(key)
            if mapping and mapping.expires_at > now:
                # Keep the pre-SNI deadline fixed. Refreshing a pending
                # mapping for every TCP handshake packet would allow a client
                # to hold an unauthenticated relay slot indefinitely.
                if mapping.active:
                    mapping.expires_at = now + self.relay_idle_timeout + 30
                return mapping
        return None

    def consume_relay_target(self, sample_ip, sample_port):
        now = self._now()
        key = (str(sample_ip), int(sample_port))
        with self._lock:
            self._cleanup_locked(now)
            mapping = self._nat_client.get(key)
            if not mapping or mapping.consumed or mapping.expires_at <= now:
                return None
            mapping.consumed = True
            mapping.expires_at = now + self.hello_timeout + 5
            return mapping

    def activate_relay_mapping(self, generation):
        with self._lock:
            mapping = self._nat_generation.get(int(generation))
            if not mapping or not mapping.consumed:
                return False
            if mapping.active:
                return True
            if (self._nat_active >= self.max_active or
                    self._nat_active_by_source[mapping.sample_ip] >=
                    self.max_active_per_source):
                return False
            self._release_pending_mapping_locked(mapping)
            mapping.active = True
            self._nat_active += 1
            self._nat_active_by_source[mapping.sample_ip] += 1
            mapping.expires_at = self._now() + self.relay_idle_timeout + 30
            return True

    def close_relay_mapping(self, generation):
        with self._lock:
            mapping = self._nat_generation.get(int(generation))
            if mapping:
                self._remove_mapping_locked(mapping, self._now())

    def _remove_mapping_locked(self, mapping, now):
        if mapping.active:
            if self._nat_active_by_source[mapping.sample_ip]:
                self._nat_active -= 1
                self._nat_active_by_source[mapping.sample_ip] -= 1
                if not self._nat_active_by_source[mapping.sample_ip]:
                    del self._nat_active_by_source[mapping.sample_ip]
        else:
            self._release_pending_mapping_locked(mapping)
        if self._nat_forward.get(mapping.forward_key) is mapping:
            self._nat_forward.pop(mapping.forward_key, None)
        if self._nat_reverse.get(mapping.reverse_key) is mapping:
            self._nat_reverse.pop(mapping.reverse_key, None)
        if self._nat_client.get(mapping.client_key) is mapping:
            self._nat_client.pop(mapping.client_key, None)
        self._nat_generation.pop(mapping.generation, None)
        self._tombstones[mapping.forward_key] = (
            now + self.RELAY_TOMBSTONE_SECONDS)
        self._client_tombstones[mapping.client_key] = (
            now + self.RELAY_TOMBSTONE_SECONDS)

    def _release_pending_mapping_locked(self, mapping):
        if self._nat_pending_by_source[mapping.sample_ip]:
            self._nat_pending -= 1
            self._nat_pending_by_source[mapping.sample_ip] -= 1
            if not self._nat_pending_by_source[mapping.sample_ip]:
                del self._nat_pending_by_source[mapping.sample_ip]

    def _cleanup_locked(self, now):
        for domain, leases in self._leases.items():
            retained = {}
            for ip, lease in leases.items():
                if lease.expires_at > now:
                    retained[ip] = lease
                else:
                    self._expired_lease_events.append((domain, ip))
            self._leases[domain] = retained
        self._aliases = {
            name: entry for name, entry in self._aliases.items()
            if entry[1] > now
        }
        for token, permit in list(self._permits_by_token.items()):
            if permit.expires_at <= now:
                self._permits_by_token.pop(token, None)
                if self._permits_by_key.get(permit.key) is permit:
                    self._permits_by_key.pop(permit.key, None)
        for mapping in list(self._nat_generation.values()):
            if mapping.expires_at <= now:
                self._remove_mapping_locked(mapping, now)
        self._tombstones = {
            key: expires for key, expires in self._tombstones.items()
            if expires > now
        }
        self._client_tombstones = {
            key: expires for key, expires in self._client_tombstones.items()
            if expires > now
        }

    def drain_expired_leases(self):
        with self._lock:
            self._cleanup_locked(self._now())
            events = tuple(self._expired_lease_events)
            self._expired_lease_events.clear()
            return events

    def close(self):
        with self._lock:
            self._closed = True
            self._leases = {domain: {} for domain in self.allowed_domains}
            self._aliases.clear()
            self._permits_by_key.clear()
            self._permits_by_token.clear()
            self._nat_forward.clear()
            self._nat_reverse.clear()
            self._nat_client.clear()
            self._nat_generation.clear()
            self._nat_pending = 0
            self._nat_pending_by_source.clear()
            self._nat_active = 0
            self._nat_active_by_source.clear()
            self._tombstones.clear()
            self._client_tombstones.clear()
            self._expired_lease_events.clear()
