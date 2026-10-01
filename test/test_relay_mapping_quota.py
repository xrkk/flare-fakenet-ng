"""Real policy allocation -> Windows packet boundary -> MCP log health.

Only WinDivert packet decoding/sending and capture IO are substituted. The
production policy, NAT lookups, SYN allocation and health predicate run intact.
"""
import io
import logging
from types import SimpleNamespace
from unittest import mock

import dpkt
import pytest

from test_windows_egress_verdict import Diverter, Packet
from test_egresspolicy import Clock, config
from fakenet.diverters.egresspolicy import EgressPolicy
from fakenet.mcp.supervisor import evaluate_health_evidence


LOCAL = ['10.0.1.%d' % n for n in range(1, 10)]
REMOTE = '93.184.216.34'


def policy_with_clock():
    clock = Clock()
    policy = EgressPolicy(config(), LOCAL, [], '10.0.0.1', clock)
    policy.replace_leases('api.deepseek.com', [(REMOTE, 60)])
    return policy, clock


def allocate(policy, source, port):
    return policy.create_relay_mapping(
        source, port, REMOTE, 443, source, policy.relay_port)


def packet_handler(policy):
    d = Diverter.__new__(Diverter)
    d.egress_policy = policy
    d._reviewed_target_protocols = frozenset()
    d._drop_log_state = {}
    d._syn_observed_flows = set()
    d._midstream_bypass_flows = set()
    d._observed_nat_tuples = {}
    d._observed_nat_forward = set()
    d._observed_nat_owners = {}
    d._timed_write_pcap = mock.Mock()
    d._log_a_teardown_seen = mock.Mock()
    d._matches_takeover_sink_route = mock.Mock(return_value=False)
    d._send_packet = mock.Mock(return_value=True)
    stream = io.StringIO()
    logger = logging.Logger('quota-production-path', logging.DEBUG)
    logger.addHandler(logging.StreamHandler(stream))
    d.logger = logger
    return d, stream


def handle_syn(d, source, port):
    packet = Packet(src=source, sport=port, dst=REMOTE)
    packet.hdr = SimpleNamespace(data=SimpleNamespace(flags=dpkt.tcp.TH_SYN))
    wire = SimpleNamespace(raw=memoryview(bytes.fromhex(
        '4500001400000000400600000a0001015db8d822')),
        is_loopback=False, is_outbound=True)
    with mock.patch('fakenet.diverters.windows.WindowsPacketCtx',
                    return_value=packet):
        d._handle_policy_packet(wire)
    return packet


@pytest.mark.parametrize('scope', ['per_source', 'global'])
def test_real_saturated_packet_denies_without_poisoning_health(scope):
    policy, _ = policy_with_clock()
    count = 32 if scope == 'per_source' else 256
    for offset in range(count):
        allocate(policy, LOCAL[offset // 32], 40000 + offset)
    source = LOCAL[0] if scope == 'per_source' else LOCAL[8]
    d, stream = packet_handler(policy)
    before = (policy._nat_pending, dict(policy._nat_pending_by_source),
              dict(policy._nat_forward), dict(policy._nat_reverse),
              dict(policy._nat_client), dict(policy._nat_generation))
    packet = handle_syn(d, source, 50000)
    after = (policy._nat_pending, dict(policy._nat_pending_by_source),
             dict(policy._nat_forward), dict(policy._nat_reverse),
             dict(policy._nat_client), dict(policy._nat_generation))
    assert after == before
    d._send_packet.assert_not_called()
    assert (packet.dst_ip, packet.dport) == (REMOTE, 443)
    healthy, reason = evaluate_health_evidence(
        dict(process_alive=True, init_evidence=True, probe=True),
        stream.getvalue())
    assert healthy, (reason, stream.getvalue())
    assert 'pending_quota' in stream.getvalue()
    assert "quota_scope=" + scope in stream.getvalue()
    assert 'DROP_EXTERNAL' in stream.getvalue()


def test_atomic_last_pending_slot_under_concurrent_creation():
    import threading
    policy, _ = policy_with_clock()
    for n in range(31):
        allocate(policy, LOCAL[0], 40000 + n)
    barrier = threading.Barrier(33, timeout=5)
    admitted, denied, errors = [], [], []

    def worker(n):
        try:
            barrier.wait()
            admitted.append(allocate(policy, LOCAL[0], 50000 + n))
        except RuntimeError as exc:
            denied.append(str(exc))
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(33)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(6)
    assert not any(t.is_alive() for t in threads)
    assert not errors
    assert len(admitted) == 1 and len(denied) == 32
    assert set(denied) == {'relay mapping pending quota exceeded'}
    assert policy._nat_pending == policy._nat_pending_by_source[LOCAL[0]] == 32
    assert all(len(table) == 32 for table in (
        policy._nat_forward, policy._nat_reverse,
        policy._nat_client, policy._nat_generation))


def test_consumed_close_and_unconsumed_timeout_recover_quota():
    policy, clock = policy_with_clock()
    mappings = [allocate(policy, LOCAL[0], 40000 + n) for n in range(32)]
    assert policy.consume_relay_target(LOCAL[0], 40000) is mappings[0]
    assert policy.consume_relay_target(LOCAL[0], 40000) is None
    policy.close_relay_mapping(mappings[0].generation)
    policy.close_relay_mapping(mappings[0].generation)  # duplicate cancellation
    assert policy._nat_pending == 31
    replacement = allocate(policy, LOCAL[0], 50000)
    assert policy._nat_pending == 32
    clock.value += 10.01
    assert policy.match_relay_forward('TCP', LOCAL[0], 50000, REMOTE, 443) is None
    assert policy._nat_pending == 0 and not policy._nat_pending_by_source
    assert not policy._nat_generation and not policy._nat_client
    assert not policy._nat_forward and not policy._nat_reverse
    assert allocate(policy, LOCAL[0], 51000).generation > replacement.generation


def test_real_accept_rate_denies_leave_only_bounded_pending_reservations():
    from fakenet.listeners.DomainEgressRelay import DomainEgressRelay
    policy, clock = policy_with_clock()
    relay = DomainEgressRelay({'port': policy.relay_port})
    # Consume the reviewed 64 accepts/10-second source rate with real method;
    # no network is opened and no worker is invented as a historical count.
    with mock.patch('fakenet.listeners.DomainEgressRelay.time.monotonic',
                    return_value=clock.value):
        assert all(relay._allow_new_flow_rate(LOCAL[0]) for _ in range(64))
        for n in range(32):
            mapping = allocate(policy, LOCAL[0], 40000 + n)
            assert not relay._allow_new_flow_rate(LOCAL[0])
            assert not mapping.consumed
        with pytest.raises(RuntimeError, match='pending quota'):
            allocate(policy, LOCAL[0], 50000)
    clock.value += 10.01
    assert allocate(policy, LOCAL[0], 51000)
    assert policy._nat_pending == 1


def test_unknown_runtime_error_still_emits_traceback_and_fails_health():
    policy, _ = policy_with_clock()
    d, stream = packet_handler(policy)
    with mock.patch.object(policy, '_ensure_open',
                           side_effect=RuntimeError('unexpected allocator bug')):
        handle_syn(d, LOCAL[0], 50000)
    d._send_packet.assert_not_called()
    assert not policy._nat_forward and policy._nat_pending == 0
    text = stream.getvalue()
    assert 'policy_exception' in text and 'Traceback (most recent call last)' in text
    assert 'unexpected allocator bug' in text
    assert evaluate_health_evidence(
        dict(process_alive=True, init_evidence=True, probe=True), text) == (
            False, 'unhandled exception in current run log')


def test_per_source_full_table_does_not_block_another_source():
    policy, _ = policy_with_clock()
    for n in range(32):
        allocate(policy, LOCAL[0], 40000 + n)
    d, _ = packet_handler(policy)
    packet = Packet(src=LOCAL[1], sport=50000, dst=REMOTE)
    mapping, lease = d.redirect_domain_tls_syn(packet)
    assert lease.domain == 'api.deepseek.com'
    assert mapping.sample_ip == LOCAL[1] and policy._nat_pending == 33
    assert (packet.dst_ip, packet.dport) == (LOCAL[1], policy.relay_port)
    assert policy._nat_pending_by_source[LOCAL[0]] == 32
    assert policy._nat_pending_by_source[LOCAL[1]] == 1


def test_syn_retransmission_does_not_allocate_or_refresh_pending_mapping():
    policy, clock = policy_with_clock()
    mapping = allocate(policy, LOCAL[0], 40000)
    d, _ = packet_handler(policy)
    packet = Packet(src=LOCAL[0], sport=40000, dst=REMOTE)
    original = ('TCP', LOCAL[0], 40000, REMOTE, 443)
    deadline = mapping.expires_at
    clock.value += 1
    assert d.apply_domain_relay_forward_redirect(packet, original) is mapping
    assert mapping.expires_at == deadline
    assert policy._nat_pending == len(policy._nat_generation) == 1
    policy.close_relay_mapping(mapping.generation, grace_seconds=0)
    with pytest.raises(ValueError, match='tombstoned'):
        allocate(policy, LOCAL[0], 40000)
    clock.value += policy.RELAY_TOMBSTONE_SECONDS + 0.01
    policy.replace_leases("api.deepseek.com", [(REMOTE, 60)])
    current = allocate(policy, LOCAL[0], 40000)
    policy.close_relay_mapping(mapping.generation)
    assert current.generation > mapping.generation
    assert policy.match_relay_forward(*original) is current
    assert policy._nat_pending == 1


def test_wrong_or_expired_dns_lease_is_not_reinterpreted_as_quota_deny():
    policy, clock = policy_with_clock()
    with pytest.raises(ValueError, match='no current DNS lease'):
        policy.create_relay_mapping(LOCAL[0], 50000, '203.0.113.7',
                                    443, LOCAL[0], policy.relay_port)
    d, _ = packet_handler(policy)
    packet = Packet(src=LOCAL[0], sport=50000, dst=REMOTE)
    # Lease valid at lookup but expires before the atomic allocation check.
    with mock.patch.object(policy, '_now', side_effect=[100., 100., 161.]):
        with pytest.raises(ValueError, match='DNS lease expired'):
            d.redirect_domain_tls_syn(packet)
    assert policy._nat_pending == 0 and not policy._nat_generation
    assert (packet.dst_ip, packet.dport) == (REMOTE, 443)


def test_real_mismatched_sni_worker_releases_both_pending_accounts():
    from fakenet.listeners.DomainEgressRelay import DomainEgressRelay
    from test_domain_egress_relay import ChunkSocket, client_hello, settings
    policy, _ = policy_with_clock()
    mapping = allocate(policy, LOCAL[0], 40000)
    assert policy.consume_relay_target(LOCAL[0], 40000) is mapping
    relay = DomainEgressRelay({'port': policy.relay_port})
    relay._settings = settings()
    d, stream = packet_handler(policy)
    relay.callbacks = SimpleNamespace(
        closeRelayMapping=policy.close_relay_mapping,
        logEgressEvent=d.log_egress_event)
    assert relay._acquire_pending(LOCAL[0])
    client = ChunkSocket([client_hello('example.com')])
    relay._handle_client(client, (LOCAL[0], 40000), mapping)
    assert client.closed and not relay._connections and not relay._workers
    assert relay._pending == policy._nat_pending == 0
    assert not relay._pending_by_source and not policy._nat_pending_by_source
    assert not policy._nat_generation and not policy._nat_client
    assert 'reason_code=sni_mismatch' in stream.getvalue()


def test_actual_rate_rejected_accepts_leave_reservations_until_timeout():
    from fakenet.listeners.DomainEgressRelay import DomainEgressRelay
    from test_domain_egress_relay import ChunkSocket
    policy, clock = policy_with_clock()
    relay = DomainEgressRelay({'port': policy.relay_port})
    d, stream = packet_handler(policy)
    relay.callbacks = SimpleNamespace(
        isLocalAddress=policy.is_exact_local_ipv4,
        consumeRelayTarget=policy.consume_relay_target,
        closeRelayMapping=policy.close_relay_mapping,
        logEgressEvent=d.log_egress_event)
    clients = []

    class Arrivals:
        def accept(self):
            n = len(clients)
            if n == 32:
                relay._stop.set()
                raise OSError('bounded scripted accept finished')
            allocate(policy, LOCAL[0], 40000 + n)
            client = ChunkSocket()
            clients.append(client)
            return client, (LOCAL[0], 40000 + n)

    relay._listener = Arrivals()
    with mock.patch('fakenet.listeners.DomainEgressRelay.time.monotonic',
                    return_value=clock.value):
        assert all(relay._allow_new_flow_rate(LOCAL[0]) for _ in range(64))
        relay._accept_loop()
    assert all(c.closed for c in clients)
    assert not relay._workers and not relay._connections
    assert relay._pending == 0
    assert policy._nat_pending == 32
    assert not any(m.consumed for m in policy._nat_generation.values())
    assert stream.getvalue().count('reason_code=mapping_or_pending_quota') == 32
    clock.value += 10.01
    assert allocate(policy, LOCAL[0], 50000)
    assert policy._nat_pending == 1
