import configparser
import json
import pathlib
import subprocess
import threading
import unittest
from unittest import mock

from fakenet.diverters.egresspolicy import (
    PolicyConfigError, ReviewedIPv4Rule, ReviewedPacketTuple, Verdict)
from fakenet.diverters.windows import (
    Diverter, ReviewedIpFlowAudit, ROUTE_PROBE_UDP_PORT)


class Policy(object):
    relay_port = 38927

    def is_exact_local_ipv4(self, value):
        return value in ('127.0.0.1', '10.0.0.5')


class TakeoverPolicy(Policy):
    takeover_enabled = True
    takeover_ipv4 = '192.168.204.1'

    def matches_takeover_sink(self, proto, src_ip, sport, dst_ip, dport):
        try:
            sport = int(sport)
            dport = int(dport)
        except (TypeError, ValueError):
            return False
        return (str(proto).upper() in ('TCP', 'UDP') and
                src_ip == '10.0.0.5' and
                dst_ip == self.takeover_ipv4 and
                1 <= sport <= 65535 and 1 <= dport <= 65535)


class MappingPolicy(Policy):
    def __init__(self):
        self.lease = object()
        self.mapping = object()
        self.mapping_args = None

    def lease_for(self, ip, port):
        if (ip, port) == ('93.184.216.34', 443):
            return self.lease
        return None

    def create_relay_mapping(self, *args):
        self.mapping_args = args
        return self.mapping


class ReviewedPolicy(Policy):
    def __init__(self, protocol='TCP', port_scope='exact', port=443):
        normalized_port = '*' if port_scope == 'all' else port
        self.rule = ReviewedIPv4Rule(
            'rule-test', protocol, '110.242.69.21', port_scope,
            None if port_scope == 'all' else port,
            '%s/110.242.69.21/%s' % (protocol, normalized_port))

    def match_reviewed_ip(self, packet):
        port_matches = (self.rule.port_scope == 'all' or
                        packet.target_port == self.rule.port)
        if (packet.outbound and packet.protocol == self.rule.protocol and
                packet.source_ipv4 == '10.0.0.5' and
                packet.source_port == 50000 and
                packet.target_ipv4 == '110.242.69.21' and
                port_matches and
                packet.interface_index == 7):
            return self.rule
        return None


class ReviewedRoutePolicy(ReviewedPolicy):
    reviewed_ipv4_enabled = True

    def reviewed_ip_settings(self):
        return {'rules': (self.rule,)}


class AuditClock(object):
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class ListenerPorts(object):
    def isListener(self, proto, port):
        return (proto, port) in (('TCP', 38926), ('TCP', 38927))

    def isProcessBlackListHit(self, proto, port, comm):
        return False

    def isProcessWhiteListMiss(self, proto, port, comm):
        return False

    def isHostWhiteListMiss(self, proto, port, host):
        return False

    def isHostBlackListHit(self, proto, port, host):
        return False

    def intersectsWithPorts(self, proto, ports):
        return False


class Packet(object):
    def __init__(self, proto='TCP', src='10.0.0.5', sport=50000,
                 dst='93.184.216.34', dport=443):
        self.proto = proto
        self.src_ip = src
        self.sport = sport
        self.dst_ip = dst
        self.dport = dport
        self.src_ip0 = src
        self.sport0 = sport
        self.dst_ip0 = dst
        self.dport0 = dport
        self.ipver = 4
        self.interface_index = 7
        self.subinterface_index = 0
        self.is_outbound = True
        self.mangled = False

    def hdrToStr(self):
        return 'test packet'


class WindowsVerdictTests(unittest.TestCase):
    def setUp(self):
        self.diverter = Diverter.__new__(Diverter)
        self.diverter.egress_policy = Policy()
        self.diverter.listener_ports = ListenerPorts()
        self.diverter._dict = {'redirectalltraffic': 'yes'}
        self.diverter.single_host_mode = True
        self.diverter.blacklist_processes = []
        self.diverter.whitelist_processes = []
        self.diverter.blacklist_ports = {'TCP': [], 'UDP': []}
        self.diverter.ip_addrs = {4: ['10.0.0.5']}
        self.diverter.pid = 999
        self.diverter.pdebug_level = 0
        self.diverter.pdebug_labels = {}
        self.diverter._reviewed_target_protocols = frozenset()

    def test_external_is_dropped_even_after_ignore_paths(self):
        self.assertEqual(
            Verdict.DROP_EXTERNAL,
            self.diverter.finalize_egress_verdict(Packet()))

    def test_process_and_port_blacklists_cannot_grant_egress(self):
        packet = Packet()
        self.diverter.blacklist_processes = ['blocked.exe']
        self.assertTrue(self.diverter.check_should_ignore(
            packet, 123, 'blocked.exe'))
        self.assertEqual(Verdict.DROP_EXTERNAL,
                         self.diverter.finalize_egress_verdict(packet))

        self.diverter.blacklist_processes = []
        self.diverter.blacklist_ports['TCP'] = [443]
        self.assertTrue(self.diverter.check_should_ignore(packet, 123, None))
        self.assertEqual(Verdict.DROP_EXTERNAL,
                         self.diverter.finalize_egress_verdict(packet))

    def test_local_listener_and_local_response(self):
        self.assertEqual(
            Verdict.DIVERT_FAKE,
            self.diverter.finalize_egress_verdict(
                Packet(dst='10.0.0.5', dport=38926)))
        self.assertEqual(
            Verdict.REINJECT_LOCAL,
            self.diverter.finalize_egress_verdict(
                Packet(dst='10.0.0.5', dport=50001)))

    def test_dhcp_broadcast_is_not_an_egress_exception(self):
        dhcp = Packet(proto='UDP', sport=68,
                      dst='255.255.255.255', dport=67)
        self.assertEqual(
            Verdict.DROP_EXTERNAL,
            self.diverter.finalize_egress_verdict(dhcp))
        dhcp.dst_ip = '10.0.0.255'
        self.assertEqual(
            Verdict.DROP_EXTERNAL,
            self.diverter.finalize_egress_verdict(dhcp))

    def test_unknown_external_protocol_is_dropped(self):
        self.assertEqual(
            Verdict.DROP_EXTERNAL,
            self.diverter.finalize_egress_verdict(Packet(proto=None)))

    def test_only_explicit_permit_allows_external(self):
        self.assertEqual(
            Verdict.ALLOW_INTERNAL_UPSTREAM,
            self.diverter.finalize_egress_verdict(
                Packet(), permit=object()))

    def test_relay_verdict_revalidates_local_listener_target(self):
        self.assertEqual(
            Verdict.REDIRECT_TLS_RELAY,
            self.diverter.finalize_egress_verdict(
                Packet(dst='10.0.0.5', dport=38927),
                relay_redirected=True))
        self.assertEqual(
            Verdict.DROP_EXTERNAL,
            self.diverter.finalize_egress_verdict(
                Packet(dst='93.184.216.34', dport=38927),
                relay_redirected=True))

    def test_relay_redirect_uses_flow_source_on_multihomed_host(self):
        policy = MappingPolicy()
        self.diverter.egress_policy = policy
        self.diverter.external_ip = '10.0.0.99'
        packet = Packet(src='10.0.0.5', dst='93.184.216.34', dport=443)

        mapping, lease = self.diverter.redirect_domain_tls_syn(packet)

        self.assertIs(mapping, policy.mapping)
        self.assertIs(lease, policy.lease)
        self.assertEqual(
            ('10.0.0.5', 50000, '93.184.216.34', 443,
             '10.0.0.5', 38927),
            policy.mapping_args)
        self.assertEqual(('10.0.0.5', 38927),
                         (packet.dst_ip, packet.dport))

    def test_default_configuration_keeps_domain_policy_disabled(self):
        path = (pathlib.Path(__file__).resolve().parents[1] /
                'fakenet' / 'configs' / 'default.ini')
        parser = configparser.ConfigParser(
            strict=True, interpolation=None)
        with path.open(encoding='utf-8-sig') as stream:
            parser.read_file(stream)
        self.assertEqual(
            'disabled',
            parser['Diverter']['ExternalAccessPolicy'].strip().lower())

    def test_disabled_mode_preserves_legacy_packet_dispatch(self):
        wrapped_packet = object()
        windivert_packet = object()
        self.diverter._callbacks = mock.Mock(
            return_value=(['callback-three'], ['callback-four']))
        self.diverter.handle_pkt = mock.Mock()
        self.diverter._send_packet = mock.Mock(return_value=True)

        with mock.patch('fakenet.diverters.windows.WindowsPacketCtx',
                        return_value=wrapped_packet) as packet_context:
            self.diverter._handle_legacy_packet(windivert_packet)

        packet_context.assert_called_once_with('divert_thread',
                                               windivert_packet)
        self.diverter.handle_pkt.assert_called_once_with(
            wrapped_packet, ['callback-three'], ['callback-four'])
        self.diverter._send_packet.assert_called_once_with(wrapped_packet)

    def test_receiver_exit_suspends_and_restores_before_handle_close(self):
        diverter = Diverter.__new__(Diverter)
        diverter._diverter_exited = threading.Event()
        diverter._diverter_exited.set()
        diverter._stopping = threading.Event()
        diverter.logger = mock.Mock()
        diverter.egress_policy = mock.Mock()
        first_listener = mock.Mock()
        second_listener = mock.Mock()
        diverter._policy_listeners = [first_listener, second_listener]
        diverter.handle = mock.Mock()
        sequence = mock.Mock()
        diverter.egress_policy.suspend = sequence.suspend
        first_listener.stop = sequence.first_stop
        second_listener.stop = sequence.second_stop
        diverter._restore_network_settings = sequence.restore
        diverter.handle.close = sequence.close

        diverter._watch_diverter_thread()

        self.assertTrue(first_listener._policy_stopped)
        self.assertTrue(second_listener._policy_stopped)
        self.assertEqual([
            mock.call.suspend(),
            mock.call.second_stop(),
            mock.call.first_stop(),
            mock.call.restore(),
            mock.call.close(),
        ], sequence.mock_calls)

    def test_suspend_policy_marks_stopping_before_policy_suspend(self):
        diverter = Diverter.__new__(Diverter)
        diverter.domain_allowlist_mode = True
        diverter._stopping = threading.Event()
        diverter.egress_policy = mock.Mock()
        diverter.egress_policy.suspend.side_effect = lambda: self.assertTrue(
            diverter._stopping.is_set())

        diverter.suspend_policy()

        self.assertTrue(diverter._stopping.is_set())
        diverter.egress_policy.suspend.assert_called_once_with()

    def test_address_refresh_shutdown_race_has_no_false_critical_log(self):
        diverter = Diverter.__new__(Diverter)
        diverter._stopping = mock.Mock()
        diverter._stopping.wait.return_value = False
        diverter._stopping.is_set.side_effect = [False, True]
        diverter.get_adapters_info = mock.Mock(return_value=[object()])
        diverter.get_ipaddresses = mock.Mock(return_value=['10.0.0.5'])
        diverter.external_ip = '10.0.0.5'
        diverter.egress_policy = mock.Mock()
        diverter.egress_policy.takeover_available.return_value = True
        diverter.egress_policy.update_local_ipv4.return_value = False
        diverter.logger = mock.Mock()

        diverter._refresh_local_addresses()

        diverter.egress_policy.update_local_ipv4.assert_called_once_with(
            {'10.0.0.5'})
        diverter.logger.critical.assert_not_called()

    def test_address_refresh_still_reports_unsafe_runtime_change(self):
        diverter = Diverter.__new__(Diverter)
        diverter._stopping = mock.Mock()
        diverter._stopping.wait.return_value = False
        diverter._stopping.is_set.return_value = False
        diverter.get_adapters_info = mock.Mock(return_value=[object()])
        diverter.get_ipaddresses = mock.Mock(return_value=['10.0.0.5'])
        diverter.external_ip = '10.0.0.5'
        diverter.egress_policy = mock.Mock()
        diverter.egress_policy.takeover_available.return_value = True
        diverter.egress_policy.update_local_ipv4.return_value = False
        diverter.logger = mock.Mock()

        diverter._refresh_local_addresses()

        diverter.logger.critical.assert_called_once_with(
            'DomainAllowList suspended after unsafe address change')

    def test_host_blacklist_cannot_grant_external_egress(self):
        packet = Packet()
        self.diverter.listener_ports.isHostBlackListHit = mock.Mock(
            return_value=True)
        self.assertTrue(self.diverter.check_should_ignore(
            packet, 123, 'sample.exe'))
        self.assertEqual(
            Verdict.DROP_EXTERNAL,
            self.diverter.finalize_egress_verdict(packet))

    def test_ftp_active_compatibility_port_cannot_grant_egress(self):
        local = Packet(src='10.0.0.5', sport=20,
                       dst='10.0.0.5', dport=50001)
        self.assertTrue(self.diverter.check_should_ignore(
            local, self.diverter.pid, 'python.exe'))
        self.assertIn(20, self.diverter.blacklist_ports['TCP'])
        external = Packet(src='10.0.0.5', sport=20,
                          dst='93.184.216.34', dport=443)
        self.assertTrue(self.diverter.check_should_ignore(
            external, 123, 'sample.exe'))
        self.assertEqual(
            Verdict.DROP_EXTERNAL,
            self.diverter.finalize_egress_verdict(external))

    def test_windivert_send_failure_is_contained(self):
        self.diverter.handle = mock.Mock()
        self.diverter.handle.send.side_effect = OSError('send failed')
        self.diverter.logger = mock.Mock()

        self.assertFalse(self.diverter._send_windivert_packet(
            object(), 'fault injection'))
        self.diverter.handle.send.assert_called_once()
        self.diverter.logger.error.assert_called_once()

    @mock.patch('fakenet.diverters.windows.ctypes.windll.kernel32.SetLastError')
    def test_windivert_close_clears_stale_last_error(self, clear_last_error):
        handle = mock.Mock()
        self.diverter.handle = handle

        self.diverter._close_windivert_handle()

        clear_last_error.assert_called_once_with(0)
        handle.close.assert_called_once_with()
        self.assertIsNone(self.diverter.handle)

    def test_ipv6_is_classified_before_packet_context(self):
        ipv6 = bytes.fromhex('6000000000003b40')
        self.assertEqual(
            Verdict.DROP_EXTERNAL,
            self.diverter.classify_ipv6_preparse(ipv6, False))
        self.assertEqual(
            Verdict.REINJECT_LOCAL,
            self.diverter.classify_ipv6_preparse(ipv6, True))
        self.assertIsNone(self.diverter.classify_ipv6_preparse(
            bytes.fromhex('45000014'), False))

    def test_takeover_sink_verdict_is_exact_for_tcp_and_udp(self):
        self.diverter.egress_policy = TakeoverPolicy()
        for proto in ('TCP', 'UDP'):
            for port in (1, 443, 65535):
                packet = Packet(
                    proto=proto, dst='192.168.204.1', dport=port)
                self.assertEqual(
                    Verdict.ALLOW_TAKEOVER_SINK,
                    self.diverter.finalize_egress_verdict(
                        packet, takeover_sink=True))
        for destination in ('192.168.204.2', '10.0.0.1',
                            '93.184.216.34'):
            packet = Packet(dst=destination, dport=443)
            self.assertEqual(
                Verdict.DROP_EXTERNAL,
                self.diverter.finalize_egress_verdict(
                    packet, takeover_sink=True))

    def test_takeover_sink_is_revalidated_before_reinjection(self):
        self.diverter.egress_policy = TakeoverPolicy()
        packet = Packet(dst='192.168.204.1', dport=8443)
        packet.src_ip = '10.0.0.99'
        self.assertEqual(
            Verdict.DROP_EXTERNAL,
            self.diverter.finalize_egress_verdict(
                packet, takeover_sink=True))

    def test_takeover_sink_bypasses_legacy_redirect_unchanged(self):
        self.diverter.egress_policy = TakeoverPolicy()
        packet = Packet(
            proto='UDP', dst='192.168.204.1', dport=443)
        windivert_packet = mock.Mock()
        windivert_packet.raw.tobytes.return_value = bytes.fromhex(
            '4500001400000000401100000a000005c0a8cc01')
        windivert_packet.is_loopback = False
        self.diverter.write_pcap = mock.Mock()
        self.diverter.log_egress_event = mock.Mock()
        self.diverter._send_packet = mock.Mock(return_value=True)
        self.diverter.handle_pkt = mock.Mock()
        self.diverter.apply_domain_relay_return_fixup = mock.Mock(
            return_value=None)
        self.diverter.egress_policy.match_control_flow = mock.Mock(
            return_value=None)

        with mock.patch('fakenet.diverters.windows.WindowsPacketCtx',
                        return_value=packet):
            self.diverter._handle_policy_packet(windivert_packet)

        self.diverter._send_packet.assert_called_once_with(packet)
        self.diverter.handle_pkt.assert_not_called()
        self.diverter.log_egress_event.assert_called_once_with(
            'ALLOW_TAKEOVER_SINK', ip='192.168.204.1',
            proto='UDP', sport=50000, dport=443)

    def test_takeover_listener_response_must_match_policy(self):
        diverter = Diverter.__new__(Diverter)
        diverter.egress_policy = TakeoverPolicy()
        diverter.egress_policy.relay_port = 38927
        relay = {
            'listener': 'DomainEgressRelay', 'protocol': 'TCP',
            'port': '38927'}
        udp = {
            'listener': 'DNSListener', 'protocol': 'UDP',
            'port': '53', 'responsea': '192.168.204.1'}
        tcp = {
            'listener': 'DNSListener', 'protocol': 'TCP',
            'port': '53', 'responsea': '192.168.204.2'}
        diverter.listeners_config = {
            'relay': relay, 'dnsudp': udp, 'dnstcp': tcp}
        with self.assertRaises(PolicyConfigError):
            diverter._validate_policy_listeners()
        tcp['responsea'] = '192.168.204.1'
        diverter._validate_policy_listeners()

    def test_route_snapshot_requires_exact_contract(self):
        diverter = Diverter.__new__(Diverter)
        diverter.egress_policy = TakeoverPolicy()
        valid = ({
            'interface_index': 7,
            'interface_alias': 'Ethernet0',
            'source_ipv4': '10.0.0.5',
            'destination_prefix': '192.168.204.0/24',
            'next_hop': '0.0.0.0',
            'route_metric': 10,
            'interface_metric': 20,
        })
        completed = mock.Mock(returncode=0, stdout=__import__('json').dumps(
            valid), stderr='')
        with mock.patch('fakenet.diverters.windows.subprocess.run',
                        return_value=completed):
            self.assertEqual(valid, diverter._read_takeover_route_snapshot())

        completed.stdout = '{"interface_index": 7}'
        with mock.patch('fakenet.diverters.windows.subprocess.run',
                        return_value=completed):
            with self.assertRaises(PolicyConfigError):
                diverter._read_takeover_route_snapshot()

    def test_reviewed_ip_allow_is_revalidated_before_reinjection(self):
        self.diverter.egress_policy = ReviewedPolicy()
        packet = Packet(dst='110.242.69.21', dport=443)
        rule = self.diverter.egress_policy.rule

        self.assertEqual(
            Verdict.ALLOW_REVIEWED_IP,
            self.diverter.finalize_egress_verdict(
                packet, reviewed_rule=rule))

        packet.interface_index = 8
        self.assertEqual(
            Verdict.DROP_EXTERNAL,
            self.diverter.finalize_egress_verdict(
                packet, reviewed_rule=rule))

    def test_reviewed_ip_match_requires_outbound_packet_tuple(self):
        packet = Packet(dst='110.242.69.21', dport=443)
        packet.is_outbound = False
        reviewed = self.diverter._reviewed_packet_tuple(packet)

        self.assertIsInstance(reviewed, ReviewedPacketTuple)
        self.assertFalse(reviewed.outbound)

    def test_reviewed_fragment_gate_drops_only_reviewed_protocol_targets(self):
        def ipv4(target, protocol, fragment_field):
            raw = bytearray(20)
            raw[0] = 0x45
            raw[6:8] = fragment_field.to_bytes(2, 'big')
            raw[9] = protocol
            raw[16:20] = bytes(int(part) for part in target.split('.'))
            return bytes(raw)

        protocols = frozenset((
            ('TCP', '110.242.69.21'), ('UDP', '110.242.69.21')))
        for fragment_field in (0x2000, 0x0001, 0x3fff):
            self.assertTrue(self.diverter.classify_reviewed_ipv4_fragment(
                ipv4('110.242.69.21', 6, fragment_field), protocols))
            self.assertTrue(self.diverter.classify_reviewed_ipv4_fragment(
                ipv4('110.242.69.21', 17, fragment_field), protocols))

        self.assertFalse(self.diverter.classify_reviewed_ipv4_fragment(
            ipv4('110.242.69.21', 6, 0), protocols))
        self.assertFalse(self.diverter.classify_reviewed_ipv4_fragment(
            ipv4('110.242.70.57', 6, 0x2000), protocols))
        self.assertFalse(self.diverter.classify_reviewed_ipv4_fragment(
            ipv4('110.242.69.21', 1, 0x2000), protocols))
        self.assertFalse(self.diverter.classify_reviewed_ipv4_fragment(
            bytes.fromhex('4500'), protocols))

    def test_reviewed_fragment_precedes_control_flow_and_packet_parser(self):
        raw = bytearray(20)
        raw[0] = 0x45
        raw[6:8] = (0x2000).to_bytes(2, 'big')
        raw[9] = 6
        raw[16:20] = bytes((110, 242, 69, 21))
        windivert_packet = mock.Mock()
        windivert_packet.raw.tobytes.return_value = bytes(raw)
        windivert_packet.is_loopback = False
        self.diverter._reviewed_target_protocols = frozenset((
            ('TCP', '110.242.69.21'),))
        self.diverter.log_egress_event = mock.Mock()
        self.diverter.egress_policy.match_control_flow = mock.Mock()

        with mock.patch('fakenet.diverters.windows.WindowsPacketCtx') as ctx:
            self.diverter._handle_policy_packet(windivert_packet)

        ctx.assert_not_called()
        self.diverter.egress_policy.match_control_flow.assert_not_called()
        self.diverter.log_egress_event.assert_called_once_with(
            'DROP_EXTERNAL', reason='reviewed_ip_fragment',
            proto='TCP', ip='110.242.69.21')

    def test_reviewed_ip_precedes_legacy_blacklist_and_redirect(self):
        policy = ReviewedPolicy()
        policy.match_control_flow = mock.Mock(return_value=None)
        policy.matches_takeover_sink = mock.Mock(return_value=False)
        self.diverter.egress_policy = policy
        self.diverter.blacklist_ports['TCP'] = [443]
        self.diverter._reviewed_target_protocols = frozenset((
            ('TCP', '110.242.69.21'),))
        self.diverter.write_pcap = mock.Mock()
        self.diverter.log_egress_event = mock.Mock()
        self.diverter._send_packet = mock.Mock(return_value=True)
        self.diverter._record_reviewed_ip_allow = mock.Mock()
        self.diverter.apply_domain_relay_return_fixup = mock.Mock(
            return_value=None)
        self.diverter.apply_domain_relay_forward_redirect = mock.Mock(
            return_value=None)
        self.diverter._is_new_tcp_syn = mock.Mock(return_value=False)
        self.diverter.handle_pkt = mock.Mock()
        packet = Packet(dst='110.242.69.21', dport=443)
        windivert_packet = mock.Mock()
        windivert_packet.raw.tobytes.return_value = bytes.fromhex(
            '4500001400000000400600000a0000056ef24515')
        windivert_packet.is_loopback = False

        with mock.patch('fakenet.diverters.windows.WindowsPacketCtx',
                        return_value=packet):
            self.diverter._handle_policy_packet(windivert_packet)

        self.diverter._send_packet.assert_called_once_with(packet)
        self.diverter.handle_pkt.assert_not_called()
        self.diverter._record_reviewed_ip_allow.assert_called_once()

    def test_reviewed_udp443_overrides_quic_and_legacy_blacklist_for_target(self):
        policy = ReviewedPolicy(protocol='UDP')
        policy.match_control_flow = mock.Mock(return_value=None)
        policy.matches_takeover_sink = mock.Mock(return_value=False)
        self.diverter.egress_policy = policy
        self.diverter.blacklist_ports['UDP'] = [443]
        self.diverter._reviewed_target_protocols = frozenset((
            ('UDP', '110.242.69.21'),))
        self.diverter.write_pcap = mock.Mock()
        self.diverter.log_egress_event = mock.Mock()
        self.diverter._send_packet = mock.Mock(return_value=True)
        self.diverter._record_reviewed_ip_allow = mock.Mock()
        self.diverter.apply_domain_relay_return_fixup = mock.Mock(
            return_value=None)
        self.diverter.apply_domain_relay_forward_redirect = mock.Mock(
            return_value=None)
        self.diverter._is_new_tcp_syn = mock.Mock(return_value=False)
        self.diverter.handle_pkt = mock.Mock()
        packet = Packet(proto='UDP', dst='110.242.69.21', dport=443)
        windivert_packet = mock.Mock()
        windivert_packet.raw.tobytes.return_value = bytes.fromhex(
            '4500001400000000401100000a0000056ef24515')
        windivert_packet.is_loopback = False

        with mock.patch('fakenet.diverters.windows.WindowsPacketCtx',
                        return_value=packet):
            self.diverter._handle_policy_packet(windivert_packet)

        self.diverter._send_packet.assert_called_once_with(packet)
        self.diverter.handle_pkt.assert_not_called()
        self.diverter._record_reviewed_ip_allow.assert_called_once()

    def test_existing_domain_mapping_precedes_reviewed_ip_rule(self):
        policy = ReviewedPolicy()
        policy.match_control_flow = mock.Mock(return_value=None)
        policy.matches_takeover_sink = mock.Mock(return_value=False)
        policy.match_reviewed_ip = mock.Mock(wraps=policy.match_reviewed_ip)
        self.diverter.egress_policy = policy
        self.diverter._reviewed_target_protocols = frozenset((
            ('TCP', '192.168.204.1'),))
        self.diverter.write_pcap = mock.Mock()
        self.diverter.log_egress_event = mock.Mock()
        self.diverter._send_packet = mock.Mock(return_value=True)
        self.diverter.apply_domain_relay_return_fixup = mock.Mock(
            return_value=None)
        mapping = object()

        def redirect(packet, original):
            packet.dst_ip = '10.0.0.5'
            packet.dport = 38927
            return mapping

        self.diverter.apply_domain_relay_forward_redirect = mock.Mock(
            side_effect=redirect)
        self.diverter._is_new_tcp_syn = mock.Mock(return_value=False)
        packet = Packet(dst='192.168.204.1', dport=443)
        windivert_packet = mock.Mock()
        windivert_packet.raw.tobytes.return_value = bytes.fromhex(
            '4500001400000000400600000a000005c0a8cc01')
        windivert_packet.is_loopback = False

        with mock.patch('fakenet.diverters.windows.WindowsPacketCtx',
                        return_value=packet):
            self.diverter._handle_policy_packet(windivert_packet)

        policy.match_reviewed_ip.assert_not_called()
        self.diverter._send_packet.assert_called_once_with(packet)
        self.assertEqual(('10.0.0.5', 38927),
                         (packet.dst_ip, packet.dport))

    def test_reviewed_route_snapshot_is_batched_and_exact(self):
        diverter = Diverter.__new__(Diverter)
        diverter.egress_policy = ReviewedRoutePolicy()
        valid = [{
            'target_ipv4': '110.242.69.21',
            'interface_index': 7,
            'interface_alias': 'Ethernet0',
            'source_ipv4': '10.0.0.5',
            'destination_prefix': '0.0.0.0/0',
            'next_hop': '10.0.0.1',
            'route_metric': 10,
            'interface_metric': 20,
        }]
        completed = mock.Mock(
            returncode=0, stdout=json.dumps(valid), stderr='')

        with mock.patch('fakenet.diverters.windows.subprocess.run',
                        return_value=completed) as run:
            self.assertEqual(
                tuple(valid), diverter._read_reviewed_ip_route_snapshots())

        self.assertEqual(ROUTE_PROBE_UDP_PORT, 9)
        self.assertEqual(run.call_args.kwargs['timeout'], 2)
        self.assertIn('110.242.69.21', run.call_args.args[0][-1])

    def test_reviewed_public_route_accepts_default_and_gateway_paths(self):
        diverter = Diverter.__new__(Diverter)
        diverter.egress_policy = ReviewedRoutePolicy()
        base = {
            'target_ipv4': '110.242.69.21',
            'interface_index': 7,
            'interface_alias': 'Ethernet0',
            'source_ipv4': '10.0.0.5',
            'destination_prefix': '0.0.0.0/0',
            'next_hop': '10.0.0.1',
            'route_metric': 10,
            'interface_metric': 20,
        }
        for changed in (
                {},
                {'destination_prefix': '110.242.0.0/16'},
                {'destination_prefix': '110.242.69.21/32',
                 'next_hop': '0.0.0.0'}):
            snapshot = dict(base, **changed)
            completed = mock.Mock(
                returncode=0, stdout=json.dumps([snapshot]), stderr='')
            with mock.patch('fakenet.diverters.windows.subprocess.run',
                            return_value=completed):
                self.assertEqual(
                    (snapshot,), diverter._read_reviewed_ip_route_snapshots())

    def test_reviewed_route_query_timeout_fails_closed(self):
        diverter = Diverter.__new__(Diverter)
        diverter.egress_policy = ReviewedRoutePolicy()

        with mock.patch(
                'fakenet.diverters.windows.subprocess.run',
                side_effect=subprocess.TimeoutExpired('powershell', 2)):
            with self.assertRaises(PolicyConfigError):
                diverter._read_reviewed_ip_route_snapshots()

    def test_reviewed_route_refresh_failure_suspends_globally_once(self):
        diverter = Diverter.__new__(Diverter)
        diverter._stopping = mock.Mock()
        diverter._stopping.wait.return_value = False
        diverter._stopping.is_set.return_value = False
        diverter.get_adapters_info = mock.Mock(return_value=[])
        diverter.get_ipaddresses = mock.Mock(return_value=[])
        diverter.external_ip = '10.0.0.5'
        diverter.egress_policy = mock.Mock()
        diverter.egress_policy.takeover_available.return_value = False
        diverter.egress_policy.update_local_ipv4.return_value = True
        diverter.egress_policy.reviewed_ipv4_enabled = True
        diverter._read_reviewed_ip_route_snapshots = mock.Mock(
            side_effect=PolicyConfigError('timeout'))
        diverter.log_egress_event = mock.Mock()
        diverter.logger = mock.Mock()

        diverter._refresh_local_addresses()

        diverter.egress_policy.suspend.assert_called_once_with()
        diverter.log_egress_event.assert_called_once_with(
            'IP_ALLOW_ROUTE_SUSPEND', reason='route_query_failed',
            error='PolicyConfigError', detail='timeout')
        diverter.logger.critical.assert_called_once()

    def test_reviewed_flow_audit_is_bounded_expires_and_summarizes(self):
        clock = AuditClock()
        audit = ReviewedIpFlowAudit(clock=clock)
        audit.MAX_ENTRIES = 2
        rule = ReviewedPolicy().rule

        def packet(port):
            return ReviewedPacketTuple(
                'TCP', '10.0.0.5', 50000 + port, '192.168.204.1', port,
                7, 0, True)

        first, pressure, entries = audit.observe(rule, packet(443))
        self.assertTrue(first)
        self.assertFalse(pressure)
        self.assertEqual(entries, 1)

    def test_reviewed_flow_audit_emits_zero_rule_summary(self):
        clock = AuditClock()
        audit = ReviewedIpFlowAudit(clock=clock, rule_ids=('rule-zero',))
        clock.advance(60)
        self.assertEqual(
            (('rule-zero', 0, 0, 0),), audit.summaries())

    def test_reviewed_flow_pressure_event_is_limited_to_once_per_minute(self):
        clock = AuditClock()
        audit = ReviewedIpFlowAudit(clock=clock)
        audit.MAX_ENTRIES = 1
        rule = ReviewedPolicy().rule

        def packet(port):
            return ReviewedPacketTuple(
                'TCP', '10.0.0.5', 50000, '192.168.204.1', port,
                7, 0, True)

        audit.observe(rule, packet(443))
        self.assertTrue(audit.observe(rule, packet(444))[1])
        self.assertFalse(audit.observe(rule, packet(445))[1])
        clock.advance(60)
        first, pressure, entries = audit.observe(rule, packet(446))
        self.assertTrue(first)
        self.assertFalse(pressure)
        self.assertEqual(1, entries)
        self.assertTrue(audit.observe(rule, packet(443))[1])
        self.assertFalse(audit.observe(rule, packet(444))[1])
        first, pressure, entries = audit.observe(rule, packet(445))
        self.assertTrue(first)
        self.assertFalse(pressure)
        self.assertEqual(entries, 1)

        clock.advance(60)
        summaries = audit.summaries()
        self.assertEqual((rule.rule_id, 7, 7, 5), summaries[0])

        clock.advance(61)
        first, pressure, entries = audit.observe(rule, packet(446))
        self.assertTrue(first)
        self.assertFalse(pressure)
        self.assertEqual(entries, 1)


if __name__ == '__main__':
    unittest.main()
