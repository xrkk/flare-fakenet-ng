import configparser
import pathlib
import threading
import unittest
from unittest import mock

from fakenet.diverters.egresspolicy import Verdict
from fakenet.diverters.windows import Diverter


class Policy(object):
    relay_port = 38927

    def is_exact_local_ipv4(self, value):
        return value in ('127.0.0.1', '10.0.0.5')


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

    def test_exact_dhcp_exception(self):
        dhcp = Packet(proto='UDP', sport=68,
                      dst='255.255.255.255', dport=67)
        self.assertEqual(
            Verdict.REINJECT_LOCAL,
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


if __name__ == '__main__':
    unittest.main()
