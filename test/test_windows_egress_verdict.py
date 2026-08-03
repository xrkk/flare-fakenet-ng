import unittest

from fakenet.diverters.egresspolicy import Verdict
from fakenet.diverters.windows import Diverter


class Policy(object):
    relay_port = 38927

    def is_exact_local_ipv4(self, value):
        return value in ('127.0.0.1', '10.0.0.5')


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
