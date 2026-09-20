"""Cross-protocol requested-log distinction through the real handle_pkt chain.

Production defect (candidate05-restart-01 sst-075): PidCommDest.isDistinct
compares pid/comm/port/ip but not proto, so after 'requested TCP
198.51.100.77:1337' for PID 3016 the same-PID/same-destination UDP case
(sport 63461) was silently suppressed — run.log has no 'requested UDP
198.51.100.77:1337' although the 57-byte echo exchange itself succeeded,
which is exactly the 'requested <PROTO>' anchor the suite's exact policy
flow needs.

Contract: same PID/comm/destination IP/port but different TCP/UDP protocol
MUST each get their requested line; same-proto repeats and same-proto
near-duplicates redirected to a bound/local IP stay suppressed; blacklist
debug-level behavior unchanged.

The handle_pkt chain here is the REAL production method on a minimal
concrete DiverterBase subclass: the OS-specific surface (packet capture,
pid lookup) is stubbed at the seams the abstract class already defines, the
log decision path (first_packet_new_session -> PidCommDest ->
isProcessBlackListed -> logger.info) is untouched production code.
"""
import logging
import sys
import types
import unittest
import unittest.mock

if 'netifaces' not in sys.modules:
    _netifaces = types.ModuleType('netifaces')
    _netifaces.AF_INET = 2
    _netifaces.AF_INET6 = 23
    _netifaces.interfaces = lambda: []
    _netifaces.ifaddresses = lambda interface: {}
    sys.modules['netifaces'] = _netifaces

from fakenet.diverters import diverterbase
from fakenet.diverters.diverterbase import (DiverterBase, PidCommDest,
                                            DGENPKTV)


class FakePkt:
    """Minimal fnpacket shape for the handle_pkt log branch."""

    def __init__(self, proto, src_ip, sport, dst_ip, dport):
        self.ipver = 4
        self.label = proto
        self.proto = proto
        self.src_ip = src_ip
        self.sport = sport
        self.dst_ip = dst_ip
        self.dport = dport
        self.dst_ip0 = dst_ip
        self.dport0 = dport
        self.src_ip0 = src_ip
        self.mangled = False

    def hdrToStr(self):
        return '%s %s:%d->%s:%d' % (self.proto, self.src_ip, self.sport,
                                    self.dst_ip, self.dport)


class StubDiverter(DiverterBase):
    """Concrete diverter carrying only what handle_pkt's decision path reads.

    Every abstract OS method is a no-op stub; get_pid_comm is the documented
    OS seam (real implementations read the OS flow table).
    """

    def __init__(self, pid_comm):
        self._pid_comm = pid_comm
        self.logger = logging.getLogger('fakenet.diverters.test')
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False
        self.pdebug_level = 0  # keep the DGENPKTV branch off so the log elif runs
        self.pid = 4242        # diverter's own pid; probe pid must differ
        self.last_conn = None
        self.sessions = {}
        self.ip_addrs = {4: {'192.168.204.233'}, 6: set()}
        self.loopback_ip = '127.0.0.1'
        # isProcessBlackListed (base implementation) reads these; not
        # blacklisted by construction in these tests.
        self.single_host_mode = True
        self.proxy_sport_to_orig_sport_map = {}
        self.blacklist_processes = set()  # nothing blacklisted by default
        # DivertParms.dport_hidden_listener reads listener_ports; no hidden
        # listeners in these tests.
        self.listener_ports = types.SimpleNamespace(
            isHidden=lambda proto, dport: False,
            isListener=lambda proto, dport: False,
            isProcessBlackListHit=lambda *a, **k: False)

    def get_pid_comm(self, pkt):
        return self._pid_comm

    # -- abstract OS surface: stubs only, never reached by these tests --
    def start(self):  # pragma: no cover - abstract stub
        pass

    def stop(self):  # pragma: no cover - abstract stub
        pass

    def check_active_ethernet_adapters(self):  # pragma: no cover
        return True

    def check_gateways(self):  # pragma: no cover
        return True

    def check_dns_servers(self):  # pragma: no cover
        return True

    def flush_dns(self):  # pragma: no cover
        pass

    def set_dns_server(self, *a, **k):  # pragma: no cover
        pass

    def restore_network_settings(self, *a, **k):  # pragma: no cover
        pass

    def getLocalIP(self, *a, **k):  # pragma: no cover
        return '192.168.204.233'

    def stopCallback(self):  # pragma: no cover
        return True

    def write_pcap(self, pkt):  # capture seam: never touch disk in tests
        pass


class CaptureHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        self.records.append(record.getMessage())


def run_packets(diverter, packets):
    handler = CaptureHandler()
    diverter.logger.addHandler(handler)
    try:
        for pkt in packets:
            diverter.handle_pkt(pkt, [], [])
    finally:
        diverter.logger.removeHandler(handler)
    return handler.records


def tcp_pkt(sport=11575):
    return FakePkt('TCP', '192.168.204.233', sport, '198.51.100.77', 1337)


def udp_pkt(sport=63461):
    return FakePkt('UDP', '192.168.204.233', sport, '198.51.100.77', 1337)


class ProtocolDistinctionTests(unittest.TestCase):

    def test_tcp_then_udp_same_pid_destination_both_logged(self):
        """The exact 075 shape: TCP first, then a UDP case to the same
        destination with the same PID must produce BOTH requested lines."""
        diverter = StubDiverter((3016, 'powershell.exe'))
        records = run_packets(diverter, [tcp_pkt(), udp_pkt()])
        self.assertIn('powershell.exe (3016) requested TCP 198.51.100.77:1337',
                      records)
        self.assertIn('powershell.exe (3016) requested UDP 198.51.100.77:1337',
                      records)

    def test_udp_then_tcp_same_pid_destination_both_logged(self):
        diverter = StubDiverter((3016, 'powershell.exe'))
        records = run_packets(diverter, [udp_pkt(), tcp_pkt()])
        self.assertIn('powershell.exe (3016) requested UDP 198.51.100.77:1337',
                      records)
        self.assertIn('powershell.exe (3016) requested TCP 198.51.100.77:1337',
                      records)

    def test_same_proto_repeat_still_suppressed(self):
        diverter = StubDiverter((3016, 'powershell.exe'))
        records = run_packets(diverter, [udp_pkt(sport=51001),
                                         udp_pkt(sport=51001)])
        self.assertEqual(records.count(
            'powershell.exe (3016) requested UDP 198.51.100.77:1337'), 1)

    def test_same_proto_redirected_near_duplicate_still_suppressed(self):
        """Same proto, same pid/comm/port, destination rewritten to a bound
        local IP: the historical near-duplicate suppression must hold."""
        diverter = StubDiverter((3016, 'powershell.exe'))
        first = udp_pkt(sport=51002)
        redirected = FakePkt('UDP', '192.168.204.233', 51002,
                             '192.168.204.233', 1337)  # bound IP re-inject
        records = run_packets(diverter, [first, redirected])
        self.assertEqual(
            [r for r in records if 'requested UDP' in r],
            ['powershell.exe (3016) requested UDP 198.51.100.77:1337'])

    def test_different_protocol_even_to_bound_ip_is_distinct(self):
        diverter = StubDiverter((3016, 'powershell.exe'))
        tcp = tcp_pkt()
        redirected_udp = FakePkt('UDP', '192.168.204.233', 51003,
                                 '192.168.204.233', 1337)
        records = run_packets(diverter, [tcp, redirected_udp])
        self.assertIn('powershell.exe (3016) requested UDP 192.168.204.233:1337',
                      records)

    def test_independent_identity_changes_keep_behavior(self):
        original = PidCommDest(3016, 'powershell.exe', 'TCP',
                               '198.51.100.77', 1337)
        for args in ((3017, 'powershell.exe', 'TCP', '198.51.100.77', 1337),
                     (3016, 'other.exe', 'TCP', '198.51.100.77', 1337),
                     (3016, 'powershell.exe', 'TCP', '203.0.113.9', 1337),
                     (3016, 'powershell.exe', 'TCP', '198.51.100.77', 443)):
            with self.subTest(args=args):
                self.assertTrue(PidCommDest(*args).isDistinct(original, set()))

    def test_blacklist_still_logs_at_debug_not_info(self):
        diverter = StubDiverter((3016, 'powershell.exe'))
        with unittest.mock.patch.object(
                diverter, 'isProcessBlackListed', return_value=(True, [], [])):
            with self.assertLogs(diverter.logger, level=logging.DEBUG) as logs:
                diverter.handle_pkt(udp_pkt(), [], [])
        requested = [r for r in logs.records if 'requested UDP' in r.getMessage()]
        self.assertEqual(len(requested), 1)
        self.assertEqual(requested[0].levelno, logging.DEBUG)


class PidCommDestUnitTests(unittest.TestCase):

    def test_isdistinct_compares_proto(self):
        tcp = PidCommDest(3016, 'powershell.exe', 'TCP', '198.51.100.77', 1337)
        udp = PidCommDest(3016, 'powershell.exe', 'UDP', '198.51.100.77', 1337)
        self.assertTrue(udp.isDistinct(tcp, set()))
        self.assertTrue(tcp.isDistinct(udp, set()))
        same = PidCommDest(3016, 'powershell.exe', 'UDP', '198.51.100.77', 1337)
        self.assertFalse(same.isDistinct(udp, set()))


if __name__ == '__main__':
    unittest.main()
