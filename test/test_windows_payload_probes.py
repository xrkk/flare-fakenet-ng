"""Windows offload bytes and acknowledged one-octet keepalive regression."""
import base64
import tempfile
import unittest
from pathlib import Path

import dpkt

from fakenet.diverters.pcapwriter import DualPcapWriter
from fakenet.payload_report import (CaptureObservationIndex, PayloadReportError,
                                    SessionFlowRegistry, build_payload_report)


def packet(reverse=False, seq=100, ack=1, data=b'', flags=dpkt.tcp.TH_ACK,
           zero_checksums=False):
    src, dst, sport, dport = ('192.0.2.1', '198.51.100.2', 40000, 8001)
    if reverse:
        src, dst, sport, dport = dst, src, dport, sport
    import socket
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags, data=data)
    tcp.off = 5
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=6, ttl=64, data=tcp)
    ip.len = len(ip)
    ip.data.ack = ack
    ip.data.sum = 0
    raw = bytearray(bytes(ip))
    if zero_checksums:
        raw[10:12] = b'\x00\x00'
        raw[36:38] = b'\x00\x00'
    return bytes(raw)


class WindowsPayloadProbeTests(unittest.TestCase):
    def report(self, packets, mutate_pair=False):
        with tempfile.TemporaryDirectory() as folder:
            raw, eth = Path(folder)/'a.pcap', Path(folder)/'b.pcap'
            index, registry = CaptureObservationIndex(), SessionFlowRegistry()
            writer = DualPcapWriter(raw, eth, clock=lambda: 1000.0+len(index))
            for n, data in enumerate(packets, 1):
                fid = registry.observe_packet(data, 'outbound', n, str(n))
                self.assertTrue(writer.write_ip_packet(data))
                index.record(data, 'initial', str(n), fid, 'outbound',
                             writer.last_timestamp, writer.last_record_ordinal)
            writer.close()
            if mutate_pair:
                content = bytearray(eth.read_bytes())
                # PCAP headers 24+16, Ethernet14, IP checksum byte10.
                content[24+16+14+10] ^= 1
                eth.write_bytes(content)
            return build_payload_report(raw, index, registry,
                                        converted_pcap_path=eth)

    def test_acknowledged_keepalive_octet_is_not_application_data(self):
        for start in (100, 0xfffffffd):
            end = (start+3) & 0xffffffff
            with self.subTest(start=start):
                model = self.report([
                    packet(seq=start, data=b'abc', flags=24),
                    packet(reverse=True, seq=900, ack=end),
                    packet(seq=(end-1)&0xffffffff, data=b'\x00'),
                    packet(seq=end, data=b'def', flags=24)])
                direction = model['flows'][0]['directions']['outbound']
                self.assertEqual(b'abcdef', base64.b64decode(direction['base64']))
                self.assertEqual([3], direction['tcp_keepalive_probe_ordinals'])
                self.assertEqual(4, model['capture']['raw_record_count'])

    def test_conflicts_without_exact_probe_evidence_still_fail(self):
        cases = [
            ('no-peer-ack', [], packet(seq=102, data=b'\x00')),
            ('wrong-peer-ack', [packet(reverse=True, ack=104)], packet(seq=102, data=b'\x00')),
            ('push', [packet(reverse=True, ack=103)], packet(seq=102, data=b'\x00', flags=24)),
            ('wrong-position', [packet(reverse=True, ack=103)], packet(seq=101, data=b'\x00')),
            ('two-bytes', [packet(reverse=True, ack=103)], packet(seq=101, data=b'XX')),
        ]
        for label, middle, tail in cases:
            with self.subTest(label=label):
                with self.assertRaisesRegex(PayloadReportError, 'TCP conflicting'):
                    self.report([packet(data=b'abc', flags=24)]+middle+[tail])

    def test_new_single_octet_data_is_kept(self):
        model = self.report([packet(data=b'abc', flags=24),
                             packet(reverse=True, ack=103),
                             packet(seq=103, data=b'd')])
        direction = model['flows'][0]['directions']['outbound']
        self.assertEqual(b'abcd', base64.b64decode(direction['base64']))
        self.assertNotIn('tcp_keepalive_probe_ordinals', direction)

    def test_zero_checksum_original_pair_is_compared_without_serializing(self):
        model = self.report([packet(data=b'abc', flags=24, zero_checksums=True)])
        self.assertTrue(model['capture']['overall_health'])
        with self.assertRaisesRegex(PayloadReportError, 'does not embed'):
            self.report([packet(data=b'abc', flags=24, zero_checksums=True)],
                        mutate_pair=True)
