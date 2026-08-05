import logging
import os
import struct
import tempfile
import unittest

import dpkt

from fakenet.diverters.pcapwriter import DualPcapWriter


IPV4_PACKET = bytes.fromhex(
    '45000028000100004006f97bc0000201c6336402'
    'c35001bb0000000100000000500210006f3c0000')


class DualPcapWriterTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.raw_path = os.path.join(self.tempdir.name, 'packets.pcap')
        self.converted_path = os.path.join(
            self.tempdir.name, 'packets-converted.pcap')

    @staticmethod
    def _read(path):
        with open(path, 'rb') as stream:
            reader = dpkt.pcap.Reader(stream)
            return reader.datalink(), reader.snaplen, list(reader)

    def test_writes_matching_raw_and_ethernet_records(self):
        writer = DualPcapWriter(
            self.raw_path,
            self.converted_path,
            logging.getLogger('dual-pcap-test'),
            clock=lambda: 1234.5)

        self.assertTrue(writer.write_ip_packet(IPV4_PACKET))
        summary = writer.close()

        raw_linktype, raw_snaplen, raw_records = self._read(self.raw_path)
        eth_linktype, eth_snaplen, eth_records = self._read(
            self.converted_path)
        self.assertEqual(dpkt.pcap.DLT_RAW, raw_linktype)
        self.assertEqual(12, raw_linktype)
        self.assertEqual(dpkt.pcap.DLT_EN10MB, eth_linktype)
        self.assertEqual(262144, raw_snaplen)
        self.assertEqual(262144, eth_snaplen)
        self.assertEqual([(1234.5, IPV4_PACKET)], raw_records)
        self.assertEqual(1, len(eth_records))
        self.assertEqual(1234.5, eth_records[0][0])
        self.assertEqual(IPV4_PACKET, eth_records[0][1][14:])
        self.assertEqual(
            b'\x02\x00\x00\x00\x00\x02'
            b'\x02\x00\x00\x00\x00\x01'
            + struct.pack('!H', 0x0800),
            eth_records[0][1][:14])
        self.assertTrue(summary.healthy)
        self.assertEqual(1, summary.raw_write_count)
        self.assertEqual(1, summary.ethernet_write_count)

    def test_ipv6_and_truncated_known_version_keep_matching_payloads(self):
        writer = DualPcapWriter(
            self.raw_path, self.converted_path,
            logging.getLogger('dual-pcap-test'), clock=lambda: 50.25)

        self.assertTrue(writer.write_ip_packet(b'\x60\x00'))
        self.assertTrue(writer.write_ip_packet(b'\x45'))
        writer.close()

        _, _, raw_records = self._read(self.raw_path)
        _, _, eth_records = self._read(self.converted_path)
        self.assertEqual([b'\x60\x00', b'\x45'],
                         [record for _, record in raw_records])
        self.assertEqual([0x86dd, 0x0800],
                         [struct.unpack('!H', record[12:14])[0]
                          for _, record in eth_records])
        self.assertEqual([b'\x60\x00', b'\x45'],
                         [record[14:] for _, record in eth_records])

    def test_1500_byte_and_protocol_payloads_are_not_changed(self):
        large = bytearray(1500)
        large[0] = 0x45
        tcp = bytearray(64)
        tcp[0], tcp[9] = 0x45, 6
        udp = bytearray(64)
        udp[0], udp[9] = 0x45, 17
        icmp = bytearray(64)
        icmp[0], icmp[9] = 0x45, 1
        fragment = bytearray(64)
        fragment[0], fragment[6], fragment[7] = 0x45, 0x20, 0x01
        payloads = [bytes(value) for value in
                    (large, tcp, udp, icmp, fragment)]
        writer = DualPcapWriter(
            self.raw_path, self.converted_path,
            logging.getLogger('dual-pcap-test'), clock=lambda: 75.0)

        for payload in payloads:
            self.assertTrue(writer.write_ip_packet(payload))
        writer.close()

        _, _, raw_records = self._read(self.raw_path)
        _, _, ethernet_records = self._read(self.converted_path)
        self.assertEqual(payloads, [record for _, record in raw_records])
        self.assertEqual(payloads,
                         [record[14:] for _, record in ethernet_records])
        self.assertEqual(1514, len(ethernet_records[0][1]))

    def test_invalid_versions_are_rejected_symmetrically_and_rate_limited(self):
        logger = logging.getLogger('dual-pcap-rejection-test')
        writer = DualPcapWriter(
            self.raw_path, self.converted_path, logger, clock=lambda: 10.0)

        with self.assertLogs(logger, level='WARNING') as captured:
            self.assertFalse(writer.write_ip_packet(b''))
            self.assertFalse(writer.write_ip_packet(b'\x70'))
        summary = writer.close()

        self.assertEqual(1, len([
            line for line in captured.output
            if 'PCAP_DUAL_PACKET_REJECTED' in line]))
        self.assertEqual(2, summary.rejected_input_count)
        self.assertEqual(0, summary.raw_write_count)
        self.assertEqual(0, summary.ethernet_write_count)

    def test_ethernet_record_over_snaplen_fails_before_either_write(self):
        writer = DualPcapWriter(
            self.raw_path, self.converted_path,
            logging.getLogger('dual-pcap-test'))
        oversized = b'\x45' + (b'\x00' * (262144 - 1))

        with self.assertRaisesRegex(Exception, 'exceeds snaplen') as first:
            writer.write_ip_packet(oversized)
        with self.assertRaises(Exception) as second:
            writer.write_ip_packet(IPV4_PACKET)
        self.assertIs(first.exception, second.exception)
        summary = writer.close()
        self.assertFalse(summary.healthy)
        self.assertEqual(0, summary.raw_write_count)
        self.assertEqual(0, summary.ethernet_write_count)

    def test_existing_second_target_rolls_back_only_new_raw_file(self):
        with open(self.converted_path, 'wb') as stream:
            stream.write(b'preserve')

        with self.assertRaises(FileExistsError):
            DualPcapWriter(
                self.raw_path, self.converted_path,
                logging.getLogger('dual-pcap-test'))

        self.assertFalse(os.path.exists(self.raw_path))
        with open(self.converted_path, 'rb') as stream:
            self.assertEqual(b'preserve', stream.read())

    def test_close_is_idempotent_and_can_discard_empty_startup_files(self):
        writer = DualPcapWriter(
            self.raw_path, self.converted_path,
            logging.getLogger('dual-pcap-test'))

        first = writer.close(discard_if_empty=True)
        second = writer.close(discard_if_empty=True)

        self.assertIs(first, second)
        self.assertTrue(first.discarded)
        self.assertFalse(os.path.exists(self.raw_path))
        self.assertFalse(os.path.exists(self.converted_path))


class FailingWriter(object):
    def __init__(self, fail_write=False, fail_close=False):
        self.fail_write = fail_write
        self.fail_close = fail_close
        self.write_calls = 0
        self.close_calls = 0

    def writepkt(self, packet, ts=None):
        self.write_calls += 1
        if self.fail_write:
            raise OSError('injected write failure')

    def close(self):
        self.close_calls += 1
        if self.fail_close:
            raise OSError('injected close failure')


class DualPcapFailureTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.raw_path = os.path.join(self.tempdir.name, 'raw.pcap')
        self.converted_path = os.path.join(
            self.tempdir.name, 'raw-converted.pcap')

    def _factory(self, writers):
        remaining = list(writers)

        def create(fileobj, snaplen, linktype):
            return remaining.pop(0)
        return create

    def test_ethernet_write_failure_permanently_stops_both_writers(self):
        raw = FailingWriter()
        ethernet = FailingWriter(fail_write=True)
        writer = DualPcapWriter(
            self.raw_path, self.converted_path,
            logging.getLogger('dual-pcap-test'),
            writer_factory=self._factory((raw, ethernet)))

        with self.assertRaisesRegex(Exception, 'injected write failure'):
            writer.write_ip_packet(IPV4_PACKET)
        with self.assertRaises(Exception):
            writer.write_ip_packet(IPV4_PACKET)
        summary = writer.close()

        self.assertEqual(1, raw.write_calls)
        self.assertEqual(1, ethernet.write_calls)
        self.assertEqual(1, summary.raw_write_count)
        self.assertEqual(0, summary.ethernet_write_count)
        self.assertFalse(summary.healthy)

    def test_raw_write_failure_never_calls_ethernet_writer(self):
        raw = FailingWriter(fail_write=True)
        ethernet = FailingWriter()
        writer = DualPcapWriter(
            self.raw_path, self.converted_path,
            logging.getLogger('dual-pcap-test'),
            writer_factory=self._factory((raw, ethernet)))

        with self.assertRaisesRegex(Exception, 'injected write failure'):
            writer.write_ip_packet(IPV4_PACKET)
        with self.assertRaises(Exception):
            writer.write_ip_packet(IPV4_PACKET)
        summary = writer.close()

        self.assertEqual(1, raw.write_calls)
        self.assertEqual(0, ethernet.write_calls)
        self.assertEqual(0, summary.raw_write_count)
        self.assertEqual(0, summary.ethernet_write_count)
        self.assertFalse(summary.healthy)

    def test_second_writer_constructor_failure_closes_and_rolls_back_both_files(self):
        raw = FailingWriter()
        calls = [raw]

        def factory(fileobj, snaplen, linktype):
            if calls:
                return calls.pop()
            raise OSError('injected constructor failure')

        with self.assertRaisesRegex(OSError, 'constructor failure'):
            DualPcapWriter(
                self.raw_path, self.converted_path,
                logging.getLogger('dual-pcap-test'),
                writer_factory=factory)

        self.assertEqual(1, raw.close_calls)
        self.assertFalse(os.path.exists(self.raw_path))
        self.assertFalse(os.path.exists(self.converted_path))

    def test_both_close_attempts_run_when_first_close_fails(self):
        raw = FailingWriter(fail_close=True)
        ethernet = FailingWriter(fail_close=True)
        writer = DualPcapWriter(
            self.raw_path, self.converted_path,
            logging.getLogger('dual-pcap-test'),
            writer_factory=self._factory((raw, ethernet)))

        summary = writer.close()

        self.assertEqual(1, raw.close_calls)
        self.assertEqual(1, ethernet.close_calls)
        self.assertIsInstance(summary.raw_close_error, OSError)
        self.assertIsInstance(summary.ethernet_close_error, OSError)
        self.assertFalse(summary.healthy)


if __name__ == '__main__':
    unittest.main()
