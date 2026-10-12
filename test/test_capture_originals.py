import base64
import hashlib
import json
import logging
import os
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace

import dpkt

from fakenet.capture_originals import (CaptureOriginalsError,
                                       CaptureOriginalsWriter,
                                       nbis_path, observations_path,
                                       seal_path)
from fakenet.diverters.diverterbase import DiverterBase
from fakenet.payload_report import (PayloadReportError, _serialize_nbis,
                                    load_capture_originals)


def tcp_packet(src, dst, sport, dport, seq, payload=b'',
               flags=dpkt.tcp.TH_ACK):
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, seq=seq, ack=1,
                       flags=flags, data=payload)
    tcp.off = 5
    packet = dpkt.ip.IP(src=socket.inet_aton(src),
                        dst=socket.inet_aton(dst),
                        p=dpkt.ip.IP_PROTO_TCP, ttl=64, data=tcp)
    packet.len = len(packet)
    return bytes(packet)


def udp_packet(src, dst, sport, dport, payload):
    udp = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
    udp.ulen = len(udp)
    packet = dpkt.ip.IP(src=socket.inet_aton(src),
                        dst=socket.inet_aton(dst),
                        p=dpkt.ip.IP_PROTO_UDP, ttl=64, data=udp)
    packet.len = len(packet)
    return bytes(packet)


def make_diverter(directory, sessions=None):
    diverter = object.__new__(DiverterBase)
    diverter.logger = logging.getLogger('capture-originals-test')
    diverter._initialize_capture_state()
    diverter.dump_packets = True
    diverter.pcap_prefix = str(Path(directory) / 'packets')
    diverter.pdebug = lambda *args: None
    diverter.network_mode = 'SingleHost'
    diverter.sessions = dict(sessions or {})
    diverter.proxy_sport_to_orig_sport_map = {}
    diverter.is_proxied_pkt_ssl_encrypted = {}
    diverter.nbis = {}
    diverter._start_capture()
    return diverter


def packet_context(raw, logical=None, role='initial', direction='outbound'):
    context = SimpleNamespace(
        octets=raw, mangled=(role == 'final'),
        hdrToStr2=lambda: 'fixture packet',
        _capture_direction=direction)
    if logical is not None:
        context._capture_logical_packet_id = logical
    return context


def write_packet(diverter, context):
    if not diverter._write_pcap_locked(context):
        raise AssertionError('packet was not captured')
    return context


def close_capture(diverter):
    diverter._capture_writers_safe_to_close = True
    return diverter._close_capture()


def build_sealed_capture(directory, converted=True):
    from fakenet.diverters.pcapwriter import DualPcapWriter
    raw = str(Path(directory) / 'packets_20260903_000000.pcap')
    converted_path = (str(Path(directory) /
                          'packets_20260903_000000-converted.pcap')
                      if converted else None)
    writer = DualPcapWriter(raw, converted_path,
                            logging.getLogger('capture-originals-test'),
                            clock=lambda: 2.0)
    packet = tcp_packet('192.0.2.10', '198.51.100.20', 40000, 3585, 100,
                        b'sealed')
    writer.write_ip_packet(packet)
    originals = CaptureOriginalsWriter(raw)
    originals.record_observation({
        'ordinal': 1, 'logical_packet_id': 'packet-1',
        'observation_role': 'initial', 'direction': 'outbound',
        'length': len(packet), 'sha256': hashlib.sha256(packet).hexdigest(),
        'timestamp': 2.0, 'record_ordinal': 1})
    summary = writer.close()
    originals.seal(summary.raw_filename, summary.ethernet_filename)
    originals.close()
    return raw, summary


def reseal_facts(raw):
    seal_file = Path(seal_path(raw))
    seal = json.loads(seal_file.read_text())
    for key in ('observations', 'nbis'):
        path = seal_file.parent / seal[key]['name']
        data = path.read_bytes()
        seal[key]['bytes'] = len(data)
        seal[key]['sha256'] = hashlib.sha256(data).hexdigest()
    seal_file.write_text(json.dumps(seal, indent=2) + '\n')


class CaptureOriginalsProducerTests(unittest.TestCase):
    def test_real_callbacks_persist_and_seal_with_initial_final_pair(self):
        with tempfile.TemporaryDirectory() as directory:
            session = SimpleNamespace(pid=111, comm='BENIGN_FIXTURE',
                                      proto='TCP', dst_ip='192.0.2.123',
                                      dport0=80)
            diverter = make_diverter(directory, {45678: session})
            summary = None
            try:
                first = packet_context(tcp_packet(
                    '192.168.204.230', '192.0.2.123', 45678, 80, 100,
                    b'GET /fixture HTTP/1.0\r\n\r\n'), logical='packet-1')
                write_packet(diverter, first)
                final = packet_context(tcp_packet(
                    '192.168.204.230', '192.0.2.123', 45678, 80, 100,
                    b'GET /fixture HTTP/1.0\r\n\r\n'), logical='packet-1',
                    role='final')
                write_packet(diverter, final)
                write_packet(diverter, packet_context(tcp_packet(
                    '192.0.2.123', '192.168.204.230', 80, 45678, 500,
                    b'HTTP/1.0 200 OK\r\n\r\n'), logical='packet-2',
                    direction='inbound'))
                diverter.logNbi(45678, {
                    'Request URI': '/fixture',
                    'body': b'\x00\xffpayload',
                    'count': 3,
                }, 'TCP', 'HTTP', 'No')
                # The same packet object observed at a second capture hook
                # must not gain a duplicate initial record on disk either.
                write_packet(diverter, final)
                self.assertEqual(3, len(diverter._capture_observation_index))
                summary = close_capture(diverter)
            finally:
                diverter._capture_writers_safe_to_close = True
                if diverter.dual_pcap is not None and summary is None:
                    summary = diverter._close_capture()
            self.assertTrue(summary.healthy)
            self.assertIsNone(diverter.capture_failure)
            raw_name = summary.raw_filename
            for path in (observations_path(raw_name), nbis_path(raw_name),
                         seal_path(raw_name)):
                self.assertTrue(os.path.isfile(path), path)
            loaded = load_capture_originals(
                raw_name, summary.ethernet_filename)
            self.assertEqual(diverter._capture_observation_index.snapshot(),
                             loaded.entries)
            self.assertEqual(
                _serialize_nbis(diverter.nbis,
                                registry=diverter._capture_flow_registry),
                _serialize_nbis(loaded.nbis,
                                registry=diverter._capture_flow_registry))
            seal = loaded.seal
            self.assertEqual(3, seal['observations']['records'])
            self.assertEqual(1, seal['nbis']['records'])
            self.assertEqual(os.path.basename(raw_name), seal['pair_basename'])
            self.assertEqual(seal['raw_pcap']['sha256'],
                             hashlib.sha256(
                                 Path(raw_name).read_bytes()).hexdigest())
            self.assertEqual([1, 2, 3],
                             [entry['ordinal'] for entry in loaded.entries])
            self.assertEqual({'initial', 'final'},
                             {entry['observation_role']
                              for entry in loaded.entries
                              if entry['logical_packet_id'] == 'packet-1'})
            self.assertEqual('packet-1',
                             os.path.basename(raw_name) and
                             loaded.entries[0]['logical_packet_id'])
            pid, comm = next(iter(loaded.nbis))
            self.assertEqual((111, 'BENIGN_FIXTURE'), (pid, comm))
            entry = loaded.nbis[(pid, comm)]['http'][0]
            self.assertEqual('/fixture', entry['nbi']['Request URI'])
            self.assertEqual(3, entry['nbi']['count'])
            self.assertEqual(b'\x00\xffpayload',
                             base64.b64decode(entry['nbi']['body']['value']))
            self.assertEqual('base64', entry['nbi']['body']['encoding'])
            # No fabricated process birth/hash facts, no truncated metrics.
            raw_journal = Path(nbis_path(raw_name)).read_text()
            self.assertNotIn('birth', raw_journal)
            self.assertNotIn('"sha256"', raw_journal)

    def test_zero_nbi_capture_is_legal(self):
        with tempfile.TemporaryDirectory() as directory:
            diverter = make_diverter(directory)
            summary = None
            try:
                write_packet(diverter, packet_context(udp_packet(
                    '192.168.204.230', '192.0.2.9', 40000, 53, b'query'),
                    logical='packet-1'))
                summary = close_capture(diverter)
            finally:
                diverter._capture_writers_safe_to_close = True
                if diverter.dual_pcap is not None and summary is None:
                    summary = diverter._close_capture()
            loaded = load_capture_originals(
                summary.raw_filename, summary.ethernet_filename)
            self.assertEqual(0, loaded.seal['nbis']['records'])
            self.assertEqual({}, loaded.nbis)
            self.assertEqual(1, loaded.seal['observations']['records'])

    def test_concurrent_packet_and_nbi_callbacks_stay_ordered(self):
        with tempfile.TemporaryDirectory() as directory:
            session = SimpleNamespace(pid=222, comm='BENIGN_FIXTURE',
                                      proto='TCP', dst_ip='192.0.2.50',
                                      dport0=443)
            diverter = make_diverter(directory, {55555: session})
            summary = None
            failures = []
            try:
                def packet_worker(worker):
                    try:
                        for number in range(4):
                            diverter.write_pcap(packet_context(tcp_packet(
                                '192.168.204.230', '192.0.2.50', 55555, 443,
                                1000 + worker * 100 + number,
                                b'worker-%d-%d' % (worker, number))))
                    except Exception as exc:      # noqa: BLE001
                        failures.append(exc)

                def nbi_worker(worker):
                    try:
                        for number in range(4):
                            diverter.logNbi(55555, {
                                'worker': worker, 'item': number},
                                'TCP', 'HTTP', 'No')
                    except Exception as exc:      # noqa: BLE001
                        failures.append(exc)

                threads = [threading.Thread(target=packet_worker, args=(0,)),
                           threading.Thread(target=packet_worker, args=(1,)),
                           threading.Thread(target=nbi_worker, args=(0,)),
                           threading.Thread(target=nbi_worker, args=(1,))]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join()
                summary = close_capture(diverter)
            finally:
                diverter._capture_writers_safe_to_close = True
                if diverter.dual_pcap is not None and summary is None:
                    summary = diverter._close_capture()
            self.assertEqual([], failures)
            loaded = load_capture_originals(
                summary.raw_filename, summary.ethernet_filename)
            self.assertEqual([1, 2, 3, 4, 5, 6, 7, 8],
                             [entry['ordinal'] for entry in loaded.entries])
            self.assertEqual(8, loaded.seal['observations']['records'])
            self.assertEqual(8, loaded.seal['nbis']['records'])

    def test_existing_journal_is_refused_without_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            raw = str(Path(directory) / 'packets_20260903_000000.pcap')
            writer = CaptureOriginalsWriter(raw)
            original = Path(observations_path(raw)).read_text()
            with self.assertRaises(CaptureOriginalsError):
                CaptureOriginalsWriter(raw)
            self.assertEqual(original,
                             Path(observations_path(raw)).read_text())
            writer.close()

    def test_seal_required_facts_and_no_fabrication(self):
        with tempfile.TemporaryDirectory() as directory:
            raw = str(Path(directory) / 'packets_20260903_000000.pcap')
            writer = CaptureOriginalsWriter(raw)
            writer.record_nbi(session={'pid': None, 'comm': None},
                              application_layer_proto='DNS',
                              is_ssl_encrypted='No',
                              network_mode='singlehost',
                              nbi={'Question': b'\x01'})
            record = json.loads(
                Path(nbis_path(raw)).read_text().splitlines()[1])
            self.assertEqual(None, record['session']['pid'])
            self.assertEqual(None, record['session']['comm'])
            self.assertNotIn('birth', record)
            self.assertNotIn('process_sha256', record)
            self.assertEqual({'encoding': 'base64', 'value': 'AQ=='},
                             record['metrics']['Question'])
            writer.close()


class CaptureOriginalsLoaderGuardTests(unittest.TestCase):
    def test_ordinal_truncation_and_missing_journal_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            raw, summary = build_sealed_capture(directory)
            path = Path(observations_path(raw))
            lines = path.read_text().splitlines()
            lines[1] = lines[1].replace('"ordinal":1', '"ordinal":7')
            path.write_text('\n'.join(lines) + '\n')
            reseal_facts(raw)
            with self.assertRaisesRegex(PayloadReportError, 'ordinal mismatch'):
                load_capture_originals(raw, summary.ethernet_filename)
        with tempfile.TemporaryDirectory() as directory:
            raw, summary = build_sealed_capture(directory)
            path = Path(observations_path(raw))
            data = path.read_bytes()
            path.write_bytes(data[:-5])
            reseal_facts(raw)
            with self.assertRaisesRegex(PayloadReportError, 'truncated'):
                load_capture_originals(raw, summary.ethernet_filename)
        with tempfile.TemporaryDirectory() as directory:
            raw, summary = build_sealed_capture(directory)
            os.unlink(observations_path(raw))
            with self.assertRaisesRegex(PayloadReportError, 'not a plain file'):
                load_capture_originals(raw, summary.ethernet_filename)

    def test_bytes_hash_identity_and_foreign_capture_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            raw, summary = build_sealed_capture(directory)
            replacement = Path(directory) / 'replacement.pcap'
            replacement.write_bytes(Path(raw).read_bytes())
            os.replace(replacement, raw)
            with self.assertRaisesRegex(PayloadReportError,
                                        'physical replacement'):
                load_capture_originals(raw, summary.ethernet_filename)
        with tempfile.TemporaryDirectory() as directory:
            raw, summary = build_sealed_capture(directory)
            seal_file = Path(seal_path(raw))
            seal = json.loads(seal_file.read_text())
            seal['raw_pcap']['sha256'] = '0' * 64
            seal_file.write_text(json.dumps(seal, indent=2) + '\n')
            with self.assertRaisesRegex(PayloadReportError,
                                        'SHA-256 differs'):
                load_capture_originals(raw, summary.ethernet_filename)
        with tempfile.TemporaryDirectory() as directory:
            raw, summary = build_sealed_capture(directory)
            seal_file = Path(seal_path(raw))
            seal = json.loads(seal_file.read_text())
            seal['pair_basename'] = 'other.pcap'
            seal_file.write_text(json.dumps(seal, indent=2) + '\n')
            with self.assertRaisesRegex(PayloadReportError, 'foreign capture'):
                load_capture_originals(raw, summary.ethernet_filename)

    def test_symlink_and_append_after_seal_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            raw, summary = build_sealed_capture(directory)
            link = Path(directory) / 'linked.pcap'
            os.symlink(raw, link)
            with self.assertRaisesRegex(PayloadReportError, 'symlink'):
                load_capture_originals(str(link), summary.ethernet_filename)
        with tempfile.TemporaryDirectory() as directory:
            raw = str(Path(directory) / 'append.pcap')
            Path(raw).write_bytes(b'\x45\x00')
            writer = CaptureOriginalsWriter(raw)
            writer.seal(raw)
            with self.assertRaisesRegex(CaptureOriginalsError, 'refused'):
                writer.record_observation({'ordinal': 1})
            writer.close()

    def test_append_failure_routes_to_capture_failure_first_error(self):
        with tempfile.TemporaryDirectory() as directory:
            diverter = make_diverter(directory)
            diverter._capture_originals._observations_stream = None
            context = packet_context(tcp_packet(
                '192.0.2.10', '198.51.100.20', 40000, 3585, 100, b'x'))
            with self.assertRaises(Exception):
                diverter.write_pcap(context)
            first = diverter.capture_failure
            self.assertIsNotNone(first)
            with self.assertRaises(Exception):
                diverter.write_pcap(context)
            self.assertIs(first, diverter.capture_failure)
            diverter._capture_writers_safe_to_close = True
            diverter._close_capture()

    def test_seal_failure_is_unhealthy_and_report_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            diverter = make_diverter(directory)

            def broken_seal(*args, **kwargs):
                raise OSError('injected seal failure')

            diverter._capture_originals.seal = broken_seal
            diverter._capture_writers_safe_to_close = True
            diverter._close_capture()
            self.assertIsNotNone(diverter.capture_failure)
            with self.assertRaisesRegex(PayloadReportError,
                                        'after capture failure'):
                diverter.generate_html_report()

    def test_memory_drift_against_sealed_originals_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            diverter = make_diverter(directory)
            write_packet(diverter, packet_context(tcp_packet(
                '192.0.2.10', '198.51.100.20', 40000, 3585, 100, b'x'),
                logical='packet-1'))
            close_capture(diverter)
            diverter._capture_observation_index.record(
                tcp_packet('192.0.2.10', '198.51.100.20', 40000, 3585, 200,
                           b'ghost'), 'initial', logical_packet_id='packet-2',
                record_ordinal=2)
            current = os.getcwd()
            try:
                os.chdir(directory)
                with self.assertRaisesRegex(
                        PayloadReportError,
                        'observation index differs from sealed originals'):
                    diverter.generate_html_report()
            finally:
                os.chdir(current)


if __name__ == '__main__':
    unittest.main()
