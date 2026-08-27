import base64
import json
import logging
import os
import re
import socket
import tempfile
import unittest
from pathlib import Path

import dpkt

from fakenet.diverters.pcapwriter import DualPcapWriter
from fakenet.diverters.diverterbase import DiverterBase
from fakenet.payload_report import (CaptureObservationIndex,
                                     PayloadReportError, SessionFlowRegistry,
                                     build_payload_report, safe_json_dumps,
                                     validate_payload_model,
                                     validate_rendered_payload_report)


def tcp_packet(src, dst, sport, dport, seq, payload=b'', flags=dpkt.tcp.TH_ACK,
               ipv6=False):
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, seq=seq, ack=1,
                       flags=flags, data=payload)
    tcp.off = 5
    if ipv6:
        packet = dpkt.ip6.IP6(src=socket.inet_pton(socket.AF_INET6, src),
                              dst=socket.inet_pton(socket.AF_INET6, dst),
                              nxt=dpkt.ip.IP_PROTO_TCP, hlim=64, data=tcp)
        packet.plen = len(tcp)
    else:
        packet = dpkt.ip.IP(src=socket.inet_aton(src),
                            dst=socket.inet_aton(dst),
                            p=dpkt.ip.IP_PROTO_TCP, ttl=64, data=tcp)
        packet.len = len(packet)
    return bytes(packet)


def udp_packet(src, dst, sport, dport, payload, ipv6=False):
    udp = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
    udp.ulen = len(udp)
    if ipv6:
        packet = dpkt.ip6.IP6(src=socket.inet_pton(socket.AF_INET6, src),
                              dst=socket.inet_pton(socket.AF_INET6, dst),
                              nxt=dpkt.ip.IP_PROTO_UDP, hlim=64, data=udp)
        packet.plen = len(udp)
    else:
        packet = dpkt.ip.IP(src=socket.inet_aton(src),
                            dst=socket.inet_aton(dst),
                            p=dpkt.ip.IP_PROTO_UDP, ttl=64, data=udp)
        packet.len = len(packet)
    return bytes(packet)


class PayloadReportTests(unittest.TestCase):
    def make_capture(self, observations):
        tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(tempdir.cleanup)
        raw_path = os.path.join(tempdir.name, 'raw.pcap')
        converted_path = os.path.join(tempdir.name, 'converted.pcap')
        writer = DualPcapWriter(raw_path, converted_path,
                                logging.getLogger('payload-report-test'),
                                clock=lambda: 1000.0 + len(index.snapshot()))
        index = CaptureObservationIndex()
        registry = SessionFlowRegistry()
        for observation in observations:
            raw = observation['raw']
            logical = observation.get('logical')
            direction = observation.get('direction', 'unknown')
            flow_id = registry.observe_packet(
                raw, direction=direction, timestamp=1000.0,
                logical_packet_id=logical)
            self.assertTrue(writer.write_ip_packet(raw))
            index.record(raw, observation.get('role', 'initial'),
                         logical_packet_id=logical, flow_id=flow_id,
                         direction=direction,
                         timestamp=writer.last_timestamp,
                         record_ordinal=writer.last_record_ordinal)
        writer.close()
        return raw_path, converted_path, index, registry

    def test_tcp_bidirectional_reorder_retransmit_and_observation_dedup(self):
        outbound_a = tcp_packet('192.0.2.10', '198.51.100.20', 40000, 3585,
                                105, b' world')
        outbound_b = tcp_packet('192.0.2.10', '198.51.100.20', 40000, 3585,
                                100, b'hello')
        inbound = tcp_packet('198.51.100.20', '192.0.2.10', 3585, 40000,
                             900, b'reply')
        paths = self.make_capture([
            {'raw': outbound_a, 'logical': 'out-1', 'direction': 'outbound'},
            {'raw': outbound_b, 'logical': 'out-2', 'direction': 'outbound'},
            # Same logical packet, initial/final paired observations.
            {'raw': outbound_b, 'logical': 'out-2', 'role': 'final',
             'direction': 'outbound'},
            # A distinct logical packet with equal bytes is a TCP retransmit.
            {'raw': outbound_b, 'logical': 'out-retransmit',
             'direction': 'outbound'},
            {'raw': inbound, 'logical': 'in-1', 'direction': 'inbound'},
        ])
        model = build_payload_report(
            paths[0], paths[2], paths[3], capture_health={
                'writer_health': True, 'coverage_health': True,
                'reassembly_health': True})
        validate_payload_model(model)
        self.assertEqual(1, len(model['flows']))
        flow = model['flows'][0]
        self.assertEqual('unknown', flow['owner'])
        self.assertEqual(11, next(
            item['bytes'] for item in flow['directions'].values()
            if item['direction'] == 'outbound'))
        self.assertEqual(b'reply', base64.b64decode(next(
            item['base64'] for item in flow['directions'].values()
            if item['direction'] == 'inbound')))

    def test_tcp_conflict_and_internal_gap_fail_closed(self):
        conflict = self.make_capture([
            {'raw': tcp_packet('192.0.2.10', '198.51.100.20', 1, 2, 100,
                               b'abc'), 'logical': 'a', 'direction': 'outbound'},
            {'raw': tcp_packet('192.0.2.10', '198.51.100.20', 1, 2, 101,
                               b'XYZ'), 'logical': 'b', 'direction': 'outbound'},
        ])
        with self.assertRaisesRegex(PayloadReportError, 'conflicting'):
            build_payload_report(conflict[0], conflict[2], conflict[3],
                                 capture_health={'writer_health': True,
                                                 'coverage_health': True,
                                                 'reassembly_health': True})
        gap = self.make_capture([
            {'raw': tcp_packet('192.0.2.10', '198.51.100.20', 1, 2, 100,
                               b'abc'), 'logical': 'a', 'direction': 'outbound'},
            {'raw': tcp_packet('192.0.2.10', '198.51.100.20', 1, 2, 105,
                               b'xyz'), 'logical': 'b', 'direction': 'outbound'},
        ])
        with self.assertRaisesRegex(PayloadReportError, 'sequence gap'):
            build_payload_report(gap[0], gap[2], gap[3],
                                 capture_health={'writer_health': True,
                                                 'coverage_health': True,
                                                 'reassembly_health': True})

    def test_tcp_sequence_wrap_is_reassembled_in_capture_order(self):
        before_wrap = tcp_packet(
            '192.0.2.10', '198.51.100.20', 40000, 3585,
            0xfffffffe, b'abcd')
        after_wrap = tcp_packet(
            '192.0.2.10', '198.51.100.20', 40000, 3585,
            2, b'efgh')
        paths = self.make_capture([
            {'raw': after_wrap, 'logical': 'wrap-2', 'direction': 'outbound'},
            {'raw': before_wrap, 'logical': 'wrap-1', 'direction': 'outbound'},
        ])
        model = build_payload_report(
            paths[0], paths[2], paths[3], capture_health={
                'writer_health': True, 'coverage_health': True,
                'reassembly_health': True})
        direction = next(item for item in model['flows'][0]['directions'].values()
                         if item['direction'] == 'outbound')
        self.assertEqual(b'abcdefgh', base64.b64decode(direction['base64']))

    def test_tcp_reused_tuple_new_syn_without_close_gets_new_generation(self):
        first_syn = tcp_packet(
            '192.0.2.1', '198.51.100.1', 123, 456, 100,
            flags=dpkt.tcp.TH_SYN)
        second_syn = tcp_packet(
            '192.0.2.1', '198.51.100.1', 123, 456, 900,
            flags=dpkt.tcp.TH_SYN)
        registry = SessionFlowRegistry()
        first_id = registry.observe_packet(first_syn, direction='outbound',
                                            timestamp=1.0,
                                            logical_packet_id='syn-1')
        second_id = registry.observe_packet(second_syn, direction='outbound',
                                             timestamp=2.0,
                                             logical_packet_id='syn-2')
        self.assertNotEqual(first_id, second_id)
        self.assertEqual(2, len(registry.snapshot()))

    def test_udp_boundaries_duplicate_payload_ipv6_and_generation(self):
        first = udp_packet('2001:db8::10', '2001:db8::20', 5000, 6000, b'same',
                           ipv6=True)
        second = udp_packet('2001:db8::20', '2001:db8::10', 6000, 5000, b'reply',
                            ipv6=True)
        paths = self.make_capture([
            {'raw': first, 'logical': 'u-1', 'direction': 'outbound'},
            {'raw': first, 'logical': 'u-2', 'direction': 'outbound'},
            {'raw': second, 'logical': 'u-3', 'direction': 'inbound'},
        ])
        model = build_payload_report(
            paths[0], paths[2], paths[3], capture_health={
                'writer_health': True, 'coverage_health': True,
                'reassembly_health': True})
        flow = model['flows'][0]
        outbound = next(item for item in flow['directions'].values()
                        if item['direction'] == 'outbound')
        self.assertEqual(2, len(outbound['datagrams']))
        self.assertEqual(8, outbound['bytes'])
        self.assertEqual(5, next(item['bytes'] for item in flow['directions'].values()
                                 if item['direction'] == 'inbound'))

        first_tcp = tcp_packet('192.0.2.1', '198.51.100.1', 123, 456, 10,
                               b'x', flags=dpkt.tcp.TH_FIN)
        second_tcp = tcp_packet('192.0.2.1', '198.51.100.1', 123, 456, 20,
                                b'y', flags=dpkt.tcp.TH_SYN)
        generation = self.make_capture([
            {'raw': first_tcp, 'logical': 'g-1', 'direction': 'outbound'},
            {'raw': second_tcp, 'logical': 'g-2', 'direction': 'outbound'},
        ])
        self.assertEqual(2, len(generation[3].snapshot()))

    def test_eight_mib_per_direction_is_not_truncated(self):
        chunk = bytes((index * 17 + 3) % 256 for index in range(60000))
        observations = []
        sequence = 1000
        for number in range(140):
            payload = chunk if number < 139 else chunk[:8 * 1024 * 1024 - 139 * len(chunk)]
            observations.append({
                'raw': tcp_packet('192.0.2.10', '198.51.100.20', 40000,
                                  3585, sequence, payload),
                'logical': 'large-out-%d' % number, 'direction': 'outbound'})
            sequence += len(payload)
        sequence = 9000
        for number in range(140):
            payload = chunk if number < 139 else chunk[:8 * 1024 * 1024 - 139 * len(chunk)]
            observations.append({
                'raw': tcp_packet('198.51.100.20', '192.0.2.10', 3585,
                                  40000, sequence, payload),
                'logical': 'large-in-%d' % number, 'direction': 'inbound'})
            sequence += len(payload)
        paths = self.make_capture(observations)
        model = build_payload_report(
            paths[0], paths[2], paths[3], capture_health={
                'writer_health': True, 'coverage_health': True,
                'reassembly_health': True})
        self.assertEqual(
            8 * 1024 * 1024,
            next(item['bytes'] for item in model['flows'][0]['directions'].values()
                 if item['direction'] == 'outbound'))
        self.assertEqual(
            8 * 1024 * 1024,
            next(item['bytes'] for item in model['flows'][0]['directions'].values()
                 if item['direction'] == 'inbound'))

    def test_index_and_html_json_escape_are_strict(self):
        index = CaptureObservationIndex()
        raw = b'\x45\x00'
        index.record(raw, 'initial', record_ordinal=1)
        with self.assertRaises(PayloadReportError):
            index.record(raw, 'initial', record_ordinal=3)
        encoded = safe_json_dumps({'payload': '</script><script>alert(1)</script>&'})
        self.assertNotIn('</script>', encoded.lower())
        self.assertIn('\\u003c', encoded)
        json.loads(encoded)

    def test_rendered_report_self_check_rejects_model_or_script_drift(self):
        model = {
            'schema': 'fakenet.payload-report.v1', 'encoding': 'base64',
            'capture': {'overall_health': False, 'coverage_health': False,
                        'reassembly_health': False,
                        'marker': 'capture-disabled'},
            'flows': [], 'nbis': [],
        }
        rendered = ('<script id="payload-data" type="application/json">%s'
                    '</script>' % safe_json_dumps(model))
        self.assertEqual(
            model, validate_rendered_payload_report(rendered, model))
        with self.assertRaisesRegex(PayloadReportError, 'differs'):
            validate_rendered_payload_report(
                rendered.replace('"flows":[]', '"flows":[{}]'), model)
        with self.assertRaisesRegex(PayloadReportError, 'one payload-data'):
            validate_rendered_payload_report('<html></html>', model)

    def test_html_template_is_offline_and_verifier_reads_one_byte_source(self):
        raw = tcp_packet('192.0.2.10', '198.51.100.20', 40000, 3585,
                         100, b'</script><script>alert(1)</script>')
        paths = self.make_capture([
            {'raw': raw, 'logical': 'malicious', 'direction': 'outbound'},
        ])
        model = build_payload_report(
            paths[0], paths[2], paths[3], nbis={
                (7, '</script><script>'): {
                    'raw': [{'nbi': {
                        'html_text': '<b>unsafe</b>',
                        'url': 'https://example.invalid/path',
                        'dom_text': 'innerHTML',
                    }}],
                }}, capture_health={'writer_health': True,
                                    'coverage_health': True,
                                    'reassembly_health': True})
        from jinja2 import Environment, FileSystemLoader
        template = Environment(loader=FileSystemLoader(str(
            Path(__file__).parents[1] / 'fakenet' / 'configs'))).get_template(
                'html_report_template.html')
        html = template.render(payload_report_json=safe_json_dumps(model))
        # Keep the original FakeNet-NG report's human-facing hierarchy and
        # interactions while the inert payload model remains authoritative.
        for marker in (
                'FAKENET-NG', 'Network-Based Indicators',
                'Copy All NBIs', 'Copy Selected NBIs',
                'Copy Filtered NBIs', 'Disclaimer',
                '"collapsible"', '"table-container"',
                'Captured TCP/UDP Payloads', 'View Full Payload',
                'UTF-8 Text', 'Full Hexdump', 'Full Base64',
                'Download Raw Bytes'):
            self.assertIn(marker, html)
        self.assertNotIn('showing first 256 bytes', html)
        self.assertIn('innerHTML', html)
        self.assertIn('https://example.invalid/path', html)
        self.assertNotIn('</script><script>', html.lower())
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'report.html')
            with open(path, 'w', encoding='utf-8') as stream:
                stream.write(html)
            import importlib.util
            verifier_path = Path(__file__).parent / 'gui_vm' / 'verify_payload_report.py'
            spec = importlib.util.spec_from_file_location('payload_verifier', verifier_path)
            verifier = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(verifier)
            result = verifier.verify(path)
            self.assertEqual('PASS', result['verdict'])

        with tempfile.TemporaryDirectory() as security_directory:
            external = os.path.join(security_directory, 'external.html')
            with open(external, 'w', encoding='utf-8') as stream:
                stream.write(html.replace(
                    '</head>',
                    '<script src="https://evil.invalid/x.js"></script>'
                    '</head>'))
            with self.assertRaisesRegex(ValueError, 'external'):
                verifier.verify(external)

            sink = os.path.join(security_directory, 'sink.html')
            with open(sink, 'w', encoding='utf-8') as stream:
                stream.write(html.replace(
                    '</body>',
                    '<script>document.body.innerHTML = "unsafe";</script>'
                    '</body>'))
            with self.assertRaisesRegex(ValueError, 'unsafe'):
                verifier.verify(sink)

    def test_diverter_report_publishes_only_after_sealed_pair(self):
        with tempfile.TemporaryDirectory() as directory:
            raw_path = os.path.join(directory, 'raw.pcap')
            converted_path = os.path.join(directory, 'converted.pcap')
            writer = DualPcapWriter(raw_path, converted_path,
                                    logging.getLogger('payload-report-test'),
                                    clock=lambda: 2.0)
            packet = tcp_packet('192.0.2.10', '198.51.100.20', 40000, 3585,
                                100, b'sealed')
            flow_registry = SessionFlowRegistry()
            index = CaptureObservationIndex()
            flow_id = flow_registry.observe_packet(
                packet, direction='outbound', timestamp=2.0,
                logical_packet_id='sealed-1')
            writer.write_ip_packet(packet)
            index.record(packet, 'initial', logical_packet_id='sealed-1',
                         flow_id=flow_id, direction='outbound', timestamp=2.0,
                         record_ordinal=writer.last_record_ordinal)
            diverter = DiverterBase.__new__(DiverterBase)
            diverter._initialize_capture_state()
            diverter.logger = logging.getLogger('payload-report-test')
            diverter.dump_packets = True
            diverter.nbis = {}
            diverter.dual_pcap = writer
            diverter._capture_observation_index = index
            diverter._capture_flow_registry = flow_registry
            summary = writer.close()
            diverter._capture_close_summary = summary
            current = os.getcwd()
            try:
                os.chdir(directory)
                output = diverter.generate_html_report()
                self.assertTrue(os.path.isfile(output))
                import importlib.util
                verifier_path = Path(__file__).parent / 'gui_vm' / 'verify_payload_report.py'
                spec = importlib.util.spec_from_file_location('sealed_verifier', verifier_path)
                verifier = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(verifier)
                self.assertEqual('PASS', verifier.verify(output)['verdict'])
            finally:
                os.chdir(current)

    def test_dump_packets_no_preserves_nbi_with_disabled_capture_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            diverter = DiverterBase.__new__(DiverterBase)
            diverter._initialize_capture_state()
            diverter.logger = logging.getLogger('payload-report-test')
            diverter.dump_packets = False
            diverter.nbis = {
                (4321, 'sample.exe'): {
                    'HTTP': [{
                        'transport_layer_proto': 'TCP',
                        'sport': 40000,
                        'dst_ip': '198.51.100.20',
                        'dport': 80,
                        'is_ssl_encrypted': False,
                        'network_mode': 'singlehost',
                        'nbi': {'url': 'https://example.invalid/path'},
                    }],
                },
            }
            current = os.getcwd()
            try:
                os.chdir(directory)
                output = diverter.generate_html_report()
                html = Path(output).read_text(encoding='utf-8')
                match = re.search(
                    r'<script[^>]*id="payload-data"[^>]*>(.*?)</script>',
                    html, re.S)
                self.assertIsNotNone(match)
                model = json.loads(match.group(1))
                self.assertFalse(model['capture']['overall_health'])
                self.assertEqual('capture-disabled',
                                 model['capture']['marker'])
                self.assertEqual([], model['flows'])
                self.assertEqual(1, len(model['nbis']))
                self.assertEqual('sample.exe', model['nbis'][0]['process'])
                self.assertEqual(
                    'https://example.invalid/path',
                    model['nbis'][0]['protocols'][0]['entries'][0]['nbi']['url'])
                self.assertIn('DumpPackets=No', model['capture']['limitation'])
            finally:
                os.chdir(current)

    def test_atomic_report_failure_removes_temporary_file(self):
        diverter = DiverterBase.__new__(DiverterBase)
        diverter._initialize_capture_state()
        diverter.logger = logging.getLogger('payload-report-test')
        diverter.dump_packets = False
        diverter.nbis = {}
        with tempfile.TemporaryDirectory() as directory:
            current = os.getcwd()
            try:
                os.chdir(directory)
                from unittest import mock
                with mock.patch('os.replace',
                                side_effect=OSError('injected replace failure')):
                    with self.assertRaisesRegex(OSError, 'replace failure'):
                        diverter.generate_html_report()
                self.assertEqual([], os.listdir(directory))
            finally:
                os.chdir(current)

    def test_reassembly_verifier_matrix_covers_reviewed_failure_boundaries(self):
        import importlib.util
        verifier_path = (Path(__file__).parent / 'gui_vm' /
                         'verify_reassembly.py')
        spec = importlib.util.spec_from_file_location(
            'reassembly_matrix_verifier', verifier_path)
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)

        checks = verifier._matrix_checks()

        identities = {item['id'] for item in checks}
        self.assertEqual({
            'tcp-ipv4-bidirectional-reorder-retransmit-logical-dedup',
            'udp-ipv6-bidirectional-distinct-identical-datagrams',
            'tcp-32bit-sequence-wrap',
            'tcp-conflicting-overlap',
            'tcp-internal-gap',
            'tcp-port-reuse-new-syn-without-observed-close',
        }, identities)
        self.assertTrue(all(item['verdict'] == 'PASS' for item in checks))

    def test_reassembly_verifier_expected_model_compares_payload_facts(self):
        import importlib.util
        verifier_path = (Path(__file__).parent / 'gui_vm' /
                         'verify_reassembly.py')
        spec = importlib.util.spec_from_file_location(
            'reassembly_expected_verifier', verifier_path)
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        actual = [{
            'flow_id': 'flow-1', 'protocol': 'TCP', 'owner': 'unknown',
            'directions': [{
                'direction_id': 'flow-1-outbound', 'direction': 'outbound',
                'bytes': 3, 'sha256': 'a' * 64,
            }],
        }]
        expected = [{
            'id': 'flow-1', 'protocol': 'TCP', 'owner': 'sample.exe',
            'directions': {'outbound': {
                'id': 'flow-1-outbound', 'direction': 'outbound',
                'bytes': 3, 'sha256': 'a' * 64,
            }},
        }]
        self.assertEqual(
            verifier._payload_projection(actual),
            verifier._payload_projection(expected))
        expected[0]['directions']['outbound']['sha256'] = 'b' * 64
        self.assertNotEqual(
            verifier._payload_projection(actual),
            verifier._payload_projection(expected))


if __name__ == '__main__':
    unittest.main()
