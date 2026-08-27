import base64
import hashlib
import importlib.util
import json
import struct
import tempfile
import unittest
from pathlib import Path


VERIFIER_PATH = (Path(__file__).resolve().parent / 'gui_vm' /
                 'verify_payload_integrity.py')
SPEC = importlib.util.spec_from_file_location(
    'payload_integrity_verifier_test_target', VERIFIER_PATH)
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


def ipv4_tcp(source, destination, sport, dport, sequence, payload):
    source_bytes = bytes(int(part) for part in source.split('.'))
    destination_bytes = bytes(int(part) for part in destination.split('.'))
    tcp = struct.pack('!HHIIBBHHH', sport, dport, sequence, 0,
                      0x50, 0x10, 65535, 0, 0) + payload
    return (struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0,
                        64, 6, 0, source_bytes, destination_bytes) + tcp)


def pcap(records):
    header = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 101)
    body = b''.join(
        struct.pack('<IIII', 1, ordinal, len(packet), len(packet)) + packet
        for ordinal, packet in enumerate(records, 1))
    return header + body


def pcapng(frames):
    section = struct.pack('<II IHHqI', 0x0a0d0d0a, 28, 0x1a2b3c4d,
                          1, 0, -1, 28)
    interface = struct.pack('<IIHHII', 1, 20, 1, 0, 262144, 20)
    blocks = [section, interface]
    for ordinal, frame in enumerate(frames, 1):
        padding = b'\0' * ((-len(frame)) % 4)
        length = 32 + len(frame) + len(padding)
        blocks.append(
            struct.pack('<IIIIIII', 6, length, 0, 0, ordinal,
                        len(frame), len(frame)) + frame + padding +
            struct.pack('<I', length))
    return b''.join(blocks)


class PayloadIntegrityVerifierTests(unittest.TestCase):
    def test_independent_reassembly_unwraps_tcp_sequence_wrap(self):
        payload = verifier._assemble_tcp([
            {'start': 2, 'payload': b'efgh', 'ordinal': 2},
            {'start': 0xfffffffe, 'payload': b'abcd', 'ordinal': 1},
        ])
        self.assertEqual(b'abcdefgh', payload)

    def test_raw_wire_and_html_payloads_are_compared_bidirectionally(self):
        outbound = ipv4_tcp('192.0.2.10', '198.51.100.20', 40000, 3585,
                            100, b'hello')
        inbound = ipv4_tcp('198.51.100.20', '192.0.2.10', 3585, 40000,
                           200, b'world')
        frames = [
            b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00' +
            outbound,
            b'\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02\x08\x00' +
            inbound,
        ]

        def direction(identifier, source, destination, direction, payload):
            return {
                'id': identifier,
                'direction': direction,
                'source': {'ip': source[0], 'port': source[1]},
                'destination': {'ip': destination[0], 'port': destination[1]},
                'bytes': len(payload),
                'sha256': hashlib.sha256(payload).hexdigest(),
                'base64': base64.b64encode(payload).decode('ascii'),
            }

        model = {
            'schema': 'fakenet.payload-report.v1',
            'capture': {'overall_health': True},
            'flows': [{
                'id': 'flow-000001',
                'protocol': 'TCP',
                'ip_version': 4,
                'owner': 'sample.exe',
                'pid': 4321,
                'process': 'sample.exe',
                'domain': 'sample.invalid',
                'source': {'ip': '192.0.2.10', 'port': 40000},
                'destination': {'ip': '198.51.100.20', 'port': 3585},
                'disposition': 'ALLOW_TAKEOVER_SINK',
                'directions': {
                    'outbound': direction(
                        'flow-000001-outbound',
                        ('192.0.2.10', 40000),
                        ('198.51.100.20', 3585), 'outbound', b'hello'),
                    'inbound': direction(
                        'flow-000001-inbound',
                        ('198.51.100.20', 3585),
                        ('192.0.2.10', 40000), 'inbound', b'world'),
                },
            }],
        }

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw_path = root / 'raw.pcap'
            wire_path = root / 'wire.pcapng'
            html_path = root / 'report.html'
            log_path = root / 'fakenet.log'
            ini_path = root / 'fakenet.ini'
            output_path = root / 'verification.json'
            raw_path.write_bytes(pcap([outbound, inbound]))
            wire_path.write_bytes(pcapng(frames))
            html_path.write_text(
                '<script id="payload-data" type="application/json">%s</script>' %
                json.dumps(model), encoding='utf-8')
            log_path.write_text('PROCESS_FLOW ALLOW_TAKEOVER_SINK\n',
                                encoding='utf-8')
            ini_path.write_text('[Diverter]\nDumpPackets=Yes\n', encoding='utf-8')

            result = verifier.verify(str(raw_path), str(wire_path),
                                     str(html_path), str(log_path), str(ini_path))

            self.assertEqual('PASS', result['verdict'])
            self.assertEqual(2, len(result['comparisons']))
            self.assertTrue(all(item['match'] for item in result['comparisons']))
            self.assertTrue(all(item['process'] == 'sample.exe'
                                for item in result['comparisons']))
            self.assertTrue(result['dump_packets'])
            self.assertEqual('hello', base64.b64decode(
                model['flows'][0]['directions']['outbound']['base64']).decode())

            model['flows'][0]['directions']['inbound']['base64'] = (
                base64.b64encode(b'wrong').decode('ascii'))
            model['flows'][0]['directions']['inbound']['sha256'] = hashlib.sha256(
                b'wrong').hexdigest()
            html_path.write_text(
                '<script id="payload-data" type="application/json">%s</script>' %
                json.dumps(model), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'mismatch'):
                verifier.verify(str(raw_path), str(wire_path),
                                str(html_path), str(log_path), str(ini_path))

            model['flows'][0]['directions']['inbound'] = direction(
                'flow-000001-inbound',
                ('198.51.100.20', 3585),
                ('192.0.2.10', 40000), 'inbound', b'world')
            model['flows'][0]['owner'] = 'unknown'
            model['flows'][0]['process'] = 'unknown'
            model['flows'][0]['pid'] = None
            html_path.write_text(
                '<script id="payload-data" type="application/json">%s</script>' %
                json.dumps(model), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'sample process'):
                verifier.verify(str(raw_path), str(wire_path),
                                str(html_path), str(log_path), str(ini_path))

            model['flows'][0]['owner'] = 'sample.exe'
            model['flows'][0]['process'] = 'sample.exe'
            model['flows'][0]['pid'] = 4321
            html_path.write_text(
                '<script id="payload-data" type="application/json">%s</script>' %
                json.dumps(model), encoding='utf-8')
            ini_path.write_text('[Diverter]\nDumpPackets=No\n',
                                encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'does not enable'):
                verifier.verify(str(raw_path), str(wire_path),
                                str(html_path), str(log_path), str(ini_path))


if __name__ == '__main__':
    unittest.main()
