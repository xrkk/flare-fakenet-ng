import importlib.util
import logging
import os
import pathlib
import tempfile
import unittest

from fakenet.diverters.pcapwriter import DualPcapWriter


ROOT = pathlib.Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location(
    'dual_pcap_vm_verifier',
    ROOT / 'test/dual_pcap_vm/verify_dual_pcap.py')
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


class DualPcapVmVerifierTests(unittest.TestCase):
    def test_independent_reader_accepts_truncated_then_normal_records_to_eof(self):
        with tempfile.TemporaryDirectory() as root:
            raw = os.path.join(root, 'packets.pcap')
            ethernet = os.path.join(root, 'packets-converted.pcap')
            writer = DualPcapWriter(
                raw, ethernet, logging.getLogger('vm-verifier-test'),
                clock=lambda: 10.25)
            writer.write_ip_packet(b'\x45')
            writer.write_ip_packet(b'\x60')
            writer.write_ip_packet(b'\x45' + (b'\x00' * 19))
            writer.close()

            result = VERIFIER.verify(raw, ethernet, minimum_records=3)

            self.assertEqual(3, result['records'])
            self.assertEqual([4, 6], result['ip_versions'])


if __name__ == '__main__':
    unittest.main()
