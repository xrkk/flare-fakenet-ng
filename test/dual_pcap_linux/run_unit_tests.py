"""Run only Linux and cross-platform dual-PCAP suites by exact filename."""

from pathlib import Path
import sys
import unittest


TEST_ROOT = Path(__file__).resolve().parents[1]
FILES = (
    'test_dual_pcap_writer.py',
    'test_diverter_pcap_lifecycle.py',
    'test_fakenet_stop_lifecycle.py',
    'test_linux_pcap_lifecycle.py',
    'test_dual_pcap_configuration.py',
    'test_dual_pcap_vm_verifier.py',
    'test_dual_pcap_linux_acceptance.py')


def main():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for filename in FILES:
        discovered = loader.discover(
            str(TEST_ROOT), pattern=filename, top_level_dir=str(TEST_ROOT))
        suite.addTests(discovered)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
