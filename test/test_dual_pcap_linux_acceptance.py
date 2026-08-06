import importlib.util
import hashlib
import json
import logging
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest import mock

import dpkt

from fakenet.diverters.pcapwriter import DualPcapWriter


ROOT = Path(__file__).resolve().parents[1]
LINUX_TEST = ROOT / 'test' / 'dual_pcap_linux'


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


verify_capture = load_module(
    'linux_verify_capture', LINUX_TEST / 'verify_capture.py')
linux_runner = load_module(
    'linux_acceptance_runner', LINUX_TEST / 'run_tests.py')


def udp_packet(destination, marker):
    udp = dpkt.udp.UDP(sport=41000, dport=53535, data=marker)
    udp.ulen = len(udp)
    packet = dpkt.ip.IP(
        src=socket.inet_aton('192.0.2.10'),
        dst=socket.inet_aton(destination), p=dpkt.ip.IP_PROTO_UDP,
        ttl=64, data=udp)
    packet.len = len(packet)
    return bytes(packet)


class LinuxAcceptanceContractTests(unittest.TestCase):
    def test_manifest_rejects_normalized_parent_escape(self):
        runner = linux_runner.Runner.__new__(linux_runner.Runner)
        with tempfile.TemporaryDirectory() as root:
            repo = Path(root)
            manifest = {
                'package_version': 'v1', 'plan_version': 'v4',
                'logs_plaintext': True,
                'files': [{'path': '../escape', 'size': 0,
                           'sha256': hashlib.sha256(b'').hexdigest()}]}
            (repo / 'dual-pcap-linux-manifest.json').write_text(
                json.dumps(manifest), encoding='utf-8')
            with mock.patch.object(linux_runner, 'REPO_ROOT', repo):
                with self.assertRaisesRegex(
                        linux_runner.AcceptanceError, 'escapes package root'):
                    runner.validate_manifest()

    def test_emergency_restore_records_post_restore_snapshot_failure(self):
        runner = linux_runner.Runner.__new__(linux_runner.Runner)
        runner._command = mock.Mock(return_value=mock.Mock(
            returncode=0, stderr=b''))
        runner.network_snapshot = mock.Mock(
            side_effect=linux_runner.AcceptanceError('snapshot unavailable'))
        before = {
            'iptables': b'v4', 'ip6tables': b'v6',
            'routes4': b'', 'routes6': b'',
            'dns': {'is_symlink': False, 'link_target': None,
                    'content': b'nameserver 127.0.0.1\n'}}
        with tempfile.TemporaryDirectory() as root:
            case = Path(root)
            remaining = runner.emergency_restore(
                before, case, ['iptables', 'ip6tables'])
            evidence = (case / 'emergency-rollback.txt').read_text(
                encoding='utf-8')

        self.assertEqual(['post-rollback-snapshot-unavailable'], remaining)
        self.assertEqual(2, runner._command.call_count)
        self.assertIn('post-rollback snapshot raised', evidence)

    def test_generated_live_config_enables_only_reviewed_test_scope(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'fakenet.ini'
            prefix = Path(root) / 'capture'
            linux_runner.Runner.write_config(path, prefix)
            config = __import__('configparser').ConfigParser()
            config.read(path, encoding='utf-8')

        self.assertEqual('yes', config.get(
            'FakeNet', 'DivertTraffic').lower())
        self.assertEqual('singlehost', config.get(
            'Diverter', 'NetworkMode').lower())
        self.assertEqual('yes', config.get(
            'Diverter', 'DumpPackets').lower())
        self.assertEqual('yes', config.get(
            'Diverter', 'LinuxFlushIptables').lower())
        self.assertEqual('yes', config.get(
            'Diverter', 'ModifyLocalDNS').lower())
        self.assertEqual('no', config.get(
            'Diverter', 'FixGateway').lower())
        self.assertEqual('no', config.get(
            'Diverter', 'FixDNS').lower())
        self.assertEqual('no', config.get(
            'Diverter', 'RedirectAllTraffic').lower())
        self.assertEqual('disabled', config.get(
            'Diverter', 'ExternalAccessPolicy').lower())
        for section in config.sections():
            if section not in ('FakeNet', 'Diverter'):
                self.assertFalse(config.getboolean(section, 'Enabled'))

    def test_live_verifier_requires_original_and_mangled_marker(self):
        with tempfile.TemporaryDirectory() as root:
            raw = os.path.join(root, 'capture.pcap')
            converted = os.path.join(root, 'capture-converted.pcap')
            writer = DualPcapWriter(
                raw, converted, logging.getLogger('linux-acceptance-test'),
                clock=lambda: 5.0)
            writer.write_ip_packet(udp_packet(
                '198.51.100.77', b'dual-pcap-linux-v1'))
            writer.write_ip_packet(udp_packet(
                '127.0.0.1', b'dual-pcap-linux-v1'))
            writer.close()

            result = verify_capture.verify_live(
                raw, converted, 'dual-pcap-linux-v1', '198.51.100.77')

        self.assertEqual(2, result['records'])
        self.assertTrue(result['mangled_destination_observed'])

    def test_one_click_runner_is_noninteractive_and_fail_closed(self):
        shell = (LINUX_TEST / 'Run-Tests.sh').read_text(encoding='utf-8')
        runner = (LINUX_TEST / 'run_tests.py').read_text(encoding='utf-8')
        combined = shell + runner
        for required in (
                'systemd-detect-virt', 'os.geteuid()',
                "'iptables-save'", "'ip6tables-save'",
                'network-before.json', 'network-after.json',
                "('normal', 'raw-write', 'ethernet-write', 'close')",
                'PCAP_DUAL_CURRENT_PACKET_DROP', 'PerformanceGate',
                'emergency_restore', 'logs_plaintext'):
            self.assertIn(required, combined)
        for forbidden in ('input(', 'pip install', 'apt install',
                          'curl ', 'wget '):
            self.assertNotIn(forbidden, combined)
        self.assertNotIn('read ', shell)

    def test_linux_drop_marker_is_in_production_handler(self):
        source = (ROOT / 'fakenet' / 'diverters' / 'linux.py').read_text(
            encoding='utf-8')
        self.assertIn('PCAP_DUAL_CURRENT_PACKET_DROP hook=%s', source)
        self.assertEqual(3, source.count('_drop_capture_failed_packet(nfqpkt'))

    def test_package_builder_contract(self):
        source = (ROOT / 'Build-DualPcapLinuxPackage.ps1').read_text(
            encoding='utf-8')
        self.assertIn("$packageVersion = 'v1'", source)
        self.assertIn('Linux双PCAP同步输出-$packageVersion', source)
        self.assertIn('dual-pcap-linux-manifest.json', source)
        self.assertIn('logs_plaintext = $true', source)
        self.assertIn('No .sha256 sidecar was generated.', source)
        self.assertIn('$shellText.Replace("`r`n", "`n")', source)
        self.assertNotRegex(source, r'(?m)^\s*Compress-Archive\b')


if __name__ == '__main__':
    unittest.main()
