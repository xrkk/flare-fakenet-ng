import importlib.util
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'fnpr_sentinel', ROOT / 'fnpr_sentinel.py')
SENTINEL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SENTINEL)


class FnprSentinelTests(unittest.TestCase):
    def test_accepts_exact_reviewed_roles_and_echoes_nonce(self):
        for role in ('preflight', 'target', 'non-target'):
            nonce, parsed_role = SENTINEL.parse_request(
                ('FNPR/1|nonce-123|%s\n' % role).encode('ascii'))
            self.assertEqual('nonce-123', nonce)
            self.assertEqual(role, parsed_role)
            self.assertEqual(
                b'FNPR/1|nonce-123|OK\n',
                SENTINEL.build_response(nonce))

    def test_rejects_unbounded_malformed_or_unreviewed_requests(self):
        invalid = (
            b'GET / HTTP/1.1\n',
            b'FNPR/1|nonce|admin\n',
            b'FNPR/1|bad nonce|target\n',
            b'FNPR/1|nonce|target\r\n',
            b'FNPR/1|nonce|target\nsecond\n',
            b'FNPR/1|' + (b'a' * 500) + b'|target\n',
        )
        for request in invalid:
            with self.subTest(request=request[:40]):
                with self.assertRaises(ValueError):
                    SENTINEL.parse_request(request)

    def test_listener_contract_is_fixed_to_reviewed_private_endpoint(self):
        self.assertEqual('192.168.204.1', SENTINEL.BIND_IPV4)
        self.assertEqual(443, SENTINEL.LISTEN_PORT)
        self.assertEqual(512, SENTINEL.MAX_REQUEST_BYTES)

    def test_one_click_launcher_is_bounded_and_does_not_change_host_network(self):
        powershell = (ROOT / 'Start-FNPR-Sentinel.ps1').read_text(
            encoding='utf-8')
        command = (ROOT / 'Start-FNPR-Sentinel.cmd').read_text(
            encoding='utf-8')
        for marker in (
                "bindIPv4 = '192.168.204.1'", 'listenPort = 443',
                "Join-Path $PSScriptRoot 'dist\\Logs'", 'Get-NetIPAddress',
                'Get-NetTCPConnection', 'Press Ctrl+C to stop.',
                'No dependency is downloaded automatically.'):
            self.assertIn(marker, powershell)
        for forbidden in (
                'New-NetFirewallRule', 'Set-NetFirewallProfile',
                'New-NetRoute', 'Set-NetIPAddress', 'Invoke-WebRequest'):
            self.assertNotIn(forbidden, powershell)
        self.assertIn('Start-FNPR-Sentinel.ps1', command)


if __name__ == '__main__':
    unittest.main()
