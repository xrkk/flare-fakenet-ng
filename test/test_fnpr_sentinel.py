import importlib.util
import logging
import os
import pathlib
import stat
import subprocess
import types
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
        self.assertTrue(issubclass(
            SENTINEL.FnprTcpServer, SENTINEL.socketserver.ThreadingTCPServer))
        self.assertTrue(issubclass(
            SENTINEL.FnprUdpServer, SENTINEL.socketserver.ThreadingUDPServer))

    def test_tcp_and_udp_handlers_echo_the_same_bounded_protocol(self):
        logger = logging.getLogger('fnpr-sentinel-test')
        logger.handlers[:] = [logging.NullHandler()]
        server = types.SimpleNamespace(logger=logger)
        request = b'FNPR/1|dual-transport|preflight\n'

        class TcpRequest(object):
            def __init__(self):
                self.response = b''
                self.pending = [request]

            def settimeout(self, unused):
                pass

            def recv(self, unused):
                return self.pending.pop(0) if self.pending else b''

            def sendall(self, data):
                self.response += data

        tcp_request = TcpRequest()
        SENTINEL.FnprRequestHandler(
            tcp_request, ('127.0.0.1', 12345), server)
        self.assertEqual(b'FNPR/1|dual-transport|OK\n',
                         tcp_request.response)

        class UdpResponseSocket(object):
            def __init__(self):
                self.sent = []

            def sendto(self, data, peer):
                self.sent.append((data, peer))

        udp_response = UdpResponseSocket()
        SENTINEL.FnprUdpRequestHandler(
            (request, udp_response), ('127.0.0.1', 12346), server)
        self.assertEqual([
            (b'FNPR/1|dual-transport|OK\n', ('127.0.0.1', 12346))
        ], udp_response.sent)

    def test_one_click_launcher_is_bounded_and_does_not_change_host_network(self):
        powershell = (ROOT / 'Start-FNPR-Sentinel.ps1').read_text(
            encoding='utf-8')
        command = (ROOT / 'Start-FNPR-Sentinel.cmd').read_text(
            encoding='utf-8')
        shell_path = ROOT / 'Start-FNPR-Sentinel.sh'
        shell = shell_path.read_text(encoding='utf-8')
        for marker in (
                "bindIPv4 = '192.168.204.1'", 'listenPort = 443',
                "Join-Path $PSScriptRoot 'dist\\Logs'", 'Get-NetIPAddress',
                'Get-NetTCPConnection', 'Get-NetUDPEndpoint',
                'TCP+UDP sentinel', 'Press Ctrl+C to stop.',
                'No dependency is downloaded automatically.'):
            self.assertIn(marker, powershell)
        for forbidden in (
                'New-NetFirewallRule', 'Set-NetFirewallProfile',
                'New-NetRoute', 'Set-NetIPAddress', 'Invoke-WebRequest'):
            self.assertNotIn(forbidden, powershell)
        self.assertIn('Start-FNPR-Sentinel.ps1', command)

        for marker in (
                "BIND_IPV4='192.168.204.1'", "LISTEN_PORT='443'",
                'dist/Logs', 'ip -4 -o addr show',
                'socket.SOCK_DGRAM', 'TCP+UDP sentinel',
                'Press Ctrl+C to stop.',
                'No dependency is downloaded automatically.',
                'FNPR_PYTHON', 'bind-check.log'):
            self.assertIn(marker, shell)
        for forbidden in (
                'iptables', 'nft ', 'ufw ', 'firewall-cmd', 'ip addr add',
                'ip route add', 'apt install', 'pip install', 'curl ',
                'wget ', 'sudo '):
            self.assertNotIn(forbidden, shell)
        if os.name != 'nt':
            self.assertTrue(shell_path.stat().st_mode & stat.S_IXUSR)
            syntax = subprocess.run(
                ['bash', '-n', str(shell_path)], capture_output=True,
                text=True)
            self.assertEqual('', syntax.stderr)
            self.assertEqual(0, syntax.returncode)


if __name__ == '__main__':
    unittest.main()
