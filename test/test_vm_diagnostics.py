# -*- coding: utf-8 -*-
"""Host-side contracts for the one-click Windows VM diagnostic runner."""

import importlib.util
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
RUNNER_PATH = ROOT / 'test' / 'gui_vm' / 'run_vm_diagnostics.py'
SPEC = importlib.util.spec_from_file_location('vm_diagnostics', RUNNER_PATH)
DIAGNOSTICS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DIAGNOSTICS)


class VmDiagnosticTests(unittest.TestCase):
    def test_same_nonce_tcp_udp_preflight(self):
        nonce = 'diag-test'
        response = b'FNPR/1|diag-test|OK\n'

        class FakeTcp(object):
            def __init__(self):
                self.sent = b''
                self.response = [response]

            def settimeout(self, unused):
                pass

            def sendall(self, data):
                self.sent += data

            def recv(self, unused):
                return self.response.pop(0) if self.response else b''

            def close(self):
                pass

        class FakeUdp(object):
            def __init__(self):
                self.sent = []

            def settimeout(self, unused):
                pass

            def sendto(self, data, peer):
                self.sent.append((data, peer))

            def recvfrom(self, unused):
                return response, (DIAGNOSTICS.SENTINEL_IPV4,
                                  DIAGNOSTICS.SENTINEL_PORT)

            def close(self):
                pass

        tcp = FakeTcp()
        udp = FakeUdp()
        ok, detail = DIAGNOSTICS.probe_sentinel_once(
            nonce, tcp_connect=lambda peer, timeout: tcp,
            udp_socket_factory=lambda: udp)

        request = b'FNPR/1|diag-test|preflight\n'
        self.assertTrue(ok, detail)
        self.assertEqual(request, tcp.sent)
        self.assertEqual([
            (request, (DIAGNOSTICS.SENTINEL_IPV4,
                       DIAGNOSTICS.SENTINEL_PORT))
        ], udp.sent)

    def test_core_log_states_distinguish_config_and_stop(self):
        state, unused = DIAGNOSTICS.evaluate_core_log(
            'EGRESS_CONTROL_READY\nStop flag found at x\n')
        self.assertEqual('observing-stop', state)

        state, unused = DIAGNOSTICS.evaluate_core_log(
            'EGRESS_CONTROL_READY\nSTOP_PHASE_END phase=complete\n'
            'FakeNet-NG exiting: rc=0\n')
        self.assertEqual('config-missing', state)

        state, unused = DIAGNOSTICS.evaluate_core_log(
            'DOMAIN_TAKEOVER_READY\nSTOP_PHASE_END phase=complete\n'
            'FakeNet-NG exiting: rc=0\n')
        self.assertEqual('complete', state)

    def test_changed_core_logs_excludes_gui_and_unchanged_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            old = root / 'fakenet-old.log'
            gui = root / 'fakenet-GUI-new.log'
            old.write_text('old', encoding='utf-8')
            gui.write_text('gui', encoding='utf-8')
            before = DIAGNOSTICS.snapshot_logs(str(root))
            new = root / 'fakenet-new.log'
            new.write_text('new', encoding='utf-8')

            changed = DIAGNOSTICS.changed_core_logs(str(root), before)

            self.assertEqual([str(new.resolve())], changed)

    def test_runner_is_one_click_and_never_force_kills(self):
        source = RUNNER_PATH.read_text(encoding='utf-8')
        command = (ROOT / 'test' / 'gui_vm' / 'Run-Diagnostics.cmd').read_text(
            encoding='utf-8')
        for marker in (
                'ACTION REQUIRED 1/1', 'Start-FNPR-Sentinel.sh',
                'TCP+UDP', 'ACTION REQUIRED] 现在点击 GUI 的“停止”按钮',
                'STOP_OBSERVE_SECONDS', 'run_export(started_utc)'):
            self.assertIn(marker, source)
        for forbidden in ('taskkill', 'TerminateProcess', 'New-NetRoute',
                          'Set-DnsClientServerAddress'):
            self.assertNotIn(forbidden, source)
        self.assertIn('run_vm_diagnostics.py', command)
        self.assertIn('Start-Process', command)

    def test_diagnostic_builder_has_distinct_non_delivery_identity(self):
        builder = (ROOT / 'Build-GuiVmPackage.ps1').read_text(
            encoding='utf-8-sig')
        command = (ROOT / 'Build-GuiVmDiagnosticPackage.cmd').read_text(
            encoding='utf-8')
        for marker in (
                "ValidateSet('Acceptance', 'Diagnostic')",
                "'v33-diagnostic-01'",
                'Windows-GUI配置工具-VM诊断-',
                'STOP_PHASE_BEGIN phase=complete',
                'Run-Diagnostics.cmd',
                'package_mode=$PackageMode.ToLowerInvariant()'):
            self.assertIn(marker, builder)
        self.assertIn('-PackageMode Diagnostic', command)
        self.assertIn('-PackageVersion v33-diagnostic-01', command)


if __name__ == '__main__':
    unittest.main()
