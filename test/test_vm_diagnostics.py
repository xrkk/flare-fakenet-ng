# -*- coding: utf-8 -*-
"""Host-side contracts for the one-click Windows VM diagnostic runner."""

import importlib.util
import pathlib
import struct
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

    def test_target_probe_always_exercises_tcp_and_udp_with_same_nonce(self):
        nonce = 'diag-target-test'
        response = b'FNPR/1|diag-target-test|OK\n'

        class FakeTcp(object):
            def __init__(self):
                self.sent = b''

            def settimeout(self, unused):
                pass

            def sendall(self, data):
                self.sent += data

            def recv(self, unused):
                return response

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
        ok, transports = DIAGNOSTICS.probe_fnpr_transports(
            nonce, 'target', tcp_connect=lambda peer, timeout: tcp,
            udp_socket_factory=lambda: udp)

        request = b'FNPR/1|diag-target-test|target\n'
        self.assertTrue(ok, transports)
        self.assertTrue(transports['tcp']['ok'])
        self.assertTrue(transports['udp']['ok'])
        self.assertEqual(request, tcp.sent)
        self.assertEqual([
            (request, (DIAGNOSTICS.SENTINEL_IPV4,
                       DIAGNOSTICS.SENTINEL_PORT))
        ], udp.sent)

    def test_target_probe_does_not_skip_udp_after_tcp_failure(self):
        nonce = 'diag-both-test'
        response = b'FNPR/1|diag-both-test|OK\n'

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

        udp = FakeUdp()

        def fail_tcp(peer, timeout):
            raise OSError('intercepted')

        ok, transports = DIAGNOSTICS.probe_fnpr_transports(
            nonce, 'target', tcp_connect=fail_tcp,
            udp_socket_factory=lambda: udp)

        self.assertFalse(ok)
        self.assertFalse(transports['tcp']['ok'])
        self.assertTrue(transports['udp']['ok'])
        self.assertEqual(1, len(udp.sent))

    def test_dns_probe_parser_requires_exact_takeover_answer(self):
        query_name = 'diag.example.invalid'
        query_id, query = DIAGNOSTICS.build_dns_a_query(query_name, 0x1234)
        self.assertEqual(0x1234, query_id)
        question = query[12:]
        response = (
            struct.pack('!HHHHHH', query_id, 0x8180, 1, 1, 0, 0) +
            question + b'\xc0\x0c' + struct.pack(
                '!HHIH', 1, 1, 60, 4) + b'\xc0\xa8\xcc\x01')

        answers = DIAGNOSTICS.parse_dns_a_response(
            response, query_id, query_name)

        self.assertEqual(['192.168.204.1'], answers)

    def test_diagnostic_evidence_files_are_machine_readable(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = DIAGNOSTICS.create_evidence_paths(
                directory, stamp='20260826-130000')
            DIAGNOSTICS.write_tsv(
                paths['results'], ('check', 'status', 'detail'), [
                    ('dns_takeover', 'PASS', '192.168.204.1'),
                    ('target_tcp', 'FAIL', 'nonce mismatch'),
                ])
            DIAGNOSTICS.write_tsv(
                paths['timeline'], ('event', 'utc', 'detail'), [
                    ('action_prompt', '2026-08-26T05:00:00Z', 'click stop'),
                ])

            results = pathlib.Path(paths['results']).read_text(encoding='utf-8')
            timeline = pathlib.Path(paths['timeline']).read_text(
                encoding='utf-8')
            self.assertIn('dns_takeover\tPASS\t192.168.204.1', results)
            self.assertIn('target_tcp\tFAIL\tnonce mismatch', results)
            self.assertIn('action_prompt\t2026-08-26T05:00:00Z', timeline)
            self.assertTrue(paths['stop_process'].endswith('.tsv'))
            self.assertTrue(paths['bootloader_console'].endswith('.txt'))

    def test_stop_trace_classifies_onefile_cleanup_window(self):
        base = 1_000_000_000
        events = [
            {'event': 'frozen_process_identity_bound',
             'monotonic_ns': base},
            {'event': 'python_atexit_last',
             'monotonic_ns': base + 1_000_000_000},
            {'event': 'python_child_exit_observed',
             'monotonic_ns': base + 1_050_000_000},
            {'event': 'onefile_cleanup_window_observed',
             'monotonic_ns': base + 1_100_000_000},
            {'event': 'mei_directory_missing_observed',
             'monotonic_ns': base + 16_000_000_000},
            {'event': 'onefile_parent_exit_observed',
             'monotonic_ns': base + 16_100_000_000},
        ]

        summary = DIAGNOSTICS.summarize_stop_trace(events)

        self.assertEqual(
            'PYINSTALLER_CLEANUP_WINDOW_OBSERVED',
            summary['classification'])
        self.assertTrue(summary['cleanup_window_seen'])
        self.assertIn('atexit_to_parent_seconds=15.100', summary['detail'])

    def test_bootloader_console_evidence_counts_cleanup_retries(self):
        content = '\n'.join([
            'LOADER: failed to remove temporary directory - attempting to '
            'mitigate the situation...',
            'LOADER: waiting 1000 milliseconds before trying to remove '
            'temporary directory again...',
            'LOADER: trying to remove temporary directory (attempt 1 / 15)...',
            'LOADER: temporary directory C:\\Temp\\_MEI1 was successfully '
            'removed.',
        ])

        result = DIAGNOSTICS.evaluate_bootloader_console(content)

        self.assertTrue(result['debug_present'])
        self.assertTrue(result['initial_remove_failed'])
        self.assertEqual(1, result['retry_waits'])
        self.assertEqual(1, result['retry_attempts'])
        self.assertTrue(result['eventually_removed'])

    def test_gui_monotonic_timeline_uses_callback_as_t0(self):
        content = '\n'.join([
            '[DEBUG-STOP03] gui_stop_callback_received monotonic_ns=1000',
            '[DEBUG-STOP03] gui_stop_feedback_visible monotonic_ns=2000',
            '[DEBUG-STOP03] gui_process_wait_end monotonic_ns=5000001000',
            '[DEBUG-STOP03] gui_finish_session_begin monotonic_ns=5100001000',
        ])

        ok, detail = DIAGNOSTICS.evaluate_gui_stop_debug_log(content)

        self.assertTrue(ok, detail)
        self.assertIn('feedback_seconds=0.000', detail)
        self.assertIn('process_handle_seconds=5.000', detail)
        self.assertIn('ui_finish_callback_seconds=5.100', detail)

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
                'STOP_OBSERVE_SECONDS', 'run_export(started_utc)',
                'probe_takeover_path', 'diagnostic-results-',
                'diagnostic-timeline-', 'diagnostic-network-before-',
                'diagnostic-network-after-', 'wait_for_gui_stop_observation'):
            self.assertIn(marker, source)
        for marker in (
                'StopProcessMonitor', 'evaluate_bootloader_console',
                'capture_windows_console.py', 'stop_delay_classification'):
            self.assertIn(marker, source)
        for forbidden in ('taskkill', 'TerminateProcess', 'New-NetRoute',
                          'Set-DnsClientServerAddress'):
            self.assertNotIn(forbidden, source)
        self.assertIn('run_vm_diagnostics.py', command)
        self.assertIn('Start-Process', command)

    def test_exporter_collects_every_diagnostic_evidence_type(self):
        exporter = (ROOT / 'test' / 'gui_vm' / 'Export-Logs.ps1').read_text(
            encoding='utf-8-sig')
        for marker in (
                'Logs\\diagnostic-*.tsv', 'Logs\\diagnostic-*.txt',
                'Logs\\diagnostic-*.json', 'Logs\\diagnostic-*.jsonl',
                'UTF8Encoding $false'):
            self.assertIn(marker, exporter)

    def test_diagnostic_stop_runtime_hook_is_diagnostic_only(self):
        hook = (ROOT / 'test' / 'gui_vm' /
                'stop_trace_runtime_hook.py').read_text(encoding='utf-8')
        console = (ROOT / 'test' / 'gui_vm' /
                   'capture_windows_console.py').read_text(encoding='utf-8')
        for marker in (
                '[DEBUG-STOP03]', 'python_runtime_started',
                'python_atexit_last', 'sys._MEIPASS'):
            self.assertIn(marker, hook)
        for marker in ('AttachConsole', 'CONOUT$', 'ReadConsoleOutputCharacterW'):
            self.assertIn(marker, console)

    def test_gui_logs_launch_time_config_identity(self):
        source = (ROOT / 'fakenet' / 'gui' / 'app.py').read_text(
            encoding='utf-8')
        for marker in ('def config_file_evidence(path):',
                       'FakeNet config evidence: path=%s sha256=%s',
                       "config_evidence['stable']"):
            self.assertIn(marker, source)

    def test_diagnostic_builder_has_distinct_non_delivery_identity(self):
        builder = (ROOT / 'Build-GuiVmPackage.ps1').read_text(
            encoding='utf-8-sig')
        command = (ROOT / 'Build-GuiVmDiagnosticPackage.cmd').read_text(
            encoding='utf-8')
        for marker in (
                "ValidateSet('Acceptance', 'Diagnostic')",
                "'v33-diagnostic-03'",
                'Windows-GUI配置工具-VM诊断-',
                'STOP_PHASE_BEGIN phase=complete',
                'Run-Diagnostics.cmd',
                'package_mode=$PackageMode.ToLowerInvariant()'):
            self.assertIn(marker, builder)
        self.assertIn('-PackageMode Diagnostic', command)
        self.assertIn('-PackageVersion v33-diagnostic-03', command)


if __name__ == '__main__':
    unittest.main()
