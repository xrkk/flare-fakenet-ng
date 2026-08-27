import importlib.util
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
RUNNER_PATH = ROOT / 'test' / 'gui_vm' / 'run_sample_payload_acceptance.py'
SPEC = importlib.util.spec_from_file_location(
    'sample_payload_acceptance_test_target', RUNNER_PATH)
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class SamplePayloadAcceptanceTests(unittest.TestCase):
    def test_physical_and_unknown_vm_refuse_before_pktmon(self):
        for verdict in (runner.launcher.VERDICT_PHYSICAL,
                        runner.launcher.VERDICT_UNKNOWN):
            with self.subTest(verdict=verdict):
                vm = runner.launcher.VmCheckResult(verdict, 'test-state')
                with mock.patch.object(runner.os, 'name', 'nt'), \
                        mock.patch.object(runner.launcher, 'query_vm_state',
                                          return_value=vm), \
                        mock.patch.object(runner, '_is_admin') as is_admin, \
                        mock.patch.object(runner.shutil, 'which') as which:
                    reason, session = runner._preflight('/does/not/exist')
                self.assertTrue(reason)
                self.assertIsNone(session)
                is_admin.assert_not_called()
                which.assert_not_called()
                self.assertIn('Physical' if verdict ==
                              runner.launcher.VERDICT_PHYSICAL else
                              'inconclusive', reason)

    def test_pktmon_stop_is_attempted_after_start_exception(self):
        calls = []
        persisted = []

        def fake_run(command, transcript, check=True):
            calls.append((list(command), check))
            if command[:2] == ['pktmon', 'start']:
                raise RuntimeError('injected start failure')
            return SimpleNamespace(returncode=0)

        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(
                    runner, '_preflight',
                    return_value=(None, {
                        'gui_log': 'gui.log', 'gui_log_offset': 0,
                        'core_log': 'core.log', 'core_log_offset': 0,
                        'stop_flag': 'core.log.stopflag'})), \
                mock.patch.object(runner, '_unique_directory',
                                  return_value=directory), \
                mock.patch.object(runner, '_run', side_effect=fake_run), \
                mock.patch.object(
                    runner, '_write_json',
                    side_effect=lambda path, value: persisted.append(
                        (path, value))):
            result = runner.run(directory, os.path.join(directory, 'gui.exe'))

        self.assertEqual(runner.EXIT_FAIL, result)
        self.assertTrue(any(command[:2] == ['pktmon', 'stop']
                            for command, _check in calls))
        self.assertTrue(persisted)
        observation = persisted[-1][1]
        self.assertTrue(observation['pktmon']['start_attempted'])
        self.assertTrue(observation['pktmon']['stop_attempted'])
        self.assertIn('injected start failure', observation['failure'])

    def test_stop_helper_records_stop_failure_without_retrying(self):
        state = {
            'started': True, 'stop_attempted': False, 'stopped': False,
            'stop_returncode': None,
        }
        transcript = io.StringIO()
        with mock.patch.object(runner, '_run',
                               side_effect=RuntimeError('stop unavailable')):
            self.assertFalse(runner._stop_pktmon(state, transcript))
            self.assertTrue(runner._stop_pktmon(state, transcript))
        self.assertTrue(state['stop_attempted'])
        self.assertTrue(state['stopped'])
        self.assertIn('stop unavailable', transcript.getvalue())

    def test_success_observation_persists_stop_timings_and_exit_codes(self):
        session = {
            'gui_log': 'gui.log', 'gui_log_offset': 10,
            'core_log': 'core.log', 'core_log_offset': 20,
            'stop_flag': os.path.abspath('core.log.stopflag'),
        }
        monotonic = iter((0.0, 0.05, 0.1, 0.2, 0.4, 0.5))
        reads = {'gui.log': 0}

        def read_suffix(path, _offset):
            if path == 'gui.log':
                reads[path] += 1
                if reads[path] == 1:
                    return ''
                return ('Stop requested via flag: %s\n'
                        'FakeNet session exited: code=0 log=core.log\n' %
                        session['stop_flag'])
            if reads['gui.log'] >= 2:
                return 'FakeNet-NG exiting: rc=0\n'
            return ''

        with mock.patch.object(runner.os.path, 'isfile', return_value=True), \
                mock.patch.object(runner, '_read_suffix', side_effect=read_suffix), \
                mock.patch.object(runner.time, 'monotonic',
                                  side_effect=lambda: next(monotonic)), \
                mock.patch.object(runner.time, 'sleep'):
            result = runner._wait_for_gui_stop(
                session, timeout=1.0, poll_interval=0.001)

        self.assertFalse(result['timed_out'])
        self.assertEqual('0', result['handle_code'])
        self.assertEqual('0', result['core_exit_code'])
        self.assertAlmostEqual(0.3, result['feedback_seconds'])
        self.assertAlmostEqual(0.3, result['top_handle_seconds'])
        self.assertTrue(any(event['event'] == 'top_handle_returned'
                            for event in result['events']))

    def test_exited_gui_without_session_markers_is_not_success(self):
        session = {
            'gui_log': 'gui.log', 'gui_log_offset': 0,
            'core_log': 'core.log', 'core_log_offset': 0,
            'stop_flag': 'core.log.stopflag',
        }
        with mock.patch.object(runner.time, 'sleep'):
            result = runner._wait_for_gui_stop(
                session, timeout=0.001, poll_interval=0.001)
        self.assertTrue(result['timed_out'])
        self.assertIsNone(result['handle_code'])
        self.assertIsNone(result['core_exit_code'])

    def test_active_session_binding_uses_latest_unclosed_gui_session(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            logs = root / 'Logs'
            logs.mkdir()
            old_core = logs / 'fakenet-old.log'
            old_core.write_text(
                'FakeNet-NG started successfully\nFakeNet-NG exiting: rc=0\n',
                encoding='utf-8')
            core = logs / 'fakenet-current.log'
            core.write_text('FakeNet-NG started successfully\n',
                            encoding='utf-8')
            gui = logs / 'fakenet-GUI-session.log'
            gui.write_text(
                'FakeNet session started: log=%s\n'
                'FakeNet session exited: code=0 log=%s\n'
                'FakeNet session started: log=%s\n' %
                (old_core, old_core, core), encoding='utf-8')

            session = runner._discover_active_session(str(root))

        self.assertEqual(str(core), session['core_log'])
        self.assertEqual(str(gui), session['gui_log'])
        self.assertEqual(str(core) + '.stopflag', session['stop_flag'])

    def test_session_evidence_uses_bound_log_paths_not_latest_glob(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            logs = root / 'Logs'
            output = root / 'evidence'
            logs.mkdir()
            output.mkdir()
            gui = logs / 'fakenet-GUI-bound.log'
            core = logs / 'fakenet-bound.log'
            config = root / 'sample.ini'
            raw = root / 'packets-bound.pcap'
            converted = root / 'packets-bound-converted.pcap'
            report = root / 'report-bound.html'
            gui.write_text('bound gui\n', encoding='utf-8')
            config.write_text('[Diverter]\nDumpPackets=Yes\n', encoding='utf-8')
            raw.write_bytes(b'raw')
            converted.write_bytes(b'converted')
            report.write_text('<html>bound</html>', encoding='utf-8')
            core.write_text(
                'Loaded configuration file: %s\n'
                'PCAP_DUAL_SUMMARY raw=%s ethernet=%s raw_count=1\n'
                'Generated new HTML report: %s\n' %
                (config, raw, converted, report), encoding='utf-8')
            (root / 'packets-newer.pcap').write_bytes(b'wrong')
            session = {'gui_log': str(gui), 'core_log': str(core)}

            copied = runner._copy_session_evidence(
                str(root), str(output), session)

            self.assertEqual(b'raw', Path(copied['raw_pcap']).read_bytes())
            self.assertEqual(b'converted',
                             Path(copied['converted_pcap']).read_bytes())
            self.assertEqual(
                '[Diverter]\nDumpPackets=Yes\n',
                Path(copied['config']).read_text(encoding='utf-8'))
            self.assertIn(
                'bound', Path(copied['html']).read_text(encoding='utf-8'))

    def test_runner_has_no_extra_enter_prompt(self):
        source = RUNNER_PATH.read_text(encoding='utf-8')
        self.assertNotIn('input(', source)
        self.assertIn('feedback_seconds', source)
        self.assertIn('top_handle_seconds', source)
        self.assertIn('finally:', source)
        self.assertIn('_stop_pktmon(pktmon_state, transcript)', source)

    def test_integrity_command_carries_the_operator_capture_boundary(self):
        command = runner._payload_integrity_command(
            r'C:\package', {
                'raw_pcap': r'C:\evidence\raw.pcap',
                'html': r'C:\evidence\report.html',
                'core_log': r'C:\evidence\core.log',
                'config': r'C:\evidence\session.ini',
            }, r'C:\evidence\wire.pcapng', r'C:\evidence', 1234.5)

        boundary = command.index('--capture-started-at')
        self.assertEqual('1234.500000', command[boundary + 1])
        self.assertEqual('--output', command[-2])
        self.assertTrue(command[-1].endswith('payload-verification.json'))


if __name__ == '__main__':
    unittest.main()
