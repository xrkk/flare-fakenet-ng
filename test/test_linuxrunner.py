# Copyright 2026 Google LLC
"""LNX-FN LinuxRunner unit tests (process + rule probes faked)."""
import subprocess
import sys
import unittest
from unittest import mock

sys.path.insert(0, '.')

from fakenet.mcp import linuxrunner as lr


class FakeProc:
    def __init__(self, rc=None):
        self._rc = rc  # None == alive
        self.terminated = False
        self.killed = False

    @property
    def returncode(self):
        return self._rc

    def poll(self):
        return self._rc

    def terminate(self):
        self.terminated = True
        self._rc = 0

    def kill(self):
        self.killed = True
        self._rc = -9

    def wait(self, timeout=None):
        return self._rc

    stdout = b''


class LinuxRunnerTests(unittest.TestCase):
    def _runner(self):
        return lr.LinuxRunner(config_path_resolver=lambda name, builtin: '/cfg/%s' % name)

    def test_start_spawns_with_stop_flag_and_waits_for_rules(self):
        runner = self._runner()
        order = []
        rules = {'nq': False, 'drop': False}

        def fake_ipt(fragment, binary='iptables'):
            order.append((binary, fragment))
            if binary == 'iptables':
                return rules['nq']
            return rules['drop']

        proc = FakeProc()
        with mock.patch.object(lr, 'subprocess') as sp, \
                mock.patch.object(lr, '_ipt_has', side_effect=fake_ipt):
            sp.Popen.return_value = proc

            def ready_later():
                rules.update(nq=True, drop=True)
            timer = mock.MagicMock()
            timer.monotonic = lambda: 0
            with mock.patch.object(lr.time, 'sleep',
                                   side_effect=lambda s: ready_later()):
                result = runner.start(None, None, {'name': 'x', 'builtin': True})
        self.assertEqual(result['state'], 'healthy')
        argv = sp.Popen.call_args[0][0]
        self.assertIn('fakenet.fakenet', argv)
        self.assertIn('-f', argv)
        self.assertEqual(proc.poll(), None)

    def test_start_failure_when_process_dies_early(self):
        runner = self._runner()
        with mock.patch.object(lr, 'subprocess') as sp, \
                mock.patch.object(lr, '_ipt_has', return_value=False):
            sp.Popen.return_value = FakeProc(rc=2)
            with self.assertRaises(lr.LinuxRunnerError) as caught:
                runner.start(None, None, {'name': 'x', 'builtin': False})
        self.assertIn('exited during startup', str(caught.exception))

    def test_stop_flag_then_clean_rules_reports_stopped(self):
        runner = self._runner()
        proc = FakeProc()
        with mock.patch.object(lr, 'subprocess') as sp:
            sp.Popen.return_value = proc
            runner._proc, runner._stop_flag, runner._run_id = \
                proc, '/tmp/flag-test', 123
            open('/tmp/flag-test', 'w').close()
            with mock.patch.object(lr, '_ipt_has', return_value=False), \
                    mock.patch.object(lr.time, 'monotonic',
                                      side_effect=[0, 1, 2, 99]), \
                    mock.patch.object(lr.time, 'sleep'):
                result = runner.stop(None)
        self.assertEqual(result['state'], 'stopped')
        self.assertTrue(result['release_controller'])
        # the stop-flag path exits on its own before any signal is needed
        self.assertFalse(proc.killed)

    def test_stop_leftover_rules_report_failed(self):
        runner = self._runner()
        proc = FakeProc()
        runner._proc, runner._stop_flag, runner._run_id = proc, None, 1
        def rules(fragment, binary='iptables'):
            return fragment == 'NFQUEUE' or 'DROP' in fragment
        with mock.patch.object(lr, '_ipt_has', side_effect=rules), \
                mock.patch.object(lr.time, 'monotonic',
                                  side_effect=[0, 99]), \
                mock.patch.object(lr.time, 'sleep'):
            result = runner.stop(None)
        self.assertEqual(result['state'], 'failed')
        self.assertIn('NFQUEUE', result['failure_reason'])

    def test_health_detail_combines_process_and_rules(self):
        runner = self._runner()
        runner._proc = FakeProc()
        def rules(fragment, binary='iptables'):
            return fragment == 'NFQUEUE' if binary == 'iptables' else True
        with mock.patch.object(lr, '_ipt_has', side_effect=rules):
            detail = runner.health_detail('started')
        self.assertTrue(detail['process_alive'])
        self.assertTrue(detail['nfqueue_present'])
        self.assertTrue(detail['ipv6_policy_drop'])

    def test_missing_resolver_rejected(self):
        runner = lr.LinuxRunner()
        with self.assertRaises(lr.LinuxRunnerError):
            runner.start(None, None, {'name': 'x', 'builtin': True})


if __name__ == '__main__':
    unittest.main()
