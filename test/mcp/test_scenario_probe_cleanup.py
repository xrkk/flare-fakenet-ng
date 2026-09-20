"""Cooperative probe-cleanup contract tests (T011-R01).

Covers the two former force-kill sites:
- _start_capture_and_probe failure cleanup: only writes the probe's own stop
  file and waits (bounded); records cooperative status and identity.
- _stop_capture_and_probe: identity-bound (pid+creation) bounded cooperative
  wait; PID reuse recorded not acted on; pktmon stop still runs on probe
  wait timeout; no Stop-Process/Force/kill tokens on either path.

The Python side is asserted on the actual generated command strings (the real
execution input), and the PowerShell wait semantics are separately proven on
real WinPS5.1 with own short-lived child processes in the VM evidence run.
"""
import importlib.util
import json
import re
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).parent
SPEC = importlib.util.spec_from_file_location('suite_cleanup_test', HERE / 'acceptance/scenario_suite.py')
suite = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = suite
SPEC.loader.exec_module(suite)

FORBIDDEN = re.compile(r'Stop-Process|TerminateProcess|taskkill|\.Kill\(|Stop-Process -Force')


def build_start_command():
    """Drive the real _start_capture_and_probe command construction with a
    recording fake VM: the first _vm_json call returns startup_failed so the
    failure cleanup path is exercised and its command captured."""
    runner = suite.Suite.__new__(suite.Suite)
    runner.vm = object()
    captured = []

    def fake_vm_json(command, timeout=120):
        captured.append(command)
        value = {'startup_failed': True, 'error': 'probe did not become ready: injected',
                 'cleanup_errors': [], 'capture_started': True, 'guest': r'G:\r',
                 'cooperative_exit': 'timeout', 'probe_pid': 4242,
                 'probe_creation_ticks': 123456789}
        return value, {'raw': 'injected'}

    def fake_kernel(run_root):
        return {'session': 'S', 'files': []}

    def fake_stop_kernel(capture):
        return {'files': []}

    runner._vm_json = fake_vm_json
    runner._start_kernel_capture = fake_kernel
    runner._stop_kernel_capture = fake_stop_kernel
    profile = {'bucket': 'default', 'tempo': 'burst', 'cadence_ms': 25,
               'connection_window_seconds': 90, 'startup_retry_seconds': 70,
               'variant': 'v', 'interleave': 'during-start',
               'probe_target': {'host': '198.51.100.77', 'port': 1337, 'protocol': 'tcp'}}
    try:
        runner._start_capture_and_probe(r'G:\guest', profile, 'nonce-1', 'run-01')
        raise AssertionError('expected SuiteError')
    except suite.SuiteError as exc:
        assert 'startup failed' in str(exc), exc
    return captured[0]


class StartCleanupTests(unittest.TestCase):
    def setUp(self):
        self.cmd = build_start_command()
        self.catch = self.cmd[self.cmd.index('}catch{'):]

    def test_no_forbidden_force_tokens(self):
        self.assertIsNone(FORBIDDEN.search(self.catch), FORBIDDEN.search(self.catch))

    def test_writes_own_stop_file_once_then_bounded_wait(self):
        self.assertIn("if(-not (Test-Path $stop))", self.catch)
        self.assertIn("[IO.File]::WriteAllText($stop,'stop'", self.catch)
        self.assertIn('AddSeconds(30)', self.catch)
        self.assertNotIn('AddSeconds(31)', self.catch)

    def test_records_cooperative_status_and_identity(self):
        self.assertIn('cooperative_exit=$coop', self.catch)
        self.assertIn('probe_pid=$created.ProcessId', self.catch)
        self.assertIn('probe_creation_ticks=$startedTicks', self.catch)

    def test_pktmon_cleanup_survives_probe_error(self):
        self.assertIn("if($captureStarted)", self.catch)
        self.assertIn('pktmon stop', self.catch)


def build_stop_command():
    runner = suite.Suite.__new__(suite.Suite)
    runner.vm = object()
    captured = {}

    def fake_vm_json(command, timeout=120):
        captured['cmd'] = command
        value = {'files': [{'path': r'G:\r\probe.jsonl', 'bytes': 1, 'sha256': '0' * 64}]}
        return value, {'output': 'ok'}

    runner._vm_json = fake_vm_json
    runner._stop_kernel_capture = lambda capture: {'files': [], 'raw': 'ok'}
    capture = {'run_label': 'run-01', 'stop': r'G:\r\probe.stop', 'pid': 777, 'probe': r'G:\r\probe.jsonl',
               'probe_creation_ticks': 639000000000000000, 'etl': r'G:\r\pktmon.etl',
               'pktmon_nic': r'G:\r\pktmon-nic.json', 'stdout': r'G:\r\probe.stdout',
               'stderr': r'G:\r\probe.stderr', 'kernel_capture': {}}
    value = runner._stop_capture_and_probe(capture)
    assert value['files'], value
    return captured['cmd']


class StopCleanupTests(unittest.TestCase):
    def setUp(self):
        self.cmd = build_stop_command()

    def test_no_forbidden_force_tokens(self):
        whole = self.cmd
        self.assertIsNone(FORBIDDEN.search(whole), FORBIDDEN.search(whole))

    def test_identity_bound_wait(self):
        self.assertIn('$expectedCreation=', self.cmd)
        self.assertIn("StartTime.ToUniversalTime().Ticks -ne $expectedCreation", self.cmd)
        self.assertIn("identity-mismatch(new process not touched)", self.cmd)

    def test_bounded_wait_and_status_recorded(self):
        self.assertIn('AddSeconds(30)', self.cmd)
        self.assertIn("$probeExit='exited'", self.cmd)
        self.assertIn("$probeExit='timeout'", self.cmd)
        self.assertIn('exit-status', self.cmd)

    def test_pktmon_stop_runs_after_probe_wait_regardless(self):
        probe_block_end = self.cmd.index('& pktmon stop')
        self.assertLess(self.cmd.index('$probeExit'), probe_block_end)

    def test_kernel_cleanup_preserved_on_primary_error(self):
        # The python wrapper still stops the kernel when pktmon stop throws.
        runner = suite.Suite.__new__(suite.Suite)
        runner.vm = object()
        order = []

        def failing_json(command, timeout=120):
            order.append('primary')
            raise suite.SuiteError('pktmon stop failed')

        runner._vm_json = failing_json
        runner._stop_kernel_capture = lambda capture: order.append('kernel') or {'files': [], 'raw': 'ok'}
        capture = {'run_label': 'run-01', 'stop': r'G:\r\probe.stop', 'pid': 1, 'probe': r'G:\r\p.jsonl',
                   'probe_creation_ticks': 1, 'etl': r'G:\r\e.etl', 'pktmon_nic': r'G:\r\n.json',
                   'stdout': r'G:\r\o', 'stderr': r'G:\r\e', 'kernel_capture': {}}
        with self.assertRaises(suite.SuiteError) as ctx:
            runner._stop_capture_and_probe(capture)
        self.assertEqual(order, ['primary', 'kernel'])
        self.assertIn('pktmon stop failed', str(ctx.exception))
        # when the kernel stop also fails, both errors are preserved
        order.clear()

        def failing_kernel(capture):
            order.append('kernel')
            raise suite.SuiteError('kernel session stop failed')
        runner._stop_kernel_capture = failing_kernel
        with self.assertRaises(suite.SuiteError) as ctx2:
            runner._stop_capture_and_probe(capture)
        self.assertEqual(order, ['primary', 'kernel'])
        self.assertIn('kernel stop failed', str(ctx2.exception))


if __name__ == '__main__':
    unittest.main()
