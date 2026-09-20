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
        self.assertIn('probe_pid=$launchPidOut', self.catch)
        self.assertIn('probe_creation_ticks=$launchCreationOut', self.catch)

    def test_pktmon_cleanup_survives_probe_error(self):
        self.assertIn("if($captureStarted)", self.catch)
        self.assertIn('pktmon stop', self.catch)


def make_stop_runner(coop_value=None, coop_exc=None, files_value=None, files_exc=None, kernel_exc=None, order=None):
    runner = suite.Suite.__new__(suite.Suite)
    runner.vm = object()
    state = {'kernel_calls': 0}

    def fake_vm_json(command, timeout=120):
        if order is not None:
            order.append('vm:' + command[:40])
        # the files export command starts with $files=@(; the MAIN stop
        # command merely embeds the conversion section later on.
        if '$files=@(' in command[:80]:
            if files_exc:
                raise files_exc
            return (files_value or {'files': [{'path': r'G:\r\probe.jsonl', 'bytes': 1, 'sha256': '0' * 64}]}), {'output': 'ok'}
        # main stop command
        if coop_exc:
            raise coop_exc
        return {'coop': coop_value}, {'output': 'ok'}

    def fake_kernel(capture):
        state['kernel_calls'] += 1
        if order is not None:
            order.append('kernel')
        if kernel_exc:
            raise kernel_exc
        return {'files': [], 'raw': 'ok'}

    runner._vm_json = fake_vm_json
    runner._stop_kernel_capture = fake_kernel
    return runner, state


CAPTURE = {'run_label': 'run-01', 'stop': r'G:\r\probe.stop', 'pid': 777,
           'probe': r'G:\r\probe.jsonl', 'probe_creation_ticks': 639000000000000000,
           'etl': r'G:\r\pktmon.etl', 'pktmon_nic': r'G:\r\pktmon-nic.json',
           'stdout': r'G:\r\probe.stdout', 'stderr': r'G:\r\probe.stderr',
           'kernel_capture': {}}


class StopCleanupContractTests(unittest.TestCase):
    """F1: timeout/identity-unknown/stopfile-error MUST fail closed; the
    kernel cleanup still runs; both errors survive when both fail."""

    def _coop(self, status, errors=None):
        return {'pid': 777, 'creation_ticks': 639000000000000000,
                'cooperative_exit': status, 'errors': errors or [],
                'pktmon_exit': 0}

    def test_success_returns_and_exports_status(self):
        runner, state = make_stop_runner(coop_value=self._coop('exited'))
        value = runner._stop_capture_and_probe(dict(CAPTURE))
        self.assertEqual(value['cooperative_exit'], 'exited')
        self.assertTrue(value['exit_status_path'].endswith('.exit-status.json'))
        self.assertEqual(state['kernel_calls'], 1)
        self.assertTrue(value['files'])

    def test_timeout_fails_closed_and_kernel_still_runs(self):
        runner, state = make_stop_runner(coop_value=self._coop('timeout'))
        with self.assertRaises(suite.SuiteError) as ctx:
            runner._stop_capture_and_probe(dict(CAPTURE))
        self.assertIn('did not cooperatively exit', str(ctx.exception))
        self.assertIn('timeout', str(ctx.exception))
        self.assertEqual(state['kernel_calls'], 1)

    def test_stopfile_error_fails_closed(self):
        runner, state = make_stop_runner(coop_value=self._coop('wait-error', ['stopfile: denied']))
        with self.assertRaises(suite.SuiteError):
            runner._stop_capture_and_probe(dict(CAPTURE))
        self.assertEqual(state['kernel_calls'], 1)

    def test_identity_unknown_fails_closed_without_wait(self):
        runner, state = make_stop_runner(coop_value=self._coop('identity-unknown'))
        with self.assertRaises(suite.SuiteError) as ctx:
            runner._stop_capture_and_probe(dict(CAPTURE))
        self.assertIn('identity-unknown', str(ctx.exception))
        self.assertEqual(state['kernel_calls'], 1)

    def test_identity_mismatch_fails_closed(self):
        runner, state = make_stop_runner(coop_value=self._coop('identity-mismatch(new process not touched)'))
        with self.assertRaises(suite.SuiteError) as ctx:
            runner._stop_capture_and_probe(dict(CAPTURE))
        self.assertIn('identity-mismatch', str(ctx.exception))

    def test_cleanup_errors_fail_even_after_exit(self):
        runner, state = make_stop_runner(coop_value=self._coop('exited', ['pktmon stop exit 1']))
        with self.assertRaises(suite.SuiteError) as ctx:
            runner._stop_capture_and_probe(dict(CAPTURE))
        self.assertIn('closed with errors', str(ctx.exception))
        self.assertEqual(state['kernel_calls'], 1)

    def test_dual_failure_preserves_both(self):
        runner, state = make_stop_runner(coop_value=self._coop('timeout'),
                                          kernel_exc=suite.SuiteError('kernel session stop failed'))
        with self.assertRaises(suite.SuiteError) as ctx:
            runner._stop_capture_and_probe(dict(CAPTURE))
        self.assertIn('kernel stop failed', str(ctx.exception))
        self.assertIn('did not cooperatively exit', str(ctx.exception))

    def test_files_export_failure_raises_after_cleanup(self):
        runner, state = make_stop_runner(coop_value=self._coop('exited'),
                                          files_exc=suite.SuiteError('disk gone'))
        with self.assertRaises(suite.SuiteError) as ctx:
            runner._stop_capture_and_probe(dict(CAPTURE))
        self.assertIn('file export failed', str(ctx.exception))
        self.assertEqual(state['kernel_calls'], 1)

    def test_no_forbidden_tokens_in_generated_body(self):
        runner, _ = make_stop_runner(coop_value=self._coop('exited'))
        cmd = {}

        def cap(command, timeout=180):
            if '$files=@(' in command[:80]:
                return {'files': [{'path': r'G:\r\probe.jsonl', 'bytes': 1, 'sha256': '0' * 64}]}, {'output': 'ok'}
            cmd['main'] = command
            return {'coop': self._coop('exited')}, {'output': 'ok'}
        runner._vm_json = cap
        runner._stop_capture_and_probe(dict(CAPTURE))
        whole = cmd['main']
        self.assertIsNone(FORBIDDEN.search(whole), FORBIDDEN.search(whole))
        self.assertIn('AddSeconds(30)', whole)
        self.assertIn('identity-unknown', whole)
        self.assertIn('identity-mismatch(new process not touched)', whole)
        self.assertIn('exit-status.json', whole)


class StartCleanupContractTests(unittest.TestCase):
    def setUp(self):
        self.cmd = build_start_command()
        self.catch = self.cmd[self.cmd.index('}catch{'):]

    def test_launch_identity_saved_before_use(self):
        self.assertIn('$launchPid=$p.Id;$launchCreation=$p.StartTime.ToUniversalTime().Ticks', self.cmd)

    def test_catch_never_dereferences_exited_process(self):
        self.assertNotIn('$p.HasExited', self.catch)
        self.assertIn('Get-Process -Id $launchPidOut', self.catch)
        self.assertIn('identity-unknown', self.catch)

    def test_no_forbidden_force_tokens(self):
        self.assertIsNone(FORBIDDEN.search(self.catch), FORBIDDEN.search(self.catch))

    def test_pktmon_cleanup_independent_of_coop_result(self):
        self.assertIn("if($captureStarted)", self.catch)


if __name__ == '__main__':
    unittest.main()
