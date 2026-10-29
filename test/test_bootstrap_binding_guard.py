"""Deterministic binding/fail-closed matrix for the private child OS bootstrap.

Every negative launches a REAL child interpreter with the generated
sitecustomize on PYTHONPATH and a benign business-marker probe script; the
positives replicate the controller's exact counterexample entry points from
seq52-controller-review/bootstrap-counterexamples.json. Fail-closed means the
child exits nonzero BEFORE any producer import and the BUSINESS_MARKER never
appears."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'tools'), str(ROOT / 'test')]
import manual_remote_fixture_support as support


PROBE = """
import sys
marker = 'NTEventLogHandler' if 'SYSLOG' in sys.argv[1] else 'backend'
print('BUSINESS_MARKER %s' % marker)
"""



class ParentFrozenDigestTests(unittest.TestCase):
    """Parent-side gate: the frozen digest handed by the caller must match the
    pushed file bytes; a request mutated after freeze never runs the guest."""

    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix='fnreg-r08-parent-', dir='/tmp'))
        self.bootstrap = support.write_child_bootstrap(self.base / 'boot')
        self.owned = r'E:\fnreg-r08\runs\exec-1\GAP-SYSLOG-ICMP-LOG\output\driver'
        self.output_root = r'E:\fnreg-r08\runs\exec-1\GAP-SYSLOG-ICMP-LOG\output'
        self.request_file = self.base / 'guest-request.json'
        self.request_value = {
            'schema': 'fakenet.native-guest-request.v1',
            'case_id': 'GAP-SYSLOG-ICMP-LOG',
            'candidate': {'source_commit': 'a' * 40, 'package_sha256': 'b' * 64,
                          'offline_fixture': True},
            'execution_id': 'exec-1', 'output_root': self.output_root,
            'manual': {'schema': 'fakenet.manual-options.v1', 'responsea': '192.0.2.55'}}
        self.request_file.write_text(json.dumps(self.request_value, indent=2) + '\n')
        import hashlib
        self.frozen_sha = hashlib.sha256(self.request_file.read_bytes()).hexdigest()

    def _stand_in(self):
        stand = support.FaithfulWindowsStandIn(self.base / 'src', {'hostname': 'fixture-vm',
                                                                   'platform': 'windows'})
        stand.pushed['push-request'] = json.loads(self.request_file.read_text())
        stand.pushed['push-request-file'] = str(self.request_file)
        # A benign guest replacement records whether it ever ran.
        stand._guest_calls = []
        stand._real_run_guest = stand._run_guest

        def benign_guest(request):
            stand._guest_calls.append(request)
            return {'returncode': 0, 'process_exited': True, 'recovered': True}
        stand._run_guest = benign_guest
        return stand

    def test_mutated_after_freeze_refused_before_guest(self):
        stand = self._stand_in()
        stand.frozen_request_sha = self.frozen_sha
        # Mutate execution_id AFTER the freeze while keeping the old digest.
        value = dict(self.request_value,
                     candidate=dict(self.request_value['candidate'], source_commit='f' * 40))
        self.request_file.write_text(json.dumps(value, indent=2) + '\n')
        stand.pushed['push-request'] = value
        import os
        os.environ['FN_MANUAL_FAITHFUL_ROOT'] = self.base_root = str(self.base)
        try:
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                stand.execute(str(self.request_file), self.frozen_sha,
                             self.output_root, {}, 60)
        finally:
            os.environ.pop('FN_MANUAL_FAITHFUL_ROOT', None)
        self.assertEqual([], stand._guest_calls)

    def test_cached_dict_divergence_refused(self):
        stand = self._stand_in()
        stand.frozen_request_sha = None
        # File matches a fresh hash but the cached dict was tampered.
        stand.pushed['push-request'] = dict(self.request_value, execution_id='foreign')
        import os
        os.environ['FN_MANUAL_FAITHFUL_ROOT'] = str(self.base)
        try:
            with self.assertRaisesRegex(ValueError, 'cached request differs'):
                stand.execute(str(self.request_file), None, self.output_root, {}, 60)
        finally:
            os.environ.pop('FN_MANUAL_FAITHFUL_ROOT', None)
        self.assertEqual([], stand._guest_calls)




class ExecuteEnvRecoveryTests(unittest.TestCase):
    """The REAL execute() entry: verified request reaches the guest, the
    child env applies only for the call, and a guest exception still
    restores every key to its prior value or absence."""

    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix='fnreg-r09-exec-', dir='/tmp'))
        self.bootstrap = support.write_child_bootstrap(self.base / 'boot')
        self.owned = r'E:\fnreg-r09\runs\exec-1\GAP-SYSLOG-ICMP-LOG\output\driver'
        self.output_root = r'E:\fnreg-r09\runs\exec-1\GAP-SYSLOG-ICMP-LOG\output'
        self.request_file = self.base / 'guest-request.json'
        self.request_value = {
            'schema': 'fakenet.native-guest-request.v1',
            'case_id': 'GAP-SYSLOG-ICMP-LOG',
            'candidate': {'source_commit': 'a' * 40, 'package_sha256': 'b' * 64,
                          'offline_fixture': True},
            'execution_id': 'exec-1', 'output_root': self.output_root,
            'manual': {'schema': 'fakenet.manual-options.v1', 'responsea': '192.0.2.55'}}
        self.request_file.write_text(json.dumps(self.request_value, indent=2) + '\n')
        import hashlib
        self.request_sha = hashlib.sha256(self.request_file.read_bytes()).hexdigest()

    def _stand_in(self):
        stand = support.FaithfulWindowsStandIn(self.base / 'src', {'hostname': 'fixture-vm',
                                                                   'platform': 'windows'})
        stand.pushed['push-request'] = json.loads(self.request_file.read_text())
        stand.pushed['push-request-file'] = str(self.request_file)
        stand.guest_seen = []
        return stand

    def test_execute_child_without_inputs_argv_refused_and_env_restored(self):
        # A NEGATIVE, accurately named: the real chain runs, but the launched
        # child has no --inputs argv, so the bootstrap refuses it.  The absent
        # marker is a REFUSAL, never a positive; real bootstrap success is
        # covered by test_execute_real_chain_bootstrap_success_and_env_restored.
        import os
        import subprocess
        import sys as _sys
        stand = self._stand_in()

        def guest(request):
            stand.guest_seen.append(request)
            # The child REALLY starts under the applied env: the sitecustomize
            # guard runs in a real interpreter with the pins from execute().
            child = self.base / 'child_probe.py'
            child.write_text("print('CHILD_MARKER')\n")
            env = {k: os.environ[k] for k in ('PYTHONPATH', 'FNREG_OS_FIXTURE_PINS') if k in os.environ}
            result = subprocess.run([_sys.executable, '-B', str(child)],
                                    capture_output=True, text=True, env=env, timeout=60)
            return {'returncode': result.returncode, 'process_exited': True,
                    'recovered': True, 'child_stdout': result.stdout,
                    'child_stderr': result.stderr}
        stand._run_guest = guest
        os.environ['FN_MANUAL_FAITHFUL_ROOT'] = str(self.base)
        os.environ.pop('PYTHONPATH', None)
        os.environ.pop('FNREG_OS_FIXTURE_PINS', None)
        try:
            outcome = stand.execute(str(self.request_file), self.request_sha,
                                    self.output_root, {}, 60)
        finally:
            os.environ.pop('FN_MANUAL_FAITHFUL_ROOT', None)
        # The guest received the VERIFIED request.
        self.assertEqual(1, len(stand.guest_seen))
        self.assertEqual(self.request_value, stand.guest_seen[0])
        # The real child refused (its argv carries no --inputs value) —
        # fail-closed with the specific refusal, never a business run.
        self.assertNotIn('CHILD_MARKER', outcome['child_stdout'])
        self.assertIn('FNREG_OS_FIXTURE_REFUSED', outcome['child_stderr'])
        self.assertIn('readable --inputs value', outcome['child_stderr'])
        # Env restored immediately after the call.
        self.assertNotIn('PYTHONPATH', os.environ)
        self.assertNotIn('FNREG_OS_FIXTURE_PINS', os.environ)

    def test_execute_real_chain_bootstrap_success_and_env_restored(self):
        """The controller's seq56 windows-positive-probe, persisted as the
        real regression: REAL transfer() -> execute() -> _run_guest(); ONLY
        the acceptance_guest.execute business boundary is a benign function
        that receives the VERIFIED request/source, derives legal inputs via
        the original builder, and launches a REAL interpreter child whose
        bootstrap must load (BOOTSTRAP line), whose business marker must run,
        and which sees only the owned sink seam.  The child env applies for
        the call only and is restored immediately on return and on a guest
        exception (prior-absent and prior-value)."""
        faithful = os.environ.get('FN_MANUAL_FAITHFUL_ROOT')
        if sys.platform != 'win32' or not faithful:
            self.skipTest('real bootstrap success needs the Windows interpreter '
                          'and a real frozen E:/D: faithful root '
                          '(FN_MANUAL_FAITHFUL_ROOT); a POSIX host child '
                          'legitimately refuses the synthetic faithful root')
        import hashlib
        import subprocess
        from pathlib import PureWindowsPath
        from unittest import mock
        import acceptance_guest as guest
        import acceptance_native as native
        output = Path(faithful) / 'runs' / 'glm-pos-exec' / 'GAP-SYSLOG-ICMP-LOG' / 'output'
        output.mkdir(parents=True, exist_ok=True)
        request_value = {
            'schema': 'fakenet.native-guest-request.v1',
            'case_id': 'GAP-SYSLOG-ICMP-LOG', 'case': {'id': 'GAP-SYSLOG-ICMP-LOG'},
            'candidate': {'source_commit': 'a' * 40, 'package_sha256': 'b' * 64,
                          'offline_fixture': True},
            'execution_id': 'glm-pos-exec',
            'checks': ['syslog', 'icmp', 'owner'], 'actions': ['native'],
            'output_root': str(output),
            'manual': {'schema': 'fakenet.manual-options.v1', 'responsea': '192.0.2.55'}}
        request_file = output.parent / 'guest-request.json'
        request_file.write_text(json.dumps(request_value, indent=2) + '\n',
                                encoding='utf-8')
        request_sha = hashlib.sha256(request_file.read_bytes()).hexdigest()
        stand = support.FaithfulWindowsStandIn(ROOT, {'hostname': 'fixture-vm',
                                                      'platform': 'windows'})
        # REAL transport: transfer() reads the pushed bytes and records the file.
        stand.transfer('push-request', 'push',
                       [{'absolute_path': str(request_file)}], str(faithful),
                       producer_reference={})
        children = []

        def benign_guest(actual_request, actual_source):
            # The guest received the VERIFIED request and the REAL source root.
            assert actual_request == request_value, 'guest request differs from frozen'
            assert actual_source == Path(ROOT), 'guest source root differs'
            directory = PureWindowsPath(actual_request['output_root']) / 'driver'
            Path(str(directory)).mkdir(parents=True, exist_ok=True)
            inputs = native._manual_input_value(
                {'candidate': actual_request['candidate'],
                 'execution_id': actual_request['execution_id']},
                {'id': actual_request['case_id']},
                dict(actual_request.get('manual') or {}),
                str(directory), str(directory / 'config'))
            inputs_file = output / 'manual-inputs.json'
            inputs_file.write_text(json.dumps(inputs, indent=2) + '\n',
                                   encoding='utf-8')
            child = output / 'marker.py'
            child.write_text(
                "import logging.handlers\n"
                "handler = logging.handlers.NTEventLogHandler('benign-positive-probe')\n"
                "assert type(handler).__name__ == '_OwnedSink', type(handler).__name__\n"
                "print('BUSINESS_MARKER owned_sink_only')\n", encoding='utf-8')
            # The child INHERITS the env execute() applied (pins are on
            # os.environ for the duration of the guest call).
            result = subprocess.run([sys.executable, '-B', str(child),
                                     '--case', actual_request['case_id'],
                                     '--inputs', str(inputs_file)],
                                    capture_output=True, text=True, timeout=40)
            children.append(dict(returncode=result.returncode, stdout=result.stdout,
                                 stderr=result.stderr))
            assert result.returncode == 0, result.stderr
            assert 'BUSINESS_MARKER owned_sink_only' in result.stdout
            assert ('FNREG_OS_FIXTURE_BOOTSTRAP case=%s'
                    % actual_request['case_id']) in result.stderr
            return 0

        keys = ('PYTHONPATH', 'FNREG_OS_FIXTURE_PINS')
        initial = {key: os.environ.get(key) for key in keys}
        try:
            for key in keys:
                os.environ.pop(key, None)
            with mock.patch.object(guest, 'execute', side_effect=benign_guest):
                outcome = stand.execute(str(request_file), request_sha,
                                        str(output), {}, 60)
            self.assertEqual({'returncode': 0, 'process_exited': True,
                              'recovered': True}, outcome)
            # Env restored immediately on the success return.
            self.assertTrue(all(key not in os.environ for key in keys))
            for prior in (None, 'pre-existing-controlled-value'):
                for key in keys:
                    if prior is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = prior
                before = {key: os.environ.get(key) for key in keys}
                with mock.patch.object(guest, 'execute',
                                       side_effect=RuntimeError(
                                           'controlled-guest-failure')):
                    with self.assertRaisesRegex(RuntimeError,
                                                'controlled-guest-failure'):
                        stand.execute(str(request_file), request_sha,
                                      str(output), {}, 60)
                # Restored to the PRE-EXISTING value or absence, immediately.
                self.assertEqual(before, {key: os.environ.get(key) for key in keys})
        finally:
            for key, value in initial.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        self.assertEqual(1, len(children))

    def test_execute_guest_exception_still_restores_env(self):
        import os
        stand = self._stand_in()

        def broken_guest(request):
            raise RuntimeError('controlled guest failure')
        stand._run_guest = broken_guest
        os.environ['FN_MANUAL_FAITHFUL_ROOT'] = str(self.base)
        os.environ['PYTHONPATH'] = 'pre-existing-value'
        prior_pins = 'prior-pins'
        os.environ['FNREG_OS_FIXTURE_PINS'] = prior_pins
        try:
            with self.assertRaisesRegex(RuntimeError, 'controlled guest failure'):
                stand.execute(str(self.request_file), self.request_sha,
                              self.output_root, {}, 60)
            # Both keys restored to their PRE-EXISTING values (not absent).
            self.assertEqual('pre-existing-value', os.environ.get('PYTHONPATH'))
            self.assertEqual(prior_pins, os.environ.get('FNREG_OS_FIXTURE_PINS'))
        finally:
            os.environ.pop('FN_MANUAL_FAITHFUL_ROOT', None)
            os.environ.pop('PYTHONPATH', None)
            os.environ.pop('FNREG_OS_FIXTURE_PINS', None)

    def test_inputs_json_list_refused_without_marker(self):
        # The controller's inputs-JSON-[] counterexample through the real
        # child: derived inputs parse as a LIST, previously AttributeError
        # warned and the marker ran; now the whole-init boundary refuses.
        import hashlib
        import os
        import subprocess
        import sys as _sys
        request = self.base / 'req-list.json'
        request.write_text(json.dumps(self.request_value, indent=2) + '\n')
        inputs = self.base / 'inputs.json'
        inputs.write_text('[]')
        child = self.base / 'probe.py'
        child.write_text("print('BUSINESS_MARKER list')\n")
        env = dict(os.environ)
        env['PYTHONPATH'] = str(self.bootstrap)
        env['FNREG_OS_FIXTURE_PINS'] = json.dumps({
            'case': 'GAP-SYSLOG-ICMP-LOG', 'fixture': True,
            'request_file_sha256': hashlib.sha256(request.read_bytes()).hexdigest(),
            'request_file': str(request),
            'expected_inputs': {'case': 'GAP-SYSLOG-ICMP-LOG'},
            'output_root': self.output_root, 'owned_root': self.owned,
            'faithful_root': 'E:/fnreg-r09', 'helper_sha256': hashlib.sha256(
                (self.bootstrap / 'os_fixture_backend.py').read_bytes()).hexdigest()})
        result = subprocess.run([_sys.executable, '-B', str(child), '--inputs', str(inputs)],
                                capture_output=True, text=True, env=env, timeout=60)
        self.assertNotEqual(0, result.returncode)
        self.assertNotIn('BUSINESS_MARKER', result.stdout)
        self.assertIn('derived inputs must be a JSON object', result.stderr)

class ParsePhaseFatalTests(unittest.TestCase):
    """The three controller parse-phase counterexamples must be FATAL."""

    def setUp(self):
        import hashlib
        self.base = Path(tempfile.mkdtemp(prefix='fnreg-r08-parse-', dir='/tmp'))
        self.bootstrap = support.write_child_bootstrap(self.base / 'boot')
        self.probe = self.base / 'probe.py'
        self.probe.write_text("print('BUSINESS_MARKER parse')\n")
        self.helper_sha = hashlib.sha256(
            (self.bootstrap / 'os_fixture_backend.py').read_bytes()).hexdigest()

    def _run(self, pins_raw, argv_extra=None):
        env = dict(os.environ)
        env['PYTHONPATH'] = str(self.bootstrap)
        if pins_raw is not None:
            env['FNREG_OS_FIXTURE_PINS'] = pins_raw
        else:
            env.pop('FNREG_OS_FIXTURE_PINS', None)
        argv = [sys.executable, '-B', str(self.probe)] + (argv_extra or [])
        return subprocess.run(argv, capture_output=True, text=True, env=env, timeout=60)

    def test_pins_wrong_json_type_fatal(self):
        result = self._run('[]')
        self.assertNotEqual(0, result.returncode)
        self.assertNotIn('BUSINESS_MARKER', result.stdout)
        self.assertIn('FNREG_OS_FIXTURE_REFUSED', result.stderr)

    def test_inputs_argv_no_value_fatal(self):
        # A COMPLETE valid pins spec with --inputs as the LAST argv element:
        # the refusal must come from the missing argv value itself.
        request = self.base / 'guest-request.json'
        request.write_text(json.dumps({'case_id': 'GAP-SYSLOG-ICMP-LOG'}))
        import hashlib
        pins = {'case': 'GAP-SYSLOG-ICMP-LOG', 'fixture': True,
                'request_file_sha256': hashlib.sha256(request.read_bytes()).hexdigest(),
                'request_file': str(request),
                'expected_inputs': {'case': 'GAP-SYSLOG-ICMP-LOG', 'fixture': True},
                'output_root': r'E:\x\\output', 'owned_root': r'E:\x\\output\\driver',
                'faithful_root': 'E:/x', 'helper_sha256': self.helper_sha}
        result = self._run(json.dumps(pins), ['--inputs'])
        self.assertNotEqual(0, result.returncode)
        self.assertNotIn('BUSINESS_MARKER', result.stdout)
        self.assertIn('readable --inputs value', result.stderr)

    def test_expected_inputs_wrong_type_fatal(self):
        pins = {'case': 'GAP-SYSLOG-ICMP-LOG', 'fixture': True,
                'request_file_sha256': 'c' * 64, 'request_file': '/nonexistent',
                'expected_inputs': ['not', 'a', 'dict'],
                'output_root': r'E:\x\\output', 'owned_root': r'E:\x\\output\\driver',
                'faithful_root': 'E:/x', 'helper_sha256': self.helper_sha}
        result = self._run(json.dumps(pins))
        self.assertNotEqual(0, result.returncode)
        self.assertNotIn('BUSINESS_MARKER', result.stdout)
        self.assertIn('expected_inputs must be an object', result.stderr)


class BootstrapBindingGuardTests(unittest.TestCase):
    def setUp(self):
        import hashlib
        self.base = Path(tempfile.mkdtemp(prefix='fnreg-r07-guard-', dir='/tmp'))
        self.bootstrap = support.write_child_bootstrap(self.base / 'boot')
        # A real frozen outer-request FILE shaped like the guest chain's push.
        self.owned = r'E:\fnreg-r07\runs\exec-1\GAP-SYSLOG-ICMP-LOG\output\driver'
        self.output_root = r'E:\fnreg-r07\runs\exec-1\GAP-SYSLOG-ICMP-LOG\output'
        self.request_file = self.base / 'guest-request.json'
        self.request_value = {
            'schema': 'fakenet.native-guest-request.v1',
            'case_id': 'GAP-SYSLOG-ICMP-LOG', 'case': {'id': 'GAP-SYSLOG-ICMP-LOG'},
            'candidate': {'source_commit': 'a' * 40, 'package_sha256': 'b' * 64,
                          'offline_fixture': True},
            'execution_id': 'exec-1', 'checks': ['syslog', 'icmp', 'owner'],
            'output_root': self.output_root, 'actions': ['native'],
            'manual': {'schema': 'fakenet.manual-options.v1', 'responsea': '192.0.2.55'}}
        self.request_file.write_text(json.dumps(self.request_value, indent=2) + '\n')
        self.request_bytes = self.request_file.read_bytes()
        self.inputs = self.base / 'manual-inputs.json'
        self.inputs_value = {
            'schema': 'fakenet.manual-input.v1', 'case': 'GAP-SYSLOG-ICMP-LOG',
            'fixture': True, 'owned_root': self.owned,
            'config': self.owned + '\\config', 'candidate_id': 'manual-candidate',
            'source_commit': 'a' * 40, 'package_sha256': 'b' * 64,
            'execution_id': 'exec-1',
            'responsea': '192.0.2.55'}
        self.inputs.write_text(json.dumps(self.inputs_value, indent=2) + '\n')
        self.probe = self.base / 'probe.py'
        self.probe.write_text(PROBE)
        self.helper_sha = hashlib.sha256(
            (self.bootstrap / 'os_fixture_backend.py').read_bytes()).hexdigest()
        self.good_pins = {
            'case': 'GAP-SYSLOG-ICMP-LOG', 'fixture': True,
            'request_file_sha256': hashlib.sha256(self.request_bytes).hexdigest(),
            'request_file': str(self.request_file),
            'expected_inputs': dict(self.inputs_value),
            'output_root': self.output_root, 'owned_root': self.owned,
            'faithful_root': 'E:/fnreg-r07',
            'helper_sha256': self.helper_sha}

    def run_child(self, pins=None, inputs_path=None, probe_arg='SYSLOG', extra_env=None):
        env = dict(os.environ)
        # The real producer child always has the product root importable; the
        # CTRLC seam installs by importing the real product modules.
        env['PYTHONPATH'] = str(self.bootstrap) + os.pathsep + str(ROOT)
        env.pop('FNREG_OS_FIXTURE_PINS', None)
        if pins is not None:
            env['FNREG_OS_FIXTURE_PINS'] = json.dumps(pins)
        if extra_env:
            env.update(extra_env)
        argv = [sys.executable, '-B', str(self.probe), probe_arg]
        if inputs_path is not None:
            argv += ['--inputs', str(inputs_path)]
        return subprocess.run(argv, capture_output=True, text=True, env=env, timeout=60)

    def assert_refused(self, result, why):
        self.assertNotEqual(0, result.returncode, '%s: child must fail closed' % why)
        self.assertNotIn('BUSINESS_MARKER', result.stdout, '%s: producer marker ran' % why)
        self.assertIn('FNREG_OS_FIXTURE_REFUSED', result.stderr, why)

    def test_single_field_wrong_request_sha_only(self):
        # ONLY the pinned request digest changes; roots/helper/identity stay
        # correct — the child must refuse on the outer-request digest itself.
        pins = dict(self.good_pins, request_file_sha256='0' * 64)
        result = self.run_child(pins=pins, inputs_path=self.inputs)
        self.assert_refused(result, 'wrong-request-sha-only')
        self.assertIn('outer request bytes differ', result.stderr)

    def test_single_field_wrong_output_root_only(self):
        # ONLY the pinned output root changes (foreign parent); everything
        # else, including the inputs file, stays correct.
        pins = dict(self.good_pins, output_root=r'Z:\elsewhere\output',
                    owned_root=r'Z:\elsewhere\output\driver')
        result = self.run_child(pins=pins, inputs_path=self.inputs)
        self.assert_refused(result, 'wrong-output-root-only')
        self.assertIn('does not match the pinned request root', result.stderr)

    def test_single_field_changed_candidate_identity_only(self):
        # ONLY the inputs' candidate_id differs from the frozen derivation.
        broken = dict(self.inputs_value, candidate_id='attacker')
        alt = self.base / 'cand.json'; alt.write_text(json.dumps(broken))
        result = self.run_child(pins=self.good_pins, inputs_path=alt)
        self.assert_refused(result, 'changed-candidate-only')
        self.assertIn('field candidate_id differs', result.stderr)

    def test_single_field_changed_execution_id_only(self):
        broken = dict(self.inputs_value, execution_id='foreign-exec')
        alt = self.base / 'exec.json'; alt.write_text(json.dumps(broken))
        result = self.run_child(pins=self.good_pins, inputs_path=alt)
        self.assert_refused(result, 'changed-execution-only')
        self.assertIn('field execution_id differs', result.stderr)

    def test_install_exception_posix_fatal_windows_completes(self):
        # The controller's ctrlc-install-exception counterexample: on POSIX a
        # winreg import failure during the install stage previously WARNED
        # and the marker still ran — the whole-init guard now makes it FATAL.
        # On Windows winreg imports fine, so the same child proves the
        # install completes with the marker (no false refusal).
        ctrl = self.base / 'ctrl.json'
        ctrl.write_text(json.dumps({**self.inputs_value, 'case': 'GAP-CTRLC-IPC'}))
        request_ctrl = self.base / 'guest-ctrl.json'
        value = dict(self.request_value, case_id='GAP-CTRLC-IPC',
                     case={'id': 'GAP-CTRLC-IPC'}, output_root=self.output_root)
        request_ctrl.write_text(json.dumps(value, indent=2) + '\n')
        import hashlib
        pins = dict(self.good_pins, case='GAP-CTRLC-IPC',
                    request_file=str(request_ctrl),
                    request_file_sha256=hashlib.sha256(request_ctrl.read_bytes()).hexdigest(),
                    expected_inputs={**self.inputs_value, 'case': 'GAP-CTRLC-IPC'})
        import sys as _sys
        result = self.run_child(pins=pins, inputs_path=ctrl, probe_arg='CTRLC')
        if _sys.platform != 'win32':
            self.assertNotEqual(0, result.returncode)
            self.assertNotIn('BUSINESS_MARKER', result.stdout)
            self.assertTrue('FNREG_OS_FIXTURE_INIT_FAILED' in result.stderr
                            or 'FNREG_OS_FIXTURE_REFUSED' in result.stderr, result.stderr)
        else:
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn('BUSINESS_MARKER', result.stdout)
            self.assertIn('FNREG_OS_FIXTURE_BOOTSTRAP case=GAP-CTRLC-IPC', result.stderr)

    def test_matrix_wrong_case(self):
        pins = dict(self.good_pins, case='GAP-LIST-MUTEX')
        self.assert_refused(self.run_child(pins=pins, inputs_path=self.inputs), 'wrong-case')

    def test_matrix_non_fixture(self):
        pins = dict(self.good_pins, fixture=False)
        self.assert_refused(self.run_child(pins=pins, inputs_path=self.inputs), 'non-fixture')
        broken = json.loads(self.inputs.read_text()); broken['fixture'] = False
        alt = self.base / 'nonfix.json'; alt.write_text(json.dumps(broken))
        self.assert_refused(self.run_child(pins=self.good_pins, inputs_path=alt), 'inputs-non-fixture')

    def test_matrix_foreign_owned_root(self):
        foreign = self.base / 'foreign.json'
        data = json.loads(self.inputs.read_text()); data['owned_root'] = r'Z:\attacker\driver'
        foreign.write_text(json.dumps(data))
        self.assert_refused(self.run_child(pins=self.good_pins, inputs_path=foreign), 'foreign-owned-root')

    def test_matrix_tampered_helper(self):
        tampered = dict(self.good_pins, helper_sha256='f' * 64)
        self.assert_refused(self.run_child(pins=tampered, inputs_path=self.inputs), 'tampered-helper')

    def test_matrix_missing_inputs_argument(self):
        self.assert_refused(self.run_child(pins=self.good_pins, inputs_path=None), 'no-inputs-argv')

    def test_matrix_unreadable_inputs(self):
        self.assert_refused(self.run_child(pins=self.good_pins,
                                           inputs_path=self.base / 'absent.json'), 'unreadable-inputs')

    def test_positive_syslog_loads_only_owned_sink(self):
        # Correct pins + matching inputs: the child starts, installs ONLY the
        # owned sink seam (no backend patch), prints the load line, and the
        # benign marker runs to prove startup completed.
        result = self.run_child(pins=self.good_pins, inputs_path=self.inputs)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn('BUSINESS_MARKER', result.stdout)
        self.assertIn('FNREG_OS_FIXTURE_BOOTSTRAP case=GAP-SYSLOG-ICMP-LOG', result.stderr)

    def test_positive_ctrlc_loads_only_backend(self):
        # POSIX: the winreg import failure during install is now a FATAL
        # init failure (previously warned and ran the marker) — assert that.
        import sys as _sys
        ctrl = self.base / 'ctrl.json'
        ctrl.write_text(json.dumps({**self.inputs_value, 'case': 'GAP-CTRLC-IPC'}))
        request_ctrl = self.base / 'guest-ctrl.json'
        value = dict(self.request_value, case_id='GAP-CTRLC-IPC',
                     case={'id': 'GAP-CTRLC-IPC'}, output_root=self.output_root)
        request_ctrl.write_text(json.dumps(value, indent=2) + '\n')
        import hashlib
        pins = dict(self.good_pins, case='GAP-CTRLC-IPC',
                    request_file=str(request_ctrl),
                    request_file_sha256=hashlib.sha256(request_ctrl.read_bytes()).hexdigest(),
                    expected_inputs={**self.inputs_value, 'case': 'GAP-CTRLC-IPC'})
        result = self.run_child(pins=pins, inputs_path=ctrl, probe_arg='CTRLC')
        if _sys.platform != 'win32':
            self.assertNotEqual(0, result.returncode)
            self.assertNotIn('BUSINESS_MARKER', result.stdout)
            self.assertIn('FNREG_OS_FIXTURE_INIT_FAILED', result.stderr)
            return
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn('BUSINESS_MARKER', result.stdout)
        self.assertIn('FNREG_OS_FIXTURE_BOOTSTRAP case=GAP-CTRLC-IPC', result.stderr)


if __name__ == '__main__':
    unittest.main()
