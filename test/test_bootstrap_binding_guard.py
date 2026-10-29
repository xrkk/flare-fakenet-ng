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
            'faithful_root': 'E:\\',
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
        pins = dict(self.good_pins, output_root=r'Z:\elsewhere\\output',
                    owned_root=r'Z:\elsewhere\\output\\driver')
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
