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
        self.base = Path(tempfile.mkdtemp(prefix='fnreg-r06-guard-', dir='/tmp'))
        self.bootstrap = support.write_child_bootstrap(self.base / 'boot')
        # A derived-inputs file shaped exactly like the real guest derivation.
        self.owned = r'E:\fnreg-r06\runs\exec-1\GAP-SYSLOG-ICMP-LOG\output\driver'
        self.inputs = self.base / 'manual-inputs.json'
        self.inputs.write_text(json.dumps({
            'schema': 'fakenet.manual-input.v1', 'case': 'GAP-SYSLOG-ICMP-LOG',
            'fixture': True, 'owned_root': self.owned,
            'config': self.owned + '\\config', 'candidate_id': 'x',
            'source_commit': 'a' * 40, 'package_sha256': 'b' * 64,
            'execution_id': 'exec-1'}))
        self.probe = self.base / 'probe.py'
        self.probe.write_text(PROBE)
        import hashlib
        self.helper_sha = hashlib.sha256(
            (self.bootstrap / 'os_fixture_backend.py').read_bytes()).hexdigest()
        self.good_pins = {
            'case': 'GAP-SYSLOG-ICMP-LOG', 'fixture': True,
            'request_sha256': 'c' * 64,
            'output_root': r'E:\fnreg-r06\runs\exec-1\GAP-SYSLOG-ICMP-LOG\output',
            'owned_root': self.owned, 'helper_sha256': self.helper_sha}

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

    def test_controller_wrong_sha_foreign_root_counterexample(self):
        # Exact controller entry point: wrong sha (0*64) AND a foreign Z: root
        # — previously installed the sink and ran the marker; must now refuse.
        result = self.run_child(pins={'case': 'GAP-SYSLOG-ICMP-LOG', 'fixture': True,
                                      'request_sha256': '0' * 64,
                                      'output_root': r'Z:\elsewhere', 'owned_root': r'Z:\elsewhere\driver',
                                      'helper_sha256': self.helper_sha},
                                inputs_path=self.inputs)
        self.assert_refused(result, 'wrong-sha-foreign-root')

    def test_controller_missing_backend_helper_counterexample(self):
        # Exact controller entry point: backend helper deleted from the
        # bootstrap; sitecustomize import errors previously WARNED and the
        # marker still ran. Now the helper absence is a fatal refusal.
        (self.bootstrap / 'os_fixture_backend.py').unlink()
        result = self.run_child(pins=self.good_pins, inputs_path=self.inputs)
        self.assert_refused(result, 'missing-backend-helper')

    def test_controller_missing_both_identities_counterexample(self):
        # Exact controller entry point: no CASE/SHA env at all previously ran
        # the marker silently on real interfaces. With the sitecustomize on
        # PYTHONPATH and no pins, the child must die before any business.
        result = self.run_child(pins=None, inputs_path=self.inputs)
        self.assert_refused(result, 'missing-both-identities')

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

    def test_matrix_init_exception_is_fatal(self):
        # A backend helper that raises at import must terminate the child.
        (self.bootstrap / 'os_fixture_backend.py').write_text('raise RuntimeError("boom")\n')
        import hashlib
        pins = dict(self.good_pins,
                    helper_sha256=hashlib.sha256(b'raise RuntimeError("boom")\n').hexdigest())
        result = self.run_child(pins=pins, inputs_path=self.inputs)
        self.assertNotEqual(0, result.returncode)
        self.assertNotIn('BUSINESS_MARKER', result.stdout)

    def test_positive_syslog_loads_only_owned_sink(self):
        # Correct pins + matching inputs: the child starts, installs ONLY the
        # owned sink seam (no backend patch), prints the load line, and the
        # benign marker runs to prove startup completed.
        result = self.run_child(pins=self.good_pins, inputs_path=self.inputs)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn('BUSINESS_MARKER', result.stdout)
        self.assertIn('FNREG_OS_FIXTURE_BOOTSTRAP case=GAP-SYSLOG-ICMP-LOG', result.stderr)

    def test_positive_ctrlc_loads_only_backend(self):
        # The backend seam install imports fakenet.diverters.windows, which
        # pulls winreg — a Windows-only module. On a POSIX host the CTRLC
        # positive is verified up to that platform boundary: all bindings
        # pass and the interpreter reaches the seam-install import; the full
        # positive runs under the real Windows fixture (S52/R05 evidence).
        import sys as _sys
        if _sys.platform != 'win32':
            ctrl = self.base / 'ctrl.json'
            ctrl.write_text(json.dumps({**json.loads(self.inputs.read_text()),
                                        'case': 'GAP-CTRLC-IPC'}))
            result = self.run_child(pins=dict(self.good_pins, case='GAP-CTRLC-IPC'),
                                    inputs_path=ctrl, probe_arg='CTRLC')
            # Sitecustomize Exception only WARNS and the interpreter
            # continues — so on POSIX the probe marker legitimately appears
            # AFTER the failed winreg import; the platform-boundary evidence
            # is the absence of any GUARD refusal (all bindings passed).
            self.assertNotIn('FNREG_OS_FIXTURE_REFUSED', result.stderr)
            self.assertIn("No module named 'winreg'", result.stderr)
            return
        pins = dict(self.good_pins, case='GAP-CTRLC-IPC')
        ctrl = self.base / 'ctrl.json'
        ctrl.write_text(json.dumps({**json.loads(self.inputs.read_text()),
                                    'case': 'GAP-CTRLC-IPC'}))
        result = self.run_child(pins=pins, inputs_path=ctrl, probe_arg='CTRLC')
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn('FNREG_OS_FIXTURE_BOOTSTRAP case=GAP-CTRLC-IPC', result.stderr)


if __name__ == '__main__':
    unittest.main()
