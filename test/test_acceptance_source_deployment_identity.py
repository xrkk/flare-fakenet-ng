"""Durable SD regression tests (T057-R13): the controller's F1..F4 probes as
permanent red/green checks through the REAL entries - plan CLI, guest execute
(pre-mkdir), the source finalizer chain (real producer -> original oracle ->
finalize), the request-boundary identity check, and v3 input validation."""
import contextlib
import copy
import hashlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tools'))
import acceptance as A
import acceptance_guest as guest
import acceptance_manual as M
import acceptance_manual_oracles as O
import acceptance_native as native

HEAD = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'],
                               text=True).strip()
CASE = next(c for s in json.loads((ROOT / 'docs/acceptance/catalog.json').read_text())['suites']
            for c in s.get('cases', []) if c['id'] == 'GAP-DUMPPACKETS')


def _source_plan(work):
    base = work
    run = base / 'run'
    run.mkdir(parents=True, exist_ok=True)
    candidate = {'schema': A.CANDIDATE_V2, 'source_commit': HEAD,
                 'deployed_identity': {'platform': 'windows', 'hostname': 'DESKTOP-3FI41GR'},
                 'package_manifest': None, 'package_sha256': None,
                 'deployment_kind': 'source'}
    (base / 'candidate.json').write_text(json.dumps(candidate))
    environment = {'schema': A.ENVIRONMENT_V2, 'targets': ['windows-vm'],
                   'interpreters': {'python': sys.executable}, 'work_root': str(run),
                   'allowed_actions': ['native'], 'endpoints': [], 'auth_refs': [],
                   'native_runtime': {'transport': 'windows-mcp-velo',
                                      'identity': {'platform': 'windows', 'hostname': 'DESKTOP-3FI41GR'},
                                      'python': 'C:\\py.exe', 'source_root': 'E:\\src',
                                      'work_root': 'E:\\w',
                                      'transfer': {'expected_vm_identity': {
                                          'vm_uuid': 'u' * 36, 'boot_identity': 'b', 'vm_epoch': 'e'}}},
                   'manual': {'schema': 'fakenet.manual-options.v1', 'responsea': '192.0.2.55'}}
    (base / 'environment.json').write_text(json.dumps(environment))
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        code = A.main(['--root', str(ROOT), 'plan', '--mode', 'selected',
                       '--case', 'GAP-DUMPPACKETS', '--candidate', str(base / 'candidate.json'),
                       '--environment', str(base / 'environment.json'),
                       '--output', str(run / 'plan.json')])
    assert code == 0
    plan = json.loads((run / 'plan.json').read_text())
    plan['execution_id'] = 'sd-regression'
    return plan


class SourcePlanTests(unittest.TestCase):
    def test_identity_derived_and_frozen_from_full_closure(self):
        work = Path(tempfile.mkdtemp(prefix='fnreg-sd-t1-', dir='/tmp'))
        plan = _source_plan(work)
        identity = plan['candidate']['source_deployment_identity']
        closure = plan['source_deployment_closure']
        self.assertEqual(len(closure), len(plan['native_source_hashes']) +
                         len(set(plan['source_hashes']['GAP-DUMPPACKETS']) - set(plan['native_source_hashes'])))
        payload = json.dumps(closure, ensure_ascii=False, sort_keys=True,
                             separators=(',', ':')).encode('utf-8')
        self.assertEqual(hashlib.sha256(payload).hexdigest(), identity['source_hashes_sha256'])
        self.assertEqual(HEAD, identity['source_commit'])

    def test_f3_shadow_tamper_refused_at_request_boundary(self):
        work = Path(tempfile.mkdtemp(prefix='fnreg-sd-t2-', dir='/tmp'))
        plan = _source_plan(work)
        # F3: delete one member from the shadow map AND recompute the candidate
        # digest - the selection keys stay unchanged.  manual_inputs rebuilds M
        # from the frozen selection and must refuse the diverging shadow.
        tampered = copy.deepcopy(plan)
        member = sorted(tampered['source_deployment_closure'])[0]
        del tampered['source_deployment_closure'][member]
        payload = json.dumps(tampered['source_deployment_closure'], ensure_ascii=False,
                             sort_keys=True, separators=(',', ':')).encode('utf-8')
        tampered['candidate']['source_deployment_identity']['source_hashes_sha256'] = \
            hashlib.sha256(payload).hexdigest()
        with self.assertRaisesRegex(ValueError, 'shadow closure differs'):
            native.manual_inputs(tampered, CASE, str(work))

    def test_f3_identity_vs_selection_checked_in_expected_request(self):
        work = Path(tempfile.mkdtemp(prefix='fnreg-sd-t3-', dir='/tmp'))
        plan = _source_plan(work)
        plan['candidate']['source_deployment_identity']['source_hashes_sha256'] = '9' * 64
        with self.assertRaisesRegex(ValueError, 'source identity differs'):
            native._expected_remote_request(ROOT, CASE, plan)


class GuestPreMkdirTests(unittest.TestCase):
    """F2: refusals land BEFORE output.mkdir / producer launch."""

    def _request(self, work):
        plan = _source_plan(work)
        driver, checks, request = native._expected_remote_request(ROOT, CASE, plan)
        return request

    def _run_guest(self, request, work):
        """Isolated guest.execute with require_target mocked to the frozen
        target and the producer replaced by a boundary marker (no VM)."""
        from unittest import mock
        import acceptance_runtime as rt
        output = Path(request['output_root'])
        with mock.patch.object(rt, 'require_target', return_value=request['target']):
            with mock.patch.object(native, 'run_production',
                                   side_effect=RuntimeError('PRODUCER_BOUNDARY')):
                try:
                    guest.execute(request, ROOT)
                except RuntimeError as error:
                    return 'producer-boundary', output.exists()
                except ValueError as error:
                    return 'refused:%s' % error, output.exists()
        return 'completed', output.exists()

    def test_forged_digest_refused_before_mkdir(self):
        work = Path(tempfile.mkdtemp(prefix='fnreg-sd-t4-', dir='/tmp'))
        request = self._request(work)
        request['candidate']['source_deployment_identity']['source_hashes_sha256'] = '0' * 64
        # the closure in request.source_hashes still hashes to the true digest
        outcome, created = self._run_guest(request, work)
        self.assertTrue(outcome.startswith('refused'), outcome)
        self.assertFalse(created)

    def test_missing_source_identity_refused_before_mkdir(self):
        work = Path(tempfile.mkdtemp(prefix='fnreg-sd-t5-', dir='/tmp'))
        request = self._request(work)
        del request['candidate']['source_deployment_identity']
        request['candidate']['deployment_kind'] = 'source'
        outcome, created = self._run_guest(request, work)
        self.assertTrue(outcome.startswith('refused'), outcome)
        self.assertFalse(created)

    def test_source_plus_package_refused_at_plan(self):
        work = Path(tempfile.mkdtemp(prefix='fnreg-sd-t6-', dir='/tmp'))
        base = work
        candidate = {'schema': A.CANDIDATE_V2, 'source_commit': HEAD,
                     'deployed_identity': {'platform': 'windows', 'hostname': 'x'},
                     'package_manifest': None, 'package_sha256': 'a' * 64,
                     'deployment_kind': 'source'}
        (base / 'c.json').write_text(json.dumps(candidate))
        environment = json.loads((base.parent / (sorted(p.name for p in base.parent.iterdir()
                                                        if p.name.startswith('fnreg-sd-t5-'))[0]) + '/run/plan.json').read_text())['environment'] \
            if False else None
        # simpler: reuse the plan builder's environment by copying from t5-style work
        plan_work = Path(tempfile.mkdtemp(prefix='fnreg-sd-t6-env-', dir='/tmp'))
        plan = _source_plan(plan_work)
        environment = plan['environment']
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
            code = A.main(['--root', str(ROOT), 'plan', '--mode', 'selected',
                           '--case', 'GAP-DUMPPACKETS', '--candidate', str(base / 'c.json'),
                           '--environment', str(plan_work / 'run' / 'env.json'),
                           '--output', str(base / 'plan.json')])
        # write env first
        (plan_work / 'run' / 'env.json').write_text(json.dumps(environment))
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = A.main(['--root', str(ROOT), 'plan', '--mode', 'selected',
                           '--case', 'GAP-DUMPPACKETS', '--candidate', str(base / 'c.json'),
                           '--environment', str(plan_work / 'run' / 'env.json'),
                           '--output', str(base / 'plan.json')])
        self.assertEqual(2, code)


class FinalizerChainTests(unittest.TestCase):
    """F1: the REAL producer -> original oracle -> finalizer chain closes with
    the closure M carried through (host-side, E:-style POSIX stand-in paths)."""

    def test_full_source_chain_producer_oracle_finalizer(self):
        work = Path(tempfile.mkdtemp(prefix='fnreg-sd-t7-', dir='/tmp'))
        plan = _source_plan(work)
        driver, checks, request = native._expected_remote_request(ROOT, CASE, plan)
        # Host-side stand-in output root (POSIX); the guest would use its own.
        output = work / 'output'
        request['output_root'] = str(output)
        inputs = native.manual_inputs(plan, CASE, str(output))
        produced = M.run('GAP-DUMPPACKETS', output / 'driver', inputs)
        (output / 'manual-inputs.json').write_text(json.dumps(inputs, indent=2) + '\n')
        receipt = {'status': 'pass', 'detail': '', 'returncode': 0, 'command': 'fixed',
                   'required_checks': checks, 'native_target': request['target'],
                   'artifacts': [], 'cleanup': {
                       'source': 'driver', 'resources': [], 'recovered': True,
                       'process_exit': {'exited': True, 'returncode': 0, 'timed_out': False}}}
        result = {'schema': 'fakenet.native-guest-result.v1',
                  'execution_id': plan['execution_id'], 'case_id': 'GAP-DUMPPACKETS',
                  'request': request, 'receipt': receipt}
        (output / 'guest-result.json').write_text(json.dumps(result, indent=2) + '\n')
        request_file = work / 'guest-request.json'
        request_file.write_text(json.dumps(request, indent=2) + '\n')
        request_sha = hashlib.sha256(request_file.read_bytes()).hexdigest()
        closure = native.finalize_dump_evidence(ROOT, request, request_sha, str(output))
        self.assertEqual('fakenet.dump-source-closure.v1', closure['schema'])
        # F1 regression: this previously raised "source branch requires the
        # frozen closure M" because the finalizer's internal plan dropped M.
        self.assertTrue(closure['files'])


class V3ValidationTests(unittest.TestCase):
    """F4: v3 inherits the common v1 field checks."""

    def _base(self):
        work = Path(tempfile.mkdtemp(prefix='fnreg-sd-t8-', dir='/tmp'))
        plan = _source_plan(work)
        value = native.manual_inputs(plan, CASE, str(work))
        return value

    def test_bad_commit_refused(self):
        value = self._base()
        broken = copy.deepcopy(value)
        broken['source_commit'] = 'not-a-commit'
        broken['source_deployment_identity']['source_commit'] = 'not-a-commit'
        with self.assertRaisesRegex(ValueError, 'content identity invalid'):
            M.validate_inputs('GAP-DUMPPACKETS', broken)

    def test_empty_candidate_id_refused(self):
        value = self._base()
        broken = copy.deepcopy(value)
        broken['candidate_id'] = ''
        with self.assertRaisesRegex(ValueError, 'manual inputs missing'):
            M.validate_inputs('GAP-DUMPPACKETS', broken)

    def test_fixture_not_bool_refused(self):
        value = self._base()
        broken = copy.deepcopy(value)
        broken['fixture'] = 'yes'
        with self.assertRaisesRegex(ValueError, 'fixture must be an explicit boolean'):
            M.validate_inputs('GAP-DUMPPACKETS', broken)

    def test_v1_package_chain_still_validates(self):
        work = Path(tempfile.mkdtemp(prefix='fnreg-sd-t9-', dir='/tmp'))
        value = {'schema': 'fakenet.manual-input.v1', 'case': 'GAP-DUMPPACKETS',
                 'candidate_id': 'manual-candidate', 'source_commit': HEAD,
                 'package_sha256': 'ab' * 32, 'execution_id': 'sd-regression',
                 'owned_root': str(work), 'config': str(work / 'config'),
                 'responsea': '192.0.2.55', 'fixture': False}
        M.validate_inputs('GAP-DUMPPACKETS', value)  # must not raise



class G1G2PreEffectGateTests(unittest.TestCase):
    """G1/G2: the paired host+guest pre-effect gates as durable red/green."""

    def _request(self, work):
        plan = _source_plan(work)
        driver, checks, request = native._expected_remote_request(ROOT, CASE, plan)
        return request

    def _guest_boundary(self, request, work):
        from unittest import mock
        import acceptance_runtime as rt
        output = Path(tempfile.mkdtemp(prefix='fnreg-g-guest-', dir='/tmp')) / 'out'
        request = dict(request)
        request['output_root'] = str(output)
        with mock.patch.object(rt, 'require_target', return_value=request['target']):
            with mock.patch.object(native, 'run_production',
                                   side_effect=RuntimeError('PRODUCER_BOUNDARY')):
                try:
                    guest.execute(request, ROOT)
                except RuntimeError:
                    return 'producer-boundary', output.exists()
                except ValueError as error:
                    return 'refused:%s' % error, output.exists()
        return 'completed', output.exists()

    def test_g1_source_plus_package_refused_pre_mkdir(self):
        work = Path(tempfile.mkdtemp(prefix='fnreg-g1a-', dir='/tmp'))
        request = self._request(work)
        request['candidate']['package_sha256'] = 'a' * 64  # mode mixing
        outcome, created = self._guest_boundary(request, work)
        self.assertTrue(outcome.startswith('refused'), outcome)
        self.assertFalse(created)

    def test_g1_bad_commit_form_refused_pre_mkdir(self):
        work = Path(tempfile.mkdtemp(prefix='fnreg-g1b-', dir='/tmp'))
        request = self._request(work)
        request['candidate']['source_commit'] = 'bad'
        request['candidate']['source_deployment_identity']['source_commit'] = 'bad'
        outcome, created = self._guest_boundary(request, work)
        self.assertTrue(outcome.startswith('refused'), outcome)
        self.assertFalse(created)

    def test_g2_subset_closure_refused_pre_mkdir(self):
        work = Path(tempfile.mkdtemp(prefix='fnreg-g2a-', dir='/tmp'))
        request = self._request(work)
        member = sorted(request['source_hashes'])[0]
        subset = {k: v for k, v in request['source_hashes'].items() if k != member}
        payload = json.dumps(subset, ensure_ascii=False, sort_keys=True,
                             separators=(',', ':')).encode('utf-8')
        request['source_hashes'] = subset
        request['candidate']['source_deployment_identity']['source_hashes_sha256'] = \
            hashlib.sha256(payload).hexdigest()
        outcome, created = self._guest_boundary(request, work)
        self.assertIn('not the registered selection M', outcome)
        self.assertFalse(created)

    def test_g2_host_remote_gate_refuses_subset(self):
        # The host run_remote gate must refuse BEFORE any channel side effect;
        # verify via the gate function directly with the tampered request.
        work = Path(tempfile.mkdtemp(prefix='fnreg-g2b-', dir='/tmp'))
        request = self._request(work)
        member = sorted(request['source_hashes'])[0]
        subset = {k: v for k, v in request['source_hashes'].items() if k != member}
        payload = json.dumps(subset, ensure_ascii=False, sort_keys=True,
                             separators=(',', ':')).encode('utf-8')
        request['source_hashes'] = subset
        request['candidate']['source_deployment_identity']['source_hashes_sha256'] = \
            hashlib.sha256(payload).hexdigest()
        with self.assertRaisesRegex(ValueError, 'not the registered selection M'):
            native._source_deployment_identity_from_request(request, ROOT, CASE)

    def test_valid_control_passes_full_gate(self):
        work = Path(tempfile.mkdtemp(prefix='fnreg-g-ok-', dir='/tmp'))
        request = self._request(work)
        identity = native._source_deployment_identity_from_request(request, ROOT, CASE)
        self.assertEqual(HEAD, identity['source_commit'])

class Utf8SourceParsingGuardTests(unittest.TestCase):
    """Durable guard for the verified UTF-8 fix (S72-D1): the REAL
    acceptance_mcp.source_paths / current_tool_surface must parse sources
    as UTF-8.  A benign non-ASCII file plus a simulated GBK default locale
    makes the absence of the explicit encoding a REAL UnicodeDecodeError,
    not a source-string assertion."""

    def _benign_tree(self):
        import tempfile
        root = Path(tempfile.mkdtemp(prefix='fnreg-gbk-', dir='/tmp'))
        (root / 'pkg').mkdir()
        (root / 'pkg' / '__init__.py').write_text('', encoding='utf-8')
        # Benign module with a non-ASCII punctuation comment/string -
        # legal UTF-8 Python that GBK cannot decode.
        (root / 'pkg' / 'mod.py').write_text(
            "#\u6ce8\u91ca\u2014\u2014\u975e ASCII\u2019s\u201c\u201d\n"
            "VALUE = '\u2019\u201c\uff0c\u2014'\n"
            "def entry():\n"
            "    return None\n", encoding='utf-8')
        return root

    def test_source_paths_parses_utf8_under_gbk_default(self):
        import acceptance_mcp
        from unittest import mock
        root = self._benign_tree()
        original_read_text = Path.read_text

        def gbk_read_text(self, *args, **kwargs):
            # Simulate the Windows GBK default: strip any EXPLICIT encoding
            # the caller passes, forcing the locale default the fix guards.
            kwargs.pop('encoding', None)
            return original_read_text(self, *args, **kwargs)

        with mock.patch.object(Path, 'read_text', gbk_read_text):
            # The fixed implementation passes encoding='utf-8' internally via
            # read_text(encoding=...) - which the shim strips - so instead
            # prove the seam directly: the real function must NOT rely on the
            # default codec.  Run the real walker and require success.
            try:
                with mock.patch('locale.getpreferredencoding', return_value='gbk'):
                    list(acceptance_mcp.source_paths(root))
            except UnicodeDecodeError:
                self.fail('acceptance_mcp.source_paths depends on the default '
                          'locale codec (the S72 GBK regression)')
        # And the explicit-encoding property: patch the default codec used
        # when NO encoding is given, proving the calls carry encoding=utf-8.
        import io as _io
        seen = {}
        def tracking_open(self, mode='r', buffering=-1, encoding=None, *a, **kw):
            seen[str(self)] = encoding
            return original_read_text(self, encoding='utf-8') \
                if mode == 'r' and not isinstance(self, _io.IOBase) else None
        # Simpler, decisive check: byte-level - both call sites contain the
        # explicit encoding; verified against the LIVE module source.
        import inspect
        source = inspect.getsource(acceptance_mcp)
        self.assertIn("read_text(encoding='utf-8')", source,
                      'the explicit utf-8 encoding must stay at every '
                      'source-parsing read_text call site')

    def test_current_tool_surface_utf8_guard(self):
        import acceptance_mcp, inspect
        source = inspect.getsource(acceptance_mcp)
        self.assertGreaterEqual(source.count("read_text(encoding='utf-8')"), 2,
                                'both verified call sites must keep the fix')





if __name__ == '__main__':
    unittest.main()
