"""Durable LM regression tests (T059-R01): the List-mutex source-deployment
identity chain through the REAL entries - plan CLI (v4 identity from the
full registered M), host/guest pre-effect gates, the real producer ->
oracle -> v4 five-key chain, tamper negatives, and v1/v3/v4 compatibility."""
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
            for c in s.get('cases', []) if c['id'] == 'GAP-LIST-MUTEX')


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
                       '--case', 'GAP-LIST-MUTEX', '--candidate', str(base / 'candidate.json'),
                       '--environment', str(base / 'environment.json'),
                       '--output', str(run / 'plan.json')])
    assert code == 0
    plan = json.loads((run / 'plan.json').read_text())
    plan['execution_id'] = 'lm-regression'
    return plan


class ListSourcePlanTests(unittest.TestCase):
    """LM-A1: real plan CLI derives/freezes the List identity from M."""

    def test_identity_from_full_registered_closure(self):
        work = Path(tempfile.mkdtemp(prefix='fnreg-lm-t1-', dir='/tmp'))
        plan = _source_plan(work)
        identity = plan['candidate']['source_deployment_identity']
        closure = plan['source_deployment_closure']
        self.assertEqual('GAP-LIST-MUTEX', identity['case_id'])
        self.assertEqual(HEAD, identity['source_commit'])
        payload = json.dumps(closure, ensure_ascii=False, sort_keys=True,
                             separators=(',', ':')).encode('utf-8')
        self.assertEqual(hashlib.sha256(payload).hexdigest(), identity['source_hashes_sha256'])
        expected = dict(native.native_source_pins(ROOT))
        for name in A.case_sources(CASE):
            expected[name] = hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        self.assertEqual(expected, closure)

    def test_mixed_selection_refused(self):
        work = Path(tempfile.mkdtemp(prefix='fnreg-lm-t2-', dir='/tmp'))
        plan_env = _source_plan(work)
        base = work
        candidate = json.loads((base / 'candidate.json').read_text())
        (base / 'c2.json').write_text(json.dumps(candidate))
        env = plan_env['environment']
        (base / 'env.json').write_text(json.dumps(env))
        out = base / 'mixed-plan.json'
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = A.main(['--root', str(ROOT), 'plan', '--mode', 'selected',
                           '--case', 'GAP-LIST-MUTEX', '--case', 'GAP-NCSI',
                           '--candidate', str(base / 'c2.json'),
                           '--environment', str(base / 'env.json'), '--output', str(out)])
        self.assertEqual(2, code)

    def test_original_dump_mixed_plan_selection_is_preserved(self):
        # Plan compatibility does not give NCSI the Dump source identity.
        work = Path(tempfile.mkdtemp(prefix='fnreg-lm-dump-mixed-', dir='/tmp'))
        _source_plan(work)
        output = work / 'run' / 'dump-mixed' / 'plan.json'
        output.parent.mkdir()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = A.main(['--root', str(ROOT), 'plan', '--mode', 'selected',
                           '--case', 'GAP-DUMPPACKETS', '--case', 'GAP-NCSI',
                           '--candidate', str(work / 'candidate.json'),
                           '--environment', str(work / 'environment.json'),
                           '--output', str(output)])
        self.assertEqual(0, code)
        plan = json.loads(output.read_text())
        self.assertEqual(['GAP-NCSI', 'GAP-DUMPPACKETS'], plan['required_cases'])
        self.assertEqual('GAP-DUMPPACKETS',
                         plan['candidate']['source_deployment_identity']['case_id'])

    def test_dump_only_m_selection_refused_for_list_identity(self):
        """The v3-for-List direction: a v4 schema on the Dump case (and vice
        versa) refuses at validate_inputs."""
        work = Path(tempfile.mkdtemp(prefix='fnreg-lm-t3-', dir='/tmp'))
        plan = _source_plan(work)
        value = native.manual_inputs(plan, CASE, str(work))
        self.assertEqual('fakenet.manual-input.v4', value['schema'])
        broken = copy.deepcopy(value)
        broken['case'] = 'GAP-DUMPPACKETS'
        with self.assertRaisesRegex(ValueError, 'fixed to'):
            M.validate_inputs('GAP-DUMPPACKETS', broken)

    def test_forged_supplied_identity_refused(self):
        work = Path(tempfile.mkdtemp(prefix='fnreg-lm-t4-', dir='/tmp'))
        base = work
        plan = _source_plan(work)
        candidate = json.loads((base / 'candidate.json').read_text())
        closure = plan['source_deployment_closure']
        payload = json.dumps(closure, ensure_ascii=False, sort_keys=True,
                             separators=(',', ':')).encode('utf-8')
        candidate['source_deployment_identity'] = {
            'schema': 'fakenet.source-deployment-identity.v1', 'source_commit': HEAD,
            'case_id': 'GAP-LIST-MUTEX', 'source_hashes_sha256': '0' * 64}
        del payload  # forged digest independent of the true closure
        (base / 'c3.json').write_text(json.dumps(candidate))
        (base / 'env.json').write_text(json.dumps(plan['environment']))
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = A.main(['--root', str(ROOT), 'plan', '--mode', 'selected',
                           '--case', 'GAP-LIST-MUTEX', '--candidate', str(base / 'c3.json'),
                           '--environment', str(base / 'env.json'),
                           '--output', str(base / 'p3.json')])
        self.assertEqual(2, code)


class ListPreEffectGateTests(unittest.TestCase):
    """LM-A2/G1-G2 for List: host/guest refusals land before side effects."""

    def _request(self, work):
        plan = _source_plan(work)
        driver, checks, request = native._expected_remote_request(ROOT, CASE, plan)
        return request

    def _guest_boundary(self, request):
        from unittest import mock
        import acceptance_runtime as rt
        output = Path(tempfile.mkdtemp(prefix='fnreg-lm-guest-', dir='/tmp')) / 'out'
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

    def test_valid_control_reaches_producer_boundary(self):
        work = Path(tempfile.mkdtemp(prefix='fnreg-lm-ok-', dir='/tmp'))
        request = self._request(work)
        outcome, created = self._guest_boundary(request)
        self.assertEqual('producer-boundary', outcome)
        self.assertTrue(created)

    def test_subset_closure_refused_before_mkdir(self):
        work = Path(tempfile.mkdtemp(prefix='fnreg-lm-sub-', dir='/tmp'))
        request = self._request(work)
        member = sorted(request['source_hashes'])[0]
        subset = {k: v for k, v in request['source_hashes'].items() if k != member}
        payload = json.dumps(subset, ensure_ascii=False, sort_keys=True,
                             separators=(',', ':')).encode('utf-8')
        request['source_hashes'] = subset
        request['candidate']['source_deployment_identity']['source_hashes_sha256'] = \
            hashlib.sha256(payload).hexdigest()
        outcome, created = self._guest_boundary(request)
        self.assertIn('not the registered selection M', outcome)
        self.assertFalse(created)

    def test_source_plus_package_refused_before_mkdir(self):
        work = Path(tempfile.mkdtemp(prefix='fnreg-lm-mix-', dir='/tmp'))
        request = self._request(work)
        request['candidate']['package_sha256'] = 'a' * 64
        outcome, created = self._guest_boundary(request)
        self.assertTrue(outcome.startswith('refused'), outcome)
        self.assertFalse(created)


class ListProducerOracleChainTests(unittest.TestCase):
    """LM-A3: real producer -> oracle with the v4 five-key chain."""

    def test_full_chain_v4(self):
        work = Path(tempfile.mkdtemp(prefix='fnreg-lm-chain-', dir='/tmp'))
        plan = _source_plan(work)
        inputs = native.manual_inputs(plan, CASE, str(work))
        self.assertEqual('fakenet.manual-input.v4', inputs['schema'])
        self.assertIsNone(inputs['package_sha256'])
        driver = Path(inputs['owned_root'])
        self.assertEqual(str(driver), str(work / 'driver'))
        produced = M.run('GAP-LIST-MUTEX', driver, inputs)
        self.assertEqual(sorted(produced['identity']),
                         ['candidate_id', 'execution_id', 'package_sha256',
                          'source_commit', 'source_deployment_identity'])
        rows, clean, detail = O.evaluate(ROOT, work / 'driver', 'GAP-LIST-MUTEX',
                                         inputs, allow_fixture=False)
        self.assertTrue(clean, detail)
        self.assertEqual(['blacklist', 'whitelist', 'mutex'], [r['id'] for r in rows])

    def test_v4_identity_extra_key_is_refused(self):
        work = Path(tempfile.mkdtemp(prefix='fnreg-lm-extra-key-', dir='/tmp'))
        plan = _source_plan(work)
        inputs = native.manual_inputs(plan, CASE, str(work))
        M.run('GAP-LIST-MUTEX', work / 'driver', inputs)
        path = work / 'driver' / 'manual-result.json'
        value = json.loads(path.read_text())
        value['identity']['unapproved_extra_field'] = 'must-refuse'
        path.write_text(json.dumps(value) + '\n')
        with self.assertRaisesRegex(ValueError, 'identity mismatch'):
            O.evaluate(ROOT, work / 'driver', 'GAP-LIST-MUTEX', inputs,
                       allow_fixture=False)

    def test_tampered_identity_refused(self):
        work = Path(tempfile.mkdtemp(prefix='fnreg-lm-tamper-', dir='/tmp'))
        plan = _source_plan(work)
        inputs = native.manual_inputs(plan, CASE, str(work))
        M.run('GAP-LIST-MUTEX', work / 'driver', inputs)
        path = work / 'driver' / 'manual-result.json'
        value = json.loads(path.read_text())
        value['identity']['source_deployment_identity']['source_hashes_sha256'] = '1' * 64
        path.write_text(json.dumps(value, indent=2) + '\n')
        with self.assertRaisesRegex(ValueError, 'identity mismatch'):
            O.evaluate(ROOT, work / 'driver', 'GAP-LIST-MUTEX',
                       inputs, allow_fixture=False)


class CompatibilityTests(unittest.TestCase):
    """LM-A4: v1 List / v3 Dump / v2 network stay unchanged."""

    def test_list_v1_package_chain_unchanged(self):
        work = Path(tempfile.mkdtemp(prefix='fnreg-lm-v1-', dir='/tmp'))
        driver = work / 'driver'
        value = {'schema': 'fakenet.manual-input.v1', 'case': 'GAP-LIST-MUTEX',
                 'candidate_id': 'manual-candidate', 'source_commit': HEAD,
                 'package_sha256': 'cd' * 32, 'execution_id': 'lm-v1-compat',
                 'owned_root': str(driver), 'config': str(driver / 'config'),
                 'responsea': '192.0.2.55', 'fixture': False}
        M.validate_inputs('GAP-LIST-MUTEX', value)
        produced = M.run('GAP-LIST-MUTEX', driver, value)
        self.assertEqual(sorted(produced['identity']),
                         ['candidate_id', 'execution_id', 'package_sha256', 'source_commit'])
        rows, clean, detail = O.evaluate(ROOT, driver, 'GAP-LIST-MUTEX',
                                         value, allow_fixture=False)
        self.assertTrue(clean, detail)

    def test_dump_v3_schema_rejects_list_case(self):
        work = Path(tempfile.mkdtemp(prefix='fnreg-lm-v3-', dir='/tmp'))
        plan = _source_plan(work)
        value = native.manual_inputs(plan, CASE, str(work))
        broken = copy.deepcopy(value)
        broken['schema'] = 'fakenet.manual-input.v3'
        with self.assertRaisesRegex(ValueError, 'fixed to'):
            M.validate_inputs('GAP-LIST-MUTEX', broken)

    def test_unknown_schema_refused(self):
        work = Path(tempfile.mkdtemp(prefix='fnreg-lm-unk-', dir='/tmp'))
        plan = _source_plan(work)
        value = native.manual_inputs(plan, CASE, str(work))
        broken = copy.deepcopy(value)
        broken['schema'] = 'fakenet.manual-input.v9'
        with self.assertRaisesRegex(ValueError, 'schema/case mismatch'):
            M.validate_inputs('GAP-LIST-MUTEX', broken)


if __name__ == '__main__':
    unittest.main()
