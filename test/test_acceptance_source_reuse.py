"""Explicit source-level reuse proof for same-product, new-harness plans."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'test'))
if os.environ.get('FN_COMPAT_CHECK_DIR'):
    os.environ.setdefault('FN_IDENTITY_CHECK_DIR',
                          str(Path(os.environ['FN_COMPAT_CHECK_DIR']) / 'identity'))
import acceptance
import acceptance_native
import acceptance_source_identity as source_identity

# The task freezes this actual product commit; do not infer a permanent
# product-equivalence claim from a moving HEAD~N expression.
OLD_SOURCE = 'e11ed78567537f60b47bd4cbea718734621baf50'


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def blob_oid(body):
    return hashlib.sha1(b'blob %d\0' % len(body) + body).hexdigest()


class SourceReuseTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(os.environ['FN_COMPAT_CHECK_DIR']) / self.id().split('.')[-1]
        self.base.mkdir(parents=True, exist_ok=False)
        self.old = OLD_SOURCE
        self.current = subprocess.run(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'],
                                      capture_output=True, text=True, check=True).stdout.strip()
        self.candidate = self.base / 'candidate.json'
        self.environment = self.base / 'environment.json'
        self.candidate.write_text(json.dumps({
            'schema': acceptance.CANDIDATE_V2, 'candidate_id': 'source-reuse-fixture',
            'source_commit': self.old, 'package_manifest': None,
            'package_sha256': None, 'deployed_identity': None,
            'source_reuse': {'schema': source_identity.SCHEMA}}, ensure_ascii=False))
        self.environment.write_text(json.dumps({
            'schema': acceptance.ENVIRONMENT_V2, 'targets': ['host-linux'],
            'interpreters': {'python': sys.executable}, 'endpoints': [],
            'auth_refs': [], 'work_root': str(self.base), 'allowed_actions': ['native']},
            ensure_ascii=False))

    def data(self):
        return {'schema': acceptance.CANDIDATE_V2, 'candidate_id': 'source-reuse-fixture',
                'source_commit': self.old, 'package_manifest': None,
                'package_sha256': None, 'deployed_identity': None,
                'source_reuse': {'schema': source_identity.SCHEMA}}

    def cli(self, *args):
        return acceptance.main(['--root', str(ROOT), *map(str, args)])

    def central_inputs(self, name='central'):
        base = self.base / name
        base.mkdir(parents=True, exist_ok=False)
        candidate = self.data()
        candidate['offline_fixture'] = True
        target = {'platform': 'linux', 'hostname': 't033-source-fixture'}
        candidate['deployed_identity'] = target
        environment = {
            'schema': acceptance.ENVIRONMENT_V2, 'targets': ['host-linux'],
            'interpreters': {'python': sys.executable}, 'endpoints': [],
            'auth_refs': [], 'work_root': str(base), 'allowed_actions': ['native'],
            'native_runtime': {'transport': 'local-target', 'identity': target},
        }
        write_json(base / 'candidate.json', candidate)
        write_json(base / 'environment.json', environment)
        return base, candidate, environment, target

    @staticmethod
    def fixture_upstream(driver_dir, checks):
        driver_dir.mkdir(parents=True, exist_ok=True)
        suites = list(dict.fromkeys(item.split('::', 1)[0] for item in checks))
        lifecycle = []
        for index, suite in enumerate(suites):
            child = driver_dir / ('suite-%02d' % index)
            child.mkdir()
            core = {'ready': True, 'stopped': True, 'forced': False, 'returncode': 0}
            lifecycle.append({'suite': suite, 'core': core})
            write_json(child / 'core-lifecycle.json', core)
            write_json(child / 'network-before.json', {})
            write_json(child / 'network-after.json', {})
            (child / 'core.log').write_text('FakeNet-NG started successfully\n', encoding='utf-8')
            (child / 'core-console.log').write_text('', encoding='utf-8')
        write_json(driver_dir / 'lifecycle.json', lifecycle)
        write_json(driver_dir / 'upstream.json', {
            'schema': 'fakenet.upstream-result.v1', 'required_checks': checks,
            'checks': [{'id': item, 'status': 'pass'} for item in checks],
            'failure': None, 'cleanup_complete': True})

    def test_explicit_product_closure_reuse_creates_plan_with_separate_harness_identity(self):
        value = acceptance.make_plan_v2(
            ROOT, 'selected', self.candidate, self.environment,
            [], ['UPSTREAM-TCP-UDP'], self.base / 'run/plan.json')
        self.assertEqual(self.old, value['source_commit'])
        self.assertEqual(self.current, value['harness_commit'])
        self.assertEqual(source_identity.SCHEMA, value['source_reuse']['schema'])
        self.assertEqual(self.old, value['source_reuse']['candidate_source'])
        self.assertEqual(self.current, value['source_reuse']['harness_commit'])
        self.assertTrue(value['source_reuse']['closure'])
        product_paths = {item['path'] for item in value['source_reuse']['closure']}
        for required in ('fakenet/fakenet.py', 'fakenet/mcp/managed.py', 'fakenet-mcp.spec', 'deploy/linux/deploy.sh'):
            self.assertIn(required, product_paths)
        self.assertTrue(value['source_hashes'])
        self.assertTrue(value['native_source_hashes'])

    def test_central_plan_execute_judge_fixture_and_rehash_negative(self):
        base, unused_candidate, unused_env, unused_target = self.central_inputs()
        plan_path = base / 'run/plan.json'
        code = self.cli('plan', '--mode', 'selected', '--case', 'UPSTREAM-TCP-UDP',
                        '--candidate', base / 'candidate.json', '--environment', base / 'environment.json',
                        '--output', plan_path)
        self.assertEqual(0, code)
        plan = json.loads(plan_path.read_text(encoding='utf-8'))
        self.assertEqual(self.old, plan['source_commit'])
        self.assertEqual(self.current, plan['harness_commit'])
        self.assertFalse(plan['blocked'])

        import acceptance_runtime as runtime_boundary
        class Child:
            pid = 999995
            def wait(self, timeout=None): return 0
        real_popen = subprocess.Popen
        def launch(argv, **kwargs):
            if argv[:1] == ['git']:
                return real_popen(argv, **kwargs)
            case = plan['cases']['UPSTREAM-TCP-UDP']
            output = base/'run/results/UPSTREAM-TCP-UDP'
            self.assertEqual(acceptance_native.production_command(ROOT, case, plan, output, sys.executable), argv)
            self.assertFalse(kwargs['shell'])
            self.fixture_upstream(output/'driver', plan['required_checks']['UPSTREAM-TCP-UDP'])
            return Child()
        with mock.patch.object(runtime_boundary, 'require_target', return_value=unused_target), \
             mock.patch.object(subprocess, 'Popen', side_effect=launch):
            code = self.cli('execute', '--plan', plan_path)
        self.assertEqual(0, code)
        summary = json.loads((base / 'run/summary.json').read_text(encoding='utf-8'))
        self.assertEqual('pass', summary['verdict'])
        self.assertTrue(summary['fixture_contract_pass'])
        self.assertFalse(summary['full_functional_pass'])
        code = self.cli('judge', '--plan', plan_path, '--results', base / 'run/results',
                        '--output', base / 'judge.json')
        self.assertEqual(0, code)
        judged = json.loads((base / 'judge.json').read_text(encoding='utf-8'))
        self.assertEqual('pass', judged['verdict'])
        self.assertTrue(judged['fixture_contract_pass'])
        self.assertFalse(judged['full_functional_pass'])

        results = base / 'run/results'
        receipt_path = results / 'UPSTREAM-TCP-UDP/receipt.json'
        artifact_path = results / 'UPSTREAM-TCP-UDP/driver/upstream.json'
        artifact = json.loads(artifact_path.read_text(encoding='utf-8'))
        artifact['checks'][0]['status'] = 'fail'
        write_json(artifact_path, artifact)
        receipt = json.loads(receipt_path.read_text(encoding='utf-8'))
        for item in receipt['artifacts']:
            if item['path'] == str(artifact_path.resolve()):
                item['sha256'] = acceptance.sha256(artifact_path)
        write_json(receipt_path, receipt)
        index_path = results / 'results.json'
        index = json.loads(index_path.read_text(encoding='utf-8'))
        for item in index['receipts']:
            if item['case_id'] == 'UPSTREAM-TCP-UDP':
                item['sha256'] = acceptance.sha256(receipt_path)
        write_json(index_path, index)
        code = self.cli('judge', '--plan', plan_path, '--results', results,
                        '--output', base / 'bad-judge.json')
        self.assertEqual(1, code)
        bad = json.loads((base / 'bad-judge.json').read_text(encoding='utf-8'))
        self.assertEqual('fail', bad['verdict'])
        self.assertFalse(bad['fixture_contract_pass'])

    def test_central_plan_rejects_tampered_pins_source_and_checks(self):
        base, unused_candidate, unused_env, unused_target = self.central_inputs()
        plan_path = base / 'run/plan.json'
        code = self.cli('plan', '--mode', 'selected', '--case', 'UPSTREAM-TCP-UDP',
                        '--candidate', base / 'candidate.json', '--environment', base / 'environment.json',
                        '--output', plan_path)
        self.assertEqual(0, code)
        original = json.loads(plan_path.read_text(encoding='utf-8'))
        mutations = []
        pins = json.loads(json.dumps(original))
        pins['native_source_hashes']['tools/acceptance.py'] = 'f' * 64
        mutations.append(pins)
        source = json.loads(json.dumps(original))
        source['candidate']['source_commit'] = 'f' * 40
        mutations.append(source)
        checks = json.loads(json.dumps(original))
        checks['required_checks']['UPSTREAM-TCP-UDP'] = ['tampered-check']
        mutations.append(checks)
        target = json.loads(json.dumps(original))
        target['environment']['native_runtime']['identity']['hostname'] = 'other-host'
        mutations.append(target)
        source_hashes = json.loads(json.dumps(original))
        first_source = next(iter(source_hashes['source_hashes']['UPSTREAM-TCP-UDP']))
        source_hashes['source_hashes']['UPSTREAM-TCP-UDP'][first_source] = 'f' * 64
        mutations.append(source_hashes)
        for plan in mutations:
            with self.assertRaises(acceptance.InputError):
                acceptance.validate_plan_registry(ROOT, plan)

    def test_product_closure_fixture_rejects_missing_extra_dirty_exec_and_symlink(self):
        content = b'benign product closure\n'
        oid = blob_oid(content)

        def root_with(mode='100644', body=content, extra=False, link=False):
            base = self.base / ('fixture-' + str(len(list(self.base.iterdir()))))
            base.mkdir()
            target = base / 'fakenet/item.py'
            target.parent.mkdir()
            if link:
                target.symlink_to(base / 'outside.py')
            else:
                target.write_bytes(body)
                target.chmod(0o755 if mode == '100755' else 0o644)
            if extra:
                (base / 'fakenet/extra.py').write_text('extra\n', encoding='utf-8')
            tree = {'fakenet/item.py': (mode, 'blob', oid)}
            if extra:
                tree['fakenet/extra.py'] = ('100644', 'blob', blob_oid(b'extra\n'))
            return base, tree

        base, tree = root_with()
        with mock.patch.object(source_identity, '_tree', return_value=tree):
            source_identity.prove(base, OLD_SOURCE, (), self.current)

        missing, tree = root_with()
        (missing / 'fakenet/item.py').unlink()
        with mock.patch.object(source_identity, '_tree', return_value=tree):
            with self.assertRaises(ValueError):
                source_identity.prove(missing, OLD_SOURCE, (), self.current)

        extra, tree = root_with(extra=True)
        # The fixture tree intentionally omits the extra file.
        tree.pop('fakenet/extra.py')
        with mock.patch.object(source_identity, '_tree', return_value=tree):
            with self.assertRaises(ValueError):
                source_identity.prove(extra, OLD_SOURCE, (), self.current)

        dirty, tree = root_with(body=b'changed product closure\n')
        with mock.patch.object(source_identity, '_tree', return_value=tree):
            with self.assertRaises(ValueError):
                source_identity.prove(dirty, OLD_SOURCE, (), self.current)

        executable, tree = root_with(mode='100644')
        (executable / 'fakenet/item.py').chmod(0o755)
        current_tree = dict(tree)
        current_tree['fakenet/item.py'] = ('100755', 'blob', oid)
        with mock.patch.object(source_identity, '_tree', side_effect=[tree, current_tree]):
            with self.assertRaises(ValueError):
                source_identity.prove(executable, OLD_SOURCE, (), self.current)

        linked, tree = root_with(link=True)
        with mock.patch.object(source_identity, '_tree', return_value=tree):
            with self.assertRaises(ValueError):
                source_identity.prove(linked, OLD_SOURCE, (), self.current)

    def test_unknown_commit_and_path_escape_are_rejected(self):
        with self.assertRaises(ValueError):
            source_identity.closure_paths(ROOT, 'f' * 40)
        with self.assertRaises(ValueError):
            source_identity.closure_paths(ROOT, OLD_SOURCE, ('../escape',))

    def test_explicit_opt_in_and_full_proof_fields_are_required(self):
        with self.assertRaises(ValueError):
            source_identity.candidate_enabled({'source_reuse': {
                'schema': source_identity.SCHEMA, 'paths': []}})
        plan = {'candidate': {}, 'source_commit': self.old, 'harness_commit': self.current,
                'source_reuse': {}, 'required_cases': []}
        self.assertFalse(source_identity.validate_plan(ROOT, plan, {}, []))

    def test_without_opt_in_old_candidate_remains_rejected(self):
        candidate = self.data(); candidate.pop('source_reuse')
        path = self.base / 'no-opt-in/candidate.json'
        path.parent.mkdir()
        path.write_text(json.dumps(candidate), encoding='utf-8')
        with self.assertRaises(acceptance.InputError):
            acceptance.make_plan_v2(
                ROOT, 'selected', path, self.environment,
                [], ['UPSTREAM-TCP-UDP'], self.base / 'no-opt-in/plan.json')
        self.assertFalse((self.base / 'no-opt-in/plan.json').exists())

    def test_wrong_opt_in_schema_is_rejected(self):
        candidate = self.data(); candidate['source_reuse'] = {'schema': 'wrong'}
        path = self.base / 'wrong/candidate.json'
        path.parent.mkdir()
        path.write_text(json.dumps(candidate), encoding='utf-8')
        with self.assertRaises((acceptance.InputError, ValueError)):
            acceptance.make_plan_v2(
                ROOT, 'selected', path, self.environment,
                [], ['UPSTREAM-TCP-UDP'], self.base / 'wrong/plan.json')

    def test_stored_harness_identity_must_equal_current_head(self):
        value = acceptance.make_plan_v2(
            ROOT, 'selected', self.candidate, self.environment,
            [], ['UPSTREAM-TCP-UDP'], self.base / 'verify/plan.json')
        plan = json.loads((self.base / 'verify/plan.json').read_text(encoding='utf-8'))
        plan['harness_commit'] = '0' * 40
        catalog = acceptance.read_catalog(ROOT)
        registered = {case['id']: case for case in acceptance.all_cases(catalog)}
        self.assertFalse(acceptance.source_plan_head_allowed(ROOT, plan, plan['candidate'], registered))

    def test_stored_proof_is_checked_as_a_complete_object(self):
        value = acceptance.make_plan_v2(
            ROOT, 'selected', self.candidate, self.environment,
            [], ['UPSTREAM-TCP-UDP'], self.base / 'proof/plan.json')
        plan = json.loads((self.base / 'proof/plan.json').read_text(encoding='utf-8'))
        plan['source_reuse']['closure'][0]['sha256'] = 'f' * 64
        catalog = acceptance.read_catalog(ROOT)
        registered = {case['id']: case for case in acceptance.all_cases(catalog)}
        self.assertFalse(acceptance.source_plan_head_allowed(ROOT, plan, plan['candidate'], registered))

    def test_native_product_pins_cannot_shrink_product_closure(self):
        base = self.base/'fixed-registry'; (base/'fakenet').mkdir(parents=True)
        body = b'original product\n'; path = base/'fakenet/fakenet.py'; path.write_bytes(body)
        tree = {'fakenet/fakenet.py': ('100644', 'blob', blob_oid(body))}
        with mock.patch.object(source_identity, '_tree', return_value=tree):
            proof = source_identity.prove(base, OLD_SOURCE, (), self.current)
            self.assertEqual(['fakenet/fakenet.py'], [r['path'] for r in proof['closure']])
            with self.assertRaisesRegex(ValueError, 'cannot alter'):
                source_identity.prove(base, OLD_SOURCE, (), self.current, {'fakenet/fakenet.py'})
            path.write_bytes(b'changed product\n')
            with self.assertRaisesRegex(ValueError, 'worktree differs'):
                source_identity.prove(base, OLD_SOURCE, (), self.current)

    def test_new_acceptance_named_product_is_not_implicitly_harness(self):
        base = self.base/'renamed'; (base/'test').mkdir(parents=True)
        name = 'test/test_acceptance_unregistered_product.py'
        (base/name).write_text('product runtime\n')
        with mock.patch.object(source_identity, '_tree', return_value={}):
            with self.assertRaisesRegex(ValueError, 'closure differs'):
                source_identity.prove(base, OLD_SOURCE, (), self.current)



if __name__ == '__main__':
    unittest.main()
