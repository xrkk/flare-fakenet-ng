"""Benign package bytes, original builder verification and unchanged catalog CLI."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
import warnings
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import acceptance as entry
import acceptance_package as package


def make_candidate(root, mutation=None):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    body = b'benign identity fixture; never executed'
    sha = hashlib.sha256(body).hexdigest()
    manifest = {'schema': 'fakenet.mcp-candidate-manifest.v1',
                'source_commit': entry.git_head(ROOT), 'source_snapshot_mode': 'commit',
                'exe_sha256': sha, 'qualification_status': 'PARTIAL',
                'native_gaps': ['benign fixture has no native qualification'],
                'zip_entry_timestamp_utc': '2000-01-01T00:00:00Z',
                'files': [{'path': 'fakenetng-mcp.exe', 'size': len(body), 'sha256': sha}]}
    if mutation == 'source':
        manifest['source_commit'] = 'a' * 40
    if mutation == 'missing-field':
        del manifest['native_gaps']
    if mutation == 'unsupported-format':
        manifest['schema'] = 'other.package.v1'
    raw = json.dumps(manifest).encode()
    if mutation == 'duplicate-json':
        raw = raw[:-1] + b',"source_commit":"' + manifest['source_commit'].encode() + b'"}'
    manifest_path = root / 'manifest.json'
    manifest_path.write_bytes(raw)
    archive_path = root / 'candidate.zip'
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', UserWarning)
        with zipfile.ZipFile(archive_path, 'x') as archive:
            items = [('fakenetng-mcp.exe', body), ('mcp-candidate-manifest.json', raw)]
            if mutation == 'member-content':
                items[0] = ('fakenetng-mcp.exe', b'wrong member body')
            if mutation == 'duplicate-member':
                items.append(items[0])
            if mutation == 'case-alias':
                items.append(('FAKENETNG-MCP.EXE', body))
            if mutation == 'escape':
                items.append(('../outside', body))
            if mutation == 'backslash':
                items.append(('dir\\ambiguous', body))
            if mutation == 'path-conflict':
                items.extend([('file', body), ('file/child', body)])
            for name, data in items:
                info = zipfile.ZipInfo(name, (2024, 1, 1, 0, 0, 0) if mutation == 'timestamp' else (2000, 1, 1, 0, 0, 0))
                info.external_attr = (0o100644 << 16)
                archive.writestr(info, data)
    return {'schema': entry.CANDIDATE_V2, 'source_commit': entry.git_head(ROOT),
            'package_path': str(archive_path), 'package_manifest': str(manifest_path),
            'package_sha256': package.sha256(archive_path), 'offline_fixture': True}


class PackageOriginalTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix='package-original-'))

    def test_actual_builder_preserves_partial_qualification(self):
        candidate = package.freeze_candidate(make_candidate(self.base / 'positive'))
        result = package.verify(ROOT, candidate)
        self.assertEqual('PASS', result['verification']['verdict'])
        self.assertEqual('PARTIAL', result['qualification_status'])
        self.assertEqual(['benign fixture has no native qualification'], result['native_gaps'])
        self.assertFalse(result['native_functionality_evaluated'])
        self.assertFalse(result['reproducible_build_evaluated'])
        for changed in ('package', 'manifest'):
            with self.subTest(changed=changed):
                local = package.freeze_candidate(make_candidate(self.base / changed))
                path = Path(local['package_path'] if changed == 'package' else local['package_manifest'])
                path.write_bytes(path.read_bytes() + b' ')
                with self.assertRaisesRegex(ValueError, 'frozen'):
                    package.verify(ROOT, local)

    def test_exact_bad_member_paths_content_and_original_timestamp(self):
        expected = {'duplicate-member': 'duplicate', 'case-alias': 'duplicate',
                    'escape': 'escaping', 'backslash': 'path', 'path-conflict': 'conflict',
                    'timestamp': 'timestamp drift', 'member-content': 'hash/size mismatch',
                    'source': 'source differs', 'duplicate-json': 'duplicate JSON',
                    'missing-field': 'fields missing', 'unsupported-format': 'unsupported package'}
        for mutation, reason in expected.items():
            with self.subTest(mutation=mutation):
                candidate = make_candidate(self.base / mutation, mutation)
                # Outer package SHA is already correct for the bad bytes;
                # only content/structure/frozen identity can reject them.
                with self.assertRaisesRegex((ValueError, RuntimeError), reason):
                    package.verify(ROOT, package.freeze_candidate(candidate))


class PackagePublicCliTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix='package-public-'))
        self.candidate = make_candidate(self.base / 'candidate')
        self.candidate_path = self.base / 'candidate.json'
        self.candidate_path.write_text(json.dumps(self.candidate))
        self.environment = {'schema': entry.ENVIRONMENT_V2, 'targets': ['linux'],
                            'interpreters': {'python': sys.executable},
                            'work_root': str(self.base), 'allowed_actions': ['offline-artifacts'],
                            'endpoints': [], 'auth_refs': []}
        self.environment_path = self.base / 'environment.json'
        self.environment_path.write_text(json.dumps(self.environment))
        self.run = self.base / 'run'

    def cli(self, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = entry.main(['--root', str(ROOT), *map(str, args)])
        return code, stdout.getvalue(), stderr.getvalue()

    def plan(self):
        result = self.cli('plan', '--mode', 'selected', '--case', package.CASE,
                          '--candidate', self.candidate_path, '--environment', self.environment_path,
                          '--output', self.run / 'plan.json')
        self.assertEqual(0, result[0], result)
        return json.loads((self.run / 'plan.json').read_text())

    def test_same_catalog_offline_channel_and_rehashed_bad_result(self):
        original_catalog = package.sha256(ROOT / 'docs/acceptance/catalog.json')
        plan = self.plan()
        self.assertEqual({}, plan['blocked'])
        self.assertEqual(package.sha256(self.candidate['package_manifest']), plan['candidate']['package_manifest_sha256'])
        result = self.cli('execute', '--plan', self.run / 'plan.json')
        self.assertEqual(0, result[0], result)
        result = self.cli('judge', '--plan', self.run / 'plan.json', '--results', self.run / 'results',
                          '--output', self.run / 'independent.json')
        self.assertEqual(0, result[0], result)
        summary = json.loads((self.run / 'independent.json').read_text())
        self.assertTrue(summary['fixture_contract_pass'])
        self.assertFalse(summary['full_functional_pass'])
        self.assertEqual(original_catalog, package.sha256(ROOT / 'docs/acceptance/catalog.json'))
        case_dir = self.run / 'results' / package.CASE
        import copy
        baseline_receipt = json.loads((case_dir / 'receipt.json').read_text())
        for mutation in ('returncode', 'cleanup'):
            with self.subTest(mutation=mutation):
                bad = copy.deepcopy(baseline_receipt)
                bad[mutation] = 1 if mutation == 'returncode' else {'source': 'self-declared'}
                verdict = package.judge(ROOT, plan['cases'][package.CASE], bad, plan)
                self.assertEqual('fail', verdict['status'])
                self.assertIn('exit/resource declaration', verdict['reason'])
        evidence = case_dir / 'package-result.json'
        result = json.loads(evidence.read_text())
        result['facts']['source_commit'] = 'a' * 40
        evidence.write_text(json.dumps(result))
        receipt_path = case_dir / 'receipt.json'
        receipt = json.loads(receipt_path.read_text())
        for item in receipt['artifacts']:
            item['sha256'] = package.sha256(item['path'])
        receipt_path.write_text(json.dumps(receipt))
        index_path = self.run / 'results/results.json'
        index = json.loads(index_path.read_text())
        for item in index['receipts']:
            if item['case_id'] == package.CASE:
                item['sha256'] = package.sha256(receipt_path)
        index_path.write_text(json.dumps(index))
        result = self.cli('judge', '--plan', self.run / 'plan.json', '--results', self.run / 'results',
                          '--output', self.run / 'negative.json')
        self.assertNotEqual(0, result[0], result)
        self.assertIn('original rejudgment', (self.run / 'negative.json').read_text())

    def test_unsupported_input_is_only_a_blocked_package_case(self):
        Path(self.candidate['package_manifest']).write_text('{"schema":"other"}')
        plan = self.plan()
        self.assertIn('package identity input unavailable', plan['blocked'][package.CASE])
        self.assertFalse((self.run / 'results').exists())
        self.assertNotIn('native_runtime', plan['environment'])


class ArtifactSourceLayerTests(PackagePublicCliTests):
    # Reuse helpers, without rerunning inherited test methods here.
    test_same_catalog_offline_channel_and_rehashed_bad_result = None

    def old_candidate(self, directory):
        value = make_candidate(directory, 'source')
        value['source_commit'] = 'a' * 40
        return value

    def select_old(self):
        self.candidate = self.old_candidate(self.base / 'old-candidate')
        self.candidate_path = self.base / 'old-candidate.json'
        self.candidate_path.write_text(json.dumps(self.candidate))
        return self.candidate

    def test_old_original_package_current_verifier_same_cli_and_no_qualification_upgrade(self):
        candidate = self.select_old()
        frozen = {key: Path(candidate[key]).read_bytes() for key in ('package_path', 'package_manifest')}
        input_bytes = self.candidate_path.read_bytes()
        plan = self.plan()
        self.assertEqual('a' * 40, plan['source_commit'])
        self.assertEqual('a' * 40, plan['candidate']['source_commit'])
        self.assertEqual(plan['schema'], entry.PLAN_V2)
        self.assertEqual(package.sha256(ROOT / 'tools/acceptance_package.py'), plan['native_source_hashes']['tools/acceptance_package.py'])
        result = self.cli('execute', '--plan', self.run / 'plan.json')
        self.assertEqual(0, result[0], result)
        result = self.cli('judge', '--plan', self.run / 'plan.json', '--results', self.run / 'results', '--output', self.run / 'independent.json')
        self.assertEqual(0, result[0], result)
        summary = json.loads((self.run / 'independent.json').read_text())
        self.assertTrue(summary['fixture_contract_pass']); self.assertFalse(summary['full_functional_pass'])
        facts = json.loads((self.run / 'results' / package.CASE / 'package-result.json').read_text())['facts']
        self.assertEqual('a' * 40, facts['source_commit']); self.assertEqual('PARTIAL', facts['qualification_status'])
        self.assertEqual(['benign fixture has no native qualification'], facts['native_gaps'])
        self.assertFalse(facts['native_functionality_evaluated']); self.assertFalse(facts['reproducible_build_evaluated'])
        for key, original in frozen.items(): self.assertEqual(original, Path(candidate[key]).read_bytes())
        self.assertEqual(input_bytes, self.candidate_path.read_bytes())

    def prepare_old_mcp_package_inputs(self):
        # Canonical benign schema; only package references/identity change to
        # this exact old candidate. No HTTP/VM/native operation is performed.
        from test_acceptance_mcp import inputs_at
        value = inputs_at(self.base / 'mcp-input')
        value.update(package=self.candidate['package_path'],
                     manifest=self.candidate['package_manifest'],
                     manifest_sha256=package.sha256(self.candidate['package_manifest']))
        value['identity'].update(source_commit=self.candidate['source_commit'],
                                 package_sha256=self.candidate['package_sha256'])
        self.environment.update(targets=['windows'], mcp=value,
            native_runtime={'transport': 'windows-mcp-velo', 'identity': dict(value['target']),
                            **value['channel']})
        self.environment_path.write_text(json.dumps(self.environment))
        return value

    def test_pure_mcp_old_package_keeps_source_pins_and_partial_qualification(self):
        self.select_old()
        inputs = self.prepare_old_mcp_package_inputs()
        import acceptance_mcp
        acceptance_mcp.validate_inputs(inputs, 'MCP-P03-FULL', fixture=True)
        manifest_before = Path(inputs['manifest']).read_bytes()
        output = self.base / 'pure-mcp' / 'plan.json'
        result = self.cli('plan', '--mode', 'selected', '--case', 'MCP-P03-FULL',
                          '--candidate', self.candidate_path, '--environment', self.environment_path,
                          '--output', output)
        self.assertEqual(0, result[0], result)
        plan = json.loads(output.read_text())
        self.assertEqual('a' * 40, plan['source_commit'])
        self.assertEqual('a' * 40, plan['candidate']['source_commit'])
        self.assertEqual(package.sha256(ROOT / 'tools/acceptance_mcp.py'),
                         plan['native_source_hashes']['tools/acceptance_mcp.py'])
        manifest = json.loads(manifest_before)
        self.assertEqual('PARTIAL', manifest['qualification_status'])
        self.assertEqual(['benign fixture has no native qualification'], manifest['native_gaps'])
        self.assertEqual(manifest_before, Path(inputs['manifest']).read_bytes())
        self.assertIn('MCP-P03-FULL', plan['blocked'])
        self.assertNotIn('native', self.environment['allowed_actions'])
        self.assertFalse((output.parent / 'results').exists())
        for kind,reason in [('package','bytes mismatch'), ('target','target differs')]:
            with self.subTest(kind=kind):
                changed = json.loads(json.dumps(self.environment))
                if kind == 'package':changed['mcp']['identity']['package_sha256'] = 'c' * 64
                else:changed['native_runtime']['identity']['hostname'] = 'foreign-target'
                self.environment_path.write_text(json.dumps(changed))
                bad = self.base / ('bad-' + kind) / 'plan.json'
                rejected = self.cli('plan', '--mode', 'selected', '--case', 'MCP-P03-FULL',
                                    '--candidate', self.candidate_path, '--environment', self.environment_path,
                                    '--output', bad)
                self.assertNotEqual(0, rejected[0], rejected)
                self.assertIn(reason, rejected[2])
                self.assertFalse(bad.exists())
        self.environment_path.write_text(json.dumps(self.environment))

    def test_runtime_source_and_mixed_selection_do_not_inherit_artifact_exception(self):
        self.select_old()
        for cases in (['CORE-REGRESSION-SELFTEST'],
                      [package.CASE, 'CORE-REGRESSION-SELFTEST'],
                      ['MCP-P03-FULL', 'CORE-REGRESSION-SELFTEST']):
            with self.subTest(cases=cases):
                output = self.base / ('mixed' if len(cases) > 1 else cases[0]) / 'plan.json'
                args = ['plan', '--mode', 'selected']
                for case in cases: args += ['--case', case]
                result = self.cli(*args, '--candidate', self.candidate_path, '--environment', self.environment_path, '--output', output)
                self.assertNotEqual(0, result[0], result)
                self.assertIn('does not match current HEAD', result[2])
                self.assertFalse(output.exists())

    def test_new_artifact_plan_never_rewrites_existing_current_source_plan(self):
        previous = self.plan()
        old_plan_path = self.run / 'plan.json'; old_bytes = old_plan_path.read_bytes()
        old_input_path = self.candidate_path; old_input = old_input_path.read_bytes()
        self.select_old(); self.run = self.base / 'next-artifact-run'; current = self.plan()
        self.assertNotEqual(previous['execution_id'], current['execution_id'])
        self.assertEqual(old_bytes, old_plan_path.read_bytes()); self.assertEqual(old_input, old_input_path.read_bytes())

    def test_relabeling_source_or_forging_verifier_pins_is_rejected_before_execute(self):
        self.select_old(); original = self.plan(); path = self.run / 'plan.json'
        import copy
        for mode in ('relabel', 'pins', 'missing-source'):
            with self.subTest(mode=mode):
                plan = copy.deepcopy(original)
                if mode == 'relabel':
                    plan['candidate']['source_commit'] = entry.git_head(ROOT); plan['source_commit'] = entry.git_head(ROOT)
                elif mode == 'pins':
                    plan['native_source_hashes']['tools/acceptance_package.py'] = 'f' * 64
                else:
                    del plan['source_hashes'][package.CASE]['tools/build_fakenetng_mcp_wine.py']
                path.write_text(json.dumps(plan))
                result = self.cli('execute', '--plan', path)
                self.assertNotEqual(0, result[0], result)
                self.assertFalse((self.run / 'results/results.json').exists())
        path.write_text(json.dumps(original))

    def test_full_and_stress_do_not_inherit_artifact_exception(self):
        self.select_old()
        for mode in ('full', 'stress'):
            with self.subTest(mode=mode):
                output = self.base / mode / 'plan.json'
                result = self.cli('plan', '--mode', mode, '--candidate', self.candidate_path,
                                  '--environment', self.environment_path, '--output', output)
                self.assertEqual(2, result[0], result)
                self.assertIn('does not match current HEAD', result[2])
                self.assertFalse(output.exists())

    def test_old_package_drift_stays_failed_under_current_verifier(self):
        for changed in ('package_path', 'package_manifest'):
            with self.subTest(changed=changed):
                self.candidate = self.old_candidate(self.base / changed)
                self.candidate_path = self.base / (changed + '.json')
                self.candidate_path.write_text(json.dumps(self.candidate))
                self.run = self.base / ('run-' + changed)
                self.plan()
                path = Path(self.candidate[changed])
                path.write_bytes(path.read_bytes() + b' ')
                result = self.cli('execute', '--plan', self.run / 'plan.json')
                self.assertNotEqual(0, result[0], result)
                if changed == 'package_manifest':
                    self.assertIn('blocked state differs from registry', result[2])
                    self.assertFalse((self.run / 'results').exists())
                else:
                    summary = json.loads((self.run / 'summary.json').read_text())
                    self.assertEqual('fail', summary['verdict'])
                    evidence = json.loads((self.run / 'results' / package.CASE / 'package-result.json').read_text())
                    self.assertIn('package bytes differ from frozen', evidence['reason'])
