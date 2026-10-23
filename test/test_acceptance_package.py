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
