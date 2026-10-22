"""Offline tests for the registered native adapter framework and oracles."""
import contextlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'test'))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ACC = load('acceptance_native_test_entry', ROOT / 'tools' / 'acceptance.py')
NATIVE = load('acceptance_native_test_module', ROOT / 'tools' / 'acceptance_native.py')
FIXTURE = load('acceptance_regression_fixture', ROOT / 'test' / 'test_acceptance_regression.py')
ACC.acceptance_native = NATIVE

FIXTURE_DRIVER = '''import argparse, json
parser = argparse.ArgumentParser()
parser.add_argument('--output')
parser.add_argument('--fail', action='store_true')
args = parser.parse_args()
rows = [{'id': 'alpha', 'status': 'fail' if args.fail else 'pass'},
        {'id': 'beta', 'status': 'pass'}]
with open(args.output + '/native.json', 'w', encoding='utf-8') as stream:
    json.dump({'checks': rows}, stream)
'''


def make_root(temp):
    root = Path(temp)
    FIXTURE.make_root(root)
    (root / 'test' / 'fixture_native_driver.py').write_text(FIXTURE_DRIVER, encoding='utf-8')
    catalog_path = root / 'docs' / 'acceptance' / 'catalog.json'
    catalog = json.loads(catalog_path.read_text(encoding='utf-8'))
    for suite in catalog['suites']:
        if suite['id'] == 'FIX-NATIVE':
            case = suite['cases'][0]
            case['adapter'] = 'native'
            case['native_driver'] = 'fixture-native'
            case['oracle'] = {'kind': 'native-json'}
            case['blocked_reason'] = 'fixture native driver'
    catalog_path.write_text(json.dumps(catalog, ensure_ascii=False, indent=2), encoding='utf-8')
    environment_path = root / 'environment.json'
    environment = json.loads(environment_path.read_text(encoding='utf-8'))
    environment['allowed_actions'] = ['offline-pytest', 'collection', 'native']
    environment_path.write_text(json.dumps(environment), encoding='utf-8')
    return root


def fixture_driver(implemented=True, missing=None):
    return {
        'implemented': implemented,
        'platforms': ['any'], 'modes': ['offline'],
        'argv': ['{python}', 'test/fixture_native_driver.py', '--output', '{output}'],
        'oracle': {'kind': 'native-json', 'artifact': 'native.json'},
        'checks': ['alpha', 'beta'],
        'requires': ['native'], 'package_required': False,
        'cleanup': 'fixture only', 'readiness': ['fixture'],
        'missing': missing,
    }


class NativeAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = make_root(self.temp.name)
        self.original = NATIVE.driver_table
        self.addCleanup(setattr, NATIVE, 'driver_table', self.original)

    def install(self, implemented=True, missing=None):
        def table(root):
            return {'fixture-native': fixture_driver(implemented, missing)}
        NATIVE.driver_table = table

    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = ACC.main(['--root', str(self.root)] + [str(item) for item in args])
            except SystemExit as exc:
                code = exc.code if isinstance(exc.code, int) else 2
        return code, out.getvalue(), err.getvalue()

    def plan(self, mode, *extra):
        output = self.root / 'Logs' / ('native-' + mode) / 'plan.json'
        code, out, err = self.run_cli(
            'plan', '--mode', mode,
            '--candidate', self.root / 'candidate.json',
            '--environment', self.root / 'environment.json',
            '--output', output, *extra)
        return code, output, err

    def test_native_plan_execute_judge_pass(self):
        self.install()
        code, path, err = self.plan('selected', '--case', 'FIX-BLOCKED')
        self.assertEqual(0, code, err)
        plan = json.loads(path.read_text(encoding='utf-8'))
        self.assertEqual(['alpha', 'beta'], plan['required_checks']['FIX-BLOCKED'])
        code, out, err = self.run_cli('execute', '--plan', path)
        self.assertEqual(0, code, err + out)
        summary = json.loads((path.parent / 'summary.json').read_text(encoding='utf-8'))
        self.assertEqual('pass', summary['verdict'])
        receipt = json.loads((path.parent / 'results' / 'FIX-BLOCKED' / 'receipt.json').read_text(encoding='utf-8'))
        self.assertEqual('native', receipt['adapter'])
        self.assertEqual(['alpha', 'beta'], receipt['required_checks'])

    def test_full_native_plus_offline_can_pass_as_fixture(self):
        self.install()
        code, path, err = self.plan('full')
        self.assertEqual(0, code, err)
        code, out, err = self.run_cli('execute', '--plan', path)
        self.assertEqual(0, code, err + out)
        summary = json.loads((path.parent / 'summary.json').read_text(encoding='utf-8'))
        self.assertTrue(summary['full_functional_pass'])

    def test_missing_native_check_is_unknown(self):
        self.install()
        code, path, err = self.plan('selected', '--case', 'FIX-BLOCKED')
        self.assertEqual(0, code, err)
        code, out, err = self.run_cli('execute', '--plan', path)
        self.assertEqual(0, code, err + out)
        oracle = path.parent / 'results' / 'FIX-BLOCKED' / 'native.json'
        oracle.write_text(json.dumps({'checks': [{'id': 'alpha', 'status': 'pass'}]}),
                          encoding='utf-8')
        receipt_path = path.parent / 'results' / 'FIX-BLOCKED' / 'receipt.json'
        receipt = json.loads(receipt_path.read_text(encoding='utf-8'))
        for artifact in receipt['artifacts']:
            if artifact['format'] == 'json':
                artifact['sha256'] = ACC.sha256(oracle)
        receipt_path.write_text(json.dumps(receipt), encoding='utf-8')
        index_path = path.parent / 'results' / 'results.json'
        index = json.loads(index_path.read_text(encoding='utf-8'))
        for entry in index['receipts']:
            if entry['case_id'] == 'FIX-BLOCKED':
                entry['sha256'] = ACC.sha256(receipt_path)
        index_path.write_text(json.dumps(index), encoding='utf-8')
        code, out, err = self.run_cli('judge', '--plan', path,
                                      '--results', path.parent / 'results',
                                      '--output', path.parent / 'summary2.json')
        self.assertEqual(2, code)
        self.assertEqual('unknown', json.loads(
            (path.parent / 'summary2.json').read_text(encoding='utf-8'))['verdict'])

    def test_unimplemented_driver_is_blocked(self):
        self.install(implemented=False, missing='fixture driver not implemented')
        code, path, err = self.plan('selected', '--case', 'FIX-BLOCKED')
        self.assertEqual(0, code, err)
        plan = json.loads(path.read_text(encoding='utf-8'))
        self.assertIn('FIX-BLOCKED', plan['blocked'])
        self.assertEqual([], plan['required_checks']['FIX-BLOCKED'])

    def test_unknown_driver_is_rejected(self):
        self.install()
        catalog_path = self.root / 'docs' / 'acceptance' / 'catalog.json'
        catalog = json.loads(catalog_path.read_text(encoding='utf-8'))
        for suite in catalog['suites']:
            if suite['id'] == 'FIX-NATIVE':
                suite['cases'][0]['native_driver'] = 'missing-driver'
        catalog_path.write_text(json.dumps(catalog), encoding='utf-8')
        code, path, err = self.plan('selected', '--case', 'FIX-BLOCKED')
        self.assertEqual(2, code)
        self.assertIn('unknown native driver', err)

    def test_fixed_argv_rejects_shell_metacharacters(self):
        with self.assertRaisesRegex(ValueError, 'metacharacter'):
            NATIVE.fixed_argv({'argv': ['run; rm -rf /']}, {})


if __name__ == '__main__':
    unittest.main()
