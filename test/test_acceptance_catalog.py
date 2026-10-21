"""The consolidated inventory must not invent acceptance credit."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('acceptance_catalog', ROOT / 'tools/acceptance.py')
acceptance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acceptance)


class JudgmentTests(unittest.TestCase):
    def test_missing_case_is_not_pass(self):
        value = acceptance.judge_rows([{'id': 'a', 'status': 'pass'}], ['a', 'b'])
        self.assertEqual(value['verdict'], 'unknown')
        self.assertEqual(value['missing'], ['b'])

    def test_failure_outside_required_selection_is_not_hidden(self):
        value = acceptance.judge_rows([{'id': 'a', 'status': 'pass'},
                                       {'id': 'b', 'status': 'fail'}], ['a'])
        self.assertEqual(value['verdict'], 'fail')

    def test_skip_observed_blocked_unknown_are_not_pass(self):
        for status in ('skip', 'observed', 'blocked', 'unknown', 'not_run'):
            with self.subTest(status=status):
                self.assertEqual(acceptance.judge_rows([{'id': 'a', 'status': status}], ['a'])['verdict'], 'unknown')

    def test_duplicate_is_not_pass(self):
        rows = [{'id': 'a', 'status': 'pass'}] * 2
        self.assertEqual(acceptance.judge_rows(rows, ['a'])['verdict'], 'unknown')

    def test_empty_plan_cannot_pass(self):
        with self.assertRaises(ValueError):
            acceptance.judge_rows([], [])

    def test_complete_plan_passes(self):
        self.assertEqual(acceptance.judge_rows([{'id': 'a', 'status': 'pass'}], ['a'])['verdict'], 'pass')

    def test_both_existing_tsv_orders_preserve_observed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'results.tsv'
            path.write_text('\ufeffPASS\ta\tok\nb\tOBSERVED\tnot judged\n', encoding='utf-8')
            rows = acceptance.parse_tsv(path)
            self.assertEqual(rows[1]['status'], 'observed')
            self.assertEqual(acceptance.judge_rows(rows, ['a', 'b'])['verdict'], 'unknown')

    def test_junit_skip_and_collection_error_are_not_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'results.xml'
            path.write_text('<testsuites><testsuite errors="1"><testcase classname="c" name="x"><skipped/></testcase></testsuite></testsuites>')
            rows = acceptance.parse_junit(path)
            self.assertEqual(acceptance.judge_rows(rows, ['c::x'])['verdict'], 'fail')

    def test_static_inventory_does_not_execute_driver(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'test.py'
            path.write_text("raise RuntimeError('must not execute')\nclass C:\n def test_a(self):\n  assert 1 == 1\n")
            items = acceptance.python_items(path, root)
            self.assertEqual(items[0]['id'], 'test.py::C::test_a')
            self.assertEqual(items[0]['assertions'], ['1 == 1'])

    def test_all_current_test_entries_are_classified(self):
        value = acceptance.inventory(ROOT)
        self.assertFalse(value['unclassified'])
        self.assertEqual(value['qualification'], 'not_run')

    def test_plan_keeps_candidate_unqualified_and_pending_groups(self):
        value = acceptance.make_plan(ROOT)
        self.assertEqual(value['candidate'], {})
        self.assertIn('GAP-MANUAL', value['required_suites'])
        self.assertIn('GAP-APPLICATION', value['required_suites'])
        self.assertNotIn('EGRESS-NEW-DEFERRED', value['required_suites'])
        self.assertFalse(value['required_checks'])


class SourceBoundReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'docs/acceptance').mkdir(parents=True)
        (self.root / 'driver.py').write_text('# original driver\n')
        suite = dict(id='one', content='a', procedure='b', judgment='c', limitations='d',
                     sources=['driver.py'], required_for_full=True,
                     evidence_level='native', oracle_status='ready')
        (self.root / 'docs/acceptance/catalog.json').write_text(json.dumps({
            'schema': 'fakenet.acceptance-catalog.v1', 'suites': [suite]}))
        self.raw = self.root / 'results.tsv'
        self.raw.write_text('PASS\ta\tok\n')
        self.plan = dict(schema='fakenet.acceptance-plan.v1', execution_id='run1',
                         candidate={'source': 'candidate'}, required_suites=['one'],
                         catalog_sha256=acceptance.sha256(self.root / 'docs/acceptance/catalog.json'),
                         source_hashes={'one': {'driver.py': acceptance.sha256(self.root / 'driver.py')}},
                         required_checks={'one': ['a']})
        self.result = dict(suite_id='one', execution_id='run1', candidate=self.plan['candidate'],
                           source_hashes=self.plan['source_hashes']['one'], evidence_level='native',
                           returncode=0, cleanup_complete=True,
                           artifacts=[dict(path=str(self.raw), sha256=acceptance.sha256(self.raw), format='tsv')])

    def judge(self):
        return acceptance.judge_session(self.plan, [self.result], self.root)

    def test_actual_original_pass(self):
        self.assertTrue(self.judge()['full_catalog_pass'])

    def test_raw_fail_overrides_forged_summary_and_zero_exit(self):
        self.raw.write_text('FAIL\ta\tfailure\n')
        self.result['artifacts'][0]['sha256'] = acceptance.sha256(self.raw)
        self.result['checks'] = [{'id': 'a', 'status': 'pass'}]
        self.result['verdict'] = 'pass'
        self.assertEqual(self.judge()['verdict'], 'fail')

    def test_other_candidate_cannot_reuse_receipt(self):
        self.result['candidate'] = {'source': 'other'}
        with self.assertRaisesRegex(ValueError, 'candidate mismatch'):
            self.judge()

    def test_changed_source_cannot_reuse_receipt(self):
        (self.root / 'driver.py').write_text('# changed\n')
        with self.assertRaisesRegex(ValueError, 'source changed'):
            self.judge()

    def test_changed_artifact_is_rejected(self):
        self.raw.write_text('PASS\tb\n')
        with self.assertRaisesRegex(ValueError, 'changed original'):
            self.judge()

    def test_cleanup_unknown_prevents_pass(self):
        self.result['cleanup_complete'] = None
        self.assertEqual(self.judge()['verdict'], 'unknown')

    def test_nonzero_process_exit_prevents_pass(self):
        self.result['returncode'] = 1
        self.assertEqual(self.judge()['verdict'], 'fail')

    def test_incomplete_oracle_cannot_get_full_credit(self):
        path = self.root / 'docs/acceptance/catalog.json'
        value = json.loads(path.read_text())
        value['suites'][0]['oracle_status'] = 'incomplete'
        path.write_text(json.dumps(value))
        self.plan['catalog_sha256'] = acceptance.sha256(path)
        self.assertFalse(self.judge()['full_catalog_pass'])

    def test_native_entry_is_not_launched_on_linux_host(self):
        if acceptance.sys.platform == 'win32':
            self.skipTest('Linux host boundary')
        path = self.root / 'docs/acceptance/catalog.json'
        value = json.loads(path.read_text())
        value['suites'][0]['launch'] = {'platform': 'windows', 'argv': ['must-not-start']}
        path.write_text(json.dumps(value))
        with mock.patch.object(acceptance.subprocess, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'Windows VM'):
                acceptance.launch('one', [], self.root / 'Logs' / 'run', self.root)
            run.assert_not_called()

    def test_unregistered_driver_is_not_launched(self):
        with mock.patch.object(acceptance.subprocess, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'no automated entry'):
                acceptance.launch('other', [], self.root / 'Logs' / 'run', self.root)
            run.assert_not_called()

    def test_benign_original_execution_stays_unjudged(self):
        path = self.root / 'docs/acceptance/catalog.json'
        value = json.loads(path.read_text())
        value['suites'][0]['launch'] = {'platform': 'host-controller', 'argv': ['{python}', 'driver.py']}
        path.write_text(json.dumps(value))
        result = acceptance.launch('one', [], self.root / 'Logs' / 'run', self.root)
        self.assertEqual(result['returncode'], 0)
        self.assertEqual(result['qualification'], 'unjudged')
        self.assertIsNone(result['cleanup_complete'])

    def test_existing_execution_directory_is_not_overwritten(self):
        path = self.root / 'docs/acceptance/catalog.json'
        value = json.loads(path.read_text())
        value['suites'][0]['launch'] = {'platform': 'host-controller', 'argv': ['{python}', 'driver.py']}
        path.write_text(json.dumps(value))
        output = self.root / 'Logs' / 'run'
        output.mkdir(parents=True)
        with mock.patch.object(acceptance.subprocess, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'new exact directory'):
                acceptance.launch('one', [], output, self.root)
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
