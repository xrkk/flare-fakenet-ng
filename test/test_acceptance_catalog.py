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

    def test_catalog_v2_defines_unique_cases_without_cycles(self):
        catalog = acceptance.read_catalog(ROOT)
        self.assertEqual('fakenet.acceptance-catalog.v2', catalog['schema'])
        self.assertEqual(25, len(catalog['suites']))
        cases = acceptance.all_cases(catalog)
        self.assertTrue(cases)
        self.assertEqual(len(cases), len({row['id'] for row in cases}))
        self.assertTrue(catalog['exclusions'])
        by_suite = {row['id']: row for row in catalog['suites']}
        self.assertTrue(by_suite['GUI-POLICY']['cases'])
        self.assertEqual([], by_suite['MCP-RELEASE']['cases'])
        self.assertEqual([], by_suite['MCP-SCENARIOS']['cases'])
        self.assertEqual([], by_suite['EGRESS-NEW-DEFERRED']['cases'])


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


class DeferredInterfaceInputTests(unittest.TestCase):
    def test_current_required_mcp_inputs_keep_shared_product_and_transport_only(self):
        catalog = acceptance.read_catalog(ROOT)
        cases = {case['id']: case for case in acceptance.all_cases(catalog)}
        self.assertEqual(
            ['test/mcp/test_command_status.py', 'test/mcp/test_capture_health.py'],
            cases['MCP-UNIT-PRODUCT']['input']['modules'])
        self.assertEqual(
            ['test/mcp/test_acceptance_evidence_writer.py', 'test/mcp/test_bounded_mcp.py'],
            cases['MCP-UNIT-TOOLING']['input']['modules'])
        for name in ('CORE-WINDOWS-OFFLINE', 'MCP-UNIT-PRODUCT', 'MCP-UNIT-TOOLING'):
            self.assertFalse(cases[name]['collection_safe'])
            self.assertTrue(cases[name]['required_for_full'])
        excluded_sources = {source for item in catalog['exclusions']
                            for source in item.get('sources', [])}
        self.assertIn('test/mcp/test_host_stdio.py', excluded_sources)
        self.assertIn('test/mcp/test_acceptance_runner_discrimination.py', excluded_sources)


class ContainedCollectionTests(unittest.TestCase):
    def setUp(self):
        import copy
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.case = copy.deepcopy(next(case for case in acceptance.all_cases(
            acceptance.read_catalog(ROOT)) if case['id'] == 'MCP-UNIT-PRODUCT'))
        self.files = list(self.case['input']['modules']) + ['tools/acceptance.py', 'docs/acceptance/catalog.json']
        for name in self.files:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('# inert source identity fixture\n')
        self.python = Path(acceptance.sys.executable)
        dependency = self.root / 'dependency'
        dependency.write_text('fixed dependency bytes')
        self.env = {'targets': ['host-linux'], 'work_root': '/out',
                    'interpreters': {'python': str(self.python)},
                    'collection_profile': {'kind': 'linux-contained-v1',
                                           'attestation': '/run-control/attestation.json',
                                           'sha256': 'a' * 64}}
        self.witness = {'schema': 'fakenet.contained-collection.v1',
            'image': acceptance.CONTAINED_IMAGE, 'container_id': '1' * 64,
            'source_root': str(self.root), 'work_root': '/out',
            'source_commit': 'b' * 40,
            'source_hashes': {name: acceptance.sha256(self.root / name) for name in self.files},
            'interpreters': {'linux-contained-v1': {'path': str(self.python),
                'sha256': acceptance.sha256(self.python),
                'dependencies': {str(dependency): acceptance.sha256(dependency)}}}}
        self.kernel = mock.patch.object(acceptance, '_contained_kernel', return_value='1' * 12)
        self.reader = mock.patch.object(acceptance, '_read_containment_witness', return_value=self.witness)
        self.kernel.start(); self.addCleanup(self.kernel.stop)
        self.reader.start(); self.addCleanup(self.reader.stop)

    def test_finite_profile_binds_source_and_actual_interpreter(self):
        observed = acceptance.contained_collection_context(self.case, self.root, self.env)
        self.assertEqual('1' * 64, observed['container_id'])
        self.assertFalse(self.case['collection_safe'])
        self.assertTrue(acceptance.collection_authorized(self.case, self.root, self.env))

    def test_supplied_marker_does_not_override_kernel_refusal(self):
        with mock.patch.object(acceptance, '_contained_kernel', side_effect=ValueError('external network')):
            self.assertFalse(acceptance.collection_authorized(self.case, self.root, self.env))

    def test_source_and_interpreter_and_dependency_drift_refuse(self):
        for path in (self.root / self.files[0], self.root / 'dependency'):
            before = path.read_bytes()
            path.write_bytes(before + b'changed')
            self.assertFalse(acceptance.collection_authorized(self.case, self.root, self.env))
            path.write_bytes(before)
        self.witness['interpreters']['linux-contained-v1']['sha256'] = '0' * 64
        self.assertFalse(acceptance.collection_authorized(self.case, self.root, self.env))

    def test_module_profile_platform_and_instance_substitution_refuse(self):
        import copy
        for field, value in [('id', 'other-case'), ('input', {'modules': ['test/extra.py']}),
                             ('collection_profile', 'wine-contained-v1')]:
            case = copy.deepcopy(self.case); case[field] = value
            self.assertFalse(acceptance.collection_authorized(case, self.root, self.env))
        env = copy.deepcopy(self.env); env['targets'] = ['host-windows']
        self.assertFalse(acceptance.collection_authorized(self.case, self.root, env))
        self.witness['container_id'] = '2' * 64
        self.assertFalse(acceptance.collection_authorized(self.case, self.root, self.env))

    def test_default_missing_profile_cannot_start_collection(self):
        self.env.pop('collection_profile')
        with mock.patch.object(acceptance.subprocess, 'run') as run:
            reason = acceptance.expected_block(self.case, ['collection', 'offline-pytest'],
                                               {'linux'}, self.root, self.env)
            self.assertIn('not authorised', reason)
            run.assert_not_called()

    def test_attestation_path_is_not_an_arbitrary_approval_file(self):
        self.reader.stop()
        self.env['collection_profile']['attestation'] = str(self.root / 'approval.json')
        self.assertFalse(acceptance.collection_authorized(self.case, self.root, self.env))
