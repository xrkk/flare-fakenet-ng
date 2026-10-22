"""End-to-end offline tests for the v2 acceptance plan/execute/judge loop.

Every case uses the real CLI entry (``acceptance.main``) against a temporary
fixture root.  The tests never start FakeNet, a VM, a network listener or a
product driver.  Negative cases mutate real raw artifacts and require the
judge to recompute a non-pass verdict instead of trusting a summary.
"""
import contextlib
import importlib.util
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('acceptance_regression', ROOT / 'tools/acceptance.py')
ACC = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ACC)

FIXTURE_MODULE = '''import unittest

class FixtureTests(unittest.TestCase):
    def test_alpha(self):
        self.assertTrue(True)

    def test_beta(self):
        self.assertEqual(2 + 2, 4)
'''

FAILING_MODULE = '''import unittest

class FailingTests(unittest.TestCase):
    def test_broken(self):
        self.assertEqual(1, 2)
'''


def suite_record(suite_id, title, module):
    return {
        'id': suite_id,
        'title': title,
        'content': 'fixture suite',
        'procedure': 'run the fixture module',
        'judgment': 'all planned nodes pass',
        'limitations': 'fixture only',
        'sources': [module],
        'prerequisites': 'offline python',
        'outputs': 'junit',
        'evidence_level': 'offline',
        'required_for_full': True,
        'oracle_status': 'existing',
        'command': None,
    }


def case_record(case_id, suite_id, module, adapter='offline-pytest', safe=True,
                stress=False, required_for_full=True):
    value = {
        'id': case_id,
        'suite_id': suite_id,
        'title': case_id,
        'platforms': ['any'],
        'modes': ['offline'],
        'input': {'module': module},
        'steps': ['collect', 'run', 'judge'],
        'expected': {'positive': 'nodes pass', 'negative': 'non-pass is not pass'},
        'oracle': {'kind': 'junit'},
        'resources': ['offline-python'],
        'readiness': ['interpreter'],
        'timeout': 120,
        'cleanup': 'temp files only',
        'dependencies': [],
        'adapter': adapter,
        'collection_safe': safe,
        'required_for_full': required_for_full,
        'stress': stress,
        'sources': [module],
    }
    if adapter != 'offline-pytest':
        value['blocked_reason'] = 'native adapter not implemented'
    return value


def make_root(temp, failing=False):
    root = Path(temp)
    (root / 'docs' / 'acceptance').mkdir(parents=True)
    (root / 'test').mkdir()
    (root / 'test' / '__init__.py').write_text('', encoding='utf-8')
    module = 'test/test_fixture_failing.py' if failing else 'test/test_fixture_module.py'
    (root / module).write_text(FAILING_MODULE if failing else FIXTURE_MODULE,
                               encoding='utf-8')
    catalog = {
        'schema': 'fakenet.acceptance-catalog.v2',
        'scope': 'fixture',
        'exclusions': [],
        'suites': [
            dict(suite_record('FIX-OFFLINE', 'fixture offline', module),
                 disposition='keep',
                 cases=[case_record('FIX-PASS', 'FIX-OFFLINE', module),
                        case_record('FIX-STRESS', 'FIX-OFFLINE', module,
                                    stress=True, required_for_full=False)]),
            dict(suite_record('FIX-NATIVE', 'fixture native', module),
                 disposition='keep',
                 cases=[case_record('FIX-BLOCKED', 'FIX-NATIVE', module,
                                    adapter='native-blocked', safe=False)]),
        ],
    }
    (root / 'docs' / 'acceptance' / 'catalog.json').write_text(
        json.dumps(catalog, ensure_ascii=False, indent=2), encoding='utf-8')
    (root / 'Logs').mkdir()
    (root / 'candidate.json').write_text(json.dumps({
        'schema': 'fakenet.acceptance-candidate.v2',
        'source_commit': 'fixture',
        'offline_fixture': True,
    }), encoding='utf-8')
    (root / 'environment.json').write_text(json.dumps({
        'schema': 'fakenet.acceptance-environment.v2',
        'targets': ['host-linux'],
        'interpreters': {'python': sys.executable},
        'endpoints': [],
        'auth_refs': [],
        'work_root': str((root / 'Logs').resolve()),
        'allowed_actions': ['offline-pytest', 'collection'],
    }), encoding='utf-8')
    return root


def run_cli(root, *args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = ACC.main(['--root', str(root)] + list(args))
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 2
    return code, out.getvalue(), err.getvalue()


def plan(root, mode, *extra):
    output = root / 'Logs' / ('run-' + mode) / 'plan.json'
    code, stdout, stderr = run_cli(
        root, 'plan', '--mode', mode,
        '--candidate', str(root / 'candidate.json'),
        '--environment', str(root / 'environment.json'),
        '--output', str(output), *extra)
    return code, output, stdout, stderr


def execute(root, plan_path):
    return run_cli(root, 'execute', '--plan', str(plan_path))


def judge(root, plan_path, results_dir, output=None):
    args = ['judge', '--plan', str(plan_path), '--results', str(results_dir)]
    if output:
        args += ['--output', str(output)]
    return run_cli(root, *args)


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def write_json(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n',
                          encoding='utf-8')


def copy_results(results_dir):
    source = Path(results_dir)
    target = source.parent / (source.name + '-mutated')
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(source, target)
    index = read_json(target / 'results.json')
    for entry in index['receipts']:
        old = Path(entry['path'])
        entry['path'] = str(target / old.parent.name / 'receipt.json')
    write_json(target / 'results.json', index)
    return target


def receipt_path(results_dir, case_id):
    return Path(results_dir) / case_id / 'receipt.json'


def index_path(results_dir):
    return Path(results_dir) / 'results.json'


def update_index(results_dir):
    index = read_json(index_path(results_dir))
    for entry in index['receipts']:
        path = Path(entry['path'])
        entry['sha256'] = ACC.sha256(path)
    write_json(index_path(results_dir), index)


def rewrite_junit(results_dir, case_id, body):
    path = Path(results_dir) / case_id / 'junit.xml'
    path.write_text(body, encoding='utf-8')
    receipt = read_json(receipt_path(results_dir, case_id))
    for artifact in receipt['artifacts']:
        artifact['path'] = str(path.resolve())
        artifact['sha256'] = ACC.sha256(path)
    write_json(receipt_path(results_dir, case_id), receipt)
    update_index(results_dir)


def junit(cases):
    body = ['<testsuites><testsuite>']
    for classname, name, kind in cases:
        if kind == 'fail':
            body.append('<testcase classname="%s" name="%s"><failure/></testcase>' % (classname, name))
        elif kind == 'skip':
            body.append('<testcase classname="%s" name="%s"><skipped/></testcase>' % (classname, name))
        else:
            body.append('<testcase classname="%s" name="%s"/>' % (classname, name))
    body.append('</testsuite></testsuites>')
    return ''.join(body)


class AcceptanceLoopTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = make_root(self.temp.name)

    def test_check_accepts_v2_catalog(self):
        code, stdout, stderr = run_cli(self.root, 'check')
        self.assertEqual(0, code, stderr)
        payload = json.loads(stdout)
        self.assertEqual('fakenet.acceptance-catalog.v2', payload['schema'])
        self.assertEqual(3, payload['counts']['cases'])

    def test_plan_full_records_blocked_native_and_exact_checks(self):
        code, path, stdout, stderr = plan(self.root, 'full')
        self.assertEqual(0, code, stderr)
        value = read_json(path)
        self.assertEqual('fakenet.acceptance-plan.v2', value['schema'])
        self.assertEqual(['FIX-PASS', 'FIX-BLOCKED'], value['required_cases'])
        self.assertIn('FIX-BLOCKED', value['blocked'])
        self.assertTrue(value['required_checks']['FIX-PASS'])
        self.assertEqual([], value['required_checks']['FIX-BLOCKED'])
        self.assertTrue((path.parent / 'collection' / 'FIX-PASS-collection.log').is_file())

    def test_selected_execute_passes_but_is_not_full(self):
        code, path, stdout, stderr = plan(self.root, 'selected', '--case', 'FIX-PASS')
        self.assertEqual(0, code, stderr)
        code, stdout, stderr = execute(self.root, path)
        self.assertEqual(0, code, stderr + stdout)
        summary = read_json(path.parent / 'summary.json')
        self.assertEqual('pass', summary['verdict'])
        self.assertEqual('selected', summary['coverage'])
        self.assertFalse(summary['full_functional_pass'])
        receipt = read_json(path.parent / 'results' / 'FIX-PASS' / 'receipt.json')
        self.assertEqual(0, receipt['returncode'])
        self.assertEqual('adapter', receipt['cleanup']['source'])
        self.assertEqual([], receipt['cleanup']['resources'])
        self.assertTrue(receipt['cleanup']['process_exit']['exited'])
        self.assertTrue(receipt['cleanup']['temp_roots'])
        self.assertTrue(any(item['format'] == 'junit' for item in receipt['artifacts']))

    def test_full_execute_reports_blocked_and_is_not_full_pass(self):
        code, path, stdout, stderr = plan(self.root, 'full')
        self.assertEqual(0, code, stderr)
        code, stdout, stderr = execute(self.root, path)
        self.assertEqual(2, code, stderr + stdout)
        summary = read_json(path.parent / 'summary.json')
        self.assertEqual('unknown', summary['verdict'])
        self.assertIn('FIX-BLOCKED', summary['unverified'])
        self.assertFalse(summary['full_functional_pass'])

    def test_independent_judge_recomputes_same_result(self):
        code, path, stdout, stderr = plan(self.root, 'selected', '--case', 'FIX-PASS')
        self.assertEqual(0, code, stderr)
        code, stdout, stderr = execute(self.root, path)
        self.assertEqual(0, code, stderr + stdout)
        output = path.parent / 'summary-rerun.json'
        code, stdout, stderr = judge(self.root, path, path.parent / 'results', output)
        self.assertEqual(0, code, stderr)
        summary = read_json(output)
        self.assertEqual('pass', summary['verdict'])

    def test_output_collision_is_refused(self):
        code, path, stdout, stderr = plan(self.root, 'selected', '--case', 'FIX-PASS')
        self.assertEqual(0, code, stderr)
        before = ACC.sha256(path)
        code, other, stdout, stderr = plan(self.root, 'selected', '--case', 'FIX-PASS')
        self.assertEqual(2, code)
        self.assertEqual(before, ACC.sha256(path))

    def test_unknown_schema_is_refused_before_execution(self):
        path = self.root / 'Logs' / 'bad' / 'plan.json'
        path.parent.mkdir()
        write_json(path, {'schema': 'fakenet.acceptance-plan.v1'})
        code, stdout, stderr = execute(self.root, path)
        self.assertEqual(2, code)
        self.assertFalse((path.parent / 'results').exists())

    def test_source_drift_is_refused_before_execution(self):
        code, path, stdout, stderr = plan(self.root, 'selected', '--case', 'FIX-PASS')
        self.assertEqual(0, code, stderr)
        module = self.root / 'test' / 'test_fixture_module.py'
        module.write_text(module.read_text(encoding='utf-8') + '\n# drift\n',
                          encoding='utf-8')
        code, stdout, stderr = execute(self.root, path)
        self.assertEqual(2, code)
        self.assertFalse((path.parent / 'results').exists())

    def test_unknown_case_selection_is_refused(self):
        code, path, stdout, stderr = plan(self.root, 'selected', '--case', 'NOPE')
        self.assertEqual(2, code)
        self.assertFalse(path.exists())

    def test_unknown_command_uses_argparse_exit(self):
        code, stdout, stderr = run_cli(self.root, 'bogus')
        self.assertEqual(2, code)

    def _executed_results(self):
        code, path, stdout, stderr = plan(self.root, 'selected', '--case', 'FIX-PASS')
        self.assertEqual(0, code, stderr)
        code, stdout, stderr = execute(self.root, path)
        self.assertEqual(0, code, stderr + stdout)
        return path, path.parent / 'results'

    def test_wrong_candidate_is_refused(self):
        path, results = self._executed_results()
        mutated = copy_results(results)
        receipt_file = receipt_path(mutated, 'FIX-PASS')
        receipt = read_json(receipt_file)
        receipt['candidate'] = {'source_commit': 'other'}
        write_json(receipt_file, receipt)
        update_index(mutated)
        code, stdout, stderr = judge(self.root, path, mutated)
        self.assertEqual(2, code)
        self.assertIn('candidate mismatch', stderr)

    def test_execution_id_mismatch_is_refused(self):
        path, results = self._executed_results()
        mutated = copy_results(results)
        index = read_json(index_path(mutated))
        index['execution_id'] = 'other'
        write_json(index_path(mutated), index)
        code, stdout, stderr = judge(self.root, path, mutated)
        self.assertEqual(2, code)
        self.assertIn('execution_id', stderr)

    def test_missing_and_duplicate_results_are_unknown(self):
        path, results = self._executed_results()
        checks = read_json(path)['required_checks']['FIX-PASS']
        self.assertEqual(2, len(checks))
        classname, name = checks[0].split('::')
        cases = [
            ('missing', [(classname, name, 'pass')]),
            ('duplicate', [(classname, name, 'pass'), (classname, name, 'pass')]),
        ]
        for label, body in cases:
            with self.subTest(label=label):
                mutated = copy_results(results)
                rewrite_junit(mutated, 'FIX-PASS',
                              junit(body))
                code, stdout, stderr = judge(self.root, path, mutated)
                self.assertEqual(2, code, stderr)

    def test_skip_is_unknown(self):
        path, results = self._executed_results()
        checks = read_json(path)['required_checks']['FIX-PASS']
        classname, name = checks[0].split('::')
        mutated = copy_results(results)
        rewrite_junit(mutated, 'FIX-PASS',
                      junit([(classname, name, 'skip')]))
        code, stdout, stderr = judge(self.root, path, mutated)
        self.assertEqual(2, code)

    def test_failure_with_zero_returncode_is_fail(self):
        path, results = self._executed_results()
        checks = read_json(path)['required_checks']['FIX-PASS']
        classname, name = checks[0].split('::')
        mutated = copy_results(results)
        rewrite_junit(mutated, 'FIX-PASS', junit([(classname, name, 'fail')]))
        receipt_file = receipt_path(mutated, 'FIX-PASS')
        receipt = read_json(receipt_file)
        receipt['returncode'] = 0
        write_json(receipt_file, receipt)
        update_index(mutated)
        code, stdout, stderr = judge(self.root, path, mutated)
        self.assertEqual(1, code)

    def test_fake_cleanup_declaration_is_unknown(self):
        path, results = self._executed_results()
        mutated = copy_results(results)
        receipt_file = receipt_path(mutated, 'FIX-PASS')
        receipt = read_json(receipt_file)
        receipt['cleanup'] = {'complete': True}
        write_json(receipt_file, receipt)
        update_index(mutated)
        code, stdout, stderr = judge(self.root, path, mutated)
        self.assertEqual(2, code)

    def test_observed_tsv_result_is_unknown(self):
        path, results = self._executed_results()
        checks = read_json(path)['required_checks']['FIX-PASS']
        mutated = copy_results(results)
        tsv = mutated / 'FIX-PASS' / 'results.tsv'
        tsv.write_text(''.join('OBSERVED\t%s\tnot judged\n' % check
                               for check in checks), encoding='utf-8')
        receipt_file = receipt_path(mutated, 'FIX-PASS')
        receipt = read_json(receipt_file)
        receipt['artifacts'] = [{'path': str(tsv.resolve()),
                                 'sha256': ACC.sha256(tsv), 'format': 'tsv'}]
        write_json(receipt_file, receipt)
        update_index(mutated)
        code, stdout, stderr = judge(self.root, path, mutated)
        self.assertEqual(2, code)

    def test_judge_requires_results_index(self):
        path, results = self._executed_results()
        empty = self.root / 'Logs' / 'empty-results'
        empty.mkdir()
        code, stdout, stderr = judge(self.root, path, empty)
        self.assertEqual(2, code)

    def test_full_plan_excludes_stress_and_stress_plan_selects_it(self):
        code, path, stdout, stderr = plan(self.root, 'full')
        self.assertEqual(0, code, stderr)
        self.assertNotIn('FIX-STRESS', read_json(path)['required_cases'])
        code, path, stdout, stderr = plan(self.root, 'stress')
        self.assertEqual(0, code, stderr)
        self.assertEqual(['FIX-STRESS'], read_json(path)['required_cases'])

    def test_relabelled_full_subset_is_rejected(self):
        path, results = self._executed_results()
        target = self.root / 'Logs' / 'relabel-full'
        target.mkdir()
        plan_copy = target / 'plan.json'
        value = read_json(path)
        value['mode'] = 'full'
        value['run_dir'] = str(target)
        write_json(plan_copy, value)
        mutated = copy_results(results)
        index = read_json(index_path(mutated))
        index['plan'] = str(plan_copy)
        index['plan_sha256'] = ACC.sha256(plan_copy)
        write_json(index_path(mutated), index)
        code, stdout, stderr = judge(self.root, plan_copy, mutated)
        self.assertEqual(2, code)
        self.assertIn('full plan does not cover', stderr)
        self.assertFalse((target / 'summary.json').exists())

    def test_extra_skipped_node_with_unknown_receipt_is_not_pass(self):
        path, results = self._executed_results()
        checks = read_json(path)['required_checks']['FIX-PASS']
        cases = []
        for check in checks:
            classname, name = check.split('::')
            cases.append((classname, name, 'pass'))
        cases.append(('unexpected.Class', 'test_skipped', 'skip'))
        mutated = copy_results(results)
        rewrite_junit(mutated, 'FIX-PASS', junit(cases))
        receipt_file = receipt_path(mutated, 'FIX-PASS')
        receipt = read_json(receipt_file)
        receipt['status'] = 'unknown'
        receipt['detail'] = 'collection/result coverage mismatch'
        write_json(receipt_file, receipt)
        update_index(mutated)
        code, stdout, stderr = judge(self.root, path, mutated)
        self.assertEqual(2, code)
        output = self.root / 'Logs' / 'extra-skip-summary.json'
        code, stdout, stderr = judge(self.root, path, mutated, output)
        self.assertEqual('unknown', read_json(output)['verdict'])

    def test_receipt_case_mismatch_is_refused(self):
        path, results = self._executed_results()
        mutated = copy_results(results)
        receipt_file = receipt_path(mutated, 'FIX-PASS')
        receipt = read_json(receipt_file)
        receipt['case_id'] = 'WRONG-CASE'
        write_json(receipt_file, receipt)
        update_index(mutated)
        code, stdout, stderr = judge(self.root, path, mutated)
        self.assertEqual(2, code)
        self.assertIn('case_id', stderr)

    def test_receipt_environment_mismatch_is_refused(self):
        path, results = self._executed_results()
        mutated = copy_results(results)
        receipt_file = receipt_path(mutated, 'FIX-PASS')
        receipt = read_json(receipt_file)
        receipt['environment'] = {'wrong': 'environment'}
        write_json(receipt_file, receipt)
        update_index(mutated)
        code, stdout, stderr = judge(self.root, path, mutated)
        self.assertEqual(2, code)
        self.assertIn('environment mismatch', stderr)

    def test_collection_only_environment_does_not_execute(self):
        environment = read_json(self.root / 'environment.json')
        environment['allowed_actions'] = ['collection']
        write_json(self.root / 'environment.json', environment)
        code, path, stdout, stderr = plan(self.root, 'selected', '--case', 'FIX-PASS')
        self.assertEqual(0, code, stderr)
        value = read_json(path)
        self.assertIn('FIX-PASS', value['blocked'])
        self.assertIn('offline-pytest', value['blocked']['FIX-PASS'])
        self.assertTrue((path.parent / 'collection' / 'FIX-PASS-collection.log').is_file())
        code, stdout, stderr = execute(self.root, path)
        self.assertEqual(2, code)
        self.assertIn('offline-pytest', stderr)
        self.assertFalse((path.parent / 'results').exists())

    def test_unknown_and_timeout_receipts_cannot_pass(self):
        path, results = self._executed_results()
        mutated = copy_results(results)
        receipt_file = receipt_path(mutated, 'FIX-PASS')
        receipt = read_json(receipt_file)
        receipt['status'] = 'unknown'
        write_json(receipt_file, receipt)
        update_index(mutated)
        code, stdout, stderr = judge(self.root, path, mutated)
        self.assertEqual(2, code)
        output = self.root / 'Logs' / 'unknown-summary.json'
        code, stdout, stderr = judge(self.root, path, mutated, output)
        self.assertEqual('unknown', read_json(output)['verdict'])
        timed = copy_results(results)
        receipt_file = receipt_path(timed, 'FIX-PASS')
        receipt = read_json(receipt_file)
        receipt['cleanup']['process_exit']['timed_out'] = True
        write_json(receipt_file, receipt)
        update_index(timed)
        code, stdout, stderr = judge(self.root, path, timed)
        self.assertEqual(2, code)

    def test_receipt_oracle_format_cannot_be_swapped(self):
        path, results = self._executed_results()
        mutated = copy_results(results)
        tsv = mutated / 'FIX-PASS' / 'results.tsv'
        tsv.write_text('PASS\ttest.test_fixture_module.FixtureTests::test_alpha\tok\n',
                       encoding='utf-8')
        receipt_file = receipt_path(mutated, 'FIX-PASS')
        receipt = read_json(receipt_file)
        receipt['artifacts'] = [{'path': str(tsv.resolve()),
                                 'sha256': ACC.sha256(tsv), 'format': 'tsv'}]
        write_json(receipt_file, receipt)
        update_index(mutated)
        code, stdout, stderr = judge(self.root, path, mutated)
        self.assertEqual(2, code)
        self.assertIn('artifact format', stderr)


if __name__ == '__main__':
    unittest.main()
