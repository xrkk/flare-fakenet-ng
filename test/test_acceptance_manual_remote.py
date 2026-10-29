"""Remote manual GAP-NCSI/GAP-RAW-DATE contract through a controlled stand-in.

Only the VM/OS boundary is substituted: the central plan/execute/judge CLI,
the real guest entry and the real loopback manual producer run on this host.
The stand-in presents the pulled originals with the exact guest Windows paths
they would carry on the existing channel.  This earns explicit fixture credit
only, never Windows native or full functional credit.
"""
import copy
import json
import os
import shutil
import sys
import unittest
import uuid
from pathlib import Path, PureWindowsPath
from unittest import mock

import os as _os
ROOT = Path(_os.environ.get('FN_MANUAL_PRODUCT_ROOT',
                            str(Path(__file__).resolve().parents[1])))
sys.path[:0] = [str(ROOT / 'tools'), str(ROOT / 'test')]
import acceptance as A
import acceptance_guest as guest
import acceptance_manual as M
import acceptance_manual_oracles as O
import acceptance_native as N
import acceptance_windows as win


def sha(path):
    import hashlib
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def catalog_case(case_id):
    catalog = json.loads((ROOT / 'docs/acceptance/catalog.json').read_text(encoding='utf-8'))
    return next(case for suite in catalog['suites'] for case in suite.get('cases', [])
                if case['id'] == case_id)



NON_PRODUCT_DIRS = {'.git', 'Logs', 'dist', '.tmp', 'PLAN', '.github',
                    '.local', '.omo', '.codex', '.pytest_cache', '__pycache__'}


def portable_ignore(directory, names):
    """Skip non-product/history dirs and names Windows cannot represent, so
    the product-root copy stays creatable under real Windows Python."""
    import re
    skipped = set(n for n in names if n in NON_PRODUCT_DIRS)
    bad = re.compile(r'[\x00-\x1f<>:"|?*]')
    reserved = {'con', 'prn', 'aux', 'nul', 'com1', 'lpt1'}
    skipped |= {n for n in names if bad.search(n) or n.rstrip('.').lower() in reserved}
    return skipped

class RemoteManualTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Facility-style non-Git product root: the central CLI records the
        # declared fixture identity instead of invoking Git in every phase,
        # exactly like the existing production entry self-tests.
        shared = Path(os.environ.get('FN_MANUAL_CHECK_DIR',
                                     str(ROOT / 'Logs' / 'manual-tests' / uuid.uuid4().hex)))
        shared.mkdir(parents=True, exist_ok=True)
        cls.shared = shared
        cls.source = shared / 'product-root'
        shutil.copytree(ROOT, cls.source, ignore=portable_ignore, dirs_exist_ok=True)

    def setUp(self):
        self.base = self.shared / 'retained' / uuid.uuid4().hex[:12]
        self.base.mkdir(parents=True, exist_ok=False)
        self.identity = {'platform': 'windows', 'hostname': 'fixture-vm'}
        self.candidate = {'schema': A.CANDIDATE_V2, 'source_commit': 'c' * 40,
                          'package_manifest': None, 'package_sha256': 'd' * 64,
                          'deployed_identity': self.identity, 'offline_fixture': True}
        (self.base / 'candidate.json').write_text(json.dumps(self.candidate))
        self.runtime = {'transport': 'windows-mcp-velo', 'identity': self.identity,
                        'mcp_config_ref': 'existing', 'mcp_server': 'VMMalBox',
                        'python': r'E:\python.exe', 'source_root': r'E:\candidate',
                        'work_root': r'E:\native-runs', 'transfer': {}}
        self.environment = {'schema': A.ENVIRONMENT_V2, 'targets': ['windows-vm'],
                            'interpreters': {'python': sys.executable},
                            'work_root': str(self.base),
                            'allowed_actions': ['native', 'vm-execute', 'vm-transfer'],
                            'endpoints': [], 'auth_refs': [],
                            'native_runtime': self.runtime,
                            'manual': {'schema': 'fakenet.manual-options.v1',
                                       'responsea': '192.0.2.55'}}
        (self.base / 'environment.json').write_text(json.dumps(self.environment))
        self.guest_runs = {}

    def cli(self, *args):
        import contextlib
        import io
        out, err = io.StringIO(), io.StringIO()
        # The product-root fixture has no Git history: short-circuit git_head to
        # its documented InputError branch (same code path a non-Git root takes)
        # so the central phases run without spawning Git probes.
        with mock.patch.object(A, 'git_head',
                               side_effect=A.InputError('fixture root has no Git history')), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = A.main(['--root', str(self.source), *[str(a) for a in args]])
        return code, out.getvalue(), err.getvalue()

    def plan(self, cases=('GAP-NCSI', 'GAP-RAW-DATE'), name='run'):
        path = self.base / name / 'plan.json'
        argv = ['plan', '--mode', 'selected', '--candidate', self.base / 'candidate.json',
                '--environment', self.base / 'environment.json', '--output', path]
        argv += [token for case in cases for token in ('--case', case)]
        code, out, err = self.cli(*argv)
        self.assertEqual(0, code, out + err)
        return path

    def guest_dir(self, case_id):
        if case_id not in self.guest_runs:
            self.guest_runs[case_id] = self.base / ('guest-' + case_id)
        return self.guest_runs[case_id]

    def remap(self, value, prefix, remote_root):
        if isinstance(value, str) and value.startswith(prefix):
            return remote_root + value[len(prefix):].replace('/', '\\')
        if isinstance(value, list):
            return [self.remap(item, prefix, remote_root) for item in value]
        if isinstance(value, dict):
            return {key: self.remap(item, prefix, remote_root) for key, item in value.items()}
        return value

    def stand_in(self):
        """Replace only ExistingWindowsChannel; run the real guest entry."""
        outer = self

        class WindowsStandIn:
            def __init__(self, root, runtime, journal):
                self.runtime = runtime
                self.pushed = {}
                self.guest_out = None

            def identity(self):
                return outer.identity

            def transfer(self, name, direction, sources, destination, *, producer_reference):
                if direction == 'push':
                    self.pushed[name] = json.loads(Path(sources[0]['absolute_path']).read_text())
                    return {}
                request = self.pushed['push-request']
                guest_out = self.guest_out
                originals = Path(destination) / 'originals'
                shutil.copytree(guest_out, originals,
                                ignore=shutil.ignore_patterns('guest-result.json'))
                prefix, remote_root = str(guest_out), request['output_root']
                for path in originals.rglob('*.json'):
                    path.write_text(json.dumps(self.remap_value(json.loads(path.read_text()),
                                                                prefix, remote_root),
                                               indent=2) + '\n', encoding='utf-8')
                real = json.loads((guest_out / 'guest-result.json').read_text())
                receipt = copy.deepcopy(real['receipt'])
                driver = N.driver_table(outer.source)[request['case']['native_driver']]
                fixture = request['candidate'].get('offline_fixture') is True
                receipt['command'] = N.remote_guest_command(
                    driver, self.runtime, request['output_root'], request['checks'],
                    fixture, case_id=request['case_id'])
                # The rewritten JSONs are the guest-side content as it exists on
                # Windows, so the guest receipt hashes the final pulled bytes.
                base = PureWindowsPath(request['output_root'])
                def final_artifact(item):
                    remote = self.remap_value(item['path'], prefix, remote_root)
                    relative = PureWindowsPath(remote).relative_to(base)
                    return dict(item, path=remote, sha256=sha(originals.joinpath(*relative.parts)))
                receipt['artifacts'] = [final_artifact(item) for item in receipt['artifacts']]
                receipt['cleanup'] = dict(receipt['cleanup'], temp_roots=[request['output_root']])
                result = {'schema': 'fakenet.native-guest-result.v1',
                          'execution_id': request['execution_id'],
                          'case_id': request['case_id'], 'request': request,
                          'receipt': receipt}
                (originals / 'guest-result.json').write_text(json.dumps(result, indent=2) + '\n',
                                                             encoding='utf-8')
                return {}

            def remap_value(self, value, prefix, remote_root):
                return outer.remap(value, prefix, remote_root)

            def execute(self, request_path, request_sha, output_root, source_hashes, timeout):
                request = self.pushed['push-request']
                local = dict(request, output_root=str(outer.guest_dir(request['case_id'])))
                import acceptance_runtime as rt
                with mock.patch.object(rt, 'require_target', return_value=outer.identity):
                    code = guest.execute(local, outer.source)
                self.guest_out = Path(local['output_root'])
                return {'returncode': code, 'process_exited': True, 'recovered': True}

        return WindowsStandIn

    def test_remote_two_case_roundtrip_and_independent_rejudge(self):
        plan = self.plan()
        with mock.patch.object(win, 'ExistingWindowsChannel', side_effect=self.stand_in()):
            code, out, err = self.cli('execute', '--plan', plan)
        self.assertEqual(0, code, out + err)
        self.assertTrue(self.guest_dir('GAP-NCSI').is_dir())
        self.assertTrue(self.guest_dir('GAP-RAW-DATE').is_dir())
        self.assertEqual(0, self.cli('judge', '--plan', plan, '--results', plan.parent / 'results',
                                     '--output', plan.parent / 'independent.json')[0])
        summary = json.loads((plan.parent / 'independent.json').read_text())
        self.assertEqual(['pass', 'pass'], [row['status'] for row in summary['cases']])
        self.assertTrue(summary['fixture_contract_pass'])
        self.assertFalse(summary['full_functional_pass'])
        # The same retained originals must re-judge identical bytes again.
        self.assertEqual(0, self.cli('judge', '--plan', plan, '--results', plan.parent / 'results',
                                     '--output', plan.parent / 'independent-again.json')[0])

    def originals(self, plan, case_id):
        return plan.parent / 'results' / case_id / 'incoming' / 'originals'

    def rehashed_judge(self, plan, case_id, mutate):
        case_dir = plan.parent / 'results' / case_id
        target = self.originals(plan, case_id)
        backups = {path: path.read_bytes() for path in target.rglob('*') if path.is_file()}
        mutate(target)
        # Keep BOTH pinned hash layers consistent (guest receipt inside the
        # pulled originals, then the host receipt index) so the refusal has to
        # come from the oracle's own byte/identity predicates.
        guest_path = target / 'guest-result.json'
        guest_result = json.loads(guest_path.read_text())
        base = PureWindowsPath(guest_result['request']['output_root'])
        for item in guest_result['receipt']['artifacts']:
            relative = PureWindowsPath(item['path']).relative_to(base)
            item['sha256'] = sha(target.joinpath(*relative.parts))
        guest_path.write_text(json.dumps(guest_result, indent=2) + '\n')
        receipt_path = case_dir / 'receipt.json'
        receipt = json.loads(receipt_path.read_text())
        for item in receipt['artifacts']:
            item['sha256'] = sha(item['path'])
        receipt_path.write_text(json.dumps(receipt))
        index_path = plan.parent / 'results' / 'results.json'
        index = json.loads(index_path.read_text())
        for entry in index['receipts']:
            if entry['case_id'] == case_id:
                entry['sha256'] = sha(receipt_path)
        index_path.write_text(json.dumps(index))
        output = plan.parent / ('bad-' + case_id + '-' + str(len(list(plan.parent.glob('bad-*')))) + '.json')
        code, out, err = self.cli('judge', '--plan', plan, '--results', plan.parent / 'results',
                                  '--output', output)
        summary = json.loads(output.read_text())
        for path, data in backups.items():
            path.write_bytes(data)
        receipt = json.loads(receipt_path.read_text())
        for item in receipt['artifacts']:
            item['sha256'] = sha(item['path'])
        receipt_path.write_text(json.dumps(receipt))
        index = json.loads(index_path.read_text())
        for entry in index['receipts']:
            if entry['case_id'] == case_id:
                entry['sha256'] = sha(receipt_path)
        index_path.write_text(json.dumps(index))
        return code, summary

    def real_remote_results(self, case_id):
        # One case per negative plan: a tainted first case must not silently
        # block the other through the shared loopback resource.
        plan = self.plan(cases=(case_id,), name='neg-' + case_id)
        with mock.patch.object(win, 'ExistingWindowsChannel', side_effect=self.stand_in()):
            code, out, err = self.cli('execute', '--plan', plan)
        self.assertEqual(0, code, out + err)
        self.assertEqual(0, self.cli('judge', '--plan', plan, '--results', plan.parent / 'results',
                                     '--output', plan.parent / 'baseline.json')[0])
        return plan

    def test_remote_negatives_refused_by_real_consumer(self):
        ncsi = self.real_remote_results('GAP-NCSI')
        raw = self.real_remote_results('GAP-RAW-DATE')

        def edit(case_id, changer):
            def mutate(target):
                path = target / 'driver' / 'manual-result.json'
                value = json.loads(path.read_text())
                changer(value, target)
                path.write_text(json.dumps(value, indent=2) + '\n')
            return mutate

        rows = []
        code, summary = self.rehashed_judge(ncsi, 'GAP-NCSI', lambda target: (
            (target / 'driver' / 'response-udp-0.bin').write_bytes(b'bad')))
        rows.append(('bad-dns', code, summary))
        code, summary = self.rehashed_judge(ncsi, 'GAP-NCSI', edit('GAP-NCSI', lambda value, target: value['queries'].pop()))
        rows.append(('missing-combination', code, summary))
        code, summary = self.rehashed_judge(ncsi, 'GAP-NCSI', edit('GAP-NCSI', lambda value, target: value.__setitem__('identity', dict(value['identity'], execution_id='foreign'))))
        rows.append(('wrong-candidate', code, summary))
        code, summary = self.rehashed_judge(ncsi, 'GAP-NCSI', edit('GAP-NCSI', lambda value, target: value['queries'][0].__setitem__('query', r'E:\elsewhere\query.bin')))
        rows.append(('path-escape', code, summary))
        code, summary = self.rehashed_judge(ncsi, 'GAP-NCSI', edit('GAP-NCSI', lambda value, target: value['cleanup'].__setitem__('stopped', False)))
        rows.append(('fake-cleanup', code, summary))
        code, summary = self.rehashed_judge(ncsi, 'GAP-NCSI', lambda target: (target / 'manual-inputs.json').write_text(
            json.dumps(dict(json.loads((target / 'manual-inputs.json').read_text()), responsea='203.0.113.9'))))
        rows.append(('input-tamper', code, summary))
        code, summary = self.rehashed_judge(raw, 'GAP-RAW-DATE', lambda target: (
            (target / 'driver' / 'raw-response.bin').write_bytes(
                (target / 'driver' / 'raw-response.bin').read_bytes() + b'x')))
        rows.append(('bad-http', code, summary))
        def wrong_date(value, target):
            value['http']['exchanges'][0]['started_epoch'] = 0
            value['http']['exchanges'][0]['ended_epoch'] = 1
        code, summary = self.rehashed_judge(raw, 'GAP-RAW-DATE', edit('GAP-RAW-DATE', wrong_date))
        rows.append(('wrong-date', code, summary))
        expected = {'bad-dns': 'DNS bytes', 'missing-combination': 'four-combination',
                    'wrong-candidate': 'identity mismatch', 'path-escape': 'escaped the producer root',
                    'fake-cleanup': 'lifecycle', 'input-tamper': 'manual inputs differ',
                    'bad-http': 'HTTP bytes', 'wrong-date': 'HTTP date'}
        for name, code, summary in rows:
            with self.subTest(negative=name):
                self.assertNotEqual(0, code)
                self.assertNotEqual('pass', summary['verdict'])
                self.assertIn(expected[name], json.dumps(summary))

    def test_fixture_originals_cannot_earn_native_credit(self):
        plan = self.real_remote_results('GAP-NCSI')
        value = json.loads(plan.read_text())
        remote_output = str(PureWindowsPath(self.runtime['work_root']) / value['execution_id'] / 'GAP-NCSI' / 'output')
        inputs = N.manual_remote_inputs(value, catalog_case('GAP-NCSI'), remote_output)
        with self.assertRaisesRegex(ValueError, 'fixture cannot native credit'):
            O.evaluate(ROOT, self.originals(plan, 'GAP-NCSI') / 'driver', 'GAP-NCSI', inputs,
                       allow_fixture=False,
                       producer_directory=str(PureWindowsPath(remote_output) / 'driver'))

    def test_remote_guest_command_pins_case_and_manual_inputs(self):
        driver = N.driver_table(ROOT)['manual-ncsi']
        argv = N.remote_guest_command(driver, self.runtime, r'E:\native-runs\e\GAP-NCSI\output',
                                      ['ncsi-ipv4', 'other-domain', 'dns-evidence'],
                                      False, case_id='GAP-NCSI')
        self.assertEqual([r'E:\python.exe', r'E:\candidate/tools/acceptance_manual.py',
                          '--case', 'GAP-NCSI',
                          '--inputs', r'E:\native-runs\e\GAP-NCSI\output\manual-inputs.json',
                          '--output', r'E:\native-runs\e\GAP-NCSI\output/driver'], argv)
        self.assertEqual('GAP-NCSI', argv[argv.index('--case') + 1])

    def test_other_manual_cases_still_reject_remote_channel(self):
        plan = self.plan(cases=('GAP-NETWORK-FIX',), name='blocked')
        value = json.loads(plan.read_text())
        self.assertIn('no remote fallback', value['blocked']['GAP-NETWORK-FIX'])
        with mock.patch.object(win, 'ExistingWindowsChannel') as channel:
            code, out, err = self.cli('execute', '--plan', plan)
        self.assertEqual(2, code, out + err)
        channel.assert_not_called()

    def test_illegal_or_missing_manual_options_block_before_channel(self):
        for options in ({'schema': 'fakenet.manual-options.v2'},
                        {'schema': 'fakenet.manual-options.v1', 'extra': 1},
                        {'schema': 'fakenet.manual-options.v1', 'responsea': 'not-an-address'},
                        None):
            with self.subTest(options=options):
                environment = copy.deepcopy(self.environment)
                if options is None:
                    environment.pop('manual')
                else:
                    environment['manual'] = options
                (self.base / 'environment.json').write_text(json.dumps(environment))
                plan = self.plan(name='options-' + uuid.uuid4().hex[:8])
                value = json.loads(plan.read_text())
                blocked = json.dumps(value['blocked'])
                self.assertTrue('manual options required' in blocked
                                or 'manual responsea address is invalid' in blocked, blocked)
                with mock.patch.object(win, 'ExistingWindowsChannel') as channel:
                    code, out, err = self.cli('execute', '--plan', plan)
                self.assertEqual(2, code, out + err)
                channel.assert_not_called()

    def guest_request(self, case_id, extra=None):
        request = {'schema': 'fakenet.native-guest-request.v1', 'case_id': case_id,
                   'case': catalog_case(case_id), 'checks': list(M.CHECKS[case_id]),
                   'source_hashes': {'tools/acceptance_guest.py': sha(ROOT / 'tools/acceptance_guest.py')},
                   'candidate': copy.deepcopy(self.candidate), 'target': self.identity,
                   'output_root': str(self.base / ('guest-entry-' + case_id)),
                   'execution_id': 'manual-remote-entry', 'actions': ['native']}
        request.update(extra or {})
        return request

    def test_guest_entry_contract_for_manual_field(self):
        import acceptance_runtime as rt
        # Options on a case outside the two fixed remote cases are refused
        # before any output directory is created.
        request = self.guest_request('GAP-NETWORK-FIX', {'manual': {'schema': 'fakenet.manual-options.v1'}})
        with mock.patch.object(rt, 'require_target', return_value=self.identity):
            with self.assertRaisesRegex(ValueError, 'manual options do not apply'):
                guest.execute(request, ROOT)
        self.assertFalse(Path(request['output_root']).exists())
        # The shared options must arrive alone; combining them with policy or
        # headless fields is not a valid guest request.
        for extra in ({'manual': {'schema': 'fakenet.manual-options.v1'},
                       'policy': {'unused': True}},
                      {'manual': {'schema': 'fakenet.manual-options.v1'},
                       'headless': {'unused': True}}):
            with self.subTest(extra=sorted(extra)):
                request = self.guest_request('GAP-NCSI', extra)
                with self.assertRaisesRegex(ValueError, 'invalid guest request schema/fields'):
                    guest.execute(request, ROOT)
                self.assertFalse(Path(request['output_root']).exists())

    def test_guest_illegal_manual_options_rejected_before_side_effects(self):
        # Controller counterexamples S29-F01/S30-F01: missing/schema/address and
        # the truly absent manual key were only refused after output.mkdir.
        # Every variant must die before any directory, subprocess or channel
        # effect, with the same messages, on both fixed remote cases.
        import acceptance_runtime as rt
        ABSENT = object()
        cases = [(ABSENT, 'explicit fixed manual options required'),
                 (None, 'explicit fixed manual options required'),
                 ({'schema': 'invalid'}, 'explicit fixed manual options required'),
                 ({'schema': 'fakenet.manual-options.v1', 'responsea': 'invalid'},
                  'manual responsea address is invalid')]
        for case_id in ('GAP-NCSI', 'GAP-RAW-DATE'):
            for manual, message in cases:
                with self.subTest(case=case_id, manual=manual):
                    request = self.guest_request(case_id, {} if manual is ABSENT
                                                 else {'manual': manual})
                    request['output_root'] = str(self.base / ('guest-entry-%s-%s'
                                                              % (case_id, uuid.uuid4().hex[:8])))
                    with mock.patch.object(rt, 'require_target', return_value=self.identity), \
                         mock.patch.object(N.subprocess, 'Popen') as launch:
                        with self.assertRaisesRegex(ValueError, message):
                            guest.execute(request, ROOT)
                    launch.assert_not_called()
                    self.assertFalse(Path(request['output_root']).exists())
        # A legal request through the same entry still derives its own
        # owned_root and runs; the shared value stays untouched.
        for case_id in ('GAP-NCSI', 'GAP-RAW-DATE'):
            with self.subTest(case=case_id, legal=True):
                legal = self.guest_request(case_id, {'manual': {'schema': 'fakenet.manual-options.v1',
                                                                'responsea': '192.0.2.55'}})
                legal['output_root'] = str(self.base / ('guest-entry-legal-%s-%s'
                                                        % (case_id, uuid.uuid4().hex[:8])))
                with mock.patch.object(rt, 'require_target', return_value=self.identity):
                    with mock.patch.object(N, 'run_production') as production:
                        production.return_value = {'status': 'pass', 'returncode': 0,
                                                   'cleanup': {'process_exit': {'exited': True}}}
                        guest.execute(legal, ROOT)
                self.assertTrue(Path(legal['output_root']).is_dir())

    def test_guest_field_paths_map_only_from_producer_root(self):
        # Controller counterexample S29-F02: a host-local absolute alias in a
        # guest JSON field used to earn the same 3 PASS as the baseline.
        plan = self.real_remote_results('GAP-NCSI')
        value = json.loads(plan.read_text())
        remote_output = str(PureWindowsPath(self.runtime['work_root']) / value['execution_id'] / 'GAP-NCSI' / 'output')
        inputs = N.manual_remote_inputs(value, catalog_case('GAP-NCSI'), remote_output)
        driver = self.originals(plan, 'GAP-NCSI') / 'driver'
        producer = str(PureWindowsPath(remote_output) / 'driver')
        rows, clean, detail = O.evaluate(self.source, driver, 'GAP-NCSI', inputs, allow_fixture=True,
                                         producer_directory=producer)
        self.assertTrue(clean, detail)
        self.assertEqual(['pass'] * 3, [row['status'] for row in rows])
        real_file = driver / 'query-udp-0.bin'
        original = (driver / 'manual-result.json').read_bytes()
        variants = [('host-alias', str(real_file), 'not absolute in the producer root'),
                    ('wrong-drive', r'D:\native-runs\query-udp-0.bin', 'escaped the producer root'),
                    ('relative', 'query-udp-0.bin', 'not absolute in the producer root'),
                    ('dotdot', producer + r'\..\query-udp-0.bin', 'outside owned case')]
        for label, path, expected in variants:
            with self.subTest(variant=label):
                broken = json.loads(original)
                broken['queries'][0]['query'] = path
                (driver / 'manual-result.json').write_text(json.dumps(broken, indent=2) + '\n')
                rows, clean, detail = O.evaluate(self.source, driver, 'GAP-NCSI', inputs,
                                                 allow_fixture=True, producer_directory=producer)
                self.assertFalse(clean, detail)
                self.assertTrue(all(row['status'] == 'fail' for row in rows), rows)
                self.assertIn(expected, json.dumps(detail))
        # Link escape mapped through the producer root is refused as well.
        escape = driver / 'query-escape.bin'
        escape.symlink_to('/etc/hosts')
        self.addCleanup(escape.unlink)
        broken = json.loads(original)
        broken['queries'][0]['query'] = producer + r'\query-escape.bin'
        (driver / 'manual-result.json').write_text(json.dumps(broken, indent=2) + '\n')
        rows, clean, detail = O.evaluate(self.source, driver, 'GAP-NCSI', inputs,
                                         allow_fixture=True, producer_directory=producer)
        self.assertFalse(clean, detail)
        self.assertIn('outside owned case', json.dumps(detail))
        (driver / 'manual-result.json').write_bytes(original)
        # The oracle's own local metadata read stays separate: the retained
        # no-producer_directory entry re-judges the un-remapped guest tree.
        guest_out = self.guest_dir('GAP-NCSI')
        local_inputs = json.loads((guest_out / 'manual-inputs.json').read_text())
        rows, clean, detail = O.evaluate(self.source, guest_out / 'driver', 'GAP-NCSI',
                                         local_inputs, allow_fixture=True)
        self.assertTrue(clean, detail)

    def test_central_judge_rejects_rehashed_host_alias_in_guest_field(self):
        # The same counterexample through the real central independent judge
        # with both pinned hash layers re-consistent.
        plan = self.real_remote_results('GAP-NCSI')
        def alias(target):
            value = json.loads((target / 'driver' / 'manual-result.json').read_text())
            value['queries'][0]['query'] = str(target / 'driver' / 'query-udp-0.bin')
            (target / 'driver' / 'manual-result.json').write_text(json.dumps(value, indent=2) + '\n')
        code, summary = self.rehashed_judge(plan, 'GAP-NCSI', alias)
        self.assertNotEqual(0, code)
        self.assertNotEqual('pass', summary['verdict'])
        self.assertIn('producer root', json.dumps(summary))


if __name__ == '__main__':
    unittest.main()
