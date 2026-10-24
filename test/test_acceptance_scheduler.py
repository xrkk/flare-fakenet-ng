import os,sys,threading,time,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'tools'))
import acceptance_scheduler as S
def active_test_guard():
    module = sys.modules.get('sitecustomize')
    if os.environ.get('FN_S3_ACTOR') in ('executor', 'controller') and module is not None:
        path = Path(module.__file__).parent
        if path.name == 'guard':
            return str(path)
    return ''

class SchedulerTests(unittest.TestCase):
 def test_capacity_depth_and_bounds(self):
  self.assertEqual(1,S.worker_capacity(depth=1))
  self.assertGreaterEqual(S.worker_capacity(depth=0),1)
  self.assertLessEqual(S.worker_capacity(depth=0),2)
 def test_dependency_order_and_missing(self):
  cases=[{'id':'B','dependencies':['A']},{'id':'A'},{'id':'C','dependencies':['MISSING']}]
  order,blocked=S.ordered_cases(cases)
  self.assertEqual(['A','B'],order)
  self.assertIn('C',blocked)
 def test_safe_group_overlaps_and_other_group_serial(self):
  active=0; maximum=0; lock=threading.Lock(); events=[]
  def runner(case):
   nonlocal active,maximum
   with lock:
    active+=1; maximum=max(maximum,active); events.append(('start',case['id'],time.monotonic()))
   time.sleep(0.2)
   with lock:
    active-=1; events.append(('end',case['id'],time.monotonic()))
   return {'status':'pass'}
  cases=[{'id':'CORE-TLSHELLO'},{'id':'CORE-DUALPCAP-WRITER'}]
  results,blocked=S.run_cases(cases,runner,capacity=2)
  self.assertEqual(2,len(results)); self.assertFalse(blocked); self.assertEqual(S.worker_capacity(),maximum)
  active=0; maximum=0
  cases=[{'id':'CORE-DNS-OFFLINE'},{'id':'CORE-LISTENERS-OFFLINE'}]
  results,blocked=S.run_cases(cases,runner,capacity=2)
  self.assertEqual(2,len(results)); self.assertEqual(maximum,1)
 def test_failed_dependency_blocks_only_dependants(self):
  def runner(case):
   return {'status':'fail' if case['id']=='A' else 'pass'}
  cases=[{'id':'A'},{'id':'B','dependencies':['A']},{'id':'C'}]
  results,blocked=S.run_cases(cases,runner,capacity=2)
  self.assertEqual('fail',results['A']['status']); self.assertIn('B',blocked); self.assertEqual('pass',results['C']['status'])
 def test_nested_depth_forces_one(self):
  old=os.environ.get('FN_ACCEPTANCE_NESTED_DEPTH'); os.environ['FN_ACCEPTANCE_NESTED_DEPTH']='2'
  try: self.assertEqual(1,S.worker_capacity())
  finally:
   if old is None: os.environ.pop('FN_ACCEPTANCE_NESTED_DEPTH',None)
   else: os.environ['FN_ACCEPTANCE_NESTED_DEPTH']=old
if __name__=='__main__': unittest.main()


class ControllerAcceptanceTests(unittest.TestCase):
 def test_successful_predecessor_is_not_prematurely_blocked(self):
  results,blocked=S.run_cases([{'id':'A'},{'id':'B','dependencies':['A']}],lambda case:{'status':'pass'},capacity=1)
  self.assertNotIn('B',blocked,'successful predecessor must actually execute before dependant is decided')
  self.assertEqual('pass',results['B']['status'])
 def test_safe_names_do_not_override_shared_resource(self):
  active=0; maximum=0; lock=threading.Lock()
  def runner(case):
   nonlocal active,maximum
   with lock:active+=1;maximum=max(maximum,active)
   time.sleep(.08)
   with lock:active-=1
   return {'status':'pass'}
  cases=[{'id':name,'resources':['shared-file']} for name in ('CORE-TLSHELLO','CORE-DUALPCAP-WRITER')]
  S.run_cases(cases,runner,capacity=2)
  self.assertEqual(1,maximum,'explicit shared resource must remain exclusive')
 def test_worker_exception_keeps_independent_result(self):
  def runner(case):
   if case['id']=='CORE-TLSHELLO':raise RuntimeError('owned fixture failure')
   return {'status':'pass'}
  results,blocked=S.run_cases([{'id':'CORE-TLSHELLO'},{'id':'CORE-DUALPCAP-WRITER'}],runner,capacity=2)
  self.assertEqual('pass',results['CORE-DUALPCAP-WRITER']['status'])
  self.assertNotEqual('pass',results['CORE-TLSHELLO']['status'])
 def test_parent_sets_nested_depth_and_keeps_product_import_priority(self):
  import acceptance as A
  from unittest import mock
  with mock.patch.dict(os.environ,{'FN_ACCEPTANCE_NESTED_DEPTH':'0','PYTHONPATH':'/tmp/fixture-untrusted-import'}):
   env=A._python_env(ROOT,ROOT/'Logs/unused-fixture-temp')
  self.assertGreater(int(env.get('FN_ACCEPTANCE_NESTED_DEPTH','0')),0,'child launch must increment nested depth')
  self.assertEqual(str(ROOT),env['PYTHONPATH'].split(os.pathsep)[0])
 def test_scheduler_tests_are_selected_not_merely_hashed(self):
  import json
  catalog=json.loads((ROOT/'docs/acceptance/catalog.json').read_text())
  case=next(x for suite in catalog['suites'] for x in suite.get('cases',[]) if x['id']=='CORE-ACCEPTANCE-SELFTEST')
  modules=case['input'].get('modules',[]) or [case['input'].get('module')]
  self.assertIn('test/test_acceptance_scheduler.py',modules)
 def test_public_cli_successful_dependency_and_independent_judge(self):
  import json,tempfile,importlib.util
  from unittest import mock
  spec=importlib.util.spec_from_file_location('controller_scheduler_fixture',ROOT/'test/test_acceptance_regression.py');F=importlib.util.module_from_spec(spec);spec.loader.exec_module(F)
  root=Path(tempfile.mkdtemp(prefix='controller-dependency-'));F.make_root(root)
  path=root/'docs/acceptance/catalog.json';catalog=F.read_json(path)
  catalog['suites'][0]['cases']=[F.case_record(name,'FIX-OFFLINE','test/test_fixture_module.py') for name in ('A','B','C')]
  catalog['suites'][0]['cases'][1]['dependencies']=['A'];F.write_json(path,catalog)
  original=F.ACC._python_env
  def guarded(*args):
   env=original(*args);guard=active_test_guard()
   env['PYTHONPATH']=(guard+os.pathsep if guard else '')+env['PYTHONPATH'];return env
  with mock.patch.object(F.ACC,'_python_env',guarded):
   code,plan,out,err=F.plan(root,'selected','--case','A','--case','B','--case','C');self.assertEqual(0,code,err)
   code,out,err=F.execute(root,plan)
   (root/'controller-verdict.json').write_text(json.dumps({'execute_rc':code,'stdout':out,'stderr':err}))
   self.assertEqual(0,code,err+out)
   code,out,err=F.judge(root,plan,plan.parent/'results',plan.parent/'controller-judge.json');self.assertEqual(0,code,err+out)
 def test_timeout_does_not_leave_owned_descendant_running(self):
  import json,tempfile,importlib.util
  from unittest import mock
  spec=importlib.util.spec_from_file_location('controller_scheduler_timeout_fixture',ROOT/'test/test_acceptance_regression.py');F=importlib.util.module_from_spec(spec);spec.loader.exec_module(F)
  root=Path(tempfile.mkdtemp(prefix='controller-timeout-'));F.make_root(root)
  marker=root/'descendant-survived.json'
  child="import time,pathlib;time.sleep(2.5);pathlib.Path("+repr(str(marker))+").write_text('owned bounded descendant survived timeout')"
  module="import subprocess,sys,time\ndef test_owned_timeout():\n subprocess.Popen([sys.executable,'-B','-c',"+repr(child)+"],start_new_session=True)\n time.sleep(10)\n"
  (root/'test/test_fixture_module.py').write_text(module)
  path=root/'docs/acceptance/catalog.json';catalog=F.read_json(path);catalog['suites'][0]['cases'][0]['timeout']=1;F.write_json(path,catalog)
  original=F.ACC._python_env
  def guarded(*args):
   env=original(*args);guard=active_test_guard()
   env['PYTHONPATH']=(guard+os.pathsep if guard else '')+env['PYTHONPATH'];return env
  with mock.patch.object(F.ACC,'_python_env',guarded):
   code,plan,out,err=F.plan(root,'selected','--case','FIX-PASS');self.assertEqual(0,code,err)
   code,out,err=F.execute(root,plan);self.assertNotEqual(0,code)
  # The fixed benign child self-terminates. Wait before asserting, so a failing
  # test itself leaves no running child and preserves the direct marker proof.
  time.sleep(3)
  (root/'controller-timeout-verdict.json').write_text(json.dumps({'execute_rc':code,'marker_exists':marker.exists()}))
  self.assertFalse(marker.exists(),'owned descendant survived the adapter timeout')


class CliScheduleCompletionTests(unittest.TestCase):
    def fixture(self, native=False):
        import importlib.util
        import tempfile
        source = ROOT / 'test' / ('test_acceptance_native.py' if native else 'test_acceptance_regression.py')
        spec = importlib.util.spec_from_file_location('s3_completion_' + source.stem, source)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        root = Path(tempfile.mkdtemp(prefix='controller-schedule-'))
        module.make_root(root)
        return module, root

    def guarded_environment(self, entry):
        from unittest import mock
        original = entry._python_env
        def boundary(*args):
            env = original(*args)
            path = active_test_guard()
            env['PYTHONPATH'] = (path + os.pathsep if path else '') + env['PYTHONPATH']
            return env
        return mock.patch.object(entry, '_python_env', boundary)

    def test_real_public_cli_parallel_intervals_stable_index_and_missing_original(self):
        import json
        F, root = self.fixture()
        ids = ['CORE-TLSHELLO', 'CORE-DUALPCAP-WRITER']
        parallel = S.worker_capacity() > 1
        catalog_path = root / 'docs/acceptance/catalog.json'
        catalog = F.read_json(catalog_path)
        cases = []
        for index, cid in enumerate(ids):
            name = 'test/test_pair_%d.py' % index
            other = root / ('start-%d.json' % (1 - index))
            start = root / ('start-%d.json' % index)
            end = root / ('end-%d.json' % index)
            body = ('import json,time,os\nfrom pathlib import Path\n'
                    'def test_owned_pair():\n'
                    ' Path(%r).write_text(json.dumps({"time":time.monotonic(),"pid":os.getpid()}))\n'
                    ' deadline=time.monotonic()+3\n'
                    ' while %r and not Path(%r).exists() and time.monotonic()<deadline:time.sleep(.01)\n'
                    ' assert not %r or Path(%r).exists(),"other actual CLI worker was never admitted"\n'
                    ' time.sleep(.08)\n'
                    ' Path(%r).write_text(json.dumps({"time":time.monotonic()}))\n') % (str(start), parallel, str(other), parallel, str(other), str(end))
            (root / name).write_text(body)
            cases.append(F.case_record(cid, 'FIX-OFFLINE', name))
        catalog['suites'][0]['cases'] = cases + [F.case_record('FIX-ERROR', 'FIX-OFFLINE', 'test/test_pair_0.py')]
        F.write_json(catalog_path, catalog)
        with self.guarded_environment(F.ACC):
            code, plan, out, err = F.plan(root, 'selected', '--case', ids[0], '--case', ids[1])
            self.assertEqual(0, code, err)
            code, out, err = F.execute(root, plan)
            self.assertEqual(0, code, err + out)
            code, out, err = F.judge(root, plan, plan.parent / 'results', plan.parent / 'independent.json')
            self.assertEqual(0, code, err + out)
        starts = [F.read_json(root / ('start-%d.json' % i)) for i in range(2)]
        ends = [F.read_json(root / ('end-%d.json' % i)) for i in range(2)]
        self.assertNotEqual(starts[0]['pid'], starts[1]['pid'])
        if parallel:
            self.assertLess(max(row['time'] for row in starts), min(row['time'] for row in ends))
        else:
            self.assertLessEqual(ends[0]['time'], starts[1]['time'])
        index = F.read_json(plan.parent / 'results/results.json')
        self.assertEqual(ids, [row['case_id'] for row in index['receipts']])
        summary = F.read_json(plan.parent / 'independent.json')
        self.assertFalse(summary['full_functional_pass'])
        for cid in ids:
            observation = F.read_json(plan.parent / 'results' / cid / 'process.json')
            self.assertTrue(observation['tree_exited'])
            self.assertEqual([], [row for row in observation['final_members'] if row['state'] not in ('Z', 'X')])
        # Keep original success and use an independent copy for a rehashed lie.
        copy = F.copy_results(plan.parent / 'results')
        receipt_path = F.receipt_path(copy, ids[0])
        receipt = F.read_json(receipt_path)
        receipt['artifacts'] = [row for row in receipt['artifacts'] if not row['path'].endswith('/process.json')]
        F.write_json(receipt_path, receipt)
        F.update_index(copy)
        code, out, err = F.judge(root, plan, copy, plan.parent / 'missing-process.json')
        self.assertNotEqual(0, code)
        bad = F.read_json(plan.parent / 'missing-process.json')
        self.assertIn('owned process observation missing', json.dumps(bad))
        # A real CLI run whose OS launch fails must still close its original
        # error and unique index; it must not silently become a product pass.
        from unittest import mock
        with self.guarded_environment(F.ACC):
            error_plan = root / 'Logs/error-run/plan.json'
            code, out, err = F.run_cli(root, 'plan', '--mode', 'selected', '--case', 'FIX-ERROR',
                                      '--candidate', str(root / 'candidate.json'),
                                      '--environment', str(root / 'environment.json'),
                                      '--output', str(error_plan))
            self.assertEqual(0, code, err)
            from types import SimpleNamespace
            backend = SimpleNamespace(**vars(S.subprocess))
            backend.Popen = mock.Mock(side_effect=OSError('owned fixture launch rejected'))
            # Fail the scheduler's OS launch only; keep source identity Git real.
            with mock.patch.object(S, 'subprocess', backend):
                code, out, err = F.execute(root, error_plan)
            self.assertEqual(3, code, err + out)
            failed = F.read_json(error_plan.parent / 'summary.json')
            self.assertEqual('OSError', failed['errors'][0]['type'])
            self.assertIn('owned fixture launch rejected', failed['errors'][0]['message'])
            self.assertEqual(['FIX-ERROR'], [row['case_id'] for row in F.read_json(error_plan.parent / 'results/results.json')['receipts']])

    def test_public_cli_replays_native_recovery_before_same_target_block_and_independent_continue(self):
        import json
        from unittest import mock
        N, root = self.fixture(native=True)
        F, A = N.FIXTURE, N.ACC
        A.acceptance_native = N.NATIVE
        table = {'mcp-fixture': N.fixture_driver(), 'fixture-native': N.fixture_driver()}
        catalog_path = root / 'docs/acceptance/catalog.json'
        catalog = F.read_json(catalog_path)
        cases = []
        for cid, driver, resource in [('BAD-A', 'mcp-fixture', 'windows-vm'),
                                      ('SAME-A', 'mcp-fixture', 'vm'),
                                      ('OTHER-B', 'fixture-native', 'linux-vm')]:
            case = F.case_record(cid, 'FIX-NATIVE', 'test/fixture_native_driver.py', adapter='native', safe=False)
            case.update(native_driver=driver, oracle={'kind': 'native-json'}, resources=[resource])
            cases.append(case)
        catalog['suites'][1]['cases'] = cases
        F.write_json(catalog_path, catalog)
        environment_path = root / 'environment.json'
        env = F.read_json(environment_path)
        env['targets'] = ['windows', 'linux']
        env['mcp'] = {'target': {'platform': 'windows', 'hostname': 'fixture-a', 'vm_uuid': '11111111-1111-1111-1111-111111111111'}}
        env['native_runtime'] = {'identity': {'platform': 'linux', 'hostname': 'fixture-b'}}
        F.write_json(environment_path, env)
        original = N.NATIVE.run_driver
        calls = []
        def fault_at_receipt_boundary(root, case, plan, directory, python):
            calls.append(case['id'])
            value = original(root, case, plan, directory, python)
            if case['id'] == 'BAD-A':
                # The actual bounded fixture has exited. Deliberately lie in
                # its cleanup claim; the unchanged native judge must reject it.
                value['cleanup']['process_exit']['exited'] = False
            return value
        import contextlib,io
        def cli(*args):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = A.main(['--root', str(root), *map(str, args)])
            return code, out.getvalue(), err.getvalue()
        with mock.patch.object(N.NATIVE, 'driver_table', lambda root: table), \
                mock.patch.object(N.NATIVE, 'run_driver', fault_at_receipt_boundary):
            plan_path = root / 'Logs/native-pair/plan.json'
            code, out, err = cli('plan', '--mode', 'selected',
                                 '--case', 'BAD-A', '--case', 'SAME-A', '--case', 'OTHER-B',
                                 '--candidate', root / 'candidate.json',
                                 '--environment', environment_path, '--output', plan_path)
            self.assertEqual(0, code, err)
            code, out, err = cli('execute', '--plan', plan_path)
            self.assertEqual(2, code, err + out)
            self.assertEqual(['BAD-A', 'OTHER-B'], calls)
            summary = F.read_json(plan_path.parent / 'summary.json')
            by_id = {row['case_id']: row for row in summary['cases']}
            self.assertNotEqual('pass', by_id['BAD-A']['status'])
            self.assertEqual('blocked', by_id['SAME-A']['status'])
            self.assertEqual('pass', by_id['OTHER-B']['status'])
            self.assertIn('BAD-A', by_id['SAME-A']['reason'])
            code, out, err = cli('judge', '--plan', plan_path, '--results', plan_path.parent / 'results',
                                 '--output', plan_path.parent / 'independent.json')
            self.assertEqual(2, code, err + out)
            results = F.copy_results(plan_path.parent / 'results')
            receipt_path = F.receipt_path(results, 'SAME-A')
            receipt = F.read_json(receipt_path)
            receipt['reason'] = 'resource recovery unresolved: OTHER-B'
            F.write_json(receipt_path, receipt)
            F.update_index(results)
            code, out, err = cli('judge', '--plan', plan_path, '--results', results,
                                 '--output', plan_path.parent / 'bad-block.json')
            self.assertEqual(2, code)
            self.assertIn('wrong reason', err)
