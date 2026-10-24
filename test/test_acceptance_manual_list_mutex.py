import contextlib,io,json,os,socket,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import acceptance as A
import acceptance_manual as M,acceptance_manual_oracles as O,acceptance_native as N
class ListMutexTests(unittest.TestCase):
 def setUp(self):
  self.base=Path(os.environ.get('FN_MANUAL_CHECK_DIR',str(ROOT/'Logs'/'manual-list-mutex-tests')))/'retained'/self.id().split('.')[-1]
  self.base.mkdir(parents=True,exist_ok=False)
 def inputs(self,out):
  return {'schema':'fakenet.manual-input.v1','case':'GAP-LIST-MUTEX','candidate_id':'list-fixture','source_commit':'a'*40,'package_sha256':'b'*64,'execution_id':'list-fixture-01','config':str(out/'config'),'owned_root':str(out),'fixture':True}
 def test_real_listener_meta_black_white_and_mutex(self):
  out=self.base/'case';inputs=self.inputs(out);value=M.run('GAP-LIST-MUTEX',out,inputs)
  rows,clean,detail=O.evaluate(ROOT,out,'GAP-LIST-MUTEX',inputs,allow_fixture=True)
  self.assertTrue(clean,detail);self.assertEqual(['blacklist','whitelist','mutex'],[x['id'] for x in rows]);self.assertTrue(N._judge_rows(rows,M.CHECKS['GAP-LIST-MUTEX'])['verdict']=='pass')
 def test_tampered_observation_is_rejected(self):
  out=self.base/'bad';inputs=self.inputs(out);M.run('GAP-LIST-MUTEX',out,inputs);p=out/'manual-result.json';v=json.loads(p.read_text());v['list_mutex']['observations'][0]['hit']=False;p.write_text(json.dumps(v));rows,clean,detail=O.evaluate(ROOT,out,'GAP-LIST-MUTEX',inputs,allow_fixture=True);self.assertFalse(clean,detail)

 def test_central_driver_registration(self):
  self.assertEqual('manual-list-mutex',N.driver_table(ROOT)['manual-list-mutex']['production_kind'])
  catalog=json.loads((ROOT/'docs/acceptance/catalog.json').read_text());row=next(c for s in catalog['suites'] for c in s.get('cases') or [] if c['id']=='GAP-LIST-MUTEX');self.assertEqual('manual-list-mutex',row['native_driver'])
 def test_same_central_cli_fixture(self):
  from unittest import mock
  import subprocess
  def write(p,v):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(v))
  def cli(*args):
   out,err=io.StringIO(),io.StringIO()
   with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):code=A.main(['--root',str(ROOT),*map(str,args)])
   return code,out.getvalue(),err.getvalue()
  identity={'platform':'linux','hostname':socket.gethostname()}
  write(self.base/'candidate.json',dict(schema=A.CANDIDATE_V2,source_commit=A.git_head(ROOT),deployed_identity=identity,package_sha256='b'*64,offline_fixture=True))
  write(self.base/'environment.json',dict(schema=A.ENVIRONMENT_V2,targets=['host-linux'],interpreters={'python':sys.executable},work_root=str(self.base),allowed_actions=['native'],endpoints=[],auth_refs=[],native_runtime={'transport':'manual-loopback-fixture','identity':identity},manual={'schema':'fakenet.manual-options.v1'}))
  run=self.base/'run'
  result=cli('plan','--mode','selected','--case','GAP-LIST-MUTEX','--candidate',self.base/'candidate.json','--environment',self.base/'environment.json','--output',run/'plan.json')
  self.assertEqual(0,result[0],result)
  real_popen=subprocess.Popen
  class Child:
   pid=999983
   def __init__(self,code):self.code=code
   def wait(self,timeout=None):return self.code
  def popen(argv,**kwargs):
   if argv[0]=='git':return real_popen(argv,**kwargs)
   self.assertEqual(str(ROOT/'tools/acceptance_manual.py'),argv[1])
   captured=io.StringIO()
   with contextlib.redirect_stdout(captured):code=M.main(argv[2:])
   kwargs['stdout'].write(captured.getvalue().encode())
   return Child(code)
  with mock.patch.object(subprocess,'Popen',side_effect=popen):result=cli('execute','--plan',run/'plan.json')
  self.assertEqual(0,result[0],result)
  result=cli('judge','--plan',run/'plan.json','--results',run/'results','--output',run/'independent.json')
  self.assertEqual(0,result[0],result)
  self.assertFalse(json.loads((run/'independent.json').read_text())['full_functional_pass'])
  path=run/'results/GAP-LIST-MUTEX/driver/manual-result.json';value=json.loads(path.read_text());value['identity']['execution_id']='foreign';path.write_text(json.dumps(value))
  result=cli('judge','--plan',run/'plan.json','--results',run/'results','--output',run/'rejected.json')
  self.assertNotEqual(0,result[0],result)

class ControllerMutexTruthTests(unittest.TestCase):
 setUp=ListMutexTests.setUp
 inputs=ListMutexTests.inputs
 def test_original_mutex_records_ports_cleanup_and_fixture_are_required(self):
  for fault in ('mutex','ports','cleanup','fixture'):
   with self.subTest(fault=fault):
    out=self.base/fault;inputs=self.inputs(out);M.run('GAP-LIST-MUTEX',out,inputs)
    path=out/'manual-result.json';v=json.loads(path.read_text())
    if fault=='mutex':v['list_mutex']['mutex']=[{'kind':'host','error':None}]*2
    elif fault=='ports':v['list_mutex']['ports']=[1,2,3,4]
    elif fault=='cleanup':v.pop('cleanup')
    else:v.pop('fixture')
    path.write_text(json.dumps(v))
    try:rows,clean,detail=O.evaluate(ROOT,out,'GAP-LIST-MUTEX',inputs,allow_fixture=fault!='fixture')
    except ValueError:continue
    self.assertFalse(clean,(fault,detail))
 def test_real_configuration_original_is_retained(self):
  out=self.base/'config';inputs=self.inputs(out);M.run('GAP-LIST-MUTEX',out,inputs)
  self.assertTrue((out/'config/list-mutex.ini').is_file(),'real parser configuration must be retained')


class ListMutexAdditionalTests(unittest.TestCase):
 setUp=ListMutexTests.setUp
 inputs=ListMutexTests.inputs
 def test_oracle_rejects_wrong_protocol_missing_query_and_bad_mutex_state(self):
  import copy
  out=self.base/'neg';inputs=self.inputs(out);M.run('GAP-LIST-MUTEX',out,inputs)
  base=json.loads((out/'manual-result.json').read_text())
  for mutation in ('protocol','missing-negative','mutex'):
   with self.subTest(mutation=mutation):
    v=copy.deepcopy(base)
    if mutation=='protocol':v['list_mutex']['queries'][0]['protocol']='UDP';v['list_mutex']['queries'][0]['result']=True
    elif mutation=='missing-negative':v['list_mutex']['queries'].pop(1)
    else:
     v['list_mutex']['mutex'][0]['error']={'type':'ListenerBlackWhiteList','message':''};v['list_mutex']['mutex'][0]['process_cleared']=False;v['list_mutex']['mutex'][0]['host_cleared']=False
    (out/'manual-result.json').write_text(json.dumps(v))
    rows,clean,detail=O.evaluate(ROOT,out,'GAP-LIST-MUTEX',inputs,allow_fixture=True)
    self.assertFalse(clean,detail)
    reason='original mutex records missing/duplicate/foreign/error mismatch' if mutation=='mutex' else 'original list observations disagree'
    self.assertIn(reason,detail['failures'])
    (out/('rejected-'+mutation+'.json')).write_text(json.dumps(detail))
  (out/'manual-result.json').write_text(json.dumps(base))
 def test_parser_conflict_requires_exit_and_empty_ports(self):
  out=self.base/'parser';inputs=self.inputs(out);M.run('GAP-LIST-MUTEX',out,inputs)
  v=json.loads((out/'manual-result.json').read_text());v['list_mutex']['parser_conflicts'][0]['registered_ports']=[8099];(out/'manual-result.json').write_text(json.dumps(v))
  rows,clean,detail=O.evaluate(ROOT,out,'GAP-LIST-MUTEX',inputs,allow_fixture=True);self.assertFalse(clean,detail)
  self.assertIn('original parser conflict observations differ',detail['failures'])
  (out/'rejected-parser.json').write_text(json.dumps(detail))

 def test_same_wrong_production_cleanup_is_independently_rejected(self):
  from unittest import mock
  from fakenet.diverters.diverterbase import ListenerMeta,ListenerBlackWhiteList
  original=ListenerMeta._validateBlackWhite
  def broken_cleanup(meta):
   process=bool(meta.proc_wl and meta.proc_bl)
   try:original(meta)
   except ListenerBlackWhiteList:
    if process:meta.proc_wl=['b.exe'];meta.proc_bl=['a.exe']
    else:meta.host_wl=['b.test'];meta.host_bl=['a.test']
    raise
  out=self.base/'same-wrong';inputs=self.inputs(out)
  with mock.patch.object(ListenerMeta,'_validateBlackWhite',broken_cleanup):
   M.run('GAP-LIST-MUTEX',out,inputs)
   rows,clean,detail=O.evaluate(ROOT,out,'GAP-LIST-MUTEX',inputs,allow_fixture=True)
  self.assertFalse(clean,detail)
  self.assertIn('mutex lists not cleared by original production path',detail['failures'])
  self.assertNotIn('original mutex records missing/duplicate/foreign/error mismatch',detail['failures'])
  self.assertEqual(2,detail['failures'].count('mutex lists not cleared by original production path'))
  self.assertEqual('fail',N._judge_rows(rows,M.CHECKS['GAP-LIST-MUTEX'])['verdict'])
  (out/'same-wrong-oracle.json').write_text(json.dumps(detail))

if __name__=='__main__':unittest.main()
