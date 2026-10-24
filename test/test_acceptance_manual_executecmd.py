import json,os,sys,tempfile,unittest
from pathlib import Path
from unittest import mock
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import acceptance_manual as M,acceptance_manual_oracles as O,acceptance_native as N
class _Proc:
 pid=43210
class ExecuteCmdTests(unittest.TestCase):
 def setUp(self):
  self.base=Path(os.environ['FN_MANUAL_CHECK_DIR'])/'retained'/self.id().split('.')[-1];self.base.mkdir(parents=True,exist_ok=False)
 def inputs(self,out):
  return {'schema':'fakenet.manual-input.v1','case':'GAP-EXECUTECMD','candidate_id':'cmd-fixture','source_commit':'a'*40,'package_sha256':'b'*64,'execution_id':'cmd-fixture-01','config':str(out/'config'),'owned_root':str(out),'fixture':True}
 def test_real_parser_command_first_session_and_negatives(self):
  out=self.base/'case';inputs=self.inputs(out)
  with mock.patch('subprocess.Popen',return_value=_Proc()) as popen:value=M.run('GAP-EXECUTECMD',out,inputs)
  self.assertEqual(1,popen.call_count)
  args,popen_kwargs=popen.call_args
  self.assertIn('cmd.exe /c echo 1234 benign.exe 192.0.2.10 40000 192.0.2.20 8080',args[0])
  rows,clean,detail=O.evaluate(ROOT,out,'GAP-EXECUTECMD',inputs,allow_fixture=True)
  self.assertTrue(clean,detail);self.assertEqual(['command','first-connection','non-connection'],[x['id'] for x in rows]);self.assertEqual('pass',N._judge_rows(rows,M.CHECKS['GAP-EXECUTECMD'])['verdict'])
 def test_original_negatives_and_tamper(self):
  out=self.base/'bad';inputs=self.inputs(out)
  with mock.patch('subprocess.Popen',return_value=_Proc()):M.run('GAP-EXECUTECMD',out,inputs)
  p=out/'manual-result.json';v=json.loads(p.read_text());v['executecmd']['command']='foreign';p.write_text(json.dumps(v));rows,clean,detail=O.evaluate(ROOT,out,'GAP-EXECUTECMD',inputs,allow_fixture=True);self.assertFalse(clean,detail)
 def test_central_driver_registration(self):
  self.assertEqual('manual-executecmd',N.driver_table(ROOT)['manual-executecmd']['production_kind'])
if __name__=='__main__':unittest.main()

class ControllerExecuteCmdTests(unittest.TestCase):
 inputs=ExecuteCmdTests.inputs
 def setUp(self):
  self.base=Path(os.environ['FN_MANUAL_CHECK_DIR'])/'retained'/self.id().split('.')[-1]
  self.base.mkdir(parents=True,exist_ok=False)
 def test_actual_first_connection_caller_is_reached(self):
  from fakenet.diverters.diverterbase import DiverterBase
  out=self.base/'case';inputs=self.inputs(out)
  with mock.patch.object(DiverterBase,'maybe_redir_port',side_effect=RuntimeError('original first-connection caller reached')):
   with mock.patch('subprocess.Popen',return_value=_Proc()):
    with self.assertRaisesRegex(RuntimeError,'original first-connection caller reached'):M.run('GAP-EXECUTECMD',out,inputs)
 def test_reject_zero_child_identity_and_missing_check_set(self):
  import copy
  out=self.base/'case';inputs=self.inputs(out)
  with mock.patch('subprocess.Popen',return_value=_Proc()):M.run('GAP-EXECUTECMD',out,inputs)
  path=out/'manual-result.json';base=json.loads(path.read_text())
  for fault in ('pid','checks'):
   with self.subTest(fault=fault):
    v=copy.deepcopy(base)
    if fault=='pid':v['executecmd']['executed'][0]['pid']=0
    else:v['checks']=[]
    path.write_text(json.dumps(v));rows,clean,detail=O.evaluate(ROOT,out,'GAP-EXECUTECMD',inputs,allow_fixture=True)
    self.assertFalse(clean,(fault,detail))
 def test_same_central_cli_fixture_and_independent_mutations(self):
  import acceptance as A,contextlib,io,socket,subprocess,copy
  def write(p,v):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(v))
  def cli(*args):
   out,err=io.StringIO(),io.StringIO()
   with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):code=A.main(['--root',str(ROOT),*map(str,args)])
   return code,out.getvalue(),err.getvalue()
  identity={'platform':'linux','hostname':socket.gethostname()}
  write(self.base/'candidate.json',dict(schema=A.CANDIDATE_V2,source_commit=A.git_head(ROOT),deployed_identity=identity,package_sha256='b'*64,offline_fixture=True))
  write(self.base/'environment.json',dict(schema=A.ENVIRONMENT_V2,targets=['host-linux'],interpreters={'python':sys.executable},work_root=str(self.base),allowed_actions=['native'],endpoints=[],auth_refs=[],native_runtime={'transport':'manual-loopback-fixture','identity':identity},manual={'schema':'fakenet.manual-options.v1'}))
  run=self.base/'run';result=cli('plan','--mode','selected','--case','GAP-EXECUTECMD','--candidate',self.base/'candidate.json','--environment',self.base/'environment.json','--output',run/'plan.json');self.assertEqual(0,result[0],result)
  real_popen=subprocess.Popen
  class Child:
   pid=999983
   def __init__(self,code):self.code=code
   def wait(self,timeout=None):return self.code
  def popen(argv,**kwargs):
   if isinstance(argv,list) and argv[0]=='git':return real_popen(argv,**kwargs)
   if isinstance(argv,str):
    self.assertTrue(argv.startswith('cmd.exe /c echo '),argv);return _Proc()
   self.assertEqual(str(ROOT/'tools/acceptance_manual.py'),argv[1]);captured=io.StringIO()
   with contextlib.redirect_stdout(captured):code=M.main(argv[2:])
   kwargs['stdout'].write(captured.getvalue().encode());return Child(code)
  with mock.patch.object(subprocess,'Popen',side_effect=popen):result=cli('execute','--plan',run/'plan.json')
  self.assertEqual(0,result[0],result)
  result=cli('judge','--plan',run/'plan.json','--results',run/'results','--output',run/'independent.json');self.assertEqual(0,result[0],result)
  self.assertFalse(json.loads((run/'independent.json').read_text())['full_functional_pass'])
  path=run/'results/GAP-EXECUTECMD/driver/manual-result.json';base=json.loads(path.read_text())
  for fault in ('identity','command','duplicate','fixture'):
   with self.subTest(fault=fault):
    v=copy.deepcopy(base)
    if fault=='identity':v['identity']['execution_id']='foreign'
    elif fault=='command':v['executecmd']['command']='foreign'
    elif fault=='duplicate':v['executecmd'].pop('duplicate_first_packet')
    else:v.pop('fixture')
    path.write_text(json.dumps(v));result=cli('judge','--plan',run/'plan.json','--results',run/'results','--output',run/(fault+'-rejected.json'));self.assertNotEqual(0,result[0],(fault,result))


class ControllerExecuteCmdBoundaryTests(unittest.TestCase):
 setUp=ControllerExecuteCmdTests.setUp
 inputs=ExecuteCmdTests.inputs
 def test_original_os_arguments_are_recorded_and_bounded(self):
  out=self.base/'case';inputs=self.inputs(out)
  with mock.patch('subprocess.Popen',return_value=_Proc()) as popen:M.run('GAP-EXECUTECMD',out,inputs)
  self.assertEqual(1,popen.call_count);args,options=popen.call_args
  self.assertEqual('cmd.exe /c echo 1234 benign.exe 192.0.2.10 40000 192.0.2.20 8080',args[0])
  self.assertEqual({'creationflags','shell','close_fds','preexec_fn'},set(options))
  self.assertEqual(0,options['creationflags']);self.assertIs(True,options['shell']);self.assertIs(True,options['close_fds']);self.assertTrue(callable(options['preexec_fn']))
  (out/'os-fixture-observation.json').write_text(json.dumps({'command':args[0],'shell':options['shell'],'close_fds':options['close_fds'],'creationflags':options['creationflags'],'preexec_name':options['preexec_fn'].__name__,'fixture':True,'actual_child_executed':False}))
 def test_same_wrong_duplicate_trigger_is_rejected(self):
  from fakenet.diverters.diverterbase import DiverterBase
  original=DiverterBase.maybe_redir_port
  def duplicate_bug(obj,crit,pkt,pid,comm):
   repeated=not crit.first_packet_new_session;original(obj,crit,pkt,pid,comm)
   if repeated:obj.maybeExecuteCmd(pkt,pid,comm)
  out=self.base/'case';inputs=self.inputs(out)
  with mock.patch.object(DiverterBase,'maybe_redir_port',duplicate_bug):
   with mock.patch('subprocess.Popen',return_value=_Proc()):M.run('GAP-EXECUTECMD',out,inputs)
  rows,clean,detail=O.evaluate(ROOT,out,'GAP-EXECUTECMD',inputs,allow_fixture=True)
  self.assertFalse(clean,detail);self.assertIn('original first/duplicate/nontrigger action sequence differs',detail['failures'])
  (out/'duplicate-bug-rejected.json').write_text(json.dumps(detail))
