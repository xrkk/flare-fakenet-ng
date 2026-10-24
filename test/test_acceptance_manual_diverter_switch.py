import json,os,sys,tempfile,unittest
from pathlib import Path
from unittest import mock
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import types
import acceptance_manual as M,acceptance_manual_oracles as O,acceptance_native as N
class _Iface:
 ifaces={'eth0':[]}
 def get_ips(self,version,iface=None):return ['192.0.2.10'] if version==4 else []
class _Backend:
 def __init__(self,*args,**kwargs):self.start_calls=0;self.stop_calls=0
 def start(self):self.start_calls+=1
 def stop(self):self.stop_calls+=1;return True
def _linux_module():
 mod=types.ModuleType('fakenet.diverters.linux');mod.Diverter=_Backend;sys.modules['fakenet.diverters.linux']=mod

class DiverterSwitchTests(unittest.TestCase):
 def setUp(self):
  self.base=Path(os.environ['FN_MANUAL_CHECK_DIR'])/'retained'/self.id().split('.')[-1];self.base.mkdir(parents=True,exist_ok=False)
 def inputs(self,out):
  return {'schema':'fakenet.manual-input.v1','case':'GAP-DIVERTER-SWITCH','candidate_id':'switch-fixture','source_commit':'a'*40,'package_sha256':'b'*64,'execution_id':'switch-fixture-01','config':str(out/'config'),'owned_root':str(out),'fixture':True}
 def test_real_fakenet_on_off_and_idempotent_stop(self):
  out=self.base/'case';inputs=self.inputs(out)
  with mock.patch('fakenet.fakenet.platform.system',return_value='Linux'),mock.patch('fakenet.fakenet.IfaceIpInfo',_Iface),mock.patch.dict(sys.modules,{'fakenet.diverters.linux':types.SimpleNamespace(Diverter=_Backend)}):value=M.run('GAP-DIVERTER-SWITCH',out,inputs)
  rows,clean,detail=O.evaluate(ROOT,out,'GAP-DIVERTER-SWITCH',inputs,allow_fixture=True)
  self.assertTrue(clean,detail);self.assertEqual(['on','off','restore'],[x['id'] for x in rows]);self.assertEqual(1,value['diverter_switch']['on']['after']['stop_calls']);self.assertFalse(value['diverter_switch']['off']['after']['started'])
 def test_tampered_off_or_false_restore_rejected(self):
  out=self.base/'bad';inputs=self.inputs(out)
  with mock.patch('fakenet.fakenet.platform.system',return_value='Linux'),mock.patch('fakenet.fakenet.IfaceIpInfo',_Iface),mock.patch.dict(sys.modules,{'fakenet.diverters.linux':types.SimpleNamespace(Diverter=_Backend)}):M.run('GAP-DIVERTER-SWITCH',out,inputs)
  p=out/'manual-result.json';v=json.loads(p.read_text());v['diverter_switch']['off']['after']['diverter']='Fake';p.write_text(json.dumps(v));rows,clean,detail=O.evaluate(ROOT,out,'GAP-DIVERTER-SWITCH',inputs,allow_fixture=True);self.assertFalse(clean,detail)

 def test_same_central_cli_and_negative(self):
  import acceptance as A,contextlib,io,socket,subprocess,copy
  def write(p,v):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(v))
  def cli(*args):
   out,err=io.StringIO(),io.StringIO()
   with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):code=A.main(['--root',str(ROOT),*map(str,args)])
   return code,out.getvalue(),err.getvalue()
  identity={'platform':'linux','hostname':socket.gethostname()}
  write(self.base/'candidate.json',dict(schema=A.CANDIDATE_V2,source_commit=A.git_head(ROOT),deployed_identity=identity,package_sha256='b'*64,offline_fixture=True))
  write(self.base/'environment.json',dict(schema=A.ENVIRONMENT_V2,targets=['host-linux'],interpreters={'python':sys.executable},work_root=str(self.base),allowed_actions=['native'],endpoints=[],auth_refs=[],native_runtime={'transport':'manual-loopback-fixture','identity':identity},manual={'schema':'fakenet.manual-options.v1'}))
  run=self.base/'run';result=cli('plan','--mode','selected','--case','GAP-DIVERTER-SWITCH','--candidate',self.base/'candidate.json','--environment',self.base/'environment.json','--output',run/'plan.json');self.assertEqual(0,result[0],result)
  real_popen=subprocess.Popen
  class Child:
   pid=999984
   def __init__(self,code):self.code=code
   def wait(self,timeout=None):return self.code
  def popen(argv,**kwargs):
   if isinstance(argv,list) and argv[0]=='git':return real_popen(argv,**kwargs)
   self.assertEqual(str(ROOT/'tools/acceptance_manual.py'),argv[1]);captured=io.StringIO()
   with contextlib.redirect_stdout(captured):code=M.main(argv[2:])
   kwargs['stdout'].write(captured.getvalue().encode());return Child(code)
  with mock.patch('fakenet.fakenet.platform.system',return_value='Linux'),mock.patch('fakenet.fakenet.IfaceIpInfo',_Iface),mock.patch.dict(sys.modules,{'fakenet.diverters.linux':types.SimpleNamespace(Diverter=_Backend)}),mock.patch.object(subprocess,'Popen',side_effect=popen):result=cli('execute','--plan',run/'plan.json')
  self.assertEqual(0,result[0],result)
  result=cli('judge','--plan',run/'plan.json','--results',run/'results','--output',run/'independent.json');self.assertEqual(0,result[0],result)
  self.assertFalse(json.loads((run/'independent.json').read_text())['full_functional_pass'])
  path=run/'results/GAP-DIVERTER-SWITCH/driver/manual-result.json';v=json.loads(path.read_text());v['diverter_switch']['off']['after']['diverter']='Fake';path.write_text(json.dumps(v))
  result=cli('judge','--plan',run/'plan.json','--results',run/'results','--output',run/'rejected.json');self.assertNotEqual(0,result[0],result)

 def test_central_registration(self):
  self.assertEqual('manual-diverter-switch',N.driver_table(ROOT)['manual-diverter-switch']['production_kind'])
if __name__=='__main__':unittest.main()

class ControllerSwitchTruthTests(unittest.TestCase):
 inputs=DiverterSwitchTests.inputs
 def setUp(self):
  self.base=Path(os.environ['FN_MANUAL_CHECK_DIR'])/'retained'/self.id().split('.')[-1];self.base.mkdir(parents=True,exist_ok=False)
 def produce(self,out,backend=_Backend):
  inputs=self.inputs(out)
  with mock.patch('fakenet.fakenet.platform.system',return_value='Linux'),mock.patch('fakenet.fakenet.IfaceIpInfo',_Iface),mock.patch.dict(sys.modules,{'fakenet.diverters.linux':types.SimpleNamespace(Diverter=backend)}):
   value=M.run('GAP-DIVERTER-SWITCH',out,inputs)
  return inputs,value
 def test_first_start_observation_and_exact_check_set_required(self):
  import copy
  out=self.base/'case';inputs,value=self.produce(out);path=out/'manual-result.json'
  for fault in ('start','checks','before'):
   with self.subTest(fault=fault):
    v=copy.deepcopy(value)
    if fault=='start':v['diverter_switch']['on']['start_calls']=0
    elif fault=='checks':v['checks']=[]
    else:v['diverter_switch']['on']['before']['diverttraffic']='no'
    path.write_text(json.dumps(v));rows,clean,detail=O.evaluate(ROOT,out,'GAP-DIVERTER-SWITCH',inputs,allow_fixture=True)
    self.assertFalse(clean,(fault,detail))
 def test_unowned_configuration_must_not_be_accepted(self):
  import shutil
  out=self.base/'case';inputs,value=self.produce(out);other=self.base/'foreign.ini';shutil.copyfile(out/'config/on.ini',other)
  value['diverter_switch']['on']['config']=str(other);(out/'manual-result.json').write_text(json.dumps(value))
  rows,clean,detail=O.evaluate(ROOT,out,'GAP-DIVERTER-SWITCH',inputs,allow_fixture=True);self.assertFalse(clean,detail)
 def test_failed_start_still_stops_owned_backend(self):
  class Failing(_Backend):
   last=None
   def __init__(self,*args,**kwargs):super().__init__(*args,**kwargs);Failing.last=self
   def start(self):super().start();raise RuntimeError('owned start failed')
  out=self.base/'case';inputs,value=self.produce(out,Failing)
  self.assertEqual(1,Failing.last.stop_calls)
  self.assertFalse(value['cleanup']['stopped'])
  rows,clean,detail=O.evaluate(ROOT,out,'GAP-DIVERTER-SWITCH',inputs,allow_fixture=True);self.assertFalse(clean,detail)


class ControllerSwitchBoundaryTests(unittest.TestCase):
 setUp=ControllerSwitchTruthTests.setUp
 inputs=DiverterSwitchTests.inputs
 def test_backend_with_no_test_counter_fields_still_passes(self):
  class Plain:
   def __init__(self,*args,**kwargs):pass
   def start(self):pass
   def stop(self):return True
  out=self.base/'case';inputs=self.inputs(out)
  with mock.patch('fakenet.fakenet.platform.system',return_value='Linux'),mock.patch('fakenet.fakenet.IfaceIpInfo',_Iface),mock.patch.dict(sys.modules,{'fakenet.diverters.linux':types.SimpleNamespace(Diverter=Plain)}):M.run('GAP-DIVERTER-SWITCH',out,inputs)
  rows,clean,detail=O.evaluate(ROOT,out,'GAP-DIVERTER-SWITCH',inputs,allow_fixture=True);self.assertTrue(clean,detail)
 def test_independent_fault_and_missing_branch_are_rejected(self):
  import copy
  out=self.base/'case';inputs=self.inputs(out)
  with mock.patch('fakenet.fakenet.platform.system',return_value='Linux'),mock.patch('fakenet.fakenet.IfaceIpInfo',_Iface),mock.patch.dict(sys.modules,{'fakenet.diverters.linux':types.SimpleNamespace(Diverter=_Backend)}):M.run('GAP-DIVERTER-SWITCH',out,inputs)
  path=out/'manual-result.json';base=json.loads(path.read_text())
  for fault in ('identity','branch','restore','fixture'):
   with self.subTest(fault=fault):
    value=copy.deepcopy(base)
    if fault=='identity':value['identity']['execution_id']='foreign'
    elif fault=='branch':value['diverter_switch'].pop('off')
    elif fault=='restore':value['diverter_switch']['on']['after']['stop1']=False
    else:value.pop('fixture')
    path.write_text(json.dumps(value))
    try:rows,clean,detail=O.evaluate(ROOT,out,'GAP-DIVERTER-SWITCH',inputs,allow_fixture=True)
    except ValueError as exc:detail={'refusal':str(exc)};clean=False
    self.assertFalse(clean,(fault,detail));(out/('rejected-'+fault+'.json')).write_text(json.dumps(detail))
