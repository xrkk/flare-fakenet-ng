import contextlib,io,json,os,socket,sys,tempfile,unittest
from unittest import mock
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import acceptance_manual as M,acceptance_manual_oracles as O,acceptance_native as N
class DumpPacketsTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup);self.base=Path(self.t.name)
 def inputs(self,out):
  return {'schema':'fakenet.manual-input.v1','case':'GAP-DUMPPACKETS','candidate_id':'pcap-fixture','source_commit':'a'*40,'package_sha256':'b'*64,'execution_id':'pcap-fixture-01','config':str(out/'config'),'owned_root':str(out),'fixture':True}
 def test_real_dual_pcap_enabled_disabled_prefix_content(self):
  out=self.base/'case';inputs=self.inputs(out);value=M.run('GAP-DUMPPACKETS',out,inputs)
  rows,clean,detail=O.evaluate(ROOT,out,'GAP-DUMPPACKETS',inputs,allow_fixture=True)
  self.assertTrue(clean,{'failures':detail,'value':value});self.assertEqual(['enabled','disabled','prefix','content'],[x['id'] for x in rows]);self.assertEqual(2,len(value['dumppackets']['enabled']['pcap_files']));self.assertEqual([],value['dumppackets']['disabled']['pcap_files'])
 def test_content_or_disabled_tamper_rejected(self):
  out=self.base/'bad';inputs=self.inputs(out);value=M.run('GAP-DUMPPACKETS',out,inputs)
  p=out/'manual-result.json';v=json.loads(p.read_text());v['dumppackets']['disabled']['pcap_files']=['fake.pcap'];p.write_text(json.dumps(v));rows,clean,detail=O.evaluate(ROOT,out,'GAP-DUMPPACKETS',inputs,allow_fixture=True);self.assertFalse(clean,detail)

 def test_same_central_cli_and_reject(self):
  import acceptance as A,subprocess,copy
  def write(p,v):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(v))
  def cli(*args):
   out,err=io.StringIO(),io.StringIO()
   with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):code=A.main(['--root',str(ROOT),*map(str,args)])
   return code,out.getvalue(),err.getvalue()
  identity={'platform':'linux','hostname':socket.gethostname()}
  write(self.base/'candidate.json',dict(schema=A.CANDIDATE_V2,source_commit=A.git_head(ROOT),deployed_identity=identity,package_sha256='b'*64,offline_fixture=True))
  write(self.base/'environment.json',dict(schema=A.ENVIRONMENT_V2,targets=['host-linux'],interpreters={'python':sys.executable},work_root=str(self.base),allowed_actions=['native'],endpoints=[],auth_refs=[],native_runtime={'transport':'manual-loopback-fixture','identity':identity},manual={'schema':'fakenet.manual-options.v1'}))
  run=self.base/'run';result=cli('plan','--mode','selected','--case','GAP-DUMPPACKETS','--candidate',self.base/'candidate.json','--environment',self.base/'environment.json','--output',run/'plan.json');self.assertEqual(0,result[0],result)
  real_popen=subprocess.Popen
  class Child:
   pid=999985
   def __init__(self,code):self.code=code
   def wait(self,timeout=None):return self.code
  def popen(argv,**kwargs):
   if isinstance(argv,list) and argv[0]=='git':return real_popen(argv,**kwargs)
   self.assertEqual(str(ROOT/'tools/acceptance_manual.py'),argv[1]);captured=io.StringIO()
   with contextlib.redirect_stdout(captured):code=M.main(argv[2:])
   kwargs['stdout'].write(captured.getvalue().encode());return Child(code)
  with mock.patch.object(subprocess,'Popen',side_effect=popen):result=cli('execute','--plan',run/'plan.json')
  self.assertEqual(0,result[0],result)
  result=cli('judge','--plan',run/'plan.json','--results',run/'results','--output',run/'independent.json');self.assertEqual(0,result[0],result)
  self.assertFalse(json.loads((run/'independent.json').read_text())['full_functional_pass'])
  path=run/'results/GAP-DUMPPACKETS/driver/manual-result.json';v=json.loads(path.read_text());v['dumppackets']['disabled']['pcap_files']=['fake.pcap'];path.write_text(json.dumps(v))
  result=cli('judge','--plan',run/'plan.json','--results',run/'results','--output',run/'rejected.json');self.assertNotEqual(0,result[0],result)

 def test_central_driver_registration(self):
  self.assertEqual('manual-dumppackets',N.driver_table(ROOT)['manual-dumppackets']['production_kind'])
if __name__=='__main__':unittest.main()
