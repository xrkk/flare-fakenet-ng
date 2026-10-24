import contextlib,io,json,logging,os,socket,sys,tempfile,unittest
from pathlib import Path
from unittest import mock
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import acceptance_manual as M,acceptance_manual_oracles as O,acceptance_native as N
class _Sink(logging.Handler):
 target=None
 def __init__(self,*args,**kwargs):super().__init__()
 def emit(self,record):
  if self.target:
   with open(self.target,'a',encoding='utf-8') as f:f.write(self.format(record)+'\n')
class SyslogTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup);self.base=Path(self.t.name)
 def inputs(self,out):
  return {'schema':'fakenet.manual-input.v1','case':'GAP-SYSLOG-ICMP-LOG','candidate_id':'syslog-fixture','source_commit':'a'*40,'package_sha256':'b'*64,'execution_id':'syslog-fixture-01','config':str(out/'config'),'owned_root':str(out),'syslog_sink':str(out/'syslog.sink'),'fixture':True}
 def test_real_main_syslog_option_and_icmp_parser(self):
  out=self.base/'case';inputs=self.inputs(out);sink=Path(inputs['syslog_sink'])
  def factory(*a,**k):return _Sink()
  with mock.patch('fakenet.fakenet.platform.system',return_value='Linux'),mock.patch('fakenet.fakenet.wait_for_shutdown',return_value=0),mock.patch('logging.handlers.SysLogHandler',side_effect=factory):
   _Sink.target=str(sink);value=M.run('GAP-SYSLOG-ICMP-LOG',out,inputs)
  rows,clean,detail=O.evaluate(ROOT,out,'GAP-SYSLOG-ICMP-LOG',inputs,allow_fixture=True)
  self.assertTrue(clean,detail);self.assertEqual(['syslog','icmp','owner'],[x['id'] for x in rows]);self.assertTrue(sink.read_text())
 def test_tamper_syslog_or_icmp(self):
  out=self.base/'bad';inputs=self.inputs(out);sink=Path(inputs['syslog_sink'])
  def factory(*a,**k):return _Sink()
  with mock.patch('fakenet.fakenet.platform.system',return_value='Linux'),mock.patch('fakenet.fakenet.wait_for_shutdown',return_value=0),mock.patch('logging.handlers.SysLogHandler',side_effect=factory):
   _Sink.target=str(sink);M.run('GAP-SYSLOG-ICMP-LOG',out,inputs)
  p=out/'manual-result.json';v=json.loads(p.read_text());v['syslog_icmp']['icmp_id']=999;p.write_text(json.dumps(v));rows,clean,detail=O.evaluate(ROOT,out,'GAP-SYSLOG-ICMP-LOG',inputs,allow_fixture=True);self.assertFalse(clean,detail)
 def test_real_icmp_negatives(self):
  out=self.base/'neg';inputs=self.inputs(out);sink=Path(inputs['syslog_sink'])
  def factory(*a,**k):return _Sink()
  with mock.patch('fakenet.fakenet.platform.system',return_value='Linux'),mock.patch('fakenet.fakenet.wait_for_shutdown',return_value=0),mock.patch('logging.handlers.SysLogHandler',side_effect=factory):
   _Sink.target=str(sink);value=M.run('GAP-SYSLOG-ICMP-LOG',out,inputs)
  self.assertEqual(1,len(Path(value['syslog_icmp']['icmp_log']).read_text().splitlines()))

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
  run=self.base/'run';result=cli('plan','--mode','selected','--case','GAP-SYSLOG-ICMP-LOG','--candidate',self.base/'candidate.json','--environment',self.base/'environment.json','--output',run/'plan.json');self.assertEqual(0,result[0],result)
  real_popen=subprocess.Popen
  class Child:
   pid=999986
   def __init__(self,code):self.code=code
   def wait(self,timeout=None):return self.code
  def popen(argv,**kwargs):
   if isinstance(argv,list) and argv[0]=='git':return real_popen(argv,**kwargs)
   self.assertEqual(str(ROOT/'tools/acceptance_manual.py'),argv[1]);captured=io.StringIO()
   with contextlib.redirect_stdout(captured):code=M.main(argv[2:])
   kwargs['stdout'].write(captured.getvalue().encode());return Child(code)
  def factory(*a,**k):return _Sink()
  with mock.patch('fakenet.fakenet.platform.system',return_value='Linux'),mock.patch('fakenet.fakenet.wait_for_shutdown',return_value=0),mock.patch('logging.handlers.SysLogHandler',side_effect=factory),mock.patch.object(subprocess,'Popen',side_effect=popen):
   _Sink.target=str(run/'results/GAP-SYSLOG-ICMP-LOG/driver/syslog.sink');result=cli('execute','--plan',run/'plan.json')
  self.assertEqual(0,result[0],result)
  result=cli('judge','--plan',run/'plan.json','--results',run/'results','--output',run/'independent.json');self.assertEqual(0,result[0],result)
  self.assertFalse(json.loads((run/'independent.json').read_text())['full_functional_pass'])

 def test_central_registration(self):
  self.assertEqual('manual-syslog-icmp',N.driver_table(ROOT)['manual-syslog-icmp']['production_kind'])
if __name__=='__main__':unittest.main()
