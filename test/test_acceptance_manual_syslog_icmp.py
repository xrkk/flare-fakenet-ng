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
def fail_parse(self,*args,**kwargs):
 raise RuntimeError('injected parser failure')

class SyslogTests(unittest.TestCase):
 def setUp(self):
  self.base=Path(os.environ['FN_MANUAL_CHECK_DIR'])/'retained'/self.id().split('.')[-1];self.base.mkdir(parents=True,exist_ok=False)
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
  self.assertEqual(2,len(Path(value['syslog_icmp']['icmp_log']).read_text().splitlines()))

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
  resultpath=run/'results/GAP-SYSLOG-ICMP-LOG/driver/manual-result.json'
  for name in ('config','owner','sink','icmp','cleanup'):
   with self.subTest(central=name):
    saved=resultpath.read_bytes();v=json.loads(saved);d=v['syslog_icmp'];target=None;old=None
    if name in ('config','sink','icmp'):
     target=Path(d[{'config':'config','sink':'syslog_sink','icmp':'icmp_log'}[name]]);old=target.read_bytes();target.write_bytes(b'bad')
    elif name=='owner':v['syslog_icmp']['owner_pid']+=12345;resultpath.write_text(json.dumps(v))
    else:v['cleanup']['scope']='whole-system';resultpath.write_text(json.dumps(v))
    try:
     result=cli('judge','--plan',run/'plan.json','--results',run/'results','--output',run/('rejected-'+name+'.json'));self.assertNotEqual(0,result[0],result)
    finally:
     resultpath.write_bytes(saved)
     if target is not None:target.write_bytes(old)


 def produce(self,out):
  inputs=self.inputs(out)
  with mock.patch('fakenet.fakenet.platform.system',return_value='Linux'),mock.patch('fakenet.fakenet.wait_for_shutdown',return_value=0),mock.patch('logging.handlers.SysLogHandler',side_effect=lambda *a,**k:_Sink()):
   _Sink.target=inputs['syslog_sink'];value=M.run('GAP-SYSLOG-ICMP-LOG',out,inputs)
  return inputs,value
 def test_preserves_caller_logger(self):
  root=logging.getLogger();prior=list(root.handlers);level=root.level;sentinel=logging.NullHandler();root.addHandler(sentinel)
  try:
   self.produce(self.base/'preserve');self.assertEqual(prior+[sentinel],root.handlers);self.assertEqual(level,root.level)
  finally:
   for handler in root.handlers:
    if handler not in prior:handler.close()
   root.handlers=prior;root.setLevel(level)
 def test_independent_bad_originals(self):
  for name in ('config','off-log','sink','icmp-address','owner','checks','cleanup'):
   with self.subTest(name=name):
    out=self.base/name;inputs,value=self.produce(out);p=out/'manual-result.json';v=json.loads(p.read_text());d=v['syslog_icmp']
    if name=='config':Path(d['config']).write_text('[FakeNet]\nDivertTraffic: Yes\n')
    elif name=='off-log':Path(d['main_log_off']).write_text('wrong')
    elif name=='sink':Path(d['syslog_sink']).write_text('FakeNet-NG "levelName" arbitrary garbage\n')
    elif name=='icmp-address':Path(d['icmp_log']).write_text('ICMP type 8 code 0 wrong->wrong\n')
    elif name=='owner':d['owner_pid']+=9999
    elif name=='checks':v['checks']=[]
    elif name=='cleanup':v['cleanup']['stopped']=True;v['syslog_icmp']['handler_closed']=False
    p.write_text(json.dumps(v));rows,clean,detail=O.evaluate(ROOT,out,'GAP-SYSLOG-ICMP-LOG',inputs,allow_fixture=True);self.assertFalse(clean,detail)

 def test_windows_handler_branch_and_fault_restoration(self):
  out=self.base/'windows';inputs=self.inputs(out)
  calls=[]
  def factory(*args,**kwargs):calls.append(args);return _Sink()
  with mock.patch('fakenet.fakenet.platform.system',return_value='Windows'),mock.patch('logging.handlers.NTEventLogHandler',side_effect=factory):
   _Sink.target=inputs['syslog_sink'];value=M.run('GAP-SYSLOG-ICMP-LOG',out,inputs)
  self.assertEqual([('FakeNet-NG',)],calls)
  rows,clean,detail=O.evaluate(ROOT,out,'GAP-SYSLOG-ICMP-LOG',inputs,allow_fixture=True);self.assertTrue(clean,detail)
  from fakenet import fakenet as core
  out=self.base/'failure';inputs=self.inputs(out);prior=list(logging.getLogger().handlers)
  with mock.patch('fakenet.fakenet.platform.system',return_value='Linux'),mock.patch('logging.handlers.SysLogHandler',side_effect=lambda *a,**k:_Sink()),mock.patch.object(core.Fakenet,'parse_config',new=fail_parse):
   _Sink.target=inputs['syslog_sink'];value=M.run('GAP-SYSLOG-ICMP-LOG',out,inputs)
  self.assertEqual(prior,logging.getLogger().handlers)
  rows,clean,detail=O.evaluate(ROOT,out,'GAP-SYSLOG-ICMP-LOG',inputs,allow_fixture=True);self.assertFalse(clean,detail)
 def test_original_icmp_fault_rejected(self):
  from fakenet.diverters.diverterbase import DiverterBase
  out=self.base/'fault';inputs=self.inputs(out)
  with mock.patch.object(DiverterBase,'check_log_icmp',return_value=None):inputs,value=self.produce(out)
  rows,clean,detail=O.evaluate(ROOT,out,'GAP-SYSLOG-ICMP-LOG',inputs,allow_fixture=True);self.assertFalse(clean,detail)

 def test_central_registration(self):
  self.assertEqual('manual-syslog-icmp',N.driver_table(ROOT)['manual-syslog-icmp']['production_kind'])
if __name__=='__main__':unittest.main()
