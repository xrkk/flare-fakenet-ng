import hashlib
import contextlib
import io
import json
import os
import socket
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import acceptance_manual as M
import acceptance_manual_oracles as O
import acceptance_native as N
NAMES=['DNSListener','HTTPListener','FTPListener','IRCListener','POPListener','SMTPListener','RawListener','TFTPListener','ProxyListener']
class StandaloneTests(unittest.TestCase):
 def setUp(self):
  self.base=Path(os.environ['FN_MANUAL_CHECK_DIR'])/'retained'/self.id().split('.')[-1];self.base.mkdir(parents=True,exist_ok=False)
 def inputs(self,out):
  return {'schema':'fakenet.manual-input.v1','case':'GAP-STANDALONE-LISTENERS','candidate_id':'standalone-fixture','source_commit':'a'*40,'package_sha256':'b'*64,'execution_id':'standalone-01','config':str(out/'config'),'owned_root':str(out),'fixture':True}
 def produce(self,out):inputs=self.inputs(out);return inputs,M.run('GAP-STANDALONE-LISTENERS',out,inputs)
 def test_real_nine_standalone_scripts(self):
  out=self.base/'case';inputs,value=self.produce(out);rows,clean,detail=O.evaluate(ROOT,out,'GAP-STANDALONE-LISTENERS',inputs,allow_fixture=True);self.assertTrue(clean,detail);self.assertEqual(['listener-bytes','listener-close'],[r['id'] for r in rows]);self.assertEqual(set(NAMES),set(value['standalone']['scripts']));rows,clean,detail=O.evaluate(ROOT,out,'GAP-STANDALONE-LISTENERS',inputs,allow_fixture=False);self.assertFalse(clean,detail)
 def test_bad_originals_and_close_faults(self):
  out=self.base/'case';inputs,value=self.produce(out);result=out/'manual-result.json';original=result.read_bytes()
  rows,clean,detail=O.evaluate(ROOT,out,'GAP-STANDALONE-LISTENERS',inputs,allow_fixture=True);self.assertTrue(clean,detail)
  def reject(label,changed):
   result.write_text(json.dumps(changed));rows,clean,detail=O.evaluate(ROOT,out,'GAP-STANDALONE-LISTENERS',inputs,allow_fixture=True);self.assertFalse(clean,(label,detail));expected={'owner':'owner original','token':'owner/token','fixture':'fixture identity','checks':'checks mismatch','missing':'nine-script set','entry':'main not called','close':'listener not closed','cleanup':'cleanup/provenance','source':'source binding'};self.assertIn(expected[label],str(detail));result.write_bytes(original)
  variants={'owner':lambda v:v['standalone'].__setitem__('owner_pid',v['standalone']['owner_pid']+1),'token':lambda v:v['standalone'].__setitem__('execution_token','foreign'),'fixture':lambda v:v.__setitem__('fixture',False),'checks':lambda v:v.__setitem__('checks',[]),'missing':lambda v:v['standalone']['scripts'].pop('ProxyListener'),'entry':lambda v:v['standalone']['scripts']['DNSListener'].__setitem__('main_called',False),'close':lambda v:v['standalone']['scripts']['HTTPListener'].__setitem__('thread_alive',True),'cleanup':lambda v:v['cleanup'].__setitem__('stopped',False),'source':lambda v:v['source_hashes'].__setitem__('fakenet/listeners/DNSListener.py','0'*64)}
  for label,change in variants.items():
   with self.subTest(fault=label):
    changed=json.loads(original);change(changed);reject(label,changed)
  for label,path,data in (('request',out/'DNSListener/request.bin',b'bad'),('response',out/'HTTPListener/response.bin',b'bad'),('log',out/'standalone.log',b'bad')):
   with self.subTest(original=label):
    (out/'manual-result.json').write_bytes(original);prior=path.read_bytes();path.write_bytes(data);rows,clean,detail=O.evaluate(ROOT,out,'GAP-STANDALONE-LISTENERS',inputs,allow_fixture=True);self.assertFalse(clean,(label,detail));path.write_bytes(prior)
  for name in NAMES:
   with self.subTest(protocol=name):
    result.write_bytes(original);path=out/name/'response.bin';prior=path.read_bytes();path.write_bytes(b'not-a-valid-protocol');changed=json.loads(original);changed['standalone']['scripts'][name]['response_sha256']=hashlib.sha256(path.read_bytes()).hexdigest();result.write_text(json.dumps(changed));rows,clean,detail=O.evaluate(ROOT,out,'GAP-STANDALONE-LISTENERS',inputs,allow_fixture=True);self.assertFalse(clean,(name,detail));self.assertNotIn('original mismatch',str(detail));path.write_bytes(prior);result.write_bytes(original)
  for file,key,mutate,reason in [('calls.json','calls_sha256',lambda v:[c for c in v if c['function']!='test'],'lifecycle calls missing'),('resources.json','resources_sha256',lambda v:dict(v,threads=[dict(v['threads'][0],alive=True)]),'resource observations not closed')]:
   with self.subTest(lifecycle=file):
    path=out/'DNSListener'/file;prior=path.read_bytes();path.write_text(json.dumps(mutate(json.loads(prior))));changed=json.loads(original);changed['standalone']['scripts']['DNSListener'][key]=hashlib.sha256(path.read_bytes()).hexdigest();result.write_text(json.dumps(changed));rows,clean,detail=O.evaluate(ROOT,out,'GAP-STANDALONE-LISTENERS',inputs,allow_fixture=True);self.assertFalse(clean,detail);self.assertIn(reason,str(detail));path.write_bytes(prior);result.write_bytes(original)
 def test_same_central_cli_and_negative(self):
  import acceptance as A
  def write(p,v):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(v))
  def cli(*args):
   out,err=io.StringIO(),io.StringIO()
   with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):code=A.main(['--root',str(ROOT),*map(str,args)])
   return code,out.getvalue(),err.getvalue()
  identity={'platform':'linux','hostname':socket.gethostname()}
  write(self.base/'candidate.json',dict(schema=A.CANDIDATE_V2,source_commit=A.git_head(ROOT),deployed_identity=identity,package_sha256='b'*64,offline_fixture=True))
  write(self.base/'environment.json',dict(schema=A.ENVIRONMENT_V2,targets=['host-linux'],interpreters={'python':sys.executable},work_root=str(self.base),allowed_actions=['native'],endpoints=[],auth_refs=[],native_runtime={'transport':'manual-loopback-fixture','identity':identity},manual={'schema':'fakenet.manual-options.v1'}))
  real_popen=subprocess.Popen
  class Child:
   pid=999990
   def __init__(self,code):self.code=code
   def wait(self,timeout=None):return self.code
  def popen(argv,**kwargs):
   if isinstance(argv,list) and argv[0]=='git':return real_popen(argv,**kwargs)
   self.assertEqual(str(ROOT/'tools/acceptance_manual.py'),argv[1]);captured=io.StringIO()
   with contextlib.redirect_stdout(captured):code=M.main(argv[2:])
   kwargs['stdout'].write(captured.getvalue().encode());return Child(code)
  run=self.base/'run';result=cli('plan','--mode','selected','--case','GAP-STANDALONE-LISTENERS','--candidate',self.base/'candidate.json','--environment',self.base/'environment.json','--output',run/'plan.json');self.assertEqual(0,result[0],result)
  with mock.patch.object(subprocess,'Popen',side_effect=popen):result=cli('execute','--plan',run/'plan.json')
  self.assertEqual(0,result[0],result)
  result=cli('judge','--plan',run/'plan.json','--results',run/'results','--output',run/'judge.json');self.assertEqual(0,result[0],result);self.assertFalse(json.loads((run/'judge.json').read_text())['full_functional_pass'])
  produced=run/'results'/'GAP-STANDALONE-LISTENERS'/'driver'/'manual-result.json';original=json.loads(produced.read_text());damaged=json.loads(produced.read_text());damaged['standalone']['scripts'].pop('ProxyListener');produced.write_text(json.dumps(damaged));result=cli('judge','--plan',run/'plan.json','--results',run/'results','--output',run/'rejected.json');self.assertNotEqual(0,result[0],result);produced.write_text(json.dumps(original))
 def test_central_registration(self):self.assertEqual('manual-standalone',N.driver_table(ROOT)['manual-standalone']['production_kind'])
if __name__=='__main__':unittest.main()
