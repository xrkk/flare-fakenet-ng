import contextlib,io,json,os,socket,sys,tempfile,unittest
from unittest import mock
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import acceptance_manual as M,acceptance_manual_oracles as O,acceptance_native as N
class DumpPacketsTests(unittest.TestCase):
 def setUp(self):
  self.base=Path(os.environ['FN_MANUAL_CHECK_DIR'])/'retained'/self.id().split('.')[-1];self.base.mkdir(parents=True,exist_ok=False)
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
  v['dumppackets']['disabled']['pcap_files']=[];path.write_text(json.dumps(v))
  for name in ('seal','config','packet','missing-disabled','fake-cleanup','prefix'):
   with self.subTest(central=name):
    saved=path.read_bytes();target=None;old=None
    if name=='seal':target=next((path.parent/'enabled').glob('*.capture-originals.json'));old=target.read_bytes();target.write_bytes(b'{}')
    elif name=='config':target=path.parent/'config/enabled.ini';old=target.read_bytes();target.write_text('[Diverter]\nDumpPackets: No\n')
    elif name=='packet':target=path.parent/'packet-0.bin';old=target.read_bytes();target.write_bytes(b'wrong')
    else:
     changed=json.loads(saved)
     if name=='missing-disabled':del changed['dumppackets']['disabled']
     elif name=='fake-cleanup':changed['cleanup']['scope']='whole-system'
     elif name=='prefix':changed['dumppackets']['enabled']['prefix']='foreign'
     path.write_text(json.dumps(changed))
    try:
     result=cli('judge','--plan',run/'plan.json','--results',run/'results','--output',run/('reject-'+name+'.json'));self.assertNotEqual(0,result[0],result)
    finally:
     path.write_bytes(saved)
     if target is not None:target.write_bytes(old)


 def test_real_parser_and_failure_close(self):
  from fakenet.diverters.diverterbase import DiverterBase
  from fakenet.diverters.pcapwriter import DualPcapWriter
  seen=[];parse=DiverterBase.parse_diverter_config;close=DualPcapWriter.close
  def observed(obj):seen.append(dict(obj._dict));return parse(obj)
  def closed(obj,*args,**kw):seen.append('closed');return close(obj,*args,**kw)
  out=self.base/'normal'
  with mock.patch.object(DiverterBase,'parse_diverter_config',observed):M.run('GAP-DUMPPACKETS',out,self.inputs(out))
  self.assertEqual(['yes','no'],[x['dumppackets'].lower() for x in seen])
  seen.clear();out=self.base/'failure'
  with mock.patch.object(DualPcapWriter,'write_ip_packet',side_effect=RuntimeError('injected writer failure')),mock.patch.object(DualPcapWriter,'close',closed):
   value=M.run('GAP-DUMPPACKETS',out,self.inputs(out))
  self.assertIn('closed',seen)
  rows,clean,detail=O.evaluate(ROOT,out,'GAP-DUMPPACKETS',self.inputs(out),allow_fixture=True);self.assertFalse(clean,detail)
 def test_independent_original_mutations(self):
  mutations=('config','seed','seal','disabled-disk','prefix','checks','before','outside','fixture','identity','content','direction','fake-cleanup')
  for name in mutations:
   with self.subTest(name=name):
    out=self.base/name;inputs=self.inputs(out);value=M.run('GAP-DUMPPACKETS',out,inputs);p=out/'manual-result.json';v=json.loads(p.read_text());en=v['dumppackets']['enabled']
    if name=='config':Path(en['config']).write_text('[Diverter]\nDumpPackets: No\nDumpPacketsFilePrefix: ignored\n')
    elif name=='seed':(out/'packet-0.bin').write_bytes(b'changed')
    elif name=='seal':next((out/'enabled').glob('*.capture-originals.json')).unlink()
    elif name=='disabled-disk':(out/'disabled/hidden.pcap').write_bytes(b'undeclared')
    elif name=='prefix':en['prefix']=str(out/'wrong-prefix')
    elif name=='checks':v['checks']=[]
    elif name=='before':en['before']=5
    elif name=='outside':en['folder']=str(self.base/'foreign')
    elif name=='fixture':v['fixture']=False
    elif name=='identity':v['identity']['execution_id']='foreign-id'
    elif name=='direction':
     journal=next((out/'enabled').glob('*.observations.ndjson'));journal.write_bytes(journal.read_bytes().replace(b'inbound',b'outbound'))
    elif name=='fake-cleanup':v['cleanup']['scope']='whole-system'
    elif name=='content':
     raw=next(x for x in (out/'enabled').glob('*.pcap') if not x.name.endswith('-converted.pcap'));raw.write_bytes(raw.read_bytes()[:-1]+b'X')
    p.write_text(json.dumps(v));rows,clean,detail=O.evaluate(ROOT,out,'GAP-DUMPPACKETS',inputs,allow_fixture=True);self.assertFalse(clean,detail);self.assertTrue(detail['failures'],detail);self.assertNotEqual('pass',N._judge_rows(rows,M.CHECKS['GAP-DUMPPACKETS'])['verdict'])
 def test_same_wrong_writer_and_seed_rejected(self):
  from fakenet.diverters.pcapwriter import DualPcapWriter
  original=DualPcapWriter.write_ip_packet
  def wrong(writer,packet):return original(writer,packet[:-1]+b'X')
  out=self.base/'wrong';inputs=self.inputs(out)
  with mock.patch.object(DualPcapWriter,'write_ip_packet',wrong):M.run('GAP-DUMPPACKETS',out,inputs)
  (out/'packet-0.bin').write_bytes((out/'packet-0.bin').read_bytes()[:-1]+b'X')
  rows,clean,detail=O.evaluate(ROOT,out,'GAP-DUMPPACKETS',inputs,allow_fixture=True);self.assertFalse(clean,detail)

 def test_central_driver_registration(self):
  self.assertEqual('manual-dumppackets',N.driver_table(ROOT)['manual-dumppackets']['production_kind'])
if __name__=='__main__':unittest.main()
