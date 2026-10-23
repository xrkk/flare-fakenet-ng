"""Original MCP assertions run against a pure in-memory HTTP transport."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import acceptance_mcp as m
import acceptance_mcp_oracles as o


def inputs_at(root):
 root=Path(root);root.mkdir(parents=True,exist_ok=True)
 package=root/'benign-package.zip'
 body=b'benign candidate test bytes';identity={'candidate_id':'memory-mcp','source_commit':__import__('acceptance').git_head(ROOT),'package_sha256':'','requirements_blob':'b'*40,'master_plan_blob':'c'*40}
 manifest_value={'schema':'fakenet.mcp-candidate-manifest.v1','source_commit':identity['source_commit'],'files':[{'path':'fakenetng-mcp.exe','sha256':hashlib.sha256(body).hexdigest(),'size':len(body)}]}
 manifest=root/'manifest.json';manifest.write_text(json.dumps(manifest_value))
 import zipfile
 with zipfile.ZipFile(package,'w') as archive:archive.writestr(zipfile.ZipInfo('fakenetng-mcp.exe',(2000,1,1,0,0,0)),body);archive.writestr('mcp-candidate-manifest.json',manifest.read_bytes())
 identity['package_sha256']=m.sha256(package)
 return {'schema':'fakenet.mcp-input.v2','identity':identity,'package':str(package),'manifest':str(manifest),'manifest_sha256':m.sha256(manifest),'target':{'platform':'windows','hostname':'DESKTOP-3FI41GR','vm_uuid':'564de0b3-b23d-3d9f-4d52-3ec22c4cfdc0'},'config_identity':{'name':'default.ini','sha256':m.sha256(ROOT/'fakenet/configs/default.ini')},'endpoint':'http://192.168.204.149:28788','listen_ip':'192.168.204.149','allowed_host':'192.168.204.1','channel':{'mcp_config_ref':str(root/'protected-reference.toml'),'mcp_server':'windows'},'actions':['observe','mcp','core','service','fault','network','config','artifact'],'work_root':str(root),'installation_root':'C:\\Program Files\\FakeNet-NG-MCP','programdata_root':'C:\\ProgramData\\FakeNet-NG-MCP','client_config_ref':str(root/'protected-reference.toml'),'guest_work_root':'E:/acceptance-evidence'}


class ReadOnlyBoundary:
 fixture=True
 def __init__(self,inputs):self.inputs=inputs
 def exchange(self,kind,value):
  if kind=='target':return self.inputs['target']
  if kind=='observe':return {'sections':{'routes':'IPv4 fixed','dns_servers':[],'listen_ports':'fixed scoped listener','windivert_processes':{'services':[],'processes':[]},'services':'Running'},'service':{'computer':self.inputs['target']['hostname'],'pid':12,'created':'birth','state':'Running'}}
  if kind=='powershell':
   if 'fault_exists=' in value['command']:
    from pathlib import PureWindowsPath
    manifest=m.read(self.inputs['manifest']);payload={'image':str(PureWindowsPath(self.inputs['installation_root'])/'fakenetng-mcp.exe'),'sha256':manifest['files'][0]['sha256'],'pid':12,'birth':'1234','enabled':False,'grace':60,'fault_exists':False}
   elif 'grace=$cfg.stop_grace_seconds' in value['command']:payload={'enabled':False,'grace':60}
   else:raise AssertionError('unexpected original PowerShell command '+value['command'])
   return {'output':json.dumps(payload),'raw':json.dumps(payload),'exit_code':0,'is_error':False}
  if kind=='uuid':return '00000000-0000-4000-8000-000000000001'
  if kind!='http':raise AssertionError('unexpected OS action '+kind)
  request=json.loads(value['data']);tool=request['params']['name'];args=request['params']['arguments'];headers={k.lower():v for k,v in value['headers'].items()}
  if tool=='get_status':payload={'state':'stopped','state_version':7,'run_id':None,'config_identity':self.inputs['config_identity']}
  elif tool=='ping':payload={'service':'fakenetng-mcp','build_identity':{'source_commit':self.inputs['identity']['source_commit'],'manifest_sha256':self.inputs['manifest_sha256']}}
  elif tool in ('create_config','stop'):payload={'error':{'code':'controller_identity_missing'}}
  elif tool=='read_config' and ('..' in args['name'] or ':' in args['name']):payload={'error':{'code':'path_escape_blocked'}}
  elif tool=='list_artifacts':payload={'artifacts':[]}
  elif tool=='read_config':payload={'name':'default.ini','content':'[FakeNet]\nDumpPackets = No\n','sha256':self.inputs['config_identity']['sha256']}
  else:payload={}
  body={'jsonrpc':'2.0','id':1,'result':{'content':[{'type':'text','text':json.dumps(payload)}]}}
  return {'status':200,'headers':{'Content-Type':'application/json'},'body':json.dumps(body).encode(),'http_error':False}


class OriginalMcpTests(unittest.TestCase):
 def setUp(self):
  self.root=Path(tempfile.mkdtemp(prefix='original-mcp-'));self.inputs=inputs_at(self.root)
 def run_readonly(self):
  out=self.root/'out';m.run('MCP-P02-FULL',out,self.inputs,selected=['ACC-005'],boundary=ReadOnlyBoundary(self.inputs),fixture=True);return out
 def test_original_acc005_and_independent_reexecution(self):
  out=self.run_readonly();rows,clean,detail=o.evaluate(ROOT,out,'MCP-P02-FULL',['ACC-005'],self.inputs,allow_fixture=True)
  self.assertEqual(rows[0]['status'],'pass',detail);self.assertTrue(clean)
  result=m.read(out/'units/ACC-005/result.json');self.assertEqual(result['actions'][0]['name'],'acc005')
  trace=m.read(out/'units/ACC-005/trace.json');self.assertTrue(any(r['kind']=='http' for r in trace['records']))
 def test_rehashed_failed_business_response_cannot_pass(self):
  out=self.run_readonly();path=out/'units/ACC-005/trace.json';trace=m.read(path)
  for row in trace['records']:
   if row['kind']=='http' and json.loads(m.unpack(row['input'])['data'])['params']['name']=='create_config':
    response=m.unpack(row['output']);body=json.loads(response['body']);body['result']['content'][0]['text']=json.dumps({'error':{'code':'config_not_created'}});response['body']=json.dumps(body).encode();row['output']=m.pack(response)
  path.write_text(json.dumps(trace));rows,clean,detail=o.evaluate(ROOT,out,'MCP-P02-FULL',['ACC-005'],self.inputs,allow_fixture=True)
  self.assertEqual(rows[0]['status'],'fail',detail);self.assertFalse(clean)
 def test_unexpected_or_unused_boundary_data_refused(self):
  out=self.run_readonly();path=out/'units/ACC-005/trace.json';trace=m.read(path);trace['records'].append(trace['records'][0]);path.write_text(json.dumps(trace))
  self.assertEqual(o.evaluate(ROOT,out,'MCP-P02-FULL',['ACC-005'],self.inputs,allow_fixture=True)[0][0]['status'],'fail')
 def test_invalid_inputs_fail_before_any_native_factory(self):
  for mutate in (lambda x:x.update(command=['arbitrary']),lambda x:x.update(actions=['observe']),lambda x:x['identity'].update(package_sha256='0'*64),lambda x:x['target'].update(vm_uuid='not-uuid')):
   with self.subTest(mutation=mutate):
    import copy
    value=copy.deepcopy(self.inputs);mutate(value)
    with mock.patch.object(m,'NativeBoundary',side_effect=AssertionError('must not construct boundary')):
     with self.assertRaises(ValueError):m.run('MCP-P02-FULL',self.root/'bad',value)
    self.assertFalse((self.root/'bad').exists())
 def test_unselected_unknown_and_duplicate_units_rejected(self):
  for selected in ([],['arbitrary'],['ACC-005','ACC-005']):
   with self.assertRaises(ValueError):m.run('MCP-P02-FULL',self.root/'bad',self.inputs,selected=selected,boundary=ReadOnlyBoundary(self.inputs),fixture=True)
 def test_original_sources_and_candidate_identity_bound(self):
  out=self.run_readonly();value=m.read(out/'mcp-result.json');value['identity']['candidate_id']='different';(out/'mcp-result.json').write_text(json.dumps(value))
  with self.assertRaisesRegex(ValueError,'identity'):o.evaluate(ROOT,out,'MCP-P02-FULL',['ACC-005'],self.inputs,allow_fixture=True)
 def test_fixture_denied_native_credit(self):
  out=self.run_readonly()
  with self.assertRaisesRegex(ValueError,'fixture'):o.evaluate(ROOT,out,'MCP-P02-FULL',['ACC-005'],self.inputs)




class PublicMcpCliTests(unittest.TestCase):
 def setUp(self):
  self.base=Path(tempfile.mkdtemp(prefix='public-mcp-'));self.inputs=inputs_at(self.base);self.run=self.base/'public-run'
 def cli(self,*args):
  import acceptance as a,contextlib,io
  stdout,stderr=io.StringIO(),io.StringIO()
  with contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stderr):code=a.main(['--root',str(ROOT)]+[str(x) for x in args])
  return code,stdout.getvalue(),stderr.getvalue()
 def prepare(self):
  import acceptance as a
  candidate={'schema':a.CANDIDATE_V2,'source_commit':self.inputs['identity']['source_commit'],'package_sha256':self.inputs['identity']['package_sha256'],'package_path':self.inputs['package'],'package_manifest':self.inputs['manifest'],'offline_fixture':True}
  environment={'schema':a.ENVIRONMENT_V2,'targets':['windows-vm'],'interpreters':{'python':sys.executable},'work_root':str(self.base),'allowed_actions':['native','vm-execute'],'endpoints':[],'auth_refs':[],
   'native_runtime':{'transport':'windows-mcp-velo','identity':self.inputs['target'],**self.inputs['channel']},'mcp':self.inputs,'mcp_checks':{'MCP-P02-FULL':['ACC-005']}}
  (self.base/'candidate.json').write_text(json.dumps(candidate));(self.base/'environment.json').write_text(json.dumps(environment))
  original=m.sha256(ROOT/'docs/acceptance/catalog.json')
  result=self.cli('plan','--mode','selected','--case','MCP-P02-FULL','--candidate',self.base/'candidate.json','--environment',self.base/'environment.json','--output',self.run/'plan.json');self.assertEqual(0,result[0],result)
  self.assertEqual(original,m.sha256(ROOT/'docs/acceptance/catalog.json'))
 def test_production_registry_original_business_and_rehashed_bad_response(self):
  self.prepare()
  with mock.patch.object(m,'NativeBoundary',side_effect=lambda *a,**kw:ReadOnlyBoundary(self.inputs)):
   result=self.cli('execute','--plan',self.run/'plan.json')
  self.assertEqual(0,result[0],result)
  result=self.cli('judge','--plan',self.run/'plan.json','--results',self.run/'results','--output',self.run/'independent.json');self.assertEqual(0,result[0],result)
  summary=m.read(self.run/'independent.json');self.assertTrue(summary['fixture_contract_pass']);self.assertFalse(summary['full_functional_pass'])
  case_dir=self.run/'results/MCP-P02-FULL';path=case_dir/'driver/units/ACC-005/trace.json';trace=m.read(path)
  for row in trace['records']:
   if row['kind']=='http' and json.loads(m.unpack(row['input'])['data'])['params']['name']=='create_config':
    response=m.unpack(row['output']);body=json.loads(response['body']);body['result']['content'][0]['text']=json.dumps({'error':{'code':'config_not_created'}});response['body']=json.dumps(body).encode();row['output']=m.pack(response)
  path.write_text(json.dumps(trace))
  receipt=m.read(case_dir/'receipt.json')
  for artifact in receipt['artifacts']:artifact['sha256']=m.sha256(artifact['path'])
  (case_dir/'receipt.json').write_text(json.dumps(receipt));index=m.read(self.run/'results/results.json')
  for row in index['receipts']:
   if row['case_id']=='MCP-P02-FULL':row['sha256']=m.sha256(case_dir/'receipt.json')
  (self.run/'results/results.json').write_text(json.dumps(index))
  result=self.cli('judge','--plan',self.run/'plan.json','--results',self.run/'results','--output',self.run/'negative.json');self.assertNotEqual(0,result[0],result)
  summary=m.read(self.run/'negative.json');self.assertFalse(summary['fixture_contract_pass']);self.assertIn('original assertions',json.dumps(summary))
 def test_full_cannot_reduce_original_group_to_one_unit(self):
  import acceptance_native as n
  self.prepare();plan=m.read(self.run/'plan.json');plan['mode']='full';catalog=m.read(ROOT/'docs/acceptance/catalog.json');case=next(c for suite in catalog['suites'] for c in suite.get('cases',[]) if c['id']=='MCP-P02-FULL')
  with self.assertRaisesRegex(ValueError,'entire original'):n.mcp_inputs(plan,case,ROOT)




class DomainBoundary(ReadOnlyBoundary):
 """Real ConfigStore/Coordinator/tool domain; only HTTP and service OS edges."""
 def __init__(self,inputs,root):
  super().__init__(inputs);self.root=Path(root);self.counter=0;self.t=1700000000.;self.guard=__import__('threading').RLock();self.assemble()
 def assemble(self):
  import os
  from fakenet.mcp import paths,tools,config,configstore,testdouble
  from unittest.mock import patch
  with patch.dict(os.environ,{'FAKENETNG_MCP_PROGRAMDATA':str(self.root)}):
   self.context=tools.AppContext(config.ServiceConfig(listen_ip=self.inputs['listen_ip'],listen_port=28788,allowed_host_ips=[self.inputs['allowed_host']]),runner=testdouble.LifecycleDouble())
  class Registrar:
   def __init__(self):self.functions={}
   def tool(self,**kwargs):
    def register(fn):self.functions[fn.__name__]=fn;return fn
    return register
  registry=Registrar();tools.register_tools(registry,self.context);self.functions=registry.functions
  from fakenet.mcp.transportguard import controller_header_state
  token=controller_header_state.set('11111111-2222-4333-8444-555555555555')
  try:self.functions['load_config'](name='default.ini',command_id='memory-prepare',expected_state_version=self.context.coordinator.snapshot()['state_version'])
  finally:controller_header_state.reset(token)
  from fakenet.mcp.artifacts import ArtifactRegistry
  owner=self
  class ProcessEdge:
   def call(self,kind,payload,deadline):
    if kind!='list-artifacts':raise AssertionError('unexpected diagnostic process '+kind)
    return ArtifactRegistry(owner.context.artifacts_root).metadata(**payload)
  self.context.diagnostics=ProcessEdge()
 def exchange(self,kind,value):
  with self.guard:
   if kind=='uuid':self.counter+=1;return '00000000-0000-4000-8000-%012d'%self.counter
   if kind in ('time','monotonic'):self.t+=0.02;return self.t
   if kind=='sleep':self.t+=value['seconds'];return None
   if kind=='powershell':
    command=value['command']
    if 'fault_exists=' in command or 'grace=$cfg.stop_grace_seconds' in command:return super().exchange(kind,value)
    if 'config-audit.jsonl' in command:output=self.context.store.audit_path.read_text()
    elif 'sc.exe start' in command:self.assemble();output='STARTED'
    else:output='GONE'
    return {'output':output,'raw':output,'exit_code':0,'is_error':False}
   if kind=='http':
    request=json.loads(value['data']);name=request.get('params',{}).get('name');args=request.get('params',{}).get('arguments') or {}
    if name in self.functions:
     from fakenet.mcp.transportguard import controller_header_state
     headers={k.lower():v for k,v in value['headers'].items()};token=controller_header_state.set(headers.get('x-fakenet-controller-id'))
     try:payload=self.functions[name](**args)
     finally:controller_header_state.reset(token)
     body={'jsonrpc':'2.0','id':1,'result':{'content':[{'type':'text','text':json.dumps(payload)}]}}
     return {'status':200,'headers':{'Content-Type':'application/json'},'body':json.dumps(body).encode(),'http_error':False}
   return super().exchange(kind,value)


class OriginalDomainTests(unittest.TestCase):
 setUp=OriginalMcpTests.setUp
 def test_original_live_domain_config_management_and_ownership(self):
  for unit in ('ACC-005','ACC-010','ACC-011','ACC-009-PRE'):
   with self.subTest(unit=unit):
    boundary=DomainBoundary(self.inputs,self.root/('domain-'+unit));out=self.root/unit
    value=m.run('MCP-P02-FULL',out,self.inputs,selected=[unit],boundary=boundary,fixture=True)
    original=m.read(out/'units'/unit/'result.json')
    self.assertEqual('pass',original['status'],original)
    rows,clean,details=o.evaluate(ROOT,out,'MCP-P02-FULL',[unit],self.inputs,allow_fixture=True)
    self.assertEqual('pass',rows[0]['status'],details);self.assertTrue(clean)

if __name__=='__main__':unittest.main()
