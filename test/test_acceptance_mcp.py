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
 return {'schema':'fakenet.mcp-input.v2','identity':identity,'package':str(package),'manifest':str(manifest),'manifest_sha256':m.sha256(manifest),'target':{'platform':'windows','hostname':'DESKTOP-3FI41GR','vm_uuid':'564de0b3-b23d-3d9f-4d52-3ec22c4cfdc0'},'config_identity':{'name':'default.ini','sha256':m.sha256(ROOT/'fakenet/configs/default.ini')},'endpoint':'http://192.168.204.149:28788','listen_ip':'192.168.204.149','allowed_host':'192.168.204.1','channel':{'mcp_config_ref':str(root/'protected-reference.toml'),'mcp_server':'windows'},'actions':['observe','mcp','core','service','fault','network','config','artifact'],'work_root':str(root),'installation_root':'C:\\Program Files\\FakeNet-NG-MCP','programdata_root':'C:\\ProgramData\\FakeNet-NG-MCP','guest_work_root':'E:/acceptance-evidence'}


class ReadOnlyBoundary:
 fixture=True
 def __init__(self,inputs):self.inputs=inputs
 def exchange(self,kind,value):
  if kind=='target':return self.inputs['target']
  if kind=='observe':return {'sections':{'routes':'IPv4 fixed','dns_servers':[],'listen_ports':'fixed scoped listener','windivert_processes':{'services':[],'processes':[]},'services':'Running'},'service':{'computer':self.inputs['target']['hostname'],'pid':12,'created':'birth','state':'Running'}}
  if kind=='powershell':
   if 'fault_exists=' in value['command']:
    from pathlib import PureWindowsPath
    manifest=m.read(self.inputs['manifest']);payload={'image':str(PureWindowsPath(self.inputs['installation_root'])/'fakenetng-mcp.exe'),'sha256':manifest['files'][0]['sha256'],'pid':12,'birth':'1234','enabled':False,'grace':60,'fault_exists':False,'service_config':{'listen_ip':self.inputs['listen_ip'],'listen_port':28788,'allowed_host_ips':[self.inputs['allowed_host']],'extra_control_ports':[]}}
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
  self.assertEqual(rows[0]['status'],'fail',detail);self.assertTrue(clean,detail)
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




class ProtocolBoundary(ReadOnlyBoundary):
 def exchange(self,kind,value):
  if kind=='sdk':
   # SDK transport boundary only: the asyncio SDK cannot run under the
   # zero-socket guard (its event loop creates a wake-up socketpair).
   # No claim that a real SDK connection ran is made by this fixture.
   from mcp.types import ListToolsResult,Tool,CallToolResult,TextContent
   return {'tools':ListToolsResult(tools=[Tool(name='ping',inputSchema={})]).model_dump(mode='json',by_alias=True),'ping':CallToolResult(content=[TextContent(type='text',text=json.dumps({'service':'fakenetng-mcp'}))]).model_dump(mode='json',by_alias=True)}
  if kind=='http':
   body=json.loads(value['data']);meta=body.get('params',{}).get('_meta',{});headers={k.lower():v for k,v in value['headers'].items()}
   version=headers.get('mcp-protocol-version')
   if version and version!='2026-07-28':return {'status':400,'headers':{'Content-Type':'application/json'},'body':json.dumps({'error':{'code':-32022}}).encode(),'http_error':True}
   if body['method']=='server/discover':return {'status':200,'headers':{'Content-Type':'application/json'},'body':json.dumps({'result':{}}).encode(),'http_error':False}
   if body['method']=='tools/list':return {'status':200,'headers':{'Content-Type':'application/json'},'body':json.dumps({'result':{'tools':[{'name':n} for n in m.current_tool_surface()]}}).encode(),'http_error':False}
   if body.get('params',{}).get('name')=='ping':
    reply={'service':'fakenetng-mcp','controller_header':'valid_uuid' if 'x-fakenet-controller-id' in headers else 'missing','build_identity':{'source_commit':self.inputs['identity']['source_commit'],'manifest_sha256':self.inputs['manifest_sha256']}}
    return {'status':200,'headers':{'Content-Type':'application/json'},'body':json.dumps({'result':{'content':[{'text':json.dumps(reply)}]}}).encode(),'http_error':False}
  if kind=='powershell':
   command=value['command']
   if 'sc.exe qc' in command:output='AUTO_START LocalSystem RUNNING'
   elif 'OWNER=' in command:output='OWNER=NT AUTHORITY\\SYSTEM'
   elif 'netstat' in command:output='TCP 192.168.204.149:28788 0.0.0.0:0 LISTENING 12'
   elif 'Get-ChildItem $d' in command:output='configs\\custom \\state \\logs \\baselines \\artifacts service.json'
   elif 'net use' in command:output='No entries'
   else:return super().exchange(kind,value)
   return {'output':output,'raw':output,'exit_code':0,'is_error':False}
  return super().exchange(kind,value)


class OriginalProtocolTests(unittest.TestCase):
 setUp=OriginalMcpTests.setUp
 def test_original_protocol_service_and_closed_current_surface(self):
  for unit in ('ACC-002','ACC-016','P01-ENTRY'):
   with self.subTest(unit=unit):
    out=self.root/unit;value=m.run('MCP-P01-FULL',out,self.inputs,selected=[unit],boundary=ProtocolBoundary(self.inputs),fixture=True)
    self.assertEqual('pass',value['checks'][unit]['status'],m.read(out/'units'/unit/'result.json'))
    rows,clean,detail=o.evaluate(ROOT,out,'MCP-P01-FULL',[unit],self.inputs,allow_fixture=True);self.assertEqual('pass',rows[0]['status'],detail)




class FaultProcessBoundary(ReadOnlyBoundary):
 """Remote process/capture/file bytes only; all original fault logic runs."""
 def __init__(self,inputs):
  super().__init__(inputs);self.t=1700000000.;self.n=0;self.fault=None;self.version=7;self.enabled=False;self.grace=60;self.run_id='11111111-1111-4111-8111-111111111111';self.guard=__import__('threading').RLock()
 def archive(self):
  import io,zipfile
  from fakenet.mcp.incident import BASIC_ITEMS
  members={name:('benign remote '+name).encode() for name,unused in BASIC_ITEMS};members['userdump.dmp']=b'MDMP benign in-memory process bytes'
  self.manifest={'run_id':self.run_id,'complete':True,'entries':[{'item':name,'result':'ok','failure_reason':None,'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest()} for name,raw in members.items()]}
  self.manifest_bytes=json.dumps(self.manifest).encode();stream=io.BytesIO()
  with zipfile.ZipFile(stream,'w') as archive:
   archive.writestr('manifest.json',self.manifest_bytes)
   for name,raw in members.items():archive.writestr(name,raw)
  self.zip_bytes=stream.getvalue()
 def response(self,payload):return {'status':200,'headers':{'Content-Type':'application/json'},'body':json.dumps({'result':{'content':[{'text':json.dumps(payload)}]}}).encode(),'http_error':False}
 def exchange(self,kind,value):
  with self.guard:
   if kind in ('time','monotonic'):self.t+=0.01;return self.t
   if kind=='uuid':self.n+=1;return '00000000-0000-4000-8000-%012d'%self.n
   if kind=='sleep':self.t+=value['seconds'];return None
   if kind=='http':
    req=json.loads(value['data']);tool=req['params']['name']
    state={'service':'fakenetng-mcp','state':'stopped','state_version':self.version,'run_id':None,'controller':None,'config_identity':self.inputs['config_identity'],'last_run_outcome':'failed' if self.fault else None,'error':None}
    if tool in ('load_config','start','stop'):
     self.version+=1;state['state_version']=self.version
     if tool=='start':state['run_id']=self.run_id
     return self.response(state)
    if tool=='get_status':return self.response(state)
   if kind=='powershell':
    command=value['command']
    if 'fault_exists=' in command:
     payload=json.loads(super().exchange(kind,value)['output']);payload.update(enabled=self.enabled,grace=self.grace);output=json.dumps(payload)
    elif 'grace=$cfg.stop_grace_seconds' in command:output=json.dumps({'enabled':self.enabled,'grace':self.grace})
    elif 'Add-Member -NotePropertyName stop_grace_seconds' in command:
     import re
     self.enabled="$preserved + @('FAKENETNG_MCP_FAULT_INJECTION=1')" in command;self.grace=int(re.search(r'NotePropertyValue (\d+)',command).group(1));output='configured'
    elif '[IO.File]::WriteAllText($path,' in command and 'fault-injection.json' in command:
     import re
     self.fault=json.loads(re.search(r"WriteAllText\(\$path,'(\{.*?\})'",command).group(1));self.archive();output=json.dumps(self.fault)
    elif 'boot=$os.LastBootUpTime' in command:output=json.dumps({'computer':self.inputs['target']['hostname'],'boot':'boot1','pid':12,'created':'birth1','state':'Running'})
    elif 'Get-DnsClientServerAddress' in command:output=json.dumps([{'InterfaceAlias':'Ethernet','ServerAddresses':['192.168.204.2']}])
    elif '$receipts=@' in command:output=json.dumps({'receipt':{'run_id':self.run_id,'receipt':self.fault},'incidents':[{'path':'C:\\ProgramData\\FakeNet-NG-MCP\\artifacts\\'+self.run_id+'\\incident\\manifest.json','manifest':self.manifest}]})
    elif 'Compress-Archive' in command:output=json.dumps({'size':len(self.zip_bytes),'sha256':hashlib.sha256(self.zip_bytes).hexdigest(),'manifest_sha256':hashlib.sha256(self.manifest_bytes).hexdigest()})
    elif '[IO.File]::OpenRead(' in command:
     import re,base64
     offset=int(re.search(r'\.Seek\((\d+),',command).group(1));count=int(re.search(r'byte\[\] (\d+)',command).group(1));output=base64.b64encode(self.zip_bytes[offset:offset+count]).decode()
    elif 'route.exe print' in command or 'netstat -ano' in command or 'WinDivert' in command or 'Get-Service dnscache,mpssvc' in command:output='fixed original remote section'
    elif 'controlled pre-stop failed' in command or 'unconsumed fault' in command:output='controlled service stop completed'
    else:raise AssertionError('unexpected fault OS command: '+command)
    return {'output':output,'raw':output,'exit_code':0,'is_error':False}
   return super().exchange(kind,value)


class OriginalFaultTests(unittest.TestCase):
 setUp=OriginalMcpTests.setUp
 def test_original_five_faults_produce_and_rejudge_original_incident_bytes(self):
  for fault in m.FAULTS:
   with self.subTest(fault=fault):
    out=self.root/fault;value=m.run('MCP-SPECIAL-FAULT-RECOVERY',out,self.inputs,selected=[fault],boundary=FaultProcessBoundary(self.inputs),fixture=True)
    self.assertEqual('pass',value['checks'][fault]['status'],m.read(out/'units'/fault/'result.json'))
    rows,clean,detail=o.evaluate(ROOT,out,'MCP-SPECIAL-FAULT-RECOVERY',[fault],self.inputs,allow_fixture=True);self.assertEqual('pass',rows[0]['status'],detail);self.assertTrue(clean)




class IpcProcessBoundary(FaultProcessBoundary):
 def __init__(self,inputs):super().__init__(inputs);self.running=False;self.step=0;self.terminal=False
 def pipe_bytes(self):
  fault=self.fault['fault'];run=self.run_id
  rows=[{'event':'failure','monotonic':100.0,'frame':{'kind':'health','run_id':run,'seq':1}}]
  if fault in ('ipc_once_timeout','ipc_permanent_timeout'):
   rows.append({'event':'health_state','monotonic':100.1,'frame':{'state':'degraded','run_id':run}})
   if fault=='ipc_once_timeout':rows.extend([{'event':'response','monotonic':101.,'frame':{'run_id':run,'seq':2,'result':{'init_evidence':True,'probe':True}}},{'event':'health_state','monotonic':101.1,'frame':{'state':'healthy','run_id':run}}])
   else:rows.extend([{'event':'failure','monotonic':101.,'frame':{'kind':'health','run_id':run,'seq':2}},{'event':'health_state','monotonic':101.1,'frame':{'state':'failed','run_id':run}}])
  else:rows.append({'event':'health_state','monotonic':100.1,'frame':{'state':'failed','run_id':run}})
  action='drop' if 'timeout' in fault else 'eof' if fault=='ipc_eof' else 'send'
  return {'parent':'\n'.join(json.dumps(row) for row in rows),'child':json.dumps({'event':action,'frame':{'run_id':run,'seq':1}}),'receipt':self.fault}
 def exchange(self,kind,value):
  with self.guard:
   if kind=='http':
    req=json.loads(value['data']);tool=req['params']['name']
    if tool in ('get_status','start','stop','load_config'):
     if tool=='start':self.running=True;self.fault=None;self.step=0;self.terminal=False
     if tool=='stop':self.running=False;self.terminal=True
     state='healthy' if self.running else 'stopped'
     if tool=='get_status' and self.fault and self.running:
      self.step+=1
      if self.step==1:state='degraded' if 'timeout' in self.fault['fault'] else 'failed'
      elif self.fault['fault']=='ipc_once_timeout':state='healthy'
      else:self.running=False;self.terminal=True;state='stopped'
     if tool!='get_status':self.version+=1
     payload={'service':'fakenetng-mcp','state':state,'state_version':self.version,'run_id':self.run_id if self.running else None,'controller':None,'config_identity':self.inputs['config_identity'],'last_run_outcome':'failed' if self.terminal else None,'error':None}
     return self.response(payload)
   if kind=='powershell':
    command=value['command']
    if '@{parent=(Get-Content' in command:output=json.dumps(self.pipe_bytes())
    elif '$names=@(Get-ChildItem' in command:output=json.dumps(['incident'])
    else:return super().exchange(kind,value)
    return {'output':output,'raw':output,'exit_code':0,'is_error':False}
   return super().exchange(kind,value)


class OriginalIpcTests(unittest.TestCase):
 setUp=OriginalMcpTests.setUp
 def test_original_six_ipc_functions_and_exact_receipt_replay(self):
  for fault in m.IPC:
   with self.subTest(fault=fault):
    out=self.root/fault;value=m.run('MCP-SPECIAL-IPC',out,self.inputs,selected=[fault],boundary=IpcProcessBoundary(self.inputs),fixture=True)
    self.assertEqual('pass',value['checks'][fault]['status'],m.read(out/'units'/fault/'result.json'))
    rows,clean,detail=o.evaluate(ROOT,out,'MCP-SPECIAL-IPC',[fault],self.inputs,allow_fixture=True);self.assertEqual('pass',rows[0]['status'],detail)
 def test_wrong_receipt_and_missing_child_are_content_failures(self):
  fault='ipc_once_timeout';out=self.root/fault;m.run('MCP-SPECIAL-IPC',out,self.inputs,selected=[fault],boundary=IpcProcessBoundary(self.inputs),fixture=True)
  path=out/'units'/fault/'trace.json';trace=m.read(path)
  for row in trace['records']:
   if row['kind']=='powershell' and '@{parent=(Get-Content' in row['input']['command']:
    output=json.loads(row['output']['output']);output['receipt']={'fault':'wrong','nonce':'wrong'};output['child']='';row['output']['output']=json.dumps(output)
  path.write_text(json.dumps(trace))
  rows,clean,detail=o.evaluate(ROOT,out,'MCP-SPECIAL-IPC',[fault],self.inputs,allow_fixture=True);self.assertEqual('fail',rows[0]['status'],detail)




class OriginalFaultContentTests(unittest.TestCase):
 setUp=OriginalMcpTests.setUp
 def test_each_wrong_hook_nonce_is_rejected_after_normal_original_baseline(self):
  for fault in m.FAULTS:
   with self.subTest(fault=fault):
    out=self.root/fault;m.run('MCP-SPECIAL-FAULT-RECOVERY',out,self.inputs,selected=[fault],boundary=FaultProcessBoundary(self.inputs),fixture=True)
    self.assertEqual('pass',o.evaluate(ROOT,out,'MCP-SPECIAL-FAULT-RECOVERY',[fault],self.inputs,allow_fixture=True)[0][0]['status'])
    path=out/'units'/fault/'trace.json';trace=m.read(path)
    for row in trace['records']:
     if row['kind']=='powershell' and '$receipts=@' in row['input']['command']:
      payload=json.loads(row['output']['output']);payload['receipt']['receipt']={'fault':'different-hook','nonce':'different-nonce'};row['output']['output']=json.dumps(payload)
    path.write_text(json.dumps(trace))
    rows,clean,detail=o.evaluate(ROOT,out,'MCP-SPECIAL-FAULT-RECOVERY',[fault],self.inputs,allow_fixture=True);self.assertEqual('fail',rows[0]['status'],detail)
 def test_candidate_mismatch_is_rejected_before_any_original_unit_replay(self):
  fault='ipc_once_timeout';out=self.root/fault;m.run('MCP-SPECIAL-IPC',out,self.inputs,selected=[fault],boundary=IpcProcessBoundary(self.inputs),fixture=True)
  path=out/'units'/fault/'trace.json';value=m.read(path);value['identity']['candidate_id']='unrelated';path.write_text(json.dumps(value))
  rows,clean,detail=o.evaluate(ROOT,out,'MCP-SPECIAL-IPC',[fault],self.inputs,allow_fixture=True);self.assertEqual('fail',rows[0]['status'],detail)




class LifecycleDomainBoundary(DomainBoundary):
 def exchange(self,kind,value):
  if kind=='powershell':
   command=value['command']
   if 'sc.exe query fakenetng-mcp' in command:output='RUNNING'
   elif "-ArgumentList 'debug'" in command:output='3'
   else:return super().exchange(kind,value)
   return {'output':output,'raw':output,'exit_code':0,'is_error':False}
  return super().exchange(kind,value)


class OriginalGroupTests(unittest.TestCase):
 setUp=OriginalMcpTests.setUp
 def test_entire_p02_group_one_boundary_and_closed_original_rejudge(self):
  out=self.root/'p02-group';value=m.run('MCP-P02-FULL',out,self.inputs,boundary=DomainBoundary(self.inputs,self.root/'domain'),fixture=True)
  self.assertEqual(set(m.CHECKS['MCP-P02-FULL']),set(value['checks']))
  self.assertTrue(all(row['status']=='pass' for row in value['checks'].values()),value)
  rows,clean,detail=o.evaluate(ROOT,out,'MCP-P02-FULL',m.CHECKS['MCP-P02-FULL'],self.inputs,allow_fixture=True);self.assertTrue(all(row['status']=='pass' for row in rows),detail);self.assertTrue(clean)
 def test_original_headless_uniqueness_and_normal_takeover(self):
  for unit in ('ACC-004-S1',):
   with self.subTest(unit=unit):
    out=self.root/unit;value=m.run('MCP-P03-FULL',out,self.inputs,selected=[unit],boundary=LifecycleDomainBoundary(self.inputs,self.root/('domain-'+unit)),fixture=True)
    self.assertEqual('pass',value['checks'][unit]['status'],m.read(out/'units'/unit/'result.json'))
    rows,clean,detail=o.evaluate(ROOT,out,'MCP-P03-FULL',[unit],self.inputs,allow_fixture=True);self.assertEqual('pass',rows[0]['status'],detail)




class OriginalUniquenessNegativeTests(unittest.TestCase):
 setUp=OriginalMcpTests.setUp
 def test_lifecycle_without_duplicate_start_guard_is_not_a_pass(self):
  # LifecycleDouble has no process ownership gate: use it as a bad process
  # boundary, never as a successful fixture for supervisor uniqueness.
  unit='ACC-001-HEADLESS';out=self.root/unit
  value=m.run('MCP-P03-FULL',out,self.inputs,selected=[unit],boundary=LifecycleDomainBoundary(self.inputs,self.root/'domain'),fixture=True)
  self.assertEqual('fail',value['checks'][unit]['status'])
  checks=m.read(out/'units'/unit/'acc001-headless-checks.json');self.assertFalse(checks['second_managed_instance_rejected'])
  self.assertEqual('fail',o.evaluate(ROOT,out,'MCP-P03-FULL',[unit],self.inputs,allow_fixture=True)[0][0]['status'])
 def test_real_supervisor_existing_process_gate_is_not_weakened(self):
  import threading
  from fakenet.mcp.supervisor import RealSupervisor,SupervisorStartError
  instance=object.__new__(RealSupervisor);instance._start_guard=None;instance._lock=threading.Lock();instance._fakenet=object()
  with mock.patch('fakenet.mcp.supervisor.os.name','nt'):
   with self.assertRaisesRegex(SupervisorStartError,'managed process already exists'):instance.start(None,None,{})




class OriginalRecoveryTests(unittest.TestCase):
 setUp=OriginalMcpTests.setUp
 def test_unknown_capture_stops_remaining_original_units(self):
  calls=[]
  class Broken(ReadOnlyBoundary):
   def exchange(self,kind,value):
    calls.append(kind)
    if kind=='observe':raise OSError('independent capture unavailable')
    return super().exchange(kind,value)
  out=self.root/'unknown';value=m.run('MCP-P02-FULL',out,self.inputs,selected=['ACC-005','ACC-010'],boundary=Broken(self.inputs),fixture=True)
  self.assertEqual('unknown',value['checks']['ACC-005']['status']);self.assertEqual({'status':'not_run','result':None,'trace':None},value['checks']['ACC-010']);self.assertEqual(1,calls.count('target'))
  rows,clean,details=o.evaluate(ROOT,out,'MCP-P02-FULL',['ACC-005','ACC-010'],self.inputs,allow_fixture=True);self.assertFalse(clean);self.assertEqual('not_run',rows[1]['status'])


class OriginalFirewallAttributionTests(unittest.TestCase):
 setUp=OriginalMcpTests.setUp
 def run_firewall(self,response=None,error=None):
  class FirewallBoundary(ProtocolBoundary):
   def exchange(self,kind,value):
    if kind=='powershell':
     cmd=value['command']
     if 'Select-String -Pattern' in cmd:output='1'
     elif 'Get-NetFirewallProfile' in cmd:output=json.dumps([{'Name':'Domain','Enabled':False},{'Name':'Private','Enabled':True},{'Name':'Public','Enabled':False}])
     elif 'show rule' in cmd:output='FakeNet-NG MCP 192.168.204.1 28788'
     elif 'README-SECURITY' in cmd:output='DNS rebinding'
     elif 'New-NetFirewallRule' in cmd:output='PROTECTED+ON'
     elif 'Remove-NetFirewallRule' in cmd:output='RESTORED'
     else:return super().exchange(kind,value)
     return {'output':output,'raw':output,'exit_code':0,'is_error':False}
    if kind=='sleep':return None
    return super().exchange(kind,value)
  out=self.root/'firewall'
  boundary=FirewallBoundary(self.inputs)
  original=boundary.exchange
  def exchange(kind,value):
   if kind=='http-source':
    if error:raise error
    return {'status':response[0],'headers':{},'body':response[1]}
   return original(kind,value)
  boundary.exchange=exchange
  value=m.run('MCP-P01-FULL',out,self.inputs,selected=['ACC-003'],boundary=boundary,fixture=True)
  rows,clean,details=o.evaluate(ROOT,out,'MCP-P01-FULL',['ACC-003'],self.inputs,allow_fixture=True)
  return value,rows,clean,details
 def test_observed_denial_replays_original_access_check(self):
  value,rows,clean,details=self.run_firewall(response=(403,b'forbidden'))
  self.assertEqual('pass',value['checks']['ACC-003']['status']);self.assertEqual('pass',rows[0]['status'],details);self.assertTrue(clean)
 def test_bind_route_or_timeout_is_not_a_remote_block(self):
  for error in (OSError(99,'Cannot assign requested address'),OSError(101,'Network is unreachable'),TimeoutError('no response')):
   with self.subTest(error=error):
    self.setUp();value,rows,clean,details=self.run_firewall(error=error)
    self.assertEqual('blocked',value['checks']['ACC-003']['status']);self.assertEqual('fail',rows[0]['status']);self.assertTrue(clean,details)
 def test_unrelated_http_error_is_not_a_remote_block(self):
  value,rows,clean,details=self.run_firewall(response=(500,b'internal error'))
  self.assertEqual('blocked',value['checks']['ACC-003']['status']);self.assertEqual('fail',rows[0]['status'])


class MultiRunFaultBoundary(FaultProcessBoundary):
 def __init__(self,inputs):
  super().__init__(inputs);self.started=0;self.archives={}
 def archive(self):
  super().archive();self.archives[self.run_id]=(self.manifest,self.manifest_bytes,self.zip_bytes)
 def exchange(self,kind,value):
  with self.guard:
   if kind=='http' and json.loads(value['data'])['params']['name']=='start':
    self.started+=1;self.run_id='22222222-2222-4222-8222-%012d'%self.started;self.archive()
   if kind=='powershell' and 'Compress-Archive' in value['command']:
    import re
    run=re.search(r'artifacts\\([0-9a-f-]{36})',value['command']).group(1)
    self.manifest,self.manifest_bytes,self.zip_bytes=self.archives[run]
   return super().exchange(kind,value)

class OriginalIncidentIntegrityTests(unittest.TestCase):
 setUp=OriginalMcpTests.setUp
 def test_integrity_slice_passes_without_claiming_root_cause_capability(self):
  unit='INCIDENT-INTEGRITY';out=self.root/'integrity'
  value=m.run('MCP-P04-FULL',out,self.inputs,selected=[unit],boundary=MultiRunFaultBoundary(self.inputs),fixture=True)
  result=m.read(out/'units'/unit/'result.json');self.assertEqual('pass',value['checks'][unit]['status'],result)
  scope=m.read(out/'units'/unit/'incident-integrity-scope.json');self.assertFalse(scope['complete_acc014']);self.assertEqual('not_evaluated',scope['root_cause_localization']);self.assertEqual(5,len(scope['run_ids']))
  rows,clean,details=o.evaluate(ROOT,out,'MCP-P04-FULL',[unit],self.inputs,allow_fixture=True);self.assertEqual('pass',rows[0]['status'],details);self.assertTrue(clean)
 def test_original_full_acc_still_requires_actual_localization(self):
  unit='ACC-014';out=self.root/'full'
  value=m.run('MCP-P04-FULL',out,self.inputs,selected=[unit],boundary=MultiRunFaultBoundary(self.inputs),fixture=True)
  result=m.read(out/'units'/unit/'result.json');self.assertEqual('blocked',value['checks'][unit]['status'],result);self.assertIn('package-only developer localization record required',json.dumps(result));self.assertIn('ACC-014',m.CHECKS['MCP-P04-FULL']);self.assertNotIn('INCIDENT-INTEGRITY',m.CHECKS['MCP-P04-FULL'])
 def test_missing_conditional_dump_cannot_pass_integrity(self):
  class NoDump(MultiRunFaultBoundary):
   def archive(self):
    super().archive()
    import io,zipfile
    self.manifest['entries']=[x for x in self.manifest['entries'] if x['item']!='userdump.dmp']
    self.manifest_bytes=json.dumps(self.manifest).encode();stream=io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(self.zip_bytes)) as original,zipfile.ZipFile(stream,'w') as archive:
     for name in original.namelist():
      if name!='userdump.dmp':archive.writestr(name,self.manifest_bytes if name=='manifest.json' else original.read(name))
    self.zip_bytes=stream.getvalue();self.archives[self.run_id]=(self.manifest,self.manifest_bytes,self.zip_bytes)
  unit='INCIDENT-INTEGRITY';out=self.root/'no-dump'
  value=m.run('MCP-P04-FULL',out,self.inputs,selected=[unit],boundary=NoDump(self.inputs),fixture=True)
  self.assertNotEqual('pass',value['checks'][unit]['status']);self.assertEqual('fail',o.evaluate(ROOT,out,'MCP-P04-FULL',[unit],self.inputs,allow_fixture=True)[0][0]['status'])


class ControlDomainBoundary(DomainBoundary):
 """Real registered tools/config domain; guest processes and wire are memory."""
 def __init__(self,inputs,root,marker_mode='normal'):
  self.service_bytes=json.dumps({'listen_ip':inputs['listen_ip'],'listen_port':28788,'allowed_host_ips':[inputs['allowed_host']],'extra_control_ports':[]}).encode();self.marker_mode=marker_mode;self.sent={};self.echoes={};self.packet_files={};self.marker='';self.closed=[]
  super().__init__(inputs,root)
  from fakenet.mcp.testdouble import LifecycleDouble
  self.context.runner.health_detail=lambda state:{**LifecycleDouble.health_detail(state),'final_filter':('(ip.DstAddr != '+self.inputs['allowed_host']+' or (tcp.SrcPort != 28788 and tcp.SrcPort != 28787 and tcp.SrcPort != 28790 and tcp.SrcPort != 29094 and tcp.SrcPort != 29095)) and (ip.DstAddr < 127.0.0.0 or ip.DstAddr > 127.255.255.255)')}
 def pcap_bytes(self,family,loop_marker,diverted_marker,port):
  import dpkt,io,socket
  stream=io.BytesIO();writer=dpkt.pcap.Writer(stream,linktype=dpkt.pcap.DLT_RAW)
  def packet(src,dst,marker,udp=True,dport=port):
   l4=dpkt.udp.UDP(sport=41000,dport=dport,data=marker.encode()) if udp else dpkt.tcp.TCP(sport=28787,dport=41000,data=marker.encode())
   if udp:l4.ulen=len(l4)
   proto=17 if udp else 6
   if ':' in src:ip=dpkt.ip6.IP6(src=socket.inet_pton(socket.AF_INET6,src),dst=socket.inet_pton(socket.AF_INET6,dst),nxt=proto,hlim=64,data=l4);ip.plen=len(l4)
   else:ip=dpkt.ip.IP(src=socket.inet_aton(src),dst=socket.inet_aton(dst),p=proto,ttl=64,data=l4);ip.len=len(ip)
   writer.writepkt(bytes(ip),ts=1.)
  local='127.0.0.1' if family=='V4' else '::1'
  packet(local,local,loop_marker)
  if self.marker_mode=='management-only':packet('192.168.204.149','192.168.204.1',diverted_marker,False,28787)
  else:packet('192.168.204.149','192.168.204.2',diverted_marker if self.marker_mode!='substring' else 'prefix-'+diverted_marker,True,53)
  if self.marker_mode=='redirected':packet('127.0.0.1','192.168.204.149',loop_marker,True,53)
  return stream.getvalue()
 def exchange(self,kind,value):
  with self.guard:
   if kind=='socket-open':
    self.assert_target(value['address']);self.sent[value['handle']]=b'';return {'connected':True}
   if kind=='socket-send':
    self.sent[value['handle']]=value['data'];port=int(value['handle'].split('-')[-1]);return None
   if kind=='socket-recv':return self.sent[value['handle']]
   if kind=='socket-timeout':return None
   if kind=='socket-close':self.closed.append(value['handle']);return {'fileno':-1}
   if kind=='powershell':
    cmd=value['command'];import re,base64
    if 'fault_exists=' in cmd:
     payload=json.loads(ReadOnlyBoundary.exchange(self,kind,value)['output']);payload['service_config']=json.loads(self.service_bytes);output=json.dumps(payload)
    elif '$b=[IO.File]::ReadAllBytes($p)' in cmd:
     output=json.dumps({'sha256':hashlib.sha256(self.service_bytes).hexdigest(),'base64':base64.b64encode(self.service_bytes).decode()})
    elif "extra control config changed; preserve scene" in cmd:
     previous=re.search(r"-ne '([a-f0-9]{64})'",cmd).group(1)
     if hashlib.sha256(self.service_bytes).hexdigest()!=previous:raise ValueError('extra control config changed; preserve scene')
     self.service_bytes=base64.b64decode(re.search(r"FromBase64String\('([^']*)'\)",cmd).group(1));output=json.dumps({'sha256':hashlib.sha256(self.service_bytes).hexdigest()})
    elif 'Start-Service fakenetng-mcp' in cmd:output='Running'
    elif 'controlled pre-stop failed' in cmd:output='controlled service stop completed'
    elif 'Start-Process powershell -WindowStyle Hidden' in cmd:output='120'
    elif 'StartTime.ToFileTimeUtc()' in cmd and 'WaitForExit' not in cmd and 'fault_exists=' not in cmd:output='123456'
    elif 'owned process PID was reused' in cmd:output='KILLED'
    elif 'Get-Content' in cmd and 'ctrl-listener-' in cmd:
     port=re.search(r'ctrl-listener-',cmd);output='\n'.join('recv echo:ctrl-'+str(p)+'-'+str(i) for p in (28790,29094,29095) for i in range(5))
    elif "$c=[Net.Sockets.UdpClient]" in cmd:
     loop=re.search(r"'(ctrl-loopback-(v[46])-[a-z0-9]+)'",cmd);self.marker=loop.group(1);family=loop.group(2).upper();diverted=self.marker.replace('ctrl-loopback','ctrl-diverted');port=39998 if family=='V4' else 39999;raw=self.pcap_bytes(family,self.marker,diverted,port);self.packet_files={'packets.pcap':raw,'packets-raw.pcap':raw};output=json.dumps({'loopback_sent':len(self.marker),'diverted_sent':len(diverted)})
    elif "Filter '*.pcap'" in cmd and ').Count' in cmd:output='2'
    elif '$rows=@($files' in cmd:
     output=json.dumps({'run_dir':'memory-guest-run','files':[{'name':name,'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest()} for name,raw in self.packet_files.items()]})
    elif "Filter 'packets" in cmd:
     name=re.search(r"Filter '(packets[^']*)'",cmd).group(1);output=base64.b64encode(self.packet_files[name]).decode()
    elif 'loopback-receipts-' in cmd and '@{content=' in cmd:output=json.dumps({'content':self.marker,'base64':base64.b64encode(self.marker.encode()).decode()})
    else:return super().exchange(kind,value)
    return {'output':output,'raw':output,'exit_code':0,'is_error':False}
   return super().exchange(kind,value)
 def assert_target(self,address):
  if address[0]!=self.inputs['listen_ip']:raise AssertionError('old or unbound VM target '+str(address))

class OriginalControlTests(unittest.TestCase):
 setUp=OriginalMcpTests.setUp
 def test_default_and_each_management_port_use_current_vm(self):
  for unit in ['CONTROL-DEFAULT']+['CONTROL-EXTRA-'+str(port) for port in (28787,28790,29094,29095)]:
   with self.subTest(unit=unit):
    boundary=ControlDomainBoundary(self.inputs,self.root/(unit+'-domain'));out=self.root/unit
    value=m.run('MCP-SPECIAL-IPC',out,self.inputs,selected=[unit],boundary=boundary,fixture=True)
    self.assertEqual('pass',value['checks'][unit]['status'],m.read(out/'units'/unit/'result.json'))
    self.assertEqual([],json.loads(boundary.service_bytes)['extra_control_ports'])
    rows,clean,details=o.evaluate(ROOT,out,'MCP-SPECIAL-IPC',[unit],self.inputs,allow_fixture=True);self.assertEqual('pass',rows[0]['status'],details);self.assertTrue(clean)
 def test_original_loopback_v4_v6_bytes_and_replay(self):
  for family in ('V4','V6'):
   with self.subTest(family=family):
    unit='LOOPBACK-'+family;out=self.root/unit;boundary=ControlDomainBoundary(self.inputs,self.root/(unit+'-domain'))
    value=m.run('MCP-SPECIAL-IPC',out,self.inputs,selected=[unit],boundary=boundary,fixture=True)
    self.assertEqual('pass',value['checks'][unit]['status'],m.read(out/'units'/unit/'result.json'))
    rows,clean,details=o.evaluate(ROOT,out,'MCP-SPECIAL-IPC',[unit],self.inputs,allow_fixture=True);self.assertEqual('pass',rows[0]['status'],details);self.assertTrue(clean)
 def test_management_text_substrings_and_redirected_marker_cannot_pass(self):
  for mode in ('management-only','substring','redirected'):
   with self.subTest(mode=mode):
    unit='LOOPBACK-V4';out=self.root/mode;boundary=ControlDomainBoundary(self.inputs,self.root/(mode+'-domain'),mode)
    value=m.run('MCP-SPECIAL-IPC',out,self.inputs,selected=[unit],boundary=boundary,fixture=True)
    self.assertEqual('fail',value['checks'][unit]['status'],m.read(out/'units'/unit/'result.json'))
    rows,clean,details=o.evaluate(ROOT,out,'MCP-SPECIAL-IPC',[unit],self.inputs,allow_fixture=True);self.assertEqual('fail',rows[0]['status'],details);self.assertTrue(clean)


class InitializationProcessBoundary(IpcProcessBoundary):
 def exchange(self,kind,value):
  with self.guard:
   if kind=='http' and json.loads(value['data'])['params']['name']=='start':
    self.running=False;self.terminal=True;self.version+=1
    return self.response({'service':'fakenetng-mcp','state':'stopped','state_version':self.version,'run_id':None,'controller':None,'config_identity':self.inputs['config_identity'],'last_run_outcome':'failed','error':None})
   if kind=='powershell' and "throw 'S2 receipt not unique'" in value['command']:
    log='Traceback (most recent call last):\n  File "fakenet/mcp/managed.py", line 1, in child_main\n  File "fakenet/fakenet.py", line 2, in start\n  File "fakenet/mcp/faultinject.py", line 3, in initialize\nRuntimeError: injected managed initialization failure'
    output=json.dumps({'run_id':self.run_id,'receipt':self.fault,'log':log,'parent':json.dumps({'event':'health_state','frame':{'state':'failed','run_id':self.run_id}}),'child':json.dumps({'event':'send','frame':{'error':'injected managed initialization failure','run_id':self.run_id}})})
    return {'output':output,'raw':output,'exit_code':0,'is_error':False}
   return super().exchange(kind,value)

class OriginalInitializationTests(unittest.TestCase):
 setUp=OriginalMcpTests.setUp
 def run_initialization(self):
  unit='INITIALIZATION-FAILURE';out=self.root/unit
  value=m.run('MCP-SPECIAL-IPC',out,self.inputs,selected=[unit],boundary=InitializationProcessBoundary(self.inputs),fixture=True)
  self.assertEqual('pass',value['checks'][unit]['status'],m.read(out/'units'/unit/'result.json'))
  rows,clean,details=o.evaluate(ROOT,out,'MCP-SPECIAL-IPC',[unit],self.inputs,allow_fixture=True);self.assertEqual('pass',rows[0]['status'],details);self.assertTrue(clean)
  return out
 def test_actual_initialization_stack_nonce_child_and_recovery_replay(self):self.run_initialization()
 def test_configuration_error_or_wrong_nonce_is_not_initialization_evidence(self):
  out=self.run_initialization();path=out/'units/INITIALIZATION-FAILURE/trace.json';trace=m.read(path)
  for row in trace['records']:
   if row['kind']=='powershell' and "throw 'S2 receipt not unique'" in row['input']['command']:
    data=json.loads(row['output']['output']);data['receipt']['nonce']='different';data['log']='ConfigError: invalid configuration';data['child']='';row['output']['output']=json.dumps(data)
  path.write_text(json.dumps(trace))
  rows,clean,details=o.evaluate(ROOT,out,'MCP-SPECIAL-IPC',['INITIALIZATION-FAILURE'],self.inputs,allow_fixture=True);self.assertEqual('fail',rows[0]['status'],details);self.assertTrue(clean)


class InvalidControlBoundary(ControlDomainBoundary):
 def __init__(self,inputs,root,stale=False):
  super().__init__(inputs,root);self.service_log=b'config load failed ConfigError extra control old\n';self.stale=stale;self.service_state='Running'
 def exchange(self,kind,value):
  if kind=='powershell':
   cmd=value['command'];import re,base64
   if '$b=[IO.File]::ReadAllBytes(' in cmd and '@{sha256=' in cmd and 'service.json' in cmd:
    output=json.dumps({'sha256':hashlib.sha256(self.service_bytes).hexdigest(),'base64':base64.b64encode(self.service_bytes).decode()})
   elif '[IO.File]::WriteAllText(' in cmd and "service.json','" in cmd:
    self.service_bytes=re.search(r"service.json','(.*?)',\[Text.UTF8Encoding\]",cmd).group(1).replace("''", "'").encode();output='written'
   elif 'if(Test-Path $p){(Get-Item $p).Length}else{0}' in cmd:output=str(len(self.service_log))
   elif 'sc.exe start fakenetng-mcp' in cmd and 'Seconds 8' in cmd:
    from fakenet.mcp.config import ServiceConfig,ConfigError
    try:ServiceConfig.from_dict(json.loads(self.service_bytes));self.service_state='Running'
    except ConfigError as exc:
     self.service_state='Stopped'
     if not self.stale:self.service_log+=('config load failed ConfigError '+str(exc)+'\n').encode()
    output=self.service_state
   elif '$reader=[IO.StreamReader]' in cmd:
    offset=int(re.search(r'\.Seek\((\d+),',cmd).group(1));output=self.service_log[offset:].decode()
   elif "$bytes=[Convert]::FromBase64String(" in cmd:
    self.service_bytes=base64.b64decode(re.search(r"FromBase64String\('([^']*)'\)",cmd).group(1));output='restored'
   elif 'service did not stop for variant' in cmd:self.service_state='Stopped';output='stopped'
   elif 'sc.exe start fakenetng-mcp' in cmd and 'Seconds 5' in cmd:self.service_state='Running';output='Running'
   else:return super().exchange(kind,value)
   return {'output':output,'raw':output,'exit_code':0,'is_error':False}
  return super().exchange(kind,value)

class OriginalInvalidControlTests(unittest.TestCase):
 setUp=OriginalMcpTests.setUp
 def run_invalid(self,stale=False):
  unit='CONTROL-INVALID';out=self.root/('invalid-stale' if stale else 'invalid');boundary=InvalidControlBoundary(self.inputs,self.root/'domain',stale)
  before=boundary.service_bytes
  value=m.run('MCP-SPECIAL-IPC',out,self.inputs,selected=[unit],boundary=boundary,fixture=True)
  self.assertEqual(before,boundary.service_bytes)
  rows,clean,details=o.evaluate(ROOT,out,'MCP-SPECIAL-IPC',[unit],self.inputs,allow_fixture=True);self.assertTrue(clean,details)
  return value,rows,details
 def test_all_illegal_types_refused_by_actual_config_validator(self):
  value,rows,details=self.run_invalid();self.assertEqual('pass',value['checks']['CONTROL-INVALID']['status']);self.assertEqual('pass',rows[0]['status'],details)
 def test_old_refusal_log_cannot_prove_current_variant_refused(self):
  value,rows,details=self.run_invalid(True);self.assertEqual('fail',value['checks']['CONTROL-INVALID']['status']);self.assertEqual('fail',rows[0]['status'],details)


class OriginalControlRecoveryTests(unittest.TestCase):
 setUp=OriginalMcpTests.setUp
 def test_concurrent_service_config_change_is_preserved_and_stops_group(self):
  class ForeignChange(ControlDomainBoundary):
   def exchange(self,kind,value):
    if kind=='powershell' and 'Get-Content' in value['command'] and 'ctrl-listener-' in value['command']:
     data=json.loads(self.service_bytes);data['extra_control_ports']=[39997];self.service_bytes=json.dumps(data).encode()
    return super().exchange(kind,value)
  selected=['CONTROL-EXTRA-29094','CONTROL-DEFAULT'];out=self.root/'foreign';boundary=ForeignChange(self.inputs,self.root/'domain')
  result=m.run('MCP-SPECIAL-IPC',out,self.inputs,selected=selected,boundary=boundary,fixture=True)
  self.assertEqual([39997],json.loads(boundary.service_bytes)['extra_control_ports']);self.assertNotEqual('pass',result['checks'][selected[0]]['status']);self.assertEqual('not_run',result['checks'][selected[1]]['status'])
  rows,clean,details=o.evaluate(ROOT,out,'MCP-SPECIAL-IPC',selected,self.inputs,allow_fixture=True);self.assertFalse(clean);self.assertEqual('fail',rows[0]['status']);self.assertEqual('not_run',rows[1]['status'])


class PublicSpecialMcpCliTests(unittest.TestCase):
 setUp=PublicMcpCliTests.setUp
 cli=PublicMcpCliTests.cli
 def test_original_catalog_control_loopback_and_bad_capture_rejudge(self):
  import acceptance as a
  checks=['CONTROL-DEFAULT','CONTROL-EXTRA-29094','CONTROL-INVALID','LOOPBACK-V4','LOOPBACK-V6']
  candidate={'schema':a.CANDIDATE_V2,'source_commit':self.inputs['identity']['source_commit'],'package_sha256':self.inputs['identity']['package_sha256'],'package_path':self.inputs['package'],'package_manifest':self.inputs['manifest'],'offline_fixture':True}
  environment={'schema':a.ENVIRONMENT_V2,'targets':['windows-vm'],'interpreters':{'python':sys.executable},'work_root':str(self.base),'allowed_actions':['native','vm-execute'],'endpoints':[],'auth_refs':[],'native_runtime':{'transport':'windows-mcp-velo','identity':self.inputs['target'],**self.inputs['channel']},'mcp':self.inputs,'mcp_checks':{'MCP-SPECIAL-IPC':checks}}
  (self.base/'candidate.json').write_text(json.dumps(candidate));(self.base/'environment.json').write_text(json.dumps(environment))
  digest=m.sha256(ROOT/'docs/acceptance/catalog.json')
  result=self.cli('plan','--mode','selected','--case','MCP-SPECIAL-IPC','--candidate',self.base/'candidate.json','--environment',self.base/'environment.json','--output',self.run/'plan.json');self.assertEqual(0,result[0],result)
  with mock.patch.object(m,'NativeBoundary',side_effect=lambda *args,**kwargs:InvalidControlBoundary(self.inputs,self.base/'domain')):
   result=self.cli('execute','--plan',self.run/'plan.json')
  self.assertEqual(0,result[0],result)
  result=self.cli('judge','--plan',self.run/'plan.json','--results',self.run/'results','--output',self.run/'independent.json');self.assertEqual(0,result[0],result)
  summary=m.read(self.run/'independent.json');self.assertTrue(summary['fixture_contract_pass']);self.assertFalse(summary['full_functional_pass']);self.assertEqual(digest,m.sha256(ROOT/'docs/acceptance/catalog.json'))
  case_dir=self.run/'results/MCP-SPECIAL-IPC';path=case_dir/'driver/units/LOOPBACK-V4/trace.json';trace=m.read(path)
  for row in trace['records']:
   if row['kind']=='powershell' and "Filter 'packets" in row['input']['command']:
    row['output']['output']=__import__('base64').b64encode(b'invalid actual capture bytes').decode()
  path.write_text(json.dumps(trace));receipt=m.read(case_dir/'receipt.json')
  for item in receipt['artifacts']:item['sha256']=m.sha256(item['path'])
  (case_dir/'receipt.json').write_text(json.dumps(receipt));index=m.read(self.run/'results/results.json')
  for row in index['receipts']:
   if row['case_id']=='MCP-SPECIAL-IPC':row['sha256']=m.sha256(case_dir/'receipt.json')
  (self.run/'results/results.json').write_text(json.dumps(index))
  result=self.cli('judge','--plan',self.run/'plan.json','--results',self.run/'results','--output',self.run/'negative.json');self.assertNotEqual(0,result[0],result)
  summary=m.read(self.run/'negative.json');self.assertFalse(summary['fixture_contract_pass']);self.assertIn('loopback PCAP content identity differs',json.dumps(summary))


class ListenerProcessBoundary(IpcProcessBoundary):
 def exchange(self,kind,value):
  with self.guard:
   if kind=='http':
    result=super().exchange(kind,value);body=json.loads(result['body']);payload=json.loads(body['result']['content'][0]['text'])
    if payload.get('state')=='healthy':payload['health']={'identity':{'pid':121,'creation_time':'123456'},'process_alive':True,'init_evidence':True,'probe':True}
    body['result']['content'][0]['text']=json.dumps(payload);result['body']=json.dumps(body).encode();return result
   if kind=='powershell':
    cmd=value['command']
    if 'stdout_stderr.log' in cmd and '@{receipt=' in cmd:
     fault=self.fault['fault'];log=('Traceback (most recent call last)\nservice_actions\nRuntimeError: injected listener thread exception' if fault=='listener_exception' else 'Traceback (most recent call last)\n_inbound_capture_loop\ncapture_checkpoint\nRuntimeError: injected capture thread exception');output=json.dumps({'receipt':self.fault,'log':log,'stderr':log})
    elif "throw 'child scope mismatch'" in cmd:
     self.running=False;self.terminal=True;output=json.dumps({'child':{'pid':121,'creation_time':'123456','run_id':self.run_id},'exit_code':-1,'service_pid_before':12,'service_pid_after':12,'service_state_after':'Running'})
    elif 'Get-Service fakenetng-mcp | Select-Object Name,Status' in cmd:output=json.dumps({'Name':'fakenetng-mcp','Status':'Running'})
    else:return super().exchange(kind,value)
    return {'output':output,'raw':output,'exit_code':0,'is_error':False}
   return super().exchange(kind,value)

class OriginalLifecycleAdditionalTests(unittest.TestCase):
 setUp=OriginalMcpTests.setUp
 def test_original_initialization_listener_and_pinned_child_scenarios(self):
  for unit,boundary_class in (('ACC-004-S2',InitializationProcessBoundary),('ACC-004-S3',ListenerProcessBoundary),('ACC-004-S6',ListenerProcessBoundary)):
   with self.subTest(unit=unit):
    out=self.root/unit;value=m.run('MCP-P03-FULL',out,self.inputs,selected=[unit],boundary=boundary_class(self.inputs),fixture=True)
    self.assertEqual('pass',value['checks'][unit]['status'],m.read(out/'units'/unit/'result.json'))
    rows,clean,details=o.evaluate(ROOT,out,'MCP-P03-FULL',[unit],self.inputs,allow_fixture=True);self.assertEqual('pass',rows[0]['status'],details);self.assertTrue(clean)
 def test_wrong_terminated_child_identity_cannot_pass(self):
  unit='ACC-004-S6';out=self.root/unit;m.run('MCP-P03-FULL',out,self.inputs,selected=[unit],boundary=ListenerProcessBoundary(self.inputs),fixture=True)
  self.assertEqual('pass',o.evaluate(ROOT,out,'MCP-P03-FULL',[unit],self.inputs,allow_fixture=True)[0][0]['status'])
  path=out/'units'/unit/'trace.json';trace=m.read(path)
  for row in trace['records']:
   if row['kind']=='powershell' and "throw 'child scope mismatch'" in row['input']['command']:
    data=json.loads(row['output']['output']);data['child']['pid']=999;row['output']['output']=json.dumps(data)
  path.write_text(json.dumps(trace));rows,clean,details=o.evaluate(ROOT,out,'MCP-P03-FULL',[unit],self.inputs,allow_fixture=True);self.assertEqual('fail',rows[0]['status'],details);self.assertTrue(clean)

if __name__=='__main__':unittest.main()
