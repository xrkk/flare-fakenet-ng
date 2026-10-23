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
 def prepare(self,case='MCP-P02-FULL',checks=None):
  checks=['ACC-005'] if checks is None else checks
  import acceptance as a
  candidate={'schema':a.CANDIDATE_V2,'source_commit':self.inputs['identity']['source_commit'],'package_sha256':self.inputs['identity']['package_sha256'],'package_path':self.inputs['package'],'package_manifest':self.inputs['manifest'],'offline_fixture':True}
  environment={'schema':a.ENVIRONMENT_V2,'targets':['windows-vm'],'interpreters':{'python':sys.executable},'work_root':str(self.base),'allowed_actions':['native','vm-execute'],'endpoints':[],'auth_refs':[],
   'native_runtime':{'transport':'windows-mcp-velo','identity':self.inputs['target'],**self.inputs['channel']},'mcp':self.inputs,'mcp_checks':{case:checks}}
  (self.base/'candidate.json').write_text(json.dumps(candidate));(self.base/'environment.json').write_text(json.dumps(environment))
  original=m.sha256(ROOT/'docs/acceptance/catalog.json')
  result=self.cli('plan','--mode','selected','--case',case,'--candidate',self.base/'candidate.json','--environment',self.base/'environment.json','--output',self.run/'plan.json');self.assertEqual(0,result[0],result)
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


class SnapshotProcessBoundary(ReadOnlyBoundary):
 """Actual StateSnapshot/BaselineStore bytes; SCM/filesystem ACL edges only."""
 def __init__(self,inputs,root):
  super().__init__(inputs);self.root=Path(root);self.root.mkdir(parents=True,exist_ok=True);self.t=1700000000.;self.n=0;self.version=7;self.state='stopped';self.run_id=None;self.denied=False;self.listener=False;self.recovery='stopped'
  from fakenet.mcp.snapshot import StateSnapshot
  from fakenet.mcp.baseline import BaselineStore
  self.snapshot=StateSnapshot(self.root/'state/state.json');self.baselines=BaselineStore(self.root/'baselines')
 def next_uuid(self):self.n+=1;return '33333333-3333-4333-8333-%012d'%self.n
 def normalize_recovery(self):
  marker,corrupt=self.snapshot.read()
  self.recovery='failed' if corrupt or self.listener else 'stopped';self.state=self.recovery;self.run_id=None
  if marker and self.recovery=='stopped':self.snapshot.clear_recovery(**marker)
 def response(self,payload):return {'status':200,'headers':{'Content-Type':'application/json'},'body':json.dumps({'result':{'content':[{'text':json.dumps(payload)}]}}).encode(),'http_error':False}
 def exchange(self,kind,value):
  import base64,re
  if kind in ('time','monotonic'):self.t+=.02;return self.t
  if kind=='sleep':self.t+=value['seconds'];return None
  if kind=='uuid':return self.next_uuid()
  if kind=='http':
   req=json.loads(value['data']);tool=req['params']['name']
   if tool in ('start','stop','load_config','get_status'):
    error=None
    if tool!='get_status':self.version+=1
    if tool=='start':
     if self.denied or self.state=='failed':error={'code':'snapshot_write_failed' if self.denied else 'recovery_required'}
     else:
      self.run_id=self.next_uuid();self.state='healthy';sections={k:'unchanged' for k in ('routes','dns_servers','windivert_processes','listen_ports','services')};baseline=self.baselines.save(self.run_id,sections)
      self.snapshot.write(run_id=self.run_id,controller_id='11111111-2222-4333-8444-555555555555',state_version=self.version,command_id='memory-accepted-start',config_sha256=self.inputs['config_identity']['sha256'],baseline_path=baseline['path'],needs_recovery=True)
    if tool=='stop':
     marker,corrupt=self.snapshot.read()
     if marker:self.snapshot.clear_recovery(**marker)
     self.state='stopped';self.run_id=None
    return self.response({'service':'fakenetng-mcp','state':self.state,'state_version':self.version,'run_id':self.run_id,'controller':None,'config_identity':self.inputs['config_identity'],'error':error})
  if kind=='powershell':
   cmd=value['command']
   if 'baselines' in cmd and '-Filter' in cmd and ').Count' in cmd:output=str(len(list(self.baselines.root.glob('*.json'))))
   elif '$rows=@($files' in cmd and 'state export exceeds bound' in cmd:
    files=list(self.baselines.root.glob('*.json'))+([self.snapshot.path] if self.snapshot.path.exists() else []);rows=[]
    for path in files:
     raw=path.read_bytes();win='C:\\ProgramData\\FakeNet-NG-MCP\\'+('state\\state.json' if path==self.snapshot.path else 'baselines\\'+path.name);rows.append({'path':win,'name':path.name,'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'body':base64.b64encode(raw).decode()})
    output=json.dumps(rows)
   elif 'owned file changed' in cmd and 'Remove-Item' in cmd:
    name=__import__('pathlib').PureWindowsPath(re.search(r"\$p='([^']+)'",cmd).group(1)).name;path=self.snapshot.path if name=='state.json' else self.baselines.root/name
    expected=re.search(r"-ne '([a-f0-9]{64})'",cmd).group(1)
    if hashlib.sha256(path.read_bytes()).hexdigest()!=expected:raise ValueError('owned file changed')
    path.unlink();output='REMOVED'
   elif 'Base64String([IO.File]::ReadAllBytes((' in cmd:output=base64.b64encode(self.snapshot.path.read_bytes()).decode()
   elif 'RESTORED_OWNED_RESPONSIBILITY' in cmd:
    raw=base64.b64decode(re.search(r"FromBase64String\('([^']+)'\)",cmd).group(1));self.snapshot.path.write_bytes(raw);output='RESTORED_OWNED_RESPONSIBILITY'
   elif "'NOT JSON {{'" in cmd:self.snapshot.path.write_bytes(b'NOT JSON {{');output='CORRUPTED'
   elif 'no service instance to kill' in cmd:self.normalize_recovery();output=json.dumps({'killed_pid':12,'created':'123456','image':'memory-service'})
   elif 'startup recovery outcome' in cmd:output='startup recovery outcome '+self.recovery
   elif '-EncodedCommand' in cmd:self.listener=True;output=json.dumps({'pid':125,'created':123456})
   elif 'owned listener not listening' in cmd:output='READY'
   elif 'owned process PID was reused' in cmd:self.listener=False;output='KILLED'
   elif 'icacls' in cmd:
    self.denied='/deny' in cmd;output='DENIED' if self.denied else 'GRANTED'
   elif 'controlled pre-stop failed' in cmd:self.normalize_recovery();output='controlled service stop completed'
   elif 'Get-Service fakenetng-mcp | Select-Object Name,Status' in cmd:self.normalize_recovery();output=json.dumps({'Name':'fakenetng-mcp','Status':'Running'})
   elif 'Get-Content' in cmd and 'state.json' in cmd:output=self.snapshot.path.read_text()
   elif 'SCAN_OK' in cmd:output='10\n0\nSCAN_OK'
   else:return super().exchange(kind,value)
   return {'output':output,'raw':output,'exit_code':0,'is_error':False}
  return super().exchange(kind,value)

class OriginalSnapshotTests(unittest.TestCase):
 setUp=OriginalMcpTests.setUp
 def test_original_snapshot_corruption_write_failure_and_owned_cleanup(self):
  unit='ACC-008';out=self.root/'predecessor';value=m.run('MCP-P03-FULL',out,self.inputs,selected=[unit],boundary=SnapshotProcessBoundary(self.inputs,self.root/'guest'),fixture=True)
  self.assertEqual('pass',value['checks'][unit]['status'],m.read(out/'units'/unit/'result.json'))
  rows,clean,details=o.evaluate(ROOT,out,'MCP-P03-FULL',[unit],self.inputs,allow_fixture=True);self.assertEqual('pass',rows[0]['status'],details);self.assertTrue(clean)
  import copy,acceptance_mcp_dependencies as dependencies
  inputs=copy.deepcopy(self.inputs);path=out/'units'/unit/'result.json';inputs['references']={unit:{'directory':str(out),'result_sha256':m.sha256(path)}}
  capability=dependencies.verify_acc008(inputs,root=ROOT,fixture=True);self.assertFalse(capability['prestop_audit_failure_proven']);self.assertEqual('startup-corrupt-snapshot-recovery-only',capability['scope'])
  with self.assertRaisesRegex(ValueError,'fixture'):
   dependencies.verify_acc008(inputs,root=ROOT,fixture=False)
  result=m.read(path);result['status']='fail';path.write_text(json.dumps(result));inputs['references'][unit]['result_sha256']=m.sha256(path)
  with self.assertRaisesRegex(ValueError,'not verified'):
   dependencies.verify_acc008(inputs,root=ROOT,fixture=True)
  result['status']='pass';path.write_text(json.dumps(result));inputs['references'][unit]['result_sha256']=m.sha256(path)
  inputs['identity']['candidate_id']='wrong'
  with self.assertRaisesRegex(ValueError,'identity differs'):dependencies.verify_acc008(inputs,root=ROOT,fixture=True)
 def test_missing_predecessor_stops_before_native_factory(self):
  with mock.patch.object(m,'NativeBoundary',side_effect=AssertionError('no service action')):
   with self.assertRaisesRegex(ValueError,'requires this execution'):m.run('MCP-P04-FULL',self.root/'missing',self.inputs,selected=['ACC-019'])
  self.assertFalse((self.root/'missing').exists())


class ControlledExitBoundary(IpcProcessBoundary):
 def __init__(self,inputs,root,mode='normal'):
  super().__init__(inputs);self.root=Path(root);self.mode=mode;self.service_state='Running';self.pid=12;self.birth='1234';self.instance='instance-1';self.attempt=0;self.phase='idle';self.pending=None;self.audit_injected=False;self.baseline_bytes=b'';self.reason=None;self.log='';self.file_replacement=False
  self.cfg={'listen_ip':inputs['listen_ip'],'listen_port':28788,'allowed_host_ips':[inputs['allowed_host']],'extra_control_ports':[],'stop_grace_seconds':60};self.cfg_bytes=json.dumps(self.cfg).encode()
 def facts(self):
  image=m.read(self.inputs['manifest'])['files'][0]['sha256']
  return {'state':self.service_state,'pid':self.pid if self.service_state=='Running' else 0,'birth':self.birth if self.service_state=='Running' else None,'prestop':{'pid':self.pid,'creation_time':self.birth,'instance_id':self.instance,'attempt':self.attempt,'phase':self.phase,'reason':self.reason},'marker':{'needs_recovery':self.running or self.phase=='failed'},'config_base64':__import__('base64').b64encode(self.cfg_bytes).decode(),'config_sha256':hashlib.sha256(self.cfg_bytes).hexdigest(),'config':self.cfg,'image_sha256':image,'children':[{'ProcessId':121}] if self.running else [],'log_length':0,'log':self.log}
 def exchange(self,kind,value):
  with self.guard:
   if kind=='http':
    req=json.loads(value['data']);tool=req['params']['name']
    if self.pending and self.phase=='draining' and tool in ('create_config','edit_config'):return self.response({'error':{'code':'not_allowed_in_state','message':'controlled shutdown'}})
    if tool=='get_status' and self.phase=='failed':return self.response({'state':'failed','state_version':self.version,'run_id':self.run_id,'controller':None,'config_identity':self.inputs['config_identity'],'failure_reason':self.reason})
    if tool=='start':
     self.running=True;self.phase='idle';self.reason=None;self.log='';self.baseline_bytes=json.dumps({'run_id':self.run_id,'sections':{'services':'original'}}).encode()
    return super().exchange(kind,value)
   if kind=='powershell':
    cmd=value['command'];import re,base64
    if cmd.startswith('# acc019:'):
     label=cmd.splitlines()[0][9:]
     if label=='fact':output=json.dumps(self.facts())
     elif label in ('direct-stop','failed-direct-stop'):output=json.dumps({'exit_code':0 if self.mode=='accept-direct-stop' else 1061,'state':'Running','pid':self.pid,'birth':self.birth})
     elif label.startswith('launch-'):
      nonce=re.search(r'acc019-([a-f0-9]{32})',cmd).group(1);mode=label[7:];argv=['stop'] if mode=='stop' else ['install','--listen-ip',self.cfg['listen_ip'],'--port','28788','--allowed-host',self.cfg['allowed_host_ips'][0]]
      self.attempt+=1;self.phase='draining';self.pending={'nonce':nonce,'argv':argv,'pid':140,'birth':'1456','completed':True,'wrapper_exited':True,'exit_code':0,'stdout':'','stderr':''};output=json.dumps({'pid':139,'birth':'1455'})
     elif label=='receipt':
      if self.pending is None:output='null'
      else:
       if self.audit_injected:
        self.phase='failed';self.reason='environment restoration audit failed';self.pending['exit_code']=1;self.running=False;self.terminal=True
        if self.mode=='failure-exits':self.service_state='Stopped'
       else:
        self.phase='succeeded';self.running=False;self.terminal=True;self.service_state='Stopped';self.log='\n'.join('STOP_PHASE_END phase='+name+' elapsed_ms=1 healthy=True' for name in ('listeners','diverter','complete'))
        if self.mode=='wrong-attempt':self.attempt=0
       output=json.dumps(self.pending);self.pending=None
     elif label=='replace-after-stopped':
      if self.service_state!='Stopped':raise AssertionError('premature replacement')
      self.file_replacement=True;output=json.dumps({'source':'a'*64,'copy':'a'*64})
     elif label=='restart':self.service_state='Running';self.pid+=1;self.birth=str(int(self.birth)+1);self.instance='instance-'+str(self.pid);self.phase='idle';self.reason=None;self.running=False;output='Running'
     elif label=='restore-config':output=''
     elif label=='baseline-read':output=json.dumps({'base64':base64.b64encode(self.baseline_bytes).decode(),'sha256':hashlib.sha256(self.baseline_bytes).hexdigest()})
     elif label=='baseline-write':
      expected=re.search(r"-ne '([a-f0-9]{64})'",cmd).group(1)
      if expected!=hashlib.sha256(self.baseline_bytes).hexdigest():raise ValueError('baseline changed')
      self.baseline_bytes=base64.b64decode(re.search(r"FromBase64String\('([^']*)'\)",cmd).group(1));self.audit_injected='ACC019-INJECTED-' in self.baseline_bytes.decode();output=json.dumps({'sha256':hashlib.sha256(self.baseline_bytes).hexdigest()})
     else:raise AssertionError('unexpected ACC019 edge '+label)
     return {'output':output,'raw':output,'exit_code':0,'is_error':False}
    if 'fault_exists=' in cmd:
     data=json.loads(ReadOnlyBoundary.exchange(self,kind,value)['output']);data['service_config']=self.cfg;data['pid']=self.pid;data['birth']=self.birth;output=json.dumps(data);return {'output':output,'raw':output,'exit_code':0,'is_error':False}
    if 'controlled pre-stop failed' in cmd:
     self.service_state='Stopped';self.running=False;self.phase='succeeded';output='controlled service stop completed';return {'output':output,'raw':output,'exit_code':0,'is_error':False}
    return super().exchange(kind,value)
   return super().exchange(kind,value)

class OriginalControlledExitTests(unittest.TestCase):
 setUp=OriginalMcpTests.setUp
 def inputs_with_predecessor(self):
  import copy
  out=self.root/'predecessor';m.run('MCP-P03-FULL',out,self.inputs,selected=['ACC-008'],boundary=SnapshotProcessBoundary(self.inputs,self.root/'snapshot-guest'),fixture=True)
  inputs=copy.deepcopy(self.inputs);inputs['actions'].append('deploy');inputs['references']={'ACC-008':{'directory':str(out),'result_sha256':m.sha256(out/'units/ACC-008/result.json')}};return inputs
 def test_current_cli_stop_upgrade_and_same_instance_audit_failure(self):
  inputs=self.inputs_with_predecessor();out=self.root/'exit';boundary=ControlledExitBoundary(inputs,self.root/'guest')
  value=m.run('MCP-P04-FULL',out,inputs,selected=['ACC-019'],boundary=boundary,fixture=True)
  self.assertEqual('pass',value['checks']['ACC-019']['status'],m.read(out/'units/ACC-019/result.json'));self.assertTrue(boundary.file_replacement);self.assertFalse(boundary.audit_injected)
  rows,clean,details=o.evaluate(ROOT,out,'MCP-P04-FULL',['ACC-019'],inputs,allow_fixture=True);self.assertEqual('pass',rows[0]['status'],details);self.assertTrue(clean,details)
 def test_direct_stop_acceptance_or_failed_audit_exit_is_not_pass(self):
  for mode in ('accept-direct-stop','failure-exits','wrong-attempt'):
   with self.subTest(mode=mode):
    self.setUp();inputs=self.inputs_with_predecessor();out=self.root/'exit';value=m.run('MCP-P04-FULL',out,inputs,selected=['ACC-019'],boundary=ControlledExitBoundary(inputs,self.root/'guest',mode),fixture=True)
    self.assertNotEqual('pass',value['checks']['ACC-019']['status'],m.read(out/'units/ACC-019/result.json'))
    rows,clean,details=o.evaluate(ROOT,out,'MCP-P04-FULL',['ACC-019'],inputs,allow_fixture=True);self.assertEqual('fail',rows[0]['status'],details)


class PublicControlledExitCliTests(unittest.TestCase):
 setUp=PublicMcpCliTests.setUp
 cli=PublicMcpCliTests.cli
 def test_same_catalog_predecessor_stop_upgrade_and_rehashed_wrong_attempt(self):
  import acceptance as a
  self.inputs['actions'].append('deploy')
  candidate={'schema':a.CANDIDATE_V2,'source_commit':self.inputs['identity']['source_commit'],'package_sha256':self.inputs['identity']['package_sha256'],'package_path':self.inputs['package'],'package_manifest':self.inputs['manifest'],'offline_fixture':True}
  environment={'schema':a.ENVIRONMENT_V2,'targets':['windows-vm'],'interpreters':{'python':sys.executable},'work_root':str(self.base),'allowed_actions':['native','vm-execute'],'endpoints':[],'auth_refs':[],'native_runtime':{'transport':'windows-mcp-velo','identity':self.inputs['target'],**self.inputs['channel']},'mcp':self.inputs,'mcp_checks':{'MCP-P04-FULL':['ACC-019']}}
  (self.base/'candidate.json').write_text(json.dumps(candidate));(self.base/'environment.json').write_text(json.dumps(environment))
  digest=m.sha256(ROOT/'docs/acceptance/catalog.json')
  result=self.cli('plan','--mode','selected','--case','MCP-P04-FULL','--candidate',self.base/'candidate.json','--environment',self.base/'environment.json','--output',self.run/'plan.json');self.assertEqual(0,result[0],result)
  plan=m.read(self.run/'plan.json');self.assertEqual(['MCP-P03-FULL','MCP-P04-FULL'],plan['required_cases']);self.assertEqual(['ACC-008'],plan['required_checks']['MCP-P03-FULL'])
  import copy
  bad=copy.deepcopy(plan);bad['required_cases'].reverse()
  with self.assertRaisesRegex(ValueError,'predecessor before P04'):__import__('acceptance_mcp_dependencies').validate_plan_order(bad)
  with mock.patch.object(m,'NativeBoundary',side_effect=lambda root,inputs,journal:SnapshotProcessBoundary(inputs,self.base/'snapshot-domain') if 'MCP-P03-FULL' in str(journal) else ControlledExitBoundary(inputs,self.base/'exit-domain')):
   result=self.cli('execute','--plan',self.run/'plan.json')
  self.assertEqual(0,result[0],result)
  result=self.cli('judge','--plan',self.run/'plan.json','--results',self.run/'results','--output',self.run/'independent.json');self.assertEqual(0,result[0],result)
  self.assertEqual(digest,m.sha256(ROOT/'docs/acceptance/catalog.json'));summary=m.read(self.run/'independent.json');self.assertTrue(summary['fixture_contract_pass']);self.assertFalse(summary['full_functional_pass'])
  case_dir=self.run/'results/MCP-P04-FULL';path=case_dir/'driver/units/ACC-019/trace.json';trace=m.read(path)
  for row in trace['records']:
   if row['kind']=='powershell' and row['input']['command'].startswith('# acc019:fact'):
    data=json.loads(row['output']['output']);data['prestop']['attempt']=0;row['output']['output']=json.dumps(data)
  path.write_text(json.dumps(trace));receipt=m.read(case_dir/'receipt.json')
  for item in receipt['artifacts']:item['sha256']=m.sha256(item['path'])
  (case_dir/'receipt.json').write_text(json.dumps(receipt));index=m.read(self.run/'results/results.json')
  for row in index['receipts']:
   if row['case_id']=='MCP-P04-FULL':row['sha256']=m.sha256(case_dir/'receipt.json')
  (self.run/'results/results.json').write_text(json.dumps(index))
  result=self.cli('judge','--plan',self.run/'plan.json','--results',self.run/'results','--output',self.run/'negative.json');self.assertNotEqual(0,result[0],result);self.assertFalse(m.read(self.run/'negative.json')['fixture_contract_pass'])

class ControlledExitPendingTests(unittest.TestCase):
 setUp=OriginalMcpTests.setUp
 def test_unknown_or_unfinished_cli_does_not_grant_recovery(self):
  inputs=OriginalControlledExitTests.inputs_with_predecessor(self)
  class Unknown(ControlledExitBoundary):
   def exchange(self,kind,value):
    if kind=='powershell' and value['command'].startswith('# acc019:receipt'):
     raise OSError('transport lost before CLI completion')
    return super().exchange(kind,value)
  out=self.root/'unknown';boundary=Unknown(inputs,self.root/'guest');result=m.run('MCP-P04-FULL',out,inputs,selected=['ACC-019','ACC-015'],boundary=boundary,fixture=True)
  self.assertIsNotNone(boundary.pending);self.assertEqual('not_run',result['checks']['ACC-015']['status']);trace=m.read(out/'units/ACC-019/trace.json');self.assertIsNotNone(trace['recovery_error']);self.assertIn('preserve scene',trace['recovery_error']['message'])


class PublicIncidentSliceCliTests(unittest.TestCase):
 setUp=PublicMcpCliTests.setUp
 cli=PublicMcpCliTests.cli
 prepare=PublicMcpCliTests.prepare
 def test_selected_slice_uses_formal_driver_without_expanding_full(self):
  self.prepare('MCP-P04-FULL',['INCIDENT-INTEGRITY'])
  with mock.patch.object(m,'NativeBoundary',side_effect=lambda *args,**kwargs:MultiRunFaultBoundary(self.inputs)):
   result=self.cli('execute','--plan',self.run/'plan.json')
  self.assertEqual(0,result[0],result)
  result=self.cli('judge','--plan',self.run/'plan.json','--results',self.run/'results','--output',self.run/'independent.json');self.assertEqual(0,result[0],result)
  summary=m.read(self.run/'independent.json');self.assertTrue(summary['fixture_contract_pass']);self.assertFalse(summary['full_functional_pass']);self.assertNotIn('INCIDENT-INTEGRITY',m.CHECKS['MCP-P04-FULL'])


class ArtifactProcessBoundary(FaultProcessBoundary):
 def __init__(self,inputs,root,foreign=False,bad_transfer=False):
  super().__init__(inputs);self.archive();self.root=Path(root);self.root.mkdir(parents=True,exist_ok=True);self.foreign=foreign;self.bad_transfer=bad_transfer;self.metadata_requests=0
  import io,dpkt,socket
  stream=io.BytesIO();writer=dpkt.pcap.Writer(stream,linktype=dpkt.pcap.DLT_RAW);udp=dpkt.udp.UDP(sport=40000,dport=53,data=b'benign-artifact-flow');udp.ulen=len(udp);ip=dpkt.ip.IP(src=socket.inet_aton('192.168.204.149'),dst=socket.inet_aton('192.168.204.2'),p=17,ttl=64,data=udp);ip.len=len(ip);writer.writepkt(bytes(ip),ts=1.);self.pcap=stream.getvalue()
  from fakenet.mcp.artifacts import ArtifactRegistry,write_publication
  incident=self.root/self.run_id/'incident';incident.mkdir(parents=True)
  (incident/'manifest.json').write_bytes(self.manifest_bytes);write_publication(incident,[incident/'manifest.json'])
  run=self.root/'runs'/self.run_id;run.mkdir(parents=True);capture=run/'packets.pcap';capture.write_bytes(self.pcap);write_publication(run,[capture]);self.registry=ArtifactRegistry(self.root)
 def exchange(self,kind,value):
  import re,base64
  if kind=='http':
   req=json.loads(value['data']);tool=req['params']['name']
   if tool=='list_artifacts':
    self.metadata_requests+=1;rows=self.registry.metadata()
    for row in rows:
     relative=Path(row['path']).relative_to(self.root);row['path']=str(__import__('pathlib').PureWindowsPath(self.inputs['programdata_root'])/'artifacts'/relative)
     if self.foreign and row['type']=='pcap':row['path']=row['path'].replace(self.run_id,'44444444-4444-4444-8444-444444444444')
    return self.response({'artifacts':rows})
   if tool=='download_artifact':return {'status':200,'headers':{'Content-Type':'application/json'},'body':json.dumps({'error':{'code':-32602,'message':'unknown tool download_artifact'}}).encode(),'http_error':False}
  if kind=='powershell':
   cmd=value['command']
   if '$names=@(Get-ChildItem' in cmd:output=json.dumps(['incident'])
   elif '@{size=(Get-Item -LiteralPath $p).Length' in cmd:output=json.dumps({'size':len(self.pcap),'sha256':hashlib.sha256(self.pcap).hexdigest()})
   elif '[IO.File]::OpenRead(' in cmd and 'packets.pcap' in cmd:
    offset=int(re.search(r'\.Seek\((\d+),',cmd).group(1));count=int(re.search(r'byte\[\] (\d+)',cmd).group(1));data=self.pcap[offset:offset+count];output=base64.b64encode((b'X'*len(data)) if self.bad_transfer else data).decode()
   else:return super().exchange(kind,value)
   return {'output':output,'raw':output,'exit_code':0,'is_error':False}
  return super().exchange(kind,value)

class OriginalArtifactTests(unittest.TestCase):
 setUp=OriginalMcpTests.setUp
 def test_original_metadata_incident_and_exact_pcap_transfer(self):
  unit='ACC-015';out=self.root/unit;boundary=ArtifactProcessBoundary(self.inputs,self.root/'artifacts')
  value=m.run('MCP-P04-FULL',out,self.inputs,selected=[unit],boundary=boundary,fixture=True)
  self.assertEqual('pass',value['checks'][unit]['status'],m.read(out/'units'/unit/'result.json'))
  rows,clean,details=o.evaluate(ROOT,out,'MCP-P04-FULL',[unit],self.inputs,allow_fixture=True);self.assertEqual('pass',rows[0]['status'],details);self.assertTrue(clean)
 def test_artifact_scope_uses_frozen_programdata_root(self):
  self.inputs['programdata_root']='D:/FakeNet-MCP-State'
  self.test_original_metadata_incident_and_exact_pcap_transfer()
 def test_foreign_run_or_changed_transfer_bytes_cannot_pass(self):
  for foreign,bad in ((True,False),(False,True)):
   with self.subTest(foreign=foreign,bad_transfer=bad):
    self.setUp();unit='ACC-015';out=self.root/unit;boundary=ArtifactProcessBoundary(self.inputs,self.root/'artifacts',foreign,bad)
    value=m.run('MCP-P04-FULL',out,self.inputs,selected=[unit],boundary=boundary,fixture=True);self.assertNotEqual('pass',value['checks'][unit]['status'],m.read(out/'units'/unit/'result.json'))
    rows,clean,details=o.evaluate(ROOT,out,'MCP-P04-FULL',[unit],self.inputs,allow_fixture=True);self.assertEqual('fail',rows[0]['status'],details)


def fixture_capability(root,inputs,legacy=False):
 """Explicit synthetic closed originals, never a real independent verdict."""
 import copy,io,zipfile
 import acceptance_mcp_capabilities as cap
 root=Path(root);root.mkdir();seed=root/'mechanical-seed'
 m.run('MCP-P04-FULL',seed,inputs,selected=['INCIDENT-INTEGRITY'],boundary=MultiRunFaultBoundary(inputs),fixture=True)
 seed_record=m.read(seed/'units/INCIDENT-INTEGRITY/fault-policy_pause.json');local=dict(inputs['identity'],incidents=[]);refs=[]
 classes=list(m.FAULTS)+['ipc_permanent_timeout','ipc_eof','ipc_wrong_run','ipc_repeat','ipc_reverse','stacks_unavailable','native_crash','unknown_cause']
 for i,klass in enumerate(classes):
  directory=root/klass;directory.mkdir();run='55555555-5555-4555-8555-%012d'%(i+1);record=copy.deepcopy(seed_record);record.update({'class':klass,'run_id':run,'nonce':'fixture-nonce-'+str(i)})
  record['fault_evidence']['receipt']={'run_id':run,'receipt':{'fault':klass,'nonce':record['nonce']}}
  exported=record['incident_exports'][0];original=Path(exported['path']);target=directory/'incident.zip'
  with zipfile.ZipFile(original) as src,zipfile.ZipFile(target,'w') as dst:
   for name in src.namelist():
    raw=src.read(name)
    if name=='manifest.json':manifest=json.loads(raw);manifest['run_id']=run;raw=json.dumps(manifest).encode()
    dst.writestr(name,raw)
  exported.update({'path':str(target),'run_id':run,'sha256':m.sha256(target),'size':target.stat().st_size,'manifest':manifest})
  record['incident_exports']=[exported];record['fault_evidence']['incidents']=[{'path':'C:\\ProgramData\\FakeNet-NG-MCP\\artifacts\\'+run+'\\incident\\manifest.json','manifest':manifest}]
  path=directory/'round.json';path.write_text(json.dumps(record));refs.append({'path':str(path),'sha256':m.sha256(path)})
  local['incidents'].append({'run_id':run,'component':'fixture-only-component','failure_chain':'fixture-only-package-reference','references':[{'incident_name':'incident','member':'exception.txt','quote':'benign remote exception.txt'}]})
 lp=root/'localization.json';lp.write_text(json.dumps(local));event={'RUN_ID':'fixture-capability','TYPE':'AUDIT','AUDIT_ID':'FIXTURE-CAPABILITY-01'}
 task=root/'task.md';task.write_text('Fixture only independent product ACC014 review. No native acceptance.\n'+json.dumps(event))
 reviewer='fixture-independent';controller='fixture-controller'
 report={'capability':'ACC-014','verdict':'pass','evidence_level':'fixture','implementers':[controller],'identity':inputs['identity'],'target':inputs['target'],'config_identity':inputs['config_identity'],'manifest_sha256':inputs['manifest_sha256'],'dependencies':cap.source_pins(ROOT),'fault_records':refs,'localization':{'path':str(lp),'sha256':m.sha256(lp)}}
 report_path=root/'report.md';report_path.write_text('# Fixture capability original\n\n```json\n'+json.dumps({'older':report} if legacy else report)+'\n```\n')
 result_path=root/'result.md';result=dict(event,STATUS='COMPLETED',WORK_STOPPED=True,native_session=reviewer,controller_native=controller,audit_path=str(report_path),audit_sha256=m.sha256(report_path));result_path.write_text('```json\n'+json.dumps(result)+'\n```\n')
 receipt_path=root/'received.json';receipt=dict(event,STATUS='RECEIVED',receiver_session=controller,result_path=str(result_path),result_sha256=m.sha256(result_path));receipt_path.write_text(json.dumps(receipt))
 receive_path=root/'receive.json';receive={'event':event,'task':str(task),'task_sha256':m.sha256(task),'result':str(result_path)};receive_path.write_text(json.dumps(receive))
 accepted_path=root/'accepted.md';accepted={'author_native':controller,'decision':'pass','reviewed_result':m.sha256(result_path)};accepted_path.write_text('```json\n'+json.dumps(accepted)+'\n```\n')
 files={'task':task,'receive_config':receive_path,'result':result_path,'receipt':receipt_path,'report':report_path,'acceptance':accepted_path};mapping={}
 for key in cap.FIELDS:
  if key in report:mapping[key]={'file':'report','pointer':('/older' if legacy else '')+'/'+key}
 mapping.update(reviewer={'file':'result','pointer':'/native_session'},controller={'file':'result','pointer':'/controller_native'},report_path={'file':'result','pointer':'/audit_path'},report_sha256={'file':'result','pointer':'/audit_sha256'},accepted_verdict={'file':'acceptance','pointer':'/decision'},accepted_result_sha256={'file':'acceptance','pointer':'/reviewed_result'},accepting_controller={'file':'acceptance','pointer':'/author_native'})
 return {'schema':cap.SCHEMA,'files':{key:{'path':str(path),'sha256':m.sha256(path)} for key,path in files.items()},'mapping':mapping}

def rehash_capability(ref):
 """Fixture mutation only: preserve valid links to target semantic rejection."""
 import acceptance_mcp_capabilities as cap
 def update(name,**fields):
  path=Path(ref['files'][name]['path']);value=cap.data(path.read_bytes());value.update(fields);path.write_text(json.dumps(value));ref['files'][name]['sha256']=m.sha256(path)
 for name in ref['files']:ref['files'][name]['sha256']=m.sha256(ref['files'][name]['path'])
 update('result',audit_sha256=ref['files']['report']['sha256'])
 update('receipt',result_sha256=ref['files']['result']['sha256'])
 update('acceptance',reviewed_result=ref['files']['result']['sha256'])

class OriginalCapabilityReferenceTests(unittest.TestCase):
 setUp=OriginalMcpTests.setUp
 def evaluate(self,ref,output):
  import copy
  inputs=copy.deepcopy(self.inputs);inputs['references']={'ACC-014':ref}
  with mock.patch.object(m.NativeBoundary,'exchange',side_effect=AssertionError('closed reference must not perform native action')):
   value=m.run('MCP-P04-FULL',output,inputs,selected=['ACC-014'],boundary=ReadOnlyBoundary(inputs),fixture=True)
  rows,clean,details=o.evaluate(ROOT,output,'MCP-P04-FULL',['ACC-014'],inputs,allow_fixture=True)
  return value,rows,clean,details
 def test_closed_fixture_originals_and_legacy_pointers_rejudge_full_original_rules(self):
  for legacy in (False,True):
   with self.subTest(legacy=legacy):
    ref=fixture_capability(self.root/str(legacy),self.inputs,legacy);before={key:m.sha256(row['path']) for key,row in ref['files'].items()};value,rows,clean,details=self.evaluate(ref,self.root/('output-'+str(legacy)))
    self.assertEqual('pass',value['checks']['ACC-014']['status'],m.read(self.root/('output-'+str(legacy))/'units/ACC-014/result.json'));self.assertEqual('pass',rows[0]['status'],details);self.assertTrue(clean)
    self.assertEqual(before,{key:m.sha256(row['path']) for key,row in ref['files'].items()})
    import acceptance_mcp_capabilities as cap
    with self.assertRaisesRegex(ValueError,'non-native'):cap.load(ref,self.inputs,ROOT,fixture=False)
 def test_wrong_event_nonindependent_plan_audit_and_unaccepted_result_rejected(self):
  import acceptance_mcp_capabilities as cap
  changes=[('receipt',lambda v:v.update(AUDIT_ID='wrong'),'event differs'),('result',lambda v:v.update(native_session='fixture-controller'),'independence'),('report',lambda v:v.update(capability='workflow-plan-audit'),'product ACC014'),('acceptance',lambda v:v.update(decision='not accepted'),'product ACC014')]
  for i,(name,mutate,reason) in enumerate(changes):
   with self.subTest(name=name):
    ref=fixture_capability(self.root/('original-'+str(i)),self.inputs);path=Path(ref['files'][name]['path']);raw=cap.data(path.read_bytes());mutate(raw);path.write_text(json.dumps(raw));rehash_capability(ref)
    with self.assertRaisesRegex(ValueError,reason):cap.load(ref,self.inputs,ROOT,fixture=True)
    value,rows,clean,details=self.evaluate(ref,self.root/('bad-output-'+str(i)));self.assertNotEqual('pass',value['checks']['ACC-014']['status']);self.assertEqual('fail',rows[0]['status'],details);self.assertTrue(clean)
 def test_malformed_reference_fields_are_controlled_rejections(self):
  import copy,acceptance_mcp_capabilities as cap
  original=fixture_capability(self.root/'original',self.inputs)
  mutations=[lambda x:x.update(files=None),lambda x:x.update(mapping=None),lambda x:x['mapping'].update(verdict=None),lambda x:x['mapping']['fault_records'].update(pointer='/missing/999'),lambda x:x['files']['report'].update(path=None)]
  for i,mutate in enumerate(mutations):
   with self.subTest(index=i):
    ref=copy.deepcopy(original);mutate(ref)
    with self.assertRaises(cap.CapabilityUnavailable):cap.load(ref,self.inputs,ROOT,fixture=True)
    value,rows,clean,details=self.evaluate(ref,self.root/('invalid-'+str(i)));self.assertEqual('blocked',value['checks']['ACC-014']['status']);self.assertTrue(clean,details)
 def test_rehashed_invalid_archive_is_controlled_and_never_passes(self):
  import acceptance_mcp_capabilities as cap
  ref=fixture_capability(self.root/'original',self.inputs);report_path=Path(ref['files']['report']['path']);report=cap.data(report_path.read_bytes());record_path=Path(report['fault_records'][0]['path']);record=m.read(record_path);archive=Path(record['incident_exports'][0]['path']);archive.write_bytes(b'not a ZIP archive');record['incident_exports'][0].update(sha256=m.sha256(archive),size=archive.stat().st_size);record_path.write_text(json.dumps(record));report['fault_records'][0]['sha256']=m.sha256(record_path);report_path.write_text(json.dumps(report));rehash_capability(ref)
  value,rows,clean,details=self.evaluate(ref,self.root/'bad-archive');self.assertNotEqual('pass',value['checks']['ACC-014']['status']);self.assertEqual('fail',rows[0]['status']);self.assertTrue(clean,details)
 def test_rehash_wrong_localization_quote_does_not_grant_capability(self):
  import acceptance_mcp_capabilities as cap
  ref=fixture_capability(self.root/'original',self.inputs);report_path=Path(ref['files']['report']['path']);report=cap.data(report_path.read_bytes());local_path=Path(report['localization']['path']);local=m.read(local_path);local['incidents'][0]['references'][0]['quote']='not in original package';local_path.write_text(json.dumps(local));report['localization']['sha256']=m.sha256(local_path)
  report_path.write_text(json.dumps(report));ref['files']['report']['sha256']=m.sha256(report_path)
  result_path=Path(ref['files']['result']['path']);result=cap.data(result_path.read_bytes());result['audit_sha256']=m.sha256(report_path);result_path.write_text(json.dumps(result));ref['files']['result']['sha256']=m.sha256(result_path)
  receipt_path=Path(ref['files']['receipt']['path']);receipt=m.read(receipt_path);receipt['result_sha256']=m.sha256(result_path);receipt_path.write_text(json.dumps(receipt));ref['files']['receipt']['sha256']=m.sha256(receipt_path)
  accepted_path=Path(ref['files']['acceptance']['path']);accepted=cap.data(accepted_path.read_bytes());accepted['reviewed_result']=m.sha256(result_path);accepted_path.write_text(json.dumps(accepted));ref['files']['acceptance']['sha256']=m.sha256(accepted_path)
  value,rows,clean,details=self.evaluate(ref,self.root/'bad-quote');self.assertEqual('fail',value['checks']['ACC-014']['status']);self.assertEqual('fail',rows[0]['status'],details);self.assertTrue(clean)

class PublicCapabilityCliTests(unittest.TestCase):
 setUp=PublicMcpCliTests.setUp
 cli=PublicMcpCliTests.cli
 prepare=PublicMcpCliTests.prepare
 def test_same_catalog_closed_reference_and_rehashed_wrong_quote(self):
  import acceptance_mcp_capabilities as cap
  self.inputs['references']={'ACC-014':fixture_capability(self.base/'original',self.inputs)}
  self.prepare('MCP-P04-FULL',['ACC-014'])
  with mock.patch.object(m,'NativeBoundary',side_effect=AssertionError('reference must not construct auth/target channel')):
   result=self.cli('execute','--plan',self.run/'plan.json')
  self.assertEqual(0,result[0],result)
  result=self.cli('judge','--plan',self.run/'plan.json','--results',self.run/'results','--output',self.run/'positive.json');self.assertEqual(0,result[0],result)
  summary=m.read(self.run/'positive.json');self.assertTrue(summary['fixture_contract_pass']);self.assertFalse(summary['full_functional_pass'])
  ref=self.inputs['references']['ACC-014'];report_path=Path(ref['files']['report']['path']);report=cap.data(report_path.read_bytes());local_path=Path(report['localization']['path']);local=m.read(local_path);local['incidents'][0]['references'][0]['quote']='wrong package quote';local_path.write_text(json.dumps(local));report['localization']['sha256']=m.sha256(local_path);report_path.write_text(json.dumps(report));rehash_capability(ref)
  # A fresh frozen plan with all valid updated hashes must still fail original assertions.
  self.run=self.base/'negative-run';self.prepare('MCP-P04-FULL',['ACC-014'])
  with mock.patch.object(m,'NativeBoundary',side_effect=AssertionError('reference must not construct auth/target channel')):
   result=self.cli('execute','--plan',self.run/'plan.json')
  result=self.cli('judge','--plan',self.run/'plan.json','--results',self.run/'results','--output',self.run/'negative.json');self.assertNotEqual(0,result[0],result)
  summary=m.read(self.run/'negative.json');self.assertFalse(summary['fixture_contract_pass']);self.assertFalse(summary['full_functional_pass'])

class ProtectionParsedDomainBoundary(LifecycleDomainBoundary):
 """Original config/tools/coordinator plus real parsed protection injection.

 Successful lifecycle OS operations remain the existing benign double. This
 boundary does not repair or normalize product parser keys to force a pass.
 """
 def __init__(self,inputs,root):
  super().__init__(inputs,root);self.protection_observations=[]
 def exchange(self,kind,value):
  if kind=='http':
   request=json.loads(value['data']);tool=request.get('params',{}).get('name')
   if tool=='start':
    from fakenet.fakenet import Fakenet
    from fakenet.mcp.supervisor import RealSupervisor,SupervisorStartError
    identity=self.context.coordinator.snapshot()['config_identity'];path=(self.context.store.builtin_root if identity['builtin'] else self.context.store.custom_root)/identity['name']
    parsed=Fakenet();parsed.parse_config(str(path));before=dict(parsed.diverter_config)
    supervisor=object.__new__(RealSupervisor);supervisor._exclusion={'ip':self.inputs['allowed_host'],'port':'28788'}
    try:supervisor._inject_exclusion(parsed);rejection=None
    except SupervisorStartError as exc:rejection=str(exc)
    self.protection_observations.append({'before':before,'after':dict(parsed.diverter_config),'rejection':rejection})
    if rejection:
     return {'status':200,'headers':{'Content-Type':'application/json'},'body':json.dumps({'result':{'content':[{'text':json.dumps({'state':'failed','error':{'code':'invalid_request','message':rejection}})}]}}).encode(),'http_error':False}
  return super().exchange(kind,value)

class OriginalProtectionRegressionTests(unittest.TestCase):
 setUp=OriginalMcpTests.setUp
 def test_real_parser_keycase_failure_is_reported_by_original_s4(self):
  unit='ACC-004-S4';out=self.root/unit;boundary=ProtectionParsedDomainBoundary(self.inputs,self.root/'domain')
  value=m.run('MCP-P03-FULL',out,self.inputs,selected=[unit],boundary=boundary,fixture=True)
  rows,clean,details=o.evaluate(ROOT,out,'MCP-P03-FULL',[unit],self.inputs,allow_fixture=True)
  observations=boundary.protection_observations;bad=[row for row in observations if row['before'].get('controllinkexcludeip')=='not-an-ip'];self.assertTrue(bad)
  # A successful test of the facility can preserve a real product failure.
  # Do not normalize keys or assert native/product acceptance from this test.
  if bad[0]['rejection'] is None:
   self.assertEqual('fail',value['checks'][unit]['status']);self.assertEqual('fail',rows[0]['status'],details)
   original=m.read(out/'units'/unit/'acc004-s4-scenario-checks.json');self.assertFalse(original['invalid_protection_fails_closed']);self.assertFalse(original['rejection_names_protection_params'])
  else:
   self.assertIn('protection',bad[0]['rejection'].lower());self.assertEqual('pass',value['checks'][unit]['status']);self.assertEqual('pass',rows[0]['status'],details)
  self.assertTrue(clean,details)
  m.write(self.root/'actual-protection-observation.json',{'observations':observations,'product_unit_status':value['checks'][unit]['status'],'fixture_only':True,'native_operation':False})

 def test_rejected_create_or_load_never_starts_old_default_or_retries(self):
  for rejected in ('create_config','load_config'):
   with self.subTest(rejected=rejected):
    class Rejected(ProtectionParsedDomainBoundary):
     def exchange(self,kind,value):
      if kind=='http':
       request=json.loads(value['data']);params=request.get('params',{});args=params.get('arguments',{})
       if params.get('name')==rejected and args.get('name','').startswith('badfilter-'):
        return {'status':200,'headers':{'Content-Type':'application/json'},'body':json.dumps({'result':{'content':[{'text':json.dumps({'error':{'code':'validation_failed','message':'fixture refusal'},'state_version':3})}]}}).encode(),'http_error':False}
      return super().exchange(kind,value)
    unit='ACC-004-S4';out=self.root/rejected;boundary=Rejected(self.inputs,self.root/('domain-'+rejected));value=m.run('MCP-P03-FULL',out,self.inputs,selected=[unit],boundary=boundary,fixture=True)
    self.assertEqual('fail',value['checks'][unit]['status']);self.assertEqual([],boundary.protection_observations)
    trace=m.read(out/'units'/unit/'trace.json');requests=[json.loads(m.unpack(row['input'])['data'])['params'] for row in trace['records'] if row['kind']=='http']
    self.assertFalse(any(row['name']=='start' for row in requests));self.assertEqual(1,sum(row['name']==rejected and row['arguments'].get('name','').startswith('badfilter-') for row in requests))
    rows,clean,details=o.evaluate(ROOT,out,'MCP-P03-FULL',[unit],self.inputs,allow_fixture=True);self.assertEqual('fail',rows[0]['status'],details);self.assertTrue(clean)

class PublicProtectionCliTests(unittest.TestCase):
 setUp=PublicMcpCliTests.setUp
 cli=PublicMcpCliTests.cli
 prepare=PublicMcpCliTests.prepare
 def test_current_product_protection_failure_is_not_signed_as_fixture_pass(self):
  self.prepare('MCP-P03-FULL',['ACC-004-S4'])
  boundary=ProtectionParsedDomainBoundary(self.inputs,self.base/'domain')
  with mock.patch.object(m,'NativeBoundary',return_value=boundary):
   executed=self.cli('execute','--plan',self.run/'plan.json')
  result=self.cli('judge','--plan',self.run/'plan.json','--results',self.run/'results','--output',self.run/'independent.json')
  summary=m.read(self.run/'independent.json');self.assertFalse(summary['full_functional_pass'])
  accepted=any(row['before'].get('controllinkexcludeip')=='not-an-ip' and row['rejection'] is None for row in boundary.protection_observations)
  if accepted:
   self.assertNotEqual(0,executed[0],executed);self.assertNotEqual(0,result[0],result);self.assertFalse(summary['fixture_contract_pass'])
  else:
   self.assertEqual(0,executed[0],executed);self.assertEqual(0,result[0],result)

class NoListenerParsedDomainBoundary(ProtectionParsedDomainBoundary):
 def __init__(self,inputs,root,fake_healthy=False):
  super().__init__(inputs,root);self.fake_healthy=fake_healthy;self.no_listener_observations=[]
 def exchange(self,kind,value):
  if kind=='http' and json.loads(value['data']).get('params',{}).get('name')=='start':
   from fakenet.fakenet import Fakenet
   from fakenet.mcp.supervisor import evaluate_health_evidence
   identity=self.context.coordinator.snapshot()['config_identity'];path=(self.context.store.builtin_root if identity['builtin'] else self.context.store.custom_root)/identity['name'];parsed=Fakenet();parsed.parse_config(str(path));self.no_listener_observations.append(list(parsed.listeners_config))
   healthy,reason=evaluate_health_evidence({'process_alive':True,'init_evidence':bool(parsed.listeners_config),'probe':True},'')
   if not healthy and not self.fake_healthy:self.context.runner.fail_next_start=reason
  return super().exchange(kind,value)

class ActiveProbeProcessBoundary(ListenerProcessBoundary):
 def pipe_bytes(self):
  if self.fault and self.fault['fault']=='diverter_stop':
   run=self.run_id;identity={'pid':121,'creation_time':'123456'}
   rows=[{'event':'request','monotonic':100.,'frame':{'kind':'health','seq':1,'run_id':run}},
         {'event':'response','monotonic':100.1,'frame':{'seq':1,'run_id':run,'result':{'init_evidence':True,'probe':False,'listeners':[{'alive':True}]}}},
         {'event':'health_state','monotonic':100.2,'frame':{'state':'failed','identity':identity,'run_id':run}}]
   return {'parent':'\n'.join(json.dumps(row) for row in rows),'child':'','receipt':self.fault}
  return super().pipe_bytes()

class OriginalHealthSliceTests(unittest.TestCase):
 setUp=OriginalMcpTests.setUp
 def test_no_listener_uses_actual_parser_and_rejects_fake_healthy(self):
  for bad in (False,True):
   with self.subTest(fake_healthy=bad):
    unit='HEALTH-NO-LISTENER';out=self.root/str(bad);boundary=NoListenerParsedDomainBoundary(self.inputs,self.root/('domain-'+str(bad)),bad);value=m.run('MCP-P03-FULL',out,self.inputs,selected=[unit],boundary=boundary,fixture=True)
    self.assertEqual([[]],boundary.no_listener_observations);expected='fail' if bad else 'pass';self.assertEqual(expected,value['checks'][unit]['status'],m.read(out/'units'/unit/'result.json'))
    rows,clean,details=o.evaluate(ROOT,out,'MCP-P03-FULL',[unit],self.inputs,allow_fixture=True);self.assertEqual(expected,rows[0]['status'],details);self.assertTrue(clean)
 def test_active_probe_requires_same_child_and_timely_actual_pipe_revocation(self):
  unit='HEALTH-ACTIVE-PROBE';out=self.root/unit;value=m.run('MCP-P03-FULL',out,self.inputs,selected=[unit],boundary=ActiveProbeProcessBoundary(self.inputs),fixture=True)
  self.assertEqual('pass',value['checks'][unit]['status'],m.read(out/'units'/unit/'result.json'));self.assertEqual('pass',o.evaluate(ROOT,out,'MCP-P03-FULL',[unit],self.inputs,allow_fixture=True)[0][0]['status'])
  import copy
  path=out/'units'/unit/'trace.json';original=m.read(path)
  for mode in ('child','late','nonce','listener'):
   with self.subTest(mode=mode):
    trace=copy.deepcopy(original)
    for row in trace['records']:
     if row['kind']=='powershell' and '@{parent=(Get-Content' in row['input']['command']:
      facts=json.loads(row['output']['output']);pipe=[json.loads(line) for line in facts['parent'].splitlines()]
      if mode=='child':pipe[-1]['frame']['identity']['pid']=999
      elif mode=='late':pipe[-1]['monotonic']=107.
      elif mode=='nonce':facts['receipt']['nonce']='wrong-nonce'
      else:pipe[1]['frame']['result']['listeners'][0]['alive']=False
      facts['parent']='\n'.join(json.dumps(item) for item in pipe);row['output']['output']=json.dumps(facts)
    path.write_text(json.dumps(trace));rows,clean,details=o.evaluate(ROOT,out,'MCP-P03-FULL',[unit],self.inputs,allow_fixture=True);self.assertEqual('fail',rows[0]['status'],details);self.assertTrue(clean)

class PublicHealthSliceCliTests(unittest.TestCase):
 setUp=PublicMcpCliTests.setUp
 cli=PublicMcpCliTests.cli
 prepare=PublicMcpCliTests.prepare
 def test_same_catalog_selected_health_slices_never_replace_full(self):
  for unit,boundary_class in [('HEALTH-NO-LISTENER',NoListenerParsedDomainBoundary),('HEALTH-ACTIVE-PROBE',ActiveProbeProcessBoundary)]:
   with self.subTest(unit=unit):
    self.setUp();self.prepare('MCP-P03-FULL',[unit]);boundary=(boundary_class(self.inputs,self.base/'domain') if unit=='HEALTH-NO-LISTENER' else boundary_class(self.inputs))
    with mock.patch.object(m,'NativeBoundary',return_value=boundary):result=self.cli('execute','--plan',self.run/'plan.json')
    self.assertEqual(0,result[0],result);result=self.cli('judge','--plan',self.run/'plan.json','--results',self.run/'results','--output',self.run/'judged.json');self.assertEqual(0,result[0],result);summary=m.read(self.run/'judged.json');self.assertTrue(summary['fixture_contract_pass']);self.assertFalse(summary['full_functional_pass'])

if __name__=='__main__':unittest.main()


class HangProcessBoundary(FaultProcessBoundary):
    """Only remote process, HTTP and clock edges; original S5 executes."""
    def __init__(self, inputs):
        super().__init__(inputs)
        self.running = False

    def exchange(self, kind, value):
        with self.guard:
            if kind == 'http':
                tool = json.loads(value['data'])['params']['name']
                if tool in ('get_status', 'start', 'stop', 'load_config'):
                    if tool == 'start':
                        self.running = True
                    elif tool == 'stop':
                        self.running = False
                    if tool != 'get_status':
                        self.version += 1
                    return self.response({
                        'service': 'fakenetng-mcp',
                        'state': 'healthy' if self.running else 'stopped',
                        'state_version': self.version,
                        'run_id': self.run_id if self.running else None,
                        'controller': None,
                        'config_identity': self.inputs['config_identity'],
                        'last_run_outcome': 'failed' if self.fault and not self.running else None,
                        'error': None,
                    })
            if kind == 'powershell' and '@{run_id=$run;receipt=$receipt}' in value['command']:
                output = json.dumps({'run_id': self.run_id, 'receipt': self.fault})
                return {'output': output, 'raw': output, 'exit_code': 0, 'is_error': False}
            return super().exchange(kind, value)


class OriginalHangReceiptTests(unittest.TestCase):
    setUp = OriginalMcpTests.setUp

    def test_actual_hook_receipt_and_original_control_window(self):
        unit = 'ACC-004-S5'
        out = self.root / 'hang'
        value = m.run('MCP-P03-FULL', out, self.inputs, selected=[unit],
                      boundary=HangProcessBoundary(self.inputs), fixture=True)
        self.assertEqual('pass', value['checks'][unit]['status'],
                         m.read(out / 'units' / unit / 'result.json'))
        rows, clean, details = o.evaluate(ROOT, out, 'MCP-P03-FULL', [unit],
                                          self.inputs, allow_fixture=True)
        self.assertEqual('pass', rows[0]['status'], details)
        self.assertTrue(clean, details)
        trace_path = out / 'units' / unit / 'trace.json'
        original = trace_path.read_text()
        for mutation in ('nonce', 'fault', 'run_id', 'exit_code'):
            with self.subTest(mutation=mutation):
                trace = json.loads(original)
                hits = 0
                for row in trace['records']:
                    if row['kind'] != 'powershell' or '@{run_id=$run;receipt=$receipt}' not in row['input']['command']:
                        continue
                    hits += 1
                    raw = row['output']
                    observed = json.loads(raw['output'])
                    if mutation in ('nonce', 'fault'):
                        observed['receipt'][mutation] = 'wrong-' + mutation
                    elif mutation == 'run_id':
                        observed['run_id'] = '22222222-2222-4222-8222-222222222222'
                    else:
                        raw['exit_code'] = 1
                    raw['output'] = json.dumps(observed)
                    raw['raw'] = raw['output']
                self.assertEqual(1, hits)
                trace_path.write_text(json.dumps(trace))
                rows, clean, details = o.evaluate(ROOT, out, 'MCP-P03-FULL', [unit],
                                                  self.inputs, allow_fixture=True)
                self.assertEqual('fail', rows[0]['status'], details)
                if mutation == 'exit_code':
                    # A failed channel read aborts the original sequence;
                    # no successful restoration may be inferred from it.
                    self.assertFalse(clean, details)
                    self.assertIn('original replay refused', str(details))
                else:
                    self.assertTrue(clean, details)
        trace_path.write_text(original)


class PublicHangMcpCliTests(unittest.TestCase):
    setUp = PublicMcpCliTests.setUp
    cli = PublicMcpCliTests.cli
    prepare = PublicMcpCliTests.prepare

    def test_same_catalog_hang_and_rehashed_wrong_receipt(self):
        self.prepare('MCP-P03-FULL', ['ACC-004-S5'])
        with mock.patch.object(m, 'NativeBoundary',
                               side_effect=lambda *args, **kwargs: HangProcessBoundary(self.inputs)):
            result = self.cli('execute', '--plan', self.run / 'plan.json')
        self.assertEqual(0, result[0], result)
        result = self.cli('judge', '--plan', self.run / 'plan.json', '--results',
                          self.run / 'results', '--output', self.run / 'positive.json')
        self.assertEqual(0, result[0], result)
        summary = m.read(self.run / 'positive.json')
        self.assertTrue(summary['fixture_contract_pass'])
        self.assertFalse(summary['full_functional_pass'])
        case_dir = self.run / 'results/MCP-P03-FULL'
        trace_path = case_dir / 'driver/units/ACC-004-S5/trace.json'
        trace = m.read(trace_path)
        hits = 0
        for row in trace['records']:
            if row['kind'] == 'powershell' and '@{run_id=$run;receipt=$receipt}' in row['input']['command']:
                hits += 1
                observed = json.loads(row['output']['output'])
                observed['receipt']['nonce'] = 'wrong-consumed-nonce'
                row['output']['output'] = json.dumps(observed)
                row['output']['raw'] = row['output']['output']
        self.assertEqual(1, hits)
        trace_path.write_text(json.dumps(trace))
        receipt = m.read(case_dir / 'receipt.json')
        for artifact in receipt['artifacts']:
            artifact['sha256'] = m.sha256(artifact['path'])
        (case_dir / 'receipt.json').write_text(json.dumps(receipt))
        index = m.read(self.run / 'results/results.json')
        for item in index['receipts']:
            if item['case_id'] == 'MCP-P03-FULL':
                item['sha256'] = m.sha256(case_dir / 'receipt.json')
        (self.run / 'results/results.json').write_text(json.dumps(index))
        result = self.cli('judge', '--plan', self.run / 'plan.json', '--results',
                          self.run / 'results', '--output', self.run / 'negative.json')
        self.assertNotEqual(0, result[0], result)
        summary = m.read(self.run / 'negative.json')
        self.assertFalse(summary['fixture_contract_pass'])
        self.assertIn('original assertions', json.dumps(summary))


class ConfigLockDomainBoundary(DomainBoundary):
    """Real configuration/coordination domain, simulated Windows file edges."""
    def __init__(self, inputs, root, fault=None):
        self.fault = fault
        self.calls = []
        self.probes = []
        self.links = {}
        self.foreign = {}
        self.targets = []
        super().__init__(inputs, root)
        if fault == 'legacy-junction':
            (self.context.store.custom_root / 'junction.ini').write_bytes(b'preexisting benign legacy object')

    def exchange(self, kind, value):
        if kind == 'http':
            request = json.loads(value['data'])
            tool = request.get('params', {}).get('name')
            self.calls.append(tool)
            arguments = request.get('params', {}).get('arguments') or {}
            self.targets.append((tool, arguments.get('name'), arguments.get('new_name')))
            if ((self.fault == 'import-conflict' and tool == 'import_config' and str(arguments.get('name')).startswith('acc009-import-')) or
                    (self.fault == 'rename-conflict' and tool == 'rename_config' and str(arguments.get('new_name')).startswith('acc009-moved-'))):
                name = arguments.get('new_name') if tool == 'rename_config' else arguments['name']
                path = self.context.store.custom_root / name
                content = m.modules()['run_p02_acc'].VALID_INI if tool == 'import_config' else m.modules()['run_p02_acc'].VALID_INI + '\n# ACC009 stopped management\n'
                with path.open('xb') as stream:
                    stream.write(content.encode())
                self.foreign[name] = path.read_bytes()
            if self.fault == 'reject-' + str(tool):
                snap = self.context.coordinator.snapshot()
                snap.update(error={'code': 'refused-' + tool}, changed=False)
                return FaultProcessBoundary.response(self, snap)
            response = super().exchange(kind, value)
            body = json.loads(response['body'])
            payload = json.loads(body['result']['content'][0]['text'])
            if self.fault == 'empty-' + str(tool):
                payload = {}
            if self.fault == 'wrong-config' and tool == 'get_status' and payload.get('state') == 'healthy':
                payload['config_identity']['name'] = 'foreign.ini'
            if self.fault == 'bad-bound-run' and tool == 'restart':
                payload['bound_run_id'] = '22222222-2222-4222-8222-222222222222'
            body['result']['content'][0]['text'] = json.dumps(payload)
            response['body'] = json.dumps(body).encode()
            return response
        if kind == 'powershell' and 'ACC009_CONFIG_PROBE_V1' in value['command']:
            import base64
            import re
            from pathlib import PureWindowsPath
            encoded = re.search(r"FromBase64String\('([A-Za-z0-9+/=]+)'\)", value['command']).group(1)
            request = json.loads(base64.b64decode(encoded))
            self.probes.append(request)
            path = self.context.store.custom_root / request['name']
            result = {'schema': 'fakenet.acc009-os.v1', 'operation': request['operation'],
                      'name': request['name'], 'token': request['token'], 'run_id': request.get('run_id'),
                      'path': str(PureWindowsPath(self.inputs['programdata_root']) / 'configs/custom' / request['name'])}
            if request['operation'] == 'file-probe':
                def observe():
                    return {'exists': path.exists(), 'sha256': m.sha256(path) if path.exists() else None,
                            'creation_time': str(path.stat().st_mtime_ns) if path.exists() else None,
                            'size': path.stat().st_size if path.exists() else 0}
                before = observe()
                locked = self.context.store.active_name == request['name']
                result.update(phase=request['phase'], before=before, restored=False)
                if locked:
                    error = 5 if self.fault == 'wrong-error' else 32
                    result['write'] = {'attempted': self.fault != 'unattempted', 'success': False, 'win32_error': error}
                    result['delete'] = {'attempted': True, 'success': False, 'win32_error': error}
                else:
                    raw = path.read_bytes()
                    path.write_bytes(raw)
                    path.unlink()
                    result['write'] = {'attempted': True, 'success': True, 'win32_error': None}
                    result['delete'] = {'attempted': True, 'success': True, 'win32_error': None}
                    with path.open('xb') as stream:
                        stream.write(raw)
                    result['restored'] = m.sha256(path) == request['sha256']
                result['after'] = observe()
                if self.fault == 'content-drift' and locked:
                    result['after']['sha256'] = '0' * 64
                if self.fault == 'wrong-restoration' and not locked:
                    result['restored'] = False
            else:
                work = PureWindowsPath(self.inputs['guest_work_root']) / ('fakenet-acc009-' + request['token'])
                result.update(work_dir=str(work), target=str(work / 'target.ini'))
                if request['operation'] == 'reparse-setup':
                    if self.fault == 'link-unavailable':
                        result.update(created=False, cleanup_complete=True, error='simulated unsupported Windows link permission')
                    else:
                        host_work = self.root / ('fakenet-acc009-' + request['token'])
                        host_work.mkdir(exist_ok=False)
                        target = host_work / 'target.ini'
                        target.write_bytes(b'acc009 benign controlled target\n')
                        path.symlink_to(target)
                        self.links[request['token']] = (host_work, target, path)
                        result.update(created=True, cleanup_complete=False, target_sha256=m.sha256(target))
                else:
                    host_work, target, link = self.links[request['token']]
                    if self.fault == 'cleanup-unconfirmed':
                        result['cleanup_complete'] = False
                    else:
                        if not link.is_symlink() or link.resolve() != target.resolve() or m.sha256(target) != request['target_sha256']:
                            raise AssertionError('fixture owned reparse identity differs')
                        link.unlink(); target.unlink(); host_work.rmdir()
                        result['cleanup_complete'] = True
            output = json.dumps(result)
            return {'output': output, 'raw': output, 'exit_code': 0, 'is_error': False}
        return super().exchange(kind, value)


class OriginalConfigLockTests(unittest.TestCase):
    setUp = OriginalMcpTests.setUp

    def run_case(self, label, fault=None):
        boundary = ConfigLockDomainBoundary(self.inputs, self.root / ('domain-' + label), fault)
        out = self.root / label
        result = m.run('MCP-P03-FULL', out, self.inputs, selected=['ACC-009'], boundary=boundary, fixture=True)
        rows, clean, details = o.evaluate(ROOT, out, 'MCP-P03-FULL', ['ACC-009'], self.inputs, allow_fixture=True)
        return boundary, out, result, rows, clean, details

    def test_original_domain_complete_lock_management_and_reparse_chain(self):
        boundary, out, result, rows, clean, details = self.run_case('normal')
        self.assertEqual('pass', result['checks']['ACC-009']['status'], m.read(out / 'units/ACC-009/result.json'))
        self.assertEqual('pass', rows[0]['status'], details)
        self.assertTrue(clean, details)
        self.assertIsNone(boundary.context.store.active_name)
        self.assertEqual([], list(boundary.context.store.custom_root.iterdir()))
        self.assertEqual(['file-probe', 'file-probe', 'reparse-setup', 'reparse-cleanup'], [p['operation'] for p in boundary.probes])
        self.assertFalse((boundary.context.store.custom_root / 'junction.ini').exists())

    def test_rejected_mutations_and_wrong_active_name_stop_dependent_probes(self):
        for fault in ('reject-create_config', 'reject-load_config', 'reject-start', 'wrong-config'):
            with self.subTest(fault=fault):
                boundary, out, result, rows, clean, details = self.run_case(fault, fault)
                self.assertNotEqual('pass', result['checks']['ACC-009']['status'])
                self.assertNotEqual('pass', rows[0]['status'], details)
                self.assertEqual([], boundary.probes)
                if fault != 'reject-start' and fault != 'wrong-config':
                    self.assertNotIn('start', boundary.calls)

    def test_wrong_error_unattempted_changed_bytes_and_restoration_are_not_locks(self):
        for fault, expected_check in (
                ('wrong-error', 'external_write_blocked'),
                ('unattempted', 'external_write_blocked'),
                ('content-drift', 'external_target_exact'),
                ('wrong-restoration', 'unlocked_after_stop'),
                ('bad-bound-run', 'restart_binds_original_run')):
            with self.subTest(fault=fault):
                boundary, out, result, rows, clean, details = self.run_case(fault, fault)
                self.assertEqual('fail', result['checks']['ACC-009']['status'])
                self.assertEqual('fail', rows[0]['status'], details)
                checks = m.read(out / 'units/ACC-009/acc009-checks.json')
                self.assertIs(False, checks[expected_check])

    def test_empty_success_receipt_stops_without_retry_or_default_fallback(self):
        for fault in ('empty-create_config', 'empty-load_config', 'empty-start'):
            with self.subTest(fault=fault):
                boundary, out, result, rows, clean, details = self.run_case(fault, fault)
                self.assertNotEqual('pass', rows[0]['status'], details)
                self.assertFalse(clean, details)
                self.assertEqual([], boundary.probes)
                self.assertEqual(1, boundary.calls.count(fault[len('empty-'):]))
                original = m.read(out / 'units/ACC-009/result.json')
                self.assertIn('receipt not confirmed', json.dumps(original))

    def test_legacy_fixed_junction_name_is_never_touched(self):
        boundary, out, result, rows, clean, details = self.run_case('legacy-junction', 'legacy-junction')
        self.assertEqual('pass', rows[0]['status'], details)
        self.assertTrue(clean, details)
        self.assertEqual(b'preexisting benign legacy object',
                         (boundary.context.store.custom_root / 'junction.ini').read_bytes())
        self.assertTrue(all(p['name'] != 'junction.ini' for p in boundary.probes))

    def test_name_conflicts_never_mutate_preexisting_import_or_rename_targets(self):
        for fault in ('import-conflict', 'rename-conflict'):
            with self.subTest(fault=fault):
                boundary, out, result, rows, clean, details = self.run_case(fault, fault)
                self.assertEqual('fail', rows[0]['status'], details)
                self.assertTrue(boundary.foreign)
                for name, original in boundary.foreign.items():
                    self.assertEqual(original, (boundary.context.store.custom_root / name).read_bytes())
                    self.assertFalse(any(tool in ('edit_config', 'delete_config') and target == name
                                         for tool, target, renamed in boundary.targets))
                self.assertNotIn('restart', boundary.calls)

    def test_link_unavailable_is_not_evaluated_and_unknown_cleanup_is_not_clean(self):
        for fault in ('link-unavailable', 'cleanup-unconfirmed'):
            with self.subTest(fault=fault):
                boundary, out, result, rows, clean, details = self.run_case(fault, fault)
                self.assertNotEqual('pass', rows[0]['status'], details)
                if fault == 'link-unavailable':
                    self.assertEqual('blocked', result['checks']['ACC-009']['status'])
                else:
                    self.assertFalse(clean, details)
                    self.assertNotIn('restart', boundary.calls)


class PublicConfigLockCliTests(unittest.TestCase):
    setUp = PublicMcpCliTests.setUp
    cli = PublicMcpCliTests.cli
    prepare = PublicMcpCliTests.prepare

    def test_same_catalog_lock_chain_and_rehashed_bad_attempt(self):
        self.prepare('MCP-P03-FULL', ['ACC-009'])
        with mock.patch.object(m, 'NativeBoundary', side_effect=lambda *a, **kw: ConfigLockDomainBoundary(self.inputs, self.base / 'domain')):
            result = self.cli('execute', '--plan', self.run / 'plan.json')
        self.assertEqual(0, result[0], result)
        result = self.cli('judge', '--plan', self.run / 'plan.json', '--results', self.run / 'results', '--output', self.run / 'positive.json')
        self.assertEqual(0, result[0], result)
        summary = m.read(self.run / 'positive.json')
        self.assertTrue(summary['fixture_contract_pass'])
        self.assertFalse(summary['full_functional_pass'])
        case_dir = self.run / 'results/MCP-P03-FULL'
        path = case_dir / 'driver/units/ACC-009/trace.json'
        trace = m.read(path)
        hits = 0
        for row in trace['records']:
            if row['kind'] == 'powershell' and 'ACC009_CONFIG_PROBE_V1' in row['input']['command']:
                observed = json.loads(row['output']['output'])
                if observed.get('phase') == 'active':
                    hits += 1
                    observed['write']['attempted'] = False
                    row['output']['output'] = json.dumps(observed)
                    row['output']['raw'] = row['output']['output']
        self.assertEqual(1, hits)
        path.write_text(json.dumps(trace))
        receipt = m.read(case_dir / 'receipt.json')
        for item in receipt['artifacts']:
            item['sha256'] = m.sha256(item['path'])
        (case_dir / 'receipt.json').write_text(json.dumps(receipt))
        index = m.read(self.run / 'results/results.json')
        for item in index['receipts']:
            if item['case_id'] == 'MCP-P03-FULL':
                item['sha256'] = m.sha256(case_dir / 'receipt.json')
        (self.run / 'results/results.json').write_text(json.dumps(index))
        result = self.cli('judge', '--plan', self.run / 'plan.json', '--results', self.run / 'results', '--output', self.run / 'negative.json')
        self.assertNotEqual(0, result[0], result)
        self.assertFalse(m.read(self.run / 'negative.json')['fixture_contract_pass'])
