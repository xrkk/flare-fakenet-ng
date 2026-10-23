#!/usr/bin/env python3
"""Fixed MCP regression orchestration; original business functions own assertions.

Transport recordings are re-executed by the independent oracle. Memory tests
replace transport/process/clock operations, never the acceptance functions.
"""
from __future__ import annotations
import argparse
import base64
import contextlib
import copy
import hashlib
import importlib
import io
import http.client
import ipaddress
import json
import os
from pathlib import Path
import socket
import re
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
import urllib.error
import urllib.parse
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = 'fakenet.mcp-headless-result.v2'
IDENTITY_FIELDS = ('candidate_id','source_commit','package_sha256','requirements_blob','master_plan_blob')
FAULTS = ('policy_pause','listener_stop','diverter_stop','child_hang','cleanup_error')
IPC = ('ipc_once_timeout','ipc_permanent_timeout','ipc_eof','ipc_wrong_run','ipc_repeat','ipc_reverse')
CHECKS = {
 'MCP-P01-FULL': ['P01-ENTRY','ACC-002','ACC-003','ACC-016'],
 'MCP-P02-FULL': ['ACC-005','ACC-010','ACC-011','ACC-009-PRE'],
 'MCP-P03-FULL': ['ACC-001-HEADLESS']+['ACC-004-S%d'%i for i in range(1,7)]+['ACC-006','ACC-007','ACC-008','ACC-009'],
 'MCP-P04-FULL': ['FAULT-POINTS','ACC-014','ACC-015','ACC-019'],
 'MCP-SPECIAL-IPC': list(IPC)+['INITIALIZATION-FAILURE','CONTROL-DEFAULT','CONTROL-INVALID']+['CONTROL-EXTRA-%d'%p for p in (28787,28790,29095,29094)]+['LOOPBACK-V4','LOOPBACK-V6'],
 'MCP-SPECIAL-FAULT-RECOVERY': list(FAULTS),
}
# Selected-only slice; full ACC-014 already executes these same assertions.
SELECTABLE_CHECKS = {case: list(checks) for case, checks in CHECKS.items()}
SELECTABLE_CHECKS['MCP-P04-FULL'].append('INCIDENT-INTEGRITY')
SELECTABLE_CHECKS['MCP-P03-FULL'].extend(['HEALTH-NO-LISTENER','HEALTH-ACTIVE-PROBE'])
CASES = tuple(CHECKS)
EXCLUSIONS = {
 'ACC-001-GUI': 'GUI launch, window and co-control interactions excluded; headless service/core uniqueness retained.',
 'ACC-018-HISTORY': 'Hard-coded previous candidate fix/retest documentation is not a current product prerequisite. Current assertions remain in P01..P04.',
 'P05-RELEASE': 'No 150 publication loop; each of the five original fault classes runs once.',
 'P06-SCENARIOS': 'No historical 100-scenario driver.',
 'ACC-002-ZCODE-CONFIG-WRITE': 'Historical paid client probe rewrites credentials/model config. Keep raw protocol assertions and existing MCP SDK interoperability without editing client config.',
}


def sha256(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def write(path,value):
 path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
 with path.open('x',encoding='utf-8') as stream: json.dump(value,stream,ensure_ascii=False,indent=2);stream.write('\n')
def read(path):return json.loads(Path(path).read_text(encoding='utf-8'))
def modules(root=ROOT):
 directory=str(Path(root)/'test/mcp/acceptance')
 if directory not in sys.path:sys.path.insert(0,directory)
 return {n:importlib.import_module(n) for n in ('helpers','run_p01_acc','run_p02_acc','run_p03_acc','run_p04_acc','run_p05_release','run_ipc_cases','run_initialization_case','run_control_cases','artifact_transfer','evidence_integrity','ipc_evidence')}

def source_paths(root=ROOT):
 # Explicit original business closure; no dynamic source selected by results.
 names=('helpers','run_p01_acc','run_p02_acc','run_p03_acc','run_p04_acc','run_p05_release','run_ipc_cases','run_initialization_case','run_control_cases','evidence_integrity','ipc_evidence','artifact_transfer','bounded_mcp','sst_fault_evidence','scenario_fault_evidence','release_matrix')
 paths=['test/mcp/acceptance/'+n+'.py' for n in names]
 paths += ['tools/acceptance_mcp.py','tools/acceptance_mcp_oracles.py','tools/acceptance_mcp_dependencies.py','tools/acceptance_mcp_capabilities.py','tools/build_fakenetng_mcp_wine.py','fakenet/mcp/server.py','fakenet/mcp/tools.py']
 import ast
 pending=list(paths);seen=set(paths)
 while pending:
  relative=pending.pop();path=Path(root)/relative
  if not path.is_file() or path.suffix!='.py':continue
  tree=ast.parse(path.read_text())
  for node in ast.walk(tree):
   candidates=[]
   if isinstance(node,ast.Import):candidates=[item.name for item in node.names]
   elif isinstance(node,ast.ImportFrom) and node.module:candidates=[node.module]
   for name in candidates:
    if '.' not in name:
     found=Path('test/mcp/acceptance')/(name+'.py')
     if (Path(root)/found).is_file() and found.as_posix() not in seen:seen.add(found.as_posix());pending.append(found.as_posix())
   if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr=='with_name' and len(node.args)==1 and isinstance(node.args[0],ast.Constant) and isinstance(node.args[0].value,str):
    name=node.args[0].value
    if '/' not in name and '\\' not in name:
     found=Path(relative).parent/name
     if (Path(root)/found).is_file():seen.add(found.as_posix())
 return sorted(seen)

def source_pins(root=ROOT):
 return {p:sha256(Path(root)/p) for p in source_paths(root)}

def validate_inputs(value,case,selected=None,*,fixture=False):
 if case not in CHECKS: raise ValueError('unknown MCP case')
 if not isinstance(value,dict) or set(value)-{'references'}!={'schema','identity','package','manifest','manifest_sha256','target','config_identity','endpoint','listen_ip','allowed_host','channel','actions','work_root','installation_root','programdata_root','guest_work_root'}:
  raise ValueError('explicit MCP input fields required; commands/artifacts are not inputs')
 if value['schema']!='fakenet.mcp-input.v2':raise ValueError('MCP input schema')
 identity=value['identity']
 if not isinstance(identity,dict) or set(identity)!=set(IDENTITY_FIELDS) or any(not isinstance(identity[k],str) or not identity[k].strip() for k in IDENTITY_FIELDS):raise ValueError('MCP candidate identity incomplete')
 for key in ('package_sha256','requirements_blob','master_plan_blob'):
  if len(identity[key]) not in ((40,64) if key!='package_sha256' else (64,)) or any(c not in '0123456789abcdef' for c in identity[key]):raise ValueError('MCP identity digest '+key)
 target=value['target']
 if not isinstance(target,dict) or set(target)!={'platform','hostname','vm_uuid'} or target['platform']!='windows' or not target['hostname'] or str(uuid.UUID(target['vm_uuid']))!=target['vm_uuid']:raise ValueError('explicit Windows target identity required')
 url=urllib.parse.urlparse(value['endpoint'])
 if url.scheme!='http' or url.username or url.query or url.fragment or url.path not in ('','/') or not url.port:raise ValueError('explicit host-only MCP base URL required')
 address=ipaddress.ip_address(url.hostname)
 if not address.is_private or address.is_unspecified or address.is_multicast:raise ValueError('MCP endpoint must be explicit private address')
 if str(ipaddress.ip_address(value['listen_ip']))!=url.hostname:raise ValueError('MCP listen/endpoint identity differs')
 allowed=ipaddress.ip_address(value['allowed_host'])
 if not allowed.is_private or allowed.is_unspecified:raise ValueError('explicit allowed source required')
 channel=value['channel']
 if not isinstance(channel,dict) or not {'mcp_config_ref','mcp_server'}<=set(channel) or not all(isinstance(channel[k],str) and channel[k] for k in ('mcp_config_ref','mcp_server')):raise ValueError('existing channel reference required')
 config=value['config_identity']
 if not isinstance(config,dict) or set(config)!={'name','sha256'} or len(config['sha256'])!=64 or any(c not in '0123456789abcdef' for c in config['sha256']):raise ValueError('explicit active configuration identity required')
 required={'observe','mcp','core','service','fault','network','config','artifact'}
 if not isinstance(value['actions'],list) or len(value['actions'])!=len(set(value['actions'])) or not required<=set(value['actions']) or set(value['actions'])-required-{'deploy'}:raise ValueError('explicit MCP action authorization required')
 for key in ('package','manifest','work_root'):
  if not isinstance(value[key],str) or not Path(value[key]).is_absolute():raise ValueError('MCP absolute path required: '+key)
 for key in ('installation_root','programdata_root','guest_work_root'):
  from pathlib import PureWindowsPath
  if not isinstance(value[key],str) or any(c in value[key] for c in ("'",'\"',';','`','\n','\r')) or not PureWindowsPath(value[key]).is_absolute():raise ValueError('Windows deployment path required: '+key)
 if value['manifest_sha256']!=sha256(value['manifest']) or identity['package_sha256']!=sha256(value['package']):raise ValueError('MCP package/manifest bytes mismatch')
 manifest=read(value['manifest'])
 if manifest.get('source_commit')!=identity['source_commit']:raise ValueError('MCP manifest/candidate mismatch')
 from pathlib import PureWindowsPath
 if PureWindowsPath(value['guest_work_root']).drive.upper() not in ('E:','D:'):raise ValueError('new VM evidence work root requires recorded E/D selection')
 import importlib.util
 spec=importlib.util.spec_from_file_location('mcp_package_original_verifier',ROOT/'tools/build_fakenetng_mcp_wine.py')
 verifier=importlib.util.module_from_spec(spec);spec.loader.exec_module(verifier)
 try:verifier.verify_package_zip(Path(value['package']),manifest)
 except (RuntimeError,KeyError,OSError,ValueError) as exc:raise ValueError('original MCP package verification refused: '+str(exc)) from exc
 if 'references' in value and (not isinstance(value['references'],dict) or set(value['references'])-{'ACC-008','ACC-014'}):raise ValueError('unknown MCP predecessor reference')
 selected=list(CHECKS[case] if selected is None else selected)
 if not selected or len(selected)!=len(set(selected)) or any(k not in SELECTABLE_CHECKS[case] for k in selected):raise ValueError('MCP selection not declared by case')
 return copy.deepcopy(value),selected


def pack(value):
 if isinstance(value,bytes):return {'$bytes':base64.b64encode(value).decode('ascii')}
 if isinstance(value,(tuple,list)):return [pack(x) for x in value]
 if isinstance(value,dict):return {str(k):pack(v) for k,v in value.items()}
 if value is None or isinstance(value,(str,int,float,bool)):return value
 raise TypeError('unsupported boundary value '+type(value).__name__)
def unpack(value):
 if isinstance(value,dict) and set(value)=={'$bytes'}:return base64.b64decode(value['$bytes'],validate=True)
 if isinstance(value,list):return [unpack(x) for x in value]
 if isinstance(value,dict):return {k:unpack(v) for k,v in value.items()}
 return value


def translate_paths(value,old,new):
 if isinstance(value,str):return value.replace(old,new)
 if isinstance(value,bytes):return value.replace(old.encode(),new.encode())
 if isinstance(value,list):return [translate_paths(x,old,new) for x in value]
 if isinstance(value,dict):return {k:translate_paths(v,old,new) for k,v in value.items()}
 return value

class ReplayMismatch(ValueError):pass
class RecordedResponse(io.BytesIO):
 def __init__(self,value):super().__init__(value['body']);self.status=value['status'];self.code=self.status;self.headers=value['headers']
 def getcode(self):return self.status
 def info(self):return self.headers


def sdk_probe(server):
 import anyio
 from mcp import Client
 async def probe():
  async with Client(server,read_timeout_seconds=60) as client:
   tools=await client.list_tools();ping=await client.call_tool('ping',{})
   return {'tools':tools.model_dump(mode='json',by_alias=True),'ping':ping.model_dump(mode='json',by_alias=True)}
 return anyio.run(probe)

class ClosedReferenceBoundary:
 """A closed-reference judgment never constructs a target/auth channel."""
 def __init__(self,fixture):self.fixture=fixture
 def exchange(self,kind,value):raise ValueError('closed capability reference cannot perform native actions')

class NativeBoundary:
 fixture=False
 def __init__(self,root,inputs,journal):
  from acceptance_windows import ExistingWindowsChannel
  self.root=Path(root);self.inputs=inputs;self.journal=Path(journal)
  self.channel=ExistingWindowsChannel(root,inputs['channel'],journal)
  self._http_connection=http.client.HTTPConnection;self._urlopen=urllib.request.urlopen;self._run=subprocess.run;self._socket=socket.create_connection;self._time=time.time;self._mono=time.monotonic;self._sleep=time.sleep;self._uuid=uuid.uuid4;self.sockets={}
 def exchange(self,kind,value):
  if kind=='http':
   request=urllib.request.Request(value['url'],data=value['data'],headers=value['headers'],method=value['method'])
   try:
    with self._urlopen(request,timeout=value['timeout']) as response:return {'status':response.status,'headers':dict(response.headers),'body':response.read(),'http_error':False}
   except urllib.error.HTTPError as exc:return {'status':exc.code,'headers':dict(exc.headers),'body':exc.read(),'http_error':True}
  if kind=='http-source':
   connection=self._http_connection(value['host'],value['port'],timeout=value['timeout'],source_address=tuple(value['source_address']))
   try:
    connection.request(value['method'],value['path'],body=value['body'],headers=value['headers'])
    response=connection.getresponse()
    return {'status':response.status,'headers':dict(response.getheaders()),'body':response.read()}
   finally:connection.close()
  if kind=='powershell':return self.channel.powershell(value['command'],timeout=value['timeout'])
  if kind=='process':
   done=self._run(value['argv'],cwd=value['cwd'],capture_output=True,text=False,timeout=value['timeout'],shell=False)
   return {'returncode':done.returncode,'stdout':done.stdout,'stderr':done.stderr}
  if kind=='sdk':return sdk_probe(value['url'])
  if kind=='socket-open':
   self.sockets[value['handle']]=self._socket(tuple(value['address']),value['timeout'],value.get('source_address'))
   return {'connected':True}
  if kind.startswith('socket-'):
   stream=self.sockets[value['handle']]
   if kind=='socket-send':stream.sendall(value['data']);return None
   if kind=='socket-recv':return stream.recv(value['count'])
   if kind=='socket-timeout':stream.settimeout(value['seconds']);return None
   if kind=='socket-close':stream.close();return {'fileno':stream.fileno()}
   raise ValueError('unknown socket operation')
  if kind=='time':return self._time()
  if kind=='monotonic':return self._mono()
  if kind=='sleep':self._sleep(value['seconds']);return None
  if kind=='uuid':return str(self._uuid())
  if kind=='target':
   raw=self.channel.powershell("$ErrorActionPreference='Stop';@{platform='windows';hostname=$env:COMPUTERNAME;vm_uuid=(Get-CimInstance Win32_ComputerSystemProduct).UUID.ToLower()}|ConvertTo-Json -Compress",timeout=30)
   if raw.get('exit_code')!=0 or raw.get('is_error'):raise ValueError('VM identity not observed')
   return json.loads(raw['output'])
  if kind=='observe':
   mods=modules(self.root);gate=object.__new__(mods['run_p05_release'].ReleaseGate);gate.args=original_args(self.inputs,self.journal);gate.channel=self.channel;gate.release=self.journal
   sections=gate.capture_sections()
   stamp=gate.vm_continuity()
   return {'sections':sections,'service':stamp,'captures':gate._capture_evidence}
  raise ValueError('unimplemented OS boundary: '+kind)

class ReplayBoundary:
 fixture=True
 def __init__(self,records,recorded_root='',replay_root=''):
  self.records=copy.deepcopy(records);self.recorded_root=recorded_root;self.replay_root=replay_root;self.offsets={};self.lock=threading.RLock()
 def exchange(self,kind,value,thread='main'):
  with self.lock:
   rows=[r for r in self.records if r['thread']==thread];index=self.offsets.get(thread,0)
   if index>=len(rows):raise ReplayMismatch('unexpected boundary operation '+thread+'/'+kind)
   row=rows[index]
   expected=unpack(row['input'])
   if self.recorded_root and self.replay_root:
    expected=translate_paths(expected,self.recorded_root,'$UNIT');value=translate_paths(value,self.replay_root,'$UNIT')
   if row['kind']!=kind or expected!=value:raise ReplayMismatch('boundary request differs: '+thread+'/'+kind)
   self.offsets[thread]=index+1
   if row.get('error'):raise OSError(row['error']['message'])
   result=unpack(row['output'])
   return translate_paths(result,self.recorded_root,self.replay_root) if self.recorded_root and self.replay_root else result
 def finish(self):
  if sum(self.offsets.values())!=len(self.records):raise ReplayMismatch('unused recorded operations')

_CONFIG_MUTATIONS = frozenset({
 'create_config', 'import_config', 'edit_config', 'rename_config',
 'delete_config', 'load_config', 'save_config'})
_TRACKED_MUTATIONS = _CONFIG_MUTATIONS | {'start', 'stop', 'restart'}
_STATUS_KEYS = ('state', 'state_version', 'run_id', 'config_identity')


def _config_identity(value):
 if value is None:return None
 if not isinstance(value,dict) or not isinstance(value.get('name'),str) or not value['name']:
  raise ValueError('configuration identity name missing')
 if (not isinstance(value.get('sha256'),str) or len(value['sha256'])!=64
         or any(c not in '0123456789abcdef' for c in value['sha256'])):
  raise ValueError('configuration identity SHA-256 missing')
 if set(value)-{'name','sha256','builtin'}:raise ValueError('configuration identity has unknown fields')
 if 'builtin' in value and type(value['builtin']) is not bool:raise ValueError('configuration builtin flag invalid')
 return {'name':value['name'],'sha256':value['sha256']}


def _status_snapshot(value):
 if not isinstance(value,dict) or any(key not in value for key in _STATUS_KEYS):
  raise ValueError('initial status is not a complete snapshot')
 if not isinstance(value['state'],str) or not value['state']:
  raise ValueError('status state missing')
 if type(value['state_version']) is not int or value['state_version']<0:
  raise ValueError('status state_version is not a nonnegative integer')
 run=value['run_id']
 if run is not None and (not isinstance(run,str) or not run):
  raise ValueError('status run_id is not null or a nonempty string')
 identity=_config_identity(value['config_identity'])
 return {'state':value['state'],'state_version':value['state_version'],
         'run_id':run,'config_identity':identity,
         'controller':value.get('controller')}


def _same_config(a,b):
 if a is None or b is None:return a is None and b is None
 return a.get('name')==b.get('name') and a.get('sha256')==b.get('sha256')


class BoundarySession:
 def __init__(self,boundary,inputs=None,logical_root=None):
  self.boundary=boundary;self.inputs=inputs;self.logical_root=logical_root;self.records=[];self.mutation_operations=[];self.config_operations=[];self.config_owned_files={};self.lock=threading.RLock();self.thread_names={};self._thread_count=0;self._socket_count=0;self.owned_runs=set();self.owned_configs=set();self._local=threading.local();self._original={'time':time.time,'monotonic':time.monotonic,'sleep':time.sleep,'uuid':uuid.uuid4,'socket':socket.create_connection,'http_connection':http.client.HTTPConnection}
 def operation(self,kind,value):
  if getattr(self._local,'inside_transport',False) and kind in self._original:
   if kind=='sleep':return self._original[kind](value['seconds'])
   result=self._original[kind]();return str(result) if kind=='uuid' else result
  thread=threading.current_thread().name
  if thread=='MainThread':thread='main'
  with self.lock:
   if isinstance(self.boundary,ReplayBoundary):return self.boundary.exchange(kind,value,thread)
   row={'thread':thread,'kind':kind,'input':pack(value)};self.records.append(row)
  try:
   self._local.inside_transport=True
   result=self.boundary.exchange(kind,value)
  except Exception as exc:
   row['error']={'type':type(exc).__name__,'message':str(exc)};raise
  finally:self._local.inside_transport=False
  row['output']=pack(result);return result
 def local_observation(self,kind,value,observe):
  if getattr(self._local,'inside_transport',False):return observe()
  thread=threading.current_thread().name
  if thread=='MainThread':thread='main'
  with self.lock:
   if isinstance(self.boundary,ReplayBoundary):return self.boundary.exchange(kind,value,thread)
   row={'thread':thread,'kind':kind,'input':pack(value),'output':pack(observe())};self.records.append(row)
   return unpack(row['output'])
 def powershell(self,command,timeout=120):
  if self.inputs:
   # Keep the original scripts, bind their historical constants to this input.
   replacements={'192.168.204.233':self.inputs['listen_ip'],'192.168.204.149':self.inputs['listen_ip'],'192.168.204.1':self.inputs['allowed_host']}
   command=re.sub(r'(?<![0-9.])(?:192\.168\.204\.233|192\.168\.204\.149|192\.168\.204\.1)(?![0-9.])',lambda match:replacements[match.group()],command)
   command=command.replace('C:\\Progra~1\\FakeNet-NG-MCP',self.inputs['installation_root'])
   command=command.replace('C:\\Program Files\\FakeNet-NG-MCP',self.inputs['installation_root'])
   command=command.replace('C:\\ProgramData\\FakeNet-NG-MCP',self.inputs['programdata_root'])
   guest_work=self.inputs.get('guest_work_root')
   if guest_work:
    command=command.replace('C:\\Windows\\Temp',guest_work)
  result=self.operation('powershell',{'command':command,'timeout':timeout})
  if (not isinstance(result,dict) or result.get('is_error') or result.get('exit_code')!=0 or not isinstance(result.get('output'),str)):
   raise ValueError('original PowerShell result unsuccessful or not observed')
  return result
 def computer_name(self):return self.powershell('$env:COMPUTERNAME',timeout=30)['output'].strip()
 def urlopen(self,request,timeout=30,**kwargs):
  if kwargs:raise ValueError('unsupported URL options')
  if isinstance(request,str):request=urllib.request.Request(request)
  operation=None
  try:
   request_body=json.loads(request.data or b'{}');params=request_body.get('params') or {};tool=params.get('name');arguments=params.get('arguments') or {}
  except (ValueError,KeyError,TypeError):
   raise ValueError('MCP request is not a complete operation')
  if tool in _TRACKED_MUTATIONS:
   operation={'tool':tool,'arguments':copy.deepcopy(arguments),
              'request_command_id':arguments.get('command_id'),
              'request_expected_version':arguments.get('expected_state_version'),
              'response_unknown':True}
   with self.lock:
    self.mutation_operations.append(operation)
    if tool in _CONFIG_MUTATIONS:self.config_operations.append(operation)
  try:
   value=self.operation('http',{'url':request.full_url,'method':request.get_method(),'headers':dict(request.header_items()),'data':request.data,'timeout':timeout})
   if value.get('http_error'):raise urllib.error.HTTPError(request.full_url,value['status'],'recorded HTTP error',value['headers'],io.BytesIO(value['body']))
   response_body=json.loads(value['body']);result=response_body.get('result')
   if not isinstance(result,dict) or result.get('isError') is True:raise ValueError('MCP operation result unavailable')
   payload=json.loads(result.get('content',[{}])[0].get('text','{}'))
   if not isinstance(payload,dict) or not payload:raise ValueError('MCP operation payload incomplete')
   if operation is not None:
    operation.update(response=copy.deepcopy(payload),response_command_id=payload.get('command_id'),response_state_version=payload.get('state_version'),changed=payload.get('changed'),config_identity=copy.deepcopy(payload.get('config_identity')),name=payload.get('name'))
    error=payload.get('error')
    if error:
     if not isinstance(error,dict) or not isinstance(error.get('code'),str):raise ValueError('mutation rejection is not structured')
     if payload.get('changed') is True:raise ValueError('rejected mutation reports a change')
     operation.update(accepted=False,response_unknown=False)
    else:
     command=operation['request_command_id'];expected=operation['request_expected_version'];version=payload.get('state_version')
     if (not isinstance(command,str) or not command or type(expected) is not int or expected<0 or payload.get('command_id')!=command or type(version) is not int or (payload.get('replayed') is not True and version<=expected) or type(payload.get('changed')) is not bool or payload.get('in_progress') is True):
      raise ValueError('accepted mutation command/version receipt incomplete')
     replay=payload.get('replayed') is True
     if replay:
      prior=[op for op in self.mutation_operations if op is not operation and op.get('accepted') and not op.get('response_unknown') and op.get('request_command_id')==command]
      if len(prior)!=1:raise ValueError('foreign replay cannot establish mutation ownership')
      original=dict(prior[0]['response']);current=dict(payload);original.pop('replayed',None);current.pop('replayed',None)
      if original!=current:raise ValueError('replay differs from current-unit original')
     operation.update(accepted=True,response_unknown=False,replay=replay)
     if not replay and payload['changed']:
      receipt=payload.get('config_result') if isinstance(payload.get('config_result'),dict) else payload
      if tool=='load_config':
       identity=_config_identity(payload.get('config_identity'))
       if identity is None or identity['name']!=arguments.get('name'):raise ValueError('accepted load name differs from request')
      if tool in ('create_config','import_config','edit_config','rename_config','save_config'):
       name=arguments.get('new_name') if tool=='rename_config' else arguments.get('name')
       identity=_config_identity({k:receipt[k] for k in ('name','sha256') if k in receipt})
       if identity['name']!=name:raise ValueError('accepted configuration file name differs from request')
       if 'content' in arguments and identity['sha256']!=hashlib.sha256(arguments['content'].encode('utf-8')).hexdigest():raise ValueError('accepted configuration file hash differs from request')
       with self.lock:
        if tool in ('create_config','import_config'):self.owned_configs.add(name)
        elif tool=='rename_config' and arguments.get('name') in self.owned_configs:
         self.owned_configs.remove(arguments['name']);self.config_owned_files.pop(arguments['name'],None);self.owned_configs.add(name)
        if name in self.owned_configs:self.config_owned_files[name]=identity['sha256']
      if tool=='delete_config':
       name=arguments.get('name')
       if name in self.owned_configs and arguments.get('expected_sha256')!=self.config_owned_files.get(name):raise ValueError('accepted deletion has wrong owned hash')
       self.owned_configs.discard(name);self.config_owned_files.pop(name,None)
     if not replay and tool in ('start','restart') and payload.get('run_id'):self.owned_runs.add(payload['run_id'])
  except BaseException:
   if operation is not None:
    operation['response_unknown']=True
    self.preserve_scene=True
   raise
  return RecordedResponse(value)
 def http_connection(self,host,port=None,timeout=30,source_address=None,**kwargs):
  if getattr(self._local,'inside_transport',False):return self._original['http_connection'](host,port,timeout=timeout,source_address=source_address,**kwargs)
  if kwargs or not source_address:raise ValueError('explicit source required for raw HTTP probe')
  owner=self
  class Connection:
   def request(self,method,path,body=None,headers=None):
    self.response=owner.operation('http-source',{'host':host,'port':port,'timeout':timeout,'source_address':list(source_address),'method':method,'path':path,'body':body,'headers':headers or {}})
   def getresponse(self):return RecordedResponse(self.response)
   def close(self):pass  # Native operation closes its socket before returning bytes.
  return Connection()
 def socket_connection(self,address,timeout=30,source_address=None,**kwargs):
  if getattr(self._local,'inside_transport',False):return self._original['socket'](address,timeout,source_address,**kwargs)
  if kwargs:raise ValueError('unsupported socket options')
  with self.lock:self._socket_count+=1;handle='socket-%d'%self._socket_count
  self.operation('socket-open',{'handle':handle,'address':list(address),'timeout':timeout,'source_address':list(source_address) if source_address else None})
  owner=self
  class Connection:
   def sendall(self,data):return owner.operation('socket-send',{'handle':handle,'data':data})
   def recv(self,count):return owner.operation('socket-recv',{'handle':handle,'count':count})
   def settimeout(self,seconds):return owner.operation('socket-timeout',{'handle':handle,'seconds':seconds})
   def close(self):return owner.operation('socket-close',{'handle':handle})
   def __enter__(self):return self
   def __exit__(self,*exc):self.close()
  return Connection()
 def receive_artifact(self,channel,artifact,destination,allowed_client=None):
  # Fixed chunked transfer over the existing channel. No new host listener.
  from pathlib import PureWindowsPath
  source=PureWindowsPath(artifact['path']);base=PureWindowsPath(self.inputs['programdata_root'])/'artifacts'
  if not source.is_relative_to(base) or '..' in source.parts or "'" in str(source):raise ValueError('artifact path escapes fixed root')
  size=artifact.get('size');want=artifact.get('sha256')
  if not isinstance(size,int) or not 0<size<=512*1024*1024 or artifact.get('complete') is not True:raise ValueError('artifact not closed/bounded')
  raw=self.powershell("$ErrorActionPreference='Stop';$p='"+str(source)+"';@{size=(Get-Item -LiteralPath $p).Length;sha256=(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLower()}|ConvertTo-Json -Compress",timeout=30)
  metadata=json.loads(raw['output'])
  if metadata!={'size':size,'sha256':want}:raise ValueError('artifact metadata changed before transfer')
  destination=Path(destination);destination.parent.mkdir(parents=True,exist_ok=True)
  with destination.open('xb') as stream:
   for offset in range(0,size,262144):
    count=min(262144,size-offset)
    block=self.powershell("$ErrorActionPreference='Stop';$s=[IO.File]::OpenRead('"+str(source)+"');try{[void]$s.Seek("+str(offset)+",[IO.SeekOrigin]::Begin);$b=New-Object byte[] "+str(count)+";$n=$s.Read($b,0,$b.Length);if($n -ne $b.Length){throw 'short original artifact'};[Convert]::ToBase64String($b)}finally{$s.Dispose()}",timeout=30)
    data=base64.b64decode(block['output'],validate=True)
    if len(data)!=count:raise ValueError('short original artifact block')
    stream.write(data)
  if sha256(destination)!=want:raise ValueError('original artifact digest differs')
  result={'path':str(destination),'size':size,'sha256':want,'guest_metadata':artifact,'transfer':raw,'mechanism':'existing-channel-chunks-no-listener','receiver':{'socket_fileno':-1,'thread_stopped':True,'kernel_listeners':[]},'closure':{'output':'CLOSED','reason':'no receiver socket created'}}
  write(destination.with_suffix('.transfer.json'),result);return result
 def run_process(self,argv,**kwargs):
  if not isinstance(argv,(list,tuple)) or kwargs.get('shell'):raise ValueError('no shell or arbitrary command text')
  # Only original fixed source argv under the current candidate is reachable.
  value=self.operation('process',{'argv':[str(x) for x in argv],'cwd':str(kwargs.get('cwd') or ROOT),'timeout':kwargs.get('timeout',120)})
  text=kwargs.get('text') or kwargs.get('universal_newlines')
  return subprocess.CompletedProcess(argv,value['returncode'],value['stdout'].decode() if text else value['stdout'],value['stderr'].decode() if text else value['stderr'])
 @contextlib.contextmanager
 def activate(self):
  from unittest.mock import patch
  real_thread_init=threading.Thread.__init__;real_alive=threading.Thread.is_alive
  def init_thread(thread,*args,**kwargs):
   with self.lock:self._thread_count+=1;number=self._thread_count
   kwargs['name']='mcp-worker-%d'%number
   real_thread_init(thread,*args,**kwargs)
  with contextlib.ExitStack() as stack:
   stack.enter_context(patch.object(threading.Thread,'is_alive',lambda thread:self.local_observation('thread-alive',{'name':thread.name},lambda:real_alive(thread))))
   for obj,name,replacement in ((urllib.request,'urlopen',self.urlopen),(subprocess,'run',self.run_process),(time,'time',lambda:self.operation('time',{})),(time,'monotonic',lambda:self.operation('monotonic',{})),(time,'sleep',lambda n:self.operation('sleep',{'seconds':n})),(uuid,'uuid4',lambda:uuid.UUID(self.operation('uuid',{}))),(threading.Thread,'__init__',init_thread)):
    stack.enter_context(patch.object(obj,name,replacement))
   stack.enter_context(patch.object(http.client,'HTTPConnection',self.http_connection))
   import artifact_transfer
   stack.enter_context(patch.object(artifact_transfer,'receive_artifact',self.receive_artifact))
   # A direct unrecorded socket path must never silently evade the evidence.
   stack.enter_context(patch.object(socket,'create_connection',self.socket_connection))
   yield


def current_tool_surface(root=ROOT):
 import ast
 names=[]
 for relative in ('fakenet/mcp/server.py','fakenet/mcp/tools.py'):
  tree=ast.parse((Path(root)/relative).read_text())
  for node in ast.walk(tree):
   if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)) and any(isinstance(d,ast.Call) and isinstance(d.func,ast.Attribute) and d.func.attr=='tool' for d in node.decorator_list):names.append(node.name)
 if len(names)!=len(set(names)):raise ValueError('ambiguous candidate tool surface')
 return sorted(names)

def original_args(inputs,out):
 identity=inputs['identity'];url=urllib.parse.urlparse(inputs['endpoint'])
 return SimpleNamespace(**identity,package=inputs['package'],manifest=inputs['manifest'],
  programdata_root=inputs['programdata_root'],guest_work_root=inputs['guest_work_root'],vm_identity=json.dumps(inputs['target'],sort_keys=True),config_identity=json.dumps(inputs['config_identity'],sort_keys=True),
  target_base_url=inputs['endpoint'].rstrip('/'),listen_ip=inputs['listen_ip'],listen_port=url.port,allowed_host=inputs['allowed_host'],
  controller_uuid='11111111-2222-4333-8444-555555555555',vm_package_dir=inputs['installation_root'],win10vm_mcp='existing-config-reference',
  manage_extra_ports=True,expected_tool_surface=current_tool_surface(),extra_exclude_port=[],run_firewall_round=True,deploy='deploy' in inputs['actions'],output_root=str(out),fault_record=[],localization_record='')

def invoke_unit(unit,args,channel,writer,mods):
 base=args.target_base_url;p1=mods['run_p01_acc'];p2=mods['run_p02_acc'];p3=mods['run_p03_acc'];p4=mods['run_p04_acc']
 if unit=='P01-ENTRY':return p1.run_p01_entry(args,channel,writer,args.package_sha256)
 if unit=='ACC-002':
  code=p1.run_acc002(args,channel,writer,target_client_probe=False)
  if code!=0:return code
  result=channel.operation('sdk',{'url':base+'/mcp'});writer.add_evidence('existing-sdk-discovery-ping',result)
  ping=result['ping'];payload=json.loads(ping['content'][0]['text'])
  return 0 if ping.get('isError') is not True and payload.get('service')=='fakenetng-mcp' and any(item.get('name')=='ping' for item in result['tools']['tools']) else 1
 if unit in ('ACC-003','ACC-016'):return getattr(p1,'run_acc'+unit[4:])(args,channel,writer)
 if unit in ('ACC-005','ACC-010'):return getattr(p2,'run_acc'+unit[4:])(base,writer)
 if unit=='ACC-011':return p2.run_acc011(base,channel,writer)
 if unit=='ACC-009-PRE':return p2.run_acc009_pre(base,channel,writer)
 if unit=='ACC-001-HEADLESS':return p3.run_acc001_headless(base,channel,writer,args)
 if unit.startswith('ACC-004-S'):return p3.run_acc004_scenario(base,channel,writer,unit[-2:])
 if unit in ('ACC-006','ACC-007','ACC-008','ACC-009'):return getattr(p3,'run_acc'+unit[4:])(base,channel,writer)
 if unit=='HEALTH-NO-LISTENER':
  checks=p3.exercise_no_listener_health(base,writer)
  return 0 if checks and all(value is True for value in checks.values()) else 1
 if unit=='HEALTH-ACTIVE-PROBE':
  from run_active_probe import run_active_probe_loss
  checks=run_active_probe_loss(base,channel,writer)
  return 0 if checks and all(value is True for value in checks.values()) else 1
 if unit=='FAULT-POINTS':return p4.run_fault_point_proof(base,channel,writer,args)
 if unit=='INCIDENT-INTEGRITY':return p4.run_incident_integrity(base,channel,writer,args)
 if unit=='ACC-014':return p4.run_acc014(base,channel,writer,args)
 if unit=='ACC-015':return p4.run_acc015(base,channel,writer,args.allowed_host,args.programdata_root)
 if unit=='ACC-019':
  args.acc008_capability=__import__('acceptance_mcp_dependencies').verify_acc008(channel.inputs,root=ROOT,fixture=channel.boundary.fixture)
  writer.add_evidence('acc019-ACC008-reference',args.acc008_capability)
  return p4.run_acc019(base,channel,writer,args)
 if unit in FAULTS:
  from types import SimpleNamespace as NS
  gate=mods['run_p05_release'].ReleaseGate(NS(**{**vars(args),'output_root':str(writer.out_dir)}));gate.channel=channel
  writer.add_evidence('fault-mode',gate.configure_fault_mode(True))
  try:
   record=gate.run_fault_round(unit,1);writer.add_evidence('fault-round',record)
   failures=mods['evidence_integrity'].validate_round(record,{k:getattr(args,k) for k in IDENTITY_FIELDS});writer.add_evidence('fault-failures',failures)
   return 1 if failures else 0
  finally:writer.add_evidence('fault-mode-restored',gate.configure_fault_mode(False))
 if unit in IPC:
  checks=mods['run_ipc_cases'].run_ipc_matrix(base,channel,writer,selected=[unit]);return 0 if checks and all(v is True for v in checks.values()) else 1
 if unit=='INITIALIZATION-FAILURE':
  checks=mods['run_initialization_case'].run_initialization_failure(base,channel,writer);writer.add_evidence('initialization-checks',checks);return 0 if checks and all(v is True for v in checks.values()) else 1
 control=mods['run_control_cases'].ControlCase(args);control.channel=channel
 if unit=='CONTROL-DEFAULT':checks=control.case_control_default(writer)
 elif unit=='CONTROL-INVALID':checks=control.case_control_invalid(writer)
 elif unit.startswith('CONTROL-EXTRA-'):checks=control.case_control_extra(writer,int(unit.rsplit('-',1)[1]))
 elif unit in ('LOOPBACK-V4','LOOPBACK-V6'):checks=control.case_loopback(writer,unit[-2:])
 else:raise ValueError('unknown original unit '+unit)
 writer.add_evidence('case-checks',checks);return 0 if checks and all(v is True for v in checks.values()) else 1



def service_preflight(session,inputs):
 manifest=read(inputs['manifest']);rows=[item for item in manifest['files'] if item['path'].replace('\\','/').lower()=='fakenetng-mcp.exe']
 if len(rows)!=1:raise ValueError('candidate service image identity is not unique')
 image=str(__import__('pathlib').PureWindowsPath(inputs['installation_root'])/'fakenetng-mcp.exe')
 script=("$ErrorActionPreference='Stop';$exe='"+image.replace("'","''")+"';"
  "$svc=Get-CimInstance Win32_Service -Filter \"Name='fakenetng-mcp'\";"
  "if(-not $svc -or $svc.State -ne 'Running' -or -not $svc.ProcessId){throw 'MCP service not running'};"
  "$p=Get-Process -Id $svc.ProcessId -ErrorAction Stop;[void]$p.Handle;"
  "if($p.Path -ine $exe){throw 'MCP service image differs'};"
  "$key='HKLM:\\SYSTEM\\CurrentControlSet\\Services\\fakenetng-mcp';"
  "$envs=@((Get-ItemProperty $key -Name Environment -ErrorAction SilentlyContinue).Environment);"
  "$cfg=Get-Content '"+inputs['programdata_root']+"\\configs\\service.json' -Raw|ConvertFrom-Json;"
  "$fault='"+inputs['programdata_root']+"\\logs\\fault-injection.json';"
  "@{image=$p.Path;sha256=(Get-FileHash -LiteralPath $p.Path -Algorithm SHA256).Hash.ToLower();"
  "pid=$p.Id;birth=$p.StartTime.ToFileTimeUtc().ToString();"
  "service_config=$cfg;enabled=($envs -contains 'FAKENETNG_MCP_FAULT_INJECTION=1');grace=$cfg.stop_grace_seconds;"
  "fault_exists=(Test-Path $fault)}|ConvertTo-Json -Compress")
 raw=session.powershell(script,timeout=60);value=json.loads(raw['output'])
 if value.get('image','').casefold()!=image.casefold() or value.get('sha256')!=rows[0]['sha256'] or not isinstance(value.get('pid'),int) or value['pid']<=0 or not str(value.get('birth','')).isdigit():raise ValueError('MCP installed image/process birth differs from candidate')
 if value.get('fault_exists') is not False or type(value.get('enabled')) is not bool or type(value.get('grace')) is not int or not isinstance(value.get('service_config'),dict):raise ValueError('unknown fault residue or service settings; preserve scene')
 return value

def _verified_version_chain(session,initial,final):
 operations=list(session.mutation_operations)
 if any(op.get('response_unknown') for op in operations):raise ValueError('configuration operation response is unresolved')
 intervals=[];seen=set()
 for op in operations:
  response=op.get('response') or {}
  if not op.get('accepted') or op.get('replay'):continue
  command=op['request_command_id']
  if command in seen:raise ValueError('duplicate mutation without replay identity')
  seen.add(command);intervals.append((op['request_expected_version'],response['state_version']))
 version=initial['state_version']
 for start,end in sorted(intervals):
  if start!=version:raise ValueError('state version continuity is unverified')
  version=end
 if version!=final['state_version']:raise ValueError('state version continuity is unverified')


def _accepted_load_operation(session, initial, final):
 """Find only a current-run accepted load that explains the actual active config."""
 candidates=[]
 for number,operation in enumerate(session.config_operations):
  if operation.get('tool')!='load_config' or operation.get('replay'):continue
  if operation.get('response_unknown'):raise ValueError('configuration load response is unresolved')
  response=operation.get('response')
  if not isinstance(response,dict) or response.get('error'):continue
  command=operation.get('request_command_id')
  expected=operation.get('request_expected_version')
  if (not isinstance(command,str) or not command
          or type(expected) is not int or expected<0
          or response.get('command_id')!=command
          or type(response.get('state_version')) is not int
          or response['state_version']<=expected):
   raise ValueError('accepted configuration load identity/version differs')
  identity=_config_identity(response.get('config_identity'))
  request_name=(operation.get('arguments') or {}).get('name')
  if not isinstance(request_name,str) or not request_name:
   raise ValueError('accepted configuration load lacks requested name')
  if identity is not None and identity['name']!=request_name:raise ValueError('accepted load name differs from request')
  if identity is None or not _same_config(identity,final):
   continue
  if initial is not None and not _same_config(initial,final):
   candidates.append((number,operation,identity))
 if not candidates:raise ValueError('active configuration changed without current-run accepted load')
 number,operation,identity=candidates[-1]
 if operation.get('changed') is not True:
  raise ValueError('accepted load did not report an actual configuration change')
 return operation


def _restore_config(mods,base,session,inputs,initial,current,writer):
 name=inputs['config_identity']['name'];digest=inputs['config_identity']['sha256']
 frozen=mods['run_p02_acc'].call(base,'read_config',{'name':name},controller=None)
 if frozen.get('error') or frozen.get('name')!=name or frozen.get('sha256')!=digest:
  raise ValueError('original configuration binding changed; do not restore by name alone')
 command=mods['run_p02_acc'].unique_command('owned-restore-config')
 restored=mods['run_p02_acc'].call(base,'load_config',{
  'name':name,'command_id':command,'expected_state_version':current['state_version']})
 if (not isinstance(restored,dict) or restored.get('error')
         or restored.get('command_id')!=command
         or type(restored.get('state_version')) is not int
         or restored['state_version']<=current['state_version']
         or restored.get('changed') is not True
         or not _same_config(_config_identity(restored.get('config_identity')),initial)):
  raise ValueError('configuration restore was not accepted with exact original identity')
 writer.add_evidence('owned-restore-config',restored)
 return restored


def _cleanup_owned_configs(mods,base,session,writer):
 for name in sorted(session.owned_configs.copy()):
  item=mods['run_p02_acc'].call(base,'read_config',{'name':name},controller=None)
  if item.get('error'):raise ValueError('owned config observation missing')
  expected=session.config_owned_files.get(name)
  if expected is not None and item.get('sha256')!=expected:
   raise ValueError('owned config content changed; do not delete foreign bytes')
  if expected is None:
   raise ValueError('owned config lacks accepted content identity')
  state=mods['run_p02_acc'].status(base)
  command=mods['run_p02_acc'].unique_command('owned-config-delete')
  deleted=mods['run_p02_acc'].call(base,'delete_config',{
   'name':name,'expected_sha256':item['sha256'],
   'command_id':command,'expected_state_version':state['state_version']})
  writer.add_evidence('owned-config-delete-'+str(len(writer.evidence)),deleted)
  if (not isinstance(deleted,dict) or deleted.get('error')
          or deleted.get('command_id')!=command
          or type(deleted.get('state_version')) is not int
          or deleted['state_version']<=state['state_version']):
   raise ValueError('owned config cleanup rejected')
 return None


def run_unit(unit,inputs,out,boundary,*,root=ROOT,fixture=None):
 mods=modules(root);session=BoundarySession(boundary,inputs);out=Path(out);writer=mods['helpers'].EvidenceWriter(out,'original-unit')
 args=original_args(inputs,out)
 if unit=='ACC-014' and 'ACC-014' in inputs.get('references',{}):
  writer.add_evidence('capability-request-reference',inputs['references']['ACC-014'])
  writer.add_evidence('capability-reference-scope',{'native_operation_performed':False,'reused_capability_only':True,'current_deployment_observed':False})
  code=2;error=None
  try:
   code=__import__('acceptance_mcp_capabilities').evaluate(inputs['references']['ACC-014'],inputs,root,writer,fixture=bool(boundary.fixture) if fixture is None else fixture)
  except (OSError,ValueError,KeyError,TypeError,AssertionError) as exc:
   error={'type':type(exc).__name__,'message':str(exc)};writer.blocker=error
  status={0:'pass',1:'fail',2:'blocked',3:'unknown'}.get(code,'unknown')
  result=writer.write_result(acc_id=unit,p_id='headless',**inputs['identity'],environment_identity=json.dumps(inputs['target'],sort_keys=True),status=status)
  trace={'schema':'fakenet.mcp-unit-trace.v1','unit':unit,'identity':inputs['identity'],'target':inputs['target'],'config_identity':inputs['config_identity'],'unit_root':str(out.resolve()),'records':[],'returncode':code,'error':error,'recovery_observed':True,'recovery_error':None,'origin':'closed-independent-capability-no-native-action'}
  return result,trace
 code=3;error=None;before=None;after=None;service_before=None;recovery_error=None;initial=None;final=None
 with session.activate():
  # Original classes importing a channel still get this same recorded transport.
  from unittest.mock import patch
  with contextlib.ExitStack() as stack:
   for module in mods.values():
    if hasattr(module,'Win10VmChannel'):stack.enter_context(patch.object(module,'Win10VmChannel',lambda *a,**kw:session))
   try:
    actual=session.operation('target',{})
    if actual!=inputs['target']:raise ValueError('observed VM differs from frozen identity')
    initial_raw=mods['run_p02_acc'].status(args.target_base_url)
    initial=_status_snapshot(initial_raw)
    writer.add_evidence('initial-status',initial_raw)
    if initial['state']!='stopped' or initial['run_id']:raise ValueError('MCP entry not idle; preserve foreign run')
    ping=mods['run_p02_acc'].call(args.target_base_url,'ping',controller=None)
    build=ping.get('build_identity') or {}
    if build.get('source_commit')!=args.source_commit or build.get('manifest_sha256')!=inputs['manifest_sha256']:raise ValueError('deployed candidate build differs')
    active=initial['config_identity']
    if active is not None:
     if not _same_config(active,inputs['config_identity']):raise ValueError('active configuration differs')
    else:
     binding=mods['run_p02_acc'].call(args.target_base_url,'read_config',{'name':inputs['config_identity']['name']},controller=None)
     if binding.get('error') or binding.get('name')!=inputs['config_identity']['name'] or binding.get('sha256')!=inputs['config_identity']['sha256']:
      raise ValueError('input configuration binding differs')
     writer.add_evidence('initial-config-binding',binding)
    service_before=service_preflight(session,inputs);writer.add_evidence('installed-service-before',service_before)
    before=session.operation('observe',{})
    writer.add_evidence('environment-before',before)
    code=invoke_unit(unit,args,session,writer,mods)
   except Exception as exc:error={'type':type(exc).__name__,'message':str(exc)};writer.blocker=error
   finally:
    if before is not None:
     try:
      if any(op.get('response_unknown') for op in session.mutation_operations):raise ValueError('configuration operation response is unresolved')
      if getattr(session,'preserve_scene',False):raise ValueError('controlled operation unresolved; preserve scene')
      final_raw=mods['run_p02_acc'].status(args.target_base_url)
      final=_status_snapshot(final_raw)
      if final['run_id'] in session.owned_runs:
       stopped=mods['run_p02_acc'].call(args.target_base_url,'stop',{'command_id':mods['run_p02_acc'].unique_command('owned-final-stop'),'expected_state_version':final['state_version']},timeout=420)
       writer.add_evidence('owned-final-stop',stopped);final_raw=mods['run_p02_acc'].status(args.target_base_url);final=_status_snapshot(final_raw)
      writer.add_evidence('pre-recovery-status',final_raw)
      writer.add_evidence('config-operations-initial',copy.deepcopy(session.config_operations))
      if final['state']!='stopped' or final['run_id'] is not None:
       raise ValueError('final service state is not idle; preserve recovery required')
      if final['state_version']<initial['state_version']:
       raise ValueError('state version regressed during the unit')
      if any(op.get('response_unknown') for op in session.config_operations):
       raise ValueError('configuration operation response is unresolved')
      _verified_version_chain(session,initial,final)
      initial_config=initial['config_identity'];final_config=final['config_identity']
      if initial_config is None:
       if final_config is not None:raise ValueError('configuration appeared from null initial state; no safe restore')
       if any(op.get('tool')=='load_config' and op.get('accepted') is True and op.get('changed') is True and not op.get('response_unknown') for op in session.config_operations):
        raise ValueError('null configuration changed without safe restore')
       _cleanup_owned_configs(mods,args.target_base_url,session,writer)
      elif _same_config(initial_config,final_config):
       _cleanup_owned_configs(mods,args.target_base_url,session,writer)
      elif final_config is None:
       raise ValueError('active configuration disappeared; preserve recovery required')
      else:
       _accepted_load_operation(session,initial_config,final_config)
       _restore_config(mods,args.target_base_url,session,inputs,initial_config,final,writer)
       _cleanup_owned_configs(mods,args.target_base_url,session,writer)
      final_raw=mods['run_p02_acc'].status(args.target_base_url)
      final=_status_snapshot(final_raw)
      _verified_version_chain(session,initial,final)
      writer.add_evidence('final-status',final_raw)
      if initial_config is None:
       if final['config_identity'] is not None:raise ValueError('restored configuration is not null')
      elif not _same_config(final['config_identity'],initial_config):
       raise ValueError('restored configuration identity not observed')
      if service_before is not None:
       restored_mode=mods['helpers'].configure_fault_service(session,service_before['enabled'],service_before['grace'])
       writer.add_evidence('service-settings-restored',restored_mode)
       service_after=service_preflight(session,inputs);writer.add_evidence('installed-service-after',service_after)
       if any(service_after[k]!=service_before[k] for k in ('image','sha256','enabled','grace','fault_exists','service_config')):raise ValueError('service settings/image restoration not observed')
      after=session.operation('observe',{});writer.add_evidence('environment-after',after)
      from fakenet.mcp.baseline import audit_compare
      differences=audit_compare(before['sections'],after['sections'])
      writer.add_evidence('environment-diff',differences)
      if differences or final.get('state')!='stopped' or final.get('run_id'):raise ValueError('MCP recovery not established; preserve original failed state')
     except Exception as exc:
      recovery_error={'type':type(exc).__name__,'message':str(exc)};error=error or recovery_error;writer.blocker=error;code=1
 status={0:'pass',1:'fail',2:'blocked',3:'unknown'}.get(code,'unknown')
 result=writer.write_result(acc_id=unit,p_id='headless',**inputs['identity'],environment_identity=json.dumps(inputs['target'],sort_keys=True),status=status)
 trace={'schema':'fakenet.mcp-unit-trace.v1','unit':unit,'identity':inputs['identity'],'target':inputs['target'],'config_identity':inputs['config_identity'],'unit_root':str(out.resolve()),'records':session.records,'returncode':code,'error':error,'initial_status':initial,'final_status':final,'config_operations':session.config_operations,'recovery_observed':before is not None and after is not None and recovery_error is None,'recovery_error':recovery_error}
 if isinstance(boundary,ReplayBoundary):
  try:boundary.finish()
  except ReplayMismatch as exc:
   reason=(error or {}).get('message') or status
   raise ReplayMismatch(str(exc)+'; original unit failure: '+reason) from exc
 return result,trace


def run(case,output,inputs,*,selected=None,boundary=None,fixture=False,root=ROOT):
 inputs,selected=validate_inputs(inputs,case,selected,fixture=fixture)
 if 'ACC-019' in selected:
  __import__('acceptance_mcp_dependencies').verify_acc008(inputs,root=root,fixture=fixture)
  if 'deploy' not in inputs['actions']:raise ValueError('ACC019 upgrade CLI requires explicit deploy action')
 out=Path(output).resolve()
 if not out.is_relative_to(Path(inputs['work_root']).resolve()):raise ValueError('MCP output outside fixed owned root')
 if out.exists():raise FileExistsError('MCP output exists; no overwrite or replay')
 out.mkdir(parents=True)
 write(out/'inputs.json',inputs);write(out/'source-pins.json',source_pins(root))
 if boundary is None:
  boundary=(ClosedReferenceBoundary(fixture) if selected==['ACC-014'] and 'ACC-014' in inputs.get('references',{})
            else NativeBoundary(root,inputs,out/'channel'))
 if bool(boundary.fixture)!=bool(fixture):raise ValueError('fixture boundary requires explicit candidate fixture identity')
 results={};unresolved=False
 for unit in selected:
  if unresolved:
   results[unit]={'status':'not_run','result':None,'trace':None};continue
  result,trace=run_unit(unit,inputs,out/'units'/unit,boundary,root=root,fixture=fixture)
  write(out/'units'/unit/'trace.json',trace)
  results[unit]={'status':result['status'],'result':'units/'+unit+'/result.json','trace':'units/'+unit+'/trace.json'}
  unresolved=trace.get('recovery_observed') is not True or trace.get('recovery_error') is not None
 write(out/'mcp-result.json',{'schema':SCHEMA,'case':case,'identity':inputs['identity'],'target':inputs['target'],'config_identity':inputs['config_identity'],'fixture':fixture,'checks':results,'exclusions':EXCLUSIONS})
 return read(out/'mcp-result.json')

def main(argv=None):
 parser=argparse.ArgumentParser();parser.add_argument('--case',choices=CASES,required=True);parser.add_argument('--inputs',required=True);parser.add_argument('--output',required=True);parser.add_argument('--checks')
 args=parser.parse_args(argv)
 result=run(args.case,args.output,read(args.inputs),selected=args.checks.split(',') if args.checks else None)
 return 0 if all(r['status']=='pass' for r in result['checks'].values()) else 1
if __name__=='__main__':raise SystemExit(main())
