"""Fresh sessions use the actual RawMcp, bounded child and loopback HTTP seam."""
import hashlib
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
from pathlib import Path
import threading
import time

import pytest

from test_formal_runtime_context import materials, load
from test_formal_runtime_ownership import configured, INI
from formal_runtime.clients import FreshClient
from formal_runtime.instance import Responsibility,ProtectedService,MutationUnknown
from formal_runtime.config_ownership import ConfigOwnedService
from bounded_mcp import TransportUnknown
import scenario_suite as suite


@pytest.fixture
def server():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*_): pass
        def do_POST(self):
            request=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            self.server.received.append({'body':request,'headers':{key.casefold():value for key,value in self.headers.items()}})
            if self.server.mode=='slow': time.sleep(.2)
            if self.server.mode=='unknown' and request['method']=='tools/call': self.server.stop_event.wait(2)
            response={'jsonrpc':'2.0','id':request.get('id'),'result':{}}
            if request['method']=='tools/call':
                params=request['params']
                if params['name']=='PowerShell':
                    boundary=getattr(self.server,'vm_boundary',None)
                    if boundary:
                        raw=boundary(params['arguments']['command'],params['arguments']['timeout'])
                        value='Response: '+raw['output']+'\nStatus Code: '+str(raw.get('exit_code',0))
                    else:value='Response: original stdout\nStatus Code: 0'
                elif self.server.store is not None:
                    self.server.store.controller_id=self.headers['X-FakeNet-Controller-ID']
                    result=self.server.store.tool_outcome(params['name'],params['arguments'])
                    value=json.dumps(result['value'] if result['ok'] else {'error':result['error']})
                    response['result']['isError']=not result['ok']
                else:value=json.dumps({'state':'stopped','original_name':params['name']})
                response['result']['content']=[{'type':'text','text':value}]
            self.send_response(200)
            if request['method']=='initialize': self.send_header('Mcp-Session-Id','own-session-%d'%len(self.server.received))
            raw=json.dumps(response).encode() if 'id' in request else b''
            self.send_header('Content-Length',str(len(raw)));self.end_headers()
            try:self.wfile.write(raw)
            except (BrokenPipeError,ConnectionResetError): pass
    value=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    value.received=[];value.mode='complete';value.store=None;value.stop_event=threading.Event();value.daemon_threads=False
    thread=threading.Thread(target=value.serve_forever);thread.start()
    yield value
    value.stop_event.set();value.shutdown();value.server_close();thread.join(2)
    assert not thread.is_alive()


def client(server,context,vm=False,state=None):
    url='http://127.0.0.1:%d/mcp'%server.server_port
    original=(suite.VmMcp if vm else suite.RawMcp)(url,controller_id='exact-original-controller')
    return FreshClient(original,context,state or Responsibility())


def test_actual_fresh_VM_sessions_and_original_response_with_ended_transport(materials,server):
    c=client(server,load(materials),vm=True)
    one=c.powershell('original command one',3);two=c.powershell('original command two',3)
    assert one['output']==two['output']=='original stdout' and one['exit_code']==0
    assert [r['body']['method'] for r in server.received]==['initialize','notifications/initialized','tools/call']*2
    sessions=[r['headers']['mcp-session-id'] for r in server.received if r['body']['method']=='tools/call']
    assert len(set(sessions))==2
    ledger=c.responsibility();assert ledger['audit_safe'] and ledger['host_writers_ended']
    assert len(ledger['calls'])==2 and all(row['response_known'] and len(row['transport_completions'])==3 for row in ledger['calls'])


def test_outer_absolute_deadline_survives_fresh_VM_constructor_and_all_handshakes(materials,server):
    c=client(server,load(materials),vm=True);server.mode='slow'
    deadline=time.monotonic()+.45;c._absolute_deadline=deadline;start=time.monotonic()
    with pytest.raises(TransportUnknown): c.powershell('must not regain three seconds',3)
    assert time.monotonic()-start<.8 and not any(r['body']['method']=='tools/call' for r in server.received)
    ledger=c.responsibility();assert ledger['host_writers_ended'] and not ledger['calls'][0]['response_known']
    for p in c.root.rglob('request.json'):
        value=json.loads(p.read_bytes());assert value['deadline_monotonic']<=deadline
    assert c._absolute_deadline==deadline


def test_expired_original_deadline_has_zero_HTTP_and_no_transport_output(materials,server):
    c=client(server,load(materials),vm=True);c._absolute_deadline=time.monotonic()-1
    with pytest.raises(TransportUnknown,match='before fresh client start'): c.powershell('no dispatch',3)
    assert not server.received and not c.root.exists()


def test_service_original_controller_and_timeout_caps_are_preserved(materials,server):
    c=client(server,load(materials));out=c.tool_outcome('get_status',{},900)
    assert out['ok'] and out['value']['state']=='stopped'
    assert server.received[0]['headers']['x-fakenet-controller-id']=='exact-original-controller'
    assert c.responsibility()['calls'][0]['effective_budget']==30
    c.tool_outcome('start',{'command_id':'own-command'},900)
    assert c.responsibility()['calls'][1]['effective_budget']==480


def test_unknown_product_mutation_is_not_replayed_and_host_child_is_ended(materials,server):
    state=Responsibility();state.admission_ready=True
    c=client(server,load(materials),state=state);protected=ProtectedService(c,c.context,state);server.mode='unknown'
    with pytest.raises(MutationUnknown): protected.tool_outcome('start',{'command_id':'exact-own'},30)
    assert not state.safe
    with pytest.raises(RuntimeError): protected.tool_outcome('start',{'command_id':'exact-own'},30)
    assert len(server.received)==1 and c.responsibility()['host_writers_ended']


def test_known_actual_ConfigStore_response_and_owner_survive_fresh_terminal_IO_failure(configured,server,monkeypatch):
    context,_,plan,store_client,old_wrapper=configured
    server.store=store_client;state=Responsibility();state.admission_ready=True
    c=client(server,context,state=state);protected=ProtectedService(c,context,state)
    wrapper=ConfigOwnedService(protected,context,plan,{'rows':store_client.store.list()})
    original_open=Path.open
    def io_boundary(path,*args,**kwargs):
        if path.name=='call-terminal.json': raise OSError('controlled fresh terminal storage failure')
        return original_open(path,*args,**kwargs)
    monkeypatch.setattr(Path,'open',io_boundary)
    name=plan['selected'][0]['scratch'];out=wrapper.tool_outcome('create_config',{'name':name,'content':INI,'command_id':'exact-create'},3)
    sha=hashlib.sha256(INI.encode()).hexdigest()
    assert out['ok'] and out['value']['sha256']==sha and wrapper.owned=={name:sha}
    assert store_client.store.read(name)['sha256']==sha and not state.safe
    ledger=c.responsibility();assert not ledger['audit_safe'] and ledger['host_writers_ended']
    assert next(iter(ledger['audit_failures'].values()))['not_remote_response_unknown']
    with pytest.raises(RuntimeError): wrapper.tool_outcome('delete_config',{'name':name,'expected_sha256':sha},3)
    assert len(server.received)==1 and store_client.store.read(name)['sha256']==sha


def test_unreadable_actual_transport_completion_keeps_known_response_and_unresolved_writer_proof(materials,server,monkeypatch):
    c=client(server,load(materials));original_open=Path.open
    def io_boundary(path,*args,**kwargs):
        mode=args[0] if args else kwargs.get('mode','r')
        if path.name=='completion.json' and mode=='rb': raise OSError('controlled completion read failure')
        return original_open(path,*args,**kwargs)
    monkeypatch.setattr(Path,'open',io_boundary)
    out=c.tool_outcome('get_status',{},3)
    assert out['ok'] and out['value']['state']=='stopped'
    ledger=c.responsibility();assert not ledger['audit_safe'] and not ledger['host_writers_ended']
    assert next(iter(ledger['audit_failures'].values()))['not_remote_response_unknown']
    with pytest.raises(RuntimeError): c.tool_outcome('start',{},3)
    assert len(server.received)==1
    monkeypatch.setattr(Path,'open',original_open)
    originals=[json.loads(p.read_bytes()) for p in c.root.rglob('completion.json')]
    assert len(originals)==1 and originals[0]['local_writer_ended']  # original stays unmodified


def test_changed_material_before_call_has_zero_request_and_zero_evidence(materials,server):
    c=client(server,load(materials));c.context.materials_path.write_bytes(b'{}')
    with pytest.raises(ValueError,match='independent materials SHA256 mismatch'): c.tool_outcome('get_status',{},3)
    assert not server.received and not c.root.exists()
