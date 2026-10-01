"""Acceptance-only subprocess transport; deadlines include parsing and cleanup.

Terminating this client never cancels the remote request. Sent requests with an
unknown result are retained and must be reconciled without mutation replay.
"""
from __future__ import annotations
import json,os,subprocess,sys,time,uuid,urllib.request,urllib.error
from pathlib import Path
class TransportUnknown(RuntimeError):
    def __init__(self,message,record):super().__init__(message);self.record=record

def save(path,value):
    with Path(path).open('w',encoding='utf-8') as f:json.dump(value,f,ensure_ascii=False)

def _child(spec,directory):
    d=Path(directory);phase={'phase':'child_started','pid':os.getpid(),'request_id':spec['request_id'],'sent':'not_yet'}
    def mark(stage,**fields):
        phase.update(phase=stage,**fields);save(d/'phase.json',phase)
    header={'Content-Type':'application/json','Accept':'application/json, text/event-stream'};header.update(spec.get('headers') or {})
    req=urllib.request.Request(spec['url'],json.dumps(spec['body'],ensure_ascii=False).encode(),headers=header)
    mark('opening',sent='possibly_sent')
    try:response=urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req,timeout=spec['budget'])
    except urllib.error.HTTPError as e:response=e
    with response:
        headers=dict(response.headers);mark('headers_received',status=response.status,headers=headers)
        stream='text/event-stream' in response.headers.get('Content-Type','');chunks=[];data=[];total=0
        with (d/'partial.bin').open('wb') as partial:
            while True:
                # read1 returns available chunk bytes rather than waiting for EOF.
                chunk=response.read1(4096) if hasattr(response,'read1') else response.read(1)
                if not chunk:
                    body=b''.join(chunks).decode('utf-8');value=json.loads(body) if body else {};break
                total+=len(chunk)
                if total>32*2**20:raise ValueError('bounded response exceeds32MiB')
                partial.write(chunk);partial.flush();chunks.append(chunk)
                raw=b''.join(chunks)
                if stream:
                    # Complete SSE records are usable without stream EOF; keep
                    # notifications separate and require this JSON-RPC id.
                    while b'\n\n' in raw.replace(b'\r\n',b'\n'):
                        normalized=raw.replace(b'\r\n',b'\n');event,raw=normalized.split(b'\n\n',1);chunks=[raw]
                        payload=b'\n'.join(x[5:].lstrip(b' ') for x in event.split(b'\n') if x.startswith(b'data:'))
                        if not payload:continue
                        candidate=json.loads(payload)
                        if candidate.get('id')==spec['body'].get('id') and ('result' in candidate or 'error' in candidate):
                            value=candidate;mark('parsed',bytes_received=total);save(d/'response.json',{'value':value,'headers':headers});return
                else:
                    # Content-Length/EOF determines completion for plain JSON.
                    length=response.headers.get('Content-Length')
                    if length is not None and total>=int(length):value=json.loads(raw);break
        mark('parsed',bytes_received=total);save(d/'response.json',{'value':value,'headers':headers})

def post(client,body,headers=None,timeout=120):
    start=time.monotonic();deadline=min(start+timeout,getattr(client,'_absolute_deadline',float('inf')));budget=deadline-start
    if budget<=0:raise TransportUnknown('absolute deadline before client start',{'sent':'not_sent'})
    base=Path(client.transport_evidence);base.mkdir(parents=True,exist_ok=True);directory=base/str(uuid.uuid4());directory.mkdir()
    spec={'url':client.url,'body':body,'headers':headers,'budget':budget,'request_id':directory.name,'start_monotonic':start,'deadline_monotonic':deadline};save(directory/'request.json',spec)
    child=None;state={'status':'UNKNOWN','request_id':directory.name,'budget':budget,'sent':'not_sent','local_writer_ended':False}
    original=None
    try:
        child=subprocess.Popen([sys.executable,'-B',str(Path(__file__).resolve()),'--child',str(directory)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        state['client_pid']=child.pid;reserve=min(.1,budget/3)
        stdout,stderr=child.communicate(json.dumps(spec).encode(),timeout=max(.001,deadline-time.monotonic()-reserve))
        state.update(returncode=child.returncode,stdout=stdout.decode(errors='replace'),stderr=stderr.decode(errors='replace'))
        if child.returncode:raise TransportUnknown('transport child failed; remote result unknown',state)
        r=json.loads((directory/'response.json').read_text())
        if time.monotonic()>=deadline:raise TransportUnknown('parsing exhausted original deadline',state)
        state['status']='COMPLETED';return r['value'],r['headers']
    except BaseException as e:
        original=e;state.update(error=repr(e),exception_type=type(e).__name__)
        if isinstance(e,KeyboardInterrupt):raise
        raise TransportUnknown('absolute transport result unknown; do not resend',state) from e
    finally:
        if child is not None and child.poll() is None:
            child.kill() # only this disposable host transport, never a guest process
            try:child.wait(timeout=max(.001,deadline-time.monotonic()))
            except subprocess.TimeoutExpired:state['cleanup_unknown']='local client did not join by original deadline'
        if child is not None:
            for pipe in [child.stdin,child.stdout,child.stderr]:
                if pipe:pipe.close()
            state['local_writer_ended']=child.poll() is not None
        phase=directory/'phase.json'
        if phase.exists():state['partial_phase']=json.loads(phase.read_text());state['sent']=state['partial_phase']['sent']
        state.update(elapsed=time.monotonic()-start,finished_monotonic=time.monotonic(),deadline=deadline)
        save(directory/'completion.json',state)

def install(client,evidence):
    client.transport_evidence=Path(evidence)
    client._post=lambda body,headers=None,timeout=120:post(client,body,headers,timeout)
    # A VM call has initialize/notification/call boundaries; all share one
    # original deadline, rather than reopening a budget at every request.
    name='powershell' if hasattr(client,'powershell') else 'tool_outcome'
    original=getattr(client,name)
    def bounded(*args,**kwargs):
        budget=kwargs.get('timeout',args[1] if name=='powershell' and len(args)>1 else args[2] if len(args)>2 else 120)
        previous=getattr(client,'_absolute_deadline',float('inf'));client._absolute_deadline=min(previous,time.monotonic()+budget)
        try:return original(*args,**kwargs)
        finally:client._absolute_deadline=previous
    setattr(client,name,bounded);return client

def guarded(execute,cleanup,persist,state):
    """Preserve business exception and entered stage even if finally also fails."""
    state.update(status='FAILED',business_entered=bool(state.get('business_entered')));persist(state)
    try:execute();state['status']='COMPLETED'
    except BaseException as e:
        import traceback
        state.update(status='FAILED',reason=repr(e),exception_type=type(e).__name__,traceback=traceback.format_exc())
    finally:
        try:cleanup()
        except BaseException as e:state.update(closure_error=repr(e),closure_exception_type=type(e).__name__,status='FAILED')
        persist(state)
    return state
if __name__=='__main__':
    spec=json.loads(sys.stdin.buffer.read());_child(spec,sys.argv[2])
