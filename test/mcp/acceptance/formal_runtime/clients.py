"""Fresh original MCP sessions inside the unchanged total transport deadline."""
from __future__ import annotations

import math
from pathlib import Path
import threading
import time
import uuid

import bounded_mcp as bounded
import scenario_suite as suite
from .command_transport import write_new_json
from .context import exact_path, read_json
from .instance import MUTATIONS


class FreshClient:
    def __init__(self, client, context, responsibility):
        self.context = context.revalidate()
        if not isinstance(client,suite.RawMcp):
            raise TypeError('fresh sessions require an original RawMcp/VmMcp client')
        self.url, self.controller_id = client.url, client.controller_id
        self.vm = isinstance(client,suite.VmMcp)
        self.state = responsibility
        self.root = context.evidence_root/'transport'/('vm' if self.vm else 'service')
        self._absolute_deadline = float('inf')
        self._lock = threading.Lock()
        self.calls = {}
        self.audit_failures = {}
        self.audit_safe = True

    def _invoke(self, method, values, timeout):
        start=time.monotonic()
        if type(timeout) not in (int,float) or not math.isfinite(timeout) or timeout<=0:
            raise ValueError('original timeout must be positive and finite')
        cap = 30 if not self.vm and values[0]=='get_status' else 480 if not self.vm and values[0] in MUTATIONS else timeout
        budget=min(timeout,cap)
        self.context.revalidate()
        if self._absolute_deadline<=time.monotonic():
            raise bounded.TransportUnknown('original absolute deadline before fresh client start',{'sent':'not_sent','local_writer_ended':True})
        with self._lock:
            if not self.audit_safe and (self.vm or values[0] in MUTATIONS):
                raise RuntimeError('unresolved fresh-client audit/host writer; no further mutation/staging')
        nonce=uuid.uuid4().hex
        directory=exact_path(str(self.root/nonce))
        directory.mkdir(parents=True,exist_ok=False)
        # The bounded window starts only after preparation (revalidation and
        # evidence writes); on slow hosts the preparation must not consume
        # the per-call budget, while the outer absolute deadline still caps.
        deadline=min(time.monotonic()+budget,self._absolute_deadline)
        if deadline<=time.monotonic():
            try: directory.rmdir()
            except OSError: pass
            raise bounded.TransportUnknown('original absolute deadline before fresh client start',{'sent':'not_sent','local_writer_ended':True})
        call={'call_id':nonce,'kind':'vm' if self.vm else 'service','method':method,
              'url':self.url,'controller_id':self.controller_id,'timeout_requested':timeout,
              'effective_budget':budget,'deadline':deadline,'materials_sha256':self.context.materials_sha256,
              'response_known':False,'original_error':None,'host_writers_ended':False}
        write_new_json(directory/'call-intent.json',call)
        with self._lock: self.calls[nonce]={'directory':directory,'record':call}
        outcome,failure=None,None
        try:
            client = suite.VmMcp(self.url,controller_id=self.controller_id) if self.vm else suite.RawMcp(self.url,controller_id=self.controller_id)
            client._absolute_deadline=deadline
            bounded.install(client,directory)
            outcome=getattr(client,method)(*values,timeout=budget)
            call['response_known']=True
            return outcome
        except BaseException as error:
            failure=error
            call['original_error']=repr(error)
            raise
        finally:
            secondary=None
            try:
                transport_dirs=sorted(path for path in directory.iterdir() if path.is_dir())
                completions=[]
                for transport_dir in transport_dirs:
                    request=exact_path(str(transport_dir/'request.json'))
                    path=exact_path(str(request.with_name('completion.json')))
                    if not path.is_file():
                        completions.append({'request':str(request),'local_writer_ended':False,'completion_missing':True})
                    else:
                        value=read_json(path)
                        completions.append({'request':str(request),'completion':str(path),
                            'status':value.get('status'),'local_writer_ended':value.get('local_writer_ended') is True,
                            'client_pid':value.get('client_pid'),'sent':value.get('sent')})
                call['transport_completions']=completions
                call['host_writers_ended']=all(row['local_writer_ended'] for row in completions)
                call['bounded_transport_directories']=len(transport_dirs)
                call['finished_monotonic']=time.monotonic()
                if not call['host_writers_ended']:
                    secondary=RuntimeError('original transport host writer completion unproven')
                write_new_json(directory/'call-terminal.json',call)
            except BaseException as error:
                secondary=error
            if secondary is not None:
                with self._lock:
                    self.audit_safe=False
                    self.audit_failures[nonce]={'error':repr(secondary),'record':dict(call),
                                               'known_original_outcome':outcome,'not_remote_response_unknown':outcome is not None}
                self.state.unknown(secondary)
                if failure is not None: failure.add_note('independent fresh-client closure/audit failure: '+repr(secondary))
                # A received original response remains received. Ownership
                # wrappers can retain its exact changed/SHA response while
                # general responsibility blocks the next mutable operation.

    def powershell(self, command, timeout=120):
        if not self.vm: raise TypeError('service fresh client cannot dispatch a VM command')
        return self._invoke('powershell',(command,),timeout)

    def tool_outcome(self,name,args=None,timeout=120):
        if self.vm: raise TypeError('VM fresh client cannot dispatch a product tool')
        return self._invoke('tool_outcome',(name,args or {}),timeout)

    def tool(self,name,args=None,timeout=120):
        outcome=self.tool_outcome(name,args,timeout)
        if not outcome['ok']: raise suite.SuiteError(str(outcome['error']))
        return outcome['value']

    def responsibility(self):
        with self._lock:
            rows=[dict(row['record']) for row in self.calls.values()]
            return {'audit_safe':self.audit_safe,'calls':rows,'audit_failures':dict(self.audit_failures),
                    'host_writers_ended':all(row.get('host_writers_ended') is True for row in rows),
                    'no_mutation_replay':True}
