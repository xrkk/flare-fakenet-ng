"""Direct adapter to the already deployed REMnux SDK, no new SSH transport."""
from __future__ import annotations
import importlib
import json
from pathlib import Path
import sys
import uuid


def save_new(path,value):
    with Path(path).open('x',encoding='utf-8') as out:json.dump(value,out,indent=2)


class RemnuxChannelError(RuntimeError):pass


class ExistingRemnuxChannel:
    def __init__(self,runtime,journal,*,sdk=None):
        self.runtime=runtime;self.journal=Path(journal);self.journal.mkdir(parents=True,exist_ok=True)
        if sdk is None:
            sys.path.insert(0,runtime['module_root'])
            sdk=importlib.import_module('remnux_control.client')
        self.sdk=sdk
        self.config=self.sdk.load_connection(runtime['connection_ref'])
        self.epoch=None

    def health(self):
        result=self.sdk.call(self.config,'remnux_health',{})
        save_new(self.journal/'health.json',result)
        guest=result.get('guest_response') or {};assessment=result.get('host_assessment') or {}
        if (result.get('transport_error') is not None or assessment.get('current_gate')!='OPEN' or
            assessment.get('guest_matches_current') is not True or guest.get('ok') is not True or
            guest.get('vm_uuid')!=self.runtime['expected_vm_uuid']):
            raise RemnuxChannelError('existing REMnux target/gate/epoch not ready')
        self.epoch=guest['request_epoch'];return result

    def call_once(self,name,tool,arguments):
        if self.epoch is None:raise RemnuxChannelError('read current Host health first')
        if tool not in ('remnux_command','remnux_process_start','remnux_process_query','remnux_process_stop'):
            raise RemnuxChannelError('unregistered native channel tool')
        arguments=dict(arguments)
        if tool!='remnux_process_query':
            arguments.update(request_epoch=self.epoch,request_id=str(uuid.uuid4()))
        arguments['workspace_id']=self.runtime['workspace_id']
        save_new(self.journal/(name+'-intent.json'),{'tool':tool,'arguments':arguments})
        try:result=self.sdk.call(self.config,tool,arguments)
        except BaseException as error:
            save_new(self.journal/(name+'-unknown.json'),{'error_type':type(error).__name__,'replay':False})
            raise RemnuxChannelError('REMnux outcome unknown; preserve original request ID') from None
        save_new(self.journal/(name+'-response.json'),result)
        if result.get('ok') is not True or result.get('vm_uuid')!=self.runtime['expected_vm_uuid'] or (result.get('request_epoch') not in (None,self.epoch) if tool=='remnux_process_query' else result.get('request_epoch')!=self.epoch):
            raise RemnuxChannelError('REMnux original response rejected or identity drifted')
        return result

    def put(self,name,local,remote):
        if self.epoch is None:raise RemnuxChannelError('read current Host health first')
        save_new(self.journal/(name+'-intent.json'),{'action':'existing SDK put_file','local':str(local),'remote':remote})
        try:result=self.sdk.put_file(self.config,self.runtime['workspace_id'],str(local),remote)
        except BaseException as error:
            save_new(self.journal/(name+'-unknown.json'),{'error_type':type(error).__name__,'replay':False})
            raise RemnuxChannelError('REMnux upload unknown; original SDK journal retained') from None
        save_new(self.journal/(name+'-response.json'),result)
        if result.get('complete') is not True:raise RemnuxChannelError('REMnux upload incomplete')
        return result

    def get(self,name,remote,output):
        if self.epoch is None:raise RemnuxChannelError('read current Host health first')
        output=Path(output)
        if output.exists():raise RemnuxChannelError('new download output already exists')
        save_new(self.journal/(name+'-intent.json'),{'action':'existing SDK get_file','remote':remote,'output':str(output)})
        try:result=self.sdk.get_file(self.config,self.runtime['workspace_id'],remote,str(output))
        except BaseException as error:
            save_new(self.journal/(name+'-unknown.json'),{'error_type':type(error).__name__,'replay':False})
            raise RemnuxChannelError('REMnux download unknown; original SDK journal retained') from None
        save_new(self.journal/(name+'-response.json'),result)
        import hashlib
        if not output.is_file() or result.get('complete') is not True or hashlib.sha256(output.read_bytes()).hexdigest()!=result.get('sha256'):
            raise RemnuxChannelError('REMnux downloaded bytes differ from SDK result')
        return result

    def start_guest(self,request_path,request_sha,*,entry='tools/acceptance_guest.py',action=None):
        if entry not in ('tools/acceptance_guest.py','tools/acceptance_multihost.py'):
            raise RemnuxChannelError('guest entry not registered')
        argv=[self.runtime['python'],'-B',str(Path(self.runtime['source_root'])/entry),'--request',request_path,'--request-sha256',request_sha]
        if entry=='tools/acceptance_multihost.py':
            if action!='serve':raise RemnuxChannelError('MultiHost start requires serve action')
            argv+=['--action','serve']
        elif action is not None:raise RemnuxChannelError('action applies only to MultiHost')
        return self.call_once('execute','remnux_process_start',{'argv':argv,'cwd':'work',
            'timeout_s':300,'execution_identity':'root_explicit',
            'reason':'owned benign FakeNet functional regression; original driver retains network recovery'})

    def observe_job(self,job_id):
        return self.call_once('observe-'+uuid.uuid4().hex,'remnux_process_query',{'job_id':job_id})


    def multihost_control(self,request_path,request_sha,action):
        if action not in ('observe','stop'):
            raise RemnuxChannelError('MultiHost control action is not registered')
        argv=[self.runtime['python'],'-B',str(Path(self.runtime['source_root'])/'tools/acceptance_multihost.py'),
              '--request',request_path,'--request-sha256',request_sha,'--action',action]
        return self.call_once(action+'-'+uuid.uuid4().hex,'remnux_command',{'argv':argv,'cwd':'work',
            'timeout_s':30,'execution_identity':'root_explicit',
            'reason':'observe/stop only the pinned benign MultiHost test core'})
