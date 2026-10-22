"""Direct adapter to the already deployed REMnux SDK, no new SSH transport."""
from __future__ import annotations
import importlib
import json
from pathlib import Path, PurePosixPath
import sys
import uuid
import time
import hashlib


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

    def start_guest(self,request_path,request_sha,*,entry='tools/acceptance_guest.py',action=None,entry_sha=None):
        if entry not in ('tools/acceptance_guest.py','tools/acceptance_multihost.py'):
            raise RemnuxChannelError('guest entry not registered')
        argv=[self.runtime['python'],'-B',str(Path(self.runtime['source_root'])/entry),'--request',request_path,'--request-sha256',request_sha]
        if entry=='tools/acceptance_multihost.py':
            if action not in ('serve','probes'):raise RemnuxChannelError('MultiHost start requires serve/probes action')
            argv+=['--action',action]
        elif action is not None:raise RemnuxChannelError('action applies only to MultiHost')
        if entry_sha is not None:argv=self.pinned_argv(entry,entry_sha,argv[3:])
        return self.call_once('execute','remnux_process_start',{'argv':argv,'cwd':'work',
            'timeout_s':300,'execution_identity':'root_explicit',
            'reason':'owned benign FakeNet functional regression; original driver retains network recovery'})

    def observe_job(self,job_id):
        return self.call_once('observe-'+uuid.uuid4().hex,'remnux_process_query',{'job_id':job_id})


    def multihost_control(self,request_path,request_sha,action,*,entry_sha=None):
        if action not in ('observe','stop'):
            raise RemnuxChannelError('MultiHost control action is not registered')
        argv=[self.runtime['python'],'-B',str(Path(self.runtime['source_root'])/'tools/acceptance_multihost.py'),
              '--request',request_path,'--request-sha256',request_sha,'--action',action]
        if entry_sha is not None:argv=self.pinned_argv('tools/acceptance_multihost.py',entry_sha,argv[3:])
        return self.call_once(action+'-'+uuid.uuid4().hex,'remnux_command',{'argv':argv,'cwd':'work',
            'timeout_s':30,'execution_identity':'root_explicit',
            'reason':'observe/stop only the pinned benign MultiHost test core'})


    def stage_multihost(self,experiment_id,files):
        # No remote directory scan or guessed source. The original SDK creates
        # each published path and verifies its transfer; first error ends stage.
        import hashlib
        if not experiment_id or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_' for c in experiment_id):
            raise RemnuxChannelError('invalid owned MultiHost stage ID')
        names=[row['relative_path'] for row in files]
        if not names or len(names)!=len(set(names)):
            raise RemnuxChannelError('empty/duplicate MultiHost stage list')
        for row in files:
            relative=Path(row['relative_path']);local=Path(row['local'])
            if (relative.is_absolute() or '..' in relative.parts or local.is_symlink() or not local.is_file() or
                local.stat().st_size!=row['size'] or hashlib.sha256(local.read_bytes()).hexdigest()!=row['sha256']):
                raise RemnuxChannelError('MultiHost staged source identity changed')
        result=[]
        for index,row in enumerate(files):
            result.append(self.put('stage-%03d'%index,row['local'],'published/'+experiment_id+'/'+row['relative_path']))
        return result

    def relative(self,path):
        root=PurePosixPath(self.runtime['workspace_root']);absolute=PurePosixPath(path)
        rel=absolute.relative_to(root)
        if '..' in rel.parts or not rel.parts or rel.parts[0] not in ('work','published'):
            raise RemnuxChannelError('path outside bound existing workspace')
        return str(rel)

    def pinned_argv(self,entry,entry_sha,args):
        if entry not in ('tools/acceptance_guest.py','tools/acceptance_multihost.py') or len(entry_sha)!=64:
            raise RemnuxChannelError('invalid pinned target entry')
        path=str(PurePosixPath(self.runtime['source_root'])/entry)
        script=("import hashlib,runpy,sys; p=sys.argv[1]; "
                "assert hashlib.sha256(open(p,'rb').read()).hexdigest()==sys.argv[2], 'entry changed'; "
                "sys.argv=[p]+sys.argv[3:]; runpy.run_path(p,run_name='__main__')")
        # runpy requires the script directory for its fixed sibling imports.
        script=script.replace("sys.argv=[p]", "sys.path.insert(0,__import__('os').path.dirname(p)); sys.argv=[p]")
        return [self.runtime['python'],'-B','-c',script,path,entry_sha]+list(args)

    @staticmethod
    def command_json(result):
        data=result.get('data') or {}
        if (data.get('exit_code')!=0 or data.get('timed_out') is not False or
            data.get('stdout_truncated') is not False or data.get('stderr_truncated') is not False or
            data.get('process',{}).get('state')!='exited'):
            raise RemnuxChannelError('original remote command failed/truncated/not exited')
        return json.loads(data['stdout'])

    def identity(self,source_hashes):
        # Health authenticates VM UUID; cwd observes the actual existing
        # workspace, while the trusted interpreter checks both target entries.
        expected={str(PurePosixPath(self.runtime['source_root'])/k):v for k,v in source_hashes.items()
                  if k in ('tools/acceptance_guest.py','tools/acceptance_multihost.py')}
        if len(expected)!=2:raise RemnuxChannelError('target entry pins missing')
        script=("import hashlib,json,pathlib,platform; expected="+repr(expected)+"; "
                "assert all(hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()==h for p,h in expected.items()), 'entry changed'; "
                "print(json.dumps({'platform':platform.system().lower(),'hostname':platform.node(),"
                "'workspace_root':str(pathlib.Path.cwd().parent)}))")
        result=self.call_once('identity','remnux_command',{'argv':[self.runtime['python'],'-B','-c',script],
            'cwd':'work','timeout_s':30,'execution_identity':'root_explicit',
            'reason':'read selected VM/workspace and verify fixed regression entries'})
        value=self.command_json(result)
        if value.pop('workspace_root',None)!=self.runtime['workspace_root'] or value!=self.runtime['identity']:
            raise RemnuxChannelError('observed VM/workspace differs from bound target')
        return value

    @staticmethod
    def process(result,job_id):
        values=(result.get('data') or {}).get('processes')
        if not isinstance(values,list) or len(values)!=1 or values[0].get('job_id')!=job_id:
            raise RemnuxChannelError('original process query does not match owned job')
        return values[0]

    def wait_exited(self,birth,timeout):
        if not isinstance(birth,dict) or not birth.get('job_id') or not birth.get('pid'):
            raise RemnuxChannelError('original process birth missing')
        end=time.monotonic()+timeout
        while True:
            found=self.process(self.observe_job(birth['job_id']),birth['job_id'])
            if any(found.get(k)!=birth.get(k) for k in ('pid','starttime','unit','cgroup','image')):
                raise RemnuxChannelError('owned producer birth identity changed')
            if found.get('state')=='exited':return found
            if found.get('state') in ('unknown','stopped') or time.monotonic()>=end:
                raise RemnuxChannelError('recovery_required: producer exit unknown; no collect or replay')
            time.sleep(.5)
