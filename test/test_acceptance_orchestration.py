"""Safe SDK/process substitutes; original byte oracles remain real."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1] if Path(__file__).parent.name=='test' else Path('/home/adminn/projects/flare-fakenet-ng')
sys.path.insert(0,str(ROOT/'tools'));sys.path.insert(0,str(ROOT/'test'))
import acceptance_native as native
import acceptance_orchestration as orchestration
import acceptance_linux as linux
import acceptance_collection as collection
import acceptance_multihost as multi
import test_acceptance_native_oracles as existing


def write(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value))


def runtime(role):
    return {'transport':'remnux-sdk','connection_ref':'/existing/'+role+'.json','module_root':'/existing/sdk',
            'workspace_id':'owned-'+role,'workspace_root':'/workspace/'+role,'expected_vm_uuid':role,
            'python':'/candidate/venv/bin/python','source_root':'/candidate','work_root':'/workspace/'+role+'/work/regression',
            'identity':{'platform':'linux','hostname':role}}


class SdkFixture:
    """Simulate only existing SDK boundary, not collection/content validators."""
    def __init__(self,outer,settings=None):
        self.outer=outer;self.settings=settings or {};self.files={};self.jobs={};self.requests={};self.events=[];self.serial=0;self.observations={}
    def load_connection(self,path):return {'role':Path(path).stem}
    def health(self,role):return {'guest_response':{'ok':True,'vm_uuid':role,'request_epoch':7},'host_assessment':{'current_gate':'OPEN','guest_matches_current':True},'transport_error':None}
    def call(self,config,tool,args):
        role=config['role'];self.events.append((role,tool))
        if tool=='remnux_health':return self.health(role)
        result={'ok':True,'vm_uuid':role,'request_epoch':args.get('request_epoch'),'data':{}}
        if tool=='remnux_command':
            argv=args['argv']
            if 'platform.node()' in argv[3]:
                value=dict(runtime(role)['identity'],workspace_root=runtime(role)['workspace_root'])
                if self.settings.get('wrong_identity'):value['hostname']='other'
            else:
                path=argv[argv.index('--request')+1];request=self.request(role,path);experiment=request['experiment_id']
                action=argv[argv.index('--action')+1]
                if action=='observe':
                    self.observations[experiment]=self.observations.get(experiment,0)+1
                    if self.settings.get('not_ready'):raise RuntimeError('UNKNOWN before observation')
                    value=self.observation(request)
                    if self.settings.get('dead_after') and self.observations[experiment]>1:raise RuntimeError('owned server exited')
                else:
                    self.events.append((role,'owned-stop'))
                    for job in self.jobs.values():
                        if job['role']==role and job.get('experiment')==experiment:job['stopped']=True
                    value={'stop_requested':True,'owner':self.observation(request)['owner']}
            result['data']={'process':{'state':'exited'},'exit_code':0,'timed_out':False,'stdout_truncated':False,'stderr_truncated':False,'stdout':json.dumps(value)}
        elif tool=='remnux_process_start':
            if self.settings.get('unknown_start'):raise RuntimeError('UNKNOWN start')
            argv=args['argv'];self.outer.assertIn('entry changed',argv[3])
            path=argv[argv.index('--request')+1];request=self.request(role,path)
            job={'role':role,'request':request,'job_id':args['request_id'],'pid':100+len(self.jobs),'starttime':123,'unit':'owned-'+args['request_id'],'cgroup':'/owned','image':'/candidate/venv/bin/python','state':'live','stopped':False}
            if request.get('experiment_id'):job['experiment']=request['experiment_id']
            if argv[-1]!='serve':job['stopped']=True
            self.jobs[job['job_id']]=job;result['data']={k:job[k] for k in ('job_id','pid','starttime','unit','cgroup','image','state')}
        elif tool=='remnux_process_query':
            job=self.jobs[args['job_id']]
            state='exited' if job['stopped'] else 'active'
            if self.settings.get('unknown_exit') and job['stopped']:state='unknown'
            found={k:job[k] for k in ('job_id','pid','starttime','unit','cgroup','image')};found['state']=state
            result['data']={'processes':[found]}
            if state=='exited' and not job.get('published'):
                self.publish(role,job['request']);job['published']=True
        else:raise AssertionError('unregistered SDK operation '+tool)
        return result
    def request(self,role,path):
        relative=str(PurePosixPath(path).relative_to(runtime(role)['workspace_root']))
        return json.loads(self.files[(role,relative)])
    def put_file(self,config,workspace,local,remote):
        self.files[(config['role'],remote)]=Path(local).read_bytes();return {'complete':True}
    def get_file(self,config,workspace,remote,output):
        self.events.append((config['role'],'download'))
        payload=self.files[(config['role'],remote)];Path(output).write_bytes(payload)
        return {'complete':True,'sha256':hashlib.sha256(payload).hexdigest()}
    def observation(self,request):
        return {'schema':'fakenet.multihost-observation.v1','owner':{'schema':'fakenet.multihost-owner.v1',
            'experiment_id':request['experiment_id'],'target':runtime('server')['identity'],'owner_pid':10,'owner_birth':'11',
            'core_pid':20,'core_birth':'22','config_sha256':request['config_sha256'],'source_hashes':request['source_hashes']},
            'config_sha256':request['config_sha256'],'core_log_sha256':'a'*64,'observed_at':time.time(),'core_ready':True}
    def publish(self,role,request):
        directory=self.outer.root/('sdk-output-%03d'%self.serial);self.serial+=1;directory.mkdir()
        remote=request['output_root']
        if request['schema']=='fakenet.native-guest-request.v1':
            child=directory/'driver/normal';child.mkdir(parents=True);existing.make_pair(child)
            (child/'fakenet.log').write_text('PCAP_DUAL_SUMMARY healthy=True')
            for name in ('network-before.json','network-after.json'):write(child/name,{})
            write(child/'case-evidence.json',{'ready':True,'forced':False,'returncode':0,'process_exited':True,'network_differences':[],'resource_residue':[],'case_error':None,'snapshot_error':None})
            write(directory/'driver/summary.json',{'results':[{'name':n,'status':'PASS'} for n in ('Environment','Dependencies','Live-normal')]})
            for name in ('stdout.log','stderr.log'):(directory/name).write_text('original guest execution')
            write(directory/'request.json',{});write(directory/'target.json',request['target'])
            artifacts=[{'path':str(PurePosixPath(remote)/p.relative_to(directory).as_posix()),'sha256':collection.digest(p),'format':'original'} for p in directory.rglob('*') if p.is_file()]
            driver=native.driver_table(self.outer.root)['pcap-linux-functional']
            receipt={'status':'pass','returncode':0,'command':native.remote_guest_command(driver,runtime(role),remote,['normal']),
                     'required_checks':['normal'],'native_target':request['target'],'artifacts':artifacts,
                     'cleanup':{'source':'driver','resources':driver['resources'],'recovered':True,'process_exit':{'exited':True,'timed_out':False,'returncode':0}}}
            write(directory/'guest-result.json',{'schema':'fakenet.native-guest-result.v1','execution_id':request['execution_id'],'case_id':request['case_id'],'request':request,'receipt':receipt})
        else:
            for name in ('network-before.json','network-after.json'):write(directory/name,{})
            if role=='server':
                owner=self.observation(request)['owner'];core={'ready':True,'stopped':True,'forced':False,'returncode':0}
                (directory/'core.log').write_text('FakeNet-NG started successfully');(directory/'core-console.log').write_text('owned console')
                write(directory/'core-lifecycle.json',core)
                write(directory/'server-result.json',{'owner':owner,'core':core,'cleanup_complete':not self.settings.get('bad_recovery'),'network_restored':True,'error':None})
            else:
                for name in ('probe-stdout.log','probe-stderr.log'):(directory/name).write_text('original callback output')
                rows=[{'id':x,'status':'pass'} for x in request['checks']]
                if self.settings.get('probe_fail'):rows[0]['status']='fail'
                write(directory/'probes.json',{'schema':'fakenet.multihost-probes.v1','experiment_id':request['experiment_id'],'client_target':request['target'],
                    'server_observation':request['server_observation'],'checks':rows,'cleanup_complete':True,'error':None,
                    'topology':{'gateway':request['server_ipv4'],'dns_servers':[request['server_ipv4']]}})
        # Closed fixture index and guest receipt are original test bytes; Host
        # still exercises the real SDK adapter, collector and content oracle.
        value=collection.write_index(directory,'0'*64);value['output_root']=remote
        request_relative=next(key for (r,key),payload in self.files.items() if r==role and key.endswith('.json') and json.loads(payload)==request)
        value['request_sha256']=hashlib.sha256(self.files[(role,request_relative)]).hexdigest()
        write(directory/'export-index.json',value)
        base=str(PurePosixPath(remote).relative_to(runtime(role)['workspace_root']))
        for path in directory.rglob('*'):
            if path.is_file():self.files[(role,base+'/'+path.relative_to(directory).as_posix())]=path.read_bytes()


class LinuxAndMultiHostTests(unittest.TestCase):
    setUp=existing.ProductionEntryTests.setUp
    cli=existing.ProductionEntryTests.cli
    plan=existing.ProductionEntryTests.plan
    def prepare(self,multihost=False):
        (self.root/'tools').mkdir(exist_ok=True)
        for name in ('acceptance_guest.py','acceptance_multihost.py'):
            shutil.copyfile(ROOT/'tools'/name,self.root/'tools'/name)
        self.environment['allowed_actions']+=['vm-execute','vm-transfer']
        if multihost:
            self.environment['allowed_actions'].append('multihost')
            self.runtime={'transport':'remnux-multihost','server':runtime('server'),'client':runtime('client'),'server_ipv4':'192.0.2.10'}
            self.case.update(native_driver='upstream-multihost',input={},modes=['multihost'])
            for name in ('template.ini','custom_responses.ini','CustomProviderExample.py','sample_raw_response.txt','sample_raw_tcp_response.txt'):
                shutil.copyfile(ROOT/'test'/name,self.root/'test'/name)
            candidate=json.loads((self.root/'candidate.json').read_text());candidate['deployed_identity']={x:self.runtime[x]['identity'] for x in ('server','client')}
        else:
            self.runtime=runtime('client');self.identity=self.runtime['identity']
            candidate=json.loads((self.root/'candidate.json').read_text());candidate['deployed_identity']=self.identity
        self.environment['native_runtime']=self.runtime
        write(self.root/'candidate.json',candidate);write(self.root/'environment.json',self.environment)
        catalog=json.loads(self.catalog_path.read_text());catalog['suites'][1]['cases'][0]=self.case;write(self.catalog_path,catalog)
    def execute_sdk(self,path,settings=None):
        sdk=SdkFixture(self,settings)
        def channel(runtime,journal):return linux.ExistingRemnuxChannel(runtime,journal,sdk=sdk)
        with mock.patch.object(orchestration,'ExistingRemnuxChannel',side_effect=channel):
            code,out,err=self.cli('execute','--plan',path)
        return sdk,code,out+err
    def test_linux_catalog_execute_collect_and_independent_original_pcap_judge(self):
        self.prepare();path=self.plan();sdk,code,output=self.execute_sdk(path)
        self.assertEqual(0,code,output)
        self.assertEqual(0,self.cli('judge','--plan',path,'--results',path.parent/'results')[0])
        self.assertTrue(any(action=='download' for role,action in sdk.events))
        self.assertFalse(json.loads((path.parent/'summary.json').read_text())['full_functional_pass'])
    def test_wrong_identity_cannot_upload_or_start(self):
        self.prepare();path=self.plan();sdk,code,output=self.execute_sdk(path,{'wrong_identity':True})
        self.assertEqual(2,code,output);self.assertFalse(sdk.jobs);self.assertFalse(sdk.files)
    def test_unknown_linux_producer_is_not_collected_or_replayed(self):
        self.prepare();path=self.plan();sdk,code,output=self.execute_sdk(path,{'unknown_exit':True})
        self.assertEqual(2,code,output);self.assertEqual(1,len(sdk.jobs));self.assertNotIn(('client','download'),sdk.events)
    def test_multihost_full_original_configs_and_finally_stop(self):
        self.prepare(True);path=self.plan();sdk,code,output=self.execute_sdk(path)
        self.assertEqual(0,code,output)
        self.assertEqual(0,self.cli('judge','--plan',path,'--results',path.parent/'results')[0])
        self.assertEqual(2,sdk.events.count(('server','owned-stop')))
        value=json.loads((path.parent/'results/FIX-BLOCKED/orchestration.json').read_text())
        self.assertEqual(list(dict.fromkeys(x.split('::')[0] for x in json.loads(path.read_text())['required_checks']['FIX-BLOCKED'])),[row['suite'] for row in value['records']])
    def test_multihost_dead_after_probe_fails_and_still_stops(self):
        self.prepare(True);path=self.plan();sdk,code,output=self.execute_sdk(path,{'dead_after':True})
        self.assertEqual(2,code,output);self.assertIn(('server','owned-stop'),sdk.events)
    def test_multihost_failed_original_callback_is_failure(self):
        self.prepare(True);path=self.plan();sdk,code,output=self.execute_sdk(path,{'probe_fail':True})
        self.assertEqual(1,code,output);self.assertEqual(1,sdk.events.count(('server','owned-stop')))
    def test_multihost_bad_recovery_prevents_another_configuration(self):
        self.prepare(True);path=self.plan();sdk,code,output=self.execute_sdk(path,{'bad_recovery':True})
        self.assertEqual(2,code,output);self.assertEqual(1,sdk.events.count(('server','owned-stop')))
    def test_unknown_server_start_is_never_replayed_or_generically_stopped(self):
        self.prepare(True);path=self.plan();sdk,code,output=self.execute_sdk(path,{'unknown_start':True})
        self.assertEqual(2,code,output);self.assertNotIn(('server','owned-stop'),sdk.events)
        self.assertEqual(1,sdk.events.count(('server','remnux_process_start')))
    def test_source_change_prevents_channel_creation(self):
        self.prepare();path=self.plan();(self.root/'tools/acceptance_guest.py').write_text('changed')
        with mock.patch.object(orchestration,'ExistingRemnuxChannel') as channel:
            code,out,err=self.cli('execute','--plan',path)
        self.assertEqual(2,code,out+err);channel.assert_not_called()
    def test_duplicate_vm_cannot_be_admitted_as_multihost(self):
        self.prepare(True);self.runtime['client']=dict(self.runtime['server']);self.environment['native_runtime']=self.runtime;write(self.root/'environment.json',self.environment)
        path=self.plan()
        with mock.patch.object(orchestration,'ExistingRemnuxChannel') as channel:
            code,out,err=self.cli('execute','--plan',path)
        self.assertEqual(2,code,out+err);channel.assert_not_called()

    def test_posix_original_pcap_corruption_refused_even_after_artifact_rehash(self):
        self.prepare();path=self.plan();sdk,code,output=self.execute_sdk(path);self.assertEqual(0,code,output)
        directory=path.parent/'results/FIX-BLOCKED';original=directory/'incoming/originals'
        guest=json.loads((original/'guest-result.json').read_text());request=json.loads((directory/'guest-request.json').read_text())
        eth=next((original/'driver/normal').glob('*-converted.pcap'));data=bytearray(eth.read_bytes());data[-1]^=1;eth.write_bytes(data)
        relative=eth.relative_to(original).as_posix()
        next(x for x in guest['receipt']['artifacts'] if x['path']==request['output_root']+'/'+relative)['sha256']=collection.digest(eth)
        with self.assertRaises(AssertionError):native._remote_original_evaluation(self.root,self.case,json.loads(path.read_text()),request,guest,original)

    def test_primary_windows_client_uses_existing_channel_and_both_configs(self):
        import acceptance_windows as win
        self.prepare(True)
        client={'transport':'windows-mcp-velo','identity':{'platform':'windows','hostname':'windows-client'},
                'mcp_config_ref':'/existing/windows.toml','mcp_server':'VMMalBox','python':r'E:\python.exe',
                'source_root':r'E:\candidate','work_root':r'E:\regression',
                'transfer':{'expected_vm_identity':{'vm_uuid':'windows-client'}}}
        self.runtime['client']=client;write(self.root/'environment.json',self.environment)
        candidate=json.loads((self.root/'candidate.json').read_text());candidate['deployed_identity']['client']=client['identity'];write(self.root/'candidate.json',candidate)
        outer=self
        class Windows:
            def __init__(self,*args):self.runtime=client
            def identity(self):return client['identity']
            def multihost_probes(self,*args):return {'returncode':0,'process_exited':True}
            def transfer(self,name,direction,sources,destination,**kwargs):
                if direction=='push':
                    self.request_path=Path(sources[0]['absolute_path']);self.request=json.loads(self.request_path.read_text());return {}
                target=Path(destination)/'client';target.mkdir()
                for name in ('network-before.json','network-after.json'):write(target/name,{})
                for name in ('probe-stdout.log','probe-stderr.log'):(target/name).write_text('original callback output')
                r=self.request
                write(target/'probes.json',{'schema':'fakenet.multihost-probes.v1','experiment_id':r['experiment_id'],'client_target':r['target'],
                    'server_observation':r['server_observation'],'checks':[{'id':x,'status':'pass'} for x in r['checks']],
                    'cleanup_complete':True,'error':None,'topology':{'gateway':r['server_ipv4'],'dns_servers':[r['server_ipv4']]}})
                index=collection.write_index(target,collection.digest(self.request_path));index['output_root']=r['output_root'];write(target/'export-index.json',index)
                return {}
        path=self.plan()
        with mock.patch.object(win,'ExistingWindowsChannel',Windows):sdk,code,output=self.execute_sdk(path)
        self.assertEqual(0,code,output);self.assertEqual(2,sdk.events.count(('server','owned-stop')))
        self.assertEqual(0,self.cli('judge','--plan',path,'--results',path.parent/'results')[0])

    def test_remote_receipt_contradiction_and_missing_execution_originals_refused(self):
        self.prepare();path=self.plan();sdk,code,output=self.execute_sdk(path);self.assertEqual(0,code,output)
        directory=path.parent/'results/FIX-BLOCKED';original=directory/'incoming/originals'
        guest=json.loads((original/'guest-result.json').read_text());request=json.loads((directory/'guest-request.json').read_text());plan=json.loads(path.read_text())
        guest['receipt']['cleanup']['process_exit']['returncode']=999
        _,clean=native._remote_original_evaluation(self.root,self.case,plan,request,guest,original)
        self.assertFalse(clean)
        guest['receipt']['cleanup']['process_exit']['returncode']=0
        (original/'stderr.log').unlink()
        guest['receipt']['artifacts']=[r for r in guest['receipt']['artifacts'] if not r['path'].endswith('/stderr.log')]
        with self.assertRaisesRegex(ValueError,'execution originals missing'):
            native._remote_original_evaluation(self.root,self.case,plan,request,guest,original)


class CollectionTests(unittest.TestCase):
    def test_closed_index_rejects_escape_duplicate_or_changed_request(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'original').write_bytes(b'benign')
            value=collection.write_index(root,'a'*64)
            self.assertEqual(1,len(collection.validate_index(value,str(root),'a'*64)))
            for names in (['../escape'],['original','original']):
                value['files']=[dict(value['files'][0],relative_path=name) for name in names]
                with self.assertRaisesRegex(ValueError,'invalid/duplicate'):collection.validate_index(value,str(root),'a'*64)
            with self.assertRaisesRegex(ValueError,'request/root'):collection.validate_index(value,str(root),'b'*64)
    def test_original_server_guards_no_pending_boolean_as_stop_authority(self):
        with tempfile.TemporaryDirectory() as temp:
            request={'output_root':temp}
            with mock.patch.object(multi,'validate',return_value=Path(temp)),mock.patch.object(multi,'observe',return_value={'pending':True}):
                with self.assertRaisesRegex(ValueError,'ownership not observed'):multi.stop(request,temp)
            self.assertFalse((Path(temp)/'stop.flag').exists())


class ExportBoundaryTests(unittest.TestCase):
    def test_rejected_existing_output_is_not_exported_or_touched(self):
        import acceptance_guest as guest
        with tempfile.TemporaryDirectory() as temp:
            directory=Path(temp);output=directory/'existing';output.mkdir();(output/'keep').write_text('keep')
            request=directory/'request.json';write(request,{'output_root':str(output),'target':{'platform':'linux'}})
            with mock.patch.object(guest,'execute',side_effect=ValueError('rejected')):
                with self.assertRaisesRegex(ValueError,'rejected'):guest.main(['--request',str(request),'--request-sha256',collection.digest(request)])
            self.assertEqual(['keep'],[p.name for p in output.iterdir()])

    def test_unresolved_guest_producer_has_no_closed_export(self):
        import acceptance_guest as guest
        with tempfile.TemporaryDirectory() as temp:
            directory=Path(temp);output=directory/'new'
            request=directory/'request.json';write(request,{'output_root':str(output),'target':{'platform':'linux'}})
            def execute(*args):
                output.mkdir();write(output/'guest-result.json',{'receipt':{'cleanup':{'process_exit':{'exited':False}}}});return 2
            with mock.patch.object(guest,'execute',side_effect=execute):
                self.assertEqual(2,guest.main(['--request',str(request),'--request-sha256',collection.digest(request)]))
            self.assertFalse((output/'export-index.json').exists())

    def test_registered_catalog_and_multihost_selection_are_valid(self):
        import acceptance
        catalog=acceptance.read_catalog(ROOT)
        case=next(c for s in catalog['suites'] for c in s.get('cases',[]) if c['id']=='UPSTREAM-MULTIHOST')
        for platform in ('windows','linux'):
            environment={'native_runtime':{'client':{'identity':{'platform':platform}}}}
            driver,checks=native.validate_case(case,ROOT,environment)
            self.assertEqual(native.upstream_checks(ROOT,platform,False),checks)
            self.assertEqual({'No Redirect','General'},{x.split('::')[0] for x in checks})
