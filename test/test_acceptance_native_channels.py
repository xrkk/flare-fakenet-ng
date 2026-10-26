"""Existing-channel contracts; no VM, network, transfer service or core starts."""
import hashlib
import importlib.util
import json
from pathlib import Path, PureWindowsPath
import shutil
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'));sys.path.insert(0,str(ROOT/'test'))
import acceptance_windows as win
import acceptance_linux as linux
import acceptance_native as native
import acceptance_guest as guest
import test_acceptance_native_oracles as existing
from test_acceptance_native_oracles import make_pair


def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class WindowsChannelTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        python=self.root/'python';python.write_bytes(b'trusted interpreter')
        origin=self.root/'velo_transfer/__init__.py';origin.parent.mkdir();origin.write_bytes(b'trusted module')
        profile=self.root/'profile.json';profile.write_text('protected reference fixture')
        self.vm={'vm_uuid':'00000000-0000-0000-0000-000000000001','boot_identity':'boot','vm_epoch':'epoch'}
        self.runtime={'transfer':{'python':str(python),'python_sha256':sha(python),'origin':str(origin),'origin_sha256':sha(origin),'connection_profile':str(profile),'expected_vm_identity':self.vm,'budget':{}},'source_root':r'E:\candidate','python':r'E:\python.exe'}

    def test_identity_requires_same_mcp_and_transfer_vm(self):
        call=mock.Mock(return_value={'exit_code':0,'output':json.dumps({'platform':'windows','hostname':'vm','vm_uuid':'other'})})
        channel=win.ExistingWindowsChannel(ROOT,self.runtime,self.root/'journal',powershell=call)
        with self.assertRaisesRegex(win.ChannelError,'different VM'):channel.identity()
        call.assert_called_once()

    def test_unknown_is_not_reissued_and_original_error_retained(self):
        call=mock.Mock(side_effect=RuntimeError('original timeout response'))
        channel=win.ExistingWindowsChannel(ROOT,self.runtime,self.root/'journal',powershell=call)
        with self.assertRaisesRegex(win.ChannelError,'unknown'):channel.invoke('execute','fixed command',30)
        with self.assertRaises(FileExistsError):channel.invoke('execute','fixed command',30)
        call.assert_called_once()
        self.assertIn('original timeout response',(self.root/'journal/execute-unknown.json').read_text())

    def test_velo_cli_terminal_contract_and_local_bytes(self):
        source=self.root/'source';source.write_bytes(b'benign request')
        def run(argv,**kwargs):
            self.assertEqual(['-I','-B','-m','velo_transfer','--spec'],argv[1:6])
            spec=json.loads(Path(argv[-1]).read_text())
            result={'schema':'velo.transfer.result.v1','direction':'push','transfer_id':spec['transfer_id'],
                    'phase':'COMPLETE','outcome':'complete','published_ever':True,'destination_verified':True,
                    'cleanup':{'host':True,'guest':True},'destination_identity':{'identity':self.vm,'canonical_path':r'E:\stage'},
                    'files':[{'relative_path':'request.json','source':str(source),'destination':r'E:\stage\request.json','size':source.stat().st_size,'sha256':sha(source)}]}
            result['destination_identity']['endpoint']='guest'
            result['destination_identity']['identity']={key:self.vm[key] for key in ('vm_uuid','boot_identity')}
            result['destination_identity']['identity']['policy_id']='fixed-policy'
            result['request_digest']='a'*64
            binding=dict(self.vm,protocol_version='velo.transfer.v1',transfer_id=spec['transfer_id'],
                         direction='push',request_digest=result['request_digest'],policy_id='fixed-policy')
            evidence=self.root/'guest-cleanup.json';evidence.write_text(json.dumps({'schema':'velo.transfer.guest.response.v1','transfer_id':binding['transfer_id'],
                'request_digest':binding['request_digest'],'local_phase':'DEST_RELEASED',
                'cleanup':{'temporary_files_removed':True,'workers_stopped':True},
                'terminal':{'schema':'velo.transfer.guest_terminal.v1','binding':binding,
                            'local_phase':'DEST_RELEASED','destination':result['destination_identity']}}))
            info=evidence.stat()
            result['evidence_index']=[{'role':'guest_cleanup','reference':{'name':'guest-cleanup',
                'size':info.st_size,'sha256':sha(evidence),'device':info.st_dev,'inode':info.st_ino,'mtime_ns':info.st_mtime_ns}}]
            path=self.root/'result.json';path.write_text(json.dumps(result))
            kwargs['stdout'].write(json.dumps({'result_path':str(path)}).encode());return types.SimpleNamespace(returncode=0)
        channel=win.ExistingWindowsChannel(ROOT,self.runtime,self.root/'journal',powershell=mock.Mock(),run=run)
        result=channel.transfer('push','push',[{'absolute_path':str(source),'relative_path':'request.json'}],r'E:\stage',producer_reference='closed request fixture')
        self.assertEqual('COMPLETE',result['phase'])
        self.assertTrue((self.root/'journal/push-terminal.json').is_file())

    def real_push_proof(self):
        spec={'expected_vm_identity':self.vm,'transfer_id':'fixed-transfer'}
        binding=dict(self.vm,protocol_version='velo.transfer.v1',transfer_id='fixed-transfer',
                     direction='push',request_digest='a'*64,policy_id='fixed-policy')
        peer={key:self.vm[key] for key in ('vm_uuid','boot_identity')};peer['policy_id']='fixed-policy'
        result={'request_digest':'a'*64,'destination_identity':{'endpoint':'guest','identity':peer}}
        response={'schema':'velo.transfer.guest.response.v1','transfer_id':binding['transfer_id'],
                  'request_digest':binding['request_digest'],'local_phase':'DEST_RELEASED',
                  'cleanup':{'temporary_files_removed':True,'workers_stopped':True},
                  'terminal':{'schema':'velo.transfer.guest_terminal.v1','binding':binding,
                              'local_phase':'DEST_RELEASED','destination':result['destination_identity']}}
        evidence=self.root/'closed-guest-cleanup.json'
        evidence.write_text(json.dumps(response))
        info=evidence.stat()
        reference={'name':'closed-guest-cleanup','size':info.st_size,'sha256':sha(evidence),
                   'device':info.st_dev,'inode':info.st_ino,'mtime_ns':info.st_mtime_ns}
        result['evidence_index']=[{'role':'guest_cleanup','reference':reference}]
        return self.root/'result.json',result,spec,binding,evidence

    def test_real_cli_push_shape_binds_requested_epoch(self):
        path,result,spec,binding,evidence=self.real_push_proof()
        self.assertEqual(self.vm['vm_epoch'],win.push_vm_binding(path,result,spec)['vm_epoch'])

    def test_wrong_requested_epoch_rejected(self):
        path,result,spec,binding,evidence=self.real_push_proof()
        spec['expected_vm_identity']=dict(self.vm,vm_epoch='different')
        with self.assertRaisesRegex(win.ChannelError,'binding'):
            win.push_vm_binding(path,result,spec)

    def test_tampered_cleanup_bytes_rejected(self):
        path,result,spec,binding,evidence=self.real_push_proof()
        evidence.write_text(json.dumps({'binding':dict(binding,vm_epoch='bad')}))
        with self.assertRaisesRegex(win.ChannelError,'binding'):
            win.push_vm_binding(path,result,spec)

    def test_peer_policy_must_equal_bound_policy(self):
        path,result,spec,binding,evidence=self.real_push_proof()
        result['destination_identity']['identity']['policy_id']='other'
        with self.assertRaisesRegex(win.ChannelError,'binding'):
            win.push_vm_binding(path,result,spec)

    def test_missing_cleanup_binding_cannot_earn_complete(self):
        path,result,spec,binding,evidence=self.real_push_proof()
        result['evidence_index']=[]
        with self.assertRaisesRegex(win.ChannelError,'binding'):
            win.push_vm_binding(path,result,spec)

    def test_top_level_binding_cannot_replace_real_terminal(self):
        path,result,spec,binding,evidence=self.real_push_proof()
        evidence.write_text(json.dumps({'binding':binding}))
        info=evidence.stat()
        result['evidence_index'][0]['reference'].update(size=info.st_size,sha256=sha(evidence),mtime_ns=info.st_mtime_ns)
        with self.assertRaisesRegex(win.ChannelError,'binding'):
            win.push_vm_binding(path,result,spec)

    def test_wrong_terminal_or_cleanup_response_rejected(self):
        for field in ('schema','cleanup','destination','transfer_id','request_digest'):
            with self.subTest(field=field):
                path,result,spec,binding,evidence=self.real_push_proof()
                value=json.loads(evidence.read_text())
                if field=='destination':value['terminal']['destination']={'endpoint':'other'}
                elif field=='cleanup':value['cleanup']['workers_stopped']=False
                else:value[field]='wrong'
                evidence.write_text(json.dumps(value));info=evidence.stat()
                result['evidence_index'][0]['reference'].update(size=info.st_size,sha256=sha(evidence),mtime_ns=info.st_mtime_ns)
                with self.assertRaisesRegex(win.ChannelError,'binding'):
                    win.push_vm_binding(path,result,spec)

    def test_transfer_error_does_not_execute_or_fallback(self):
        call=mock.Mock();run=mock.Mock(return_value=types.SimpleNamespace(returncode=3))
        channel=win.ExistingWindowsChannel(ROOT,self.runtime,self.root/'journal',powershell=call,run=run)
        with self.assertRaisesRegex(win.ChannelError,'no fallback'):
            channel.transfer('push','push',[],r'E:\stage',producer_reference='fixture')
        call.assert_not_called();run.assert_called_once()


class RemnuxChannelTests(unittest.TestCase):
    def test_requires_current_host_health_and_preserves_mutation_id(self):
        with tempfile.TemporaryDirectory() as temp:
            sdk=mock.Mock();sdk.load_connection.return_value={}
            sdk.call.side_effect=[{'guest_response':{'ok':True,'vm_uuid':'expected','request_epoch':7},'host_assessment':{'current_gate':'OPEN','guest_matches_current':True},'transport_error':None},RuntimeError('UNKNOWN')]
            runtime={'connection_ref':'existing','expected_vm_uuid':'expected','workspace_id':'owned','python':'/opt/fakenet-ng/venv/bin/python','source_root':'/opt/fakenet-ng'}
            channel=linux.ExistingRemnuxChannel(runtime,temp,sdk=sdk)
            with self.assertRaisesRegex(linux.RemnuxChannelError,'health first'):channel.start_guest('published/request.json','a'*64)
            channel.health()
            with self.assertRaisesRegex(linux.RemnuxChannelError,'unknown'):channel.start_guest('published/request.json','a'*64)
            intent=json.loads((Path(temp)/'execute-intent.json').read_text())
            self.assertEqual(7,intent['arguments']['request_epoch'])
            self.assertEqual('root_explicit',intent['arguments']['execution_identity'])
            with self.assertRaises(FileExistsError):channel.start_guest('published/request.json','a'*64)
            self.assertEqual(2,sdk.call.call_count)

    def test_download_hash_checked_without_overwriting_existing(self):
        with tempfile.TemporaryDirectory() as temp:
            sdk=mock.Mock();sdk.load_connection.return_value={}
            channel=linux.ExistingRemnuxChannel({'connection_ref':'existing','workspace_id':'owned'},Path(temp)/'journal',sdk=sdk);channel.epoch=1
            path=Path(temp)/'output';path.write_bytes(b'keep')
            with self.assertRaisesRegex(linux.RemnuxChannelError,'exists'):channel.get('get','work/output',path)
            sdk.get_file.assert_not_called();self.assertEqual(b'keep',path.read_bytes())


class RemoteProductionTests(unittest.TestCase):
    setUp=existing.ProductionEntryTests.setUp
    cli=existing.ProductionEntryTests.cli
    plan=existing.ProductionEntryTests.plan

    def prepare_windows(self):
        self.case.update(native_driver='pcap-windows-functional',platforms=['windows'],input={'cases':['normal']})
        catalog=json.loads(self.catalog_path.read_text());catalog['suites'][1]['cases'][0]=self.case;self.catalog_path.write_text(json.dumps(catalog))
        self.identity={'platform':'windows','hostname':'fixture-vm'}
        candidate=json.loads((self.root/'candidate.json').read_text());candidate['deployed_identity']=self.identity;(self.root/'candidate.json').write_text(json.dumps(candidate))
        self.runtime={'transport':'windows-mcp-velo','identity':self.identity,'mcp_config_ref':'existing','mcp_server':'VMMalBox','python':r'E:\python.exe','source_root':r'E:\candidate','work_root':r'E:\native-runs','transfer':{}}
        self.environment.update(targets=['windows-vm'],native_runtime=self.runtime)
        self.environment['allowed_actions']+=['vm-execute','vm-transfer'];(self.root/'environment.json').write_text(json.dumps(self.environment))
        (self.root/'test/dual_pcap_vm').mkdir();shutil.copyfile(ROOT/'test/dual_pcap_vm/verify_dual_pcap.py',self.root/'test/dual_pcap_vm/verify_dual_pcap.py')

    def fake_channel(self,root,runtime,journal):
        outer=self
        class Channel:
            def identity(self):return outer.identity
            def transfer(self,name,direction,sources,destination,**kwargs):
                if direction=='push':self.request=json.loads(Path(sources[0]['absolute_path']).read_text());return {}
                directory=Path(destination)/'originals';directory.mkdir(parents=True)
                child=directory/'driver/normal';child.mkdir(parents=True);make_pair(child)
                (child/'fakenet.log').write_text('PCAP_DUAL_SUMMARY healthy=True')
                for name in ('network-before.json','network-after.json'):(child/name).write_text('{}')
                (child/'case-evidence.json').write_text(json.dumps({'ready':True,'forced':False,'returncode':0,'process_exited':True,'network_restored':True}))
                (directory/'driver/results.tsv').write_text('\\n'.join([]))
                rows=['Dependencies','Start-normal','Exit-normal','Capture-normal','NetworkRestore-normal','LivePcapPair']
                (directory/'driver/results.tsv').write_text('\n'.join('PASS\t'+n+'\tobserved' for n in rows)+'\n')
                for name in ('stdout.log','stderr.log'):(directory/name).write_text('original target log')
                (directory/'request.json').write_text('{}');(directory/'target.json').write_text(json.dumps(outer.identity))
                remote_base=PureWindowsPath(self.request['output_root'])
                artifacts=[{'path':str(remote_base/p.relative_to(directory)),'sha256':sha(p),'format':'original'} for p in directory.rglob('*') if p.is_file()]
                driver=native.driver_table(root)['pcap-windows-functional']
                receipt={'command':native.remote_guest_command(driver,runtime,self.request['output_root'],['normal']),
                         'native_target':outer.identity,'required_checks':['normal'],'returncode':0,'status':'pass','artifacts':artifacts,
                         'cleanup':{'source':'driver','resources':driver['resources'],'recovered':True,'process_exit':{'exited':True,'timed_out':False,'returncode':0}}}
                (directory/'guest-result.json').write_text(json.dumps({'schema':'fakenet.native-guest-result.v1','case_id':'FIX-BLOCKED','execution_id':self.request['execution_id'],'request':self.request,'receipt':receipt}))
                return {}
            def execute(self,*args):return {'returncode':0,'process_exited':True,'recovered':True}
        return Channel()

    def test_actual_remote_cli_roundtrip_and_independent_original_oracle(self):
        self.prepare_windows();path=self.plan()
        with mock.patch.object(win,'ExistingWindowsChannel',side_effect=self.fake_channel):
            code,out,err=self.cli('execute','--plan',path)
        self.assertEqual(0,code,out+err)
        self.assertEqual(0,self.cli('judge','--plan',path,'--results',path.parent/'results')[0])

    def test_remote_actions_missing_block_before_channel(self):
        self.prepare_windows();self.environment['allowed_actions'].remove('vm-transfer');(self.root/'environment.json').write_text(json.dumps(self.environment))
        path=self.plan()
        with mock.patch.object(win,'ExistingWindowsChannel') as channel:
            code,out,err=self.cli('execute','--plan',path)
        self.assertEqual(2,code,out+err);channel.assert_not_called()

    def test_protection_field_survives_remote_independent_judge(self):
        # Controller red (remote-judge-red.json): the remote original oracle
        # refused a legal upstream_protected_tcp_ports field as a frozen-plan
        # difference.  The field must flow through the real producer request
        # and the real independent judge rebuild unchanged.
        self.prepare_windows()
        self.runtime['upstream_protected_tcp_ports']=[28787,28790]
        (self.root/'environment.json').write_text(json.dumps(self.environment))
        path=self.plan()
        with mock.patch.object(win,'ExistingWindowsChannel',side_effect=self.fake_channel):
            code,out,err=self.cli('execute','--plan',path)
        self.assertEqual(0,code,out+err)
        self.assertEqual(0,self.cli('judge','--plan',path,'--results',path.parent/'results')[0])

    def test_local_protection_null_rejected_before_output_directory(self):
        import acceptance_runtime as rt
        self.prepare_windows()
        self.runtime.update(transport='local-target',
                            upstream_protected_tcp_ports=None)
        (self.root/'environment.json').write_text(json.dumps(self.environment))
        plan=json.loads(self.plan().read_text())
        output=self.root/'null-local-output'
        with mock.patch.object(rt,'require_target',return_value=self.identity), \
             mock.patch.object(native.subprocess,'Popen') as launch:
            with self.assertRaisesRegex(ValueError,'explicit array, not null'):
                native.run_production(self.root,self.case,plan,output,sys.executable)
        launch.assert_not_called()
        self.assertFalse(output.exists())

    def test_remote_protection_field_explicit_null_rejected_before_channel(self):
        # An explicitly declared null is not the absent default and must be
        # rejected before any channel side effect.
        self.prepare_windows()
        self.runtime['upstream_protected_tcp_ports']=None
        (self.root/'environment.json').write_text(json.dumps(self.environment))
        with mock.patch.object(win,'ExistingWindowsChannel') as channel:
            code,out,err=self.cli('execute','--plan',self.plan())
        self.assertNotEqual(0,code,out+err);channel.assert_not_called()

    def test_guest_wrong_source_is_rejected_before_native_launch(self):
        import acceptance_runtime as rt
        request={'schema':'fakenet.native-guest-request.v1','case_id':'FIX-BLOCKED','case':self.case,'checks':['normal'],
                 'source_hashes':{'test/test.py':'f'*64},'candidate':{},'target':self.identity,'output_root':str(self.root/'no-output'),
                 'execution_id':'fixture','actions':['native']}
        with mock.patch.object(rt,'require_target'),mock.patch.object(native,'run_production') as launch:
            with self.assertRaisesRegex(ValueError,'source mismatch'):guest.execute(request,self.root)
            launch.assert_not_called();self.assertFalse((self.root/'no-output').exists())


class MultiHostTests(unittest.TestCase):
    def setUp(self):
        import acceptance_multihost
        self.multi=acceptance_multihost
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.output=self.root/'output';self.output.mkdir()
        self.config=self.root/'config.ini';self.config.write_text('[Diverter]\nNetworkMode: MultiHost\n')
        self.identity={'platform':'linux','hostname':'server'}
        self.request={'schema':'fakenet.multihost-request.v1','actions':['native','multihost'],'experiment_id':'experiment',
                      'target':self.identity,'source_hashes':{},'server_ipv4':'192.0.2.10','output_root':str(self.output),
                      'config_path':str(self.config),'config_sha256':sha(self.config),'checks':['General::DNS listener test'],'max_seconds':30}
        self.owner={'schema':'fakenet.multihost-owner.v1','experiment_id':'experiment','target':self.identity,'owner_pid':10,'owner_birth':'111','core_pid':20,'core_birth':'222','config_sha256':sha(self.config),'source_hashes':{}}
        (self.output/'owner.json').write_text(json.dumps(self.owner));(self.output/'core.log').write_text('FakeNet-NG started successfully')

    def test_observe_reads_actual_owned_birth_config_and_log(self):
        import acceptance_runtime as rt
        with mock.patch.object(rt,'target_identity',return_value=self.identity),mock.patch.object(self.multi,'birth',side_effect=lambda pid:'111' if pid==10 else '222'):
            observation=self.multi.observe(self.request,self.root)
        self.assertEqual(self.owner,observation['owner']);self.assertTrue(observation['core_ready'])
        self.assertEqual(sha(self.output/'core.log'),observation['core_log_sha256'])

    def test_pid_reuse_and_config_change_refused_before_stop(self):
        import acceptance_runtime as rt
        with mock.patch.object(rt,'target_identity',return_value=self.identity),mock.patch.object(self.multi,'birth',return_value='reused'):
            with self.assertRaisesRegex(ValueError,'reused'):self.multi.stop(self.request,self.root)
        self.assertFalse((self.output/'stop.flag').exists())
        self.config.write_text('[Diverter]\nNetworkMode: SingleHost\n')
        with mock.patch.object(rt,'target_identity',return_value=self.identity),mock.patch.object(self.multi,'birth',side_effect=['111','222']):
            with self.assertRaisesRegex(ValueError,'configuration changed'):self.multi.observe(self.request,self.root)

    def test_boolean_ready_cannot_start_client_probes(self):
        import acceptance_runtime as rt
        self.request['server_observation']={'core_ready':True}
        with mock.patch.object(rt,'require_target'),mock.patch.object(self.multi.importlib.util,'spec_from_file_location') as loader:
            with self.assertRaisesRegex(ValueError,'boolean ready is insufficient'):self.multi.probes(self.request,self.root)
            loader.assert_not_called()

    def test_stop_only_sets_bound_flag_after_live_observation(self):
        import acceptance_runtime as rt
        with mock.patch.object(rt,'target_identity',return_value=self.identity),mock.patch.object(self.multi,'birth',side_effect=['111','222']):
            result=self.multi.stop(self.request,self.root)
        self.assertTrue(result['stop_requested']);self.assertTrue((self.output/'stop.flag').is_file())


    def test_server_owner_uses_original_core_finally_and_network_observations(self):
        import acceptance_runtime as rt
        self.request['output_root']=str(self.root/'server-output')
        core=mock.Mock();core.process.pid=20;core.state={'ready':True,'stopped':True,'forced':False,'returncode':0};core.stop.return_value=True
        def ready():
            directory=Path(self.request['output_root']);(directory/'core.log').write_text('FakeNet-NG started successfully');(directory/'stop.flag').touch()
        core.start.side_effect=ready
        with mock.patch.object(rt,'require_target'),mock.patch.object(rt,'network_snapshot',return_value={'dns':'same'}),mock.patch.object(rt,'OwnedCore',return_value=core),mock.patch.object(self.multi,'birth',return_value='born'):
            result=self.multi.serve(self.request,self.root)
        self.assertTrue(result['passed']);core.stop.assert_called_once()
        evidence=json.loads((Path(self.request['output_root'])/'server-result.json').read_text())
        self.assertTrue(evidence['network_restored']);self.assertEqual('born',evidence['owner']['core_birth'])


    def test_original_general_and_no_redirect_config_stays_equivalent(self):
        import configparser
        import test_upstream_runner_contract as original
        for suite in ('General','No Redirect'):
            output=self.root/('config-'+suite.replace(' ','-'))
            rows=self.multi.prepare_original_config(ROOT,suite,output)
            actual=configparser.RawConfigParser();actual.read(output/'fakenet.ini')
            expected=original.DRIVER.FakeNetConfig(str(ROOT/'test/template.ini'),singlehostmode=False,proxied=suite=='General',redirectall=suite=='General')
            self.assertEqual({s:dict(actual[s]) for s in actual.sections()},{s:dict(expected.rawconfig[s]) for s in expected.rawconfig.sections()})
            self.assertEqual(5,len(rows));self.assertTrue((output/'input-manifest.json').is_file())

    def test_sdk_staging_refuses_changed_config_before_any_upload(self):
        output=self.root/'prepared';rows=self.multi.prepare_original_config(ROOT,'General',output)
        (output/'fakenet.ini').write_text('changed')
        sdk=mock.Mock();sdk.load_connection.return_value={}
        channel=linux.ExistingRemnuxChannel({'connection_ref':'existing','workspace_id':'owned'},self.root/'journal',sdk=sdk);channel.epoch=7
        with self.assertRaisesRegex(linux.RemnuxChannelError,'source identity changed'):channel.stage_multihost('experiment',rows)
        sdk.put_file.assert_not_called()
