"""Same production registry/orchestration; OS process/socket/capture edges only."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT)]
import acceptance as ACC
import acceptance_headless as H
import acceptance_headless_oracles as O
import acceptance_native as N


class ContentTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
    def produce(self,mode='process',name='run',selected=None):
        out=self.root/name
        value=H.run(mode,out,H.memory_inputs(),memory=True,selected=selected)
        self.assertIsNone(value['error']);return out
    def judge(self,out,mode='process',checks=None):
        return O.evaluate(ROOT,out,mode,checks or (H.PROCESS_CHECKS if mode=='process' else H.PAYLOAD_CHECKS),allow_fixture=True,expected_inputs=H.memory_inputs())
    def test_same_producer_both_normal_modes(self):
        for mode in ('process','payload'):
            with self.subTest(mode=mode):
                out=self.produce(mode,name=mode);rows,clean,_=self.judge(out,mode)
                self.assertTrue(clean);self.assertEqual('pass',N._judge_rows(rows,[r['id'] for r in rows])['verdict'])
    def test_unknown_selection_and_incomplete_inputs_rejected_before_output(self):
        for values,selection in [({},None),(dict(H.memory_inputs(),commands={}),None),(H.memory_inputs(),['unknown'])]:
            with mock.patch.object(H.subprocess,'Popen',side_effect=AssertionError('unplanned OS launch')):
                with self.assertRaises(ValueError):H.run('process',self.root/'absent',values,selected=selection)
            self.assertFalse((self.root/'absent').exists())
    def test_identity_only_has_no_probe_core_or_capture(self):
        with mock.patch.object(H.MemoryBoundary,'exchange',side_effect=AssertionError('unexpected probe')),mock.patch.object(H.MemoryBoundary,'start_core',side_effect=AssertionError('unexpected core')):
            out=self.produce(selected=['identity']);rows,clean,_=self.judge(out,checks=['identity'])
        self.assertTrue(clean);self.assertEqual('pass',rows[0]['status'])
    def test_original_reassembly_gap_conflict_and_udp_matrix(self):
        verifier=O._load(ROOT,'test/gui_vm/verify_reassembly.py')
        rows=verifier._matrix_checks()
        self.assertTrue(rows)
        self.assertTrue(all(row['verdict']=='PASS' for row in rows))
        self.assertTrue(any(row.get('gap_conflict') for row in rows))

    def test_budget_comes_from_actual_core_bucket(self):
        budget=H.owner_budget();self.assertEqual(16,budget['capacity']);self.assertEqual(32,budget['refill_per_second']);self.assertGreater(budget['burst'],budget['capacity'])
    def test_bad_mapping_nonce_negative_process_and_frozen_inputs(self):
        for mode in ('mapping','nonce','negative','image','wrong-plan'):
            with self.subTest(mode=mode):
                out=self.produce(name=mode);path=out/'headless-result.json';v=H.read_json(path)
                if mode=='mapping':
                    log=out/'core.log';log.write_text(log.read_text().replace('process_image_sha256=','bad_hash='))
                elif mode=='nonce':
                    log=out/v['clients']['positive']['path'];rows=[json.loads(line) for line in log.read_text().splitlines()];rows[1]['nonce']='other';log.write_text(''.join(json.dumps(r)+'\n' for r in rows))
                elif mode=='negative':
                    log=out/v['clients']['non-target']['path'];rows=[json.loads(line) for line in log.read_text().splitlines()];rows[1].update(success=True,failure_stage='',winsock_error=0);rows[-1]['failures']=0;log.write_text(''.join(json.dumps(r)+'\n' for r in rows))
                elif mode=='image':(out/'target.exe').write_bytes(b'MZwrong bytes')
                else:v['inputs']['source_ip']='192.168.204.199';H.write_json(path,v)
                try:rows,clean,_=self.judge(out);verdict=N._judge_rows(rows,H.PROCESS_CHECKS)['verdict']
                except ValueError:verdict='fail'
                self.assertNotEqual('pass',verdict)
    def test_corrupt_converted_gap_html_direction_and_multiple_pid(self):
        for mode in ('converted','gap','direction','pid','udp'):
            with self.subTest(mode=mode):
                out=self.produce('payload',mode);v=H.read_json(out/'headless-result.json')
                if mode=='converted':
                    path=out/v['paths']['converted'];data=bytearray(path.read_bytes());data[-1]^=1;path.write_bytes(data)
                elif mode=='gap':
                    path=out/v['paths']['raw'];path.write_bytes(path.read_bytes()[:24])
                else:
                    path=out/v['paths']['html'];model=O._load(ROOT,'test/gui_vm/verify_payload_integrity.py')._html_model(path)
                    if mode=='pid':model['flows'][0]['pid']+=100
                    elif mode=='direction':model['flows'][0]['directions'].pop(next(iter(model['flows'][0]['directions'])))
                    else:model['flows']=[f for f in model['flows'] if f['protocol']!='UDP']
                    path.write_text('<script id="payload-data" type="application/json">'+json.dumps(model)+'</script>')
                try:rows,clean,_=self.judge(out,'payload');verdict=N._judge_rows(rows,H.PAYLOAD_CHECKS)['verdict']
                except (ValueError,AssertionError):verdict='fail'
                self.assertNotEqual('pass',verdict)
    def test_cleanup_failure_keeps_evidence_and_no_followup_client(self):
        class Failing(H.MemoryBoundary):
            def start_capture(self):raise OSError('capture not observable')
        out=self.root/'failed';boundary=Failing(out,H.memory_inputs(),'process')
        value=H.run('process',out,H.memory_inputs(),selected=['target-positive'],boundary=boundary)
        self.assertIn('capture not observable',value['error']);self.assertEqual({},value['clients'])
        self.assertTrue((out/'owned-core.json').exists());self.assertTrue((out/'network-after.json').exists())
    def test_core_nonzero_and_network_change_do_not_restore(self):
        for kind in ('exit','network'):
            out=self.produce(name=kind);v=H.read_json(out/'headless-result.json')
            path=out/(v['core'] if kind=='exit' else v['network_after']);data=H.read_json(path)
            if kind=='exit':data['returncode']=9
            else:data['routes']=['changed']
            H.write_json(path,data);rows,clean,_=self.judge(out);self.assertFalse(clean)
            self.assertEqual('fail',next(r for r in rows if r['id']=='pcap-restore')['status'])


class ProductionCliTests(unittest.TestCase):
    CASES=['PR-REDIRECT-POSITIVE','PR-OWNER-BOUNDED','PR-PCAP-RESTORE','PAYLOAD-THREE-WAY']
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.base=Path(self.temp.name);self.run=self.base/'run'
        self.identity={'platform':'windows','hostname':'memory-OS'}
        self.catalog_hash=H.sha256(ROOT/'docs/acceptance/catalog.json')
        H.write_json(self.base/'candidate.json',{'schema':ACC.CANDIDATE_V2,'source_commit':ACC.git_head(ROOT),'deployed_identity':self.identity,'offline_fixture':True})
        H.write_json(self.base/'environment.json',{'schema':ACC.ENVIRONMENT_V2,'targets':['windows-vm'],'interpreters':{'python':sys.executable},'work_root':str(self.base),'allowed_actions':['native'],
                    'endpoints':[],'auth_refs':[],'native_runtime':{'transport':'local-target','identity':self.identity},'headless':H.memory_inputs()})
    def cli(self,*args):
        stdout,stderr=io.StringIO(),io.StringIO()
        with contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stderr):code=ACC.main(['--root',str(ROOT)]+list(map(str,args)))
        return code,stdout.getvalue(),stderr.getvalue()
    def execute(self,cases=None):
        selection=[]
        for case in cases or self.CASES:selection+=['--case',case]
        r=self.cli('plan','--mode','selected',*selection,'--candidate',self.base/'candidate.json','--environment',self.base/'environment.json','--output',self.run/'plan.json');self.assertEqual(0,r[0],r)
        original=subprocess.Popen;calls=[]
        class Process:
            pid=123456789
            def __init__(self,argv):
                if '--memory' not in argv:raise AssertionError('fixture did not bind OS memory edge')
                calls.append(argv);self.code=H.main(argv[2:])
            def wait(self,timeout=None):return self.code
        def popen(argv,*args,**kwargs):
            if len(argv)>1 and argv[1].endswith('acceptance_headless.py'):return Process(argv)
            return original(argv,*args,**kwargs)
        with mock.patch.object(N.subprocess,'Popen',side_effect=popen),mock.patch('acceptance_runtime.require_target',return_value=self.identity):r=self.cli('execute','--plan',self.run/'plan.json')
        self.assertEqual(0,r[0],r);self.assertEqual(len(cases or self.CASES),len(calls))
        self.assertEqual(self.catalog_hash,H.sha256(ROOT/'docs/acceptance/catalog.json'))
        r=self.cli('judge','--plan',self.run/'plan.json','--results',self.run/'results','--output',self.run/'independent.json');self.assertEqual(0,r[0],r)
        summary=H.read_json(self.run/'independent.json');self.assertTrue(summary['fixture_contract_pass']);self.assertFalse(summary['full_functional_pass'])
        self.assertEqual(len(cases or self.CASES),summary['checks']['passed'])
    def mutate_and_judge(self,case,mutation):
        directory=self.run/'results'/case;driver=directory/'driver'
        mutation(driver)
        receipt=H.read_json(directory/'receipt.json')
        for a in receipt['artifacts']:a['sha256']=H.sha256(a['path'])
        H.write_json(directory/'receipt.json',receipt)
        index=H.read_json(self.run/'results/results.json')
        for row in index['receipts']:
            if row['case_id']==case:row['sha256']=H.sha256(directory/'receipt.json')
        H.write_json(self.run/'results/results.json',index)
        r=self.cli('judge','--plan',self.run/'plan.json','--results',self.run/'results','--output',self.run/'negative.json');self.assertNotEqual(0,r[0],r)
        summary=H.read_json(self.run/'negative.json');self.assertFalse(summary['fixture_contract_pass']);self.assertFalse(summary['full_functional_pass']);return summary
    def test_normal_unchanged_registry_four_cases(self):self.execute()
    def test_wrong_config_rehashed_production_cli(self):
        case='PR-REDIRECT-POSITIVE';self.execute([case])
        summary=self.mutate_and_judge(case,lambda d:(d/'session.ini').write_text('[Diverter]\nExternalProcessRedirectEnabled=No\nDumpPackets=No\n'))
        self.assertIn('configuration',json.dumps(summary))
    def test_changed_network_rehashed_production_cli(self):
        case='PR-PCAP-RESTORE';self.execute([case])
        summary=self.mutate_and_judge(case,lambda d:H.write_json(d/'network-after.json',{'routes':['changed']}))
        self.assertIn('pcap-restore',json.dumps(summary))
    def test_unrelated_one_way_wire_rehashed_production_cli(self):
        import dpkt
        case='PR-REDIRECT-POSITIVE';self.execute([case])
        def mutate(directory):
            from test_acceptance_native_oracles import make_pair
            src='203.0.113.77';dst=H.memory_inputs()['target_ip'];tcp=dpkt.tcp.TCP(sport=12345,dport=H.memory_inputs()['port'],seq=1,data=b'unrelated no nonce');tcp.off=5
            ip=dpkt.ip.IP(src=H.socket.inet_aton(src),dst=H.socket.inet_aton(dst),p=6,data=tcp);ip.len=len(ip)
            with (directory/'wire.pcapng').open('wb') as stream:dpkt.pcapng.Writer(stream,linktype=101).writepkt(bytes(ip),ts=H.time.time())
        summary=self.mutate_and_judge(case,mutate)
        self.assertNotEqual('pass',summary['cases'][0]['status'])


class RemoteHeadlessTests(unittest.TestCase):
    setUp=ProductionCliTests.setUp
    cli=ProductionCliTests.cli
    def test_existing_channel_four_cases_and_independent_rejudge(self):
        import shutil
        import time
        from pathlib import PureWindowsPath
        import acceptance_windows as windows
        import acceptance_policy as policy
        environment=H.read_json(self.base/'environment.json')
        runtime={'transport':'windows-mcp-velo','identity':self.identity,'mcp_config_ref':'existing','mcp_server':'existing',
                 'python':'E:/python.exe','source_root':'E:/candidate','work_root':'E:/runs','transfer':{}}
        environment['native_runtime']=runtime
        environment['allowed_actions']=['native','vm-execute','vm-transfer','policy-services']
        inputs=H.memory_inputs()
        environment['headless_service']={'bind_ipv4':inputs['target_ip'],'allowed_peer_ipv4':inputs['source_ip'],'max_seconds':120}
        H.write_json(self.base/'environment.json',environment)
        selection=[]
        for case in ProductionCliTests.CASES:selection+=['--case',case]
        result=self.cli('plan','--mode','selected',*selection,'--candidate',self.base/'candidate.json','--environment',self.base/'environment.json','--output',self.run/'plan.json')
        self.assertEqual(0,result[0],result)
        outer=self
        services=[]
        class Service(policy.HostServices):
            def start(self):
                self.directory.mkdir();(self.directory/'events.jsonl').touch()
                self.owner.update(birth=1.0,ready=True);H.write_json(self.directory/'ready.json',self.owner)
                services.append(self)
            def stop(self):
                self.owner.update(stopped=True,ended_at=time.time());H.write_json(self.directory/'lifecycle.json',self.owner)
        class Channel:
            def __init__(self,root,runtime,journal):self.runtime=runtime;self.request=None
            def identity(self):return outer.identity
            def transfer(self,name,direction,sources,destination,**kwargs):
                if direction=='push':self.request=H.read_json(sources[0]['absolute_path'])
                else:shutil.copytree(self.local,Path(destination)/'originals')
                return {}
            def execute(self,*args):
                request=self.request;self.local=outer.base/'guest-memory'/request['case_id'];self.local.mkdir(parents=True)
                mode='payload' if request['case_id']=='PAYLOAD-THREE-WAY' else 'process'
                boundary=H.MemoryBoundary(self.local/'driver',request['headless'],mode)
                produced=H.run(mode,self.local/'driver',request['headless'],selected=request['checks'],boundary=boundary)
                if produced['error']:raise AssertionError(produced['error'])
                # Simulate the guest's actual Windows paths; closed references stay relative.
                (self.local/'driver/session.ini').write_text(H.config_text(mode,inputs,str(PureWindowsPath(request['output_root'])/'driver'),self.runtime['source_root']))
                for name in ('stdout.log','stderr.log'):(self.local/name).write_text('memory OS boundary')
                H.write_json(self.local/'target.json',outer.identity);H.write_json(self.local/'request.json',{'checks':request['checks'],'target':outer.identity})
                for flow in produced['controls']+boundary.flows:
                    f=flow['tuple'];services[-1].append({'transport':f['proto'],'peer_ip':f['src'],'peer_port':f['sport'],'nonce':flow['nonce'],'request_hex':flow['request_hex'],'response_hex':flow['response_hex']})
                driver=N.driver_table(ROOT)[request['case']['native_driver']]
                artifacts=[{'path':str(PureWindowsPath(request['output_root'])/p.relative_to(self.local)),'sha256':H.sha256(p)} for p in self.local.rglob('*') if p.is_file()]
                receipt={'status':'pass','command':N.remote_guest_command(driver,self.runtime,request['output_root'],request['checks'],True),
                         'native_target':outer.identity,'required_checks':request['checks'],'returncode':0,'artifacts':artifacts,
                         'cleanup':{'source':'driver','resources':driver['resources'],'recovered':True,'process_exit':{'exited':True,'returncode':0,'timed_out':False}}}
                H.write_json(self.local/'guest-result.json',{'schema':'fakenet.native-guest-result.v1','case_id':request['case_id'],'execution_id':request['execution_id'],'request':request,'receipt':receipt})
                return {'process_exited':True,'returncode':0}
        with mock.patch.object(windows,'ExistingWindowsChannel',Channel),mock.patch.object(policy,'HostServices',Service):
            result=self.cli('execute','--plan',self.run/'plan.json')
        self.assertEqual(0,result[0],result);self.assertEqual(4,len(services))
        result=self.cli('judge','--plan',self.run/'plan.json','--results',self.run/'results','--output',self.run/'independent.json')
        self.assertEqual(0,result[0],result)
        summary=H.read_json(self.run/'independent.json');self.assertEqual(4,summary['checks']['passed']);self.assertTrue(summary['fixture_contract_pass']);self.assertFalse(summary['full_functional_pass'])
        self.assertEqual(self.catalog_hash,H.sha256(ROOT/'docs/acceptance/catalog.json'))


if __name__=='__main__':unittest.main()
