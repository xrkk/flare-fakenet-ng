"""Safe vertical driver tests: native processes/network are replaced, not oracles."""
import importlib.util
import json
import logging
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

import dpkt
from fakenet.diverters.pcapwriter import DualPcapWriter

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT/relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


LINUX = load('native_linux_functional', 'test/dual_pcap_linux/run_tests.py')
WIN_VERIFY = load('native_windows_pair', 'test/dual_pcap_vm/verify_dual_pcap.py')
LINUX_VERIFY = load('native_linux_pair', 'test/dual_pcap_linux/verify_capture.py')


def make_pair(directory, corrupt=False):
    raw, eth = directory/'capture_01.pcap', directory/'capture_01-converted.pcap'
    writer = DualPcapWriter(str(raw), str(eth), logging.getLogger('benign-pcap'), clock=lambda: 5.0)
    for target in ('198.51.100.77','127.0.0.1'):
        udp = dpkt.udp.UDP(sport=41000, dport=53535, data=b'dual-pcap-linux-v1')
        udp.ulen = len(udp)
        packet = dpkt.ip.IP(src=socket.inet_aton('192.0.2.10'),dst=socket.inet_aton(target), p=17,ttl=64,data=udp)
        packet.len = len(packet)
        writer.write_ip_packet(bytes(packet))
    writer.close()
    if corrupt:
        data = bytearray(eth.read_bytes()); data[-1] ^= 1; eth.write_bytes(data)
    return raw, eth


class FunctionalPcapTests(unittest.TestCase):
    def test_original_pair_oracles_accept_good_and_refuse_changed_payload(self):
        with tempfile.TemporaryDirectory() as temp:
            directory=Path(temp); raw,eth=make_pair(directory)
            self.assertEqual(2,WIN_VERIFY.verify(str(raw),str(eth),expected_versions=(4,))['records'])
            self.assertTrue(LINUX_VERIFY.verify_live(str(raw),str(eth),LINUX.MARKER,LINUX.TARGET_IP)['mangled_destination_observed'])
            content=bytearray(eth.read_bytes());content[-1]^=1;eth.write_bytes(content)
            for verify in (lambda:WIN_VERIFY.verify(str(raw),str(eth),expected_versions=(4,)), lambda:LINUX_VERIFY.verify_live(str(raw),str(eth),LINUX.MARKER,LINUX.TARGET_IP)):
                with self.assertRaises(AssertionError):verify()

    def run_case(self, root, mode, corrupt=False, missing_drop=False, changed_network=False):
        runner=LINUX.Runner(root/'run', [mode])
        snapshot={'iptables':b'v4','ip6tables':b'v6','routes4':b'r4','routes6':b'r6','dns':{'is_symlink':False,'link_target':None,'content':b'dns'}}
        after=dict(snapshot)
        if changed_network:after['routes4']=b'changed'
        runner.network_snapshot=mock.Mock(side_effect=[snapshot,after])
        runner.resource_residue=mock.Mock(return_value=[])
        runner.emergency_restore=mock.Mock(return_value=[])
        runner.wait_for_ready=mock.Mock()
        runner.send_marker=mock.Mock()
        process=mock.Mock(pid=42); process.returncode=None; process.poll.side_effect=lambda:process.returncode
        def finish(*unused):
            process.returncode=0 if mode=='normal' else 1
            return process.returncode
        runner.wait_process=mock.Mock(side_effect=finish)
        real_popen=subprocess.Popen
        def launch(argv,*args,**kwargs):
            if 'fakenet.fakenet' not in argv and not any('fault_launcher.py' in a for a in argv):
                return real_popen(argv,*args,**kwargs)
            directory=runner.run_directory/mode
            if mode=='normal':
                make_pair(directory,corrupt)
                text='PCAP_DUAL_SUMMARY healthy=True'
            else:
                text='PCAP_DUAL_WRITE_FAILED\n'
                if mode in ('raw-write','ethernet-write') and not missing_drop:text+='PCAP_DUAL_CURRENT_PACKET_DROP\n'
                if mode=='close':text+='PCAP_DUAL_SUMMARY healthy=False\n'
            (directory/'fakenet.log').write_text(text)
            return process
        with mock.patch.object(LINUX.subprocess,'Popen',side_effect=launch),mock.patch.object(LINUX.time,'sleep'):
            detail=runner.run_case(mode)
        return runner,detail

    def test_linux_normal_calls_original_cli_and_saves_recovery_observations(self):
        with tempfile.TemporaryDirectory() as temp:
            runner,detail=self.run_case(Path(temp),'normal')
            self.assertIn('PASS',detail)
            directory=runner.run_directory/'normal'
            self.assertTrue((directory/'verify.json').is_file())
            evidence=json.loads((directory/'case-evidence.json').read_text())
            self.assertTrue(evidence['ready']);self.assertTrue(evidence['process_exited'])
            self.assertEqual([],evidence['network_differences'])

    def test_linux_corrupt_pair_is_refused_by_original_cli(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(LINUX.AcceptanceError,'PCAP verification failed'):
                self.run_case(Path(temp),'normal',corrupt=True)

    def test_three_linux_fault_paths_and_missing_drop(self):
        for mode in ('raw-write','ethernet-write','close'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as temp:
                runner,detail=self.run_case(Path(temp),mode)
                self.assertIn('exit=1',detail)
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(LINUX.AcceptanceError,'drop count'):
                self.run_case(Path(temp),'raw-write',missing_drop=True)

    def test_network_changed_still_fails_after_emergency_restore(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(LINUX.AcceptanceError,'did not restore'):
                self.run_case(Path(temp),'normal',changed_network=True)

    def test_functional_entry_skips_old_unit_stress_and_stops_after_first_error(self):
        with tempfile.TemporaryDirectory() as temp:
            runner=LINUX.Runner(Path(temp)/'run',['normal','raw-write'])
            runner.preflight=mock.Mock(return_value='fixture VM')
            runner.dependency_identity=mock.Mock(return_value='fixture dependencies')
            runner.run_case=mock.Mock(side_effect=RuntimeError('fixture failure'))
            with mock.patch.object(runner,'run_logged',side_effect=AssertionError('heavy runner')):
                self.assertEqual(1,runner.run_functional())
            runner.run_case.assert_called_once_with('normal')

    def test_invalid_cli_refused_before_directory_or_process(self):
        with mock.patch.object(LINUX,'Runner') as constructor:
            for args in (['--case','normal'],['--functional'],['--functional','--case','normal','--case','normal','--output-directory','/not-created']):
                with self.assertRaises(SystemExit) as error:LINUX.main(args)
                self.assertEqual(2,error.exception.code)
            constructor.assert_not_called()

    def test_windows_functional_path_excludes_uac_and_heavy_work(self):
        # Windows execution is separately required; this is only a dispatch
        # contract check alongside actual original pair oracle tests above.
        text=(ROOT/'test/dual_pcap_vm/Run-DualPcapTests.ps1').read_text()
        self.assertIn('Functional mode requires an already elevated VM channel',text)
        self.assertIn("elseif (-not $FaultMode -or $FaultMode -eq 'close')",text)
        self.assertIn('capture readiness timeout',text)
        self.assertIn("if (-not $Functional) {\n    $dependencyExit",text)
        self.assertIn("if (-not $Functional) {\n        $testExit",text)
        self.assertIn("if ($Functional) {\n            foreach ($mode in $Case)",text)
        self.assertIn('} finally {\n        $restored = Test-NetworkRestored',text)
        self.assertNotIn("else { $fatalCount -eq 1 -and $dropCount -eq 1 }",text)


class ProductionEntryTests(unittest.TestCase):
    def setUp(self):
        sys.path.insert(0,str(ROOT/'tools'))
        sys.path.insert(0,str(ROOT/'test'))
        import acceptance_native
        self.native=acceptance_native
        self.acc=load('production_acceptance_entry','tools/acceptance.py')
        self.fixture=load('production_acceptance_fixture','test/test_acceptance_regression.py')
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=self.fixture.make_root(self.temp.name)
        import shutil
        shutil.copyfile(ROOT/'test/test.py',self.root/'test/test.py')
        (self.root/'test/dual_pcap_linux').mkdir()
        shutil.copyfile(ROOT/'test/dual_pcap_linux/verify_capture.py',self.root/'test/dual_pcap_linux/verify_capture.py')
        self.catalog_path=self.root/'docs/acceptance/catalog.json'
        catalog=json.loads(self.catalog_path.read_text())
        self.case=catalog['suites'][1]['cases'][0]
        self.case.update(adapter='native',native_driver='pcap-linux-functional',platforms=['linux'],modes=['singlehost'],input={'cases':['normal']},oracle={'kind':'pcap'})
        self.catalog_path.write_text(json.dumps(catalog))
        self.identity={'platform':'linux','hostname':'fixture-vm'}
        candidate=json.loads((self.root/'candidate.json').read_text());candidate['deployed_identity']=self.identity
        (self.root/'candidate.json').write_text(json.dumps(candidate))
        self.environment=json.loads((self.root/'environment.json').read_text())
        self.environment['allowed_actions']+=['native'];self.environment['native_runtime']={'transport':'local-target','identity':self.identity}
        (self.root/'environment.json').write_text(json.dumps(self.environment))

    def cli(self,*args):
        import contextlib,io
        out,err=io.StringIO(),io.StringIO()
        with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
            code=self.acc.main(['--root',str(self.root)]+[str(a) for a in args])
        return code,out.getvalue(),err.getvalue()

    def plan(self):
        path=self.root/'Logs/run/plan.json'
        code,out,err=self.cli('plan','--mode','selected','--case','FIX-BLOCKED','--candidate',self.root/'candidate.json','--environment',self.root/'environment.json','--output',path)
        self.assertEqual(0,code,err+out)
        return path

    def native_process(self, launch):
        # Isolate the native launch seam. Source Git checks and original PCAP
        # validator subprocesses retain the real shared subprocess module.
        backend = SimpleNamespace(**vars(subprocess))
        backend.Popen = launch
        return mock.patch.object(self.native, 'subprocess', backend)

    def process_stub(self,argv,**kwargs):
        # Replace only the native launch, leave real PCAP oracles untouched.
        directory=Path(argv[argv.index('--output-directory')+1]); directory.mkdir()
        child=directory/'normal';child.mkdir()
        make_pair(child)
        (child/'fakenet.log').write_text('PCAP_DUAL_SUMMARY healthy=True')
        for name in ('network-before.json','network-after.json'):(child/name).write_text('{}')
        (child/'case-evidence.json').write_text(json.dumps({'ready':True,'forced':False,'returncode':0,'process_exited':True,'network_differences':[],'resource_residue':[],'case_error':None,'snapshot_error':None}))
        (directory/'summary.json').write_text(json.dumps({'results':[{'name':n,'status':'PASS'} for n in ('Environment','Dependencies','Live-normal')]}))
        process=mock.Mock(pid=123);process.wait.return_value=0
        return process

    def test_actual_plan_execute_and_independent_judge_with_original_pcap(self):
        path=self.plan()
        import acceptance_runtime as rt
        with mock.patch.object(rt,'require_target',return_value=self.identity),self.native_process(mock.Mock(side_effect=self.process_stub)):
            code,out,err=self.cli('execute','--plan',path)
        self.assertEqual(0,code,out+err)
        result=json.loads((path.parent/'summary.json').read_text())
        self.assertEqual('pass',result['verdict']);self.assertFalse(result['full_functional_pass'])
        code,out,err=self.cli('judge','--plan',path,'--results',path.parent/'results')
        self.assertEqual(0,code,out+err)
        # Rehash a corrupted PCAP to prove content verification, not only SHA.
        case_dir=path.parent/'results/FIX-BLOCKED'
        eth=next((case_dir/'driver/normal').glob('*-converted.pcap'))
        content=bytearray(eth.read_bytes());content[-1]^=1;eth.write_bytes(content)
        receipt_path=case_dir/'receipt.json';receipt=json.loads(receipt_path.read_text())
        next(a for a in receipt['artifacts'] if a['path']==str(eth))['sha256']=self.native.sha256(eth)
        receipt_path.write_text(json.dumps(receipt))
        index_path=path.parent/'results/results.json';index=json.loads(index_path.read_text());index['receipts'][0]['sha256']=self.native.sha256(receipt_path);index_path.write_text(json.dumps(index))
        code,out,err=self.cli('judge','--plan',path,'--results',path.parent/'results')
        self.assertEqual(2,code,out+err)
        self.assertIn('original native oracle refused',out)

    def test_absent_target_is_blocked_and_wrong_target_refuses_before_launch(self):
        self.environment.pop('native_runtime');(self.root/'environment.json').write_text(json.dumps(self.environment))
        path=self.plan();plan=json.loads(path.read_text());self.assertIn('local-target',plan['blocked']['FIX-BLOCKED'])
        launch = mock.Mock()
        with self.native_process(launch):
            code,out,err=self.cli('execute','--plan',path)
            self.assertEqual(2,code,out+err);launch.assert_not_called()

    def test_registered_upstream_exact_selection_matches_original_platform_callbacks(self):
        import test_upstream_runner_contract as original
        ids=['UPSTREAM-TCP-UDP','UPSTREAM-DNS','UPSTREAM-HTTP-CUSTOM','UPSTREAM-FTP-POP-SMTP-IRC','UPSTREAM-SMTP-SSL','UPSTREAM-PROXY-HIDDEN','UPSTREAM-BLACKLIST','UPSTREAM-PROCESS-FILTERS','UPSTREAM-LISTENER-FILTERS','UPSTREAM-REDIRECTALL-OFF']
        driver=self.native.driver_table(ROOT)['upstream-singlehost']
        for platform in ('windows','linux'):
            settings=original.settings_stub(windows=platform=='windows',pythonname='python')
            tester=original.DRIVER.FakeNetTester(settings)
            tester.makeConfig=mock.Mock(return_value=mock.Mock())
            suites=tester.collectSuites()
            expected={s['label']+'::'+name for s in suites for name in s['tests']}
            actual=[name for case_id in ids for name in self.native.select_checks(driver,{'id':case_id},{'native_runtime':{'identity':{'platform':platform}}})]
            self.assertEqual(len(actual),len(set(actual)))
            self.assertEqual(expected,set(actual))

    def test_original_tsv_header_is_not_a_result_row(self):
        path=self.root/'original.tsv';path.write_text('status\tname\tdetail\nPASS\talpha\tok\n')
        self.assertEqual([{'id':'alpha','status':'pass'}],self.native._read_oracle('tsv',path))


    def test_windows_production_entry_routes_all_four_modes_to_original_pair_oracle(self):
        self.case.update(native_driver='pcap-windows-functional',platforms=['windows'], input={'cases':['normal','raw-write','ethernet-write','close']})
        catalog=json.loads(self.catalog_path.read_text());catalog['suites'][1]['cases'][0]=self.case;self.catalog_path.write_text(json.dumps(catalog))
        self.identity={'platform':'windows','hostname':'fixture-windows-vm'}
        candidate=json.loads((self.root/'candidate.json').read_text());candidate['deployed_identity']=self.identity;(self.root/'candidate.json').write_text(json.dumps(candidate))
        self.environment['targets']=['windows-vm'];self.environment['native_runtime']['identity']=self.identity;(self.root/'environment.json').write_text(json.dumps(self.environment))
        import shutil,acceptance_runtime as rt
        (self.root/'test/dual_pcap_vm').mkdir();shutil.copyfile(ROOT/'test/dual_pcap_vm/verify_dual_pcap.py',self.root/'test/dual_pcap_vm/verify_dual_pcap.py')
        path=self.plan()
        def launch(argv,**kwargs):
            self.assertEqual('powershell.exe',argv[0])
            self.assertEqual('normal,raw-write,ethernet-write,close',argv[argv.index('-CaseSet')+1])
            directory=Path(argv[argv.index('-OutputDirectory')+1]);directory.mkdir()
            results=['PASS\tDependencies\timports']
            for mode in self.case['input']['cases']:
                child=directory/mode;child.mkdir()
                for name in ('network-before.json','network-after.json'):(child/name).write_text('{}')
                state={'ready':True,'forced':False,'returncode':0 if mode=='normal' else 1,'process_exited':True,'network_restored':True}
                (child/'case-evidence.json').write_text(json.dumps(state))
                text='PCAP_DUAL_SUMMARY healthy=True' if mode=='normal' else 'PCAP_DUAL_WRITE_FAILED'
                if mode=='close':text+='\nPCAP_DUAL_SUMMARY healthy=False'
                (child/'fakenet.log').write_text(text)
                if mode=='normal':make_pair(child)
                for prefix in ('Start-','Exit-','Capture-','NetworkRestore-'):results.append('PASS\t'+prefix+mode+'\tobserved')
            results.append('PASS\tLivePcapPair\toriginal verifier')
            (directory/'results.tsv').write_text('\n'.join(results)+'\n')
            process=mock.Mock(pid=99);process.wait.return_value=0;return process
        with mock.patch.object(rt,'require_target',return_value=self.identity),self.native_process(mock.Mock(side_effect=launch)):
            code,out,err=self.cli('execute','--plan',path)
        self.assertEqual(0,code,out+err)
        receipt=json.loads((path.parent/'results/FIX-BLOCKED/receipt.json').read_text())
        self.assertEqual('fixture',receipt['evidence_level'])
        self.assertEqual(self.case['input']['cases'],receipt['required_checks'])
        self.assertEqual(0,self.cli('judge','--plan',path,'--results',path.parent/'results')[0])
