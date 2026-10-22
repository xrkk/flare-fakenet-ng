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
