"""Real LinuxRunner/driver/PCAP oracle with only OS edges isolated."""
import base64
import configparser
import contextlib
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import acceptance_linux_runtime as L
import acceptance_linux_runtime_oracles as O


class LinuxTests(unittest.TestCase):
    def root(self, name):
        path = Path(os.environ['FN_COMPAT_CHECK_DIR']) / self.id().split('.')[-1] / name
        path.mkdir(parents=True, exist_ok=False)
        return path

    def inputs(self, root):
        config = root / 'source.ini'
        config.write_text('[Diverter]\nNetworkMode: SingleHost\nDumpPackets: Yes\n')
        pins = ['fakenet/mcp/linuxrunner.py', 'fakenet/diverters/linuxnetpolicy.py',
                'deploy/linux/deploy.sh', 'deploy/linux/update-idle.py',
                'tools/acceptance_linux_runtime.py', 'tools/acceptance_linux_runtime_oracles.py']
        return {'schema': L.INPUT_SCHEMA, 'case': 'LINUX-SINGLEHOST', 'candidate_id': 'benign-fixture',
                'source_commit': 'a' * 40, 'package_sha256': 'b' * 64, 'execution_id': 'benign-0001',
                'target': {'platform': 'linux', 'hostname': socket.gethostname()},
                'owned_root': str(root / 'out'), 'source_hashes': {p: L.sha(ROOT / p) for p in pins},
                'config': str(config), 'config_sha256': L.sha(config), 'mode': 'singlehost',
                'probe': {'address': '192.0.2.20', 'port': 8080, 'nonce': '1' * 32}}

    @contextlib.contextmanager
    def os_edges(self, value):
        import dpkt
        import acceptance_runtime as runtime
        from fakenet.mcp import linuxrunner, captureseal
        current = {'proc': None, 'started': 0}
        original_command = runtime.command
        real_run = subprocess.run
        real_popen = subprocess.Popen
        real_exists = Path.exists

        class Process:
            pid = 999991
            def __init__(self, argv):
                self.flag = Path(argv[argv.index('-f') + 1])
                self.flag.unlink(missing_ok=True)
                self.returncode = None
            def poll(self):
                if self.flag.exists(): self.returncode = 0
                return self.returncode
            def terminate(self): self.returncode = 0
            def kill(self): self.returncode = -9
            def wait(self, timeout=None): return self.returncode

        def popen(argv, **kwargs):
            current['started'] += 1
            proc = Process(argv); current['proc'] = proc
            config = configparser.RawConfigParser(); config.read(argv[argv.index('-c') + 1])
            path = Path(config.get('Diverter', 'DumpPacketsFilePrefix') + '.pcap')
            payload = ('FN-LINUX/' + value['probe']['nonce']).encode()
            with path.open('wb') as stream:
                writer = dpkt.pcap.Writer(stream)
                for src, sport, dst, dport in [('192.0.2.10', 40000, '192.0.2.20', 8080),
                                              ('192.0.2.20', 8080, '192.0.2.10', 40000)]:
                    udp = dpkt.udp.UDP(sport=sport, dport=dport, data=payload); udp.ulen = len(udp)
                    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=17, data=udp); ip.len = len(ip)
                    frame = dpkt.ethernet.Ethernet(src=b'a'*6, dst=b'b'*6, type=0x800, data=ip)
                    writer.writepkt(bytes(frame), ts=1.0)
            return proc

        def command(argv, **kwargs):
            if argv[0]=='git':
                with mock.patch.object(subprocess,'Popen',real_popen):
                    return real_run(argv,**kwargs)
            alive = current['proc'] is not None and current['proc'].poll() is None
            text = b''
            if argv[0] == 'iptables-save': text = b'-A OUTPUT -j NFQUEUE\n' if alive else b''
            elif argv[0] == 'ip6tables-save': text = b'-A OUTPUT -j DROP\n' if alive else b''
            elif argv[:1] != ['ip']: raise AssertionError('unexpected OS command ' + repr(argv))
            return subprocess.CompletedProcess(argv, 0, text, b'')

        class Datagram:
            def __init__(self, *args): self.payload = None
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def settimeout(self, timeout): pass
            def connect(self, address): self.address = address
            def getsockname(self): return ('192.0.2.10', 40000)
            def send(self, data): self.payload = data; return len(data)
            def recv(self, count): return self.payload

        def target_command(argv, *args, **kwargs):
            if argv == ['systemd-detect-virt', '--vm']: return b'vmware\n'
            return original_command(argv, *args, **kwargs)

        with mock.patch.object(subprocess, 'Popen', side_effect=popen), \
             mock.patch.object(subprocess, 'run', side_effect=command), \
             mock.patch.object(socket, 'socket', Datagram), \
             mock.patch.object(L, '_birth', return_value='123456'), \
             mock.patch.object(captureseal, 'create_control', return_value=None), \
             mock.patch.object(os, 'geteuid', return_value=0), \
             mock.patch.object(runtime, 'command', side_effect=target_command), \
             mock.patch.object(Path, 'exists', lambda p: False if str(p) in ('/.dockerenv', '/run/.containerenv') else real_exists(p)):
            yield current

    def execute(self, name):
        root = self.root(name); value = self.inputs(root)
        with self.os_edges(value) as effects:
            record = L.run('LINUX-SINGLEHOST', value['owned_root'], value)
            self.assertEqual(1, effects['started'])
        self.assertIsNone(record['error'], record)
        record['fixture'] = True
        (Path(value['owned_root']) / 'linux-result.json').write_text(json.dumps(record))
        return Path(value['owned_root']), value

    def test_original_runner_and_true_wire_originals_record_partial_case(self):
        out, value = self.execute('normal')
        rows, clean, detail = O.evaluate(ROOT, out, 'LINUX-SINGLEHOST', allow_fixture=True, expected_inputs=value)
        self.assertEqual({'singlehost':'pass', 'multihost':'fail', 'nfqueue':'pass', 'ipv6-block':'pass', 'restore':'pass'},
                         {r['id']:r['status'] for r in rows}, detail)
        self.assertFalse(clean, 'missing second target must not earn full case credit')
        self.assertEqual(value, json.loads((out/'linux-result.json').read_text())['inputs'])

    def test_rehashed_missing_reverse_packet_and_restore_are_rejected(self):
        import dpkt
        for fault in ('reverse', 'restore', 'identity'):
            with self.subTest(fault=fault):
                out, value = self.execute(fault)
                if fault == 'reverse':
                    path = next(out.glob('capture*.pcap'))
                    with path.open('rb') as stream: records = list(dpkt.pcap.Reader(stream))
                    with path.open('wb') as stream:
                        writer = dpkt.pcap.Writer(stream); writer.writepkt(records[0][1], records[0][0])
                elif fault == 'restore':
                    (out/'network-after.json').write_text('{}')
                else:
                    value = dict(value, execution_id='other-execution')
                result_path = out/'linux-result.json'; record = json.loads(result_path.read_text())
                record['originals'] = {str(p.relative_to(out)): L.sha(p) for p in out.rglob('*') if p.is_file() and p.name!='linux-result.json'}
                result_path.write_text(json.dumps(record))
                rows, clean, detail = O.evaluate(ROOT, out, 'LINUX-SINGLEHOST', allow_fixture=True, expected_inputs=value)
                self.assertFalse(clean)
                self.assertNotEqual(['pass']*4, [r['status'] for r in rows if r['id']!='multihost'], detail)

    def test_driver_cli_refuses_full_credit_and_rejudge_matches_originals(self):
        import contextlib, io
        root = self.root('cli'); value = self.inputs(root)
        request = root / 'inputs.json'; request.write_text(json.dumps(value))
        output = io.StringIO()
        with self.os_edges(value), contextlib.redirect_stdout(output):
            code = L.main(['--case', 'LINUX-SINGLEHOST', '--inputs', str(request), '--output', value['owned_root']])
        self.assertEqual(1, code)
        result = json.loads(output.getvalue())
        self.assertEqual('fail', result['status'])
        self.assertEqual('fail', next(row['status'] for row in result['checks'] if row['id']=='multihost'))
        rows, clean, detail = O.evaluate(ROOT, value['owned_root'], 'LINUX-SINGLEHOST', expected_inputs=value)
        self.assertEqual(result['checks'], rows)
        self.assertFalse(clean)

    def test_central_cli_keeps_incomplete_cases_blocked_and_exact_checks(self):
        import acceptance as central
        import acceptance_native as native
        import io
        root = self.root('central-cli'); value = self.inputs(root)
        target = value['target']
        candidate = {'schema':central.CANDIDATE_V2,'candidate_id':'benign-fixture',
                     'source_commit':central.git_head(ROOT),'package_sha256':'b'*64,
                     'offline_fixture':True,'deployed_identity':target}
        options = {k:value[k] for k in ('config','config_sha256','mode','probe')}
        options['schema']='fakenet.linux-runtime-options.v2'
        environment = {'schema':central.ENVIRONMENT_V2,'targets':['host-linux'],
            'interpreters':{'python':sys.executable},'endpoints':[],'auth_refs':[],
            'work_root':str(root),'allowed_actions':['native'],
            'native_runtime':{'transport':'local-target','identity':target},'linux':options}
        cp=root/'candidate.json'; ep=root/'environment.json'
        cp.write_text(json.dumps(candidate)); ep.write_text(json.dumps(environment))
        plan=root/'run/plan.json'
        def cli(*args):
            stdout=io.StringIO();stderr=io.StringIO()
            with contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stderr):
                code=central.main(['--root',str(ROOT),*map(str,args)])
            return code,stdout.getvalue(),stderr.getvalue()
        code,out,error=cli('plan','--mode','selected','--case','LINUX-SINGLEHOST',
            '--candidate',cp,'--environment',ep,'--output',plan)
        self.assertEqual(0,code,error+out)
        frozen=json.loads(plan.read_text())
        self.assertEqual(L.CHECKS['LINUX-SINGLEHOST'],frozen['required_checks']['LINUX-SINGLEHOST'])
        class Child:
            pid=999992
            def __init__(self,code):self.code=code
            def wait(self,timeout=None):return self.code
        self.assertIn('LINUX-SINGLEHOST',frozen['blocked'])
        with self.os_edges(value) as effects:
            low_popen=subprocess.Popen
            def child(argv,**kwargs):
                if '-m' in argv:return low_popen(argv,**kwargs)
                self.assertEqual(str(ROOT/'tools/acceptance_linux_runtime.py'),argv[1])
                captured=io.StringIO()
                with contextlib.redirect_stdout(captured):code=L.main(argv[2:])
                kwargs['stdout'].write(captured.getvalue().encode())
                return Child(code)
            with mock.patch.object(subprocess,'Popen',side_effect=child):
                code,out,error=cli('execute','--plan',plan)
        self.assertNotEqual(0,code,error+out)
        self.assertEqual(0,effects['started'],'blocked whole case must not start a partial native experiment')
        summary=json.loads((plan.parent/'summary.json').read_text())
        self.assertFalse(summary['full_functional_pass'])
        code,out,error=cli('judge','--plan',plan,'--results',plan.parent/'results',
                           '--output',root/'judged.json')
        self.assertNotEqual(0,code,error+out)
        judged=json.loads((root/'judged.json').read_text())
        self.assertFalse(judged['full_functional_pass'])
        self.assertNotEqual('pass',judged['verdict'])

    def test_invalid_identity_and_multihost_have_no_output_or_os_effects(self):
        root = self.root('refused'); value = self.inputs(root)
        for invalid in (dict(value, source_commit='g'*40), dict(value, command=['arbitrary'])):
            with self.assertRaises(ValueError): L.run('LINUX-SINGLEHOST', value['owned_root'], invalid)
            self.assertFalse(Path(value['owned_root']).exists())
        config = Path(value['config']); config.write_text('[Diverter]\nNetworkMode: MultiHost\n')
        value.update(mode='multihost', config_sha256=L.sha(config))
        with self.assertRaises(NotImplementedError): L.run('LINUX-SINGLEHOST', value['owned_root'], value)
        self.assertFalse(Path(value['owned_root']).exists())


if __name__ == '__main__': unittest.main()
