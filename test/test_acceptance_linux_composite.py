"""Code-level composite contracts; no product process or network execution."""
import json
import os
from pathlib import Path
import socket
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'test'))
import acceptance_linux_composite as composite
import acceptance_native as native
import acceptance_linux_runtime as runtime
import test_acceptance_orchestration as existing


class CompositeTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(os.environ['FN_COMPAT_CHECK_DIR']) / (type(self).__name__+'-'+self.id().split('.')[-1])
        self.base.mkdir(parents=True, exist_ok=False)
        self.config = self.base / 'source.ini'
        self.config.write_text('[Diverter]\nNetworkMode: SingleHost\nDumpPackets: Yes\n')
        self.server = existing.runtime('server')
        self.client = existing.runtime('client')
        self.target = self.server['identity']
        self.sources = {name: runtime.sha(ROOT / name) for name in (
            'fakenet/mcp/linuxrunner.py', 'fakenet/diverters/linuxnetpolicy.py',
            'deploy/linux/deploy.sh', 'deploy/linux/update-idle.py',
            'tools/acceptance_linux_runtime.py', 'tools/acceptance_linux_runtime_oracles.py',
            'tools/acceptance_linux_composite.py', 'tools/acceptance_orchestration.py',
            'tools/acceptance_multihost.py', 'tools/acceptance_linux.py',
            'tools/acceptance_guest.py', 'tools/acceptance_collection.py',
            'test/test.py', 'test/template.ini', 'test/custom_responses.ini',
            'test/CustomProviderExample.py', 'test/sample_raw_response.txt',
            'test/sample_raw_tcp_response.txt')}

    def inputs(self, name='case'):
        return {
            'schema': composite.INPUT_SCHEMA, 'case': 'LINUX-SINGLEHOST',
            'candidate_id': 'composite-fixture', 'source_commit': 'a' * 40,
            'package_sha256': 'b' * 64, 'execution_id': 'composite-fixture-0001',
            'target': self.target, 'owned_root': str(self.base / name),
            'deployed_identity': {'singlehost': self.target, 'server': self.server['identity'],
                                  'client': self.client['identity']},
            'source_hashes': self.sources,
            'singlehost': {'target': self.target,
                           'config': str(self.config),
                           'config_sha256': runtime.sha(self.config),
                           'probe': {'address': '192.0.2.20', 'port': 8080,
                                     'nonce': '1' * 32}},
            'multihost': {'server': self.server, 'client': self.client,
                          'server_ipv4': '192.0.2.10',
                          'allowed_actions': ['native', 'multihost', 'vm-execute', 'vm-transfer']},
            'fixture': True,
        }

    def test_exact_three_role_identity_is_required(self):
        value = self.inputs()
        composite.validate_inputs(value['owned_root'], value)
        for field in ('singlehost', 'server', 'client'):
            broken = json.loads(json.dumps(value))
            broken['deployed_identity'].pop(field)
            with self.assertRaises(ValueError):
                composite.validate_inputs(broken['owned_root'], broken)
        duplicate = self.inputs('duplicate')
        duplicate['multihost']['client'] = dict(duplicate['multihost']['server'])
        reference = composite._identities(duplicate)
        duplicate['deployed_identity'] = reference
        with self.assertRaises(ValueError):
            composite.validate_inputs(duplicate['owned_root'], duplicate)
        self.assertFalse(Path(value['owned_root']).exists())

    def test_single_plan_uses_remote_sdk_and_server_identity(self):
        value = self.inputs()
        case, plan = composite._single_plan(value)
        self.assertEqual('LINUX-SINGLEHOST', case['id'])
        self.assertEqual('remnux-sdk', plan['environment']['native_runtime']['transport'])
        self.assertEqual(self.server['identity'], plan['candidate']['deployed_identity'])
        self.assertEqual(self.server['identity'], plan['environment']['native_runtime']['identity'])
        self.assertIn('LINUX-SINGLEHOST', plan['source_hashes'])

    def test_linux_inputs_composite_binds_declared_target(self):
        value = self.inputs()
        options = {'schema': 'fakenet.linux-composite-options.v1',
                   'singlehost': value['singlehost'], 'multihost': value['multihost']}
        plan = {'environment': {'linux': options,
                                'native_runtime': {'transport': 'remnux-multihost',
                                                   'server': self.server, 'client': self.client,
                                                   'server_ipv4': '192.0.2.10'}},
                'candidate': {'candidate_id': 'composite-fixture', 'source_commit': 'a' * 40,
                              'package_sha256': 'b' * 64, 'offline_fixture': True,
                              'deployed_identity': value['deployed_identity']},
                'execution_id': 'composite-fixture-0001'}
        built = native.linux_inputs(plan, {'id': 'LINUX-SINGLEHOST'}, self.base / 'central')
        self.assertEqual(composite.INPUT_SCHEMA, built['schema'])
        self.assertEqual(value['deployed_identity'], built['deployed_identity'])
        self.assertEqual(self.target, built['singlehost']['target'])
        self.assertTrue(built['fixture'])

    def test_composite_oracle_rejects_unpassed_single_gate(self):
        value = self.inputs('bad-gate')
        value['deployed_identity'] = {'singlehost': self.target, 'server': self.server['identity'],
                                      'client': self.client['identity']}
        out = Path(value['owned_root']); out.mkdir()
        (out / 'linux-result.json').write_text(json.dumps({
            'schema': composite.SCHEMA, 'inputs': value, 'fixture': True,
            'singlehost_gate': False, 'singlehost': {}, 'multihost': {}}))
        rows, clean, detail = composite.evaluate(ROOT, out, value, allow_fixture=True)
        self.assertFalse(clean)
        self.assertTrue(all(row['status'] == 'fail' for row in rows))



# The old fixtures explicitly declare no Git history. Model that OS response
# only for their exact owned temporary roots; never substitute product HEAD.
import contextlib
import io
import subprocess
import types
import pytest
from unittest import mock


@pytest.fixture(scope='session', autouse=True)
def owned_fixture_git():
    original = subprocess.run
    temp = Path(os.environ['TMPDIR']).resolve()
    def run(argv, *args, **kwargs):
        if isinstance(argv, (list, tuple)) and len(argv) == 5 and list(argv[:2]) == ['git', '-C'] and list(argv[3:]) in (['rev-parse', '--show-toplevel'], ['rev-parse', 'HEAD']):
            root = Path(argv[2]).resolve()
            candidate = root/'candidate.json'
            if root.is_relative_to(temp) and candidate.is_file() and not (root/'.git').exists():
                record = json.loads(candidate.read_text())
                if record.get('schema') == 'fakenet.acceptance-candidate.v2' and record.get('offline_fixture') is True:
                    return subprocess.CompletedProcess(argv, 128, '' if kwargs.get('text') else b'', 'fixture has no Git history' if kwargs.get('text') else b'fixture has no Git history')
        return original(argv, *args, **kwargs)
    with mock.patch.object(subprocess, 'run', side_effect=run):
        yield
    assert subprocess.run is original


class GuestSdk(existing.SdkFixture):
    """Original guest/SingleHost bytes; the existing SDK is the only edge."""
    def __init__(self, outer, runtimes, settings=None):
        super().__init__(outer, settings)
        self.runtimes = runtimes
    def request(self, role, path):
        relative = str(Path(path).relative_to(self.runtimes[role]['workspace_root']))
        return json.loads(self.files[(role, relative)])
    def put_file(self, config, workspace, local, remote):
        result = super().put_file(config, workspace, local, remote)
        path = Path(self.runtimes[config['role']]['workspace_root'])/remote
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(Path(local).read_bytes())
        return result
    def publish(self, role, request):
        if request['schema'] != 'fakenet.native-guest-request.v1':
            return super().publish(role, request)
        import acceptance_guest as guest
        import acceptance_collection as collection
        import acceptance_runtime as rt
        import test_acceptance_linux_runtime as original_linux
        out = Path(request['output_root'])
        value = native.linux_inputs({'candidate': request['candidate'],
                                    'environment': {'linux': request['linux'],
                                                    'native_runtime': self.runtimes[role]},
                                    'execution_id': request['execution_id']},
                                   request['case'], out, ROOT)
        edges = original_linux.LinuxTests('test_original_runner_and_true_wire_originals_record_partial_case')
        class Child:
            pid = 999993
            def __init__(self, code): self.returncode = code
            def wait(self, timeout=None): return self.returncode
        with edges.os_edges(value), mock.patch.object(rt, 'target_identity', return_value=request['target']):
            low_popen = subprocess.Popen
            def child(argv, **kwargs):
                if '-m' in argv or argv[:1] == ['git']:
                    return low_popen(argv, **kwargs)
                assert argv[1] == str(ROOT/'tools/acceptance_linux_runtime.py'), argv
                captured = io.StringIO()
                with contextlib.redirect_stdout(captured):
                    code = runtime.main(argv[2:])
                kwargs['stdout'].write(captured.getvalue().encode())
                return Child(code)
            with mock.patch.object(subprocess, 'Popen', side_effect=child):
                guest.execute(request, ROOT)
        if self.settings.get('single_restore_noop'):
            (out/'driver/network-after.json').write_text('{}')
            raw = json.loads((out/'driver/linux-result.json').read_text())
            raw['originals']['network-after.json'] = runtime.sha(out/'driver/network-after.json')
            (out/'driver/linux-result.json').write_text(json.dumps(raw))
            g = json.loads((out/'guest-result.json').read_text())
            for item in g['receipt']['artifacts']:
                item['sha256'] = runtime.sha(item['path'])
            (out/'guest-result.json').write_text(json.dumps(g))
        index = collection.write_index(out, runtime.sha(next(
            p for p in (Path(self.runtimes[role]['workspace_root'])/'published').rglob('*.json')
            if json.loads(p.read_text()) == request)))
        base = out.relative_to(self.runtimes[role]['workspace_root']).as_posix()
        for p in out.rglob('*'):
            if p.is_file(): self.files[(role, base+'/'+p.relative_to(out).as_posix())] = p.read_bytes()

class ControllerTests(CompositeTests):
    def setup_runtime(self):
        self.runtimes = {}
        for role in ('server', 'client'):
            r = dict(existing.runtime(role))
            workspace = self.base/('remote-'+role)
            workspace.mkdir()
            r.update(workspace_root=str(workspace), work_root=str(workspace/'work/regression'),
                     source_root=str(ROOT), python=sys.executable)
            self.runtimes[role] = r
        self.server, self.client = self.runtimes['server'], self.runtimes['client']
        self.target = self.server['identity']

    def execute(self, settings=None):
        import acceptance as central
        self.setup_runtime()
        value = self.inputs()
        work = self.base/'central'; work.mkdir()
        candidate = {'schema': central.CANDIDATE_V2, 'candidate_id': value['candidate_id'],
                     'source_commit': central.git_head(ROOT), 'package_sha256': value['package_sha256'],
                     'offline_fixture': True, 'deployed_identity': value['deployed_identity']}
        environment = {'schema': central.ENVIRONMENT_V2, 'targets': ['host-linux'],
                       'interpreters': {'python': sys.executable}, 'endpoints': [], 'auth_refs': [],
                       'work_root': str(work), 'allowed_actions': value['multihost']['allowed_actions'],
                       'native_runtime': {'transport': 'remnux-multihost', 'server': self.server,
                                          'client': self.client, 'server_ipv4': '192.0.2.10'},
                       'linux': {'schema': 'fakenet.linux-composite-options.v1',
                                 'singlehost': value['singlehost'], 'multihost': value['multihost']}}
        cp, ep = work/'candidate.json', work/'environment.json'
        cp.write_text(json.dumps(candidate)); ep.write_text(json.dumps(environment))
        self.plan = work/'run/plan.json'
        def cli(*args):
            out = io.StringIO(); err = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = central.main(['--root', str(ROOT), *map(str,args)])
            return code, out.getvalue()+err.getvalue()
        self.cli = cli
        self.assertEqual(0, cli('plan', '--mode','selected','--case','LINUX-SINGLEHOST',
                                '--candidate',cp,'--environment',ep,'--output',self.plan)[0])
        self.root = self.base/'sdk'; self.root.mkdir()
        sdk = GuestSdk(self, self.runtimes, settings)
        import acceptance_linux as linux
        def channel(r, journal): return linux.ExistingRemnuxChannel(r, journal, sdk=sdk)
        with mock.patch.object(existing, 'runtime', side_effect=lambda role: self.runtimes[role]), \
             mock.patch.object(existing.orchestration, 'ExistingRemnuxChannel', side_effect=channel):
            code, text = cli('execute', '--plan', self.plan)
        return sdk, code, text

    def test_central_original_guest_and_independent_multihost(self):
        sdk, code, text = self.execute()
        self.assertEqual(0, code, text)
        self.assertEqual(0, self.cli('judge','--plan',self.plan,'--results',self.plan.parent/'results')[0])
        summary = json.loads((self.plan.parent/'summary.json').read_text())
        self.assertFalse(summary['full_functional_pass'])
        output = self.plan.parent/'results/LINUX-SINGLEHOST'
        value = json.loads((output/'linux-inputs.json').read_text())
        rows, clean, detail = composite.evaluate(ROOT, output/'driver', value, allow_fixture=False)
        self.assertFalse(clean)
        self.assertIn('fixture', str(detail))
        # Rehash a corrupted original at every enclosing layer; bytes still fail.
        original = output/'driver/singlehost/incoming/originals'
        bad = original/'driver/network-after.json'; bad.write_text('{}')
        raw = json.loads((original/'driver/linux-result.json').read_text())
        raw['originals']['network-after.json'] = runtime.sha(bad)
        (original/'driver/linux-result.json').write_text(json.dumps(raw))
        guest = json.loads((original/'guest-result.json').read_text())
        for item in guest['receipt']['artifacts']:
            relative = Path(item['path']).relative_to(guest['request']['output_root'])
            item['sha256'] = runtime.sha(original/relative)
        (original/'guest-result.json').write_text(json.dumps(guest))
        receipt_path = output/'receipt.json'; receipt = json.loads(receipt_path.read_text())
        for item in receipt['artifacts']: item['sha256'] = runtime.sha(item['path'])
        receipt_path.write_text(json.dumps(receipt))
        self.assertNotEqual(0,self.cli('judge','--plan',self.plan,'--results',self.plan.parent/'results')[0])

    def test_original_singlehost_bad_recovery_stops_before_multihost(self):
        sdk, code, text = self.execute({'single_restore_noop': True})
        self.assertNotEqual(0,code,text)
        starts = [j for j in sdk.jobs.values() if j.get('experiment')]
        self.assertEqual([], starts, 'failed recovery must start no MultiHost owner')

    def test_unknown_original_start_is_not_replayed(self):
        sdk, code, text = self.execute({'unknown_start': True})
        self.assertNotEqual(0,code,text)
        self.assertEqual(1, sdk.events.count(('server','remnux_process_start')))
        self.assertFalse(any(j.get('experiment') for j in sdk.jobs.values()))

class DirectConsumerTests(unittest.TestCase):
    """Run the original owner, observations and every original Linux callback."""
    def setUp(self):
        self.base = Path(os.environ['FN_COMPAT_CHECK_DIR'])/self.id().split('.')[-1]
        self.base.mkdir()

    def test_original_serve_observe_all_probes_and_owned_stop(self):
        import acceptance_multihost as multi
        import acceptance_runtime as rt
        import acceptance_orchestration as orchestration
        import acceptance_linux_runtime_oracles as oracle
        import ftplib, poplib, smtplib, netifaces
        from pip._vendor import requests
        from pip._vendor.requests import adapters
        # Optional protocol libraries are transport edges in this fixture.
        # Original tester callbacks and their content comparisons remain real.
        irc = types.ModuleType('irc'); irc.client = types.ModuleType('irc.client')
        icmplib = types.ModuleType('icmplib')
        import threading, time
        files = multi.prepare_original_config(ROOT,'General',self.base/'configuration')
        server = {'platform':'linux','hostname':'server'}
        client = {'platform':'linux','hostname':'client'}
        target = {'value':server}
        settings = {'suite':'General','bad_wire':False}
        commands = []; sent = []; callbacks = []
        class Process:
            pid = 999994
            returncode = None
            def __init__(self, argv, **kwargs):
                assert kwargs['cwd'] == Path(argv[argv.index('-f')+1]).parent
                assert kwargs['shell'] is False
                assert Path(kwargs['env']['PYTHONPATH']) == ROOT
                self.flag = Path(argv[argv.index('-f')+1]); self.log = Path(argv[argv.index('-l')+1])
                self.log.write_text('FakeNet-NG started successfully\n')
            def poll(self):
                if self.flag.exists(): self.returncode = 0
                return self.returncode
            def wait(self, timeout=None): self.returncode = 0; return 0
        class Wire:
            def __init__(self,*args,**kwargs): self.data=b''
            def settimeout(self,value): pass
            def connect(self,address):
                self.address=address;host,port=address
                if host=='6.6.6.6' or port in (139,67) or (settings['suite']=='No Redirect' and address!=('192.0.2.10',1337)):
                    raise OSError('configured no redirect/exclusion')
            def send(self,data): self.data+=data;sent.append((self.address,data));return len(data)
            def recv(self,count):
                port=self.address[1]
                if settings['bad_wire']:return b'wrong original bytes'
                return {1000:b'\x0fL\x0aR\x0e',1001:b'static string TCP response',1002:b'sample TCP raw file response',1003:bytes(x+1 for x in self.data)}.get(port,self.data)
            def close(self): pass
        class Session:
            def get(self,url,timeout=None,verify=None):
                from urllib.parse import urlsplit
                u=urlsplit(url);host=u.hostname;port=u.port
                if u.scheme=='https' and verify: raise requests.exceptions.SSLError('fixture self-signed certificate')
                body='H T T P   L I S T E N E R'
                if u.path=='/test.txt':body='Wraps this'
                if host=='some.random.c2.com':body='success'
                if host=='both_host.com' and u.path=='/and_uri.txt':body='Ahoy'
                if host=='other.c2.com' and port==81:body='success'
                return types.SimpleNamespace(status_code=200,text=body)
        class FTP:
            def connect(self,*a): pass
            def login(self): pass
            def set_pasv(self,*a): pass
            def retrbinary(self,command,callback):
                assert command=='RETR FakeNet.gif'
                callback((ROOT/'fakenet/defaultFiles/FakeNet.gif').read_bytes())
            def quit(self): pass
        class POP:
            def __init__(self,*a,**k): pass
            def user(self,value): assert value=='popuser'
            def pass_(self,value): assert value=='password'
            def retr(self,value): return b'+OK',[b'From: Alice'],16
        class SMTP:
            def __init__(self,*a,**k): pass
            def sendmail(self,sender,recipient,message):
                assert sender=='from-fakenet@example.org' and recipient=='to-fakenet@example.org'
                assert message=='FakeNet-NG SMTP test email';return {}
            def quit(self): pass
        class IRC:
            def __init__(self): self.handlers={};self.queue=[]
            def server(self):return self
            def connect(self,host,port,nick):
                self.nick=nick;self.queue.append(types.SimpleNamespace(type='welcome',arguments=['Welcome to IRC'],source='server',target=nick))
            def add_global_handler(self,key,fn):self.handlers[key]=fn
            def join(self,channel):self.queue.append(types.SimpleNamespace(type='join',source=self.nick,target=channel,arguments=[]))
            def privmsg(self,target,message):self.queue.append(types.SimpleNamespace(type='pubmsg' if target.startswith('#') else 'privmsg',source=target,target=target,arguments=[message]))
            def process_data(self):
                while self.queue:
                    e=self.queue.pop(0);self.handlers[e.type](self,e)
            def quit(self):pass
            def close(self):pass
        real_read=Path.read_text
        def read(path,*args,**kwargs):
            if path==Path('/etc/resolv.conf'):return 'nameserver 192.0.2.10\n'
            return real_read(path,*args,**kwargs)
        def command(argv,timeout=30):
            commands.append(argv)
            if argv[:1]==['ip']:return b'[{"gateway":"192.0.2.10"}]'
            raise AssertionError(argv)
        outcomes=[]
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.dict(sys.modules, {'requests': requests, 'requests.adapters': adapters,
                                                             'irc': irc, 'irc.client': irc.client, 'icmplib': icmplib}))
            irc.client.Reactor = IRC
            icmplib.ping = lambda *args, **kwargs: types.SimpleNamespace(is_alive=True)
            stack.enter_context(mock.patch.object(rt,'require_target',side_effect=lambda identity: identity if identity==target['value'] else (_ for _ in ()).throw(ValueError('target mismatch'))))
            stack.enter_context(mock.patch.object(rt,'target_identity',side_effect=lambda:target['value']))
            stack.enter_context(mock.patch.object(rt,'network_snapshot',return_value={'fixture_network':'unchanged'}))
            stack.enter_context(mock.patch.object(rt,'command',side_effect=command))
            stack.enter_context(mock.patch.object(subprocess,'Popen',side_effect=Process))
            stack.enter_context(mock.patch.object(multi,'birth',side_effect=lambda pid:'fixture-'+str(pid)))
            stack.enter_context(mock.patch.object(socket,'socket',Wire))
            stack.enter_context(mock.patch.object(socket,'gethostbyname',return_value='192.0.2.123'))
            stack.enter_context(mock.patch.object(netifaces,'interfaces',return_value=['fixture']))
            stack.enter_context(mock.patch.object(netifaces,'ifaddresses',return_value={netifaces.AF_INET:[{'addr':'192.0.2.10'}]}))
            stack.enter_context(mock.patch.object(requests,'Session',Session))
            stack.enter_context(mock.patch.object(ftplib,'FTP',FTP))
            stack.enter_context(mock.patch.object(poplib,'POP3',POP))
            stack.enter_context(mock.patch.object(smtplib,'SMTP',SMTP))
            stack.enter_context(mock.patch.object(smtplib,'SMTP_SSL',SMTP))
            stack.enter_context(mock.patch.object(irc.client,'Reactor',IRC))
            stack.enter_context(mock.patch.object(icmplib,'ping',return_value=types.SimpleNamespace(is_alive=True)))
            stack.enter_context(mock.patch.object(Path,'read_text',read))
            for number,suite in enumerate(('General','No Redirect')):
                settings['suite']=suite
                if number:files=multi.prepare_original_config(ROOT,suite,self.base/('configuration-'+str(number)))
                config=Path(files[0]['local']);server_out=self.base/('server-'+str(number))
                case=composite._catalog_case('UPSTREAM-MULTIHOST')
                checks=[x for x in native.validate_case(case,ROOT,{'native_runtime':{'client':{'identity':client}}})[1] if x.startswith(suite+'::')]
                req={'schema':'fakenet.multihost-request.v1','actions':['native','multihost'],
                     'experiment_id':'direct-'+str(number),'source_hashes':{'test/test.py':runtime.sha(ROOT/'test/test.py')},
                     'server_ipv4':'192.0.2.10','config_sha256':runtime.sha(config),'config_path':str(config),
                     'checks':checks,'max_seconds':5,'target':server,'output_root':str(server_out)}
                target['value']=server
                def serve():outcomes.append(multi.serve(req,ROOT))
                thread=threading.Thread(target=serve);thread.start()
                try:
                    deadline=time.monotonic()+2
                    while not (server_out/'owner.json').exists() and thread.is_alive() and time.monotonic()<deadline:time.sleep(.01)
                    self.assertTrue((server_out/'owner.json').is_file(), (server_out/'server-result.json').read_text() if (server_out/'server-result.json').is_file() else 'owner not published')
                    before=multi.observe(req,ROOT)
                    target['value']=client
                    client_req=dict(req,target=client,server_target=server,output_root=str(self.base/('client-'+str(number))),server_observation=before)
                    result=multi.probes(client_req,ROOT)
                    self.assertTrue(result['passed'],result)
                    self.assertEqual(checks,[r['id'] for r in result['checks']])
                    self.assertTrue(all(r['status']=='pass' for r in result['checks']),result)
                    callbacks+=checks
                    # The original callback and byte equality must reject a bad
                    # wire response, without a replacement callback/result.
                    if suite=='General':
                        bad=dict(client_req,output_root=str(self.base/'bad-wire'),checks=[next(x for x in checks if 'TCP custom test static Base64' in x)])
                        settings['bad_wire']=True
                        rejected=multi.probes(bad,ROOT);settings['bad_wire']=False
                        self.assertFalse(rejected['passed'])
                        stale=dict(client_req,output_root=str(self.base/'stale'),server_observation=dict(before,observed_at=0))
                        with self.assertRaisesRegex(ValueError,'fresh observed'):multi.probes(stale,ROOT)
                        self.assertFalse(Path(stale['output_root']).exists())
                    target['value']=server
                    after=multi.observe(req,ROOT);self.assertEqual(before['owner'],after['owner'])
                    multi.stop(req,ROOT)
                finally:
                    if thread.is_alive() and not (server_out/'stop.flag').exists():(server_out/'stop.flag').touch()
                    thread.join(3)
                self.assertFalse(thread.is_alive())
                self.assertTrue(outcomes[-1]['cleanup_complete'],outcomes)
                with self.assertRaisesRegex(ValueError,'stopping/stopped'):multi.observe(req,ROOT)
        self.assertGreater(len(callbacks),40)
        self.assertTrue(sent)
        self.assertTrue(commands)
        (self.base/'direct-consumer-evidence.json').write_text(json.dumps({'callbacks':callbacks,'outcomes':outcomes,'wire':[(a,d.hex()) for a,d in sent],'commands':commands}))
