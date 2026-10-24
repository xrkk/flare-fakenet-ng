"""Original callbacks with platform-local imports and an owned route model."""
import builtins
import contextlib
import copy
import json
import os
from pathlib import Path
import socket
import sys
import types
import unittest
from unittest import mock

from test_acceptance_manual_network_fix import _fixture, M, O, N, ROOT


class PlatformRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(os.environ['FN_MANUAL_CHECK_DIR']) / self.id().split('.')[-1]
        self.base.mkdir()

    def inputs(self, out, platform='linux'):
        value = dict(schema='fakenet.manual-input.v2', case='GAP-NETWORK-FIX',
                    candidate_id='route-fixture', source_commit='a'*40,
                    package_sha256='b'*64, execution_id='owned-route-001',
                    config=str(out/'config'), owned_root=str(out), fixture=True,
                    platform=platform, network=dict(ipv4='192.0.2.10', interface='eth0',
                    adapter_guid='{GUID}' if platform == 'windows' else None))
        names=['tools/acceptance_manual.py','tools/acceptance_manual_oracles.py','tools/acceptance_linux_recovery.py','fakenet/diverters/diverterbase.py']+['fakenet/diverters/'+n+'.py' for n in (('winutil','windows') if platform=='windows' else ('linutil','linux'))]
        value['source_hashes']={n:M.sha256(ROOT/n) for n in names}
        return value

    @contextlib.contextmanager
    def produce(self, name, noop=False, drift=False):
        import acceptance_linux_recovery as recovery
        from fakenet.diverters import linutil
        out=self.base/name;inputs=self.inputs(out);routes=[]
        with _fixture(out) as fixture:
            old=linutil.subprocess.call
            def call(argv,*a,**kw):
                rc=old(argv,*a,**kw)
                if list(argv)==['route','add','default','gw','192.0.2.10'] and rc==0:
                    routes.append(dict(dst='default',gateway='192.0.2.10',dev='eth0',table='main',protocol='boot'))
                return rc
            def snapshot():
                values=copy.deepcopy(routes)
                if drift and values:values.append(dict(dst='default',gateway='192.0.2.1',dev='foreign0',table=123))
                return values
            def delete(argv):
                if not noop:routes.clear()
                return 0
            with mock.patch.object(linutil.subprocess,'call',side_effect=call), mock.patch.object(recovery,'route_snapshot',side_effect=snapshot), mock.patch.object(recovery,'route_delete',side_effect=delete):
                value=M.run('GAP-NETWORK-FIX',out,inputs)
        yield out,inputs,value,fixture

    def test_linux_real_callbacks_and_owned_recovery(self):
        with self.produce('normal') as (out,inputs,value,fixture):
            rows,clean,detail=O.evaluate(ROOT,out,'GAP-NETWORK-FIX',inputs,allow_fixture=True)
            self.assertTrue(clean,detail)
            self.assertEqual('pass',rows[0]['status'])
            self.assertNotIn('windows',value['network_fix'])
            self.assertTrue(value['network_fix']['route']['restored'])
            self.assertFalse(value['network_fix']['route']['original_stop_restored'])
            self.assertEqual('not-supported',detail['linux_fix_dns'])
            self.assertIn('not proven restored',value['known_limits']['linux_new_gateway_restoration'])
            result=out/'manual-result.json';saved=result.read_bytes();bad=json.loads(saved)
            bad['network_fix']['route']['after_recovery']=bad['network_fix']['route']['after_stop']
            result.write_text(json.dumps(bad))
            self.assertFalse(O.evaluate(ROOT,out,'GAP-NETWORK-FIX',inputs,allow_fixture=True)[1])
            result.write_bytes(saved)
            self.assertFalse(O.evaluate(ROOT,out,'GAP-NETWORK-FIX',inputs,allow_fixture=False)[1])

    def test_noop_or_foreign_recovery_cannot_be_clean(self):
        for name,kw in [('noop',dict(noop=True)),('foreign',dict(drift=True))]:
            with self.produce(name,**kw) as (out,inputs,value,fixture):
                self.assertFalse(O.evaluate(ROOT,out,'GAP-NETWORK-FIX',inputs,allow_fixture=True)[1])
                self.assertFalse(value['network_fix']['route']['restored'])

    def test_platform_validation_precedes_output(self):
        out=self.base/'bad';value=self.inputs(out);value['platform']='not-a-platform'
        with self.assertRaises(ValueError):M.run('GAP-NETWORK-FIX',out,value)
        self.assertFalse(out.exists())

    def test_central_input_generation_binds_platform_and_source(self):
        identity=dict(platform='linux',hostname=socket.gethostname())
        plan=dict(candidate=dict(source_commit='a'*40,package_sha256='b'*64,offline_fixture=True),
                  execution_id='owned-route-001', environment=dict(native_runtime=dict(identity=identity),
                  manual=dict(schema='fakenet.manual-options.v2',network=dict(ipv4='192.0.2.10',interface='eth0',adapter_guid=None))))
        value=N.manual_inputs(plan,dict(id='GAP-NETWORK-FIX'),self.base/'central')
        self.assertEqual('fakenet.manual-input.v2',value['schema'])
        self.assertEqual('linux',value['platform'])
        self.assertIn('tools/acceptance_linux_recovery.py',value['source_hashes'])


    def test_windows_original_callbacks_do_not_import_linux(self):
        out=self.base/'windows';value=self.inputs(out, 'windows')
        original=builtins.__import__
        def platform_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name=='fakenet.diverters' and set(fromlist or ()) & {'linux','linutil'}:
                raise AssertionError('Windows tried to import Linux producer')
            return original(name,globals,locals,fromlist,level)
        with _fixture(out),mock.patch('builtins.__import__',side_effect=platform_import):
            result=M.run('GAP-NETWORK-FIX',out,value)
        self.assertNotIn('linux',result['network_fix'])
        rows,clean,detail=O.evaluate(ROOT,out,'GAP-NETWORK-FIX',value,allow_fixture=True)
        self.assertTrue(clean,detail)
        self.assertTrue(all(row['status']=='pass' for row in rows))

    def test_start_failure_after_add_recovers_only_owned_route(self):
        import acceptance_linux_recovery as recovery
        from fakenet.diverters import linux, linutil
        out=self.base/'failed-start';value=self.inputs(out);routes=[]
        with _fixture(out):
            old=linutil.subprocess.call
            def call(argv,*a,**kw):
                rc=old(argv,*a,**kw)
                if argv==['route','add','default','gw','192.0.2.10']:
                    routes.append(dict(dst='default',gateway='192.0.2.10',dev='eth0',table='main'))
                return rc
            original=linux.Diverter.startCallback
            def startup(instance):
                original(instance)
                raise RuntimeError('fixture startup failed after original route add')
            def delete(argv):routes.clear();return 0
            with mock.patch.object(linutil.subprocess,'call',side_effect=call),mock.patch.object(linux.Diverter,'startCallback',startup),mock.patch.object(recovery,'route_snapshot',side_effect=lambda:copy.deepcopy(routes)),mock.patch.object(recovery,'route_delete',side_effect=delete):
                result=M.run('GAP-NETWORK-FIX',out,value)
        self.assertEqual([],routes)
        self.assertTrue(result['network_fix']['route']['restored'])
        self.assertIn('fixture startup failed',result['network_fix']['branches']['linux_gateway']['error'])
        self.assertFalse(O.evaluate(ROOT,out,'GAP-NETWORK-FIX',value,allow_fixture=True)[1])

    def test_foreign_row_and_live_writer_are_never_deleted(self):
        import acceptance_linux_recovery as recovery
        row=dict(dst='default',gateway='192.0.2.10',dev='eth0',table=100,metric=9)
        for before,active,quiescent in [([row],[row],True),([],[row],False),([],[row,dict(row,table=101)],True)]:
            with mock.patch.object(recovery,'route_snapshot',return_value=active),mock.patch.object(recovery,'route_delete') as delete:
                result=recovery.recover_route(before,active,active,'192.0.2.10','eth0',True,quiescent)
            self.assertFalse(result['restored'])
            delete.assert_not_called()
        argv=recovery.delete_command(row)
        self.assertEqual(['ip','-4','route','del','default','via','192.0.2.10','dev','eth0','table','100','metric','9'],argv)

    def test_v2_same_central_cli_execute_and_independent_judge(self):
        import acceptance as A
        import acceptance_runtime as runtime
        import acceptance_native as native
        import contextlib,io,subprocess,types
        identity=dict(platform='windows',hostname='fixture-windows')
        candidate=self.base/'candidate.json';environment=self.base/'environment.json'
        candidate.write_text(json.dumps(dict(schema=A.CANDIDATE_V2,source_commit=A.git_head(ROOT),deployed_identity=identity,package_sha256='b'*64,offline_fixture=True)))
        environment.write_text(json.dumps(dict(schema=A.ENVIRONMENT_V2,targets=['windows-vm'],interpreters={'python':sys.executable},work_root=str(self.base),allowed_actions=['native'],endpoints=[],auth_refs=[],native_runtime=dict(transport='local-target',identity=identity),manual=dict(schema='fakenet.manual-options.v2',network=dict(ipv4='192.0.2.10',interface='Ethernet',adapter_guid='{GUID}')))))
        def cli(*args):
            stdout,stderr=io.StringIO(),io.StringIO()
            with contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stderr):code=A.main(['--root',str(ROOT),*map(str,args)])
            return code,stdout.getvalue(),stderr.getvalue()
        plan=self.base/'central-run/plan.json';created=cli('plan','--mode','selected','--case','GAP-NETWORK-FIX','--candidate',candidate,'--environment',environment,'--output',plan)
        self.assertEqual(0,created[0],created)
        class Child:
            pid=998877
            def wait(self,timeout=None):return self.code
        def launch(argv,**kw):
            self.assertEqual(str(ROOT/'tools/acceptance_manual.py'),argv[1])
            output=io.StringIO()
            with contextlib.redirect_stdout(output):code=M.main(argv[2:])
            kw['stdout'].write(output.getvalue().encode());child=Child();child.code=code;return child
        backend=types.SimpleNamespace(**vars(subprocess));backend.Popen=launch
        driver=plan.parent/'results/GAP-NETWORK-FIX/driver'
        with _fixture(driver),mock.patch.object(runtime,'require_target',return_value=identity),mock.patch.object(native,'subprocess',backend):
            ran=cli('execute','--plan',plan)
        self.assertEqual(0,ran[0],ran)
        judged=cli('judge','--plan',plan,'--results',plan.parent/'results','--output',plan.parent/'judged.json')
        self.assertEqual(0,judged[0],judged)
        self.assertFalse(json.loads((plan.parent/'judged.json').read_text())['full_functional_pass'])
        raw=driver/'manual-result.json';value=json.loads(raw.read_text());value['network_fix']['branches']['win_modify']['registry_after']='foreign';raw.write_text(json.dumps(value))
        rejected=cli('judge','--plan',plan,'--results',plan.parent/'results','--output',plan.parent/'rejected.json')
        self.assertNotEqual(0,rejected[0],rejected)


    def test_linux_never_imports_windows_and_preserves_missing_prerequisite(self):
        import acceptance_linux_recovery as recovery
        from fakenet.diverters import linux
        out=self.base/'existing-default';value=self.inputs(out)
        row=dict(dst='default',gateway='192.0.2.1',dev='eth0',table='main')
        original_import=builtins.__import__
        def platform_import(name,globals=None,locals=None,fromlist=(),level=0):
            if name=='fakenet.diverters' and set(fromlist or ()) & {'windows','winutil'}:
                raise AssertionError('Linux tried to import Windows producer')
            return original_import(name,globals,locals,fromlist,level)
        with _fixture(out),mock.patch.object(linux.Diverter,'linux_get_default_gw',return_value='192.0.2.1'),mock.patch.object(recovery,'route_snapshot',return_value=[row]),mock.patch.object(recovery,'route_delete') as delete,mock.patch('builtins.__import__',side_effect=platform_import):
            result=M.run('GAP-NETWORK-FIX',out,value)
        delete.assert_not_called()
        rows,clean,detail=O.evaluate(ROOT,out,'GAP-NETWORK-FIX',value,allow_fixture=True)
        self.assertTrue(clean,detail)
        self.assertEqual('unknown',rows[0]['status'])
        self.assertIn('existing default route preserved',detail['gateway_precondition'])
        self.assertEqual([row],result['network_fix']['route']['before'])


class PhaseDeploymentTests(unittest.TestCase):
    def setUp(self):
        previous_umask=os.umask(0o077)
        self.addCleanup(os.umask,previous_umask)
        import test_acceptance_linux_deploy_update as original
        self.base=Path(os.environ['FN_COMPAT_CHECK_DIR'])/self.id().split('.')[-1]
        self.base.mkdir();self.original=original
        self.package=self.base/'install';self.install_pin=original.build_install_package(self.package)
        self.template=self.base/'template';self.template.mkdir(mode=0o700)
        from acceptance_linux_runtime import _update_module, sha
        updater=_update_module();names={}
        for name in updater.FILES:
            target=self.template/name;target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(('updated '+name+'\n').encode());target.chmod(0o600);names[name]=sha(target)
        (self.template/'update-idle.py').write_bytes((ROOT/'deploy/linux/update-idle.py').read_bytes())
        data=dict(schema='fakenet.linux-update-template.v1',base_manifest=updater.BASE_MANIFEST,
                  source_commit='a'*40,files=names,updater_sha256=sha(self.template/'update-idle.py'),interpreter_sha256='c'*64)
        (self.template/'template.json').write_text(json.dumps(data));self.template_pin=sha(self.template/'template.json')
        for file in self.template.rglob('*'):
            if file.is_file():file.chmod(0o600)
        self.system=self.base/'system';self.system.mkdir(mode=0o700)
        for name in ('opt','etc','etc/systemd','etc/systemd/system'):(self.system/name).mkdir(mode=0o755)

    def inputs(self):
        import acceptance_linux_runtime as L
        pins=['fakenet/mcp/linuxrunner.py','fakenet/diverters/linuxnetpolicy.py','deploy/linux/deploy.sh','deploy/linux/update-idle.py','tools/acceptance_linux_runtime.py','tools/acceptance_linux_runtime_oracles.py','tools/acceptance_linux_recovery.py']
        return dict(schema='fakenet.linux-runtime-input.v3',case='LINUX-DEPLOY-UPDATE',
                    candidate_id='phase-fixture',source_commit='a'*40,package_sha256='b'*64,execution_id='phase-fixture-001',
                    target=dict(platform='linux',hostname=socket.gethostname()),source_hashes={n:L.sha(ROOT/n) for n in pins},
                    owned_root=str(self.base/'output'),system_root=str(self.system),install_package=str(self.package),install_manifest_sha256=self.install_pin,
                    update_template=str(self.template),update_template_sha256=self.template_pin,operation='phase-fixture-001',fixture=True,
                    actions=[],fault='import-start',binding=dict(vm_uuid='fixture-vm',boot_id='fixture-boot',control_services={},control_state={},interpreter_sha256='c'*64,service_argv=[]))

    def provider(self):
        from acceptance_linux_recovery import installation_inventory, remove_created_installation
        test=self
        class Provider:
            fixture=True;owner=os.getuid()
            def __init__(self):self.pid=0;self.created=None;self.commands=[]
            def service(self):return dict(load='loaded' if (test.system/'etc/systemd/system/fakenet-ng-linux.service').exists() else 'not-found',pid=self.pid,active='active' if self.pid else 'inactive')
            def clean(self):
                if installation_inventory(test.system) or self.pid:raise ValueError('fixture target not clean')
                return dict(service=self.service(),paths_absent=['opt/fakenet-ng','etc/fakenet-ng-linux','etc/systemd/system/fakenet-ng-linux.service'])
            def install_run(self,argv):self.commands.append(list(argv));return types.SimpleNamespace(returncode=0,stdout='',stderr='')
            def installed(self,receipt):
                self.pid=4242
                if self.created is None:self.created=installation_inventory(test.system)
                return dict(service=self.service(),process=dict(pid=self.pid,birth='fixture',children=''))
            def preflight(self,manifest):
                if not self.pid:raise ValueError('missing owned fixture service')
                return dict(pid=self.pid,start='fixture')
            def status(self):return dict(state='stopped',run_id=None,controller=None,health=dict(process_alive=False))
            def command(self,argv):
                self.commands.append(list(argv))
                if argv[:2]==['systemctl','stop']:self.pid=0;return ''
                if argv[:2]==['systemctl','start']:
                    if b'FN-OWNED-UPDATE-IMPORT-FAILURE' in (test.system/'opt/fakenet-ng/fakenet/mcp/linuxrunner.py').read_bytes():raise RuntimeError('fixture OS service rejected import failure')
                    self.pid=4243;return ''
                if argv[:2]==['systemctl','show']:return str(self.pid)
                if argv[:2]==['systemctl','is-active']:return 'active' if self.pid else 'inactive'
                raise AssertionError('unexpected fixture command: '+str(argv))
            def quiet(self):return self.pid==0
            def stop(self):self.pid=0;return self.service()
            def started(self):return dict(service=self.service(),process=dict(pid=self.pid,birth='fixture2',children=''))
            def cleanup(self,expected):
                self.pid=0;remove_created_installation(test.system,self.created,expected)
                return dict(service=self.service(),paths_absent=['opt/fakenet-ng','etc/fakenet-ng-linux','etc/systemd/system/fakenet-ng-linux.service'],restored=True)
        return Provider()

    def test_original_install_then_derived_update_and_recovery(self):
        import types,acceptance_linux_runtime as L,acceptance_linux_runtime_oracles as O
        value=self.inputs();provider=self.provider()
        with mock.patch('acceptance_runtime.require_target',return_value=value['target']):record=L.run('LINUX-DEPLOY-UPDATE',value['owned_root'],value,os_boundary=provider)
        self.assertIsNone(record['error'],record)
        rows,clean,detail=O.evaluate(ROOT,value['owned_root'],'LINUX-DEPLOY-UPDATE',expected_inputs=value,allow_fixture=True)
        self.assertTrue(clean,detail)
        self.assertTrue(all(row['status']=='pass' for row in rows),rows)
        self.assertFalse((self.system/'opt/fakenet-ng').exists())
        self.assertEqual(self.template_pin,L.sha(self.template/'template.json'))
        out=Path(value['owned_root']);normal=record['phase']['normal']
        manifest=json.loads((out/normal['package']/'manifest.json').read_text())
        self.assertEqual(record['phase']['token']['inode'],manifest['token_inode'])
        self.assertFalse(O.evaluate(ROOT,out,'LINUX-DEPLOY-UPDATE',expected_inputs=value,allow_fixture=False)[1])
        target=out/normal['package']/'manifest.json';raw=target.read_bytes();changed=json.loads(raw);changed['token_inode']+=1;target.write_text(json.dumps(changed))
        self.assertFalse(O.evaluate(ROOT,out,'LINUX-DEPLOY-UPDATE',expected_inputs=value,allow_fixture=True)[1]);target.write_bytes(raw)

    def test_native_prefix_or_missing_authority_refused_before_output(self):
        import acceptance_linux_runtime as L
        value=self.inputs();value['fixture']=False
        with self.assertRaises(ValueError):L.run('LINUX-DEPLOY-UPDATE',value['owned_root'],value)
        self.assertFalse(Path(value['owned_root']).exists())

    def test_clean_precondition_failure_has_no_install(self):
        import acceptance_linux_runtime as L
        value=self.inputs();(self.system/'opt/fakenet-ng').mkdir();p=self.provider()
        with mock.patch('acceptance_runtime.require_target',return_value=value['target']),self.assertRaises(ValueError):L.run('LINUX-DEPLOY-UPDATE',value['owned_root'],value,os_boundary=p)
        self.assertFalse(Path(value['owned_root']).exists());self.assertEqual([],p.commands)

    def test_phase_same_central_cli_and_changed_restoration_rejected(self):
        import acceptance as A
        import acceptance_native as native
        import acceptance_linux_runtime as L
        import acceptance_runtime as runtime
        import subprocess,io,hashlib
        value=self.inputs()
        head=A.git_head(ROOT)
        template=json.loads((self.template/'template.json').read_text());template['source_commit']=head
        (self.template/'template.json').write_text(json.dumps(template))
        value['source_commit']=head;value['update_template_sha256']=L.sha(self.template/'template.json')
        self.system=self.base/'central-run/results/LINUX-DEPLOY-UPDATE/system'
        value['system_root']=str(self.system)
        provider=self.provider()
        fields=('system_root','install_package','install_manifest_sha256','update_template','update_template_sha256','operation','fault','binding')
        options={key:value[key] for key in fields};options['schema']='fakenet.linux-deploy-options.v2'
        candidate=self.base/'candidate.json';environment=self.base/'environment.json'
        candidate.write_text(json.dumps(dict(schema=A.CANDIDATE_V2,candidate_id=value['candidate_id'],source_commit=head,package_sha256='b'*64,offline_fixture=True,deployed_identity=value['target'])))
        environment.write_text(json.dumps(dict(schema=A.ENVIRONMENT_V2,targets=['host-linux'],interpreters={'python':sys.executable},endpoints=[],auth_refs=[],work_root=str(self.base),allowed_actions=['native'],native_runtime=dict(transport='local-target',identity=value['target']),linux=options)))
        def cli(*args):
            out,err=io.StringIO(),io.StringIO()
            with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):code=A.main(['--root',str(ROOT),*map(str,args)])
            return code,out.getvalue(),err.getvalue()
        plan=self.base/'central-run/plan.json'
        result=cli('plan','--mode','selected','--case','LINUX-DEPLOY-UPDATE','--candidate',candidate,'--environment',environment,'--output',plan)
        self.assertEqual(0,result[0],result)
        real_run=L.run
        def fixture_run(*args,**kwargs):kwargs['os_boundary']=provider;return real_run(*args,**kwargs)
        class Child:
            pid=999991
            def wait(self,timeout=None):return self.code
        def launch(argv,**kwargs):
            for name in ('','opt','etc','etc/systemd','etc/systemd/system'):(self.system/name).mkdir(mode=0o755,parents=True,exist_ok=True)
            self.assertEqual(str(ROOT/'tools/acceptance_linux_runtime.py'),argv[1])
            out=io.StringIO()
            with mock.patch.object(L,'run',side_effect=fixture_run),contextlib.redirect_stdout(out):code=L.main(argv[2:])
            kwargs['stdout'].write(out.getvalue().encode());child=Child();child.code=code;return child
        backend=types.SimpleNamespace(**vars(subprocess));backend.Popen=launch
        with mock.patch.object(runtime,'require_target',return_value=value['target']),mock.patch.object(native,'subprocess',backend):result=cli('execute','--plan',plan)
        self.assertEqual(0,result[0],result)
        judged=cli('judge','--plan',plan,'--results',plan.parent/'results','--output',self.base/'judged.json')
        self.assertEqual(0,judged[0],judged)
        self.assertFalse(json.loads((self.base/'judged.json').read_text())['full_functional_pass'])
        folder=plan.parent/'results/LINUX-DEPLOY-UPDATE/driver';path=folder/'restored/fakenet/mcp/linuxrunner.py'
        path.write_bytes(b'foreign restoration')
        record=json.loads((folder/'linux-result.json').read_text());record['originals'][path.relative_to(folder).as_posix()]=hashlib.sha256(path.read_bytes()).hexdigest()
        (folder/'linux-result.json').write_text(json.dumps(record))
        rejected=cli('judge','--plan',plan,'--results',plan.parent/'results','--output',self.base/'rejected.json')
        self.assertNotEqual(0,rejected[0],rejected)

    def test_failure_recovery_refuses_foreign_source_and_live_owner(self):
        import acceptance_linux_runtime as L
        from acceptance_linux_recovery import recover_published_update
        value=self.inputs();provider=self.provider()
        with mock.patch('acceptance_runtime.require_target',return_value=value['target']):record=L.run('LINUX-DEPLOY-UPDATE',value['owned_root'],value,os_boundary=provider)
        self.assertIsNone(record['error'],record.get('error'))
        # Recreate only the two failed targets from preserved published originals.
        out=Path(value['owned_root']);target=self.system/'opt/fakenet-ng'
        for name in record['phase']['fault']['published']:
            path=target/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes((out/record['phase']['fault']['published'][name]['path']).read_bytes())
        receipt=self.system/'opt/.fakenet-update-phase-fixture-001-fault/receipt.json'
        failed=json.loads(receipt.read_text())
        for name,row in failed['originals'].items():(target/name).chmod(row['mode'])
        package=out/'derived/fault';before=receipt.read_bytes()
        with self.assertRaisesRegex(ValueError,'quiescent'):recover_published_update(receipt,self.system,package,lambda:False)
        path=target/'fakenet/mcp/linuxrunner.py';path.write_bytes(b'foreign drift')
        with self.assertRaisesRegex(ValueError,'foreign source drift'):recover_published_update(receipt,self.system,package,lambda:True)
        self.assertEqual(b'foreign drift',path.read_bytes());self.assertEqual(before,receipt.read_bytes())
