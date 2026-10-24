"""Original callbacks with platform-local imports and an owned route model."""
import builtins
import contextlib
import copy
import json
import os
from pathlib import Path
import socket
import sys
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
