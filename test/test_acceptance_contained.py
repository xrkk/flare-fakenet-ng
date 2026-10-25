"""Contained preparation must preserve ownership, failures and original verdicts."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
spec = importlib.util.spec_from_file_location('contained', ROOT/'tools/acceptance_contained.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ContainedTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root/'Logs').mkdir()
        self.output = self.root/'Logs/run'

    def controller(self):
        with mock.patch.object(m.os, 'getuid', return_value=1000):
            return m.Controller(self.root, self.output, 'linux')

    def test_output_rejects_existing_link_and_source_paths_before_create(self):
        outside = self.root/'tools'
        outside.mkdir()
        linked = self.root/'Logs/link'
        linked.symlink_to(outside, target_is_directory=True)
        for path in [self.root, self.root/'Logs', outside/'run', linked/'run']:
            with self.subTest(path=path), mock.patch.object(m.subprocess, 'run') as call:
                with self.assertRaises(ValueError):
                    m.Controller(self.root, path)
                call.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_unknown_profile_and_wrong_uid_do_not_create_output(self):
        with self.assertRaises(ValueError):
            m.Controller(self.root, self.output, 'arbitrary-module')
        with mock.patch.object(m.os, 'getuid', return_value=0):
            with self.assertRaises(ValueError):
                m.Controller(self.root, self.output)
        self.assertFalse(self.output.exists())

    def test_source_snapshot_uses_nul_paths_and_rejects_changed_bytes(self):
        name = '非ASCII 文件.py'
        p = self.root/name
        p.write_bytes(b'original')
        import hashlib
        blob = hashlib.sha1(b'blob 8\0original').hexdigest()
        tree = ('100644 blob '+blob+'\t'+name+'\0').encode()
        def git(*args):
            return b'a'*40 if args[0] == 'rev-parse' else tree
        commit, hashes = m.source_snapshot(self.root, git)
        self.assertEqual('a'*40, commit)
        self.assertEqual({name: m.digest(p)}, hashes)
        p.write_bytes(b'drift')
        with self.assertRaisesRegex(ValueError, 'differs'):
            m.source_snapshot(self.root, git)

    def test_create_uncertainty_retains_exact_cid_for_owned_cleanup(self):
        c = self.controller()
        cid = 'a'*64
        def fail(name, argv, **kwargs):
            (c.output/'container.cid').write_text(cid)
            raise RuntimeError('create response lost')
        with mock.patch.object(c, 'call', side_effect=fail):
            with self.assertRaisesRegex(RuntimeError, 'lost'):
                c.create()
        self.assertEqual(cid, c.cid)

    def test_wrong_owner_refuses_stop_and_remove(self):
        c = self.controller()
        c.cid = 'b'*64
        observed = {'Id':c.cid, 'Image':m.IMAGE,
                    'Config':{'Labels':{m.LABEL:'someone-else'}}}
        with mock.patch.object(c, 'call', return_value=json.dumps([observed])) as call:
            with self.assertRaisesRegex(ValueError, 'ownership'):
                c.cleanup()
        self.assertEqual(['inspect'], [a.args[0] for a in call.call_args_list])

    def test_cleanup_proves_exit_before_remove(self):
        c = self.controller()
        c.cid = 'c'*64
        running = {'State':{'Running':True,'Pid':21}}
        stopped = {'State':{'Running':False,'Pid':0}}
        with mock.patch.object(c, 'inspect', side_effect=[running, stopped]), mock.patch.object(c, 'call') as call:
            self.assertEqual('stopped_and_removed',c.cleanup()['status'])
            self.assertEqual(['stop','remove'],[a.args[0] for a in call.call_args_list])
        self.assertEqual(stopped,json.loads((c.output/'stopped.json').read_text()))

    def test_still_running_is_not_removed(self):
        c = self.controller()
        c.cid = 'd'*64
        with mock.patch.object(c, 'inspect', return_value={'State':{'Running':True,'Pid':21}}), mock.patch.object(c, 'call') as call:
            with self.assertRaisesRegex(ValueError, 'did not stop'):
                c.cleanup()
            self.assertEqual(['stop'],[a.args[0] for a in call.call_args_list])

    def test_timeout_preserves_bytes_and_never_returns_success(self):
        c = self.controller()
        error = subprocess.TimeoutExpired(['fixed'],1,output=b'partial',stderr=b'failed')
        with mock.patch.object(m.subprocess,'run',side_effect=error):
            with self.assertRaisesRegex(RuntimeError,'124'):
                c.call('test',['fixed'])
        self.assertEqual(b'partial',(self.output/'01-test.stdout').read_bytes())
        self.assertEqual(124,c.record['commands'][0]['returncode'])

    def test_setup_failure_is_closed_and_cleanup_failure_wins(self):
        c = self.controller()
        with mock.patch.object(m,'source_snapshot',side_effect=ValueError('source drift')), mock.patch.object(c,'cleanup',side_effect=ValueError('owner changed')):
            self.assertEqual(3,c.run())
        result=json.loads((self.output/'run.json').read_text())
        self.assertEqual('source drift',result['error'])
        self.assertEqual('owner changed',result['cleanup_error'])
        self.assertEqual('cleanup_failed',result['status'])
        self.assertFalse(result['full_functional_pass'])

    def test_missing_image_failure_has_no_container_to_stop(self):
        c = self.controller()
        with mock.patch.object(m,'source_snapshot',return_value=('a'*40,{'source':'hash'})), mock.patch.object(c,'call',return_value=b'[]') as call:
            self.assertEqual(3,c.run())
        self.assertIsNone(c.cid)
        self.assertEqual(['image'],[a.args[0] for a in call.call_args_list])
        result=json.loads((self.output/'run.json').read_text())
        self.assertEqual('no_known_container',result['cleanup']['status'])

    def test_actual_boundary_rejects_writable_source(self):
        c = self.controller()
        value={'HostConfig':{'NetworkMode':'none','ReadonlyRootfs':True,'CapDrop':['ALL'],
               'SecurityOpt':['no-new-privileges'],'PidsLimit':256,'Memory':2*1024**3,'NanoCpus':2*10**9},
               'Config':{'User':'1000:1000'},'Mounts':[]}
        for source,dest in [(c.root,'/workspace'),(c.root,str(c.root)),(c.controls,'/run-control'),(c.evidence,'/out')]:
            value['Mounts'].append({'Type':'bind','Source':str(source),'Destination':dest,'RW':dest=='/out'})
        c.verify_boundary(value)
        value['Mounts'][0]['RW']=True
        with self.assertRaisesRegex(ValueError,'mount differs'):
            c.verify_boundary(value)

    def test_unknown_create_outcome_is_not_reported_clean(self):
        c = self.controller()
        c.creation_attempted = True
        with self.assertRaisesRegex(ValueError,'outcome unknown'):
            c.cleanup()

    def test_existing_cli_dispatches_only_finite_preset(self):
        import acceptance
        with mock.patch('acceptance_contained.launch',return_value=3) as launch:
            self.assertEqual(3,acceptance.main(['--root',str(self.root),'contained-offline','--profile','linux']))
        launch.assert_called_once_with(self.root,None,'linux')

    def test_run_failures_at_each_stage_preserve_failure_and_owned_cleanup(self):
        for stage in ['prepare','linux-plan','linux-execute','linux-judge']:
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as directory:
                root=Path(directory)
                (root/'Logs').mkdir()
                python=root/'.venv-mcp-runners/bin/python'
                python.parent.mkdir(parents=True)
                python.write_text('interpreter')
                with mock.patch.object(m.os,'getuid',return_value=1000):
                    c=m.Controller(root,root/'Logs/run','linux')
                def execute(name,args,**kwargs):
                    if name==stage:raise RuntimeError(stage+' original failure')
                    if name=='prepare':
                        m.save(c.evidence/'runtime.json',{'linux-contained-v1':{'path':str(python)}})
                with mock.patch.object(m,'source_snapshot',return_value=('a'*40,{'f':'hash'})), mock.patch.object(c,'call',return_value=json.dumps([{'Id':m.IMAGE}]).encode()), mock.patch.object(c,'create'), mock.patch.object(c,'exec',side_effect=execute), mock.patch.object(c,'cleanup',return_value={'status':'stopped_and_removed'}) as clean:
                    self.assertEqual(3,c.run())
                clean.assert_called_once()
                record=json.loads((c.output/'run.json').read_text())
                self.assertEqual(stage+' original failure',record['error'])
                self.assertEqual('failed',record['status'])
                self.assertFalse(record['full_functional_pass'])

    def test_internal_prepare_refuses_uncontained_environment(self):
        with mock.patch.object(Path,'read_text',return_value='{"profiles":["linux"],"python":"/fake"}'), mock.patch('acceptance._contained_kernel',side_effect=ValueError('not contained')):
            with self.assertRaisesRegex(ValueError,'not contained'):
                m.prepare()


if __name__ == '__main__':
    unittest.main()
