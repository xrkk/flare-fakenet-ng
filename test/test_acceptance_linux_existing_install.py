"""Existing-installation (v4) acceptance contracts; benign OS boundary only.

The producer runs inside an owned fixture system root through an explicit
isolated provider, and the independent v4 consumer recomputes the raw evidence.
No root, network, service, VM or real installation change happens here.
"""
import contextlib
import hashlib
import io
import json
import os
import socket
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import acceptance as A
import acceptance_linux_recovery as recovery
import acceptance_linux_runtime as L
import acceptance_linux_runtime_oracles as O
import acceptance_native as native

FILES = ('fakenet/mcp/linuxrunner.py', 'fakenet/diverters/linuxnetpolicy.py')
PIN_NAMES = ['fakenet/mcp/linuxrunner.py', 'fakenet/diverters/linuxnetpolicy.py',
             'deploy/linux/deploy.sh', 'deploy/linux/update-idle.py',
             'tools/acceptance_linux_runtime.py', 'tools/acceptance_linux_runtime_oracles.py',
             'tools/acceptance_linux_recovery.py']


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class ExistingInstallationTests(unittest.TestCase):
    def setUp(self):
        previous = os.umask(0o077)
        self.addCleanup(os.umask, previous)
        self.base = Path(os.environ['FN_COMPAT_CHECK_DIR']) / self.id().split('.')[-1]
        self.base.mkdir(parents=True, exist_ok=False, mode=0o700)
        self.system = self.base / 'system'
        self.system.mkdir(mode=0o700)
        self.build_installation('installed')

    def build_installation(self, text):
        for name in ('opt/fakenet-ng/fakenet/mcp', 'opt/fakenet-ng/fakenet/diverters',
                     'opt/fakenet-ng/fakenet/configs', 'etc/fakenet-ng-linux',
                     'etc/systemd/system'):
            (self.system / name).mkdir(mode=0o700, parents=True, exist_ok=True)
        self.installed = {}
        for name in FILES:
            path = self.system / 'opt/fakenet-ng' / name
            path.write_bytes((text + ' ' + name + '\n').encode())
            path.chmod(0o600)
            self.installed[name] = _sha(path)
        self.config = self.system / 'opt/fakenet-ng/fakenet/configs/default.ini'
        self.config.write_text('[Diverter]\nLinuxFlushIptables: No\nFixGateway: No\n'
                               'FixDNS: No\nModifyLocalDNS: No\nStopDNSService: No\n')
        self.config.chmod(0o600)
        self.unit = self.system / 'etc/systemd/system/fakenet-ng-linux.service'
        self.unit.write_text('[Service]\nExecStart=/usr/bin/python3 -m fakenet.mcp.linuxrunner\n')
        self.unit.chmod(0o600)
        self.token = self.system / 'etc/fakenet-ng-linux/token'
        self.token.write_bytes(b'a' * 64 + b'\n')
        self.token.chmod(0o600)
        state = self.token.stat()
        self.token_row = dict(inode=state.st_ino, mode=0o600, sha256=_sha(self.token))
        self.interpreter = 'c' * 64
        self.argv = ['-m', 'fakenet.mcp.linuxrunner']
        self.template = self.base / 'template'
        if not self.template.exists():
            self.template.mkdir(mode=0o700)
            for name in FILES:
                target = self.template / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(('updated ' + name + '\n').encode())
                target.chmod(0o600)
            (self.template / 'update-idle.py').write_bytes((ROOT / 'deploy/linux/update-idle.py').read_bytes())
            (self.template / 'update-idle.py').chmod(0o600)
            files = {name: _sha(self.template / name) for name in FILES}
            data = dict(schema='fakenet.linux-update-template.v1',
                        base_manifest=L._update_module().BASE_MANIFEST,
                        source_commit='a' * 40, files=files,
                        updater_sha256=_sha(self.template / 'update-idle.py'),
                        interpreter_sha256=self.interpreter)
            path = self.template / 'template.json'
            path.write_text(json.dumps(data))
            path.chmod(0o600)
        self.template_pin = _sha(self.template / 'template.json')

    def inputs(self, name='output', fault='import-start'):
        existing = dict(sources=dict(self.installed),
                        unit_sha256=_sha(self.unit), config_sha256=_sha(self.config),
                        credential=dict(self.token_row),
                        service=dict(pid=4210, birth='fixture-birth', argv=list(self.argv),
                                     interpreter_sha256=self.interpreter))
        return dict(schema=L.EXISTING_SCHEMA, case='LINUX-DEPLOY-UPDATE',
                    candidate_id='existing-fixture', source_commit='a' * 40,
                    package_sha256='b' * 64, execution_id='existing-fixture-001',
                    target=dict(platform='linux', hostname=socket.gethostname()),
                    source_hashes={n: L.sha(ROOT / n) for n in PIN_NAMES},
                    owned_root=str(self.base / name), system_root=str(self.system),
                    update_template=str(self.template), update_template_sha256=self.template_pin,
                    operation='existing-fixture-001', fixture=True, actions=[],
                    fault=fault,
                    binding=dict(vm_uuid='fixture-vm', boot_id='fixture-boot',
                                 control_services={}, control_state={},
                                 interpreter_sha256=self.interpreter, service_argv=list(self.argv)),
                    existing_installation=existing, first_install_not_tested=True)

    def provider(self):
        test = self

        class Provider:
            fixture = True
            owner = os.getuid()

            def __init__(self):
                self.pid = 4210
                self.commands = []
                self.copies = {}
                self.expected = None

            def observe_existing(self):
                inventory = recovery.installation_inventory(test.system)
                sources = {name: inventory['opt/fakenet-ng/' + name]['sha256'] for name in FILES}
                if self.expected is not None:
                    service = self.expected['service']
                    if (service['pid'] != self.pid or service['birth'] != 'fixture-birth'
                            or service['argv'] != list(test.argv)
                            or service['interpreter_sha256'] != test.interpreter):
                        raise ValueError('existing installation process identity differs from the frozen observation')
                    state = test.token.stat()
                    observed = dict(inode=state.st_ino, mode=0o600, sha256=_sha(test.token))
                    if (self.expected['sources'] != sources
                            or self.expected['unit_sha256'] != _sha(test.unit)
                            or self.expected['config_sha256'] != _sha(test.config)
                            or self.expected['credential'] != observed):
                        raise ValueError('existing installation source/unit/configuration/credential differs')
                for name in FILES:
                    self.copies[name] = (test.system / 'opt/fakenet-ng' / name).read_bytes()
                state = test.token.stat()
                credential = dict(inode=state.st_ino, mode=0o600, sha256=_sha(test.token))
                return dict(machine={}, service=dict(load='loaded', pid=self.pid, active='active'),
                            process=dict(pid=self.pid, birth='fixture-birth', argv=list(test.argv),
                                         interpreter_sha256=test.interpreter, children=''),
                            credential=credential, sources=sources,
                            unit_sha256=_sha(test.unit), config_sha256=_sha(test.config),
                            first_install_not_tested=True)

            def baseline_receipt(self, destination, operation):
                observation = self.observe_existing()
                directory = test.system / 'opt' / ('.fakenet-existing-baseline-' + operation)
                directory.mkdir(mode=0o700)
                path = directory / 'baseline.json'
                receipt = dict(schema='fakenet.linux-existing-install-baseline.v1',
                               baseline_kind='existing-install', first_install_tested=False,
                               phase='existing-observed', operation=operation,
                               sources=dict(observation['sources']),
                               files={name: None for name in FILES},
                               installed_files={
                                   'opt/fakenet-ng/fakenet/configs/default.ini': _sha(test.config),
                                   'etc/fakenet-ng-linux/token': observation['credential']['sha256'],
                                   'etc/systemd/system/fakenet-ng-linux.service': _sha(test.unit)},
                               credential=observation['credential'], manifest_sha256=None,
                               provenance={'kind': 'named-existing-install-baseline',
                                           'observed_at': '2026-11-02T00:00:00+00:00',
                                           'observed_by': 'fixture'})
                path.write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
                path.chmod(0o600)
                return path

            def service(self):
                return dict(load='loaded', pid=self.pid, active='active' if self.pid else 'inactive')

            def command(self, argv):
                self.commands.append(list(argv))
                if argv[:2] == ['systemctl', 'stop']:
                    self.pid = 0
                    return ''
                if argv[:2] == ['systemctl', 'start']:
                    if b'FN-OWNED-UPDATE-IMPORT-FAILURE' in (test.system / 'opt/fakenet-ng/fakenet/mcp/linuxrunner.py').read_bytes():
                        raise RuntimeError('fixture OS service rejected import failure')
                    self.pid = 4211
                    return ''
                if argv[:2] == ['systemctl', 'show']:
                    return str(self.pid)
                if argv[:2] == ['systemctl', 'is-active']:
                    return 'active' if self.pid else 'inactive'
                raise AssertionError('unexpected fixture command: ' + str(argv))

            def preflight(self, manifest):
                if not self.pid:
                    raise ValueError('missing fixture installation service')
                return dict(pid=self.pid, birth='fixture-birth')

            def status(self):
                return dict(state='stopped', run_id=None, controller=None,
                            health=dict(process_alive=False))

            def started(self):
                return dict(service=self.service(),
                            process=dict(pid=self.pid, birth='fixture-birth', argv=list(test.argv),
                                         interpreter_sha256=test.interpreter, children=''))

            def quiet(self):
                return self.pid == 0

            def stop(self):
                self.pid = 0
                return self.service()

            def cleanup_own(self, baseline_sources, published_sources):
                for name, want in baseline_sources.items():
                    path = test.system / 'opt/fakenet-ng' / name
                    path.write_bytes(self.copies[name])
                    path.chmod(0o600)
                    if _sha(path) != want:
                        raise ValueError('owned existing source restore differs')
                self.pid = 4211
                state = test.token.stat()
                if dict(inode=state.st_ino, mode=0o600, sha256=_sha(test.token)) != test.token_row:
                    raise ValueError('installed credential identity changed after owned restore')
                return dict(restored=True, installation_preserved=True,
                            preserved_paths=['opt/fakenet-ng', 'etc/fakenet-ng-linux',
                                             'etc/systemd/system/fakenet-ng-linux.service'],
                            restored_sources=dict(baseline_sources), service=self.service(),
                            credential=test.token_row, first_install_not_tested=True)
        return Provider()

    def run_case(self, name='output', fault='import-start', provider=None):
        value = self.inputs(name, fault)
        provider = provider or self.provider()
        if hasattr(provider, 'expected'):
            provider.expected = value['existing_installation']
        with mock.patch('acceptance_runtime.require_target', return_value=value['target']):
            record = L.run('LINUX-DEPLOY-UPDATE', value['owned_root'], value, os_boundary=provider)
        return value, provider, record

    def test_existing_install_positive_and_owned_restore(self):
        value, provider, record = self.run_case()
        self.assertIsNone(record['error'], record.get('error'))
        self.assertTrue(record['first_install_not_tested'])
        self.assertIn('first install not tested', record['scope'])
        rows, clean, detail = O.evaluate(ROOT, value['owned_root'], 'LINUX-DEPLOY-UPDATE',
                                         expected_inputs=value, allow_fixture=True)
        self.assertTrue(clean, detail)
        self.assertEqual(L.EXISTING_CHECKS, [row['id'] for row in rows])
        self.assertTrue(all(row['status'] == 'pass' for row in rows), rows)
        self.assertTrue(record['cleanup']['installation_preserved'])
        self.assertEqual(self.token_row, record['cleanup']['credential'])
        self.assertTrue((self.system / 'opt/fakenet-ng').exists())
        self.assertEqual(self.installed,
                         {name: _sha(self.system / 'opt/fakenet-ng' / name) for name in FILES})
        self.assertFalse(O.evaluate(ROOT, value['owned_root'], 'LINUX-DEPLOY-UPDATE',
                                    expected_inputs=value, allow_fixture=False)[1])

    def test_drift_forged_and_changed_restoration_are_refused(self):
        value, provider, record = self.run_case('drift')
        out = Path(value['owned_root'])
        mutations = {
            'source': lambda v: v['existing_installation']['sources'].update({FILES[0]: '0' * 64}),
            'credential': lambda v: v['existing_installation']['credential'].update(sha256='1' * 64),
            'unit': lambda v: v['existing_installation'].update(unit_sha256='2' * 64),
            'config': lambda v: v['existing_installation'].update(config_sha256='3' * 64),
            'scope': lambda v: v.update(first_install_not_tested=False),
            'service': lambda v: v['existing_installation']['service'].update(pid=1),
        }
        for label, mutate in mutations.items():
            with self.subTest(field=label):
                broken = self.inputs('drift-' + label)
                mutate(broken)
                provider = self.provider()
                provider.expected = broken['existing_installation']
                with mock.patch('acceptance_runtime.require_target', return_value=broken['target']), \
                        self.assertRaises(ValueError):
                    L.run('LINUX-DEPLOY-UPDATE', broken['owned_root'], broken, os_boundary=provider)
                self.assertFalse(Path(broken['owned_root']).exists())
        result = out / 'linux-result.json'
        raw = result.read_bytes()
        forged = json.loads(raw)
        forged['checks'] = ['install', 'idle-update', 'transaction', 'token', 'rollback']
        result.write_text(json.dumps(forged))
        self.assertFalse(O.evaluate(ROOT, out, 'LINUX-DEPLOY-UPDATE',
                                    expected_inputs=value, allow_fixture=True)[1])
        result.write_bytes(raw)
        restored = out / record['phase']['recovery']['observed'][FILES[0]]['path']
        saved = restored.read_bytes()
        restored.write_bytes(b'foreign restoration')
        self.assertFalse(O.evaluate(ROOT, out, 'LINUX-DEPLOY-UPDATE',
                                    expected_inputs=value, allow_fixture=True)[1])
        restored.write_bytes(saved)
        self.assertTrue(O.evaluate(ROOT, out, 'LINUX-DEPLOY-UPDATE',
                                   expected_inputs=value, allow_fixture=True)[1])

    def _real_provider(self, root, inputs, commands=None):
        from acceptance_linux_recovery import ExistingInstallation
        commands = commands if commands is not None else []
        inputs = dict(inputs, actions=['native', 'linux-install', 'linux-service', 'linux-fault-recovery'])
        with mock.patch.object(ExistingInstallation, 'require_root_user', False), \
                mock.patch.object(ExistingInstallation, 'required_root', str(root)):
            provider = ExistingInstallation(inputs)
        provider.command = lambda argv: commands.append(list(argv))
        provider.quiet = lambda: True
        provider._process = lambda pid: dict(pid=pid, birth='fixture-birth', argv=list(self.argv),
                                             interpreter_sha256=self.interpreter, children='')
        provider.service = lambda: dict(load='loaded', pid=4210, active='active')
        provider.machine = lambda: {}
        return provider

    def test_real_provider_post_restart_state_and_checked_cleanup(self):
        """F1/F2: the REAL production provider must restart and must refuse
        foreign bytes before any service action or write."""
        value = self.inputs('real-provider')
        commands = []
        provider = self._real_provider(self.system, value, commands)
        provider.baseline = dict(inventory=recovery.installation_inventory(self.system),
                                 sources=dict(self.installed), service=dict(load='loaded', pid=4210, active='active'),
                                 process=dict(pid=4210, birth='fixture-birth', argv=list(self.argv),
                                              interpreter_sha256=self.interpreter),
                                 credential=self.token_row, unit_sha256=_sha(self.unit),
                                 config_sha256=_sha(self.config))
        provider._baseline_copy = {name: (self.system / 'opt/fakenet-ng' / name).read_bytes() for name in FILES}
        provider._baseline_mode = {name: 0o600 for name in FILES}
        # F1: the post-restart observation must work on the real class state.
        started = provider.started()
        self.assertEqual(4210, started['service']['pid'])
        # F2 drift: foreign bytes must be refused untouched, with no command.
        target = self.system / 'opt/fakenet-ng' / FILES[0]
        target.write_bytes(b'foreign drift')
        foreign = target.read_bytes()
        with self.assertRaisesRegex(ValueError, 'foreign existing source bytes'):
            provider.cleanup_own(dict(self.installed), {FILES[0]: 'f' * 64, FILES[1]: 'e' * 64})
        self.assertEqual([], commands)
        self.assertEqual(foreign, target.read_bytes())
        # restore the published update state and perform the owned cleanup
        published = {}
        for name in FILES:
            path = self.system / 'opt/fakenet-ng' / name
            path.write_bytes(('updated ' + name + '\n').encode())
            published[name] = _sha(path)
        result = provider.cleanup_own(dict(self.installed), published)
        self.assertTrue(result['restored'])
        self.assertTrue(result['installation_preserved'])
        self.assertEqual(self.installed,
                         {name: _sha(self.system / 'opt/fakenet-ng' / name) for name in FILES})
        self.assertIn(['systemctl', 'stop', 'fakenet-ng-linux.service'], commands)
        self.assertIn(['systemctl', 'start', 'fakenet-ng-linux.service'], commands)

    def _real_cleanup(self, value, provider):
        from acceptance_linux_recovery import ExistingInstallation
        real = object.__new__(ExistingInstallation)
        real.root = self.system; real.unit = 'fakenet-ng-linux.service'
        real.expected = value['existing_installation']
        real._baseline_copy = {n: (self.system / 'opt/fakenet-ng' / n).read_bytes() for n in FILES}
        real._baseline_mode = {n: 0o600 for n in FILES}
        real.baseline = {'inventory': recovery.installation_inventory(self.system)}
        real.command = provider.command; real.quiet = provider.quiet; real.service = provider.service
        return real.cleanup_own

    def test_actual_caller_rejects_foreign_bytes_before_cleanup(self):
        """F2 caller: foreign bytes injected AFTER the normal update completed
        must be preserved and rejected before any cleanup command/write."""
        value = self.inputs('caller-foreign')
        provider = self.provider(); provider.expected = value['existing_installation']
        provider.cleanup_own = self._real_cleanup(value, provider)
        original_status = provider.status
        target = self.system / 'opt/fakenet-ng' / FILES[0]
        marker = b'FOREIGN-BYTES-NOT-PUBLISHED-BY-THIS-OPERATION\n'
        state = {'injected': False, 'commands': None}

        def status():
            result = original_status()
            receipt = self.system / 'opt' / ('.fakenet-update-' + value['operation'] + '-normal') / 'receipt.json'
            if (not state['injected'] and receipt.exists()
                    and json.loads(receipt.read_text()).get('phase') == 'completed'):
                target.write_bytes(marker)
                state['injected'] = True
                state['commands'] = len(provider.commands)
            return result
        provider.status = status
        value, provider, record = self.run_case('caller-foreign', provider=provider)
        self.assertTrue(state['injected'])
        self.assertEqual(marker, target.read_bytes())
        self.assertFalse(record['cleanup'].get('restored'))
        self.assertTrue(record['cleanup'].get('preserved_installation', True))
        after = len(provider.commands) - (state['commands'] or 0)
        self.assertEqual(0, after, provider.commands)

    def test_source_change_during_stop_is_rejected_before_overwrite(self):
        value = self.inputs('stop-drift')
        provider = self.provider(); provider.expected = value['existing_installation']
        provider.cleanup_own = self._real_cleanup(value, provider)
        original_command = provider.command
        target = self.system / 'opt/fakenet-ng' / FILES[1]

        def command(argv):
            answer = original_command(argv)
            if argv[:2] == ['systemctl', 'stop']:
                target.write_bytes(b'LATE-STOP-DRIFT')
            return answer
        provider.command = command
        value, provider, record = self.run_case('stop-drift', provider=provider)
        self.assertFalse(record['cleanup'].get('restored'))
        self.assertEqual(b'LATE-STOP-DRIFT', target.read_bytes())

    def test_consumer_requires_final_process_and_machine_evidence(self):
        value, provider, record = self.run_case('consumer-negatives')
        result = Path(value['owned_root']) / 'linux-result.json'
        raw = result.read_bytes()
        base = json.loads(raw)

        def rejected(changed):
            result.write_text(json.dumps(changed))
            try:
                rows, clean, detail = O.evaluate(ROOT, value['owned_root'], 'LINUX-DEPLOY-UPDATE',
                                                 expected_inputs=value, allow_fixture=True)
            finally:
                result.write_bytes(raw)
            return not clean
        self.assertTrue(O.evaluate(ROOT, value['owned_root'], 'LINUX-DEPLOY-UPDATE',
                                   expected_inputs=value, allow_fixture=True)[1])
        mutations = {
            'missing-process': lambda v: v['phase']['cleanup_observed'].__setitem__('process', None),
            'wrong-pid': lambda v: v['phase']['cleanup_observed']['process'].__setitem__('pid', 1),
            'empty-birth': lambda v: v['phase']['cleanup_observed']['process'].__setitem__('birth', ''),
            'wrong-argv': lambda v: v['phase']['cleanup_observed']['process'].__setitem__('argv', ['foreign']),
            'wrong-interpreter': lambda v: v['phase']['cleanup_observed']['process'].__setitem__('interpreter_sha256', '0' * 64),
            'children': lambda v: v['phase']['cleanup_observed']['process'].__setitem__('children', '4242'),
            'foreign-machine': lambda v: v['phase']['cleanup_observed'].__setitem__('machine', {'FOREIGN_NETWORK_STATE': True}),
        }
        for label, mutate in mutations.items():
            with self.subTest(field=label):
                changed = json.loads(raw)
                mutate(changed)
                self.assertTrue(rejected(changed), label)

    def _central_environment(self, name):
        head = A.git_head(ROOT)
        template = json.loads((self.template / 'template.json').read_text())
        template['source_commit'] = head
        (self.template / 'template.json').write_text(json.dumps(template))
        self.template_pin = _sha(self.template / 'template.json')
        # The fixture installation lives outside the empty central run dir so
        # the frozen binding (token inode) is known before the plan.
        self.system = self.base / (name + '-system')
        self.build_installation('installed')
        value = self.inputs(name)
        value['source_commit'] = head
        value['update_template_sha256'] = self.template_pin
        value['system_root'] = str(self.system)
        fields = ('system_root', 'update_template', 'update_template_sha256', 'operation',
                  'fault', 'binding', 'existing_installation', 'first_install_not_tested')
        options = {key: value[key] for key in fields}
        options['schema'] = 'fakenet.linux-deploy-options.v3'
        candidate = self.base / (name + '-candidate.json')
        environment = self.base / (name + '-environment.json')
        candidate.write_text(json.dumps(dict(schema=A.CANDIDATE_V2, candidate_id=value['candidate_id'],
                                             source_commit=head, package_sha256='b' * 64,
                                             offline_fixture=True, deployed_identity=value['target'])))
        environment.write_text(json.dumps(dict(
            schema=A.ENVIRONMENT_V2, targets=['host-linux'], interpreters={'python': sys.executable},
            endpoints=[], auth_refs=[], work_root=str(self.base), allowed_actions=['native'],
            native_runtime=dict(transport='local-target', identity=value['target']), linux=options)))
        return value, candidate, environment

    @staticmethod
    def _cli(*args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = A.main(['--root', str(ROOT), *map(str, args)])
        return code, stdout.getvalue(), stderr.getvalue()

    def _central_chain(self, name, provider_factory, expect_execute=0):
        value, candidate, environment = self._central_environment(name)
        run = self.base / (name + '-run')
        plan = run / 'plan.json'
        code, stdout, stderr = self._cli('plan', '--mode', 'selected', '--case', 'LINUX-DEPLOY-UPDATE',
                                         '--candidate', candidate, '--environment', environment,
                                         '--output', plan)
        self.assertEqual(0, code, (stdout, stderr))
        planned = json.loads(plan.read_text())
        self.assertEqual(L.EXISTING_CHECKS,
                         planned['cases']['LINUX-DEPLOY-UPDATE']['required_checks'])
        provider = provider_factory()
        real_run = L.run

        def fixture_run(*args, **kwargs):
            kwargs['os_boundary'] = provider
            return real_run(*args, **kwargs)

        class Child:
            pid = 999994

            def wait(self, timeout=None):
                return self.code

        def launch(argv, **kwargs):
            captured = io.StringIO()
            with mock.patch.object(L, 'run', side_effect=fixture_run), contextlib.redirect_stdout(captured):
                code = L.main(argv[2:])
            kwargs['stdout'].write(captured.getvalue().encode())
            child = Child(); child.code = code
            return child

        backend = types.SimpleNamespace(**vars(__import__('subprocess')))
        backend.Popen = launch
        with mock.patch.object(__import__('acceptance_runtime'), 'require_target',
                               return_value=value['target']), \
                mock.patch.object(native, 'subprocess', backend):
            code, stdout, stderr = self._cli('execute', '--plan', plan)
        if expect_execute is not None:
            self.assertEqual(expect_execute, code, (stdout, stderr))
        code, stdout, stderr = self._cli('judge', '--plan', plan, '--results', run / 'results',
                                         '--output', run / 'judged.json')
        return value, plan, run, code, stdout, stderr

    def test_central_execute_and_judge_positive(self):
        provider = self.provider()

        def factory():
            provider.expected = provider.observe_existing() and None
            return provider
        value, plan, run, code, stdout, stderr = self._central_chain('central-positive', factory)
        self.assertEqual(0, code, (stdout, stderr))
        summary = json.loads((run / 'judged.json').read_text())
        self.assertFalse(summary['full_functional_pass'])
        self.assertEqual('pass', summary['cases'][0]['status'], summary)
        record = json.loads((run / 'results/LINUX-DEPLOY-UPDATE/driver/linux-result.json').read_text())
        self.assertEqual('derived/normal', record['phase']['normal']['package'])
        self.assertTrue(record['phase']['normal']['reentry_commands'] == [])
        self.assertIn('fault', record['phase'])
        self.assertIn('recovery', record['phase'])
        self.assertTrue(record['cleanup']['restored'])

    def test_central_judge_rejects_broken_actual_restore(self):
        value, provider, record = self.run_case('broken-restore')
        broken = self.provider()

        def broken_cleanup(baseline_sources, published_sources):
            # reports success but physically leaves the updated bytes in place
            return dict(restored=True, installation_preserved=True,
                        preserved_paths=['opt/fakenet-ng', 'etc/fakenet-ng-linux',
                                         'etc/systemd/system/fakenet-ng-linux.service'],
                        restored_sources=dict(baseline_sources), service=broken.service(),
                        credential=self.token_row, first_install_not_tested=True)
        broken.cleanup_own = broken_cleanup

        def factory():
            broken.expected = broken.observe_existing() and None
            return broken
        out_value, plan, run, code, stdout, stderr = self._central_chain('central-broken', factory, expect_execute=None)
        # The producer itself claims success (error None, restored True) yet the
        # independent consumer must reject the physically unrestored sources.
        self.assertNotEqual(0, code, (stdout, stderr))
        driver = run / 'results/LINUX-DEPLOY-UPDATE/driver'
        record = json.loads((driver / 'linux-result.json').read_text())
        self.assertIsNone(record['error'])
        self.assertTrue(record['cleanup']['restored'])
        rows, clean, detail = O.evaluate(ROOT, driver, 'LINUX-DEPLOY-UPDATE',
                                         expected_inputs=record['inputs'], allow_fixture=True)
        self.assertFalse(clean)
        self.assertIn('not physically restored', json.dumps(detail))
        judged = self._cli('judge', '--plan', plan, '--results', run / 'results',
                           '--output', run / 'judged-broken.json')
        self.assertNotEqual(0, judged[0], judged)


if __name__ == '__main__':
    unittest.main()
