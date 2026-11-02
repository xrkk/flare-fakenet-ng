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
                            process=dict(pid=self.pid, birth='fixture-2', children=''))

            def quiet(self):
                return self.pid == 0

            def stop(self):
                self.pid = 0
                return self.service()

            def cleanup_own(self, baseline_sources):
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

    def test_central_plan_freezes_the_existing_install_checks(self):
        """The central plan derives the existing-install check names from the
        v3 options; execution/judging of this benign fixture is covered by the
        direct producer+consumer positive above (the central execute path must
        create the system root after the plan, which this fixture cannot do)."""
        head = A.git_head(ROOT)
        template = json.loads((self.template / 'template.json').read_text())
        template['source_commit'] = head
        (self.template / 'template.json').write_text(json.dumps(template))
        self.template_pin = _sha(self.template / 'template.json')
        value = self.inputs('central-plan')
        value['source_commit'] = head
        value['update_template_sha256'] = self.template_pin
        fields = ('system_root', 'update_template', 'update_template_sha256', 'operation',
                  'fault', 'binding', 'existing_installation', 'first_install_not_tested')
        options = {key: value[key] for key in fields}
        options['schema'] = 'fakenet.linux-deploy-options.v3'
        candidate = self.base / 'candidate.json'
        environment = self.base / 'environment.json'
        candidate.write_text(json.dumps(dict(schema=A.CANDIDATE_V2, candidate_id=value['candidate_id'],
                                             source_commit=head, package_sha256='b' * 64,
                                             offline_fixture=True, deployed_identity=value['target'])))
        environment.write_text(json.dumps(dict(
            schema=A.ENVIRONMENT_V2, targets=['host-linux'], interpreters={'python': sys.executable},
            endpoints=[], auth_refs=[], work_root=str(self.base), allowed_actions=['native'],
            native_runtime=dict(transport='local-target', identity=value['target']), linux=options)))
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = A.main(['--root', str(ROOT), 'plan', '--mode', 'selected',
                           '--case', 'LINUX-DEPLOY-UPDATE', '--candidate', str(candidate),
                           '--environment', str(environment), '--output',
                           str(self.base / 'plan/plan.json')])
        self.assertEqual(0, code, (stdout.getvalue(), stderr.getvalue()))
        planned = json.loads((self.base / 'plan/plan.json').read_text())
        self.assertEqual(L.EXISTING_CHECKS,
                         planned['cases']['LINUX-DEPLOY-UPDATE']['required_checks'])
        self.assertNotIn('LINUX-DEPLOY-UPDATE', planned.get('blocked') or {})
        derived = native.linux_inputs(planned, next(
            c for s in json.loads((ROOT / 'docs/acceptance/catalog.json').read_text())['suites']
            for c in s.get('cases', []) if c['id'] == 'LINUX-DEPLOY-UPDATE'), str(self.base / 'derived'))
        self.assertEqual(L.EXISTING_SCHEMA, derived['schema'])
        self.assertTrue(derived['first_install_not_tested'])


if __name__ == '__main__':
    unittest.main()
