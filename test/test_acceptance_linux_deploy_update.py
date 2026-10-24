"""Linux install/update originals with only test-owned OS/service boundaries."""
import contextlib
import subprocess
import hashlib
import copy
import io
import json
import os
from pathlib import Path
import shutil
import socket
import sys
import tarfile
import types
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import acceptance_linux_runtime as L
import acceptance_linux_runtime_oracles as O


def build_install_package(package):
    package = Path(package); package.mkdir(mode=0o700)
    source = {
        'fakenet/configs/default.ini': '[Diverter]\nNetworkMode=Auto\n',
        'fakenet/mcp/build_identity.py': '# benign fixture\n',
        'fakenet/mcp/linuxrunner.py': '# benign fixture\n',
        'fakenet/diverters/linuxnetpolicy.py': '# benign fixture\n',
    }
    with tarfile.open(package / 'source.tar.gz', 'w:gz') as archive:
        for name, text in source.items():
            data = text.encode(); info = tarfile.TarInfo(name)
            info.size = len(data); info.mode = 0o644
            archive.addfile(info, io.BytesIO(data))
    wheels = []
    (package / 'wheels').mkdir(mode=0o755)
    for name in ('Cython', 'setuptools', 'wheel', 'mcp', 'uvicorn', 'dpkt',
                 'dnslib', 'pyOpenSSL', 'cryptography', 'jinja2', 'pyasyncore',
                 'pyasynchat'):
        path = package / 'wheels' / (name + '-fixture.whl')
        path.write_bytes(b'benign dependency fixture\n')
        wheels.append({'name': name, 'version': '1', 'file': 'wheels/' + path.name,
                       'sha256': L.sha(path)})
    (package / 'requirements.lock').write_text(''.join(
        "%s==%s --hash=sha256:%s\n" % (r['name'], r['version'], r['sha256']) for r in wheels))
    (package / 'dependency-lock.json').write_text(json.dumps(
        {'python': '3.12', 'platform': 'Linux x86_64', 'wheels': wheels, 'sdists': []}))
    for name in ('deploy.sh', 'lnxfn-serve.py', 'fakenet-ng-linux.service'):
        (package / name).write_text('benign fixture\n')
    for path in package.rglob('*'):
        path.chmod(0o755 if path.is_dir() else 0o644)
    files = {p.relative_to(package).as_posix():
             {'size': p.stat().st_size, 'sha256': L.sha(p)}
             for p in package.rglob('*') if p.is_file() and p.name != 'manifest.json'}
    (package / 'manifest.json').write_text(json.dumps({'schema_version': 1, 'files': files}))
    (package / 'manifest.json').chmod(0o644)
    return L.sha(package / 'manifest.json')


def build_update_package(package, accepted):
    package = Path(package); package.mkdir(mode=0o700)
    update = L._update_module()
    rows = {}; base_files = {}
    for name in update.FILES:
        old = accepted / 'opt/fakenet-ng' / name
        incoming = package / name
        incoming.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        incoming.write_bytes(b'new ' + name.encode() + b'\n')
        rows[name] = {'old_sha256': L.sha(old), 'new_sha256': L.sha(incoming)}
        base_files['opt/fakenet-ng/' + name] = L.sha(old)
    (package / 'update-idle.py').write_bytes((ROOT / 'deploy/linux/update-idle.py').read_bytes())
    token = accepted / 'etc/fakenet-ng-linux/token'
    manifest = {'base_manifest': update.BASE_MANIFEST, 'source_commit': 'a' * 40,
                'files': rows, 'base_files': base_files,
                'token_inode': token.stat().st_ino,
                'updater_sha256': L.sha(package / 'update-idle.py')}
    (package / 'manifest.json').write_text(json.dumps(manifest))
    for path in package.rglob('*'):
        path.chmod(0o755 if path.is_dir() else 0o600)
    (package / 'manifest.json').chmod(0o600)
    return L.sha(package / 'manifest.json')


def make_base(root):
    root = Path(root); root.mkdir(mode=0o700, parents=True)
    target = root / 'opt/fakenet-ng'
    target.mkdir(mode=0o755, parents=True)
    for name in L._update_module().FILES:
        path = target / name; path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        path.write_text('old ' + name)
    (target / 'unrelated.txt').write_text('must remain unchanged')
    token = root / 'etc/fakenet-ng-linux/token'
    token.parent.mkdir(mode=0o700, parents=True)
    token.write_text('a' * 64); token.chmod(0o600)
    return root


class Boundary:
    def __init__(self, base, failure_root, token_root):
        self.base = base; self.failure_root = failure_root; self.token_root = token_root
        self.owner = os.getuid(); self.calls = []
        self.started = False

    def record(self, branch, argv):
        self.calls.append({'branch': branch, 'argv': list(argv)})

    def install_run(self, argv):
        self.record('install', argv)
        return types.SimpleNamespace(returncode=0, stdout='', stderr='')

    def install_failure_run(self, argv):
        self.record('install-failure', argv)
        raise RuntimeError('fixture installation command failure')

    def install_idle(self, target):
        return None

    def preflight(self, manifest):
        return {'pid': 4242, 'start': 'fixture'}

    def status(self):
        return {'state': 'stopped', 'run_id': None, 'controller': None,
                'health': {'process_alive': False}}

    def active_status(self):
        return {'state': 'healthy', 'run_id': 'live', 'controller': 'fixture',
                'health': {'process_alive': True}}

    def update_run(self, argv):
        self.record('update', argv)
        if argv[:2] == ['systemctl', 'stop']: self.started = False; return ''
        if argv[:2] == ['systemctl', 'show']: return '123' if self.started else '0'
        if argv[:2] == ['systemctl', 'start']: self.started = True; return 'active'
        if argv[:2] == ['systemctl', 'is-active']: return 'active'
        raise RuntimeError('unexpected fixture service command: ' + repr(argv))

    def active_run(self, argv):
        self.record('active', argv); return ''

    def source_run(self, argv):
        self.record('source', argv); return ''

    def token_run(self, argv):
        self.record('token', argv); return ''

    def stop_run(self, argv):
        self.record('stop', argv); raise RuntimeError('fixture stop failure')

    def start_run(self, argv):
        self.record('start', argv)
        if argv[:2] == ['systemctl', 'stop']: return ''
        if argv[:2] == ['systemctl', 'show']: return '0'
        if argv[:2] == ['systemctl', 'start']: raise RuntimeError('fixture start failure')
        raise AssertionError('unexpected start-failure command')


class DeployUpdateTests(unittest.TestCase):
    def setUp(self):
        old_umask = os.umask(0o077)
        self.addCleanup(os.umask, old_umask)
        self.base = Path(os.environ['FN_COMPAT_CHECK_DIR']) / self.id().split('.')[-1]
        self.base.mkdir(parents=True, exist_ok=False)
        self.install_package = self.base / 'install-package'
        self.install_pin = build_install_package(self.install_package)
        self.accepted = make_base(self.base / 'accepted')
        self.update_package = self.base / 'update-package'
        self.update_pin = build_update_package(self.update_package, self.accepted)
        self.failure_root = self.base / 'failure-root'
        self.failure_root.mkdir(mode=0o700)
        (self.failure_root / 'opt/fakenet-ng').mkdir(mode=0o755, parents=True)
        (self.failure_root / 'opt/fakenet-ng/original.txt').write_text('retained original')
        (self.failure_root / 'etc/systemd/system').mkdir(mode=0o755, parents=True)
        self.token_root = self.base / 'token-root'
        shutil.copytree(self.accepted, self.token_root)

    def inputs(self, fresh='fresh'):
        return {
            'schema': L.INPUT_SCHEMA, 'case': 'LINUX-DEPLOY-UPDATE',
            'candidate_id': 'deploy-fixture', 'source_commit': 'a' * 40,
            'package_sha256': 'b' * 64, 'execution_id': 'deploy-fixture-0001',
            'target': {'platform': 'linux', 'hostname': socket.gethostname()},
            'fresh_root': str(self.base / fresh),
            'accepted_update_root': str(self.accepted),
            'install_package': str(self.install_package),
            'install_manifest_sha256': self.install_pin,
            'update_package': str(self.update_package),
            'update_manifest_sha256': self.update_pin,
            'operation': 'deploy-fixture-0001',
            'fixture': True,
            'source_hashes': {
                rel: L.sha(ROOT / rel) for rel in (
                    'fakenet/mcp/linuxrunner.py', 'fakenet/diverters/linuxnetpolicy.py',
                    'deploy/linux/deploy.sh', 'deploy/linux/update-idle.py',
                    'tools/acceptance_linux_runtime.py',
                    'tools/acceptance_linux_runtime_oracles.py')
            },
        }

    def boundary(self):
        return Boundary(self.accepted, self.failure_root, self.token_root)

    def test_original_fixture_install_update_negative_and_recovery(self):
        value = self.inputs()
        boundary = self.boundary()
        from unittest import mock
        with mock.patch('acceptance_runtime.require_target', return_value=value['target']):
            record = L.run('LINUX-DEPLOY-UPDATE', value['fresh_root'], value, os_boundary=boundary)
        self.assertIsNone(record['error'], record)
        rows, clean, detail = O.evaluate(ROOT, value['fresh_root'], 'LINUX-DEPLOY-UPDATE',
                                         expected_inputs=value, allow_fixture=True)
        self.assertTrue(clean, detail)
        self.assertEqual(['install', 'idle-update', 'transaction', 'token', 'rollback'],
                         [row['id'] for row in rows])
        self.assertTrue(all(row['status'] == 'pass' for row in rows))

    def test_recovery_noop_cannot_count_as_rollback(self):
        from unittest import mock
        value = self.inputs('no-recovery')
        with mock.patch('acceptance_runtime.require_target', return_value=value['target']), mock.patch.object(L, '_recover_update', return_value={'restored': {}, 'receipt': 'not-restored'}):
            record = L.run('LINUX-DEPLOY-UPDATE', value['fresh_root'], value, os_boundary=self.boundary())
        self.assertIn('accepted file changed', record['error'])
        rows, clean, detail = O.evaluate(ROOT, value['fresh_root'], 'LINUX-DEPLOY-UPDATE', expected_inputs=value, allow_fixture=True)
        self.assertFalse(clean, detail)

    def test_missing_accepted_root_refused_before_output(self):
        value = self.inputs('missing')
        value.pop('accepted_update_root')
        with self.assertRaises(ValueError):
            L.run('LINUX-DEPLOY-UPDATE', value['fresh_root'], value)
        self.assertFalse(Path(value['fresh_root']).exists())

    def test_tampered_original_is_rejected_by_oracle(self):
        value = self.inputs('tampered')
        from unittest import mock
        with mock.patch('acceptance_runtime.require_target', return_value=value['target']):
            record = L.run('LINUX-DEPLOY-UPDATE', value['fresh_root'], value,
                           os_boundary=self.boundary())
        self.assertIsNone(record['error'], record)
        target = Path(value['fresh_root']) / 'opt/fakenet-ng/fakenet/configs/default.ini'
        original = target.read_bytes()
        target.write_bytes(original + b'\nforeign edit\n')
        rows, clean, detail = O.evaluate(ROOT, value['fresh_root'], 'LINUX-DEPLOY-UPDATE',
                                         expected_inputs=value, allow_fixture=True)
        self.assertFalse(clean, detail)
        target.write_bytes(original)

    def test_central_cli_and_independent_recovery_negatives(self):
        import acceptance as A
        from unittest import mock
        value = self.inputs('central')
        boundary = self.boundary()
        options = {key: value[key] for key in ('accepted_update_root', 'install_package', 'install_manifest_sha256', 'update_package', 'update_manifest_sha256', 'operation')}
        options['schema'] = 'fakenet.linux-deploy-options.v1'
        work = self.base / 'cli'
        work.mkdir()
        candidate = {'schema': A.CANDIDATE_V2, 'candidate_id': value['candidate_id'], 'source_commit': A.git_head(ROOT), 'package_sha256': 'b'*64, 'offline_fixture': True, 'deployed_identity': value['target']}
        environment = {'schema': A.ENVIRONMENT_V2, 'targets': ['host-linux'], 'interpreters': {'python': sys.executable}, 'endpoints': [], 'auth_refs': [], 'work_root': str(work), 'allowed_actions': ['native'], 'native_runtime': {'transport': 'local-target', 'identity': value['target']}, 'linux': options}
        for name, obj in [('candidate', candidate), ('environment', environment)]:
            (work/(name+'.json')).write_text(json.dumps(obj))
        def cli(*args):
            text, error = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(text), contextlib.redirect_stderr(error):
                code = A.main(['--root', str(ROOT), *map(str, args)])
            return code, text.getvalue(), error.getvalue()
        plan = work/'run/plan.json'
        result = cli('plan', '--mode', 'selected', '--case', 'LINUX-DEPLOY-UPDATE', '--candidate', work/'candidate.json', '--environment', work/'environment.json', '--output', plan)
        self.assertEqual(0, result[0], result)
        real_run, real_popen = L.run, subprocess.Popen
        def fixture_run(*args, **kwargs):
            kwargs['os_boundary'] = boundary
            return real_run(*args, **kwargs)
        class Child:
            pid = 999993
            def __init__(self, code): self.code = code
            def wait(self, timeout=None): return self.code
        def child(argv, **kwargs):
            if argv[0] == 'git': return real_popen(argv, **kwargs)
            self.assertEqual(str(ROOT/'tools/acceptance_linux_runtime.py'), argv[1])
            output = Path(argv[argv.index('--output') + 1])
            # The central driver nests its result beneath results/<case>.
            # Its failure scenario must share that exact owned case parent.
            boundary.failure_root = output.parent / 'failure-root'
            boundary.failure_root.mkdir(mode=0o700)
            (boundary.failure_root/'opt/fakenet-ng').mkdir(mode=0o755, parents=True)
            (boundary.failure_root/'opt/fakenet-ng/original.txt').write_text('retained original')
            for rel in ('etc', 'etc/systemd', 'etc/systemd/system'):
                (boundary.failure_root/rel).mkdir(mode=0o755)
            captured = io.StringIO()
            with mock.patch('acceptance_runtime.require_target', return_value=value['target']), mock.patch.object(L, 'run', side_effect=fixture_run), contextlib.redirect_stdout(captured):
                code = L.main(argv[2:])
            kwargs['stdout'].write(captured.getvalue().encode())
            return Child(code)
        with mock.patch('acceptance_runtime.require_target', return_value=value['target']), mock.patch.object(subprocess, 'Popen', side_effect=child):
            result = cli('execute', '--plan', plan)
        self.assertEqual(0, result[0], result)
        result = cli('judge', '--plan', plan, '--results', plan.parent/'results', '--output', work/'judge.json')
        self.assertEqual(0, result[0], result)
        self.assertFalse(json.loads((work/'judge.json').read_text())['full_functional_pass'])
        folder = plan.parent/'results/LINUX-DEPLOY-UPDATE/driver'
        result_path = folder/'linux-result.json'
        original = result_path.read_bytes()
        record = json.loads(original)
        raw = folder/'recovery-observed/fakenet/mcp/linuxrunner.py'
        before = raw.read_bytes()
        raw.write_bytes(b'not restored')
        changed = json.loads(original)
        changed['originals'][raw.relative_to(folder).as_posix()] = hashlib.sha256(raw.read_bytes()).hexdigest()
        result_path.write_text(json.dumps(changed))
        result = cli('judge', '--plan', plan, '--results', plan.parent/'results', '--output', work/'rejected.json')
        self.assertNotEqual(0, result[0], result)
        rows, clean, detail = O.evaluate(ROOT, folder, 'LINUX-DEPLOY-UPDATE', allow_fixture=True, expected_inputs=record['inputs'])
        self.assertFalse(clean, detail)
        self.assertIn('observed restored bytes differ', str(detail))
        raw.write_bytes(before)
        result_path.write_bytes(original)

    def test_linux_inputs_distinguishes_the_two_roots_and_fixture(self):
        import acceptance_native as native
        value = self.inputs('central')
        options = {key: value[key] for key in (
            'accepted_update_root', 'install_package', 'install_manifest_sha256',
            'update_package', 'update_manifest_sha256', 'operation')}
        options['schema'] = 'fakenet.linux-deploy-options.v1'
        plan = {'environment': {'linux': options, 'native_runtime': {'identity': value['target']}},
                'candidate': {'candidate_id': 'deploy-fixture', 'source_commit': 'a' * 40,
                              'package_sha256': 'b' * 64, 'offline_fixture': True},
                'execution_id': 'deploy-fixture-0001'}
        case = {'id': 'LINUX-DEPLOY-UPDATE'}
        built = native.linux_inputs(plan, case, self.base / 'central')
        self.assertNotEqual(built['fresh_root'], built['accepted_update_root'])
        self.assertTrue(built['fixture'])
        self.assertEqual(str(self.accepted), built['accepted_update_root'])


if __name__ == '__main__':
    unittest.main()
