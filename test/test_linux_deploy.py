"""Offline deployment boundaries; no real services, credentials or network."""
import configparser
import hashlib
import io
import json
import os
import re
from pathlib import Path
import subprocess
import tarfile
import tempfile
import types
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'deploy/linux/deploy.sh'


def module():
    text = SCRIPT.read_text().split("<<'PY_DEPLOY'\n", 1)[1].rsplit('\nPY_DEPLOY', 1)[0]
    result = types.ModuleType('deploy_fixture')
    exec(compile(text, str(SCRIPT), 'exec'), result.__dict__)
    result.OWNER = os.getuid()
    return result


class DeployTests(unittest.TestCase):
    def setUp(self):
        previous_umask = os.umask(0o077)
        self.addCleanup(os.umask, previous_umask)
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('DEPLOY_TEST_ROOT'))
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / 'root'
        for rel in ('opt', 'etc/systemd/system'):
            (self.root / rel).mkdir(parents=True)
        self.package = self.base / 'package'
        self.package.mkdir(mode=0o700)
        self.m = module()
        self.calls = []
        self.operation = 'fixture-operation-0001'
        self.make_package()

    def archive(self, path, entries):
        with tarfile.open(path, 'w:gz') as tf:
            for name, content in entries.items():
                data = content.encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mode = 0o644
                tf.addfile(info, io.BytesIO(data))

    def make_package(self):
        source = {'fakenet/configs/default.ini': '[Diverter]\nNetworkMode=Auto\n'}
        for rel in ['mcp/build_identity.py', 'mcp/linuxrunner.py', 'diverters/linuxnetpolicy.py']:
            source['fakenet/' + rel] = '# benign package fixture\n'
        self.archive(self.package / 'source.tar.gz', source)
        wheels = []
        (self.package / 'wheels').mkdir()
        for name in ['Cython', 'setuptools', 'wheel', 'mcp', 'uvicorn', 'dpkt',
                     'dnslib', 'pyOpenSSL', 'cryptography', 'jinja2', 'pyasyncore', 'pyasynchat']:
            path = self.package / 'wheels' / (name + '-fixture.whl')
            path.write_bytes(b'benign transport fixture')
            wheels.append(dict(name=name, version='1', file='wheels/' + path.name,
                               sha256=self.m.digest(path)))
        (self.package / 'requirements.lock').write_text(''.join(
            f"{r['name']}=={r['version']} --hash=sha256:{r['sha256']}\n" for r in wheels))
        (self.package / 'dependency-lock.json').write_text(json.dumps(dict(
            python='3.12', platform='Linux x86_64', wheels=wheels, sdists=[])))
        for name in ['deploy.sh', 'lnxfn-serve.py', 'fakenet-ng-linux.service']:
            (self.package / name).write_text('benign fixture\n')
        self.seal()

    def seal(self):
        files = {p.relative_to(self.package).as_posix():
                 dict(size=p.stat().st_size, sha256=self.m.digest(p))
                 for p in self.package.rglob('*') if p.is_file() and p.name != 'manifest.json'}
        (self.package / 'manifest.json').write_text(json.dumps(dict(schema_version=1, files=files)))
        self.pinned = self.m.digest(self.package / 'manifest.json')

    def fake_run(self, argv):
        self.calls.append(argv)

    def deploy(self, runner=None):
        return self.m.install(self.package, self.pinned, self.operation,
                              root=self.root, run=runner or self.fake_run,
                              idle=lambda target: None)

    def test_missing_dependency_refuses_before_target_or_transaction(self):
        next((self.package / 'wheels').iterdir()).unlink()
        with self.assertRaisesRegex(self.m.Refused, 'incomplete'):
            self.deploy()
        self.assertEqual([], list((self.root / 'opt').iterdir()))
        self.assertFalse((self.root / 'etc/fakenet-ng-linux').exists())
        self.assertEqual([], self.calls)

    def test_resealed_manifest_cannot_omit_dependency(self):
        next((self.package / 'wheels').iterdir()).unlink()
        self.seal()
        with self.assertRaisesRegex(self.m.Refused, 'dependency'):
            self.deploy()
        self.assertEqual([], list((self.root / 'opt').iterdir()))

    def test_existing_valid_token_preserved_and_completed_reentry_has_no_effects(self):
        config = self.root / 'etc/fakenet-ng-linux'
        config.mkdir(mode=0o700)
        token = config / 'token'
        token.write_text('a' * 64)
        token.chmod(0o600)
        identity = token.stat().st_ino
        self.deploy()
        calls = list(self.calls)
        self.deploy()
        self.assertEqual(calls, self.calls)
        self.assertEqual(identity, token.stat().st_ino)
        self.assertEqual('a' * 64, token.read_text())
        cfg = configparser.RawConfigParser()
        cfg.read(self.root / 'opt/fakenet-ng/fakenet/configs/default.ini')
        for option in ('LinuxFlushIptables', 'FixGateway', 'FixDNS',
                       'ModifyLocalDNS', 'StopDNSService'):
            self.assertFalse(cfg.getboolean('Diverter', option))
        self.assertFalse(cfg.has_option('Diverter', 'LinuxFlushDNSCommand'))

    def test_invalid_token_refuses_without_any_installation(self):
        config = self.root / 'etc/fakenet-ng-linux'
        config.mkdir(mode=0o700)
        token = config / 'token'
        token.write_text('a' * 64)
        token.chmod(0o644)
        with self.assertRaisesRegex(self.m.Refused, '0600'):
            self.deploy()
        self.assertEqual([], self.calls)
        self.assertEqual([], list((self.root / 'opt').iterdir()))

    def test_symlink_target_and_foreign_writable_parent_refused(self):
        target = self.root / 'opt/fakenet-ng'
        target.symlink_to(self.base)
        with self.assertRaises(self.m.Refused):
            self.deploy()
        target.unlink()
        (self.root / 'opt').chmod(0o777)
        with self.assertRaisesRegex(self.m.Refused, 'unprotected'):
            self.deploy()
        self.assertEqual([], self.calls)

    def test_install_failure_never_activates_and_preserves_residue(self):
        target = self.root / 'opt/fakenet-ng'
        target.mkdir()
        old = target / 'original.txt'
        old.write_text('retained original')
        inode = old.stat().st_ino
        def fail(argv):
            self.calls.append(argv)
            raise self.m.Refused('offline installation failed')
        with self.assertRaisesRegex(self.m.Refused, 'offline installation failed'):
            self.deploy(fail)
        archived = self.root / 'opt' / ('fakenet-ng.preserved-' + self.operation) / 'original.txt'
        self.assertEqual(inode, archived.stat().st_ino)
        self.assertEqual('retained original', archived.read_text())
        self.assertFalse(any(argv[0] == 'systemctl' for argv in self.calls))
        self.assertFalse((self.root / 'etc/systemd/system/fakenet-ng-linux.service').exists())
        transaction = self.root / 'opt' / ('.fakenet-deploy-' + self.operation)
        self.assertEqual([], [p for p in transaction.glob('stage-*') if p.is_dir()])
        receipt = json.loads((transaction / 'receipt.json').read_text())
        self.assertEqual('failed', receipt['phase'])
        with self.assertRaisesRegex(self.m.Refused, 'interrupted deployment'):
            self.deploy()
        self.assertEqual(1, len(self.calls))

    def test_manifest_tampering_and_archive_traversal_refuse_before_mutation(self):
        (self.package / 'lnxfn-serve.py').write_text('tampered')
        with self.assertRaisesRegex(self.m.Refused, 'changed'):
            self.deploy()
        self.seal()
        self.archive(self.package / 'source.tar.gz', {'../escape': 'x'})
        self.seal()
        with self.assertRaisesRegex(self.m.Refused, 'unsafe archive'):
            self.deploy()
        self.assertEqual([], list((self.root / 'opt').iterdir()))

    def test_legacy_missing_dependency_creates_target_before_failing(self):
        # Execute the old shell path only in an isolated rewritten filesystem.
        old = subprocess.check_output(['git', '-C', str(ROOT), 'show',
              '3ed8592df4c326331000a7ec6d2abda84bac948b:deploy/linux/deploy.sh'], text=True)
        work = self.base / 'legacy'
        work.mkdir()
        bin_dir = work / 'bin'
        bin_dir.mkdir()
        for name, content in {
            'sudo': '#!/bin/sh\nexec "$@"\n',
            'python3': '#!/bin/sh\nmkdir -p "$3/bin"\nprintf "#!/bin/sh\\nexit 9\\n" > "$3/bin/pip"\nchmod +x "$3/bin/pip"\n',
        }.items():
            path = bin_dir / name
            path.write_text(content)
            path.chmod(0o755)
        old = re.sub(r'/(opt|etc|tmp)(?=/)',
                     lambda m: str(work / m.group(1)), old)
        script = work / 'old.sh'
        script.write_text(old)
        result = subprocess.run(['/bin/bash', str(script)], capture_output=True,
                                env=dict(os.environ, PATH=str(bin_dir) + ':/usr/bin:/bin'))
        self.assertEqual(9, result.returncode)
        self.assertTrue((work / 'opt/fakenet-ng').exists())
        # The matching new-path test above requires zero such side effects.


if __name__ == '__main__':
    unittest.main()
