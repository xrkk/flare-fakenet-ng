#!/bin/bash
# Verified offline deployment. All arguments are passed as data.
set -euo pipefail
exec /usr/bin/python3 -I -B -S - "$@" <<'PY_DEPLOY'
import argparse
import configparser
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

OWNER = 0
UNIT_NAME = 'fakenet-ng-linux.service'
VM_UUID = '289e4d56-ebaf-5147-96ba-40dfc2a942a3'


class Refused(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise Refused(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ordinary(path, directory=False):
    s = path.lstat()
    require(s.st_uid == OWNER and not s.st_mode & 0o022,
            'unprotected object: ' + str(path))
    require(stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode),
            'unexpected object type: ' + str(path))
    if not directory:
        require(s.st_nlink == 1, 'hard-linked object: ' + str(path))
    return s


def parents(path, root):
    for p in [root] + list(reversed(path.parent.relative_to(root).parents)):
        if p != root:
            p = root / p
        ordinary(p, True)
    ordinary(path.parent, True)


def inventory(root):
    rows = []
    for p in [root] + sorted(root.rglob('*')):
        s = p.lstat()
        require(s.st_uid == OWNER, 'foreign owner: ' + str(p))
        row = dict(path=str(p.relative_to(root)), device=s.st_dev,
                   inode=s.st_ino, mode=stat.S_IMODE(s.st_mode),
                   uid=s.st_uid, gid=s.st_gid, links=s.st_nlink,
                   size=s.st_size, mtime_ns=s.st_mtime_ns)
        if stat.S_ISLNK(s.st_mode):
            dest = p.resolve(strict=True)
            require(dest.is_relative_to(root) or
                    str(dest) in ('/usr/bin/python3', '/usr/bin/python3.12'),
                    'unexpected symlink: ' + str(p))
            row.update(kind='symlink', target=os.readlink(p))
        elif stat.S_ISDIR(s.st_mode):
            ordinary(p, True)
            row['kind'] = 'directory'
        else:
            ordinary(p)
            # Credential-like files are never read or hashed for evidence.
            row['kind'] = 'file'
            if p.suffix.lower() in ('.key', '.pem') or any(
                    x in p.name.lower() for x in ('secret', 'token', 'private')):
                row['content_not_read'] = 'credential-like name'
            else:
                row['sha256'] = digest(p)
        rows.append(row)
    return rows


def validate_token(path):
    if not path.exists() and not path.is_symlink():
        return False
    s = ordinary(path)
    require(stat.S_IMODE(s.st_mode) == 0o600,
            'existing token must be root 0600')
    # Private validation only: never return bytes or their hash.
    require(re.fullmatch(rb'[0-9a-fA-F]{64}\n?', path.read_bytes()) is not None,
            'existing token has invalid format')
    return True


def validate_package(package, pinned):
    ordinary(package, True)
    require(not package.stat().st_mode & 0o077, 'package must be private')
    mpath = package / 'manifest.json'
    ordinary(mpath)
    require(digest(mpath) == pinned, 'manifest fingerprint mismatch')
    m = json.loads(mpath.read_text())
    require(m.get('schema_version') == 1, 'unsupported manifest')
    expected = m['files']
    required = {'source.tar.gz', 'requirements.lock', 'dependency-lock.json',
                'lnxfn-serve.py', 'fakenet-ng-linux.service', 'deploy.sh'}
    require(required.issubset(expected), 'missing required package member')
    actual = set()
    for p in package.rglob('*'):
        if p.is_dir() and not p.is_symlink():
            ordinary(p, True)
            continue
        ordinary(p)
        name = p.relative_to(package).as_posix()
        if name == 'manifest.json':
            continue
        require(name in expected, 'unlisted package member: ' + name)
        require(digest(p) == expected[name]['sha256'] and
                p.stat().st_size == expected[name]['size'],
                'package member changed: ' + name)
        actual.add(name)
    require(actual == set(expected), 'package incomplete')
    lock = json.loads((package / 'dependency-lock.json').read_text())
    require(lock['python'] == '3.12' and lock['platform'] == 'Linux x86_64',
            'wrong dependency target')
    locked = lock['wheels'] + lock['sdists']
    for item in locked:
        require(item['file'] in expected and
                expected[item['file']]['sha256'] == item['sha256'],
                'missing or mismatched dependency: ' + item['file'])
    require({r['name'].lower() for r in lock['wheels']} >=
            {'cython', 'setuptools', 'wheel', 'mcp', 'uvicorn', 'dpkt',
             'dnslib', 'pyopenssl', 'cryptography', 'jinja2', 'pyasyncore',
             'pyasynchat'}, 'incomplete build/runtime dependency set')
    lines = ''.join(f"{r['name']}=={r['version']} --hash=sha256:{r['sha256']}\n"
                    for r in lock['wheels'])
    require((package / 'requirements.lock').read_text() == lines,
            'requirements do not match dependency lock')
    for name in ['source.tar.gz'] + [r['file'] for r in lock['sdists']]:
        with tarfile.open(package / name) as tf:
            members = tf.getmembers()
            require(all(not Path(v.name).is_absolute() and
                        '..' not in Path(v.name).parts and
                        (v.isdir() or v.isfile()) for v in members),
                    'unsafe archive: ' + name)
            if name == 'source.tar.gz':
                require('fakenet/mcp/build_identity.py' in
                        {v.name for v in members}, 'build_identity.py absent')
    return m, lock


def command(argv):
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1',
               PIP_CONFIG_FILE='/dev/null', PIP_NO_CACHE_DIR='1',
               PIP_DISABLE_PIP_VERSION_CHECK='1')
    r = subprocess.run(argv, capture_output=True, text=True, env=env,
                       timeout=300)
    if r.stdout:
        print(r.stdout, end='', flush=True)
    if r.stderr:
        print(r.stderr, end='', file=sys.stderr, flush=True)
    require(r.returncode == 0, 'command failed: ' + argv[0])
    return r


def no_active_install(target):
    r = subprocess.run(['systemctl', 'show', UNIT_NAME,
                        '--property=LoadState,MainPID,DropInPaths'],
                       capture_output=True, text=True, timeout=10)
    require(r.returncode == 0 and 'LoadState=not-found' in r.stdout and
            'MainPID=0' in r.stdout and 'DropInPaths=\n' in r.stdout,
            'existing service requires a separately reviewed update')
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit() or int(proc.name) == os.getpid():
            continue
        try:
            for name in ('exe', 'cwd'):
                require(not os.readlink(proc / name).startswith(str(target)),
                        'active process references existing installation')
            args = (proc / 'cmdline').read_bytes()
            require(str(target).encode() not in args and
                    b'fakenet.fakenet' not in args,
                    'active command references existing installation')
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
    for argv in (['iptables-save'], ['ip6tables-save'],
                 ['iptables-legacy-save'], ['ip6tables-legacy-save'],
                 ['nft', 'list', 'ruleset']):
        r = subprocess.run(argv, capture_output=True, text=True, timeout=10)
        require(r.returncode == 0 and not r.stdout.strip(),
                'pre-existing rules: refuse adoption or cleanup')


def save(path, value):
    # The transaction directory is root-private; replace only our own journal.
    tmp = path.with_suffix('.pending')
    with tmp.open('x') as f:
        json.dump(value, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def install(package, pinned, operation, root=Path('/'), run=command,
            idle=no_active_install):
    require(re.fullmatch(r'[a-zA-Z0-9-]{8,80}', operation), 'invalid operation')
    manifest, lock = validate_package(package, pinned)  # before ANY mutation
    target = root / 'opt/fakenet-ng'
    config = root / 'etc/fakenet-ng-linux'
    unit = root / 'etc/systemd/system' / UNIT_NAME
    archive = target.with_name('fakenet-ng.preserved-' + operation)
    transaction = root / 'opt' / ('.fakenet-deploy-' + operation)
    for path in (target, config, unit, transaction):
        parents(path, root)
    token = config / 'token'
    if config.exists() or config.is_symlink():
        ordinary(config, True)
        require(not config.stat().st_mode & 0o077, 'config must be private')
    token_exists = validate_token(token)
    if transaction.exists() or transaction.is_symlink():
        ordinary(transaction, True)
        receipt = transaction / 'receipt.json'
        ordinary(receipt)
        previous = json.loads(receipt.read_text())
        require(previous['manifest_sha256'] == pinned and
                previous['operation'] == operation, 'transaction identity conflict')
        require(previous['phase'] == 'completed',
                'interrupted deployment: preserve originals; explicit recovery required')
        require(validate_token(token), 'completed token missing')
        for name, sha in previous['installed_files'].items():
            p = root / name
            ordinary(p)
            require(digest(p) == sha, 'completed installation changed: ' + name)
        print(json.dumps(dict(ok=True, state='already_completed', operation=operation)))
        return previous
    require(not unit.exists() and not unit.is_symlink(), 'existing unit refused')
    require(not archive.exists() and not archive.is_symlink(), 'archive collision')
    old = inventory(target) if target.exists() or target.is_symlink() else []
    idle(target)
    # No target/unit/token changes occur until the complete preflight passes.
    transaction.mkdir(mode=0o700)
    receipt = dict(operation=operation, manifest_sha256=pinned, phase='prepared',
                   archive=str(archive) if old else None, original_objects=old,
                   token_reused=token_exists)
    save(transaction / 'receipt.json', receipt)
    stage = Path(tempfile.mkdtemp(prefix='stage-', dir=transaction))
    try:
        if old:
            require(inventory(target) == old, 'residue changed before preservation')
            os.rename(target, archive)
        receipt['phase'] = 'preserved'
        save(transaction / 'receipt.json', receipt)
        target.mkdir(mode=0o755)
        with tarfile.open(package / 'source.tar.gz') as tf:
            tf.extractall(target, filter='data')
        shutil.copyfile(package / 'lnxfn-serve.py', target / 'lnxfn-serve.py')
        os.chmod(target / 'lnxfn-serve.py', 0o755)
        config_path = target / 'fakenet/configs/default.ini'
        cfg = configparser.RawConfigParser()
        cfg.read(config_path)
        require(cfg.has_section('Diverter'), 'Diverter configuration missing')
        cfg.set('Diverter', 'LinuxControlEndpoints', '192.168.204.1:2222')
        for option in ('LinuxFlushIptables', 'FixGateway', 'FixDNS',
                       'ModifyLocalDNS', 'StopDNSService'):
            cfg.set('Diverter', option, 'No')
        cfg.remove_option('Diverter', 'LinuxFlushDNSCommand')
        with config_path.open('w') as f:
            cfg.write(f)
        python = target / 'venv/bin/python'
        run(['/usr/bin/python3.12', '-I', '-B', '-m', 'venv', str(target / 'venv')])
        run([str(python), '-B', '-m', 'pip', 'install', '--no-index',
             '--find-links', str(package / 'wheels'), '--require-hashes',
             '-r', str(package / 'requirements.lock')])
        for i, item in enumerate(lock['sdists']):
            build = stage / str(i)
            build.mkdir()
            with tarfile.open(package / item['file']) as tf:
                tf.extractall(build, filter='data')
            dirs = list(build.iterdir())
            require(len(dirs) == 1 and dirs[0].is_dir(), 'unexpected source root')
            run([str(python), '-B', '-m', 'pip', 'install', '--no-index',
                 '--no-deps', '--no-build-isolation', str(dirs[0])])
        run([str(python), '-B', '-m', 'pip', 'check'])
        run([str(python), '-I', '-B', '-c',
             'import netfilterqueue,netifaces,pyftpdlib,asyncore,asynchat; '
             'import mcp,uvicorn,dpkt,dnslib,OpenSSL,jinja2'])
        # Credentials and activation follow successful installation only.
        if not config.exists():
            config.mkdir(mode=0o700)
        if token_exists:
            require(validate_token(token), 'existing token changed')
        else:
            fd = os.open(token, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as f:
                f.write(secrets.token_hex(32))
        unit_text = (package / 'fakenet-ng-linux.service').read_text()
        unit.write_text(unit_text.replace('[Service]\n',
            '[Service]\nEnvironment=PROGRAMDATA=/opt/fakenet-ng/runtime\n'
            'Environment=PYTHONDONTWRITEBYTECODE=1\n'))
        os.chmod(unit, 0o644)
        receipt['phase'] = 'installed'
        receipt['installed_files'] = {str(p.relative_to(root)): digest(p)
            for p in [unit, target / 'lnxfn-serve.py', config_path,
                      target / 'fakenet/mcp/linuxrunner.py',
                      target / 'fakenet/diverters/linuxnetpolicy.py',
                      target / 'fakenet/mcp/build_identity.py']}
        save(transaction / 'receipt.json', receipt)
        run(['systemctl', 'daemon-reload'])
        run(['systemctl', 'enable', '--now', UNIT_NAME])
        run(['systemctl', 'is-active', UNIT_NAME])
        receipt['phase'] = 'completed'
        save(transaction / 'receipt.json', receipt)
        print(json.dumps(dict(ok=True, state='completed', operation=operation,
                              archive=receipt['archive'], token_reused=token_exists)))
        return receipt
    except Exception:
        receipt['failure_at'] = receipt['phase']
        receipt['phase'] = 'failed'
        save(transaction / 'receipt.json', receipt)
        raise
    finally:
        # Only this invocation's private disposable build directory.
        # Original package, receipt and preserved installation remain.
        cleanup = inventory(stage)
        save(transaction / 'stage-cleanup.json', dict(
            stage=str(stage), objects=cleanup, writers_exited=True,
            disposition='private build intermediates; original inputs retained in package'))
        require(inventory(stage) == cleanup, 'stage identity changed before cleanup')
        shutil.rmtree(stage)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--operation', required=True)
    args = parser.parse_args()
    require(os.geteuid() == 0, 'run through the authorized root management channel')
    require(Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower()
            == VM_UUID, 'wrong guest UUID')
    require(sys.version_info[:2] == (3, 12), 'Python 3.12 required')
    install(args.package, args.manifest_sha256, args.operation)


if __name__ == '__main__':
    try:
        main()
    except (Refused, OSError, ValueError, KeyError) as error:
        print(json.dumps(dict(ok=False, error=type(error).__name__, detail=str(error))),
              file=sys.stderr)
        sys.exit(1)
PY_DEPLOY
