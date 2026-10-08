#!/usr/bin/env python3
"""Bounded source-only update of the accepted S0048 idle Linux installation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import urllib.request

OWNER = 0
UNIT = 'fakenet-ng-linux.service'
FILES = ('fakenet/mcp/linuxrunner.py', 'fakenet/diverters/linuxnetpolicy.py')
BASE_MANIFEST = '9f09c2b2c0051af25e689914f1a5d3839e1112e0a70b0effb15fd38252e772ef'
VM = '289e4d56-ebaf-5147-96ba-40dfc2a942a3'


def require(ok, why):
    if not ok:
        raise RuntimeError(why)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def protected(path, directory=False):
    s = path.lstat()
    require(s.st_uid == OWNER and not s.st_mode & 0o022, 'unprotected path: ' + str(path))
    require(stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode),
            'unexpected object: ' + str(path))
    if not directory:
        require(s.st_nlink == 1, 'linked file: ' + str(path))
    return s


def chain(path, root):
    protected(root, True)
    for parent in reversed(path.parent.relative_to(root).parents):
        protected(root / parent, True)
    protected(path.parent, True)


def save(path, data):
    pending = path.with_suffix('.pending')
    with pending.open('x') as f:
        json.dump(data, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    pending.chmod(0o600)
    os.replace(pending, path)


def command(argv):
    r = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    require(r.returncode == 0, 'command failed: ' + ' '.join(argv))
    return r.stdout


def status():
    token = Path('/etc/fakenet-ng-linux/token').read_text().strip()
    params = dict(name='get_status', arguments={}, _meta={
        'io.modelcontextprotocol/protocolVersion': '2026-07-28',
        'io.modelcontextprotocol/clientCapabilities': {}})
    req = urllib.request.Request('http://127.0.0.1:28788/mcp',
        data=json.dumps(dict(jsonrpc='2.0', id=1, method='tools/call', params=params)).encode(),
        headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json',
                 'Accept': 'application/json, text/event-stream',
                 'MCP-Protocol-Version': '2026-07-28', 'Mcp-Method': 'tools/call',
                 'Mcp-Name': 'get_status'})
    with urllib.request.urlopen(req, timeout=10) as response:
        return json.load(response)['result']['structuredContent']


def process(pid):
    p = Path('/proc') / str(pid)
    return dict(pid=pid, start=(p / 'stat').read_text().rsplit(')', 1)[1].split()[19],
                exe=os.readlink(p / 'exe'),
                argv=(p / 'cmdline').read_bytes().decode().split('\0')[:-1],
                children=(p / 'task' / str(pid) / 'children').read_text().strip())


def native_preflight(manifest):
    require(Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower() == VM,
            'wrong VM')
    require(Path('/proc/sys/kernel/random/boot_id').read_text().strip() ==
            'fa87e4f5-da46-4845-ac04-5d0e496e9128', 'boot identity changed')
    for unit, pid, start in [('remnux-control.service', 10185, '7563545'),
                             ('maltrace-p03-debug.service', 12584, '8314457'),
                             (UNIT, 14511, '8716736')]:
        actual = int(command(['systemctl', 'show', unit, '--property=MainPID', '--value']))
        require(actual == pid and process(pid)['start'] == start, 'service identity changed')
    require(process(14511)['children'] == '', 'FN children still active')
    require(process(14511)['exe'] == '/usr/bin/python3.12' and
            sha(Path('/proc/14511/exe')) == manifest['interpreter_sha256'],
            'FN interpreter changed')
    connected = command(['ss', '-Hnt', 'state', 'established', '( sport = :28788 )'])
    require(not connected.strip(), 'unknown active FN client/inflight')
    base = Path('/opt/.fakenet-package-linux-master-20260930-S0048/manifest.json')
    require(sha(base) == BASE_MANIFEST, 'accepted base manifest changed')
    for argv in (['iptables-save'], ['ip6tables-save'], ['iptables-legacy-save'],
                 ['ip6tables-legacy-save']):
        text = command(argv)
        require(not any(line.startswith('-A ') or
                        (line.startswith(':') and ' DROP ' in line)
                        for line in text.splitlines()), 'unexpected active rules')
    rules = json.loads(command(['nft', '-j', 'list', 'ruleset']))
    require(not any('rule' in item for item in rules['nftables']), 'unexpected nft rules')
    state_file = Path('/var/lib/maltrace/remnux-control/state.json')
    envelope = json.loads(state_file.read_bytes())
    raw = json.dumps(envelope['payload'], sort_keys=True, separators=(',', ':'),
                     ensure_ascii=False).encode()
    require(hashlib.sha256(raw).hexdigest() == envelope['sha256'], 'P01 state checksum')
    state = envelope['payload']
    require(state['request_epoch'] == state['credential_generation'] == 82 and
            state['namespace'] == '327bfefbd5214a1e9ac1038d3a91895f' and
            state['gate'] == 'OPEN', 'P01 state changed')
    return process(14511)


def update(package, pinned, operation, root=Path('/'), preflight=native_preflight,
           run=command, get_status=status):
    require(re.fullmatch(r'[A-Za-z0-9-]{8,80}', operation), 'invalid operation')
    protected(package, True)
    require(not package.stat().st_mode & 0o077, 'package must be private')
    protected(package / 'manifest.json')
    require(sha(package / 'manifest.json') == pinned, 'manifest fingerprint')
    manifest = json.loads((package / 'manifest.json').read_text())
    require(manifest['base_manifest'] == BASE_MANIFEST and
            set(manifest['files']) == set(FILES), 'wrong update scope/base')
    require(re.fullmatch(r'[0-9a-f]{40}', manifest['source_commit']), 'source commit missing')
    require({p.relative_to(package).as_posix() for p in package.rglob('*') if not p.is_dir()}
            == set(FILES) | {'manifest.json', 'update-idle.py'}, 'unexpected package files')
    protected(package / 'update-idle.py')
    require(sha(package / 'update-idle.py') == manifest['updater_sha256'], 'updater changed')
    for name, row in manifest['files'].items():
        incoming = package / name
        chain(incoming, package)
        protected(incoming)
        require(sha(incoming) == row['new_sha256'], 'incoming source changed')
    target = root / 'opt/fakenet-ng'
    tx = root / 'opt' / ('.fakenet-update-' + operation)
    chain(tx, root)
    if tx.exists() or tx.is_symlink():
        protected(tx, True)
        protected(tx / 'receipt.json')
        receipt = json.loads((tx / 'receipt.json').read_text())
        require(receipt['manifest'] == pinned and receipt['operation'] == operation,
                'update identity conflict')
        require(receipt['phase'] == 'completed', 'interrupted update: explicit recovery required')
        for name, row in manifest['files'].items():
            protected(target / name)
            require(sha(target / name) == row['new_sha256'], 'completed source drift')
        return receipt
    # Independent accepted S0048 fingerprints, supplied in the pinned package.
    for name, expected in manifest['base_files'].items():
        path = root / name
        chain(path, root)
        protected(path)
        require(sha(path) == expected, 'accepted file changed: ' + name)
    for name, row in manifest['files'].items():
        require(manifest['base_files']['opt/fakenet-ng/' + name] == row['old_sha256'],
                'old source not bound to accepted installation')
    token = root / 'etc/fakenet-ng-linux/token'
    chain(token, root)
    ts = protected(token)
    require(stat.S_IMODE(ts.st_mode) == 0o600 and
            ts.st_ino == manifest['token_inode'], 'token identity changed')
    require(re.fullmatch(rb'[0-9a-fA-F]{64}\n?', token.read_bytes()), 'invalid token')
    before = preflight(manifest)
    snap = get_status()
    require(snap['state'] == 'stopped' and snap['run_id'] is None and
            snap['controller'] is None and not snap['health']['process_alive'], 'not idle')
    tx.mkdir(mode=0o700)
    receipt = dict(operation=operation, manifest=pinned, phase='prepared',
                   before_process=before, before_status=snap, originals={}, published=[])
    save(tx / 'receipt.json', receipt)
    try:
        backups = tx / 'originals'
        backups.mkdir(mode=0o700)
        for name, row in manifest['files'].items():
            source = target / name
            s = protected(source)
            dest = backups / Path(name).name
            with dest.open('xb') as f:
                f.write(source.read_bytes())
                f.flush()
                os.fsync(f.fileno())
            dest.chmod(0o600)
            require(sha(dest) == row['old_sha256'], 'backup mismatch')
            receipt['originals'][name] = dict(backup=str(dest), sha256=sha(dest),
                inode=s.st_ino, device=s.st_dev, mode=stat.S_IMODE(s.st_mode),
                uid=s.st_uid, gid=s.st_gid, mtime_ns=s.st_mtime_ns)
        receipt['phase'] = 'backed_up'
        save(tx / 'receipt.json', receipt)
        run(['systemctl', 'stop', UNIT])
        # A successful systemctl stop is synchronous; no service writes race publication.
        require(int(run(['systemctl', 'show', UNIT, '--property=MainPID', '--value'])) == 0,
                'old service did not stop')
        receipt['phase'] = 'service_stopped'
        save(tx / 'receipt.json', receipt)
        for name, row in manifest['files'].items():
            destination = target / name
            require(sha(destination) == row['old_sha256'], 'source drift before publish')
            temp = destination.with_name('.' + destination.name + '.' + operation + '.new')
            receipt['pending'] = str(temp)
            save(tx / 'receipt.json', receipt)
            with temp.open('xb') as f:
                f.write((package / name).read_bytes())
                f.flush()
                os.fsync(f.fileno())
            temp.chmod(receipt['originals'][name]['mode'])
            require(sha(temp) == row['new_sha256'], 'staged source changed')
            os.replace(temp, destination)
            receipt['published'].append(name)
            receipt.pop('pending')
            save(tx / 'receipt.json', receipt)
        receipt['phase'] = 'published'
        save(tx / 'receipt.json', receipt)
        run(['systemctl', 'start', UNIT])
        run(['systemctl', 'is-active', UNIT])
        receipt['phase'] = 'started'
        save(tx / 'receipt.json', receipt)
        # Caller records readiness separately after bounded service initialization.
        receipt['new_pid'] = int(run(['systemctl', 'show', UNIT, '--property=MainPID', '--value']))
        require(receipt['new_pid'] > 0, 'new service missing')
        receipt['phase'] = 'completed'
        save(tx / 'receipt.json', receipt)
        return receipt
    except Exception as error:
        receipt['failure_at'] = receipt['phase']
        receipt['phase'] = 'failed'
        receipt['error'] = type(error).__name__
        save(tx / 'receipt.json', receipt)
        raise


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--operation', required=True)
    args = parser.parse_args()
    require(os.geteuid() == 0, 'authorized root channel required')
    os.umask(0o077)
    receipt = update(args.package, args.manifest_sha256, args.operation)
    print(json.dumps(receipt))


if __name__ == '__main__':
    main()
