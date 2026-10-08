#!/usr/bin/env python3
"""Package an immutable Linux source commit and a verified offline closure.

Does not fetch dependencies, build binaries, invoke services or write to guest.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    repo = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser()
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source-commit', required=True)
    args = parser.parse_args()
    output = args.output.absolute()
    if not output.is_relative_to(repo / 'dist'):
        parser.error('distributable must be in repository dist/')
    commit = subprocess.check_output(['git', '-C', str(repo), 'rev-parse',
                                     args.source_commit + '^{commit}'], text=True).strip()
    if commit != args.source_commit:
        parser.error('supply the full immutable commit')
    lock_path = repo / 'deploy/linux/offline-lock.json'
    lock = json.loads(lock_path.read_text())
    artifacts = lock['wheels'] + lock['sdists']
    if {row.get('name') for row in lock['sdists']} != {
            'netifaces', 'pyftpdlib', 'netfilterqueue'}:
        parser.error('incomplete frozen source-build closure')
    for row in artifacts:
        path = args.inputs / row['file']
        if not path.is_file() or path.is_symlink() or sha(path) != row['sha256']:
            parser.error('missing/changed input: ' + row['file'])
    source = subprocess.check_output(['git', '-C', str(repo), 'archive',
                                      '--format=tar', commit, 'fakenet'])
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    (output / 'source.tar.gz').write_bytes(gzip.compress(source, mtime=0))
    for row in artifacts:
        dest = output / row['file']
        dest.parent.mkdir(exist_ok=True)
        shutil.copyfile(args.inputs / row['file'], dest)
    for name in ('deploy.sh', 'lnxfn-serve.py', 'fakenet-ng-linux.service'):
        shutil.copyfile(repo / 'deploy/linux' / name, output / name)
    shutil.copyfile(lock_path, output / 'dependency-lock.json')
    (output / 'requirements.lock').write_text(''.join(
        f"{r['name']}=={r['version']} --hash=sha256:{r['sha256']}\n"
        for r in lock['wheels']))
    files = {p.relative_to(output).as_posix(): dict(size=p.stat().st_size,
                                                  sha256=sha(p))
             for p in sorted(output.rglob('*')) if p.is_file()}
    manifest = dict(schema_version=1, source_commit=commit,
                    target=dict(python='3.12', platform='Linux x86_64'), files=files)
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    for p in output.rglob('*'):
        p.chmod(0o700 if p.is_dir() else 0o600)
    print(json.dumps(dict(package=str(output), source_commit=commit,
                          manifest_sha256=sha(output / 'manifest.json'),
                          files=len(files))))


if __name__ == '__main__':
    main()
