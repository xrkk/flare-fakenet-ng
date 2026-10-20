#!/usr/bin/env python3
"""Export the single-author egress contract into MalTrace's local copy.

The exported file is a necessary distribution artifact, not a development
copy.  It carries the source path/hash/version and must not be edited
independently.  This tool is standard-library only and never imports the
target project.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile


SOURCE_RELATIVE = Path('fakenet/mcp/egress_contract.py')
HEADER = (
    '# GENERATED FILE - DO NOT EDIT INDEPENDENTLY\n'
    '# Generated from {source} by tools/export_egress_contract.py\n'
    '# Source-SHA256: {source_sha256}\n'
    '# Contract-Version: {version}\n'
)


def sha256_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def read_contract(repo, source=None):
    repo = Path(repo).resolve()
    source = (repo / (source or SOURCE_RELATIVE)).resolve()
    if not source.is_relative_to(repo) or not source.is_file():
        raise ValueError('contract source is not a plain file inside the repo')
    raw = source.read_bytes()
    compile(raw, str(source), 'exec')
    return source, raw


def contract_version(raw):
    code = compile(raw, '<contract>', 'exec')
    namespace = {}
    exec(code, namespace)
    version = namespace.get('CONTRACT_VERSION')
    if not isinstance(version, int) or version < 1:
        raise ValueError('contract version missing')
    return version


def generated_bytes(source_relative, raw):
    source_sha = sha256_bytes(raw)
    version = contract_version(raw)
    header = HEADER.format(source=source_relative.as_posix(),
                           source_sha256=source_sha,
                           version=version).encode('utf-8')
    identity = (
        '\n\n# Generated identity (do not edit)\n'
        'SOURCE_SHA256 = %r\n'
        'GENERATED_SOURCE_PATH = %r\n'
        'GENERATED_CONTRACT_VERSION = CONTRACT_VERSION\n'
        % (source_sha, source_relative.as_posix())
    ).encode('utf-8')
    return header + raw + identity, source_sha, version


def atomic_write(path, raw):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix='.egress-export-')
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', default='.')
    parser.add_argument('--source')
    parser.add_argument('--output', required=True)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args(argv)
    source, raw = read_contract(args.repo, args.source)
    relative = source.relative_to(Path(args.repo).resolve())
    output_raw, source_sha, version = generated_bytes(relative, raw)
    target = Path(args.output).resolve()
    if args.check:
        if not target.is_file():
            print(json.dumps({'status': 'MISSING', 'target': str(target),
                              'source_sha256': source_sha,
                              'contract_version': version}))
            return 1
        current = target.read_bytes()
        matches = current == output_raw
        print(json.dumps({'status': 'MATCH' if matches else 'DRIFT',
                          'target': str(target),
                          'source_sha256': source_sha,
                          'output_sha256': sha256_bytes(output_raw),
                          'current_sha256': sha256_bytes(current),
                          'contract_version': version}))
        return 0 if matches else 1
    atomic_write(target, output_raw)
    print(json.dumps({'status': 'WRITTEN', 'target': str(target),
                      'source_sha256': source_sha,
                      'output_sha256': sha256_bytes(output_raw),
                      'contract_version': version}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
