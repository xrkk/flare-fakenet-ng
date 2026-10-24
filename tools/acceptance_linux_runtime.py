#!/usr/bin/env python3
"""Fixed Linux regression driver. Actual OS work runs only on the bound VM.

The result records originals, never substitutes summary flags for observations.
MultiHost remains explicitly incomplete until an independently observed second
client is connected; a local UDP probe must not earn that check.
"""
from __future__ import annotations
import argparse
import configparser
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import types

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = 'fakenet.linux-runtime-result.v2'
INPUT_SCHEMA = 'fakenet.linux-runtime-input.v2'
CHECKS = {'LINUX-SINGLEHOST': ['singlehost', 'multihost', 'nfqueue', 'ipv6-block', 'restore'],
          'LINUX-DEPLOY-UPDATE': ['install', 'idle-update', 'transaction', 'token', 'rollback']}
CASES = tuple(CHECKS)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def _deploy_module():
    text = (ROOT / 'deploy/linux/deploy.sh').read_text()
    body = text.split("<<'PY_DEPLOY'\n", 1)[1].rsplit('\nPY_DEPLOY', 1)[0]
    module = types.ModuleType('linux_acceptance_original_install')
    exec(compile(body, str(ROOT / 'deploy/linux/deploy.sh'), 'exec'), module.__dict__)
    return module


def _update_module():
    path = ROOT / 'deploy/linux/update-idle.py'
    spec = importlib.util.spec_from_file_location('linux_acceptance_original_update', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_inputs(case, out, value):
    if case not in CASES or not isinstance(value, dict):
        raise ValueError('Linux case/inputs invalid')
    common = {'schema', 'case', 'candidate_id', 'source_commit', 'package_sha256',
              'execution_id', 'target', 'owned_root', 'source_hashes'}
    specific = ({'config', 'config_sha256', 'mode', 'probe'} if case == 'LINUX-SINGLEHOST'
                else {'install_package', 'install_manifest_sha256', 'update_package',
                      'update_manifest_sha256', 'operation'})
    if set(value) != common | specific or value.get('schema') != INPUT_SCHEMA or value.get('case') != case:
        raise ValueError('Linux exact input schema required')
    for key, size in (('source_commit', 40), ('package_sha256', 64)):
        if not isinstance(value[key], str) or not re.fullmatch('[0-9a-f]{%d}' % size, value[key]):
            raise ValueError('Linux source/package identity invalid')
    if not isinstance(value['candidate_id'], str) or not value['candidate_id']:
        raise ValueError('candidate identity required')
    if not isinstance(value['execution_id'], str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,100}', value['execution_id']):
        raise ValueError('execution identity invalid')
    if value['target'].get('platform') != 'linux' or set(value['target']) != {'platform', 'hostname'}:
        raise ValueError('explicit Linux target required')
    destination = Path(out)
    if not destination.is_absolute() or destination.is_symlink() or destination.exists() or str(destination) != value['owned_root']:
        raise ValueError('new absolute owned output required')
    pins = value['source_hashes']
    required = {'fakenet/mcp/linuxrunner.py', 'fakenet/diverters/linuxnetpolicy.py',
                'deploy/linux/deploy.sh', 'deploy/linux/update-idle.py',
                'tools/acceptance_linux_runtime.py', 'tools/acceptance_linux_runtime_oracles.py'}
    if not isinstance(pins, dict) or not required.issubset(pins):
        raise ValueError('Linux original source bindings required')
    for rel, digest in pins.items():
        path = ROOT / rel
        if Path(rel).is_absolute() or '..' in Path(rel).parts or path.is_symlink() or not path.resolve().is_relative_to(ROOT) or sha(path) != digest:
            raise ValueError('Linux source mismatch: ' + rel)
    if case == 'LINUX-SINGLEHOST':
        config = Path(value['config'])
        if not config.is_absolute() or config.is_symlink() or not config.is_file() or sha(config) != value['config_sha256']:
            raise ValueError('Linux configuration identity invalid')
        parser = configparser.RawConfigParser(); parser.read(config)
        if value['mode'] not in ('singlehost', 'multihost') or parser.get('Diverter', 'NetworkMode').lower() != value['mode']:
            raise ValueError('Linux configuration mode differs')
        # Native MultiHost needs a separate client/gateway, not a local probe.
        if value['mode'] == 'multihost':
            raise NotImplementedError('MultiHost requires existing two-target orchestration; local probe cannot replace second client')
        probe = value['probe']
        if not isinstance(probe, dict) or set(probe) != {'address', 'port', 'nonce'}:
            raise ValueError('fixed UDP echo probe required')
        ipaddress.IPv4Address(probe['address'])
        if type(probe['port']) is not int or not 1 <= probe['port'] <= 65535 or not re.fullmatch(r'[a-f0-9]{32}', probe['nonce']):
            raise ValueError('probe identity invalid')
    else:
        if not re.fullmatch(r'[A-Za-z0-9-]{8,72}', value['operation']):
            raise ValueError('deployment operation invalid')
        for name in ('install', 'update'):
            package = Path(value[name + '_package'])
            if not package.is_absolute() or package.is_symlink() or not package.is_dir() or sha(package / 'manifest.json') != value[name + '_manifest_sha256']:
                raise ValueError('deployment package identity invalid')
        # Original validator verifies the complete dependency lock before writes.
        _deploy_module().validate_package(Path(value['install_package']), value['install_manifest_sha256'])
    return destination


def _birth(pid):
    return Path('/proc/%d/stat' % pid).read_text().rsplit(')', 1)[1].split()[19]


def _udp_probe(spec):
    payload = ('FN-LINUX/' + spec['nonce']).encode()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
        stream.settimeout(3)
        stream.connect((spec['address'], spec['port']))
        local = list(stream.getsockname())
        stream.send(payload)
        response = stream.recv(4096)
    if response != payload:
        raise RuntimeError('controlled UDP echo nonce differs')
    return {'local': local, 'remote': [spec['address'], spec['port']], 'payload_hex': payload.hex(), 'response_hex': response.hex()}


def _runtime(out, value, record):
    from acceptance_runtime import network_snapshot
    from fakenet.mcp.linuxrunner import LinuxRunner
    before = network_snapshot(); _json(out / 'network-before.json', before)
    (out / 'source.ini').write_bytes(Path(value['config']).read_bytes())
    parser = configparser.RawConfigParser(); parser.read(out / 'source.ini')
    parser.set('Diverter', 'DumpPackets', 'Yes')
    parser.set('Diverter', 'DumpPacketsFilePrefix', str(out / 'capture'))
    config = out / 'actual.ini'
    with config.open('x') as stream: parser.write(stream)
    identity = {'name': config.name, 'sha256': sha(config), 'builtin': False}
    runner = LinuxRunner(config_path_resolver=lambda name, builtin: str(config))
    start = None; stop = None
    try:
        start = runner.start(None, value['execution_id'], identity)
        _json(out / 'start.json', start)
        _json(out / 'process.json', {'pid': runner._proc.pid, 'birth': _birth(runner._proc.pid),
                                    'config_sha256': identity['sha256']})
        _json(out / 'network-active.json', network_snapshot())
        _json(out / 'health.json', runner.health_detail(start['state']))
        _json(out / 'probe.json', _udp_probe(value['probe']))
    finally:
        # Always ask the original owner to stop, including a failed start.
        stop = runner.stop(None)
        _json(out / 'stop.json', stop)
        after = network_snapshot(); _json(out / 'network-after.json', after)
        record['cleanup'] = {'stopped': stop.get('state') == 'stopped' and stop.get('run_id') is None,
                             'network_restored': before == after}
    if hasattr(runner, '_child_log') and Path(runner._child_log).is_file():
        (out / 'core-console.log').write_bytes(Path(runner._child_log).read_bytes())
    record['configuration'] = {'path': 'actual.ini', 'sha256': identity['sha256']}
    record['missing_checks'] = ['multihost']


def _deploy_update(out, value, record):
    raise NotImplementedError(
        'installer requires a fresh target, while the original pinned updater '
        'requires the accepted existing base and token inode; separate owned '
        'targets or an explicitly restored accepted base are required. '
        'No installation or system service action was started.')


def run(case, out, inputs=None, memory_mode=False):
    destination = validate_inputs(case, out, inputs)
    if memory_mode:
        raise ValueError('no synthetic memory driver; tests isolate OS at its boundary')
    if case == 'LINUX-DEPLOY-UPDATE':
        _deploy_update(destination, inputs, {})  # Refuse before any write/service operation.
    from acceptance_runtime import require_target
    require_target(inputs['target'])
    destination.mkdir(parents=True, exist_ok=False)
    record = {'schema': SCHEMA, 'case': case, 'inputs': inputs, 'cleanup': {'stopped': False, 'network_restored': False}, 'error': None}
    try:
        if case == 'LINUX-SINGLEHOST': _runtime(destination, inputs, record)
        else: _deploy_update(destination, inputs, record)
    except BaseException as exc:
        record['error'] = type(exc).__name__ + ': ' + str(exc)
    finally:
        record['originals'] = {p.relative_to(destination).as_posix(): sha(p) for p in sorted(destination.rglob('*')) if p.is_file()}
        _json(destination / 'linux-result.json', record)
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(); parser.add_argument('--case', required=True, choices=CASES)
    parser.add_argument('--output', required=True); parser.add_argument('--inputs', required=True)
    args = parser.parse_args(argv)
    value = json.loads(Path(args.inputs).read_text())
    run(args.case, args.output, value)
    import acceptance_linux_runtime_oracles as oracle
    rows, clean, detail = oracle.evaluate(ROOT, args.output, args.case, expected_inputs=value)
    passed = clean and all(row['status'] == 'pass' for row in rows)
    print(json.dumps({'status': 'pass' if passed else 'fail', 'checks': rows, 'detail': detail}))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
