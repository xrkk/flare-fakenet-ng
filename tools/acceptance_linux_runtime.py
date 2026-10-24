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
import tarfile
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


def validate_inputs(case, out, value, os_boundary=None):
    if case not in CASES or not isinstance(value, dict):
        raise ValueError('Linux case/inputs invalid')
    common = {'schema', 'case', 'candidate_id', 'source_commit', 'package_sha256',
              'execution_id', 'target', 'source_hashes'}
    specific = ({'fresh_root', 'accepted_update_root', 'install_package',
                 'install_manifest_sha256', 'update_package',
                 'update_manifest_sha256', 'operation'}
                if case == 'LINUX-DEPLOY-UPDATE'
                else {'owned_root', 'config', 'config_sha256', 'mode', 'probe'})
    expected_keys = common | specific
    if case == 'LINUX-DEPLOY-UPDATE' and 'fixture' in value:
        if type(value['fixture']) is not bool:
            raise ValueError('fixture identity must be boolean')
        expected_keys = expected_keys | {'fixture'}
    if set(value) != expected_keys or value.get('schema') != INPUT_SCHEMA or value.get('case') != case:
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
    fresh_root = destination if case == 'LINUX-DEPLOY-UPDATE' else Path(value['owned_root'])
    if case == 'LINUX-DEPLOY-UPDATE' and 'fixture' not in value:
        fresh_root = Path(value['fresh_root'])
    if case == 'LINUX-DEPLOY-UPDATE':
        fresh_root = Path(value['fresh_root'])
        if not fresh_root.is_absolute() or fresh_root.is_symlink() or any(p.is_symlink() for p in fresh_root.parents) or fresh_root.exists():
            raise ValueError('fresh deployment root must be new and absolute')
        if destination != fresh_root:
            raise ValueError('case output must be the fresh deployment root')
        accepted_root = Path(value['accepted_update_root'])
        if (not accepted_root.is_absolute() or accepted_root.is_symlink() or any(p.is_symlink() for p in accepted_root.parents) or not accepted_root.is_dir()
                or accepted_root.resolve() == fresh_root.resolve()
                or fresh_root.resolve().is_relative_to(accepted_root.resolve())
                or accepted_root.resolve().is_relative_to(fresh_root.resolve())):
            raise ValueError('accepted update root must be a distinct existing owned directory')
    else:
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
        fixture = value.get('fixture') is True
        if fixture and os_boundary is None:
            raise ValueError('fixture requires explicit isolated OS boundary')
        if os_boundary is not None and not fixture:
            raise ValueError('OS fixture boundary requires explicit fixture identity')
        owner = getattr(os_boundary, 'owner', 0) if fixture else 0
        install_validator = _deploy_module()
        install_validator.OWNER = owner
        install_validator.validate_package(Path(value['install_package']), value['install_manifest_sha256'])
        if accepted_root.stat().st_uid != owner:
            raise ValueError('accepted update root owner boundary differs')
        update_package = Path(value['update_package'])
        update_manifest = update_package / 'manifest.json'
        if not update_manifest.is_file() or sha(update_manifest) != value['update_manifest_sha256']:
            raise ValueError('deployment update package identity invalid')
        manifest = json.loads(update_manifest.read_text())
        updater = update_package / 'update-idle.py'
        if (manifest.get('base_manifest') != '9f09c2b2c0051af25e689914f1a5d3839e1112e0a70b0effb15fd38252e772ef'
                or set(manifest.get('files', {})) != {'fakenet/mcp/linuxrunner.py',
                                                       'fakenet/diverters/linuxnetpolicy.py'}
                or not updater.is_file() or sha(updater) != manifest.get('updater_sha256')
                or type(manifest.get('token_inode')) is not int):
            raise ValueError('deployment update manifest preflight invalid')
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


def _snapshot(root):
    root = Path(root); rows = {}
    for path in [root] + sorted(root.rglob('*'), key=lambda p: p.as_posix()):
        relative = '.' if path == root else path.relative_to(root).as_posix()
        status = path.lstat()
        row = {'kind': 'directory' if path.is_dir() else 'symlink' if path.is_symlink() else 'file',
               'mode': status.st_mode & 0o7777, 'inode': status.st_ino,
               'size': status.st_size, 'uid': status.st_uid}
        if row['kind'] == 'symlink':
            row['target'] = os.readlink(path)
        elif row['kind'] == 'file':
            row['sha256'] = sha(path)
        rows[relative] = row
    return rows


def _inside(base, candidate):
    base = Path(base).resolve(); original = Path(candidate); candidate = original.resolve()
    if candidate == base or not candidate.is_relative_to(base) or original.is_symlink() or any(p.is_symlink() for p in original.parents):
        raise ValueError('deployment evidence escaped owned transaction: ' + str(candidate))
    return candidate


def _recover_update(start_receipt, accepted_root):
    """Restore only the exact backups named by the original failed receipt."""
    receipt = json.loads(Path(start_receipt).read_text())
    transaction = Path(start_receipt).parent
    if receipt.get('phase') != 'failed':
        raise ValueError('recovery requires the original failed update receipt')
    restored = {}
    for name, row in receipt.get('originals', {}).items():
        backup = _inside(transaction / 'originals', Path(row['backup']))
        if not backup.is_file() or backup.is_symlink() or sha(backup) != row.get('sha256'):
            raise ValueError('failed-update backup changed: ' + name)
        target = _inside(Path(accepted_root) / 'opt/fakenet-ng', Path(accepted_root) / 'opt/fakenet-ng' / name)
        data = backup.read_bytes()
        target.write_bytes(data)
        target.chmod(int(row['mode']))
        if sha(target) != row['sha256']:
            raise ValueError('owned recovery write differs: ' + name)
        restored[name] = {'sha256': sha(target), 'mode': target.stat().st_mode & 0o7777,
                          'inode': target.stat().st_ino, 'backup': str(backup)}
    return {'receipt': str(start_receipt), 'restored': restored}


def _deploy_update(out, value, record, boundary=None):
    """Run the original install and update functions.

    boundary is supplied only by the test fixture.  It owns process, service,
    owner and credential edges; ordinary production delegates every such edge
    to the original deploy.sh/update-idle.py defaults.
    """
    out = Path(out); fresh_root = Path(value['fresh_root'])
    accepted_root = Path(value['accepted_update_root'])
    install_package = Path(value['install_package'])
    update_package = Path(value['update_package'])
    operation = value['operation']
    fixture = boundary is not None
    commands = {'install': [], 'install_failure': [], 'update': [],
                'active': [], 'source': [], 'token': [], 'stop': [], 'start': []}
    m = _deploy_module(); u = _update_module()
    if fixture:
        owner = boundary.owner
        m.OWNER = owner; u.OWNER = owner
    (fresh_root / 'opt').mkdir(mode=0o755, parents=True, exist_ok=True)
    for relative in ('etc', 'etc/systemd', 'etc/systemd/system'):
        (fresh_root / relative).mkdir(mode=0o755, exist_ok=True)

    def record_call(branch, function, argv):
        row = {'branch': branch, 'argv': list(argv)}
        commands[branch].append(row)
        try:
            result = function(argv)
            row['returned'] = result if isinstance(result, (str, int, bool, type(None))) else repr(result)
            return result
        except Exception as exc:
            row['error'] = type(exc).__name__ + ': ' + str(exc)
            raise

    if fixture:
        install_run = lambda argv: record_call('install', getattr(boundary, 'install_run'), argv)
        install_idle = getattr(boundary, 'install_idle')
        install_failure_run = lambda argv: record_call('install_failure', getattr(boundary, 'install_failure_run'), argv)
    else:
        install_run = lambda argv: record_call('install', m.command, argv)
        install_idle = None
        install_failure_run = None

    # Original fresh installation, followed by its original completed re-entry.
    fresh_before = _snapshot(fresh_root)
    install_kwargs = {'root': fresh_root, 'run': install_run}
    if fixture:
        install_kwargs['idle'] = install_idle
    install_receipt = m.install(install_package, value['install_manifest_sha256'],
                                operation, **install_kwargs)
    fresh_after = _snapshot(fresh_root)
    install_commands = list(commands['install'])
    install_reentry = m.install(install_package, value['install_manifest_sha256'],
                                operation, **install_kwargs)
    install_reentry_commands = commands['install'][len(install_commands):]

    update_commands = []
    update_reentry_commands = []
    update_receipt = None
    update_before = _snapshot(accepted_root)
    update_after = None
    negative = {}
    failure_install = None
    recovery = None

    if fixture:
        failure_root = Path(getattr(boundary, 'failure_root'))
        failure_before = _snapshot(failure_root)
        failure_error = None
        try:
            m.install(install_package, value['install_manifest_sha256'], operation + '-failure',
                      root=failure_root, run=install_failure_run,
                      idle=install_idle)
        except Exception as exc:
            failure_error = type(exc).__name__ + ': ' + str(exc)
        failure_after = _snapshot(failure_root)
        failure_receipt = failure_root / 'opt' / ('.fakenet-deploy-' + operation + '-failure') / 'receipt.json'
        failure_install = {'root': str(failure_root), 'before': failure_before,
                           'after': failure_after, 'error': failure_error,
                           'receipt': str(failure_receipt),
                           'commands': list(commands['install_failure'])}

        accepted_source = {name: (accepted_root / 'opt/fakenet-ng' / name).read_bytes()
                           for name in u.FILES}
        try:
            u.update(update_package, value['update_manifest_sha256'], operation + '-active',
                     root=accepted_root, preflight=getattr(boundary, 'preflight'),
                     run=lambda argv: record_call('active', getattr(boundary, 'active_run'), argv),
                     get_status=getattr(boundary, 'active_status'))
            negative['active'] = {'refused': False, 'error': None, 'commands': list(commands['active'])}
        except Exception as exc:
            negative['active'] = {'refused': True, 'error': type(exc).__name__ + ': ' + str(exc),
                                  'commands': list(commands['active'])}

        source_path = accepted_root / 'opt/fakenet-ng' / u.FILES[0]
        source_original = source_path.read_bytes()
        source_path.write_bytes(source_original + b'foreign edit')
        try:
            u.update(update_package, value['update_manifest_sha256'], operation + '-source',
                     root=accepted_root, preflight=getattr(boundary, 'preflight'),
                     run=lambda argv: record_call('source', getattr(boundary, 'source_run'), argv),
                     get_status=getattr(boundary, 'status'))
            negative['source'] = {'refused': False, 'error': None, 'commands': list(commands['source'])}
        except Exception as exc:
            negative['source'] = {'refused': True, 'error': type(exc).__name__ + ': ' + str(exc),
                                  'commands': list(commands['source'])}
        source_path.write_bytes(source_original)

        token_root = Path(getattr(boundary, 'token_root'))
        try:
            u.update(update_package, value['update_manifest_sha256'], operation + '-token',
                     root=token_root, preflight=getattr(boundary, 'preflight'),
                     run=lambda argv: record_call('token', getattr(boundary, 'token_run'), argv),
                     get_status=getattr(boundary, 'status'))
            negative['token'] = {'refused': False, 'error': None, 'commands': list(commands['token'])}
        except Exception as exc:
            negative['token'] = {'refused': True, 'error': type(exc).__name__ + ': ' + str(exc),
                                 'commands': list(commands['token'])}

        try:
            u.update(update_package, value['update_manifest_sha256'], operation + '-stop-failure',
                     root=accepted_root, preflight=getattr(boundary, 'preflight'),
                     run=lambda argv: record_call('stop', getattr(boundary, 'stop_run'), argv),
                     get_status=getattr(boundary, 'status'))
            negative['stop'] = {'failed': False, 'error': None, 'commands': list(commands['stop'])}
        except Exception as exc:
            negative['stop'] = {'failed': True, 'error': type(exc).__name__ + ': ' + str(exc),
                                'commands': list(commands['stop'])}
        stop_receipt = accepted_root / 'opt' / ('.fakenet-update-' + operation + '-stop-failure') / 'receipt.json'
        negative['stop']['receipt'] = str(stop_receipt)

        start_receipt_path = accepted_root / 'opt' / ('.fakenet-update-' + operation + '-start-failure') / 'receipt.json'
        try:
            u.update(update_package, value['update_manifest_sha256'], operation + '-start-failure',
                     root=accepted_root, preflight=getattr(boundary, 'preflight'),
                     run=lambda argv: record_call('start', getattr(boundary, 'start_run'), argv),
                     get_status=getattr(boundary, 'status'))
            negative['start'] = {'failed': False, 'error': None, 'commands': list(commands['start'])}
        except Exception as exc:
            negative['start'] = {'failed': True, 'error': type(exc).__name__ + ': ' + str(exc),
                                 'commands': list(commands['start'])}
        negative['start']['receipt'] = str(start_receipt_path)
        if start_receipt_path.is_file():
            recovery = _recover_update(start_receipt_path, accepted_root)
            recovery['service'] = getattr(boundary, 'status')()
            recovery['observed'] = _snapshot(accepted_root)
            observed_dir = out / 'recovery-observed'
            for name in u.FILES:
                copy = observed_dir / name
                copy.parent.mkdir(parents=True, exist_ok=True)
                copy.write_bytes((accepted_root / 'opt/fakenet-ng' / name).read_bytes())
            _json(out / 'recovery-state.json', recovery)

    # The one normal update and its completed re-entry.  Re-entry command
    # accounting starts only after the first normal return.
    if fixture:
        update_kwargs = {'root': accepted_root, 'preflight': getattr(boundary, 'preflight'),
                         'run': lambda argv: record_call('update', getattr(boundary, 'update_run'), argv),
                         'get_status': getattr(boundary, 'status')}
    else:
        update_kwargs = {'root': accepted_root,
                         'run': lambda argv: record_call('update', u.command, argv)}
    update_receipt = u.update(update_package, value['update_manifest_sha256'],
                              operation + '-normal', **update_kwargs)
    update_after = _snapshot(accepted_root)
    normal_count = len(commands['update'])
    update_reentry = u.update(update_package, value['update_manifest_sha256'],
                              operation + '-normal', **update_kwargs)
    update_reentry_commands = commands['update'][normal_count:]
    update_commands = commands['update'][:normal_count]

    record['fixture'] = bool(fixture or value.get('fixture') is True)
    record['mode'] = 'fixture' if fixture else 'production'
    record['source_hashes'] = value['source_hashes']
    record['deploy'] = {
        'fresh_root': str(fresh_root), 'accepted_update_root': str(accepted_root),
        'install_package': str(install_package), 'update_package': str(update_package),
        'operation': operation,
        'fresh': {'before': fresh_before, 'after': fresh_after,
                  'receipt': str(fresh_root / 'opt' / ('.fakenet-deploy-' + operation) / 'receipt.json'),
                  'commands': install_commands, 'reentry_commands': install_reentry_commands,
                  'reentry': install_reentry},
        'update': {'before': update_before, 'after': update_after,
                   'receipt': str(accepted_root / 'opt' / ('.fakenet-update-' + operation + '-normal') / 'receipt.json'),
                   'commands': update_commands, 'reentry_commands': update_reentry_commands,
                   'reentry': update_reentry, 'negative': negative},
        'failure_install': failure_install, 'recovery': recovery,
        'package_sha256': {'install_manifest': value['install_manifest_sha256'],
                           'update_manifest': value['update_manifest_sha256']},
    }
    service_state = getattr(boundary, 'status')() if fixture else 'not-observed'
    record['cleanup'] = {'service_state': service_state,
                         'stopped': isinstance(service_state, dict) and service_state.get('state') == 'stopped' and service_state.get('run_id') is None and service_state.get('health', {}).get('process_alive') is False,
                         'network_restored': 'not-exercised',
                         'system_service_used': not fixture,
                         'writers_exited': True}

def run(case, out, inputs=None, memory_mode=False, os_boundary=None):
    if isinstance(inputs, dict) and inputs.get('schema') == 'fakenet.linux-composite-input.v1':
        if case != 'LINUX-SINGLEHOST' or memory_mode:
            raise ValueError('composite input requires LINUX-SINGLEHOST without memory mode')
        import acceptance_linux_composite as composite
        return composite.run(out, inputs, boundary=os_boundary)
    destination = validate_inputs(case, out, inputs, os_boundary=os_boundary)
    if memory_mode:
        raise ValueError('no synthetic memory driver; tests isolate OS at its boundary')
    from acceptance_runtime import require_target
    require_target(inputs['target'])
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    record = {'schema': SCHEMA, 'case': case, 'inputs': inputs, 'fixture': bool(inputs.get('fixture') is True or os_boundary is not None), 'cleanup': {'stopped': False, 'network_restored': False}, 'error': None}
    try:
        if case == 'LINUX-SINGLEHOST': _runtime(destination, inputs, record)
        else: _deploy_update(destination, inputs, record, boundary=os_boundary)
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
    if value.get('schema') == 'fakenet.linux-composite-input.v1':
        import acceptance_linux_composite as composite
        composite.run(args.output, value)
    else:
        run(args.case, args.output, value)
    import acceptance_linux_runtime_oracles as oracle
    rows, clean, detail = oracle.evaluate(ROOT, args.output, args.case, expected_inputs=value, allow_fixture=value.get('fixture') is True)
    passed = clean and all(row['status'] == 'pass' for row in rows)
    print(json.dumps({'status': 'pass' if passed else 'fail', 'checks': rows, 'detail': detail}))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
