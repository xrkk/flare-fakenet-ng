"""Independent Linux original-evidence verifier; summaries grant no credit."""
from __future__ import annotations
import base64
import configparser
import hashlib
import ipaddress
import json
from pathlib import Path
import re

CHECKS = {'LINUX-SINGLEHOST': ['singlehost', 'multihost', 'nfqueue', 'ipv6-block', 'restore'],
          'LINUX-DEPLOY-UPDATE': ['install', 'idle-update', 'transaction', 'token', 'rollback']}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _read(folder, relative):
    path = folder / relative
    if Path(relative).is_absolute() or '..' in Path(relative).parts or path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(folder.resolve()):
        raise ValueError('Linux original escaped or missing: ' + relative)
    return json.loads(path.read_text())


def _payloads(folder, expected):
    import dpkt
    packets = []
    for path in folder.glob('capture*.pcap'):
        if path.is_symlink(): raise ValueError('PCAP symlink')
        with path.open('rb') as stream:
            reader = dpkt.pcap.Reader(stream)
            for timestamp, raw in reader:
                if reader.datalink() == dpkt.pcap.DLT_EN10MB: ip = dpkt.ethernet.Ethernet(raw).data
                elif reader.datalink() in (dpkt.pcap.DLT_RAW, 101): ip = dpkt.ip.IP(raw)
                else: raise ValueError('unsupported PCAP link type')
                if not isinstance(ip, dpkt.ip.IP) or not isinstance(ip.data, dpkt.udp.UDP): continue
                udp = ip.data
                packets.append((str(ipaddress.IPv4Address(ip.src)), udp.sport,
                                str(ipaddress.IPv4Address(ip.dst)), udp.dport, bytes(udp.data)))
    probe = _read(folder, 'probe.json')
    payload = ('FN-LINUX/' + expected['probe']['nonce']).encode()
    if probe['payload_hex'] != payload.hex() or probe['response_hex'] != payload.hex() or probe['remote'] != [expected['probe']['address'], expected['probe']['port']]:
        raise ValueError('UDP exchange differs from nonce/request')
    local = probe['local']; remote = probe['remote']
    if (local[0], local[1], remote[0], remote[1], payload) not in packets or (remote[0], remote[1], local[0], local[1], payload) not in packets:
        raise ValueError('PCAP lacks both exact nonce directions')
    return probe


def _evaluate_deploy_update(root, folder, expected_inputs, allow_fixture, value):
    rows = {name: 'fail' for name in ('install', 'idle-update', 'transaction', 'token', 'rollback')}
    detail = {}
    def require(ok, why):
        if not ok: raise ValueError(why)
    def actual(path, reason):
        path = Path(path)
        require(path.is_absolute() and path.is_file() and not path.is_symlink(), reason)
        return path
    def inside(base, path, reason):
        base = Path(base).resolve(); path = Path(path)
        require(path.is_absolute() and not path.is_symlink() and path.resolve().is_relative_to(base), reason)
        return path
    try:
        fixture = value.get('fixture') is True
        require(fixture == (expected_inputs.get('fixture') is True), 'fixture identity differs')
        if fixture:
            require(allow_fixture, 'fixture cannot earn native credit')
        require(value.get('inputs') == expected_inputs, 'frozen deployment inputs mismatch')
        deploy = value.get('deploy')
        require(isinstance(deploy, dict) and deploy.get('accepted_update_root'), 'deployment originals missing')
        fresh = Path(expected_inputs.get('fresh_root', deploy.get('fresh_root')))
        update = Path(expected_inputs.get('accepted_update_root', deploy.get('accepted_update_root')))
        require(fresh.is_dir() and update.is_dir(), 'owned deployment roots missing')
        install_package = Path(expected_inputs['install_package'])
        update_package = Path(expected_inputs['update_package'])
        require(sha(install_package / 'manifest.json') == expected_inputs['install_manifest_sha256'], 'install package changed')
        require(sha(update_package / 'manifest.json') == expected_inputs['update_manifest_sha256'], 'update package changed')
        update_manifest = json.loads((update_package / 'manifest.json').read_text())
        require(update_manifest.get('base_manifest') == '9f09c2b2c0051af25e689914f1a5d3839e1112e0a70b0effb15fd38252e772ef', 'accepted base manifest differs')
        op = expected_inputs['operation']

        fresh_receipt = actual(fresh / 'opt' / ('.fakenet-deploy-' + op) / 'receipt.json', 'fresh original receipt missing')
        receipt = json.loads(fresh_receipt.read_text())
        require(receipt.get('phase') == 'completed' and receipt.get('manifest_sha256') == expected_inputs['install_manifest_sha256'] and receipt.get('operation') == op, 'fresh install did not complete through original receipt')
        target = fresh / 'opt/fakenet-ng'; token = fresh / 'etc/fakenet-ng-linux/token'; unit = fresh / 'etc/systemd/system/fakenet-ng-linux.service'
        require(target.is_dir() and unit.is_file() and token.is_file(), 'fresh installed tree missing')
        require(token.stat().st_mode & 0o777 == 0o600 and re.fullmatch(r'[0-9a-fA-F]{64}\n?', token.read_text()) is not None, 'fresh token invalid')
        config = configparser.RawConfigParser(); config.read(target / 'fakenet/configs/default.ini')
        require(config.has_section('Diverter'), 'installed Diverter config missing')
        for option in ('LinuxFlushIptables', 'FixGateway', 'FixDNS', 'ModifyLocalDNS', 'StopDNSService'):
            require(config.getboolean('Diverter', option) is False, 'installed network option enabled: ' + option)
        require(not config.has_option('Diverter', 'LinuxFlushDNSCommand'), 'installed DNS command remains')
        for name, digest in receipt.get('installed_files', {}).items():
            path = actual(fresh / name, 'installed file missing: ' + name)
            require(sha(path) == digest, 'installed file changed: ' + name)
        fresh_record = deploy.get('fresh') or {}
        require(fresh_record.get('reentry_commands') == [], 'install reentry executed commands')
        require(fresh_record.get('before') and 'opt/fakenet-ng' not in fresh_record['before'], 'fresh target existed before install')
        require(fresh_record.get('commands') is not None, 'install command evidence missing')
        rows['install'] = 'pass'

        update_receipt = actual(update / 'opt' / ('.fakenet-update-' + op + '-normal') / 'receipt.json', 'normal update receipt missing')
        ureceipt = json.loads(update_receipt.read_text())
        require(ureceipt.get('phase') == 'completed' and ureceipt.get('manifest') == expected_inputs['update_manifest_sha256'] and ureceipt.get('operation') == op + '-normal', 'normal update receipt mismatch')
        token_base = update / 'etc/fakenet-ng-linux/token'
        require(token_base.is_file() and token_base.stat().st_mode & 0o777 == 0o600 and token_base.stat().st_ino == update_manifest['token_inode'], 'accepted token identity changed')
        transaction = update / 'opt' / ('.fakenet-update-' + op + '-normal')
        for name, row in update_manifest['files'].items():
            path = update / 'opt/fakenet-ng' / name
            require(path.is_file() and sha(path) == row['new_sha256'], 'updated source differs: ' + name)
            backup = inside(transaction / 'originals', Path(ureceipt['originals'][name]['backup']), 'update backup escaped transaction')
            require(backup.is_file() and sha(backup) == row['old_sha256'], 'update backup differs: ' + name)
        unrelated = deploy.get('update', {}).get('before', {}).get('opt/fakenet-ng/unrelated.txt')
        require(unrelated is not None, 'initial unrelated file state missing')
        unrelated_path = update / 'opt/fakenet-ng/unrelated.txt'
        require(unrelated_path.is_file() and sha(unrelated_path) == unrelated.get('sha256') and unchanged_stat(unrelated_path, unrelated), 'unrelated accepted file changed')
        update_record = deploy.get('update') or {}
        update_commands = update_record.get('commands') or []
        stops = [i for i, row in enumerate(update_commands) if row.get('argv', [])[:2] == ['systemctl', 'stop']]
        starts = [i for i, row in enumerate(update_commands) if row.get('argv', [])[:2] == ['systemctl', 'start']]
        require(stops and starts and min(stops) < min(starts), 'normal update did not stop before start')
        require(update_record.get('reentry_commands') == [], 'update reentry executed commands')
        require((update_record.get('reentry') or {}).get('phase') == 'completed', 'update reentry not completed')
        rows['idle-update'] = 'pass'; rows['transaction'] = 'pass'; rows['token'] = 'pass'

        if not fixture:
            detail['rollback'] = 'original updater has no automatic rollback; no recovery was performed in production'
            rows['rollback'] = 'blocked'
            return ([{'id': name, 'status': rows[name]} for name in ('install', 'idle-update', 'transaction', 'token', 'rollback')],
                    False, detail)
        failure = deploy.get('failure_install')
        require(isinstance(failure, dict) and failure.get('error'), 'failed install evidence missing')
        failure_root = inside(fresh.parent, Path(failure['root']), 'failed install root escaped case')
        failure_receipt = inside(failure_root / 'opt', failure_root / 'opt' / ('.fakenet-deploy-' + op + '-failure') / 'receipt.json', 'failed install receipt escaped case')
        freceipt = json.loads(failure_receipt.read_text())
        require(freceipt.get('phase') == 'failed' and freceipt.get('failure_at') in ('preserved', 'installed'), 'failed install phase missing')
        archived = failure_root / Path(freceipt.get('archive')) / 'original.txt'
        require(archived.is_file() and archived.read_text() == 'retained original', 'failed install original not preserved')
        original_before = (failure.get('before') or {}).get('opt/fakenet-ng/original.txt')
        require(original_before and original_before.get('inode') == archived.stat().st_ino, 'failed install archive inode differs')
        require(not any('systemctl' in (row.get('argv') or []) for row in failure.get('commands', []) if isinstance(row, dict)), 'failed install activated service')

        negative = deploy.get('update', {}).get('negative', {})
        for branch in ('active', 'source', 'token'):
            item = negative.get(branch) or {}
            require(item.get('refused') is True and item.get('error'), 'required update negative not refused: ' + branch)
        for branch in ('active', 'source', 'token'):
            tx = update / 'opt' / ('.fakenet-update-' + op + '-' + branch)
            require(not tx.exists(), 'refused update created transaction: ' + branch)
        stop = negative.get('stop') or {}; sreceipt = None
        if stop.get('receipt'):
            sreceipt = inside(update / 'opt', Path(stop['receipt']), 'stop failure receipt escaped accepted root')
            sdata = json.loads(sreceipt.read_text())
            require(sdata.get('phase') == 'failed' and sdata.get('published') == [], 'stop failure evidence mismatch')
        else: raise ValueError('stop failure receipt missing')
        start = negative.get('start') or {}
        require(start.get('error') and start.get('receipt'), 'start failure evidence missing')
        streceipt = inside(update / 'opt', Path(start['receipt']), 'start failure receipt escaped accepted root')
        sdata = json.loads(streceipt.read_text())
        require(sdata.get('phase') == 'failed' and len(sdata.get('published', [])) == 2, 'start failure publication/phase missing')
        for name, row in update_manifest['files'].items():
            backup = inside(streceipt.parent / 'originals', Path(sdata['originals'][name]['backup']), 'start failure backup escaped transaction')
            require(backup.is_file() and sha(backup) == row['old_sha256'], 'start failure lost old backup: ' + name)
        recovery = deploy.get('recovery')
        require(isinstance(recovery, dict) and recovery.get('restored'), 'owned rollback recovery missing')
        for name, row in update_manifest['files'].items():
            restored = recovery['restored'].get(name) or {}
            require(restored.get('sha256') == row['old_sha256'] and restored.get('mode') is not None,
                    'rollback source bytes/mode differ: ' + name)
            backup = inside(streceipt.parent / 'originals', Path(sdata['originals'][name]['backup']), 'rollback backup escaped transaction')
            require(Path(restored.get('backup', '')).resolve() == backup.resolve(), 'rollback backup path differs: ' + name)
        recovery_state = _read(folder, 'recovery-state.json')
        require(recovery_state == recovery, 'recovery state original differs')
        for name, row in update_manifest['files'].items():
            raw = folder / 'recovery-observed' / name
            require(raw.is_file() and not raw.is_symlink() and sha(raw) == row['old_sha256'],
                    'observed restored bytes differ: ' + name)
            observed = recovery_state.get('observed', {}).get('opt/fakenet-ng/' + name, {})
            require(observed.get('sha256') == row['old_sha256'] and observed.get('mode') == sdata['originals'][name]['mode'],
                    'observed restoration state differs: ' + name)
        service = recovery_state.get('service') or {}
        require(service.get('state') == 'stopped' and service.get('run_id') is None and service.get('health', {}).get('process_alive') is False,
                'recovery service not stopped')
        require(value.get('error') is None and value.get('cleanup', {}).get('stopped') is True and value.get('cleanup', {}).get('system_service_used') is False,
                'producer error or unknown cleanup')
        # The failed receipt remains after owned recovery; no automatic-rollback
        # claim is made by the oracle.
        detail['rollback'] = 'owned recovery from original failed-receipt backups verified; failed receipt retained'
        rows['rollback'] = 'pass'
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        rows = {name: 'fail' for name in rows}
        detail['error'] = type(exc).__name__ + ': ' + str(exc)
    return ([{'id': name, 'status': rows[name]} for name in ('install', 'idle-update', 'transaction', 'token', 'rollback')],
            all(status == 'pass' for status in rows.values()), detail)


def unchanged_stat(path, row):
    status = Path(path).stat()
    return (status.st_mode & 0o7777) == row.get('mode') and status.st_ino == row.get('inode') and status.st_size == row.get('size')



def evaluate(root, original, case, checks=None, allow_fixture=False, expected_inputs=None):
    identities = CHECKS[case]
    if checks is not None and list(checks) != identities:
        raise ValueError('Linux full case requires exact original check set')
    rows = {name: 'fail' for name in identities}; detail = {}
    folder = Path(original)
    try:
        value = _read(folder, 'linux-result.json')
        if value.get('schema') != 'fakenet.linux-runtime-result.v2' or value.get('case') != case:
            raise ValueError('unrecognized Linux original result schema/case')
        if not isinstance(expected_inputs, dict) or value.get('inputs') != expected_inputs:
            raise ValueError('independent frozen Linux request identity required')
        if value.get('fixture') is True and not allow_fixture:
            raise ValueError('fixture cannot earn native credit')
        pins = value.get('originals')
        if not isinstance(pins, dict) or not pins:
            raise ValueError('Linux exact original index required')
        actual = {p.relative_to(folder).as_posix() for p in folder.rglob('*') if p.is_file() and p.name != 'linux-result.json'}
        if set(pins) != actual: raise ValueError('Linux original set differs')
        for name, digest in pins.items():
            path = folder / name
            if Path(name).is_absolute() or '..' in Path(name).parts or path.is_symlink() or not path.resolve().is_relative_to(folder.resolve()) or sha(path) != digest:
                raise ValueError('Linux original changed/escaped: ' + name)
        for rel, digest in expected_inputs['source_hashes'].items():
            path = Path(root) / rel
            if Path(rel).is_absolute() or '..' in Path(rel).parts or path.is_symlink() or not path.resolve().is_relative_to(Path(root).resolve()) or sha(path) != digest:
                raise ValueError('Linux original code binding differs')
        if case == 'LINUX-DEPLOY-UPDATE':
            return _evaluate_deploy_update(root, folder, expected_inputs, allow_fixture, value)
        needed = {'source.ini', 'actual.ini', 'start.json', 'stop.json', 'health.json', 'process.json',
                  'network-before.json', 'network-active.json', 'network-after.json', 'probe.json'}
        if not needed.issubset(pins): raise ValueError('runtime originals incomplete')
        parser = configparser.RawConfigParser(); parser.read(folder / 'actual.ini')
        if sha(folder / 'source.ini') != expected_inputs['config_sha256']:
            raise ValueError('requested source configuration changed')
        expected_config = configparser.RawConfigParser(); expected_config.read(folder / 'source.ini')
        expected_config.set('Diverter', 'DumpPackets', 'Yes')
        expected_config.set('Diverter', 'DumpPacketsFilePrefix', expected_inputs['owned_root'] + '/capture')
        if {sec: dict(parser.items(sec)) for sec in parser.sections()} != {sec: dict(expected_config.items(sec)) for sec in expected_config.sections()}:
            raise ValueError('runtime configuration differs from deterministic requested configuration')
        config = value['configuration']
        if config != {'path': 'actual.ini', 'sha256': sha(folder / 'actual.ini')}:
            raise ValueError('actual configuration bytes differ')
        start = _read(folder, 'start.json'); stop = _read(folder, 'stop.json')
        health = _read(folder, 'health.json'); process = _read(folder, 'process.json')
        if start.get('state') != 'healthy' or not isinstance(start.get('run_id'), str) or not re.fullmatch('[a-f0-9]{32}', start['run_id']):
            raise ValueError('original LinuxRunner start not healthy')
        if type(process.get('pid')) is not int or process['pid'] <= 0 or not str(process.get('birth', '')).isdecimal() or process.get('config_sha256') != config['sha256']:
            raise ValueError('process/configuration birth missing')
        if health.get('process_alive') is not True or health.get('nfqueue_present') is not True or health.get('ipv6_policy_drop') is not True:
            raise ValueError('current process/rules not observed')
        before = _read(folder, 'network-before.json'); active = _read(folder, 'network-active.json'); after = _read(folder, 'network-after.json')
        v4 = base64.b64decode(active['iptables'], validate=True).decode()
        v6 = base64.b64decode(active['ip6tables'], validate=True).decode()
        _payloads(folder, expected_inputs)
        if parser.get('Diverter', 'NetworkMode').lower() == expected_inputs['mode'] == 'singlehost': rows['singlehost'] = 'pass'
        if '-j NFQUEUE' in v4: rows['nfqueue'] = 'pass'
        if '-j DROP' in v6 or '-P OUTPUT DROP' in v6: rows['ipv6-block'] = 'pass'
        if before == after and stop.get('state') == 'stopped' and stop.get('run_id') is None and stop.get('release_controller') is True:
            rows['restore'] = 'pass'
        # A single local process/PCAP cannot establish the original second VM.
        detail['multihost'] = 'missing independently observed two-target client/gateway lifecycle'
        detail['producer_error'] = value.get('error')
    except (OSError, ValueError, KeyError, TypeError, NotImplementedError) as exc:
        rows = {name: 'fail' for name in identities}
        detail['error'] = type(exc).__name__ + ': ' + str(exc)
    return [{'id': name, 'status': rows[name]} for name in identities], all(v == 'pass' for v in rows.values()), detail
