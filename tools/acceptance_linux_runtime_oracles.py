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
            # No truthful normal deployment+restore producer currently exists.
            raise NotImplementedError('original accepted-base/token deployment recovery chain is not connected')
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
