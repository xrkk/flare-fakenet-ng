#!/usr/bin/env python3
"""Independent content judge for the headless policy driver.

The judge reads the original INI, core log and every declared capture.  It
does not trust the driver's check status, application booleans or cleanup
boolean: each pass is reconstructed from an attempt, a matching packet in the
attempt window, the selected policy value and the recorded service response.
"""
from __future__ import annotations

import configparser
import hashlib
import ipaddress
import json
import socket
import struct
from pathlib import Path

SCHEMA = 'fakenet.policy-result.v1'
APPLICATION_CHECKS = {'tls_application', 'reviewed_ip_tls', 'sink_tcp',
                      'sink_udp'}
DNS_CHECKS = {'exact_domain', 'wildcard_domain', 'apex_denied',
              'default_deny'}
DENY_CHECKS = {'apex_denied', 'default_deny', 'port_80_denied',
               'port_444_denied', 'udp443_denied', 'other_ip_denied',
               'adjacent_denied', 'icmp_denied', 'ipv6_denied'}
STATUS = ('pass', 'fail', 'unknown', 'not_run', 'blocked', 'skip',
          'observed')


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _read(path):
    return Path(path).read_text(encoding='utf-8', errors='replace')


def _safe_file(original, item, label):
    if not isinstance(item, dict):
        raise ValueError('%s reference missing' % label)
    relative = item.get('path')
    if not isinstance(relative, str) or Path(relative).is_absolute():
        raise ValueError('%s path is not relative' % label)
    path = (Path(original) / relative).resolve()
    if not path.is_relative_to(Path(original).resolve()):
        raise ValueError('%s path escapes original directory' % label)
    if path.is_symlink() or not path.is_file():
        raise ValueError('%s original is missing' % label)
    if item.get('sha256') != _sha256(path):
        raise ValueError('%s original hash changed' % label)
    return path


def _pcap_packets(path):
    data = Path(path).read_bytes()
    if len(data) < 24:
        return []
    magic = data[:4]
    if magic == b'\x0a\x0d\x0d\x0a':
        return _pcapng_packets(data)
    if magic == b'\xd4\xc3\xb2\xa1':
        endian, nano = '<', False
    elif magic == b'\xa1\xb2\xc3\xd4':
        endian, nano = '>', False
    elif magic == b'\x4d\x3c\xb2\xa1':
        endian, nano = '<', True
    elif magic == b'\xa1\xb2\x3c\x4d':
        endian, nano = '>', True
    else:
        raise ValueError('unsupported PCAP magic')
    _, _, _, _, _, linktype = struct.unpack(endian + 'HHIIII',
                                           data[4:24])
    offset = 24
    packets = []
    while offset + 16 <= len(data):
        sec, frac, included, original = struct.unpack(
            endian + 'IIII', data[offset:offset + 16])
        offset += 16
        if included > len(data) - offset:
            raise ValueError('truncated PCAP record')
        frame = data[offset:offset + included]
        offset += included
        stamp = sec + frac / (1e9 if nano else 1e6)
        packet = _decode_frame(frame, linktype, stamp)
        if packet is not None:
            packets.append(packet)
    return packets


def _pcapng_packets(data):
    # Bounded support for the simple Ethernet pcapng produced by the existing
    # observation path; unknown blocks are skipped, never guessed.
    packets = []
    offset = 0
    endian = '<'
    while offset + 12 <= len(data):
        block_type = struct.unpack(endian + 'I', data[offset:offset + 4])[0]
        if block_type == 0x0A0D0D0A:
            if offset + 12 > len(data):
                break
            bom = data[offset + 8:offset + 12]
            endian = '<' if bom == b'\x4d\x3c\x2b\x1a' else '>'
            block_len = struct.unpack(endian + 'I', data[offset + 4:offset + 8])[0]
            offset += block_len
            continue
        block_len = struct.unpack(endian + 'I', data[offset + 4:offset + 8])[0]
        if block_len < 12 or offset + block_len > len(data):
            break
        if block_type == 6 and block_len >= 32:
            interface = struct.unpack(endian + 'I', data[offset + 8:offset + 12])[0]
            ts_high, ts_low, cap_len, orig_len = struct.unpack(
                endian + 'IIII', data[offset + 12:offset + 28])
            frame = data[offset + 28:offset + 28 + cap_len]
            # Interface resolution is intentionally conservative; Ethernet is
            # the only link type used by this policy path.
            packet = _decode_frame(frame, 1, ts_high * 4294967296 + ts_low)
            if packet is not None:
                packets.append(packet)
        offset += block_len
    return packets


def _decode_frame(frame, linktype, stamp):
    if linktype == 1:
        if len(frame) < 14:
            return None
        ethertype = struct.unpack('!H', frame[12:14])[0]
        offset = 14
        if ethertype == 0x8100 and len(frame) >= 18:
            ethertype = struct.unpack('!H', frame[16:18])[0]
            offset = 18
        if ethertype != 0x0800:
            return None
    elif linktype in (101, 12, 228):
        offset = 0
    else:
        return None
    if len(frame) < offset + 20:
        return None
    version = frame[offset] >> 4
    if version != 4:
        return None
    ihl = (frame[offset] & 0x0f) * 4
    if ihl < 20 or len(frame) < offset + ihl + 4:
        return None
    total = struct.unpack('!H', frame[offset + 2:offset + 4])[0]
    if total < ihl + 4:
        return None
    transport = offset + ihl
    protocol = frame[offset + 9]
    src = socket.inet_ntoa(frame[offset + 12:offset + 16])
    dst = socket.inet_ntoa(frame[offset + 16:offset + 20])
    if protocol == 6 and len(frame) >= transport + 20:
        sport, dport = struct.unpack('!HH', frame[transport:transport + 4])
        data_offset = (frame[transport + 12] >> 4) * 4
        payload = frame[transport + data_offset:offset + total]
        return {'time': stamp, 'proto': 'TCP', 'src': src, 'sport': sport,
                'dst': dst, 'dport': dport, 'payload': payload}
    if protocol == 17 and len(frame) >= transport + 8:
        sport, dport = struct.unpack('!HH', frame[transport:transport + 4])
        payload = frame[transport + 8:offset + total]
        return {'time': stamp, 'proto': 'UDP', 'src': src, 'sport': sport,
                'dst': dst, 'dport': dport, 'payload': payload}
    if protocol in (1, 58):
        return {'time': stamp, 'proto': 'ICMP' if protocol == 1 else 'ICMPv6',
                'src': src, 'sport': 0, 'dst': dst, 'dport': 0,
                'payload': b''}
    return None


def _matching(packets, tuple_value, start, end):
    proto = str(tuple_value.get('proto', '')).upper()
    dst = tuple_value.get('dst')
    port = tuple_value.get('port')
    found = []
    for packet in packets:
        if not start - 1.0 <= packet['time'] <= end + 1.0:
            continue
        if packet['proto'] != proto:
            continue
        forward = packet['dst'] == dst and (proto not in ('TCP', 'UDP') or
                                            packet['dport'] == port)
        reverse = packet['src'] == dst and (proto not in ('TCP', 'UDP') or
                                            packet['sport'] == port)
        if forward or reverse:
            found.append(packet)
    return found


def _config_value(config, key):
    return config.get('Diverter', key, fallback='')


def _validate_config(original, scenario, inputs, checks):
    config_path = _safe_file(original, inputs['_config'], 'configuration')
    parser = configparser.ConfigParser(interpolation=None)
    parser.optionxform = str
    parser.read(config_path, encoding='utf-8-sig')
    if not parser.has_section('Diverter'):
        raise ValueError('configuration has no Diverter section')
    if _config_value(parser, 'ExternalAccessPolicy').strip().lower() != 'egresscontrol':
        raise ValueError('ExternalAccessPolicy is not EgressControl')
    if _config_value(parser, 'DumpPackets').strip().lower() not in (
            'yes', 'true', 'on', 'enabled', '1'):
        raise ValueError('DumpPackets is not enabled')
    if '443' not in [part.strip() for part in
                     _config_value(parser, 'ExternalAllowedTCPPorts').split(',')]:
        raise ValueError('ExternalAllowedTCPPorts does not contain 443')
    domains = _config_value(parser, 'ExternalAllowedDomains')
    if inputs['allowed_domain'] not in domains:
        raise ValueError('allowed domain is absent from configuration')
    if inputs['wildcard_domain'] not in domains:
        raise ValueError('wildcard domain is absent from configuration')
    try:
        ipaddress.ip_address(_config_value(parser, 'ExternalDnsServer').strip())
    except ValueError as error:
        raise ValueError('ExternalDnsServer is invalid') from error
    if scenario in ('ipv4', 'combined'):
        if _config_value(parser, 'ExternalAllowedIPv4'):
            raise ValueError('old ExternalAllowedIPv4 key is present')
        rule = _config_value(parser, 'ExternalAllowedIPv4Rules').strip()
        expected = 'TCP/%s/%d' % (inputs['reviewed_ip'],
                                  int(inputs['reviewed_port']))
        if rule != expected:
            raise ValueError('reviewed IPv4 rule differs from the selected input')
    if scenario in ('takeover', 'combined'):
        if _config_value(parser, 'ExternalTakeoverIPv4').strip() != inputs['sink_ip']:
            raise ValueError('takeover sink differs from the selected input')
        ttl = _config_value(parser, 'ExternalTakeoverDnsTTL').strip()
        if not ttl.isdigit() or not 1 <= int(ttl) <= 300:
            raise ValueError('takeover DNS TTL is invalid')
        for section in parser.sections():
            if parser[section].get('Listener') == 'DNSListener' and \
                    parser[section].get('ResponseA') != inputs['sink_ip']:
                raise ValueError('takeover DNS listener does not answer the sink')
    return parser


def _log_has(text, marker):
    return marker in text


def evaluate(original, scenario, checks, *, allow_fixture=False,
             expected_inputs=None):
    original = Path(original)
    value = json.loads(_read(original / 'policy-result.json'))
    if value.get('schema') != SCHEMA:
        raise ValueError('unknown policy result schema')
    if value.get('scenario') != scenario:
        raise ValueError('policy scenario mismatch')
    if value.get('fixture') is True and not allow_fixture:
        raise ValueError('fixture result cannot be used as native credit')
    if value.get('fixture') is True and allow_fixture:
        declared = [item.get('id') for item in value.get('checks') or []
                    if isinstance(item, dict)]
        if sorted(declared) != sorted(checks):
            raise ValueError('fixture check set differs from the driver table')
        attempts = value.get('attempts') or []
        by_id = {item.get('id'): item for item in attempts
                 if isinstance(item, dict)}
        rows = []
        for item in value.get('checks') or []:
            if item.get('status') != 'pass' or item.get('id') not in by_id:
                rows.append({'id': item.get('id'), 'status': 'unknown'})
            elif by_id[item['id']].get('nonce') != item.get('nonce'):
                rows.append({'id': item['id'], 'status': 'unknown'})
            else:
                rows.append({'id': item['id'], 'status': 'pass'})
        cleanup = value.get('cleanup') or {}
        process = cleanup.get('process_exit') or {}
        clean = (cleanup.get('stopped') is True and
                 cleanup.get('network_restored') is True and
                 process.get('exited') is True and
                 process.get('timed_out') is False and
                 process.get('returncode') == 0)
        return rows, clean
    config_path = _safe_file(original, value.get('config'), 'configuration')
    log_path = _safe_file(original, value.get('log'), 'core log')
    log_text = _read(log_path)
    if 'policy_exception' in log_text:
        raise ValueError('policy exception is present in the core log')
    pcap_items = value.get('pcap')
    if isinstance(pcap_items, dict):
        pcap_items = [pcap_items]
    if not isinstance(pcap_items, list):
        raise ValueError('capture table missing')
    packets = []
    pcap_paths = []
    for item in pcap_items:
        path = _safe_file(original, item, 'PCAP')
        pcap_paths.append(path)
        packets.extend(_pcap_packets(path))
    if not packets:
        # A declaration with only a header is not native evidence.
        value['_empty_capture'] = True
    inputs = dict(value.get('inputs') or {})
    if expected_inputs is not None:
        for key, expected in expected_inputs.items():
            if inputs.get(key) != expected:
                raise ValueError('policy input differs from the frozen plan: %s'
                                 % key)
    required_inputs = ('allowed_domain', 'wildcard_domain', 'apex_domain',
                       'denied_domain', 'reviewed_ip', 'reviewed_port',
                       'sink_ip', 'sink_port', 'adjacent_ip', 'adjacent_port')
    if any(key not in inputs for key in required_inputs):
        raise ValueError('result input table is incomplete')
    inputs['_config'] = value['config']
    try:
        _validate_config(original, scenario, inputs, checks)
        config_ok = True
    except ValueError:
        config_ok = False
    attempts = value.get('attempts')
    if not isinstance(attempts, list):
        raise ValueError('attempt table missing')
    attempt_by_id = {}
    for item in attempts:
        if not isinstance(item, dict) or not isinstance(item.get('id'), str):
            raise ValueError('invalid attempt row')
        if item['id'] in attempt_by_id:
            raise ValueError('duplicate attempt id: %s' % item['id'])
        if not isinstance(item.get('nonce'), str) or not item['nonce']:
            raise ValueError('attempt nonce missing: %s' % item['id'])
        attempt_by_id[item['id']] = item

    rows = []
    seen = set()
    for item in value.get('checks') or []:
        if not isinstance(item, dict) or not isinstance(item.get('id'), str):
            raise ValueError('invalid policy check row')
        name = item['id']
        status = item.get('status')
        if status not in STATUS:
            raise ValueError('invalid policy check status')
        if name not in checks:
            rows.append({'id': name, 'status': status})
            continue
        if name in seen:
            rows.append({'id': name, 'status': 'fail'})
            continue
        seen.add(name)
        valid = status == 'pass'
        reason = ''
        attempt = attempt_by_id.get(name)
        tuple_value = item.get('tuple')
        nonce = item.get('nonce')
        if valid and (attempt is None or not isinstance(tuple_value, dict)):
            valid, reason = False, 'attempt or tuple missing'
        if valid:
            if attempt.get('nonce') != nonce:
                valid, reason = False, 'attempt nonce mismatch'
            if tuple_value != attempt.get('tuple'):
                valid, reason = False, 'check tuple differs from attempt'
            try:
                start, end = float(attempt['started_at']), float(attempt['ended_at'])
                if end < start:
                    raise ValueError
            except (KeyError, TypeError, ValueError):
                valid, reason = False, 'attempt time window invalid'
        matched = []
        if valid:
            matched = _matching(packets, tuple_value, start, end)
            if name not in ('icmp_denied', 'ipv6_denied', 'route_restore') and not matched:
                valid, reason = False, 'no matching packet in attempt window'
            if name in DNS_CHECKS:
                if name in ('exact_domain', 'wildcard_domain'):
                    if not _log_has(log_text, 'DNS_LEASE_ADD domain=%s ' %
                                    (inputs['allowed_domain'] if name == 'exact_domain'
                                     else 'www.' + inputs['wildcard_domain'][2:])):
                        valid, reason = False, 'DNS lease log missing'
                elif not _log_has(log_text, "Received A request for domain '%s" %
                                  (inputs['apex_domain'] if name == 'apex_denied'
                                   else inputs['denied_domain'])):
                    valid, reason = False, 'denied DNS request was not observed'
            if name in APPLICATION_CHECKS:
                application = item.get('application')
                if not isinstance(application, dict) or \
                        application.get('response_nonce') != nonce:
                    valid, reason = False, 'application response nonce mismatch'
                elif application.get('response_bytes', 0) <= 0 or \
                        application.get('request_bytes', 0) <= 0:
                    valid, reason = False, 'application byte counts are empty'
                if len(matched) < 2:
                    valid, reason = False, 'bidirectional packets are missing'
                if name == 'tls_application' and not (
                        'REDIRECT_TLS_RELAY' in log_text or
                        'TLS_SNI_ALLOW' in log_text):
                    valid, reason = False, 'TLS policy log missing'
                if name == 'reviewed_ip_tls' and \
                        'ALLOW_REVIEWED_IP_FIRST_FLOW' not in log_text:
                    valid, reason = False, 'reviewed-IP allow log missing'
                if name in ('sink_tcp', 'sink_udp') and \
                        'ALLOW_TAKEOVER_SINK' not in log_text:
                    valid, reason = False, 'takeover allow log missing'
                if name in ('sink_tcp', 'sink_udp') and not any(
                        nonce.encode('ascii') in packet['payload']
                        for packet in matched):
                    valid, reason = False, 'application nonce is absent from packets'
                if name in ('tls_application', 'reviewed_ip_tls') and not any(
                        packet['payload'] for packet in matched):
                    valid, reason = False, 'TLS packets have no content'
            if name in DENY_CHECKS:
                if not matched and name not in ('icmp_denied', 'ipv6_denied'):
                    valid, reason = False, 'denied attempt packet missing'
                if name == 'icmp_denied':
                    if ('ALLOW_TAKEOVER_SINK ip=%s proto=ICMP' %
                            inputs['sink_ip']) in log_text:
                        valid, reason = False, 'ICMP reached the takeover sink'
                elif name == 'ipv6_denied':
                    if 'DROP_EXTERNAL reason=external_ipv6' not in log_text:
                        valid, reason = False, 'IPv6 fail-closed log missing'
                elif name not in DNS_CHECKS and not (
                        'DIVERT_FAKE' in log_text or
                        'DROP_EXTERNAL' in log_text):
                    valid, reason = False, 'denial decision log missing'
            if name == 'route_restore':
                route = value.get('route') or {}
                if not (route.get('before') == route.get('after') and
                        route.get('match') is True and
                        'TAKEOVER_ROUTE_RESTORED' in log_text):
                    valid, reason = False, 'route restoration was not observed'
        if valid and not config_ok:
            valid, reason = False, 'configuration content is invalid'
        if valid and not item.get('evidence'):
            valid, reason = False, 'evidence list is empty'
        if valid:
            rows.append({'id': name, 'status': 'pass'})
        else:
            rows.append({'id': name,
                         'status': status if status != 'pass' else
                         ('unknown' if not reason else 'fail')})
    for name in checks:
        if name not in seen:
            rows.append({'id': name, 'status': 'not_run'})
    cleanup = value.get('cleanup') or {}
    process = cleanup.get('process_exit') or {}
    network = value.get('network') or {}
    clean = (pcap_items and bool(packets)
             and config_ok
             and value.get('stopped') is True
             and value.get('network_restored') is True
             and network.get('match') is True
             and cleanup.get('source') == 'driver'
             and process.get('exited') is True
             and process.get('timed_out') is False
             and process.get('returncode') == 0)
    if scenario in ('takeover', 'combined'):
        route = value.get('route') or {}
        clean = clean and route.get('match') is True
    clean = clean and all(row.get('status') == 'pass' for row in rows)
    return rows, bool(clean)


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--original', required=True)
    parser.add_argument('--scenario', required=True)
    parser.add_argument('--checks', required=True)
    parser.add_argument('--allow-fixture', action='store_true')
    args = parser.parse_args(argv)
    checks = [item for item in args.checks.split(',') if item]
    rows, clean = evaluate(Path(args.original), args.scenario, checks,
                           allow_fixture=args.allow_fixture)
    print(json.dumps({'rows': rows, 'clean': clean}, sort_keys=True))
    return 0 if clean and all(row['status'] == 'pass' for row in rows) else 1


if __name__ == '__main__':
    raise SystemExit(main())
