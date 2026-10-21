"""Bounded passive VM-edge observations; never change network policy.

Zero observed packets is not proof.  A complete current capture and a fresh,
same-path stopped calibration are required. Unsupported paths remain unknown.
"""
from __future__ import annotations

import hashlib

from fakenet.mcp import host_probe
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import struct
import subprocess
import time
from datetime import datetime

LIMIT = 4 * 1024 * 1024
DESTINATIONS = {'198.51.100.77', '2001:db8::77'}


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _time(value):
    return datetime.fromisoformat(str(value).replace('Z', '+00:00')).timestamp()


def _options(raw, endian):
    result = {}
    pos = 0
    while pos + 4 <= len(raw):
        code, length = struct.unpack_from(endian + 'HH', raw, pos)
        pos += 4
        if code == 0:
            break
        if pos + length > len(raw) or code in result:
            raise ValueError('invalid pcapng options')
        result[code] = raw[pos:pos + length]
        pos += (length + 3) & ~3
    return result


def parse_capture(raw, _packets=None):
    """Parse bounded, single-section Ethernet pcapng with final loss stats."""
    if not 28 <= len(raw) < LIMIT:
        raise ValueError('capture size invalid or limit reached')
    endian = None
    interfaces, packets, stats = [], ([] if _packets is None else _packets), {}
    pos = 0
    while pos < len(raw):
        if len(raw) - pos < 12:
            raise ValueError('truncated pcapng')
        if raw[pos:pos + 4] == b'\x0a\x0d\x0d\x0a':
            if endian is not None:
                raise ValueError('multiple capture sections')
            endian = {'4d3c2b1a': '<', '1a2b3c4d': '>'}.get(
                raw[pos + 8:pos + 12].hex())
        if endian is None:
            raise ValueError('pcapng section missing')
        kind, length = struct.unpack_from(endian + 'II', raw, pos)
        if length < 12 or length % 4 or pos + length > len(raw):
            raise ValueError('invalid pcapng block')
        if struct.unpack_from(endian + 'I', raw, pos + length - 4)[0] != length:
            raise ValueError('pcapng block length mismatch')
        body = raw[pos + 8:pos + length - 4]
        if kind == 1:
            if len(body) < 8:
                raise ValueError('invalid interface block')
            link, _, snap = struct.unpack_from(endian + 'HHI', body)
            opts = _options(body[8:], endian)
            if link != 1 or snap < 65535:
                raise ValueError('unsupported capture link or snapshot length')
            resolution = opts.get(9, b'\x06')
            if len(resolution) != 1 or resolution[0] & 128:
                raise ValueError('unsupported timestamp resolution')
            interfaces.append({'name': opts.get(2, b'').decode('utf8'),
                               'scale': 10 ** resolution[0]})
        elif kind == 6:
            if len(body) < 20:
                raise ValueError('invalid packet block')
            iface, high, low, size, original = struct.unpack_from(endian + 'IIIII', body)
            if iface >= len(interfaces) or size != original or 20 + size > len(body):
                raise ValueError('truncated packet or unknown interface')
            frame = body[20:20 + size]
            if len(frame) < 14:
                raise ValueError('short Ethernet frame')
            source_mac = ':'.join('%02x' % b for b in frame[6:12])
            ethertype = int.from_bytes(frame[12:14], 'big')
            packet = frame[14:]
            if ethertype == 0x0800:
                if len(packet) < 20 or packet[0] >> 4 != 4:
                    raise ValueError('short IPv4 packet')
                offset = (packet[0] & 15) * 4
                if offset < 20 or len(packet) < offset:
                    raise ValueError('invalid IPv4 header')
                source, destination = (str(ipaddress.ip_address(packet[a:b]))
                                       for a, b in ((12, 16), (16, 20)))
                protocol = packet[9]
                family = 'ipv4'
            elif ethertype == 0x86dd:
                if len(packet) < 40 or packet[0] >> 4 != 6:
                    raise ValueError('short IPv6 packet')
                source, destination = (str(ipaddress.ip_address(packet[a:b]))
                                       for a, b in ((8, 24), (24, 40)))
                protocol, offset, family = packet[6], 40, 'ipv6'
            else:
                raise ValueError('unsupported captured Ethernet payload')
            source_port = destination_port = None
            if protocol in (6, 17) and len(packet) >= offset + 4:
                source_port, destination_port = struct.unpack_from('!HH', packet, offset)
            packets.append({'interface': interfaces[iface]['name'], 'mac': source_mac,
                            'time': ((high << 32) | low) / interfaces[iface]['scale'],
                            'family': family, 'source': source, 'destination': destination,
                            'protocol': protocol, 'source_port': source_port,
                            'destination_port': destination_port,
                            'payload': packet[offset:]})
        elif kind == 5:
            if len(body) < 12:
                raise ValueError('invalid statistics block')
            iface = struct.unpack_from(endian + 'I', body)[0]
            opts = _options(body[12:], endian)
            if iface >= len(interfaces) or iface in stats:
                raise ValueError('invalid statistics interface')
            if 5 not in opts or len(opts[5]) != 8:
                raise ValueError('capture drop statistics missing')
            drops = struct.unpack(endian + 'Q', opts[5])[0]
            if 7 in opts:
                if len(opts[7]) != 8:
                    raise ValueError('invalid OS drop statistics')
                drops += struct.unpack(endian + 'Q', opts[7])[0]
            stats[iface] = drops
        elif kind not in (0x0a0d0d0a, 4):
            raise ValueError('unsupported pcapng block')
        pos += length
    if not interfaces or set(stats) != set(range(len(interfaces))):
        raise ValueError('final capture statistics missing')
    if any(stats.values()):
        raise ValueError('capture dropped packets')
    return {'interfaces': interfaces, 'packets': packets, 'drops': stats}


def topology(snapshot):
    """Network identity, not an assertion that this network is blocked."""
    nics = [nic for nic in (snapshot.get('vmx') or {}).get('nics', [])
            if nic.get('present') and nic.get('start_connected')]
    return {'vm_uuid': (snapshot.get('vmx') or {}).get('uuid'),
            'nics': nics, 'networking_sha256': (snapshot.get('networking') or {}).get('sha256'),
            'nat_sha256': (snapshot.get('nat') or {}).get('sha256'),
            'route': snapshot.get('route_to_guest'), 'network_type': snapshot.get('network_type')}


def _raw_ref(ref):
    if not isinstance(ref, dict):
        raise ValueError('evidence reference missing')
    path = Path(str(ref.get('path', '')))
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ValueError('unsafe evidence reference')
    if path.stat().st_size > LIMIT or any(parent.is_symlink() for parent in path.parents):
        raise ValueError('unsafe or oversized evidence reference')
    raw = path.read_bytes()
    if len(raw) > LIMIT or _sha(raw) != ref.get('sha256'):
        raise ValueError('evidence hash or size mismatch')
    return raw


def route_keys(probe, family=None):
    result = {}
    for row in probe.get('steps') or []:
        key = row.get('family')
        if key not in ('ipv4', 'ipv6'):
            raise ValueError('probe family unavailable')
        if family is not None and key != family:
            continue
        route = row.get('route')
        if not isinstance(route, dict) or not all(route.get(k) for k in ('source', 'interface', 'next_hop')):
            raise ValueError('probe route unavailable')
        key = row.get('family')
        if key not in ('ipv4', 'ipv6'):
            raise ValueError('probe family unavailable')
        if key in result and result[key] != route:
            raise ValueError('multiple paths in one family unsupported')
        result[key] = route
    required = {family} if family is not None else {'ipv4', 'ipv6'}
    if set(result) != required:
        raise ValueError('path evidence incomplete:' + str(family or 'dual-stack'))
    return result


def evaluate_capture(capture, probe, snapshot, calibration_ref, *, started, ended,
                     heartbeat_port, capture_identity, now=None):
    """Observe leaks first. Missing visibility or execution never becomes pass."""
    result = {'value': None, 'reason': 'observation_incomplete', 'paths': [], 'leaks': [],
              'common_complete': False}
    observed_packets = []
    try:
        try:
            parsed = parse_capture(capture, observed_packets)
            parse_error = None
        except ValueError as exc:
            parsed = {'packets': observed_packets}
            parse_error = exc
        target = topology(snapshot)
        nics = target['nics']
        macs = {str(nic.get('mac', '')).lower() for nic in nics}
        # Leakage is decisive even if calibration/other path facts are absent.
        leaks = [p for p in parsed['packets'] if p['mac'] in macs and
                 p['destination'] in DESTINATIONS]
        if leaks:
            result.update(value=False, reason='running_egress_leak_observed',
                          leaks=[{k:v for k,v in p.items() if k != 'payload'} for p in leaks])
            return result
        if parse_error is not None:
            raise parse_error
        if len(nics) != 1 or not nics[0].get('interface_present'):
            raise ValueError('single mapped NIC required; other topology unsupported')
        nic = nics[0]
        if {x['name'] for x in parsed['interfaces']} != {nic['interface']}:
            raise ValueError('capture interface mismatch')
        if _time(probe['completed_at']) > ended or any(
                not started <= _time(row['started']) <= _time(row['ended']) <= ended
                for row in probe.get('steps') or []):
            raise ValueError('capture window does not cover probe')
        heartbeat = [p for p in parsed['packets'] if p['mac'] in macs and
                     p['source_port'] == heartbeat_port and
                     _time(probe['completed_at']) <= p['time'] <= ended]
        if not heartbeat:
            raise ValueError('current post-probe control heartbeat missing')
        receipt = json.loads(_raw_ref(calibration_ref))
        if receipt.get('schema') != 'fakenetng.egress-visibility.v1':
            raise ValueError('calibration schema invalid')
        if receipt.get('capture_identity') != capture_identity or receipt.get('topology') != target:
            raise ValueError('calibration topology or capture settings changed')
        current = time.time() if now is None else now
        before, expires = _time(receipt['created_at']), _time(receipt['expires_at'])
        if not before <= started <= ended <= current + 1 or not current < expires <= before + 3600:
            raise ValueError('calibration expired or time order invalid')
        state = json.loads(_raw_ref(receipt['guest_status']))
        if state.get('state') != 'stopped' or state.get('run_id') is not None:
            raise ValueError('calibration engine not stopped')
        baseline = json.loads(_raw_ref(receipt['probe']))
        baseline = baseline.get('probe', baseline)
        for key in ('vm_uuid', 'boot_id', 'account', 'sid', 'session', 'token_integrity_level'):
            if not baseline.get('identity', {}).get(key) or baseline['identity'][key] != probe.get('identity', {}).get(key):
                raise ValueError('calibration guest context changed')
        if receipt.get('probe_template_sha256') != host_probe.script_sha256(host_probe.PROBE_TEMPLATE):
            raise ValueError('calibration probe template changed')
        payload = receipt.get('probe_payload') or {}
        if payload.get('calibration_mode') is not True or payload.get('positive_enabled') is not False:
            raise ValueError('calibration fixed probe mode invalid')
        planned = payload.get('steps') or []
        if len(planned) != 2 or {row.get('id') for row in planned} != {'ipv4_udp_random', 'ipv6_udp_random'}:
            raise ValueError('calibration matrix invalid')
        for row in planned:
            if row.get('kind') != 'udp' or row.get('destination') not in DESTINATIONS or row.get('probe_kind') != 'udp_raw':
                raise ValueError('calibration destination invalid')
        script_hash = _sha(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode())
        host_probe.validate_probe_result(baseline, [row['id'] for row in planned], nonce=payload.get('nonce'), expected_script_hash=script_hash, positive_required=False)
        for row in baseline.get('steps') or []:
            if not before - 60 <= _time(row['started']) <= _time(row['ended']) <= before:
                raise ValueError('calibration probe time invalid')
        old = parse_capture(_raw_ref(receipt['capture']))
        result['common_complete'] = True
        result['calibration'] = {
            'ref': dict(calibration_ref),
            'expires_at': receipt.get('expires_at'),
            'probe_template_sha256': receipt.get('probe_template_sha256'),
            'capture_identity': receipt.get('capture_identity')}
        # Common identity, capture and loss checks qualify neither family on
        # failure. Once those pass, evaluate each actual path independently;
        # a missing IPv6 route must not erase a calibrated IPv4 observation.
        families = {}
        for family in ('ipv4', 'ipv6'):
            path = {'family': family, 'interface': nic['interface'],
                    'value': None, 'visible': False}
            try:
                route = route_keys(probe, family)[family]
                if route_keys(baseline, family)[family] != route:
                    raise ValueError('calibration guest routes changed:' + family)
                rows = [row for row in baseline['steps'] if row.get('family') == family and row.get('send_completed') is True]
                matching = [p for p in old['packets'] if p['mac'] in macs and
                            p['interface'] == nic['interface'] and p['family'] == family and
                            p['source'] == route['source'] and p['destination'] in DESTINATIONS and
                            baseline.get('nonce', '').encode() in p['payload'] and any(
                                row.get('destination') == p['destination'] and row.get('port') == p['destination_port'] and
                                str(row.get('local_endpoint', '')).endswith(':' + str(p['source_port'])) and
                                _time(row['started']) <= p['time'] <= _time(row['ended']) for row in rows)]
                if not matching or not baseline.get('nonce'):
                    raise ValueError('same-path outbound calibration missing:' + family)
                path.update(value=True, visible=True, route=route,
                            reason='scoped_running_window_no_egress_observed')
            except (ValueError, KeyError, TypeError, AttributeError) as exc:
                path['reason'] = str(exc)
            families[family] = path
            result['paths'].append(dict(path))
        result['families'] = families
        if all(path['value'] is True for path in families.values()):
            result.update(value=True, reason='scoped_running_window_no_egress_observed')
        else:
            result['reason'] = 'one_or_more_family_paths_unconfirmed'
    except (ValueError, OSError, KeyError, TypeError, AttributeError) as exc:
        result['reason'] = str(exc)
    return result


def capture_options(config, scope, snapshot):
    """Bind an opt-in capture mode to the already validated finite probe scope."""
    mode = config.get('promiscuous', False)
    if mode is False:
        return {}
    if mode is not True:
        raise ValueError('invalid promiscuous capture option')
    target = topology(snapshot)
    nics = target['nics']
    if len(nics) != 1:
        raise ValueError('single mapped NIC required')
    expected = {'mode': 'process-promiscuous', 'vm_uuid': target['vm_uuid'],
                'interface': nics[0].get('interface'), 'mac': nics[0].get('mac'),
                'dumpcap_sha256': _sha(Path('/usr/bin/dumpcap').read_bytes())}
    grant = scope.get('passive_capture')
    if not isinstance(grant, dict) or any(
            not value or grant.get(key) != value for key, value in expected.items()):
        raise ValueError('process-promiscuous capture scope mismatch')
    return {'promiscuous': True}


class PassiveCapture:
    """Own one bounded dumpcap process; never sudo or set interface policy."""
    def __init__(self, directory, snapshot, *, heartbeat_port=28787, seconds=35,
                 promiscuous=False):
        self.path = Path(directory) / 'running-observation.pcapng'
        self.log_path = Path(directory) / 'running-observation.stderr'
        self.process = None
        self.started = self.ended = None
        self._completion = None
        self.mode_ready = False
        self.link_before = self.link_active = None
        if type(promiscuous) is not bool:
            raise ValueError('invalid capture mode')
        self.promiscuous = promiscuous
        nics = topology(snapshot)['nics']
        if len(nics) != 1 or not nics[0].get('interface_present'):
            raise ValueError('single mapped NIC required')
        self.nic = nics[0]
        mac = str(self.nic.get('mac', '')).lower()
        interface = str(self.nic.get('interface', ''))
        if not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', mac) or not re.fullmatch(r'vmnet[0-9]+', interface):
            raise ValueError('unsupported capture target')
        self.filter = ('ether src %s and ((dst host 198.51.100.77 or '
                       'dst host 2001:db8::77) or (tcp src port %d))' %
                       (mac, heartbeat_port))
        binary = Path('/usr/bin/dumpcap')
        self.identity = {'binary': str(binary), 'sha256': _sha(binary.read_bytes()),
                         'interface': interface, 'filter': self.filter,
                         'promiscuous': promiscuous, 'snaplen': 65535}
        if promiscuous:
            self.identity.update(settle_seconds=2, drain_seconds=3)
        self.seconds = max(1, min(35, int(seconds)))

    def _link_state(self):
        result = subprocess.run(
            ['/usr/sbin/ip', '-details', '-json', 'link', 'show', self.nic['interface']],
            check=True, capture_output=True, text=True, timeout=2, shell=False)
        rows = json.loads(result.stdout)
        if len(rows) != 1 or rows[0].get('ifname') != self.nic['interface']:
            raise ValueError('capture interface identity unavailable')
        row = rows[0]
        value = {key: row.get(key) for key in ('ifindex', 'address', 'flags', 'promiscuity')}
        if (type(value['ifindex']) is not int or not value['address'] or
                not isinstance(value['flags'], list) or
                type(value['promiscuity']) is not int):
            raise ValueError('capture interface state incomplete')
        value['kernel_flags'] = int((Path('/sys/class/net') / self.nic['interface'] / 'flags').read_text().strip(), 16)
        value['flags'] = sorted(value['flags'])
        return value

    def start(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.promiscuous:
            self.link_before = self._link_state()
        self.log = self.log_path.open('xb')
        try:
            argv = ['/usr/bin/dumpcap', '-q']
            if not self.promiscuous:
                argv.append('-p')
            argv += ['-i', self.nic['interface'], '-f', self.filter, '-s', '65535',
                     '-a', 'duration:%d' % self.seconds, '-a', 'filesize:4096',
                     '-w', str(self.path)]
            self.process = subprocess.Popen(
                argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=self.log, shell=False, env=dict(os.environ, LC_ALL='C'))
            limit = time.monotonic() + 2
            while time.monotonic() < limit:
                self.log.flush()
                if self.process.poll() is not None:
                    raise ValueError('capture failed to start')
                if b'Capturing on' in self.log_path.read_bytes():
                    self.started = time.time()
                    if self.promiscuous:
                        time.sleep(2)
                        self.link_active = self._link_state()
                        if (self.process.poll() is not None or
                                any(self.link_active[k] != self.link_before[k]
                                    for k in ('ifindex', 'address')) or
                                self.link_active['promiscuity'] < self.link_before['promiscuity'] + 1 or
                                not self.link_active['kernel_flags'] & 0x100):
                            raise ValueError('process capture mode unconfirmed')
                        self.mode_ready = True
                    return
                time.sleep(.025)
            raise ValueError('capture readiness unconfirmed')
        except Exception:
            self.finish()
            raise

    def finish(self):
        if self._completion is not None:
            return self._completion
        if self.process is None:
            if hasattr(self, 'log'):
                self.log.close()
            return {'complete': False, 'reason': 'capture not started'}
        alive = self.process.poll() is None
        if alive and self.promiscuous and self.link_active is not None:
            time.sleep(3)
            alive = self.process.poll() is None
        if alive:
            self.process.send_signal(signal.SIGINT)
        try:
            code = self.process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=.5)
            code = None
        self.ended = time.time()
        self.log.close()
        result = {'complete': alive and code == 0 and self.started is not None,
                  'returncode': code, 'started': self.started, 'ended': self.ended,
                  'path': str(self.path), 'sha256': _sha(self.path.read_bytes())
                  if self.path.is_file() else None, 'identity': self.identity}
        if self.promiscuous:
            result.update(interface_before=self.link_before, interface_active=self.link_active,
                          interface_restored=False)
            try:
                result['interface_after'] = self._link_state()
                result['interface_restored'] = result['interface_after'] == self.link_before
            except (ValueError, OSError, subprocess.SubprocessError) as exc:
                result['interface_error'] = str(exc)
            result['complete'] = (result['complete'] and result['interface_restored'] and
                                  self.mode_ready)
        self._completion = result
        return result
