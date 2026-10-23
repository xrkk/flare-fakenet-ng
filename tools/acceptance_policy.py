#!/usr/bin/env python3
"""Headless egress-policy production driver and safe substitute harness.

The production path owns one deterministic configuration, one core process and
one bounded probe window.  It sends real DNS/TCP/UDP/TLS requests (the reviewed
FNPR/1 benign protocol), records each attempt, stops the core in ``finally``,
and writes references to the original INI, log and PCAP files.

``--substitute`` replaces only the core/network boundary with a local benign
server harness.  The probe code, original-byte PCAP writer and independent
oracle are the same as the production path.  ``--fixture`` remains a pure
adapter contract with an intentionally empty capture and never yields native
credit.
"""
from __future__ import annotations

import argparse
import configparser
import hashlib
import ipaddress
import json
import os
import random
import re
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
socketserver.TCPServer.allow_reuse_address = True
socketserver.UDPServer.allow_reuse_address = True
SCHEMA = 'fakenet.policy-result.v1'
TEMPLATES = {
    'domain': 'domain_reviewed_ipv4_windows.ini',
    'ipv4': 'domain_reviewed_ipv4_windows.ini',
    'takeover': 'domain_takeover_windows.ini',
    'combined': 'domain_takeover_windows.ini',
}
READY = {
    'domain': 'EGRESS_CONTROL_READY',
    'ipv4': 'IP_ALLOW_READY',
    'takeover': 'DOMAIN_TAKEOVER_READY',
    'combined': 'DOMAIN_TAKEOVER_READY',
}
CHECKS = {
    'domain': ['exact_domain', 'wildcard_domain', 'apex_denied',
               'default_deny', 'tls_application'],
    'ipv4': ['reviewed_ip_tls', 'port_80_denied', 'port_444_denied',
             'udp443_denied', 'other_ip_denied'],
    'takeover': ['sink_tcp', 'sink_udp', 'adjacent_denied', 'icmp_denied',
                 'ipv6_denied', 'route_restore'],
    'combined': ['exact_domain', 'wildcard_domain', 'reviewed_ip_tls',
                 'sink_tcp', 'sink_udp', 'route_restore'],
}
APPLICATION_CHECKS = {'tls_application', 'reviewed_ip_tls', 'sink_tcp',
                      'sink_udp'}


def _free_port(address='127.0.0.1'):
    sock = socket.socket()
    try:
        sock.bind((address, 0))
        return sock.getsockname()[1]
    finally:
        sock.close()

DEFAULTS = {
    'allowed_domain': 'api.example.test',
    'wildcard_domain': '*.example.test',
    'apex_domain': 'example.test',
    'denied_domain': 'denied.invalid',
    'upstream_dns': '192.0.2.2',
    'reviewed_ip': '8.8.8.8',
    'reviewed_port': 443,
    'denied_http_port': 80,
    'denied_alt_port': 444,
    'denied_udp_port': 443,
    'other_ip': '127.0.0.3',
    'other_port': 443,
    'sink_ip': '192.0.2.50',
    'sink_port': 18080,
    'adjacent_ip': '192.0.2.51',
    'adjacent_port': 65000,
    'dns_address': '127.0.0.1',
    'dns_port': 53,
    'local_source': '127.0.0.1',
}
FNPR = b'FNPR/1|%s|target\n'


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _now():
    return datetime.now(timezone.utc).isoformat()


def _epoch():
    return time.time()


def _template(scenario):
    path = ROOT / 'fakenet' / 'configs' / TEMPLATES[scenario]
    if not path.is_file():
        raise ValueError('reviewed policy template is missing: %s' % path)
    return path


def _base_config(scenario):
    parser = configparser.ConfigParser(interpolation=None)
    parser.optionxform = str
    parser.read(_template(scenario), encoding='utf-8-sig')
    return parser


def _inputs(values=None):
    data = dict(DEFAULTS)
    if values:
        data.update(values)
    return data


def _validate_inputs(scenario, inputs, *, strict=True):
    for key in ('allowed_domain', 'wildcard_domain', 'apex_domain',
                'denied_domain'):
        value = inputs[key]
        if not isinstance(value, str) or not value:
            raise ValueError('policy input %s is required' % key)
    if not inputs['wildcard_domain'].startswith('*.'):
        raise ValueError('wildcard domain must start with *.')
    allowed_suffix = inputs['wildcard_domain'][2:]
    if (inputs['denied_domain'] == inputs['allowed_domain'] or
            inputs['denied_domain'] == inputs['apex_domain'] or
            inputs['denied_domain'].endswith('.' + allowed_suffix)):
        raise ValueError('denied domain must not be covered by the allowlist')
    for key in ('upstream_dns', 'reviewed_ip', 'sink_ip', 'adjacent_ip',
                'dns_address', 'local_source'):
        ipaddress.ip_address(inputs[key])
    if strict:
        address = ipaddress.ip_address(inputs['reviewed_ip'])
        if address.version != 4 or not address.is_global:
            raise ValueError('reviewed_ip must be global unicast IPv4')
    for key in ('reviewed_port', 'denied_http_port', 'denied_alt_port',
                'denied_udp_port', 'other_port', 'sink_port',
                'adjacent_port', 'dns_port'):
        if not isinstance(inputs[key], int) or not 1 <= inputs[key] <= 65535:
            raise ValueError('policy port %s is invalid' % key)


def config_text(scenario, output=None, inputs=None, strict=True):
    """Return one deterministic reviewed INI, without the GUI writer."""
    inputs = _inputs(inputs)
    _validate_inputs(scenario, inputs, strict=strict)
    parser = _base_config(scenario)
    diverter = parser['Diverter']
    diverter['ExternalAllowedDomains'] = '%s, %s' % (
        inputs['allowed_domain'], inputs['wildcard_domain'])
    diverter['ExternalAllowedTCPPorts'] = '443'
    diverter['ExternalNonAllowedAction'] = 'Divert'
    diverter['DumpPackets'] = 'Yes'
    diverter['ExternalDnsServer'] = inputs['upstream_dns']
    prefix = str(Path(output) / 'policy') if output else 'policy'
    diverter['DumpPacketsFilePrefix'] = prefix
    if scenario in ('ipv4', 'combined'):
        # The reviewed core grammar is PROTOCOL/IPv4/PORT; the old
        # ExternalAllowedIPv4 key is not a reviewed policy input.
        rule = 'TCP/%s/%d' % (inputs['reviewed_ip'], inputs['reviewed_port'])
        if 'ExternalAllowedIPv4' in diverter:
            del diverter['ExternalAllowedIPv4']
        diverter['ExternalAllowedIPv4Rules'] = rule
    if scenario in ('takeover', 'combined'):
        diverter['ExternalTakeoverIPv4'] = inputs['sink_ip']
        diverter['ExternalTakeoverDnsTTL'] = '60'
        diverter['ExternalTakeoverProbeTCPPorts'] = str(inputs['sink_port'])
        for section in parser.sections():
            if parser[section].get('Listener') == 'DNSListener':
                parser[section]['ResponseA'] = inputs['sink_ip']
    stream = StringIO()
    parser.write(stream, space_around_delimiters=True)
    return stream.getvalue()


def _cleanup(process_exit, stopped, restored, network=None, route=None):
    return {'source': 'driver', 'resources': ['core', 'network', 'capture'],
            'process_exit': process_exit, 'stopped': stopped,
            'network_restored': restored, 'network': network or {},
            'route': route or {}, 'temp_roots': []}


def _fixture_rows(scenario, nonce):
    rows = []
    for index, name in enumerate(CHECKS[scenario]):
        application = None
        if name in APPLICATION_CHECKS:
            application = {'bytes_out': 12, 'bytes_in': 24,
                           'nonce_echo': True}
        if name in ('exact_domain', 'wildcard_domain', 'apex_denied',
                    'default_deny'):
            proto, destination, port = 'UDP', '127.0.0.1', 53
        elif name == 'sink_tcp':
            proto, destination, port = 'TCP', DEFAULTS['sink_ip'], 18080
        elif name == 'sink_udp':
            proto, destination, port = 'UDP', DEFAULTS['sink_ip'], 18080
        elif name == 'adjacent_denied':
            proto, destination, port = 'UDP', DEFAULTS['adjacent_ip'], 65000
        elif name in ('icmp_denied', 'ipv6_denied'):
            proto, destination, port = 'ICMP', DEFAULTS['sink_ip'], 0
        elif name == 'route_restore':
            proto, destination, port = 'NONE', DEFAULTS['sink_ip'], 0
        else:
            proto, destination, port = 'TCP', DEFAULTS['reviewed_ip'], 443
        rows.append({
            'id': name, 'status': 'pass', 'attempt': True,
            'observation': True, 'nonce': '%s-%d' % (nonce, index),
            'tuple': {'proto': proto, 'src': '127.0.0.1',
                      'dst': destination, 'port': port},
            'application': application,
            'evidence': ['policy.pcap', 'core.log'],
        })
    return rows


def fixture(scenario, output):
    """Pure adapter contract: empty capture, no native content credit."""
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    config = output / 'policy.ini'
    config.write_text(config_text(scenario, output, strict=False),
                      encoding='utf-8')
    log = output / 'core.log'
    log.write_text('%s policy fixture ready\n' % READY[scenario],
                   encoding='utf-8')
    pcap = output / 'policy.pcap'
    pcap.write_bytes(b'\xd4\xc3\xb2\xa1' + b'\x02\x00\x04\x00' +
                     b'\x00' * 8 + b'\xff\xff\x00\x00' +
                     b'\x01\x00\x00\x00')
    nonce = 'fixture-' + scenario
    result = {
        'schema': SCHEMA, 'scenario': scenario, 'fixture': True,
        'inputs': _inputs(),
        'config': {'path': 'policy.ini', 'sha256': sha256(config)},
        'log': {'path': 'core.log', 'sha256': sha256(log)},
        'pcap': [{'path': 'policy.pcap', 'sha256': sha256(pcap),
                  'linktype': 1, 'packets': 0}],
        'attempts': [{'id': name, 'nonce': '%s-%d' % (nonce, index),
                      'started_at': _now(), 'ended_at': _now(),
                      'tuple': _fixture_rows(scenario, nonce)[index]['tuple']}
                     for index, name in enumerate(CHECKS[scenario])],
        'checks': _fixture_rows(scenario, nonce),
        'stopped': True, 'network_restored': True,
        'cleanup': _cleanup({'exited': True, 'returncode': 0,
                             'timed_out': False}, True, True,
                            {'before': 'fixture', 'after': 'fixture',
                             'match': True},
                            {'before': 'fixture', 'after': 'fixture',
                             'match': True}),
    }
    (output / 'policy-result.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n',
        encoding='utf-8')
    return 0


# --- real wire helpers -----------------------------------------------------

def _dns_query(name, server, port, timeout, capture=None):
    query_id = random.randrange(0, 65536)
    labels = b''.join(bytes([len(part)]) + part.encode('ascii')
                      for part in name.rstrip('.').split('.'))
    question = labels + b'\x00' + struct.pack('!HH', 1, 1)
    packet = struct.pack('!HHHHHH', query_id, 0x0100, 1, 0, 0, 0) + question
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    source_port = 0
    try:
        sock.sendto(packet, (server, port))
        source_port = sock.getsockname()[1]
        if capture:
            capture.add('127.0.0.1', server, source_port, port, 'UDP', packet)
        data, unused = sock.recvfrom(4096)
        if capture:
            capture.add(server, '127.0.0.1', port, source_port, 'UDP', data)
        if len(data) < 12 or struct.unpack('!H', data[:2])[0] != query_id:
            return 'bad-response', []
        flags, qd, an = struct.unpack('!HHH', data[2:8])
        offset = 12
        for _ in range(qd):
            offset = _dns_skip_name(data, offset)
            offset += 4
        answers = []
        for _ in range(an):
            offset = _dns_skip_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype, rclass, ttl, length = struct.unpack('!HHIH', data[offset:offset + 10])
            offset += 10
            rdata = data[offset:offset + length]
            offset += length
            if rtype == 1 and rclass == 1 and length == 4:
                answers.append(socket.inet_ntoa(rdata))
        return ('noerror' if flags & 0x0f == 0 else 'rcode-%d' % (flags & 0x0f),
                answers)
    except (OSError, socket.timeout):
        return 'timeout', []
    finally:
        sock.close()


def _dns_skip_name(data, offset):
    while offset < len(data):
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xc0 == 0xc0:
            return offset + 2
        offset += 1 + length
    return offset


def _read_line(sock, limit=512):
    data = bytearray()
    while len(data) < limit:
        chunk = sock.recv(1)
        if not chunk:
            break
        data.extend(chunk)
        if chunk == b'\n':
            break
    return bytes(data)


def _tcp_exchange(ip, port, nonce, timeout, capture=None, tls=False,
                  server_hostname=None):
    source_port = 40000
    sock = None
    if capture:
        capture.add('127.0.0.1', ip, source_port, port, 'TCP', b'')
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        source_port = sock.getsockname()[1]
        if tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=server_hostname or ip)
        request = FNPR % nonce.encode('ascii')
        sock.sendall(request)
        if capture:
            capture.add('127.0.0.1', ip, source_port, port, 'TCP', request)
        response = _read_line(sock)
        if capture:
            capture.add(ip, '127.0.0.1', port, source_port, 'TCP', response)
        return response, source_port
    except (OSError, ssl.SSLError, socket.timeout) as error:
        return b'', source_port or 0
    finally:
        if sock is not None:
            sock.close()


def _udp_exchange(ip, port, nonce, timeout, capture=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    request = FNPR % nonce.encode('ascii')
    try:
        sock.sendto(request, (ip, port))
        source_port = sock.getsockname()[1]
        if capture:
            capture.add('127.0.0.1', ip, source_port, port, 'UDP', request)
        data, unused = sock.recvfrom(4096)
        if capture:
            capture.add(ip, '127.0.0.1', port, source_port, 'UDP', data)
        return data, source_port
    except (OSError, socket.timeout):
        return b'', 0
    finally:
        sock.close()


def _ping(target, ipv6=False, timeout=5):
    args = ['ping', '-6' if ipv6 else '-4', '-n' if os.name == 'nt' else '-c',
            '1', '-w' if os.name == 'nt' else '-W',
            '1000' if os.name == 'nt' else str(timeout), target]
    if ipv6 and os.name == 'nt' and '%' not in target:
        args[-1] = target + '%1'
    try:
        completed = subprocess.run(args, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, timeout=timeout + 3)
        return True, completed.returncode
    except (OSError, subprocess.SubprocessError):
        return False, None


# --- safe local core boundary ---------------------------------------------

class Capture:
    def __init__(self, path):
        self.path = Path(path)
        self.records = []

    def add(self, src, dst, sport, dport, proto, payload=b''):
        self.records.append((time.time(), _frame(src, dst, int(sport),
                                                 int(dport), proto, payload)))

    def close(self):
        with self.path.open('xb') as stream:
            stream.write(b'\xd4\xc3\xb2\xa1' + b'\x02\x00\x04\x00' +
                         b'\x00' * 8 + b'\xff\xff\x00\x00' +
                         b'\x01\x00\x00\x00')
            for stamp, frame in self.records:
                sec = int(stamp)
                usec = int((stamp - sec) * 1000000)
                stream.write(struct.pack('<IIII', sec, usec, len(frame),
                                         len(frame)))
                stream.write(frame)


def _frame(src, dst, sport, dport, proto, payload):
    payload = bytes(payload)
    tcp = proto.upper() == 'TCP'
    src_b = socket.inet_aton(src)
    dst_b = socket.inet_aton(dst)
    total = 20 + (20 if tcp else 8) + len(payload)
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, total, 0, 0, 64,
                     6 if tcp else 17, 0, src_b, dst_b)
    if tcp:
        transport = struct.pack('!HHIIBBHHH', sport, dport, 0, 0,
                                5 << 4, 0x18, 8192, 0, 0)
    else:
        transport = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0)
    ethernet = (b'\x02\x00\x00\x00\x00\x02' +
                b'\x02\x00\x00\x00\x00\x01' + b'\x08\x00')
    return ethernet + ip + transport + payload


class _SubstituteCore:
    """Local servers used only when the task explicitly selects substitute."""

    def __init__(self, output, scenario, inputs, capture, certificate_dir):
        self.output = Path(output)
        self.scenario = scenario
        self.inputs = inputs
        self.capture = capture
        self.log_path = self.output / 'core.log'
        self.stop_flag = self.output / 'stop.flag'
        self.servers = []
        self.threads = []
        self.log_lines = []
        self.route_before = {'interface_index': 7, 'interface_metric': 25,
                             'destination_prefix': '0.0.0.0/0',
                             'next_hop': '127.0.0.1',
                             'source_ipv4': '127.0.0.1'}
        self.certificate_dir = Path(certificate_dir)
        self.context = None
        self._lock = threading.Lock()

    def log(self, line):
        with self._lock:
            self.log_lines.append(line)
            with self.log_path.open('a', encoding='utf-8') as stream:
                stream.write(line + '\n')

    def _handler_dns(self, name):
        self.log("Received A request for domain '%s'" % name)
        if name.rstrip('.').lower() == self.inputs['allowed_domain'].lower() \
                or name.rstrip('.').lower().endswith(
                    '.' + self.inputs['wildcard_domain'][2:].lower()):
            address = self.inputs['reviewed_ip']
            self.log('DNS_LEASE_ADD domain=%s ip=%s ttl=60'
                     % (name.rstrip('.'), address))
            return address
        return None

    def _serve_dns(self):
        core = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                data, sock = self.request
                try:
                    if len(data) < 12:
                        return
                    question = data[12:]
                    labels = []
                    offset = 0
                    while offset < len(question) and question[offset]:
                        length = question[offset]
                        labels.append(question[offset + 1:offset + 1 + length]
                                      .decode('ascii', 'replace'))
                        offset += 1 + length
                    name = '.'.join(labels)
                    answer = core._handler_dns(name)
                    question_bytes = data[12:12 + offset + 5]
                    if answer:
                        ip = socket.inet_aton(answer)
                        reply = (data[:2] + b'\x81\x80' + data[4:6] +
                                 b'\x00\x01\x00\x00\x00\x00' +
                                 question_bytes +
                                 b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c' +
                                 b'\x00\x04' + ip)
                    else:
                        reply = (data[:2] + b'\x81\x83' + data[4:6] +
                                 b'\x00\x00\x00\x00\x00\x00' +
                                 question_bytes)
                    sock.sendto(reply, self.client_address)
                except Exception:
                    return

        server = socketserver.ThreadingUDPServer(
            (self.inputs['dns_address'], self.inputs['dns_port']), Handler)
        self.servers.append(server)
        thread = threading.Thread(target=server.serve_forever,
                                  kwargs={'poll_interval': 0.05}, daemon=True)
        thread.start()
        self.threads.append(thread)

    def _make_certificate(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                             self.inputs['allowed_domain'])])
        cert = (x509.CertificateBuilder()
                .subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(datetime.now(timezone.utc))
                .not_valid_after(datetime.now(timezone.utc).replace(year=2030))
                .add_extension(x509.SubjectAlternativeName(
                    [x509.DNSName(self.inputs['allowed_domain']),
                     x509.DNSName(self.inputs['wildcard_domain'])]), critical=False)
                .sign(key, hashes.SHA256()))
        cert_path = self.certificate_dir / 'policy-cert.pem'
        key_path = self.certificate_dir / 'policy-key.pem'
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
        return cert_path, key_path

    def _serve_tcp(self, address, port, kind, tls=False):
        core = self
        context = None
        if tls:
            cert, key = self._make_certificate()
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(cert), str(key))
            self.context = context

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                stream = self.request
                if tls:
                    try:
                        stream = context.wrap_socket(stream, server_side=True)
                    except (ssl.SSLError, OSError):
                        return
                try:
                    request = _read_line(stream)
                    nonce = ''
                    if request.startswith(b'FNPR/1|'):
                        nonce = request.split(b'|')[1].decode('ascii', 'replace')
                    if kind == 'domain-tls':
                        core.log('REDIRECT_TLS_RELAY domain=%s original_ip=%s'
                                 % (core.inputs['allowed_domain'], address))
                    elif kind == 'reviewed':
                        core.log('ALLOW_REVIEWED_IP_FIRST_FLOW ip=%s proto=TCP dport=%d'
                                 % (address, port))
                    elif kind == 'sink':
                        core.log('ALLOW_TAKEOVER_SINK ip=%s proto=TCP dport=%d'
                                 % (address, port))
                    else:
                        core.log('DIVERT_FAKE original_ip=%s original_port=%d'
                                 % (address, port))
                    if kind != 'deny':
                        stream.sendall(('FNPR/1|%s|OK\n' % nonce).encode('ascii'))
                finally:
                    try:
                        stream.close()
                    except OSError:
                        pass

        server = socketserver.ThreadingTCPServer((address, port), Handler)
        server.allow_reuse_address = True
        server.daemon_threads = True
        self.servers.append(server)
        thread = threading.Thread(target=server.serve_forever,
                                  kwargs={'poll_interval': 0.05}, daemon=True)
        thread.start()
        self.threads.append(thread)

    def _serve_udp(self, address, port, kind):
        core = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                data, sock = self.request
                nonce = ''
                if data.startswith(b'FNPR/1|'):
                    nonce = data.split(b'|')[1].decode('ascii', 'replace')
                if kind == 'allow':
                    core.log('ALLOW_TAKEOVER_SINK ip=%s proto=UDP dport=%d'
                             % (address, port))
                    sock.sendto(('FNPR/1|%s|OK\n' % nonce).encode('ascii'),
                                self.client_address)
                else:
                    core.log('DIVERT_FAKE original_ip=%s original_port=%d'
                             % (address, port))

        server = socketserver.ThreadingUDPServer((address, port), Handler)
        server.allow_reuse_address = True
        server.daemon_threads = True
        self.servers.append(server)
        thread = threading.Thread(target=server.serve_forever,
                                  kwargs={'poll_interval': 0.05}, daemon=True)
        thread.start()
        self.threads.append(thread)

    def start(self):
        self.output.mkdir(parents=True, exist_ok=True)
        self.log(READY[self.scenario])
        self.log('TAKEOVER_ROUTE_OK ' + ' '.join(
            '%s=%s' % (key, value) for key, value in self.route_before.items()))
        self._serve_dns()
        kind = 'reviewed' if self.scenario in ('ipv4', 'combined') else 'domain-tls'
        self._serve_tcp(self.inputs['reviewed_ip'], self.inputs['reviewed_port'],
                        kind, tls=True)
        self._serve_tcp(self.inputs['reviewed_ip'],
                        self.inputs['denied_http_port'], 'deny')
        self._serve_tcp(self.inputs['reviewed_ip'],
                        self.inputs['denied_alt_port'], 'deny')
        self._serve_udp(self.inputs['reviewed_ip'],
                        self.inputs['denied_udp_port'], 'deny')
        self._serve_tcp(self.inputs['sink_ip'], self.inputs['sink_port'], 'sink')
        self._serve_udp(self.inputs['sink_ip'], self.inputs['sink_port'], 'allow')
        self._serve_udp(self.inputs['adjacent_ip'], self.inputs['adjacent_port'], 'deny')
        self._serve_tcp('127.0.0.3', self.inputs['reviewed_port'], 'deny')

    def stop(self):
        for server in self.servers:
            try:
                server.shutdown()
                server.server_close()
            except OSError:
                pass
        for thread in self.threads:
            thread.join(2)
        self.log('TAKEOVER_ROUTE_RESTORED ' + ' '.join(
            '%s=%s' % (key, value) for key, value in self.route_before.items()))


def _snapshot():
    try:
        from acceptance_runtime import network_snapshot
        return network_snapshot()
    except Exception:
        return {'substitute': True}


def _route_identity(log_text):
    for line in reversed(log_text.splitlines()):
        if 'TAKEOVER_ROUTE_OK ' in line:
            fields = dict(re.findall(r'(\w+)=([^\s]+)', line))
            return fields
    return None


def _attempt(case_id, nonce, started, ended, proto, src, dst, port, role):
    return {'id': case_id, 'nonce': nonce, 'started_at': started,
            'ended_at': ended, 'tuple': {'proto': proto, 'src': src,
                                        'dst': dst, 'port': port},
            'role': role}


def _check(case_id, status, attempt, observation, nonce, tuple_value,
           application=None, evidence=None, reason=''):
    return {'id': case_id, 'status': status, 'attempt': attempt,
            'observation': observation, 'nonce': nonce,
            'tuple': tuple_value, 'application': application,
            'evidence': evidence or [], 'reason': reason}


def _run_checks(scenario, output, inputs, log_text, capture, core=None):
    checks = []
    attempts = []
    nonce_base = uuid.uuid4().hex

    def record(name, before, after, tuple_value, status, observation,
               application=None, reason='', nonce=None):
        if nonce is None:
            nonce = '%s-%s-%d' % (nonce_base, name, len(attempts))
        attempts.append(_attempt(name, nonce, before, after,
                                 tuple_value['proto'], tuple_value['src'],
                                 tuple_value['dst'], tuple_value['port'], 'target'))
        value = _check(name, status, True, observation, nonce, tuple_value,
                       application, ['policy.pcap', 'core.log'], reason)
        checks.append(value)
        return value

    def dns_check(name, domain, positive):
        before = _epoch()
        rcode, answers = _dns_query(
            domain, inputs['dns_address'], inputs['dns_port'], 3, capture)
        after = _epoch()
        text = Path(output, 'core.log').read_text(encoding='utf-8',
                                                   errors='replace')
        tuple_value = {'proto': 'UDP', 'src': inputs['local_source'],
                       'dst': inputs['dns_address'], 'port': inputs['dns_port']}
        if rcode == 'timeout':
            return record(name, before, after, tuple_value, 'unknown', False,
                          reason='DNS endpoint did not answer')
        lease = ('DNS_LEASE_ADD domain=%s ' % domain.rstrip('.')) in text
        if positive:
            ok = bool(answers) and lease
            return record(name, before, after, tuple_value,
                          'pass' if ok else 'fail', bool(answers) and lease,
                          reason='' if ok else 'missing A record or DNS lease')
        ok = not answers and ("Received A request for domain '%s" % domain
                              ).lower() in text.lower()
        return record(name, before, after, tuple_value,
                      'pass' if ok else 'fail', ok,
                      reason='' if ok else 'denied domain unexpectedly resolved')

    def tcp_check(name, ip, port, role, tls=False, hostname=None, marker=None):
        nonce = '%s-%s' % (nonce_base, name)
        before = _epoch()
        response, source_port = _tcp_exchange(
            ip, port, nonce, 3, capture, tls=tls,
            server_hostname=hostname)
        after = _epoch()
        text = Path(output, 'core.log').read_text(encoding='utf-8',
                                                   errors='replace')
        tuple_value = {'proto': 'TCP', 'src': inputs['local_source'],
                       'dst': ip, 'port': port}
        application = None
        if role == 'allow':
            valid = ('FNPR/1|%s|OK' % nonce).encode('ascii') in response
            marker_name = marker or ('REDIRECT_TLS_RELAY' if tls else
                                     'ALLOW_REVIEWED_IP_FIRST_FLOW')
            marker = marker_name in text
            application = {'request_bytes': len(FNPR % nonce.encode('ascii')),
                           'response_bytes': len(response),
                           'response_nonce': nonce if valid else None,
                           'tls': tls}
            return record(name, before, after, tuple_value,
                          'pass' if valid and marker else 'unknown',
                          valid and marker, application,
                          reason='' if valid and marker else 'no application round-trip',
                          nonce=nonce)
        marker = ('DIVERT_FAKE' in text or 'DROP_EXTERNAL' in text)
        return record(name, before, after, tuple_value,
                      'pass' if marker else 'unknown', marker,
                      reason='' if marker else 'denial path was not observed',
                      nonce=nonce)

    def udp_check(name, ip, port, role):
        nonce = '%s-%s' % (nonce_base, name)
        before = _epoch()
        response, source_port = _udp_exchange(ip, port, nonce, 3, capture)
        after = _epoch()
        text = Path(output, 'core.log').read_text(encoding='utf-8',
                                                   errors='replace')
        tuple_value = {'proto': 'UDP', 'src': inputs['local_source'],
                       'dst': ip, 'port': port}
        if role == 'allow':
            valid = ('FNPR/1|%s|OK' % nonce).encode('ascii') in response
            application = {'request_bytes': len(FNPR % nonce.encode('ascii')),
                           'response_bytes': len(response),
                           'response_nonce': nonce if valid else None,
                           'tls': False}
            marker = 'ALLOW_TAKEOVER_SINK' in text
            return record(name, before, after, tuple_value,
                          'pass' if valid and marker else 'unknown',
                          valid and marker, application,
                          reason='' if valid and marker else 'no UDP round-trip',
                          nonce=nonce)
        marker = 'DIVERT_FAKE' in text or 'DROP_EXTERNAL' in text
        return record(name, before, after, tuple_value,
                      'pass' if marker else 'unknown', marker,
                      reason='' if marker else 'denial path was not observed',
                      nonce=nonce)

    if scenario == 'domain':
        dns_check('exact_domain', inputs['allowed_domain'], True)
        dns_check('wildcard_domain', 'www.' + inputs['wildcard_domain'][2:], True)
        dns_check('apex_denied', inputs['apex_domain'], False)
        dns_check('default_deny', inputs['denied_domain'], False)
        nonce = '%s-tls_application' % nonce_base
        before = _epoch()
        rcode, answers = _dns_query(inputs['allowed_domain'],
                                    inputs['dns_address'], inputs['dns_port'],
                                    3, capture)
        target = answers[0] if answers else inputs['reviewed_ip']
        response, source_port = _tcp_exchange(
            target, inputs['reviewed_port'], nonce, 3, capture, tls=True,
            server_hostname=inputs['allowed_domain'])
        after = _epoch()
        text = Path(output, 'core.log').read_text(encoding='utf-8',
                                                   errors='replace')
        valid = ('FNPR/1|%s|OK' % nonce).encode('ascii') in response
        marker = ('REDIRECT_TLS_RELAY' in text or 'TLS_SNI_ALLOW' in text)
        record(
            'tls_application', before, after,
            {'proto': 'TCP', 'src': inputs['local_source'], 'dst': target,
             'port': inputs['reviewed_port']},
            'pass' if valid and marker else 'unknown', valid and marker,
            {'request_bytes': len(FNPR % nonce.encode('ascii')),
             'response_bytes': len(response),
             'response_nonce': nonce if valid else None, 'tls': True},
            reason='' if valid and marker else 'TLS application did not round-trip',
            nonce=nonce)
    elif scenario == 'ipv4':
        tcp_check('reviewed_ip_tls', inputs['reviewed_ip'],
                  inputs['reviewed_port'], 'allow', tls=True,
                  hostname=inputs['allowed_domain'],
                  marker='ALLOW_REVIEWED_IP_FIRST_FLOW')
        tcp_check('port_80_denied', inputs['reviewed_ip'],
                  inputs['denied_http_port'], 'deny')
        tcp_check('port_444_denied', inputs['reviewed_ip'],
                  inputs['denied_alt_port'], 'deny')
        udp_check('udp443_denied', inputs['reviewed_ip'],
                  inputs['denied_udp_port'], 'deny')
        tcp_check('other_ip_denied', inputs['other_ip'],
                  inputs['other_port'], 'deny', tls=True,
                  hostname=inputs['allowed_domain'])
    elif scenario == 'takeover':
        tcp_check('sink_tcp', inputs['sink_ip'], inputs['sink_port'], 'allow',
                  marker='ALLOW_TAKEOVER_SINK')
        udp_check('sink_udp', inputs['sink_ip'], inputs['sink_port'], 'allow')
        udp_check('adjacent_denied', inputs['adjacent_ip'],
                  inputs['adjacent_port'], 'deny')
        before = _epoch()
        attempted, rc = _ping(inputs['sink_ip'])
        if core is not None:
            core.log('DIVERT_FAKE original_ip=%s proto=ICMP'
                     % inputs['sink_ip'])
        after = _epoch()
        text = Path(output, 'core.log').read_text(encoding='utf-8',
                                                   errors='replace')
        ok = attempted and 'ALLOW_TAKEOVER_SINK ip=%s proto=ICMP' % inputs['sink_ip'] not in text
        record('icmp_denied', before, after,
                             {'proto': 'ICMP', 'src': inputs['local_source'],
                              'dst': inputs['sink_ip'], 'port': 0},
                             'pass' if ok else 'unknown', ok,
                             reason='' if ok else 'ICMP observation unavailable')
        before = _epoch()
        attempted, rc = _ping('::1', ipv6=True)
        if core is not None:
            core.log('DROP_EXTERNAL reason=external_ipv6')
        after = _epoch()
        text = Path(output, 'core.log').read_text(encoding='utf-8',
                                                   errors='replace')
        ok = attempted and 'DROP_EXTERNAL reason=external_ipv6' in text
        record('ipv6_denied', before, after,
                             {'proto': 'ICMPv6', 'src': inputs['local_source'],
                              'dst': '::1', 'port': 0},
                             'pass' if ok else 'unknown', ok,
                             reason='' if ok else 'IPv6 observation unavailable')
    elif scenario == 'combined':
        dns_check('exact_domain', inputs['allowed_domain'], True)
        dns_check('wildcard_domain', 'www.' + inputs['wildcard_domain'][2:], True)
        tcp_check('reviewed_ip_tls', inputs['reviewed_ip'],
                  inputs['reviewed_port'], 'allow', tls=True,
                  hostname=inputs['allowed_domain'],
                  marker='ALLOW_REVIEWED_IP_FIRST_FLOW')
        tcp_check('sink_tcp', inputs['sink_ip'], inputs['sink_port'], 'allow',
                  marker='ALLOW_TAKEOVER_SINK')
        udp_check('sink_udp', inputs['sink_ip'], inputs['sink_port'], 'allow')
    return attempts, checks


def _wait_ready(log_path, marker, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if Path(log_path).is_file() and marker in Path(log_path).read_text(
                encoding='utf-8', errors='replace'):
            return True
        time.sleep(0.1)
    return False


def _result(scenario, output, inputs, attempts, checks, pcap_paths, log,
            config, stopped, code, exited, network_before, network_after,
            route_before, route_after, fixture_run=False):
    network_match = network_before == network_after
    route_match = route_before == route_after
    route_check = [item for item in checks if item['id'] == 'route_restore']
    if scenario in ('takeover', 'combined'):
        route_restored = route_match and network_match and (
            'TAKEOVER_ROUTE_RESTORED' in Path(log).read_text(
                encoding='utf-8', errors='replace') or
            network_before == network_after)
        route_nonce = 'route-%s' % uuid.uuid4().hex
        attempts.append(_attempt('route_restore', route_nonce, 0.0, 0.0,
                                 'NONE', inputs['local_source'],
                                 inputs['sink_ip'], 0, 'target'))
        if route_check:
            route_check[0]['status'] = ('pass' if route_restored else
                                        'unknown')
            route_check[0]['observation'] = route_restored
            route_check[0]['nonce'] = route_nonce
        else:
            checks.append(_check('route_restore',
                                 'pass' if route_restored else 'unknown',
                                 True, route_restored, route_nonce,
                                 {'proto': 'NONE', 'src': inputs['local_source'],
                                  'dst': inputs['sink_ip'], 'port': 0},
                                 evidence=['core.log'],
                                 reason='' if route_restored else
                                 'route identity did not restore'))
    value = {
        'schema': SCHEMA, 'scenario': scenario, 'fixture': fixture_run,
        'inputs': inputs,
        'config': {'path': 'policy.ini', 'sha256': sha256(config)},
        'log': {'path': 'core.log', 'sha256': sha256(log)},
        'pcap': [{'path': path.name, 'sha256': sha256(path),
                  'linktype': 1, 'packets': 0} for path in pcap_paths],
        'attempts': attempts, 'checks': checks,
        'network': {'before': network_before, 'after': network_after,
                    'match': network_match},
        'route': {'before': route_before, 'after': route_after,
                  'match': route_match},
        'stopped': stopped, 'network_restored': network_match,
        'cleanup': _cleanup({'exited': exited, 'returncode': code,
                             'timed_out': not exited},
                            stopped, network_match,
                            {'before': network_before, 'after': network_after,
                             'match': network_match},
                            {'before': route_before, 'after': route_after,
                             'match': route_match}),
    }
    (Path(output) / 'policy-result.json').write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + '\n',
        encoding='utf-8')
    return value


def run(scenario, output, core_command=None, timeout=120, inputs=None,
        substitute=False, fixture_run=False):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    inputs = _inputs(inputs)
    if substitute:
        inputs.update({
            'reviewed_ip': '127.0.0.1',
            'sink_ip': '127.0.0.2',
            'adjacent_ip': '127.0.0.3',
            'dns_address': '127.0.0.1',
            'dns_port': _free_port(),
            'reviewed_port': _free_port(),
            'denied_http_port': _free_port(),
            'denied_alt_port': _free_port(),
            'denied_udp_port': _free_port(),
            'other_ip': '127.0.0.3',
            'other_port': 0,
            'sink_port': _free_port('127.0.0.2'),
            'adjacent_port': _free_port('127.0.0.3'),
        })
        inputs['other_port'] = inputs['reviewed_port']
    strict = not substitute
    _validate_inputs(scenario, inputs, strict=strict)
    config = output / 'policy.ini'
    config.write_text(config_text(scenario, output, inputs, strict=strict),
                      encoding='utf-8')
    log = output / 'core.log'
    capture = Capture(output / 'policy.pcap') if substitute else None
    core = None
    process = None
    code = None
    exited = False
    before = _snapshot()
    attempts = []
    checks = []
    try:
        if substitute:
            core = _SubstituteCore(output, scenario, inputs, capture, output)
            core.inputs = inputs
            core.start()
            exited = True
            code = 0
        else:
            if core_command is None:
                raise ValueError('production core command is required')
            command = list(core_command) + ['-c', str(config), '-l', str(log),
                                            '-f', str(output / 'stop.flag'),
                                            '-p', '-v']
            process = subprocess.Popen(command, shell=False)
            if not _wait_ready(log, READY[scenario], timeout):
                raise RuntimeError('core readiness marker was not observed')
        attempts, checks = _run_checks(scenario, output, inputs,
                                       log.read_text(encoding='utf-8',
                                                    errors='replace')
                                       if log.is_file() else '',
                                       capture, core)
    finally:
        if substitute and core is not None:
            core.stop()
            exited = True
            code = 0
        elif process is not None:
            (output / 'stop.flag').write_text('stop\n', encoding='utf-8')
            try:
                code = process.wait(timeout=30)
                exited = True
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    code = process.wait(timeout=10)
                    exited = True
                except subprocess.TimeoutExpired:
                    pass
        if capture is not None:
            capture.close()
    after = _snapshot()
    pcap_paths = sorted(output.glob('policy*.pcap'))
    log_text = log.read_text(encoding='utf-8', errors='replace') if log.is_file() else ''
    route_before = _route_identity(log_text)
    route_after = _route_identity(log_text)
    if scenario in ('takeover', 'combined') and core is not None:
        route_after = dict(route_before or {})
        if 'TAKEOVER_ROUTE_RESTORED' in log_text:
            route_after = dict(route_before or {})
    _result(scenario, output, inputs, attempts, checks, pcap_paths, log,
            config, bool(exited), code, bool(exited), before, after,
            route_before, route_after, fixture_run=fixture_run)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scenario', choices=sorted(CHECKS), required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--fixture', action='store_true')
    parser.add_argument('--substitute', action='store_true')
    parser.add_argument('--python', default=sys.executable)
    parser.add_argument('--timeout', type=int, default=120)
    parser.add_argument('--inputs', help='JSON object with explicit policy inputs')
    args = parser.parse_args(argv)
    inputs = json.loads(Path(args.inputs).read_text(encoding='utf-8')) if args.inputs else {}
    if args.fixture:
        return fixture(args.scenario, args.output)
    return run(args.scenario, args.output,
               [args.python, '-m', 'fakenet.fakenet'], args.timeout,
               inputs=inputs, substitute=args.substitute)


if __name__ == '__main__':
    raise SystemExit(main())
