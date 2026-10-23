#!/usr/bin/env python3
"""Headless egress-policy production driver and safe substitute harness.

The production path owns one deterministic configuration, one core process and
one bounded probe window.  It sends real DNS/TCP/UDP/TLS requests (the reviewed
FNPR/1 benign protocol), records each attempt, stops the core in ``finally``,
and writes references to the original INI, log and PCAP files.

``--substitute`` replaces the socket/process boundary with pure memory objects.
It never binds a port, sends a packet, or invokes ping.  The probe code, original-byte PCAP writer and independent
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
SCHEMA = 'fakenet.policy-result.v1'
TEMPLATES = {
    'domain': 'domain_reviewed_ipv4_windows.ini',
    'ipv4': 'domain_reviewed_ipv4_windows.ini',
    'takeover': 'domain_takeover_windows.ini',
    'combined': 'domain_takeover_windows.ini',
    'combo': 'domain_takeover_windows.ini',
}
READY = {
    'domain': 'EGRESS_CONTROL_READY',
    'ipv4': 'IP_ALLOW_READY',
    'takeover': 'DOMAIN_TAKEOVER_READY',
    'combined': 'DOMAIN_TAKEOVER_READY',
    'combo': 'DOMAIN_TAKEOVER_READY',
}
CHECKS = {
    'domain': ['exact_domain', 'wildcard_domain', 'apex_denied',
               'default_deny', 'tls_application', 'route_restore'],
    'ipv4': ['reviewed_ip_tls', 'port_80_denied', 'port_444_denied',
             'udp443_denied', 'other_ip_denied'],
    'takeover': ['sink_tcp', 'sink_udp', 'adjacent_denied', 'icmp_denied',
                 'ipv6_denied', 'route_restore'],
    'combined': ['exact_domain', 'wildcard_domain', 'reviewed_ip_tls',
                 'sink_tcp', 'sink_udp', 'route_restore'],
    'combo': ['exact_domain', 'wildcard_domain', 'tls_application',
              'reviewed_ip_tls', 'sink_tcp', 'sink_udp', 'port_80_denied',
              'port_444_denied', 'udp443_denied', 'other_ip_denied',
              'adjacent_denied', 'route_restore'],
}
APPLICATION_CHECKS = {'tls_application', 'reviewed_ip_tls', 'sink_tcp',
                      'sink_udp'}


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
    if scenario not in CHECKS or not isinstance(inputs, dict):
        raise ValueError('invalid policy scenario/input object')
    missing = set(DEFAULTS) - set(inputs)
    extra = set(inputs) - set(DEFAULTS) - {'tls_ca_file', 'tls_peer_sha256', 'ipv6_target', 'local_source_ipv6', 'host_service'}
    if missing or extra:
        raise ValueError('explicit policy input fields missing=%r extra=%r' % (sorted(missing), sorted(extra)))
    for key in ('allowed_domain', 'wildcard_domain', 'apex_domain', 'denied_domain'):
        value = inputs[key]
        if not isinstance(value, str) or not value or any(c in value for c in '\r\n ,'):
            raise ValueError('invalid policy domain: ' + key)
    if not inputs['wildcard_domain'].startswith('*.'):
        raise ValueError('wildcard domain must start with *.')
    suffix = inputs['wildcard_domain'][2:].lower().rstrip('.')
    denied = inputs['denied_domain'].lower().rstrip('.')
    if denied in (inputs['allowed_domain'].lower(), inputs['apex_domain'].lower(), suffix) or denied.endswith('.' + suffix):
        raise ValueError('denied domain is covered by the allowlist')
    for key in ('upstream_dns', 'reviewed_ip', 'sink_ip', 'adjacent_ip', 'dns_address', 'local_source', 'other_ip'):
        address = ipaddress.ip_address(inputs[key])
        if address.version != 4 or address.is_unspecified or address.is_multicast:
            raise ValueError('usable IPv4 required: ' + key)
    if strict:
        address = ipaddress.ip_address(inputs['reviewed_ip'])
        if not address.is_global or address.is_reserved or address.is_loopback:
            raise ValueError('reviewed_ip must be global unicast IPv4')
        private = [ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')]
        if scenario in ('takeover', 'combined', 'combo') and not any(ipaddress.ip_address(inputs['sink_ip']) in n for n in private):
            raise ValueError('takeover sink must be RFC1918 IPv4')
        if inputs['upstream_dns'] == inputs['local_source']:
            raise ValueError('upstream DNS cannot be the local source')
    for key in ('reviewed_port', 'denied_http_port', 'denied_alt_port', 'denied_udp_port', 'other_port', 'sink_port', 'adjacent_port', 'dns_port'):
        if type(inputs[key]) is not int or not 1 <= inputs[key] <= 65535:
            raise ValueError('invalid policy port: ' + key)
    if len({inputs['reviewed_port'], inputs['denied_http_port'], inputs['denied_alt_port']}) != 3:
        raise ValueError('allowed and denied TCP endpoints must be distinct')


def config_text(scenario, output=None, inputs=None, strict=True):
    """Return one deterministic reviewed INI, without the GUI writer."""
    inputs = _inputs(inputs)
    _validate_inputs(scenario, inputs, strict=strict)
    parser = _base_config(scenario)
    diverter = parser['Diverter']
    diverter['ExternalAllowedDomains'] = '%s, %s' % (
        inputs['allowed_domain'], inputs['wildcard_domain'])
    diverter['ExternalAllowedTCPPorts'] = str(inputs['reviewed_port'])
    diverter['ExternalNonAllowedAction'] = 'Divert'
    diverter['DumpPackets'] = 'Yes'
    diverter['ExternalDnsServer'] = inputs['upstream_dns']
    prefix = str(Path(output) / 'policy') if output else 'policy'
    diverter['DumpPacketsFilePrefix'] = prefix
    if scenario in ('ipv4', 'combined', 'combo'):
        # The reviewed core grammar is PROTOCOL/IPv4/PORT; the old
        # ExternalAllowedIPv4 key is not a reviewed policy input.
        rule = 'TCP/%s/%d' % (inputs['reviewed_ip'], inputs['reviewed_port'])
        if 'ExternalAllowedIPv4' in diverter:
            del diverter['ExternalAllowedIPv4']
        diverter['ExternalAllowedIPv4Rules'] = rule
    if scenario in ('takeover', 'combined', 'combo'):
        diverter['ExternalTakeoverIPv4'] = inputs['sink_ip']
        diverter['ExternalTakeoverDnsTTL'] = '60'
        diverter['ExternalTakeoverProbeTCPPorts'] = str(inputs['sink_port'])
        for section in parser.sections():
            if parser[section].get('Listener') == 'DNSListener':
                parser[section]['ResponseA'] = inputs['sink_ip']
    for section in parser.sections():
        if parser[section].get('Listener')=='DNSListener' and parser[section].get('ResponseA','').lower()=='getfirstnonloopback':
            parser[section]['ResponseA']=inputs['local_source']
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

def _dns_query(name, server, port, timeout, capture=None, io=None, trace=None):
    trace = trace if trace is not None else {}
    labels = b''.join(bytes([len(part)]) + part.encode('ascii') for part in name.rstrip('.').split('.'))
    packet = struct.pack('!HHHHHH', random.randrange(65536), 0x0100, 1, 0, 0, 0) + labels + b'\x00' + struct.pack('!HH', 1, 1)
    sock=(io or socket).socket(socket.AF_INET,socket.SOCK_DGRAM);sock.settimeout(timeout)
    trace.update(started_at=time.time(),request_hex=packet.hex(),response_hex='',sent=False,error=None,domain=name)
    try:
        sock.sendto(packet,(server,port));src,sport=sock.getsockname()
        trace.update(sent=True,tuple={'proto':'UDP','src':src,'sport':sport,'dst':server,'port':port})
        if capture:capture.add(src,server,sport,port,'UDP',packet)
        data,peer=sock.recvfrom(4096);trace['response_hex']=data.hex()
        if peer!=(server,port):raise ValueError('DNS response peer changed')
        if capture:capture.add(server,src,port,sport,'UDP',data)
        if len(data)<12 or data[:2]!=packet[:2]:raise ValueError('DNS transaction mismatch')
        flags,qd,an=struct.unpack('!HHH',data[2:8]);offset=12;answers=[]
        for _ in range(qd):offset=_dns_skip_name(data,offset)+4
        for _ in range(an):
            offset=_dns_skip_name(data,offset)
            if offset+10>len(data):raise ValueError('truncated DNS answer')
            kind,cls,ttl,n=struct.unpack('!HHIH',data[offset:offset+10]);offset+=10
            if offset+n>len(data):raise ValueError('truncated DNS rdata')
            if kind==1 and cls==1 and n==4:answers.append(socket.inet_ntoa(data[offset:offset+n]))
            offset+=n
        trace.update(dns_rcode=flags&15,dns_answers=answers)
        return ('noerror' if flags&15==0 else 'rcode-%d'%(flags&15)),answers
    except (OSError,ValueError) as error:
        trace['error']=type(error).__name__+': '+str(error);return 'timeout',[]
    finally:trace['ended_at']=time.time();sock.close()


def _dns_skip_name(data, offset):
    start=offset
    while offset<len(data):
        n=data[offset]
        if n==0:return offset+1
        if n&0xc0==0xc0:
            if offset+1>=len(data):raise ValueError('truncated DNS name')
            return offset+2
        if n>63 or offset+n+1>len(data):raise ValueError('invalid DNS label')
        offset+=n+1
        if offset-start>255:raise ValueError('DNS name too long')
    raise ValueError('truncated DNS name')


def _read_line(sock, limit=512):
    data=bytearray()
    while len(data)<limit:
        part=sock.recv(1)
        if not part:break
        data.extend(part)
        if part==b'\n':break
    return bytes(data)


def _tcp_exchange(ip, port, nonce, timeout, capture=None, tls=False,
                  server_hostname=None, io=None, trace=None, policy_inputs=None):
    trace=trace if trace is not None else {}
    sock=(io or socket).socket(socket.AF_INET,socket.SOCK_STREAM);sock.settimeout(timeout)
    request=FNPR%nonce.encode('ascii');sport=0
    trace.update(started_at=time.time(),request_hex=request.hex(),response_hex='',sent=False,error=None,tls=tls)
    try:
        sock.bind((io.inputs['local_source'] if io else '',0));sock.connect((ip,port));src,sport=sock.getsockname()
        trace['tuple']={'proto':'TCP','src':src,'sport':sport,'dst':ip,'port':port}
        if tls:
            context=io.tls_context() if io else ssl.create_default_context(cafile=(policy_inputs or {}).get('tls_ca_file'))
            sock=context.wrap_socket(sock,server_hostname=server_hostname or ip)
            trace.update(tls_peer_der=sock.getpeercert(binary_form=True).hex(),tls_hostname=server_hostname or ip)
        sock.sendall(request);trace['sent']=True
        if capture:capture.add(src,ip,sport,port,'TCP',request)
        response=_read_line(sock);trace['response_hex']=response.hex()
        if capture and response:capture.add(ip,src,port,sport,'TCP',response)
        return response,sport
    except (OSError,ssl.SSLError) as error:
        trace['error']=type(error).__name__+': '+str(error);return b'',sport
    finally:trace['ended_at']=time.time();sock.close()


def _udp_exchange(ip, port, nonce, timeout, capture=None, io=None, trace=None):
    trace=trace if trace is not None else {};sock=(io or socket).socket(socket.AF_INET,socket.SOCK_DGRAM);sock.settimeout(timeout)
    request=FNPR%nonce.encode('ascii');sport=0
    trace.update(started_at=time.time(),request_hex=request.hex(),response_hex='',sent=False,error=None,tls=False)
    try:
        sock.sendto(request,(ip,port));src,sport=sock.getsockname();trace.update(sent=True,tuple={'proto':'UDP','src':src,'sport':sport,'dst':ip,'port':port})
        if capture:capture.add(src,ip,sport,port,'UDP',request)
        response,peer=sock.recvfrom(512)
        if peer!=(ip,port):raise OSError('UDP response peer changed')
        trace['response_hex']=response.hex()
        if capture:capture.add(ip,src,port,sport,'UDP',response)
        return response,sport
    except OSError as error:
        trace['error']=type(error).__name__+': '+str(error);return b'',sport
    finally:trace['ended_at']=time.time();sock.close()


def _ping(target, ipv6=False, timeout=5, io=None, trace=None):
    trace=trace if trace is not None else {}
    if io is not None:return io.ping(target,ipv6,trace)
    args=['ping','-6' if ipv6 else '-4','-n' if os.name=='nt' else '-c','1','-w' if os.name=='nt' else '-W','1000' if os.name=='nt' else str(timeout),target]
    try:
        result=subprocess.run(args,capture_output=True,timeout=timeout+3)
        trace.update(command=args,stdout_hex=result.stdout.hex(),stderr_hex=result.stderr.hex(),returncode=result.returncode)
        return True,result.returncode
    except (OSError,subprocess.SubprocessError) as exc:
        trace.update(command=args,error=type(exc).__name__+': '+str(exc));return False,None


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


def _frame(src,dst,sport,dport,proto,payload):
    v6=ipaddress.ip_address(src).version==6
    number={'TCP':6,'UDP':17,'ICMP':1,'ICMPv6':58}[proto]
    if proto=='TCP':transport=struct.pack('!HHIIBBHHH',sport,dport,1,1,0x50,0x18,8192,0,0)+payload
    elif proto=='UDP':transport=struct.pack('!HHHH',sport,dport,len(payload)+8,0)+payload
    else:transport=payload
    if v6:
        network=struct.pack('!IHBB',6<<28,len(transport),number,64)+socket.inet_pton(socket.AF_INET6,src)+socket.inet_pton(socket.AF_INET6,dst)
        return b'\x00'*12+b'\x86\xdd'+network+transport
    network=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(transport),0,0,64,number,0,socket.inet_aton(src),socket.inet_aton(dst))
    return b'\x00'*12+b'\x08\x00'+network+transport


class _MemorySocket:
    def __init__(self, core, peer=None):
        self.core, self.peer = core, peer
        self.local = (core.inputs['local_source'], core.next_port())
        self.response = b''
    def settimeout(self, timeout): pass
    def getsockname(self): return self.local
    def getpeername(self): return self.peer
    def close(self): pass
    def bind(self, address): pass
    def connect(self, peer): self.peer=peer
    def getpeercert(self, binary_form=False): return b'memory-only-peer'
    def sendto(self, data, peer):
        self.peer = peer
        if peer == (self.core.inputs['dns_address'], self.core.inputs['dns_port']):
            offset=12; labels=[]
            while data[offset]:
                n=data[offset]; labels.append(data[offset+1:offset+1+n].decode('ascii')); offset+=n+1
            name='.'.join(labels); address=self.core.dns(name); question=data[12:offset+5]
            self.response=data[:2]+(b'\x81\x80' if address else b'\x81\x83')+data[4:6]+(b'\x00\x01' if address else b'\x00\x00')+b'\x00'*4+question
            if address:
                self.response+=b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'+socket.inet_aton(address)
        else: self.exchange(data, 'UDP')
        return len(data)
    def sendall(self, data): self.exchange(data, 'TCP')
    def exchange(self, data, proto):
        nonce=data.split(b'|')[1].decode('ascii') if data.startswith(b'FNPR/1|') else ''
        ip,port=self.peer; i=self.core.inputs
        allowed=self.core.baseline or (proto=='TCP' and (ip,port)==(i['reviewed_ip'],i['reviewed_port'])) or (ip,port)==(i['sink_ip'],i['sink_port'])
        event=('ALLOW_TAKEOVER_SINK' if ip==i['sink_ip'] else ('ALLOW_REVIEWED_IP_FIRST_FLOW' if self.core.scenario in ('ipv4','combined') else 'REDIRECT_TLS_RELAY')) if allowed else 'DIVERT_FAKE_PROBE'
        self.core.log('%s src=%s sport=%d dst=%s ip=%s original_ip=%s dport=%d original_port=%d proto=%s probe_nonce=%s epoch=%d' % (event,self.local[0],self.local[1],ip,ip,ip,port,port,proto,nonce,int(time.time())))
        self.response=('FNPR/1|%s|OK\n'%nonce).encode() if allowed else b''
    def recv(self, size):
        part,self.response=self.response[:size],self.response[size:]; return part
    def recvfrom(self, size):
        if not self.response: raise socket.timeout('memory denied')
        return self.recv(size),self.peer


class _SubstituteCore:
    """Pure memory socket/process boundary. Never binds, sends or pings."""
    def __init__(self, output, scenario, inputs, capture, certificate_dir=None):
        self.output=Path(output);self.scenario=scenario;self.inputs=inputs
        self.log_path=self.output/'core.log';self.counter=42000;self.baseline=False;self.capture=capture
    def next_port(self): self.counter+=1;return self.counter
    def socket(self, *args): return _MemorySocket(self)
    def create_connection(self, peer, timeout=None): return _MemorySocket(self,peer)
    def tls_context(self): return self
    def wrap_socket(self, sock, server_hostname=None): return sock
    def log(self, line):
        with self.log_path.open('a',encoding='utf-8') as stream:stream.write(line+'\n')
    def dns(self, name):
        self.log("Received A request for domain '%s'"%name)
        if name==self.inputs['allowed_domain'] or name.endswith('.'+self.inputs['wildcard_domain'][2:]):
            self.log('DNS_LEASE_ADD domain=%s ip=%s ttl=60'%(name,self.inputs['reviewed_ip']));return self.inputs['reviewed_ip']
        if self.baseline:return self.inputs['reviewed_ip']
        parser=configparser.ConfigParser();parser.read(self.output/'policy.ini')
        return next((parser.get(s,'ResponseA') for s in parser.sections() if parser.get(s,'Listener',fallback='')=='DNSListener'),None)
    def start(self): self.log(READY[self.scenario])
    def stop(self): self.log('memory core stopped')
    def ping(self,target,ipv6=False,trace=None):
        trace=trace if trace is not None else {};proto='ICMPv6' if ipv6 else 'ICMP'
        src=self.inputs['local_source_ipv6'] if ipv6 else self.inputs['local_source']
        ident=self.next_port();request=struct.pack('!BBHHH',128 if ipv6 else 8,0,0,ident,1)+b'memory-echo'
        if self.capture:
            self.capture.add(src,target,0,0,proto,request)
            if self.baseline:self.capture.add(target,src,0,0,proto,struct.pack('!BBHHH',129 if ipv6 else 0,0,0,ident,1)+b'memory-echo')
        if not self.baseline:self.log('DROP_EXTERNAL reason=%s original_ip=%s'%('external_ipv6' if ipv6 else 'no_authorized_route',target))
        code=0 if self.baseline else 1
        trace.update(command=['memory-only-ping',target],stdout_hex=b'memory echo'.hex(),stderr_hex='',returncode=code)
        return True,code


class HostServices:
    """Owned, bounded FNPR TCP/UDP endpoints for the selected host sink.

    Only the native controller constructs this object. The guest never reads
    private key material or installs a service. Tests inject memory boundaries.
    """
    @staticmethod
    def validate(inputs, checks, allowed_actions):
        needed={'sink_tcp','sink_udp'}&set(checks)
        if not needed:return None
        spec=inputs.get('host_service')
        if 'policy-services' not in allowed_actions or not isinstance(spec,dict):
            raise ValueError('selected sink needs explicit policy-services action and host_service binding')
        if set(spec)!={'bind_ipv4','allowed_peer_ipv4','max_seconds'}:
            raise ValueError('invalid host_service fields')
        if spec['bind_ipv4']!=inputs['sink_ip'] or spec['allowed_peer_ipv4']!=inputs['local_source']:
            raise ValueError('host service/guest endpoint binding differs from policy inputs')
        if type(spec['max_seconds']) is not int or not 1<=spec['max_seconds']<=300:
            raise ValueError('host service needs bounded lifetime')
        return spec

    def __init__(self,inputs,checks,actions,directory):
        self.inputs=inputs;self.checks=set(checks);self.spec=self.validate(inputs,checks,actions)
        self.directory=Path(directory);self.servers=[];self.threads=[];self.timer=None
        self.lock=threading.Lock();self.stop_lock=threading.Lock();self.stopped=False
        self.owner={'id':uuid.uuid4().hex,'pid':os.getpid(),'started_at':time.time(),
                    'bind_ipv4':inputs['sink_ip'],'port':inputs['sink_port'],
                    'allowed_peer_ipv4':inputs['local_source'],'ready':False,'stopped':False}

    def append(self,event):
        with self.lock:
            with (self.directory/'events.jsonl').open('a',encoding='utf-8') as stream:
                stream.write(json.dumps(dict(event,owner=self.owner['id'],time=time.time()))+'\n')

    def start(self):
        if self.spec is None:return
        import psutil
        local={a.address for addresses in psutil.net_if_addrs().values() for a in addresses if a.family==socket.AF_INET}
        if self.inputs['sink_ip'] not in local:raise ValueError('selected host sink is not an observed local interface')
        self.owner['birth']=psutil.Process(os.getpid()).create_time()
        self.directory.mkdir(exist_ok=False)
        (self.directory/'events.jsonl').touch(exist_ok=False)
        owner=self
        def answer(data,peer,transport,send):
            if peer[0]!=owner.spec['allowed_peer_ipv4']:raise ValueError('unselected peer')
            if len(data)>512 or not data.endswith(b'\n') or data.count(b'\n')!=1:raise ValueError('invalid bounded FNPR framing')
            fields=data[:-1].decode('ascii').split('|')
            if len(fields)!=3 or fields[0]!='FNPR/1' or fields[2] not in ('target','preflight','non-target') or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,192}',fields[1]):raise ValueError('invalid FNPR request')
            response=('FNPR/1|%s|OK\n'%fields[1]).encode()
            send(response)
            owner.append({'transport':transport,'peer_ip':peer[0],'peer_port':peer[1],
                          'request_hex':data.hex(),'response_hex':response.hex(),'nonce':fields[1]})
        class Tcp(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(3)
                try:answer(_read_line(self.request),self.client_address,'TCP',self.request.sendall)
                except (OSError,ValueError,UnicodeError) as exc:owner.append({'error':type(exc).__name__})
        class Udp(socketserver.BaseRequestHandler):
            def handle(self):
                data,sock=self.request
                try:answer(data,self.client_address,'UDP',lambda response:sock.sendto(response,self.client_address))
                except (OSError,ValueError,UnicodeError) as exc:owner.append({'error':type(exc).__name__})
        class TcpServer(socketserver.ThreadingTCPServer):
            allow_reuse_address=False
            daemon_threads=False
        class UdpServer(socketserver.ThreadingUDPServer):
            allow_reuse_address=False
            daemon_threads=False
        try:
            for name,cls,handler in [('sink_tcp',TcpServer,Tcp),('sink_udp',UdpServer,Udp)]:
                if name not in self.checks:continue
                server=cls((self.spec['bind_ipv4'],self.inputs['sink_port']),handler)
                self.servers.append(server)
                thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.05},daemon=True)
                thread.start();self.threads.append(thread)
            if not self.threads or not all(t.is_alive() for t in self.threads):raise RuntimeError('owned endpoint thread not ready')
            self.owner['ready']=True
            self.timer=threading.Timer(self.spec['max_seconds'],self.stop);self.timer.daemon=True;self.timer.start()
            (self.directory/'ready.json').write_text(json.dumps(self.owner))
        except BaseException:
            self.stop();raise

    def stop(self):
        if self.spec is None:return
        with self.stop_lock:
            if self.stopped:return
            if self.timer:self.timer.cancel()
            for index,server in enumerate(self.servers):
                if index<len(self.threads):server.shutdown()
                server.server_close()
            for thread in self.threads:thread.join(5)
            self.stopped=all(not t.is_alive() for t in self.threads)
            self.owner.update(stopped=self.stopped,ended_at=time.time())
            if self.directory.exists():(self.directory/'lifecycle.json').write_text(json.dumps(self.owner))


def _snapshot():
    from acceptance_runtime import network_snapshot
    return network_snapshot()


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


def _combo_binding(context):
    return {key: context[key] for key in
            ('run_id', 'config_sha256', 'owner', 'started_at')}


def _combo_trace(context):
    return {'combo_binding': _combo_binding(context)} if context else {}


def _run_checks(scenario, output, inputs, log_text, capture, core=None, selected=None, baseline=False, combo_context=None):
    selected=set(CHECKS[scenario]) if selected is None else set(selected)
    attempts=[];checks=[];nonce_base=combo_context['run_id'] if combo_context else uuid.uuid4().hex
    evidence_dir=Path(output)/('controls' if baseline else 'probes');evidence_dir.mkdir(exist_ok=False)
    def probe(name,kind,dst,port,positive,domain=None,tls=False,resolution=None):
        if name not in selected:return
        trace=_combo_trace(combo_context);nonce=nonce_base+'-'+name
        log=Path(output)/'core.log';start=log.stat().st_size if log.exists() else 0
        if kind=='DNS':
            rcode,answers=_dns_query(domain,dst,port,3,capture,io=core,trace=trace)
            valid=bool(answers) if positive else rcode!='timeout' and not answers
        else:
            if scenario=='combo' and not baseline and name in ('sink_tcp','sink_udp'):
                resolution=_combo_trace(combo_context);rcode,answers=_dns_query(inputs['denied_domain'],inputs['dns_address'],inputs['dns_port'],3,capture,io=core,trace=resolution)
                resolution_path=evidence_dir/(name+'-dns.json');resolution_path.write_text(json.dumps(resolution)+'\n')
                trace['dns_resolution']={'path':str(resolution_path.relative_to(output)),'sha256':sha256(resolution_path),'answers':answers,'rcode':rcode}
                if answers!=[inputs['sink_ip']]:
                    trace.update(sent=False,error='denied-domain DNS did not return the configured sink')
                    path=evidence_dir/(name+'.json');path.write_text(json.dumps(trace)+'\n')
                    checks.append({'id':name,'status':'unknown','reason':'denied-domain sink DNS missing','evidence':[str(path.relative_to(output))]});return
                dst=answers[0]
            response,sport=(_tcp_exchange(dst,port,nonce,3,capture,tls=tls,server_hostname=domain or inputs['allowed_domain'],io=core,trace=trace,policy_inputs=inputs) if kind=='TCP' else _udp_exchange(dst,port,nonce,3,capture,io=core,trace=trace))
            valid=response==('FNPR/1|%s|OK\n'%nonce).encode()
        end=log.stat().st_size if log.exists() else 0
        trace.update(id=name,nonce=nonce,positive=positive,log_range=[start,end])
        if resolution is not None:trace['resolution']=resolution
        path=evidence_dir/(name+'.json');path.write_text(json.dumps(trace,indent=2)+'\n')
        tup=trace.get('tuple',{'proto':kind,'src':inputs['local_source'],'sport':0,'dst':dst,'port':port})
        attempt=_attempt(name,nonce,trace['started_at'],trace['ended_at'],tup['proto'],tup['src'],tup['dst'],tup['port'],'target');attempt['tuple']=tup;attempt['probe']={'path':str(path.relative_to(output)),'sha256':sha256(path)};attempts.append(attempt)
        if baseline:status='pass' if valid else 'unknown'
        elif kind=='DNS':status='pass' if valid else 'unknown'
        elif positive:status='pass' if valid else 'unknown'
        else:status='fail' if valid else 'unknown' # only the original content oracle may establish denial
        checks.append(_check(name,status,trace['sent'],bool(trace.get('response_hex')),nonce,tup,evidence=['core.log',attempt['probe']['path']]))
    names={'exact_domain':inputs['allowed_domain'],'wildcard_domain':'www.'+inputs['wildcard_domain'][2:],'apex_denied':inputs['apex_domain'],'default_deny':inputs['denied_domain']}
    for name,domain in names.items():
        probe(name,'DNS',inputs['dns_address'],inputs['dns_port'],name in ('exact_domain','wildcard_domain'),domain)
    if 'tls_application' in selected:
        # Never fall back to a different address after DNS failure.
        dns_trace=_combo_trace(combo_context);rcode,answers=_dns_query(inputs['allowed_domain'],inputs['dns_address'],inputs['dns_port'],3,capture,io=core,trace=dns_trace)
        resolution_path=evidence_dir/'tls-resolution.json';resolution_path.write_text(json.dumps(dns_trace))
        if answers:probe('tls_application','TCP',answers[0],inputs['reviewed_port'],True,inputs['allowed_domain'],True,{'path':str(resolution_path.relative_to(output)),'sha256':sha256(resolution_path)})
        else:
            checks.append({'id':'tls_application','status':'unknown','reason':'selected DNS prerequisite did not resolve'})
    for args in [
        ('reviewed_ip_tls','TCP',inputs['reviewed_ip'],inputs['reviewed_port'],True,inputs['allowed_domain'],True),
        ('port_80_denied','TCP',inputs['reviewed_ip'],inputs['denied_http_port'],False),
        ('port_444_denied','TCP',inputs['reviewed_ip'],inputs['denied_alt_port'],False),
        ('udp443_denied','UDP',inputs['reviewed_ip'],inputs['denied_udp_port'],False),
        ('other_ip_denied','TCP',inputs['other_ip'],inputs['other_port'],False),
        ('sink_tcp','TCP',inputs['sink_ip'],inputs['sink_port'],True),
        ('sink_udp','UDP',inputs['sink_ip'],inputs['sink_port'],True),
        ('adjacent_denied','UDP',inputs['adjacent_ip'],inputs['adjacent_port'],False)]:probe(*args)
    for name,ipv6,target in [('icmp_denied',False,inputs['sink_ip']),('ipv6_denied',True,inputs.get('ipv6_target'))]:
        if name not in selected:continue
        if not target or (ipv6 and not inputs.get('local_source_ipv6')):
            checks.append({'id':name,'status':'unknown','reason':'explicit IPv6 endpoint is absent'});continue
        log=Path(output)/'core.log';lo=log.stat().st_size if log.exists() else 0
        trace={};before=time.time();attempted,code=_ping(target,ipv6=ipv6,io=core,trace=trace);after=time.time()
        hi=log.stat().st_size if log.exists() else 0
        trace.update(id=name,nonce=nonce_base+'-'+name,started_at=before,ended_at=after,sent=attempted,returncode=code,target=target,log_range=[lo,hi])
        path=evidence_dir/(name+'.json');path.write_text(json.dumps(trace))
        a=_attempt(name,trace['nonce'],before,after,'ICMPv6' if ipv6 else 'ICMP',inputs.get('local_source_ipv6') if ipv6 else inputs['local_source'],target,0,'target');a['probe']={'path':str(path.relative_to(output)),'sha256':sha256(path)};attempts.append(a)
        checks.append(_check(name,'fail' if code==0 and not baseline else 'unknown',attempted,False,trace['nonce'],a['tuple'],evidence=[str(path.relative_to(output))]))
    return attempts,checks


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
            route_before, route_after, fixture_run=False, selected=None):
    network_match = network_before == network_after
    route_match = route_before == route_after
    route_check = [item for item in checks if item['id'] == 'route_restore']
    if 'route_restore' in (selected or CHECKS[scenario]):
        route_restored = bool(stopped and exited and code==0 and route_match and network_match and route_before is not None and route_after is not None)
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
    if selected is not None:
        attempts[:] = [item for item in attempts if item['id'] in selected]
        checks[:] = [item for item in checks if item['id'] in selected]
    value = {
        'schema': SCHEMA, 'scenario': scenario, 'fixture': fixture_run,
        'inputs': inputs,
        'config': {'path': 'policy.ini', 'sha256': sha256(config)},
        'log': {'path': 'core.log', 'sha256': sha256(log)},
        'pcap': [{'path': path.name, 'sha256': sha256(path),
                  'linktype': 1, 'packets': 0} for path in pcap_paths],
        'attempts': attempts, 'checks': checks,
        'observations': {name: {'path':name+'.json','sha256':sha256(Path(output)/(name+'.json'))} for name in ('network-before','network-after','core-lifecycle')},
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


def memory_inputs(values=None):
    inputs=_inputs(values)
    inputs.update(reviewed_ip='127.0.0.1',sink_ip='127.0.0.2',adjacent_ip='127.0.0.3',
                      reviewed_port=14443,denied_http_port=18080,denied_alt_port=18444,
                      denied_udp_port=14443,sink_port=19000,adjacent_port=19001,
                      dns_address='127.0.0.1',dns_port=15353,local_source='127.0.0.1',
                      other_ip='127.0.0.3',other_port=14443,ipv6_target='2001:db8::1',local_source_ipv6='2001:db8::2')

    return inputs


def run(scenario, output, core_command=None, timeout=120, inputs=None,
        substitute=False, fixture_run=False, selected=None):
    if selected is None: selected=set(CHECKS[scenario])
    selected=set(selected)
    if scenario == 'combo' and selected != set(CHECKS['combo']):
        raise ValueError('combo requires the complete twelve-check selection')
    if not selected or not selected.issubset(CHECKS[scenario]):
        raise ValueError('unknown/empty policy selection')
    if substitute:
        inputs=memory_inputs(inputs)
    elif not isinstance(inputs,dict) or set(DEFAULTS)-set(inputs):
        raise ValueError('explicit production policy inputs required; no default endpoints')
    if not substitute and (not isinstance(core_command,list) or not core_command):
        raise ValueError('explicit production core command required')
    strict=not substitute
    _validate_inputs(scenario,inputs,strict=strict)
    output=Path(output)
    output.mkdir(parents=True,exist_ok=False)
    config = output / 'policy.ini'
    config.write_text(config_text(scenario, output, inputs, strict=strict),
                      encoding='utf-8')
    log = output / 'core.log'
    capture = Capture(output / 'policy.pcap') if substitute else None
    core = None
    process = None
    owned = None
    birth = None
    forced = False
    error = None
    controls = []
    combo_context = None
    code = None
    exited = False
    before = {'memory_fixture': True, 'routes': []} if substitute else _snapshot()
    (output/'network-before.json').write_text(json.dumps(before))
    attempts = []
    checks = []
    try:
        if substitute:
            core=_SubstituteCore(output,scenario,inputs,capture,output)
            core.baseline=True
        controls,_=_run_checks(scenario,output,inputs,'',None,core,selected,baseline=True)
        if substitute:
            core.baseline=False;core.start();exited=True;code=0
        else:
            from acceptance_runtime import OwnedCore
            import psutil
            command=list(core_command)+['-n','--no-pause','-c',str(config),'-l',str(log),'-f',str(output/'stop.flag')]
            owned=OwnedCore(command,ROOT,output,output/'stop.flag',log,source_root=ROOT)
            owned.start(timeout=timeout)
            process=owned.process
            birth=psutil.Process(process.pid).create_time()
        if scenario == 'combo':
            run_id = uuid.uuid4().hex
            owner = ({'kind': 'memory-fixture', 'id': run_id} if substitute else
                     {'kind': 'owned-child', 'pid': process.pid, 'birth': birth})
            combo_context = {'schema': 'fakenet.combo-context.v1',
                             'scenario': 'combo', 'run_id': run_id,
                             'config_sha256': sha256(config), 'owner': owner,
                             'started_at': time.time()}
        attempts, checks = _run_checks(scenario, output, inputs,
                                       log.read_text(encoding='utf-8',
                                                    errors='replace')
                                       if log.is_file() else '',
                                       capture, core, selected, combo_context=combo_context)
    except BaseException as exc:
        error=type(exc).__name__+': '+str(exc)
    finally:
        if combo_context is not None:
            combo_context['ended_at'] = time.time()
        if substitute and core is not None:
            core.stop();exited=True;code=0
        elif owned is not None:
            try:
                if not (output/'core-lifecycle.json').is_file():
                    owned.stop()
            except BaseException as exc:
                error=(error+'; ' if error else '')+'cleanup '+type(exc).__name__+': '+str(exc)
            process=owned.process
            exited=owned.state.get('stopped') is True
            code=owned.state.get('returncode');forced=owned.state.get('forced') is True
        if capture is not None:capture.close()
    try:
        after = {'memory_fixture': True, 'routes': []} if substitute else _snapshot()
    except (OSError,ValueError,RuntimeError) as exc:
        after = {'observation_error':type(exc).__name__+': '+str(exc)}
        error=(error+'; ' if error else '')+after['observation_error']
    (output/'network-after.json').write_text(json.dumps(after))
    pcap_paths = sorted(output.glob('policy*.pcap'))
    log_text = log.read_text(encoding='utf-8', errors='replace') if log.is_file() else ''
    route_before = before.get('routes', before.get('routes4'))
    route_after = after.get('routes', after.get('routes4'))
    (output/'core-lifecycle.json').write_text(json.dumps({'source':'owned-child','pid':None if process is None else process.pid,'birth':birth,'exited':bool(exited),'returncode':code,'forced':forced,'timed_out':not exited,'memory_fixture':substitute}))
    if combo_context is not None:
        lifecycle_path = output / 'core-lifecycle.json'
        lifecycle = json.loads(lifecycle_path.read_text())
        lifecycle.update(combo_run_id=combo_context['run_id'],
                         combo_owner=combo_context['owner'],
                         combo_window={key: combo_context[key] for key in
                                       ('started_at', 'ended_at')})
        lifecycle_path.write_text(json.dumps(lifecycle) + '\n')
        combo_context['config_sha256_after'] = sha256(config)
        combo_context['lifecycle'] = {'path': 'core-lifecycle.json',
                                      'sha256': sha256(lifecycle_path)}
        combo_context['pcap'] = [{'path': path.name, 'sha256': sha256(path)}
                                 for path in pcap_paths]
        (output / 'combo-context.json').write_text(json.dumps(combo_context) + '\n')
    if not log.exists():log.write_text('')
    value = _result(scenario, output, inputs, attempts, checks, pcap_paths, log,
            config, bool(exited), code, bool(exited), before, after,
            route_before, route_after, fixture_run=fixture_run or substitute,
            selected=selected)
    value['controls']=controls;value['error']=error
    if combo_context is not None:
        value['combo_context'] = {'path': 'combo-context.json',
                                  'sha256': sha256(output / 'combo-context.json')}
    (output/'policy-result.json').write_text(json.dumps(value,indent=2)+'\n')
    return 1 if error else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scenario', choices=sorted(CHECKS), required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--fixture', action='store_true')
    parser.add_argument('--substitute', action='store_true')
    parser.add_argument('--python', default=sys.executable)
    parser.add_argument('--timeout', type=int, default=120)
    parser.add_argument('--inputs', help='JSON object with explicit policy inputs')
    parser.add_argument('--checks', help='comma-separated selected check ids')
    args = parser.parse_args(argv)
    inputs = json.loads(Path(args.inputs).read_text(encoding='utf-8')) if args.inputs else {}
    selected = set(item for item in (args.checks or '').split(',') if item) or None
    if args.fixture:
        return fixture(args.scenario, args.output)
    return run(args.scenario, args.output,
               [args.python, '-m', 'fakenet.fakenet'], args.timeout,
               inputs=inputs, substitute=args.substitute, selected=selected)


if __name__ == '__main__':
    raise SystemExit(main())
