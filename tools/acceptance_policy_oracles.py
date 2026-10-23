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
    candidate=Path(original)/relative
    if any(part.is_symlink() for part in [candidate,*candidate.parents] if part.is_relative_to(Path(original))):
        raise ValueError('%s original contains a symlink' % label)
    path = candidate.resolve()
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
        if included != original or included > len(data) - offset:
            raise ValueError('truncated PCAP record')
        frame = data[offset:offset + included]
        offset += included
        stamp = sec + frac / (1e9 if nano else 1e6)
        packet = _decode_frame(frame, linktype, stamp)
        if packet is not None:
            packets.append(packet)
    if offset != len(data):raise ValueError('trailing partial PCAP record')
    return packets


def _pcapng_packets(data):
    packets=[];offset=0;endian=None;interfaces=[]
    while offset<len(data):
        if len(data)-offset<12:raise ValueError('trailing short pcapng block')
        section=data[offset:offset+4]==b'\x0a\x0d\x0d\x0a'
        if section:
            bom=data[offset+8:offset+12]
            if bom not in (b'\x4d\x3c\x2b\x1a',b'\x1a\x2b\x3c\x4d'):raise ValueError('invalid pcapng byte order')
            endian='<' if bom==b'\x4d\x3c\x2b\x1a' else '>';interfaces=[]
        if endian is None:raise ValueError('pcapng section missing')
        kind,n=struct.unpack(endian+'II',data[offset:offset+8])
        if n<12 or n%4 or offset+n>len(data) or struct.unpack(endian+'I',data[offset+n-4:offset+n])[0]!=n:raise ValueError('invalid pcapng block framing')
        body=data[offset+8:offset+n-4]
        if kind==1:
            if len(body)<8:raise ValueError('short pcapng interface')
            link,reserved,snap=struct.unpack(endian+'HHI',body[:8]);resolution=1e-6;options=body[8:];pos=0
            while pos+4<=len(options):
                code,size=struct.unpack(endian+'HH',options[pos:pos+4]);pos+=4
                if pos+size>len(options):raise ValueError('short pcapng interface option')
                if code==9:
                    if size!=1:raise ValueError('invalid timestamp resolution')
                    value=options[pos];resolution=(2.0**-(value&127)) if value&128 else 10.0**-value
                if code==14 and any(options[pos:pos+size]):raise ValueError('nonzero timestamp offset unsupported')
                pos+=(size+3)&~3
                if code==0:break
            interfaces.append((link,resolution))
        elif kind==6:
            if len(body)<20:raise ValueError('short enhanced packet')
            interface,hi,lo,cap,original=struct.unpack(endian+'IIIII',body[:20])
            if interface>=len(interfaces) or cap!=original or 20+((cap+3)&~3)>len(body):raise ValueError('invalid/truncated enhanced packet')
            link,resolution=interfaces[interface];packet=_decode_frame(body[20:20+cap],link,((hi<<32)|lo)*resolution)
            if packet is not None:packets.append(packet)
        offset+=n
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
        if ethertype == 0x86dd:
            if len(frame)<offset+40:return None
            size=struct.unpack('!H',frame[offset+4:offset+6])[0]
            if len(frame)<offset+40+size:raise ValueError('truncated IPv6 original')
            if frame[offset+6]!=58:return None
            return {'time':stamp,'proto':'ICMPv6','src':socket.inet_ntop(socket.AF_INET6,frame[offset+8:offset+24]),'dst':socket.inet_ntop(socket.AF_INET6,frame[offset+24:offset+40]),'sport':0,'dport':0,'payload':frame[offset+40:offset+40+size]}
        if ethertype != 0x0800:return None
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
    if len(frame)<offset+total or struct.unpack('!H',frame[offset+6:offset+8])[0]&0x3fff:raise ValueError('truncated/fragmented IPv4 packet')
    transport = offset + ihl
    protocol = frame[offset + 9]
    src = socket.inet_ntoa(frame[offset + 12:offset + 16])
    dst = socket.inet_ntoa(frame[offset + 16:offset + 20])
    if protocol == 6 and len(frame) >= transport + 20:
        sport, dport = struct.unpack('!HH', frame[transport:transport + 4])
        data_offset = (frame[transport + 12] >> 4) * 4
        if data_offset<20 or transport+data_offset>offset+total:raise ValueError('invalid TCP header length')
        payload = frame[transport + data_offset:offset + total]
        return {'time': stamp, 'proto': 'TCP', 'src': src, 'sport': sport,
                'dst': dst, 'dport': dport, 'payload': payload, 'seq':struct.unpack('!I',frame[transport+4:transport+8])[0]}
    if protocol == 17 and len(frame) >= transport + 8:
        sport, dport = struct.unpack('!HH', frame[transport:transport + 4])
        payload = frame[transport + 8:offset + total]
        return {'time': stamp, 'proto': 'UDP', 'src': src, 'sport': sport,
                'dst': dst, 'dport': dport, 'payload': payload}
    if protocol in (1, 58):
        return {'time': stamp, 'proto': 'ICMP' if protocol == 1 else 'ICMPv6',
                'src': src, 'sport': 0, 'dst': dst, 'dport': 0,
                'payload': frame[transport:offset+total]}
    return None


def _legacy_destination_matching(packets, tuple_value, start, end):
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
    if str(inputs['reviewed_port']) not in [part.strip() for part in
                     _config_value(parser, 'ExternalAllowedTCPPorts').split(',')]:
        raise ValueError('ExternalAllowedTCPPorts differs from selected TLS port')
    domains = [p.strip() for p in _config_value(parser, 'ExternalAllowedDomains').split(',')]
    if inputs['allowed_domain'] not in domains:
        raise ValueError('allowed domain is absent from configuration')
    if inputs['wildcard_domain'] not in domains:
        raise ValueError('wildcard domain is absent from configuration')
    if _config_value(parser,'ExternalDnsServer').strip()!=inputs['upstream_dns']:raise ValueError('upstream DNS differs from selected input')
    try:
        ipaddress.ip_address(_config_value(parser, 'ExternalDnsServer').strip())
    except ValueError as error:
        raise ValueError('ExternalDnsServer is invalid') from error
    if scenario in ('ipv4', 'combined', 'combo'):
        if _config_value(parser, 'ExternalAllowedIPv4'):
            raise ValueError('old ExternalAllowedIPv4 key is present')
        rule = _config_value(parser, 'ExternalAllowedIPv4Rules').strip()
        expected = 'TCP/%s/%d' % (inputs['reviewed_ip'],
                                  int(inputs['reviewed_port']))
        if rule != expected:
            raise ValueError('reviewed IPv4 rule differs from the selected input')
    if scenario in ('takeover', 'combined', 'combo'):
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


def _load_json(original, item, label):
    return json.loads(_read(_safe_file(original,item,label)))


def _dns_content(request,response,domain):
    if len(request)<12 or len(response)<12 or request[:2]!=response[:2]:
        raise ValueError('DNS request/response identity differs')
    labels=[];offset=12
    while offset<len(request) and request[offset]:
        n=request[offset]
        if n>63 or offset+n+1>len(request):raise ValueError('invalid DNS query')
        labels.append(request[offset+1:offset+1+n].decode('ascii'));offset+=1+n
    if '.'.join(labels).lower()!=domain.lower().rstrip('.'):
        raise ValueError('DNS question differs from planned domain')
    flags,qd,an=struct.unpack('!HHH',response[2:8]);offset=12
    def skip(data,start):
        for _ in range(256):
            if start>=len(data):break
            n=data[start]
            if n==0:return start+1
            if n&192==192:
                if start+1<len(data):return start+2
                break
            if n>63:break
            start+=1+n
        raise ValueError('invalid DNS answer name')
    for _ in range(qd):offset=skip(response,offset)+4
    answers=[]
    for _ in range(an):
        offset=skip(response,offset)
        if offset+10>len(response):raise ValueError('short DNS answer')
        kind,cls,ttl,n=struct.unpack('!HHIH',response[offset:offset+10]);offset+=10
        if offset+n>len(response):raise ValueError('short DNS answer data')
        if kind==1 and cls==1 and n==4:answers.append(socket.inet_ntoa(response[offset:offset+4]))
        offset+=n
    return flags&15,answers


def _matching(packets, flow, start, end):
    required={'proto','src','sport','dst','port'}
    if not required.issubset(flow) or flow['proto'] not in ('TCP','UDP'):
        return []
    if type(flow['sport']) is not int or type(flow['port']) is not int or not 1<=flow['sport']<=65535 or not 1<=flow['port']<=65535:
        return []
    result=[]
    for p in packets:
        if not start-.01<=p['time']<=end+.01 or p['proto']!=flow['proto']:continue
        out=(p['src'],p['sport'],p['dst'],p['dport'])==(flow['src'],flow['sport'],flow['dst'],flow['port'])
        incoming=(p['src'],p['sport'],p['dst'],p['dport'])==(flow['dst'],flow['port'],flow['src'],flow['sport'])
        if out or incoming:result.append(dict(p,direction='out' if out else 'in'))
    return result


def _decision(log,trace):
    span=trace.get('log_range')
    if not isinstance(span,list) or len(span)!=2 or any(type(n) is not int for n in span) or not 0<=span[0]<=span[1]<=len(log):
        return False
    flow=trace['tuple'];nonce=trace['nonce']
    for line in log[span[0]:span[1]].decode('utf-8','replace').splitlines():
        if not any(marker in line for marker in ('DIVERT_FAKE_PROBE','DROP_EXTERNAL','DIVERT_FAKE ')):continue
        fields=dict(__import__('re').findall(r'(\w+)=([^\s]+)',line))
        if fields.get('original_ip',fields.get('dst',fields.get('ip')))!=flow['dst']:continue
        if fields.get('original_port',fields.get('dport'))!=str(flow['port']):continue
        if 'probe_nonce' in fields and fields['probe_nonce']!=nonce:continue
        if 'src' in fields and fields['src']!=flow['src']:continue
        if 'sport' in fields and fields['sport']!=str(flow['sport']):continue
        if 'proto' in fields and fields['proto'].upper()!=flow['proto']:continue
        return True
    return False


class Unobservable(ValueError): pass


def _stream(packets):
    payloads=[p for p in packets if p['payload']]
    if not payloads:return b''
    if payloads[0]['proto']!='TCP':return b''.join(p['payload'] for p in payloads)
    base=payloads[0]['seq'];data={}
    for p in payloads:
        offset=(p['seq']-base)&0xffffffff
        if offset>1024*1024:raise ValueError('TCP sequence outside bounded probe window')
        for index,byte in enumerate(p['payload']):
            at=offset+index
            if at in data and data[at]!=byte:raise ValueError('TCP capture has conflicting bytes')
            data[at]=byte
    if sorted(data)!=list(range(len(data))):raise Unobservable('TCP capture has a gap')
    return bytes(data[i] for i in range(len(data)))


COMBO_CHECKS = {'exact_domain', 'wildcard_domain', 'tls_application',
                'reviewed_ip_tls', 'sink_tcp', 'sink_udp', 'port_80_denied',
                'port_444_denied', 'udp443_denied', 'other_ip_denied',
                'adjacent_denied', 'route_restore'}


def _combo_interval(value):
    import math
    start, end = value['started_at'], value['ended_at']
    if (any(type(v) not in (int, float) or not math.isfinite(v) for v in (start, end))
            or not 0 < start <= end):
        raise ValueError('combo evidence has an invalid time window')
    return start, end


def _combo_context(original, value, fixture, checks):
    if set(checks) != COMBO_CHECKS or len(checks) != len(COMBO_CHECKS):
        raise ValueError('combo requires its exact twelve-check set')
    context = _load_json(original, value.get('combo_context'), 'combo context')
    if context.get('schema') != 'fakenet.combo-context.v1' or context.get('scenario') != 'combo':
        raise ValueError('combo context schema/scenario differs')
    if not __import__('re').fullmatch('[0-9a-f]{32}', str(context.get('run_id', ''))):
        raise ValueError('combo run identity missing')
    _combo_interval(context)
    config = _safe_file(original, value.get('config'), 'combo configuration')
    if context.get('config_sha256') != _sha256(config) or context.get('config_sha256_after') != _sha256(config):
        raise ValueError('combo configuration changed during the single run')
    if context.get('lifecycle') != value.get('observations', {}).get('core-lifecycle'):
        raise ValueError('combo lifecycle differs from original observation')
    life = _load_json(original, context['lifecycle'], 'combo owned lifecycle')
    owner = context.get('owner')
    expected = ({'kind': 'memory-fixture', 'id': context['run_id']} if fixture else
                {'kind': 'owned-child', 'pid': life.get('pid'), 'birth': life.get('birth')})
    if (owner != expected or life.get('combo_owner') != owner
            or life.get('combo_run_id') != context['run_id']
            or life.get('combo_window') != {key: context[key] for key in ('started_at', 'ended_at')}
            or life.get('memory_fixture') is not fixture):
        raise ValueError('combo core birth/run/window does not match')
    if not fixture and (type(life.get('pid')) is not int or life['pid'] <= 0 or not life.get('birth')):
        raise ValueError('combo native core birth missing')
    declared = [{'path': p['path'], 'sha256': p['sha256']} for p in value.get('pcap', [])]
    if not declared or context.get('pcap') != declared:
        raise ValueError('combo capture belongs to a different run')
    return context


def _combo_trace_binding(trace, context):
    expected = {key: context[key] for key in ('run_id', 'config_sha256', 'owner', 'started_at')}
    if trace.get('combo_binding') != expected:
        raise ValueError('probe belongs to a different combo configuration/core/run')
    start, end = _combo_interval(trace)
    if not context['started_at'] <= start <= end <= context['ended_at']:
        raise ValueError('probe is outside the single combo capture window')
    return start, end


def _combo_dns(original, reference, domain, context, inputs, packets, consumer_start):
    trace = _load_json(original, reference, 'combo consumed DNS')
    start, end = _combo_trace_binding(trace, context)
    flow = trace['tuple']
    if (trace.get('sent') is not True or trace.get('domain') != domain
            or flow.get('proto') != 'UDP' or flow.get('src') != inputs['local_source']
            or flow.get('dst') != inputs['dns_address'] or flow.get('port') != inputs['dns_port']
            or type(flow.get('sport')) is not int or not 1 <= flow['sport'] <= 65535
            or end > consumer_start):
        raise ValueError('combo DNS send/endpoint/consumption order differs')
    request, response = bytes.fromhex(trace['request_hex']), bytes.fromhex(trace['response_hex'])
    code, answers = _dns_content(request, response, domain)
    matched = _matching(packets, flow, start, end)
    if (code != 0 or not answers
            or not any(p['direction'] == 'out' and p['payload'] == request for p in matched)
            or not any(p['direction'] == 'in' and p['payload'] == response for p in matched)):
        raise ValueError('combo consumed DNS has no matching original wire exchange')
    return answers


def _combo_sink_control(original, control, flow, context):
    if not control:
        raise ValueError('combo fixed sink stopped-state control missing')
    trace = _load_json(original, control.get('probe'), 'combo stopped sink control')
    start, end = _combo_interval(trace)
    observed = trace.get('tuple') or {}
    if (trace.get('sent') is not True or end > context['started_at']
            or trace.get('id') != control.get('id') or trace.get('nonce') != control.get('nonce')
            or control.get('tuple') != observed
            or any(observed.get(k) != flow.get(k) for k in ('proto', 'src', 'dst', 'port'))
            or bytes.fromhex(trace.get('response_hex', '')) != ('FNPR/1|%s|OK\n' % control.get('nonce')).encode()):
        raise ValueError('combo fixed sink stopped-state endpoint did not succeed')


def evaluate(original, scenario, checks, *, allow_fixture=False, expected_inputs=None):
    original=Path(original);value=json.loads(_read(original/'policy-result.json'))
    if value.get('schema')!=SCHEMA or value.get('scenario')!=scenario:raise ValueError('policy schema/scenario mismatch')
    fixture=value.get('fixture') is True
    if fixture and not allow_fixture:raise ValueError('fixture result cannot be used as native credit')
    preliminary=[]
    for item in value.get('pcap') or []:preliminary.extend(_pcap_packets(_safe_file(original,item,'PCAP')))
    if not preliminary and set(checks)!={'route_restore'}:
        why='no usable original packet; interception is unverified'
        try:
            cfg=configparser.ConfigParser();cfg.read(_safe_file(original,value.get('config'),'configuration'))
            if cfg.get('Diverter','ExternalAccessPolicy',fallback='').lower()!='egresscontrol':why+='; configuration disables the selected policy'
        except (OSError,ValueError,configparser.Error):why+='; configuration original unavailable'
        return [{'id':n,'status':'unknown','reason':why} for n in checks],False
    inputs=value.get('inputs')
    if not isinstance(inputs,dict):raise ValueError('result input table is incomplete')
    if expected_inputs is not None and inputs!=expected_inputs:raise ValueError('policy inputs differ from frozen plan')
    config_path=_safe_file(original,value.get('config'),'configuration');log_path=_safe_file(original,value.get('log'),'core log');log=log_path.read_bytes()
    try:
        parser=_validate_config(original,scenario,dict(inputs,_config=value['config']),checks);config_ok=True
    except (ValueError,KeyError,configparser.Error):parser=None;config_ok=False
    packets=[]
    for item in value.get('pcap') or []:packets.extend(_pcap_packets(_safe_file(original,item,'PCAP')))
    attempts={}
    for a in value.get('attempts') or []:
        if not isinstance(a,dict) or not isinstance(a.get('id'),str) or a['id'] in attempts:raise ValueError('invalid/duplicate attempt')
        attempts[a['id']]=a
    controls={a['id']:a for a in value.get('controls') or []}
    observed=value.get('observations') or {};clean=False
    try:
        before=_load_json(original,observed.get('network-before'),'before network observation')
        after=_load_json(original,observed.get('network-after'),'after network observation')
        life=_load_json(original,observed.get('core-lifecycle'),'core lifecycle')
        clean=(bool(before) and before==after and life.get('exited') is True and life.get('returncode')==0 and life.get('timed_out') is False and life.get('forced',False) is False and life.get('source')=='owned-child')
        if not fixture:clean=clean and not before.get('memory_fixture') and not after.get('memory_fixture') and type(life.get('pid')) is int and life['pid']>0 and bool(life.get('birth'))
    except (OSError,ValueError,TypeError):clean=False
    combo_context = None
    if scenario == 'combo':
        try:
            combo_context = _combo_context(original, value, fixture, checks)
        except (OSError, ValueError, KeyError, TypeError) as error:
            return [{'id': name, 'status': 'fail', 'reason': str(error)} for name in checks], False
    rows=[];seen=set()
    for row in value.get('checks') or []:
        name=row.get('id');status=row.get('status');reason=''
        if name in seen:rows.append({'id':name,'status':'fail','reason':'duplicate check'});continue
        seen.add(name)
        if name not in checks:rows.append({'id':name,'status':'fail','reason':'unexpected check'});continue
        if status in ('fail','blocked','not_run','skip','observed'):
            rows.append({'id':name,'status':status,'reason':row.get('reason','producer failure/not run')});continue
        result='unknown'
        try:
            if not config_ok:raise ValueError('invalid configuration content')
            if name=='route_restore':
                if not clean:raise ValueError('independent network/core cleanup missing')
                result='pass'
            elif name in ('icmp_denied','ipv6_denied'):
                a=attempts.get(name)
                if not a:raise ValueError('echo attempt missing')
                trace=_load_json(original,a.get('probe'),'echo original');flow=a['tuple']
                if trace.get('id')!=name or trace.get('nonce')!=a.get('nonce') or trace.get('target')!=flow['dst'] or trace.get('sent') is not True:raise ValueError('echo original identity differs')
                if trace.get('returncode')==0:raise ValueError('forbidden echo succeeded')
                raw=[p for p in packets if float(trace['started_at'])<=p['time']<=float(trace['ended_at']) and p['proto']==flow['proto']]
                out=[p for p in raw if p['src']==flow['src'] and p['dst']==flow['dst'] and p['payload'] and p['payload'][0] in (8,128)]
                replies=[p for p in raw if p['src']==flow['dst'] and p['dst']==flow['src'] and p['payload'] and p['payload'][0] in (0,129)]
                control=controls.get(name)
                if replies:raise ValueError('forbidden echo reply captured')
                if len(out)!=1:reason='unique outgoing echo original missing'
                elif not control:reason='stopped echo positive control missing'
                else:
                    c=_load_json(original,control.get('probe'),'echo control');lo,hi=trace.get('log_range',[0,0]);decision=log[lo:hi].decode('utf-8','replace')
                    if c.get('target')==flow['dst'] and c.get('returncode')==0 and c.get('stdout_hex') and 'DROP_EXTERNAL' in decision and ('original_ip='+flow['dst']) in decision:result='pass'
                    else:reason='echo control/current denial not observed'
            else:
                a=attempts.get(name)
                if not a:raise ValueError('attempt missing')
                trace=_load_json(original,a.get('probe'),'probe original')
                if trace.get('id')!=name or trace.get('nonce')!=a.get('nonce') or trace.get('tuple')!=a.get('tuple') or row.get('tuple')!=a.get('tuple') or row.get('nonce')!=a.get('nonce'):
                    raise ValueError('probe/attempt/check identity differs')
                if trace.get('sent') is not True:raise ValueError('probe was not sent')
                start,end=float(trace['started_at']),float(trace['ended_at'])
                if combo_context is not None:
                    _combo_trace_binding(trace, combo_context)
                    if trace.get('nonce') != combo_context['run_id'] + '-' + name:
                        raise ValueError('probe nonce differs from the single combo run')
                if end<start or a.get('started_at')!=start or a.get('ended_at')!=end:raise ValueError('probe time window differs')
                flow=trace['tuple'];matched=_matching(packets,flow,start,end)
                outgoing=[p for p in matched if p['direction']=='out'];incoming=[p for p in matched if p['direction']=='in']
                expected={
                    'reviewed_ip_tls':('TCP',inputs['reviewed_ip'],inputs['reviewed_port']),
                    'port_80_denied':('TCP',inputs['reviewed_ip'],inputs['denied_http_port']),
                    'port_444_denied':('TCP',inputs['reviewed_ip'],inputs['denied_alt_port']),
                    'udp443_denied':('UDP',inputs['reviewed_ip'],inputs['denied_udp_port']),
                    'other_ip_denied':('TCP',inputs['other_ip'],inputs['other_port']),
                    'sink_tcp':('TCP',inputs['sink_ip'],inputs['sink_port']),
                    'sink_udp':('UDP',inputs['sink_ip'],inputs['sink_port']),
                    'adjacent_denied':('UDP',inputs['adjacent_ip'],inputs['adjacent_port'])}
                if name in DNS_CHECKS:expected[name]=('UDP',inputs['dns_address'],inputs['dns_port'])
                if name in expected and (flow['proto'],flow['dst'],flow['port'])!=expected[name]:raise ValueError('probe destination/protocol differs from frozen input')
                if flow['src']!=inputs['local_source']:raise ValueError('probe source differs from selected guest')
                request=bytes.fromhex(trace['request_hex']);response=bytes.fromhex(trace['response_hex'])
                if not outgoing:raise Unobservable('no original outgoing packet in exact flow')
                if name in DNS_CHECKS:
                    domain={'exact_domain':inputs['allowed_domain'],'wildcard_domain':'www.'+inputs['wildcard_domain'][2:],'apex_denied':inputs['apex_domain'],'default_deny':inputs['denied_domain']}[name]
                    if not any(p['payload']==request for p in outgoing) or not any(p['payload']==response for p in incoming):raise ValueError('DNS wire bytes/directions differ')
                    rcode,answers=_dns_content(request,response,domain)
                    if name in ('exact_domain','wildcard_domain'):
                        if rcode!=0 or not answers or ('DNS_LEASE_ADD domain='+domain+' ').encode() not in log:raise ValueError('allowed DNS response/lease missing')
                    else:
                        fake_answers=[parser.get(s,'ResponseA',fallback='') for s in parser.sections() if parser.get(s,'Listener',fallback='')=='DNSListener']
                        if answers and (not fake_answers or set(answers)!=set(fake_answers)):raise ValueError('denied DNS resolved outside configured fake listener')
                        if ("Received A request for domain '%s"%domain).encode() not in log:raise ValueError('current DNS decision not observed')
                    result='pass'
                else:
                    nonce=a['nonce'];expected_request=('FNPR/1|%s|target\n'%nonce).encode();expected_response=('FNPR/1|%s|OK\n'%nonce).encode()
                    if request!=expected_request:raise ValueError('request protocol/nonce differs')
                    positive=name in APPLICATION_CHECKS
                    if name in ('tls_application','reviewed_ip_tls') and trace.get('tls') is not True:raise ValueError('selected TLS check did not establish TLS')
                    if name=='tls_application':
                        resolution=_load_json(original,trace.get('resolution'),'TLS DNS prerequisite');_,addresses=_dns_content(bytes.fromhex(resolution['request_hex']),bytes.fromhex(resolution['response_hex']),inputs['allowed_domain'])
                        if flow['dst'] not in addresses:raise ValueError('TLS destination differs from original DNS prerequisite')
                        if combo_context is not None:
                            consumed = _combo_dns(original, trace.get('resolution'), inputs['allowed_domain'],
                                                  combo_context, inputs, packets, start)
                            if flow['dst'] not in consumed:
                                raise ValueError('combo application did not consume its actual DNS answer')
                    if scenario=='combo' and name in ('sink_tcp','sink_udp'):
                        addresses = _combo_dns(original, trace.get('dns_resolution'), inputs['denied_domain'],
                                               combo_context, inputs, packets, start)
                        _combo_sink_control(original, controls.get(name), flow, combo_context)
                        if addresses!=[inputs['sink_ip']] or flow['dst']!=inputs['sink_ip']:
                            raise ValueError('sink was not consumed from denied-domain DNS answer')
                    if not trace.get('tls') or fixture:
                        if not request in _stream(outgoing):raise ValueError('request nonce absent from original packets')
                    elif not any(p['payload'] for p in outgoing):raise ValueError('TLS original outgoing content missing')
                    if positive:
                        if response!=expected_response:raise ValueError('application original response nonce/content differs')
                        if not incoming or not any(p['payload'] for p in incoming):raise ValueError('original reverse flow content missing')
                        if (not trace.get('tls') or fixture) and not response in _stream(incoming):raise ValueError('reverse application nonce/content absent')
                        if trace.get('tls') and not fixture:
                            from cryptography import x509
                            from cryptography.x509.oid import ExtensionOID
                            cert=x509.load_der_x509_certificate(bytes.fromhex(trace['tls_peer_der']))
                            names=cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
                            ssl=__import__('ssl');ssl.match_hostname({'subjectAltName':[('DNS',n) for n in names]},inputs['allowed_domain'])
                            want=inputs.get('tls_peer_sha256')
                            if want and hashlib.sha256(bytes.fromhex(trace['tls_peer_der'])).hexdigest()!=want:raise ValueError('TLS peer differs from frozen identity')
                        result='pass'
                    else:
                        # An actual success wins over an unrelated deny log.
                        if response==expected_response or expected_response in _stream(incoming):raise ValueError('forbidden endpoint returned a successful response')
                        if not _decision(log,trace):reason='current exact denial decision missing'
                        else:
                            control=controls.get(name)
                            if not control:reason='stopped-state reachable endpoint control missing'
                            else:
                                observed_control=_load_json(original,control.get('probe'),'endpoint control')
                                cflow=observed_control.get('tuple') or {};ct=observed_control.get('nonce')
                                if (cflow.get('dst'),cflow.get('port'),cflow.get('proto'))!=(flow['dst'],flow['port'],flow['proto']) or bytes.fromhex(observed_control.get('response_hex',''))!=('FNPR/1|%s|OK\n'%ct).encode():reason='endpoint control did not succeed'
                                else:result='pass'
        except Unobservable as error:
            result='unknown';reason=str(error)
        except (ValueError,KeyError,TypeError,OSError,struct.error) as error:
            result='fail';reason=str(error)
        rows.append({'id':name,'status':result,'reason':reason})
    for name in checks:
        if name not in seen:rows.append({'id':name,'status':'not_run'})
    return rows,bool(clean and config_ok and all(r['status']=='pass' for r in rows))


def verify_host_services(original, directory, checks, inputs):
    original=Path(original);directory=Path(directory)
    life=json.loads(_read(directory/'lifecycle.json'));ready=json.loads(_read(directory/'ready.json'))
    if not life.get('stopped') or not ready.get('ready') or life.get('id')!=ready.get('id') or life.get('birth')!=ready.get('birth') or not life.get('birth'):
        raise ValueError('owned endpoint lifetime/identity not established')
    if life.get('bind_ipv4')!=inputs['sink_ip'] or life.get('port')!=inputs['sink_port'] or life.get('allowed_peer_ipv4')!=inputs['local_source']:
        raise ValueError('owned endpoint binding differs from selected input')
    events=[json.loads(line) for line in _read(directory/'events.jsonl').splitlines() if line]
    result=json.loads(_read(original/'policy-result.json'))
    for name in {'sink_tcp','sink_udp'}&set(checks):
        a=next(a for a in result['attempts'] if a['id']==name);trace=_load_json(original,a['probe'],'sink probe')
        matches=[e for e in events if e.get('owner')==life['id'] and e.get('nonce')==a['nonce']]
        if len(matches)!=1:raise ValueError('missing/ambiguous independent sink exchange')
        e=matches[0];flow=trace['tuple']
        if (e.get('transport'),e.get('peer_ip'),e.get('peer_port'))!=(flow['proto'],flow['src'],flow['sport']) or e.get('request_hex')!=trace['request_hex'] or e.get('response_hex')!=trace['response_hex']:
            raise ValueError('independent sink stream bytes/identity differ')
        # Host and guest clocks need not have the same epoch. Each must lie
        # within its own observed lifecycle; cross-host correlation uses nonce.
        if not life['started_at']<=e['time']<=life['ended_at']:raise ValueError('sink exchange outside owned lifetime')
    return True


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
