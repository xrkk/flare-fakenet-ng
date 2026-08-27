#!/usr/bin/env python3
"""Compare NIC pktmon, FakeNet raw PCAP, and HTML payload facts offline."""

import argparse
import base64
import configparser
import hashlib
import ipaddress
import json
import math
import os
import re
import struct
import sys

SCHEMA = 'fakenet.payload-verification.v1'
TCP_SEQUENCE_MODULUS = 1 << 32
TCP_SEQUENCE_HALF = 1 << 31


class VerificationFailure(ValueError):
    """A failed verdict whose structured comparison evidence is available."""

    def __init__(self, message, result=None):
        super().__init__(message)
        self.result = result


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _read(path):
    with open(path, 'rb') as stream:
        return stream.read()


def _html_model(path):
    text = _read(path).decode('utf-8')
    match = re.search(
        r'<script\b[^>]*\bid=["\']payload-data["\'][^>]*>(.*?)</script\s*>',
        text, re.I | re.S)
    if match is None:
        raise ValueError('HTML payload-data model missing')
    model = json.loads(match.group(1).strip())
    if model.get('schema') != 'fakenet.payload-report.v1':
        raise ValueError('unexpected HTML payload schema')
    if not (model.get('capture') or {}).get('overall_health'):
        raise ValueError('HTML capture is not healthy')
    return model


def _pcapng_packets(data):
    """Yield packet bytes from pcapng Enhanced/Simple Packet Blocks."""
    if len(data) < 12 or data[:4] != b'\x0a\x0d\x0d\x0a':
        raise ValueError('wire input is not a pcapng file')
    packets = []
    offset = 0
    endian = '<'
    while offset + 12 <= len(data):
        block_type = struct.unpack_from(endian + 'I', data, offset)[0]
        block_length = struct.unpack_from(endian + 'I', data, offset + 4)[0]
        if block_length < 12 or offset + block_length > len(data):
            raise ValueError('truncated pcapng block')
        block = data[offset:offset + block_length]
        if block_type == 0x0A0D0D0A:
            if block[8:12] == b'\x4d\x3c\x2b\x1a':
                endian = '<'
            elif block[8:12] == b'\x1a\x2b\x3c\x4d':
                endian = '>'
        elif block_type == 0x00000006 and len(block) >= 32:
            captured = struct.unpack_from(endian + 'I', block, 20)[0]
            start = 28
            packets.append(bytes(block[start:start + captured]))
        elif block_type == 0x00000003 and len(block) >= 16:
            captured = struct.unpack_from(endian + 'I', block, 8)[0]
            packets.append(bytes(block[12:12 + captured]))
        offset += block_length
    return packets


def _normalize_tcp_segments(segments):
    """Unwrap 32-bit TCP sequence fields for independent verification."""
    if not segments:
        return []
    first = min(segments, key=lambda item: int(item.get('ordinal', 0)))
    reference = int(first['start']) % TCP_SEQUENCE_MODULUS
    normalized = []
    for original in segments:
        item = dict(original)
        raw = int(original['start']) % TCP_SEQUENCE_MODULUS
        delta = ((raw - reference + TCP_SEQUENCE_HALF) %
                 TCP_SEQUENCE_MODULUS) - TCP_SEQUENCE_HALF
        item['start'] = reference + delta
        normalized.append(item)
    return normalized


def _assemble_tcp(segments):
    segments = _normalize_tcp_segments(segments)
    ordered = sorted((item for item in segments if item['payload']),
                     key=lambda item: (item['start'], item['ordinal']))
    if not ordered:
        return b''
    output = bytearray()
    base = ordered[0]['start']
    cursor = base
    for segment in ordered:
        start = int(segment['start'])
        payload = bytes(segment['payload'])
        if start > cursor:
            raise ValueError('TCP sequence gap in independent capture')
        overlap = cursor - start
        if overlap < len(payload):
            existing = bytes(output[start - base:start - base + overlap])
            if existing != payload[:overlap]:
                raise ValueError('TCP conflicting overlap in independent capture')
            output.extend(payload[overlap:])
            cursor = start + len(payload)
        else:
            existing = bytes(output[start - base:start - base + len(payload)])
            if existing != payload:
                raise ValueError('TCP conflicting retransmission in independent capture')
    return bytes(output)


def _ethernet_payload(frame):
    if not frame:
        raise ValueError('empty wire frame')
    if (frame[0] >> 4) in (4, 6):
        return frame
    if len(frame) < 14:
        raise ValueError('truncated Ethernet frame')
    ether_type = struct.unpack_from('!H', frame, 12)[0]
    offset = 14
    while ether_type in (0x8100, 0x88A8, 0x9100):
        if len(frame) < offset + 4:
            raise ValueError('truncated VLAN frame')
        ether_type = struct.unpack_from('!H', frame, offset + 2)[0]
        offset += 4
    if ether_type not in (0x0800, 0x86DD):
        raise ValueError('unsupported Ethernet type 0x%04x' % ether_type)
    return frame[offset:]


def _packet_parts(raw):
    """Parse the TCP/UDP facts needed by the verifier using only stdlib."""
    raw = _ethernet_payload(bytes(raw))
    version = raw[0] >> 4
    if version == 4:
        if len(raw) < 20:
            raise ValueError('truncated IPv4 header')
        header_length = (raw[0] & 0x0F) * 4
        total_length = struct.unpack_from('!H', raw, 2)[0]
        if header_length < 20 or total_length < header_length or total_length > len(raw):
            raise ValueError('truncated IPv4 packet')
        ip_end = total_length
        protocol = raw[9]
        source = str(ipaddress.ip_address(raw[12:16]))
        destination = str(ipaddress.ip_address(raw[16:20]))
        transport_offset = header_length
    elif version == 6:
        if len(raw) < 40:
            raise ValueError('truncated IPv6 header')
        payload_length = struct.unpack_from('!H', raw, 4)[0]
        ip_end = 40 + payload_length
        if ip_end > len(raw):
            raise ValueError('truncated IPv6 packet')
        protocol = raw[6]
        source = str(ipaddress.ip_address(raw[8:24]))
        destination = str(ipaddress.ip_address(raw[24:40]))
        transport_offset = 40
    else:
        raise ValueError('unsupported IP version %d' % version)
    if protocol not in (6, 17):
        return {
            'version': version, 'protocol': 'OTHER', 'src': source,
            'dst': destination, 'sport': None, 'dport': None,
            'seq': None, 'flags': 0, 'payload': b'',
        }
    if protocol == 6:
        if ip_end < transport_offset + 20:
            raise ValueError('truncated TCP header')
        sport, dport = struct.unpack_from('!HH', raw, transport_offset)
        sequence = struct.unpack_from('!I', raw, transport_offset + 4)[0]
        header_length = (raw[transport_offset + 12] >> 4) * 4
        if header_length < 20 or transport_offset + header_length > ip_end:
            raise ValueError('truncated TCP header')
        return {
            'version': version, 'protocol': 'TCP', 'src': source,
            'dst': destination, 'sport': sport, 'dport': dport,
            'seq': sequence, 'flags': raw[transport_offset + 13],
            'payload': raw[transport_offset + header_length:ip_end],
        }
    if ip_end < transport_offset + 8:
        raise ValueError('truncated UDP header')
    sport, dport, length = struct.unpack_from('!HHH', raw, transport_offset)
    if length < 8 or transport_offset + length > ip_end:
        raise ValueError('truncated UDP packet')
    return {
        'version': version, 'protocol': 'UDP', 'src': source,
        'dst': destination, 'sport': sport, 'dport': dport,
        'seq': None, 'flags': 0,
        'payload': raw[transport_offset + 8:transport_offset + length],
    }


def _read_pcap(path):
    data = _read(path)
    if len(data) < 24:
        raise ValueError('raw input is not a complete pcap file')
    magic = data[:4]
    formats = {
        b'\xd4\xc3\xb2\xa1': '<', b'\xa1\xb2\xc3\xd4': '>',
        b'M<\xb2\xa1': '<', b'\xa1\xb2<M': '>',
    }
    endian = formats.get(magic)
    if endian is None:
        raise ValueError('raw input has an unsupported pcap magic')
    linktype = struct.unpack_from(endian + 'I', data, 20)[0]
    records = []
    offset = 24
    ordinal = 0
    while offset + 16 <= len(data):
        _seconds, _subseconds, captured, original = struct.unpack_from(
            endian + 'IIII', data, offset)
        del original
        offset += 16
        if offset + captured > len(data):
            raise ValueError('truncated raw pcap record')
        ordinal += 1
        records.append((ordinal, bytes(data[offset:offset + captured])))
        offset += captured
    if offset != len(data):
        raise ValueError('trailing bytes in raw pcap')
    if linktype not in (12, 101):
        raise ValueError('raw pcap linktype is not raw IP: %d' % linktype)
    return records


def _wire_records(path):
    data = _read(path)
    frames = _pcapng_packets(data)
    records = []
    for ordinal, frame in enumerate(frames, 1):
        try:
            facts = _packet_parts(frame)
        except Exception:
            continue
        if facts['protocol'] in ('TCP', 'UDP'):
            facts['ordinal'] = ordinal
            records.append(facts)
    return records


def _raw_records(path):
    records = []
    for ordinal, packet in _read_pcap(path):
        try:
            facts = _packet_parts(packet)
        except Exception:
            raise ValueError('unable to parse raw pcap record %d' % ordinal)
        if facts['protocol'] in ('TCP', 'UDP'):
            facts['ordinal'] = ordinal
            records.append(facts)
    return records


def _key(facts):
    left = (facts['src'], facts['sport'])
    right = (facts['dst'], facts['dport'])
    return facts['protocol'], facts['version'], min(left, right), max(left, right)


def _wire_payload(records):
    groups = {}
    for facts in records:
        direction_key = (facts['src'], facts['sport'], facts['dst'], facts['dport'])
        group = groups.setdefault((_key(facts), direction_key), [])
        group.append(facts)
    result = {}
    for (flow_key, direction_key), facts_list in groups.items():
        if facts_list[0]['protocol'] == 'TCP':
            segments = []
            for facts in facts_list:
                segments.append({
                    'start': facts['seq'] + (1 if facts['flags'] & 2 else 0),
                    'payload': facts['payload'],
                    'fin': bool(facts['flags'] & 1),
                    'ordinal': facts['ordinal'],
                })
            payload = _assemble_tcp(segments)
        else:
            payload = b''.join(facts['payload'] for facts in facts_list)
        result[(flow_key, direction_key)] = payload
    return result


def _capture_payload(records):
    return _wire_payload(records)


def _input_facts(raw_pcap, wire_pcapng, html, log, ini):
    return {name: {'path': os.path.abspath(path),
                   'sha256': _sha256(_read(path))}
            for name, path in (('raw_pcap', raw_pcap),
                               ('wire_pcapng', wire_pcapng),
                               ('html', html), ('log', log), ('ini', ini))}


def verify(raw_pcap, wire_pcapng, html, log, ini,
           capture_started_at=None):
    model = _html_model(html)
    records = _wire_records(wire_pcapng)
    wire = _wire_payload(records)
    raw = _capture_payload(_raw_records(raw_pcap))
    log_text = _read(log).decode('utf-8', errors='replace')
    all_allowed = [flow for flow in model.get('flows', [])
                   if flow.get('disposition') == 'ALLOW_TAKEOVER_SINK']
    if not all_allowed:
        raise ValueError('no ALLOW_TAKEOVER_SINK flow in HTML model')

    excluded = []
    if capture_started_at is None:
        allowed = all_allowed
        capture_window = {
            'mode': 'whole-session',
            'started_at_epoch': None,
            'selected_flow_ids': [flow.get('id') for flow in allowed],
            'excluded_flows': excluded,
        }
    else:
        capture_started_at = float(capture_started_at)
        if not math.isfinite(capture_started_at) or capture_started_at < 0:
            raise ValueError('capture start epoch is invalid')
        allowed = []
        for flow in all_allowed:
            try:
                started_at = float(flow['started_at'])
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(
                    'ALLOW_TAKEOVER_SINK flow start time is missing') from exc
            if not math.isfinite(started_at):
                raise ValueError(
                    'ALLOW_TAKEOVER_SINK flow start time is invalid')
            if started_at < capture_started_at:
                excluded.append({
                    'flow_id': flow.get('id'),
                    'started_at': started_at,
                    'reason': 'started_before_sample_capture_window',
                })
            else:
                allowed.append(flow)
        capture_window = {
            'mode': 'runner-action-window',
            'started_at_epoch': capture_started_at,
            'selected_flow_ids': [flow.get('id') for flow in allowed],
            'excluded_flows': excluded,
        }
        if not allowed:
            raise ValueError(
                'no ALLOW_TAKEOVER_SINK flow started in the sample capture window')

    for flow in allowed:
        if (flow.get('owner') in (None, '', 'unknown') or
                flow.get('process') in (None, '', 'unknown') or
                flow.get('pid') is None):
            raise ValueError(
                'ALLOW_TAKEOVER_SINK flow is not bound to the sample process')
    comparisons = []
    for flow in allowed:
        flow_key = (flow['protocol'], int(flow['ip_version']),
                    min((flow['source']['ip'], flow['source']['port']),
                        (flow['destination']['ip'], flow['destination']['port'])),
                    max((flow['source']['ip'], flow['source']['port']),
                        (flow['destination']['ip'], flow['destination']['port'])))
        for direction in (flow.get('directions') or {}).values():
            source = direction['source']
            destination = direction['destination']
            direction_key = (source['ip'], source['port'],
                             destination['ip'], destination['port'])
            try:
                html_bytes = base64.b64decode(
                    direction.get('base64', '').encode('ascii'), validate=True)
            except Exception as exc:
                raise ValueError('invalid HTML payload Base64') from exc
            if (len(html_bytes) != int(direction.get('bytes', -1)) or
                    _sha256(html_bytes) != direction.get('sha256')):
                raise ValueError('HTML payload length/hash is self-inconsistent')
            wire_bytes = wire.get((flow_key, direction_key), b'')
            raw_bytes = raw.get((flow_key, direction_key), b'')
            comparisons.append({
                'flow_id': flow['id'], 'direction_id': direction['id'],
                'direction': direction.get('direction', 'unknown'),
                'owner': flow.get('owner'), 'pid': flow.get('pid'),
                'process': flow.get('process'),
                'disposition': flow.get('disposition'),
                'domain': flow.get('domain', 'unknown'),
                'wire_bytes': len(wire_bytes), 'raw_bytes': len(raw_bytes),
                'fakenet_bytes': len(html_bytes),
                'wire_sha256': _sha256(wire_bytes),
                'raw_sha256': _sha256(raw_bytes),
                'fakenet_sha256': _sha256(html_bytes),
                'wire_match': wire_bytes == html_bytes,
                'raw_match': raw_bytes == html_bytes,
                'match': wire_bytes == html_bytes and raw_bytes == html_bytes,
            })
    fatal_markers = (
        'PCAP_DUAL_WRITE_FAILED', 'HTML_REPORT_SUPPRESSED',
        'overall_health=false', 'Traceback (most recent call last):',
        'FakeNet-NG terminated with an error',
    )
    capture_fatal = any(marker in log_text for marker in fatal_markers)
    if not os.path.isfile(ini):
        raise ValueError('actual INI evidence is missing')
    parser = configparser.ConfigParser(interpolation=None)
    try:
        with open(ini, 'r', encoding='utf-8-sig') as stream:
            parser.read_file(stream)
        dump_packets = parser.getboolean('Diverter', 'DumpPackets')
    except Exception as exc:
        raise ValueError('actual INI DumpPackets setting is unreadable') from exc

    result = {
        'schema': SCHEMA,
        'inputs': _input_facts(raw_pcap, wire_pcapng, html, log, ini),
        'capture_window': capture_window,
        'comparisons': comparisons,
        'gap_conflict': False, 'capture_fatal': capture_fatal,
        'process_binding': {'verdict': 'PENDING'},
        'dump_packets': dump_packets,
        'verdict': 'FAIL',
    }

    def reject(message, mismatches=None):
        result['error'] = message
        if mismatches is not None:
            result['mismatches'] = mismatches
        raise VerificationFailure(message, result)

    if 'ALLOW_TAKEOVER_SINK' not in log_text:
        reject('ALLOW_TAKEOVER_SINK evidence is absent from log')
    if capture_fatal:
        reject('capture/core fatal marker is present in log')
    if not dump_packets:
        reject('actual INI does not enable DumpPackets')
    mismatches = [item for item in comparisons if not item['match']]
    if not comparisons or mismatches:
        reject('wire/raw/FakeNet/HTML payload mismatch', mismatches)

    comparisons_by_flow = {}
    for item in comparisons:
        comparisons_by_flow.setdefault(item['flow_id'], []).append(item)
    bidirectional = []
    for flow in allowed:
        items = comparisons_by_flow.get(flow['id'], [])
        has_outbound = any(
            item['direction'] == 'outbound' and item['fakenet_bytes'] > 0
            for item in items)
        has_inbound = any(
            item['direction'] == 'inbound' and item['fakenet_bytes'] > 0
            for item in items)
        if has_outbound and has_inbound:
            bidirectional.append(flow)
    if not bidirectional:
        reject('no single sample flow has non-empty outbound and inbound payload')
    bindings = {(flow.get('pid'), flow.get('process'), flow.get('owner'))
                for flow in bidirectional}
    if len(bindings) != 1:
        reject('sample process binding is not unique')
    pid, process, owner = next(iter(bindings))
    result['process_binding'] = {
        'verdict': 'PASS', 'pid': pid, 'process': process, 'owner': owner,
        'flow_ids': [flow['id'] for flow in bidirectional],
    }
    result['verdict'] = 'PASS'
    return result


def main(argv=None):
    parser = argparse.ArgumentParser()
    for name in ('raw-pcap', 'wire-pcapng', 'html', 'log', 'ini'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--capture-started-at', type=float)
    parser.add_argument('--output', required=True)
    args = parser.parse_args(argv)
    try:
        result = verify(args.raw_pcap, args.wire_pcapng, args.html,
                        args.log, args.ini, args.capture_started_at)
        code = 0
    except VerificationFailure as exc:
        result = exc.result or {
            'schema': SCHEMA, 'verdict': 'FAIL', 'error': str(exc)}
        code = 1
    except Exception as exc:
        result = {'schema': SCHEMA, 'verdict': 'FAIL', 'error': str(exc)}
        code = 1
    with open(args.output, 'w', encoding='utf-8', newline='\n') as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    print(json.dumps(result, ensure_ascii=False))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
