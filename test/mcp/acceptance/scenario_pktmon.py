# Copyright 2026 Google LLC
"""Decode pktmon facts; NIC identity must come from the current VM capture.

This module does not infer a NIC from a component number or a MAC.  Callers
must bind component_ids to the native pktmon component/adapter inventory and
verify capture completeness before using an empty selection as absence proof.
"""
import ipaddress
import re


class PacketEvidenceError(ValueError):
    pass


ENDPOINT = r'(?:[0-9]{1,3}\.){4}[0-9]+'
TUPLE = re.compile(r'(?<![\w.])(' + ENDPOINT + r') > (' + ENDPOINT + r'):')


def _endpoint(value):
    address, port = value.rsplit('.', 1)
    ipaddress.IPv4Address(address)
    port = int(port)
    if not 0 <= port <= 65535:
        raise PacketEvidenceError('packet port outside range')
    return '%s:%s' % (address, port)


def parse_packets(raw):
    """Return byte-addressed IPv4 TCP/UDP observations, retaining uncertainty.

    Unknown transport or component metadata is preserved and rejected by the
    selector if it could describe a requested tuple. Non-IP records are outside
    this adapter. It is not an IPv6, fragment, or arbitrary-protocol oracle.
    """
    if raw.startswith(b'\xff\xfe'):
        codec, offset = 'utf-16-le', 2
    elif raw.startswith(b'\xef\xbb\xbf'):
        codec, offset = 'utf-8', 3
    else:
        codec, offset = 'utf-8', 0
    text = raw[offset:].decode(codec)
    groups, current, begin = [], [], offset
    for line in text.splitlines(keepends=True):
        if line.startswith('['):
            if current:
                groups.append((begin, offset, ''.join(current)))
            begin, current = offset, []
        current.append(line)
        offset += len(line.encode(codec))
    if current:
        groups.append((begin, offset, ''.join(current)))
    packets = []
    for begin, end, block in groups:
        header, _, body = block.partition('\n')
        if '[Microsoft-Windows-PktMon]' not in header or 'IPv4' not in body:
            continue
        tuples = TUPLE.findall(body)
        if not tuples:
            continue
        if len(tuples) != 1:
            raise PacketEvidenceError('multiple transport tuples in one pktmon record')
        source, target = map(_endpoint, tuples[0])
        direction = re.search(r'(?:方向|Direction)\s+(Tx|Rx)\b', header)
        component = re.search(r'(?:组件|Component(?:Id)?)\s+(\d+)\b', header)
        original = re.search(r'OriginalSize\s+(\d+)\b', header)
        logged = re.search(r'LoggedSize\s+(\d+)\b', header)
        timestamp = re.search(r'::(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+)', header)
        transport = 'TCP' if re.search(r'Flags \[[^\]]*\]', body) else (
            'UDP' if re.search(r'\bUDP\b', body) else None)
        packets.append(dict(src=source, dst=target, protocol=transport,
                            direction=direction[1] if direction else None,
                            component=int(component[1]) if component else None,
                            timestamp_local=timestamp[1] if timestamp else None,
                            original_size=int(original[1]) if original else None,
                            logged_size=int(logged[1]) if logged else None,
                            byte_start=begin, byte_end=end))
    return packets


def select_packets(packets, src, dst, protocol, *, component_ids=None, direction=None):
    """Select an exact directional tuple, optionally at verified components.

    Unknown metadata for a potentially matching observation is an error, never
    an empty match. An empty component set cannot prove traffic absence.
    """
    if protocol not in ('TCP', 'UDP') or direction not in (None, 'Tx', 'Rx'):
        raise PacketEvidenceError('unsupported transport/direction')
    if component_ids is not None:
        component_ids = set(component_ids)
        if not component_ids or any(type(x) is not int or x < 0 for x in component_ids):
            raise PacketEvidenceError('current capture component identity required')
    selected = []
    for packet in packets:
        if packet['src'] != src or packet['dst'] != dst:
            continue
        if component_ids is not None:
            if packet['component'] is None:
                raise PacketEvidenceError('matching tuple has unknown capture component')
            if packet['component'] not in component_ids:
                continue
        if direction is not None:
            if packet['direction'] is None:
                raise PacketEvidenceError('matching tuple has unknown direction')
            if packet['direction'] != direction:
                continue
        if packet['protocol'] is None:
            raise PacketEvidenceError('matching tuple has unknown transport')
        if packet['protocol'] != protocol:
            continue
        if (packet['original_size'] is None or packet['logged_size'] is None
                or packet['logged_size'] < packet['original_size']):
            raise PacketEvidenceError('matching tuple capture is incomplete')
        selected.append(packet)
    return selected
