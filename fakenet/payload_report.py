# Copyright 2026 Google LLC
"""Capture-backed payload indexing, reassembly, and report-model helpers.

The packet capture remains the byte authority.  This module only keeps a
small in-memory observation index while packets are written and performs the
potentially expensive reassembly after the writers have been closed.  Keeping
those two operations separate is important: report generation must never
change the paired-PCAP contract or make a packet thread perform disk I/O.
"""

import base64
import binascii
import hashlib
import json
import os
import re
import socket
import threading

import dpkt


PAYLOAD_REPORT_SCHEMA = 'fakenet.payload-report.v1'
PAYLOAD_REPORT_ENCODING = 'base64'
OBSERVATION_ROLES = frozenset(('initial', 'final', 'inbound'))
DIRECTIONS = frozenset(('outbound', 'inbound', 'unknown'))
TCP_SEQUENCE_MODULUS = 1 << 32
TCP_SEQUENCE_HALF = 1 << 31


class PayloadReportError(RuntimeError):
    """A capture cannot be represented as a complete payload report."""


def _sha256(data):
    return hashlib.sha256(bytes(data)).hexdigest()


def _b64(data):
    return base64.b64encode(bytes(data)).decode('ascii')


def _ip_text(value, version):
    try:
        return socket.inet_ntop(socket.AF_INET if version == 4 else
                                socket.AF_INET6, value)
    except (OSError, TypeError, ValueError):
        return binascii.hexlify(bytes(value)).decode('ascii')


def _json_safe(value):
    """Convert listener-owned values to JSON data without executable text."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, bytes):
        return {'encoding': PAYLOAD_REPORT_ENCODING, 'value': _b64(value)}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    return str(value)


def safe_json_dumps(value):
    """Serialize a model for an inert ``application/json`` script element.

    Escaping ``<``/``>``/``&`` is required even when the element is not
    executed: hostile payload bytes and process names must not be able to
    terminate the element and introduce markup.  The browser derives all
    secondary displays from this one JSON/Base64 source.
    """
    encoded = json.dumps(_json_safe(value), ensure_ascii=False,
                         separators=(',', ':'), allow_nan=False)
    return (encoded.replace('&', '\\u0026').replace('<', '\\u003c')
            .replace('>', '\\u003e').replace('\u2028', '\\u2028')
            .replace('\u2029', '\\u2029'))


def validate_rendered_payload_report(html_text, expected_model):
    """Verify the exact inert JSON embedded in a rendered report."""
    matches = re.findall(
        r'<script\b[^>]*\bid=["\']payload-data["\'][^>]*>'
        r'(.*?)</script\s*>', str(html_text), re.I | re.S)
    if len(matches) != 1:
        raise PayloadReportError(
            'rendered report must contain one payload-data JSON element')
    try:
        embedded = json.loads(matches[0].strip())
        expected = json.loads(safe_json_dumps(expected_model))
    except (TypeError, ValueError) as exc:
        raise PayloadReportError(
            'rendered payload-data is not valid JSON: %s' % exc) from exc
    if embedded != expected:
        raise PayloadReportError(
            'rendered payload-data differs from the verified report model')
    capture = embedded.get('capture') or {}
    if capture.get('overall_health'):
        validate_payload_model(embedded)
    elif not (capture.get('overall_health') is False and
              capture.get('marker') == 'capture-disabled' and
              capture.get('coverage_health') is False and
              capture.get('reassembly_health') is False and
              isinstance(embedded.get('nbis'), list)):
        raise PayloadReportError(
            'rendered unhealthy report is not an explicit capture-disabled report')
    return embedded


class CaptureObservationIndex(object):
    """Thread-safe index matching successful writer records to observations."""

    def __init__(self):
        self._lock = threading.Lock()
        self._entries = []
        self._next_logical_packet_id = 1

    def new_logical_packet_id(self, prefix='packet'):
        """Allocate an ID without racing concurrent capture producers."""
        with self._lock:
            logical = '%s-%08d' % (prefix, self._next_logical_packet_id)
            self._next_logical_packet_id += 1
            return logical

    def record(self, raw_bytes, observation_role, logical_packet_id=None,
               flow_id=None, direction='unknown', timestamp=None,
               record_ordinal=None):
        raw_bytes = bytes(raw_bytes)
        role = str(observation_role or '')
        if role not in OBSERVATION_ROLES:
            raise PayloadReportError('unknown observation role %r' % role)
        if not raw_bytes:
            raise PayloadReportError('empty observation cannot be indexed')
        with self._lock:
            expected = len(self._entries) + 1
            ordinal = expected if record_ordinal is None else int(record_ordinal)
            if ordinal != expected:
                raise PayloadReportError(
                    'observation ordinal %d is not expected ordinal %d' %
                    (ordinal, expected))
            entry = {
                'ordinal': ordinal,
                'logical_packet_id': str(logical_packet_id or
                                         'packet-%08d' % ordinal),
                'observation_role': role,
                'direction': str(direction or 'unknown'),
                'length': len(raw_bytes),
                'sha256': _sha256(raw_bytes),
            }
            if flow_id is not None:
                entry['flow_id'] = str(flow_id)
            if timestamp is not None:
                entry['timestamp'] = float(timestamp)
            self._entries.append(entry)
            return dict(entry)

    def snapshot(self):
        with self._lock:
            return [dict(entry) for entry in self._entries]

    def __len__(self):
        with self._lock:
            return len(self._entries)


def _packet_parts(raw_bytes):
    """Return parsed IP/L4 facts used by both flow registration and report."""
    raw_bytes = bytes(raw_bytes)
    if not raw_bytes:
        raise PayloadReportError('empty raw packet')
    version = (raw_bytes[0] & 0xf0) >> 4
    try:
        if version == 4:
            packet = dpkt.ip.IP(raw_bytes)
            protocol = int(packet.p)
            src = _ip_text(packet.src, 4)
            dst = _ip_text(packet.dst, 4)
        elif version == 6:
            packet = dpkt.ip6.IP6(raw_bytes)
            protocol = int(packet.nxt)
            src = _ip_text(packet.src, 6)
            dst = _ip_text(packet.dst, 6)
        else:
            raise PayloadReportError('unsupported IP version %d' % version)
    except PayloadReportError:
        raise
    except Exception as exc:
        raise PayloadReportError('unable to parse IP packet: %s' % exc) from exc

    transport = packet.data
    if protocol == dpkt.ip.IP_PROTO_TCP:
        if not isinstance(transport, dpkt.tcp.TCP):
            try:
                transport = dpkt.tcp.TCP(bytes(transport))
            except Exception as exc:
                raise PayloadReportError('truncated TCP packet: %s' % exc) from exc
        payload = bytes(transport.data or b'')
        return {
            'version': version, 'protocol': 'TCP', 'protocol_number': protocol,
            'src': src, 'dst': dst, 'sport': int(transport.sport),
            'dport': int(transport.dport), 'seq': int(transport.seq),
            'ack': int(transport.ack), 'flags': int(transport.flags),
            'payload': payload,
        }
    if protocol == dpkt.ip.IP_PROTO_UDP:
        if not isinstance(transport, dpkt.udp.UDP):
            try:
                transport = dpkt.udp.UDP(bytes(transport))
            except Exception as exc:
                raise PayloadReportError('truncated UDP packet: %s' % exc) from exc
        return {
            'version': version, 'protocol': 'UDP', 'protocol_number': protocol,
            'src': src, 'dst': dst, 'sport': int(transport.sport),
            'dport': int(transport.dport), 'payload': bytes(transport.data or b''),
            'seq': None, 'ack': None, 'flags': 0,
        }
    return {
        'version': version, 'protocol': 'OTHER', 'protocol_number': protocol,
        'src': src, 'dst': dst, 'sport': None, 'dport': None,
        'payload': b'', 'seq': None, 'ack': None, 'flags': 0,
    }


def _endpoint(facts, source=True):
    prefix = 'src' if source else 'dst'
    return (facts[prefix], facts['sport'] if source else facts['dport'])


def _canonical_key(facts):
    left = _endpoint(facts, True)
    right = _endpoint(facts, False)
    return (facts['protocol'], min(left, right), max(left, right),
            facts['version'])


class SessionFlowRegistry(object):
    """Unbounded-in-session flow ownership and connection-generation registry."""

    def __init__(self):
        self._lock = threading.Lock()
        self._next_id = 1
        self._flows = []
        self._by_key = {}
        self._logical_to_flow = {}

    @staticmethod
    def _new_flow(flow_id, facts, timestamp, direction):
        source = _endpoint(facts, True)
        destination = _endpoint(facts, False)
        endpoint_key = (source[0], source[1], destination[0], destination[1])
        syn_sequences = {}
        if facts['protocol'] == 'TCP' and facts['flags'] & dpkt.tcp.TH_SYN:
            syn_sequences[endpoint_key] = int(facts['seq']) & (
                TCP_SEQUENCE_MODULUS - 1)
        return {
            'id': flow_id,
            'protocol': facts['protocol'],
            'ip_version': facts['version'],
            'source': {'ip': source[0], 'port': source[1]},
            'destination': {'ip': destination[0], 'port': destination[1]},
            'owner': 'unknown', 'pid': None, 'process': 'unknown',
            'disposition': 'unknown', 'domain': 'unknown',
            'started_at': timestamp, 'ended_at': timestamp,
            'closed': False,
            '_directions': {endpoint_key: direction},
            '_syn_sequences': syn_sequences,
            '_logical_ids': set(),
        }

    def _allocate(self, facts, timestamp, direction):
        flow_id = 'flow-%06d' % self._next_id
        self._next_id += 1
        flow = self._new_flow(flow_id, facts, timestamp, direction)
        self._flows.append(flow)
        self._by_key[_canonical_key(facts)] = flow
        return flow

    def observe_packet(self, raw_bytes, direction='unknown', timestamp=None,
                       logical_packet_id=None):
        """Register one observation and return its stable flow ID.

        Parsing failures intentionally return ``None``.  A malformed packet is
        still handled by the paired writer; report generation will later fail
        closed when it reads the sealed PCAP, while tiny synthetic test doubles
        do not make the capture hot path fail for an unrelated registry.
        """
        try:
            facts = _packet_parts(raw_bytes)
        except PayloadReportError:
            return None
        if facts['protocol'] not in ('TCP', 'UDP'):
            return None
        direction = str(direction or 'unknown')
        if direction not in DIRECTIONS:
            direction = 'unknown'
        with self._lock:
            if logical_packet_id is not None:
                known = self._logical_to_flow.get(str(logical_packet_id))
                if known is not None:
                    return known['id']
            key = _canonical_key(facts)
            flow = self._by_key.get(key)
            syn = (bool(facts['flags'] & dpkt.tcp.TH_SYN)
                   if facts['protocol'] == 'TCP' else False)
            source = _endpoint(facts, True)
            destination = _endpoint(facts, False)
            endpoint_key = (source[0], source[1], destination[0], destination[1])
            syn_sequence = (int(facts['seq']) & (TCP_SEQUENCE_MODULUS - 1)
                            if syn else None)
            # A SYN retransmission has the same sequence number and remains in
            # the current generation.  A new SYN on the same directional
            # endpoint with a different ISN is a new connection even when the
            # old generation ended without an observed FIN/RST.  Keep the
            # reverse SYN/SYN-ACK handshake in the same generation by keying
            # this comparison by direction rather than only by four-tuple.
            known_syn = (flow.get('_syn_sequences', {}).get(endpoint_key)
                         if flow is not None else None)
            new_syn_generation = (
                facts['protocol'] == 'TCP' and syn and
                known_syn is not None and syn_sequence != known_syn)
            if (flow is None or
                    (facts['protocol'] == 'TCP' and
                     flow.get('closed') and syn) or
                    new_syn_generation):
                flow = self._allocate(facts, timestamp, direction)
            reverse_key = (destination[0], destination[1], source[0], source[1])
            if endpoint_key not in flow['_directions']:
                if reverse_key in flow['_directions']:
                    flow['_directions'][endpoint_key] = (
                        'inbound' if flow['_directions'][reverse_key] == 'outbound'
                        else 'outbound' if flow['_directions'][reverse_key] == 'inbound'
                        else 'unknown')
                else:
                    flow['_directions'][endpoint_key] = direction
            if syn and endpoint_key not in flow['_syn_sequences']:
                flow['_syn_sequences'][endpoint_key] = syn_sequence
            if timestamp is not None:
                ts = float(timestamp)
                if flow['started_at'] is None or ts < flow['started_at']:
                    flow['started_at'] = ts
                if flow['ended_at'] is None or ts > flow['ended_at']:
                    flow['ended_at'] = ts
            if logical_packet_id is not None:
                logical = str(logical_packet_id)
                flow['_logical_ids'].add(logical)
                self._logical_to_flow[logical] = flow
            if facts['protocol'] == 'TCP' and facts['flags'] & (
                    dpkt.tcp.TH_FIN | dpkt.tcp.TH_RST):
                flow['closed'] = True
            return flow['id']

    def update(self, flow_id, owner=None, pid=None, process=None,
               disposition=None, domain=None):
        if flow_id is None:
            return
        with self._lock:
            flow = next((item for item in self._flows
                         if item['id'] == str(flow_id)), None)
            if flow is None:
                return
            if owner not in (None, ''):
                flow['owner'] = str(owner)
            if pid is not None:
                flow['pid'] = pid
            if process not in (None, ''):
                flow['process'] = str(process)
            if disposition not in (None, ''):
                flow['disposition'] = str(disposition)
            if domain not in (None, ''):
                flow['domain'] = str(domain)

    def direction_for(self, flow_id, source, source_port, destination,
                      destination_port):
        with self._lock:
            flow = next((item for item in self._flows
                         if item['id'] == str(flow_id)), None)
            if flow is None:
                return 'unknown'
            return flow['_directions'].get(
                (source, int(source_port), destination, int(destination_port)),
                'unknown')

    def snapshot(self):
        with self._lock:
            result = []
            for flow in self._flows:
                result.append({
                    key: value for key, value in flow.items()
                    if not key.startswith('_')
                })
            return result


def _read_pcap(path):
    records = []
    try:
        with open(path, 'rb') as stream:
            for ordinal, (timestamp, raw) in enumerate(dpkt.pcap.Reader(stream), 1):
                records.append((ordinal, float(timestamp), bytes(raw)))
    except Exception as exc:
        raise PayloadReportError('unable to read PCAP %s: %s' % (path, exc)) from exc
    return records


def _validate_pair(raw_records, converted_records):
    if converted_records is None:
        return
    if len(raw_records) != len(converted_records):
        raise PayloadReportError(
            'raw/converted record count mismatch: %d/%d' %
            (len(raw_records), len(converted_records)))
    for (raw_ord, raw_ts, raw), (eth_ord, eth_ts, ethernet) in zip(
            raw_records, converted_records):
        if raw_ord != eth_ord:
            raise PayloadReportError('raw/converted ordinal mismatch at %d' % raw_ord)
        try:
            frame = dpkt.ethernet.Ethernet(ethernet)
            converted_raw = bytes(frame.data)
        except Exception as exc:
            raise PayloadReportError(
                'unable to decode converted record %d: %s' % (raw_ord, exc)) from exc
        if not converted_raw or (converted_raw[0] >> 4) not in (4, 6):
            raise PayloadReportError(
                'converted record %d is not an IP packet' % raw_ord)
        if abs(raw_ts - eth_ts) > 0.000001:
            raise PayloadReportError(
                'raw/converted timestamp mismatch at ordinal %d' % raw_ord)


def _validate_index(raw_records, entries):
    if len(raw_records) != len(entries):
        raise PayloadReportError(
            'observation index/PCAP count mismatch: %d/%d' %
            (len(entries), len(raw_records)))
    for (ordinal, timestamp, raw), entry in zip(raw_records, entries):
        if int(entry.get('ordinal', -1)) != ordinal:
            raise PayloadReportError('observation ordinal mismatch at %d' % ordinal)
        if int(entry.get('length', -1)) != len(raw):
            raise PayloadReportError('observation length mismatch at %d' % ordinal)
        if entry.get('sha256') != _sha256(raw):
            raise PayloadReportError('observation hash mismatch at %d' % ordinal)
        if ('timestamp' in entry and
                abs(float(entry['timestamp']) - timestamp) > 0.000001):
            raise PayloadReportError('observation timestamp mismatch at %d' % ordinal)
        if entry.get('observation_role') not in OBSERVATION_ROLES:
            raise PayloadReportError('invalid observation role at %d' % ordinal)


def _choose_observations(raw_records, entries):
    selected = []
    by_logical = {}
    for record, entry in zip(raw_records, entries):
        logical = str(entry['logical_packet_id'])
        previous = by_logical.get(logical)
        if previous is None:
            selected.append((record, entry))
            by_logical[logical] = (record, entry)
            continue
        previous_entry = previous[1]
        prev_role = previous_entry['observation_role']
        role = entry['observation_role']
        if role == prev_role:
            raise PayloadReportError(
                'logical packet %s has duplicate %s observations' %
                (logical, role))
        if {role, prev_role} != {'initial', 'final'}:
            raise PayloadReportError(
                'logical packet %s has incompatible observation roles %s/%s' %
                (logical, prev_role, role))
        # Initial is the authoritative application view.  The final view is
        # retained in the paired PCAP, but must not double-count payload bytes.
        if role == 'initial' and prev_role == 'final':
            index = selected.index(previous)
            selected[index] = (record, entry)
            by_logical[logical] = (record, entry)
    return selected


def _normalize_tcp_segments(segments):
    """Unwrap TCP sequence numbers relative to the first observed segment.

    TCP sequence fields are 32-bit modulo values.  Sorting those values as
    ordinary integers makes a stream crossing ``0xffffffff -> 0`` look like a
    backwards retransmission or a gap.  The capture window is necessarily
    less than 2**31 bytes for an unambiguous relative ordering, so a signed
    modular delta from the first observed segment is sufficient and keeps the
    original ordinal available as the deterministic tie-breaker.
    """
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
    if not segments:
        return b'', None
    segments = _normalize_tcp_segments(segments)
    # ACK/SYN/FIN/RST control packets with no payload must not create a false
    # data gap merely because their sequence number is ahead of the last
    # application byte.  Keep FIN positions separately so a FIN after an
    # observed data hole still rejects the report.
    fin_positions = [int(item['start']) + len(bytes(item['payload']))
                     for item in segments if item.get('fin')]
    ordered = sorted(
        (item for item in segments if bytes(item['payload'])),
        key=lambda item: (item['start'], item['ordinal']))
    if not ordered:
        return b'', None
    output = bytearray()
    cursor = None
    base_start = None
    for segment in ordered:
        start = int(segment['start'])
        payload = bytes(segment['payload'])
        end = start + len(payload)
        if cursor is None:
            base_start = start
            cursor = start
            output.extend(payload)
            cursor = end
            continue
        if start > cursor:
            raise PayloadReportError(
                'TCP internal sequence gap between %d and %d' % (cursor, start))
        overlap = cursor - start
        if overlap < len(payload):
            existing = bytes(output[start - base_start:
                                   start - base_start + overlap])
            if existing != payload[:overlap]:
                raise PayloadReportError(
                    'TCP conflicting overlap at sequence %d' % start)
            output.extend(payload[overlap:])
            cursor = end
        elif payload:
            existing = bytes(output[start - base_start:
                                   start - base_start + len(payload)])
            if existing != payload:
                raise PayloadReportError(
                    'TCP conflicting retransmission at sequence %d' % start)
    # A FIN exactly at the next contiguous position is complete; only a FIN
    # beyond the cursor denotes a missing payload range.  With no observed
    # payload, there is no internal range we can prove missing.
    if any(position > cursor for position in fin_positions):
        raise PayloadReportError(
            'TCP terminal sequence gap after %d before %d' %
            (cursor, min(position for position in fin_positions
                          if position > cursor)))
    return bytes(output), cursor


def _serialize_nbis(nbis, registry=None):
    result = []
    registered_flows = registry.snapshot() if registry is not None else []

    def associated_flow(entry):
        if not isinstance(entry, dict):
            return None
        protocol = str(entry.get('transport_layer_proto', '')).upper()
        sport = entry.get('sport')
        destination_ip = str(entry.get('dst_ip', ''))
        destination_port = entry.get('dport')
        try:
            sport = int(sport)
            destination_port = int(destination_port)
        except (TypeError, ValueError):
            return None
        for flow in registered_flows:
            if flow.get('protocol') != protocol:
                continue
            source = flow.get('source') or {}
            destination = flow.get('destination') or {}
            if ((source.get('port') == sport and
                 destination.get('ip') == destination_ip and
                 destination.get('port') == destination_port) or
                    (destination.get('port') == sport and
                     source.get('ip') == destination_ip and
                     source.get('port') == destination_port)):
                return flow.get('id')
        return None

    for process_key, values in (nbis or {}).items():
        if isinstance(process_key, (tuple, list)):
            pid = process_key[0] if process_key else None
            process = process_key[1] if len(process_key) > 1 else 'unknown'
        else:
            pid = None
            process = str(process_key)
        item = {'pid': pid, 'process': process, 'protocols': []}
        for protocol, entries in (values or {}).items():
            serialized_entries = []
            for entry in entries or []:
                serialized = _json_safe(entry)
                if isinstance(serialized, dict):
                    flow_id = associated_flow(entry)
                    serialized['flow_id'] = flow_id or 'unknown'
                serialized_entries.append(serialized)
            item['protocols'].append({
                'protocol': str(protocol),
                'entries': serialized_entries,
            })
        result.append(item)
    return result


def _flow_model(registry_flow, flow_id, facts, timestamp):
    if registry_flow is None:
        return {
            'id': str(flow_id), 'protocol': facts['protocol'],
            'ip_version': facts['version'], 'source': {
                'ip': facts['src'], 'port': facts['sport']},
            'destination': {'ip': facts['dst'], 'port': facts['dport']},
            'owner': 'unknown', 'pid': None, 'process': 'unknown',
            'disposition': 'unknown', 'domain': 'unknown',
            'started_at': timestamp, 'ended_at': timestamp,
            'directions': {},
        }
    return {
        'id': registry_flow['id'], 'protocol': registry_flow['protocol'],
        'ip_version': registry_flow['ip_version'],
        'source': registry_flow['source'], 'destination': registry_flow['destination'],
        'owner': registry_flow.get('owner') or 'unknown',
        'pid': registry_flow.get('pid'),
        'process': registry_flow.get('process') or 'unknown',
        'disposition': registry_flow.get('disposition') or 'unknown',
        'domain': registry_flow.get('domain') or 'unknown',
        'started_at': registry_flow.get('started_at'),
        'ended_at': registry_flow.get('ended_at'),
        'directions': {},
    }


def build_payload_report(raw_pcap_path, observation_index, flow_registry=None,
                         nbis=None, capture_health=None,
                         converted_pcap_path=None):
    """Build and validate the complete report model from sealed PCAP files."""
    raw_records = _read_pcap(raw_pcap_path)
    converted_records = (_read_pcap(converted_pcap_path)
                         if converted_pcap_path else None)
    _validate_pair(raw_records, converted_records)
    entries = (observation_index.snapshot() if hasattr(observation_index, 'snapshot')
               else [dict(item) for item in observation_index])
    _validate_index(raw_records, entries)

    health = dict(capture_health or {})
    for key in ('writer_health', 'coverage_health', 'reassembly_health'):
        health.setdefault(key, True)
    health['overall_health'] = all(bool(health[key]) for key in (
        'writer_health', 'coverage_health', 'reassembly_health'))
    if not health['overall_health']:
        raise PayloadReportError('capture health is not complete: %s' % health)

    registry = flow_registry or SessionFlowRegistry()
    selected = _choose_observations(raw_records, entries)
    registry_flows = {item['id']: item for item in registry.snapshot()}
    flow_models = {}
    tcp_segments = {}
    udp_datagrams = {}
    for (ordinal, timestamp, raw), entry in selected:
        facts = _packet_parts(raw)
        if facts['protocol'] not in ('TCP', 'UDP'):
            continue
        logical = entry.get('logical_packet_id')
        flow_id = entry.get('flow_id')
        if flow_id is None:
            flow_id = registry.observe_packet(
                raw, entry.get('direction', 'unknown'), timestamp, logical)
        if flow_id is None:
            flow_id = 'flow-unowned-%06d' % ordinal
        flow_id = str(flow_id)
        registry_flow = registry_flows.get(flow_id)
        model = flow_models.get(flow_id)
        if model is None:
            model = _flow_model(registry_flow, flow_id, facts, timestamp)
            flow_models[flow_id] = model
        direction = entry.get('direction', 'unknown')
        if direction not in DIRECTIONS or direction == 'unknown':
            direction = registry.direction_for(
                flow_id, facts['src'], facts['sport'], facts['dst'], facts['dport'])
        if direction not in DIRECTIONS:
            direction = 'unknown'
        direction_key = (facts['src'], facts['sport'], facts['dst'], facts['dport'])
        direction_model = model['directions'].setdefault(direction, {
            'id': '%s-%s' % (flow_id, direction),
            'direction': direction, 'source': {
                'ip': facts['src'], 'port': facts['sport']},
            'destination': {'ip': facts['dst'], 'port': facts['dport']},
            'started_at': timestamp, 'ended_at': timestamp,
            'bytes': 0, 'sha256': _sha256(b''),
            'encoding': PAYLOAD_REPORT_ENCODING, 'base64': '',
        })
        direction_model['started_at'] = min(direction_model['started_at'], timestamp)
        direction_model['ended_at'] = max(direction_model['ended_at'], timestamp)
        if facts['protocol'] == 'TCP':
            start = facts['seq'] + (1 if facts['flags'] & dpkt.tcp.TH_SYN else 0)
            tcp_segments.setdefault((flow_id, direction), []).append({
                'start': start, 'payload': facts['payload'],
                'fin': bool(facts['flags'] & dpkt.tcp.TH_FIN),
                'ordinal': ordinal,
            })
        else:
            udp_datagrams.setdefault((flow_id, direction), []).append({
                'ordinal': ordinal, 'timestamp': timestamp,
                'length': len(facts['payload']), 'sha256': _sha256(facts['payload']),
                'offset': 0, 'payload': facts['payload'],
                'source': {'ip': facts['src'], 'port': facts['sport']},
                'destination': {'ip': facts['dst'], 'port': facts['dport']},
            })

    for flow_id, model in flow_models.items():
        for direction, direction_model in model['directions'].items():
            if model['protocol'] == 'TCP':
                payload, _cursor = _assemble_tcp(tcp_segments.get(
                    (flow_id, direction), []))
                direction_model['bytes'] = len(payload)
                direction_model['sha256'] = _sha256(payload)
                direction_model['base64'] = _b64(payload)
            else:
                datagrams = udp_datagrams.get((flow_id, direction), [])
                offset = 0
                payload_parts = []
                for number, datagram in enumerate(datagrams, 1):
                    datagram['offset'] = offset
                    offset += datagram['length']
                    datagram['id'] = '%s-%s-datagram-%06d' % (
                        flow_id, direction, number)
                    datagram['direction'] = direction
                    datagram['bytes'] = datagram['length']
                    datagram['started_at'] = datagram['timestamp']
                    datagram['ended_at'] = datagram['timestamp']
                    datagram['owner'] = model.get('owner') or 'unknown'
                    datagram['pid'] = model.get('pid')
                    datagram['process'] = model.get('process') or 'unknown'
                    datagram['disposition'] = model.get('disposition') or 'unknown'
                    datagram['domain'] = model.get('domain') or 'unknown'
                    # This is a range reference into the direction's one
                    # Base64 value, not a second copy of the payload bytes.
                    datagram['base64'] = {
                        'source': direction_model['id'],
                        'offset': datagram['offset'],
                        'length': datagram['length'],
                    }
                    payload_parts.append(datagram['payload'])
                payload = b''.join(payload_parts)
                direction_model['bytes'] = len(payload)
                direction_model['sha256'] = _sha256(payload)
                direction_model['base64'] = _b64(payload)
                direction_model['datagrams'] = [
                    {key: value for key, value in datagram.items()
                     if key != 'payload'} for datagram in datagrams]

    # Ensure registry-only zero-payload TCP streams are still represented.
    for registry_flow in registry.snapshot():
        if registry_flow['protocol'] != 'TCP' or registry_flow['id'] in flow_models:
            continue
        model = _flow_model(registry_flow, registry_flow['id'], {
            'protocol': 'TCP', 'version': registry_flow['ip_version'],
            'src': registry_flow['source']['ip'], 'dst': registry_flow['destination']['ip'],
            'sport': registry_flow['source']['port'],
            'dport': registry_flow['destination']['port'],
        }, registry_flow.get('started_at'))
        model['directions']['unknown'] = {
            'id': '%s-unknown' % registry_flow['id'], 'direction': 'unknown',
            'source': registry_flow['source'], 'destination': registry_flow['destination'],
            'started_at': registry_flow.get('started_at'),
            'ended_at': registry_flow.get('ended_at'), 'bytes': 0,
            'sha256': _sha256(b''), 'encoding': PAYLOAD_REPORT_ENCODING,
            'base64': '',
        }
        flow_models[registry_flow['id']] = model

    model = {
        'schema': PAYLOAD_REPORT_SCHEMA,
        'encoding': PAYLOAD_REPORT_ENCODING,
        'capture': {
            'raw_pcap': os.path.basename(str(raw_pcap_path)),
            'converted_pcap': (os.path.basename(str(converted_pcap_path))
                               if converted_pcap_path else None),
            'raw_record_count': len(raw_records),
            'converted_record_count': (len(converted_records)
                                       if converted_records is not None else None),
            'observation_record_count': len(entries),
            'writer_health': bool(health['writer_health']),
            'coverage_health': bool(health['coverage_health']),
            'reassembly_health': True,
            'overall_health': True,
            'marker': 'complete-capture',
        },
        'flows': list(flow_models.values()),
        'nbis': _serialize_nbis(nbis, registry=registry),
    }
    validate_payload_model(model)
    return model


def validate_payload_model(model):
    if not isinstance(model, dict) or model.get('schema') != PAYLOAD_REPORT_SCHEMA:
        raise PayloadReportError('invalid payload report schema')
    if model.get('encoding') != PAYLOAD_REPORT_ENCODING:
        raise PayloadReportError('invalid payload report encoding')
    capture = model.get('capture') or {}
    if not capture.get('overall_health'):
        raise PayloadReportError('payload report capture is not healthy')
    flow_ids = set()
    for flow in model.get('flows', []):
        flow_id = str(flow.get('id', ''))
        if not flow_id or flow_id in flow_ids:
            raise PayloadReportError('duplicate or missing flow ID')
        flow_ids.add(flow_id)
        owner = flow.get('owner')
        if owner in (None, ''):
            raise PayloadReportError('flow %s has no owner value' % flow_id)
        direction_ids = set()
        for direction in (flow.get('directions') or {}).values():
            direction_id = str(direction.get('id', ''))
            if not direction_id or direction_id in direction_ids:
                raise PayloadReportError('duplicate or missing direction ID')
            direction_ids.add(direction_id)
            try:
                payload = base64.b64decode(
                    str(direction.get('base64', '')).encode('ascii'), validate=True)
            except Exception as exc:
                raise PayloadReportError(
                    'invalid Base64 for %s: %s' % (direction_id, exc)) from exc
            if len(payload) != int(direction.get('bytes', -1)):
                raise PayloadReportError('payload length mismatch for %s' % direction_id)
            if _sha256(payload) != direction.get('sha256'):
                raise PayloadReportError('payload hash mismatch for %s' % direction_id)
            if flow.get('protocol') == 'UDP':
                cursor = 0
                datagram_ids = set()
                for datagram in direction.get('datagrams', []):
                    if int(datagram.get('offset', -1)) != cursor:
                        raise PayloadReportError(
                            'UDP datagram boundary mismatch for %s' % direction_id)
                    length = int(datagram.get('length', -1))
                    if length < 0:
                        raise PayloadReportError('invalid UDP datagram length')
                    if int(datagram.get('bytes', -1)) != length:
                        raise PayloadReportError('UDP datagram byte count mismatch')
                    datagram_id = str(datagram.get('id', ''))
                    if not datagram_id or datagram_id in datagram_ids:
                        raise PayloadReportError('duplicate or missing UDP datagram ID')
                    datagram_ids.add(datagram_id)
                    reference = datagram.get('base64') or {}
                    if (reference.get('source') != direction_id or
                            int(reference.get('offset', -1)) != cursor or
                            int(reference.get('length', -1)) != length):
                        raise PayloadReportError(
                            'UDP datagram Base64 reference mismatch')
                    if datagram.get('sha256') != _sha256(
                            payload[cursor:cursor + length]):
                        raise PayloadReportError('UDP datagram hash mismatch')
                    cursor += length
                if cursor != len(payload):
                    raise PayloadReportError(
                        'UDP datagram lengths mismatch for %s' % direction_id)
    return True
