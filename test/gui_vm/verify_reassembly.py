#!/usr/bin/env python3
"""Offline reassembly verifier for deterministic ACC-003 fixtures."""

import argparse
import base64
import hashlib
import json
import logging
import os
import socket
import sys
import tempfile

import dpkt

from fakenet.diverters.pcapwriter import DualPcapWriter
from fakenet.payload_report import (CaptureObservationIndex,
                                    PayloadReportError,
                                    SessionFlowRegistry,
                                    build_payload_report,
                                    validate_payload_model)


SCHEMA = 'fakenet.reassembly-verification.v1'


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_bytes(value):
    return hashlib.sha256(bytes(value)).hexdigest()


def _tcp(source, destination, sport, dport, sequence, payload=b'',
         flags=dpkt.tcp.TH_ACK, ipv6=False):
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, seq=sequence, ack=1,
                       flags=flags, data=payload)
    tcp.off = 5
    if ipv6:
        packet = dpkt.ip6.IP6(
            src=socket.inet_pton(socket.AF_INET6, source),
            dst=socket.inet_pton(socket.AF_INET6, destination),
            nxt=dpkt.ip.IP_PROTO_TCP, hlim=64, data=tcp)
        packet.plen = len(tcp)
    else:
        packet = dpkt.ip.IP(
            src=socket.inet_aton(source), dst=socket.inet_aton(destination),
            p=dpkt.ip.IP_PROTO_TCP, ttl=64, data=tcp)
        packet.len = len(packet)
    return bytes(packet)


def _udp(source, destination, sport, dport, payload, ipv6=False):
    udp = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
    udp.ulen = len(udp)
    if ipv6:
        packet = dpkt.ip6.IP6(
            src=socket.inet_pton(socket.AF_INET6, source),
            dst=socket.inet_pton(socket.AF_INET6, destination),
            nxt=dpkt.ip.IP_PROTO_UDP, hlim=64, data=udp)
        packet.plen = len(udp)
    else:
        packet = dpkt.ip.IP(
            src=socket.inet_aton(source), dst=socket.inet_aton(destination),
            p=dpkt.ip.IP_PROTO_UDP, ttl=64, data=udp)
        packet.len = len(packet)
    return bytes(packet)


def _capture_case(observations):
    """Create one isolated paired-PCAP case and return verified identities."""
    with tempfile.TemporaryDirectory(prefix='fakenet-reassembly-matrix-') as root:
        raw_path = os.path.join(root, 'raw.pcap')
        converted_path = os.path.join(root, 'converted.pcap')
        index = CaptureObservationIndex()
        registry = SessionFlowRegistry()
        writer = DualPcapWriter(
            raw_path, converted_path, logging.getLogger('reassembly-matrix'),
            clock=lambda: 1700000000.0 + len(index.snapshot()) * 0.001)
        for item in observations:
            raw = item['raw']
            logical = item['logical']
            direction = item.get('direction', 'unknown')
            flow_id = registry.observe_packet(
                raw, direction=direction, timestamp=1700000000.0,
                logical_packet_id=logical)
            if not writer.write_ip_packet(raw):
                raise RuntimeError('matrix paired writer rejected a packet')
            index.record(
                raw, item.get('role', 'initial'),
                logical_packet_id=logical, flow_id=flow_id,
                direction=direction, timestamp=writer.last_timestamp,
                record_ordinal=writer.last_record_ordinal)
        summary = writer.close()
        identities = {
            'raw_pcap_sha256': _sha256(raw_path),
            'converted_pcap_sha256': _sha256(converted_path),
            'index_sha256': _sha256_bytes(json.dumps(
                index.snapshot(), sort_keys=True,
                separators=(',', ':')).encode('utf-8')),
            'records': summary.raw_write_count,
        }
        try:
            model = build_payload_report(
                raw_path, index, registry,
                capture_health={'writer_health': True,
                                'coverage_health': True,
                                'reassembly_health': True},
                converted_pcap_path=converted_path)
        except PayloadReportError as exc:
            return None, identities, str(exc), registry
        validate_payload_model(model)
        return model, identities, None, registry


def _direction_payload(flow, name):
    for item in (flow.get('directions') or {}).values():
        if item.get('direction') == name:
            return base64.b64decode(item['base64'].encode('ascii'))
    raise ValueError('matrix flow has no %s direction' % name)


def _payload_projection(flows):
    """Return only the frozen byte facts shared by report/model schemas."""
    projected = []
    for flow in flows:
        directions = flow.get('directions') or {}
        if isinstance(directions, dict):
            directions = directions.values()
        projected.append({
            'flow_id': flow.get('flow_id', flow.get('id')),
            'protocol': flow['protocol'],
            'directions': sorted(({
                'direction_id': item.get('direction_id', item.get('id')),
                'direction': item['direction'],
                'bytes': item['bytes'],
                'sha256': item['sha256'],
            } for item in directions), key=lambda item: item['direction_id']),
        })
    return sorted(projected, key=lambda item: item['flow_id'])


def _matrix_checks():
    checks = []

    out_a = _tcp('192.0.2.10', '198.51.100.20', 40000, 3585,
                 105, b' world')
    out_b = _tcp('192.0.2.10', '198.51.100.20', 40000, 3585,
                 100, b'hello')
    inbound = _tcp('198.51.100.20', '192.0.2.10', 3585, 40000,
                   900, b'reply')
    model, inputs, error, _registry = _capture_case([
        {'raw': out_a, 'logical': 'out-2', 'direction': 'outbound'},
        {'raw': out_b, 'logical': 'out-1', 'direction': 'outbound'},
        {'raw': out_b, 'logical': 'out-1', 'role': 'final',
         'direction': 'outbound'},
        {'raw': out_b, 'logical': 'out-retransmit', 'direction': 'outbound'},
        {'raw': inbound, 'logical': 'in-1', 'direction': 'inbound'},
    ])
    if error:
        raise ValueError('TCP reorder/retransmit case failed: %s' % error)
    flow = model['flows'][0]
    expected_out = b'hello world'
    expected_in = b'reply'
    if (_direction_payload(flow, 'outbound') != expected_out or
            _direction_payload(flow, 'inbound') != expected_in or
            flow.get('owner') != 'unknown'):
        raise ValueError('TCP reorder/retransmit/dedup result mismatch')
    checks.append({
        'id': 'tcp-ipv4-bidirectional-reorder-retransmit-logical-dedup',
        'inputs': inputs,
        'expected': {
            'outbound_bytes': len(expected_out),
            'outbound_sha256': _sha256_bytes(expected_out),
            'inbound_bytes': len(expected_in),
            'inbound_sha256': _sha256_bytes(expected_in),
            'owner': 'unknown'},
        'verdict': 'PASS',
    })

    udp_out = _udp('2001:db8::10', '2001:db8::20', 5000, 6000,
                   b'same', ipv6=True)
    udp_in = _udp('2001:db8::20', '2001:db8::10', 6000, 5000,
                  b'reply', ipv6=True)
    model, inputs, error, _registry = _capture_case([
        {'raw': udp_out, 'logical': 'udp-1', 'direction': 'outbound'},
        {'raw': udp_out, 'logical': 'udp-1', 'role': 'final',
         'direction': 'outbound'},
        {'raw': udp_out, 'logical': 'udp-2', 'direction': 'outbound'},
        {'raw': udp_in, 'logical': 'udp-3', 'direction': 'inbound'},
    ])
    if error:
        raise ValueError('UDP IPv6 case failed: %s' % error)
    flow = model['flows'][0]
    outbound = next(item for item in flow['directions'].values()
                    if item['direction'] == 'outbound')
    if (_direction_payload(flow, 'outbound') != b'samesame' or
            _direction_payload(flow, 'inbound') != b'reply' or
            len(outbound.get('datagrams', [])) != 2):
        raise ValueError('UDP IPv6 boundary/logical identity mismatch')
    checks.append({
        'id': 'udp-ipv6-bidirectional-distinct-identical-datagrams',
        'inputs': inputs,
        'expected': {
            'outbound_bytes': 8,
            'outbound_sha256': _sha256_bytes(b'samesame'),
            'outbound_datagrams': 2,
            'inbound_bytes': 5,
            'inbound_sha256': _sha256_bytes(b'reply')},
        'verdict': 'PASS',
    })

    wrap_a = _tcp('192.0.2.1', '198.51.100.1', 1234, 3585,
                  0xfffffffc, b'abcd')
    wrap_b = _tcp('192.0.2.1', '198.51.100.1', 1234, 3585,
                  0, b'efgh')
    model, inputs, error, _registry = _capture_case([
        {'raw': wrap_b, 'logical': 'wrap-2', 'direction': 'outbound'},
        {'raw': wrap_a, 'logical': 'wrap-1', 'direction': 'outbound'},
    ])
    if error or _direction_payload(model['flows'][0], 'outbound') != b'abcdefgh':
        raise ValueError('TCP 32-bit sequence wrap result mismatch: %s' % error)
    checks.append({
        'id': 'tcp-32bit-sequence-wrap', 'inputs': inputs,
        'expected': {'bytes': 8, 'sha256': _sha256_bytes(b'abcdefgh')},
        'verdict': 'PASS',
    })

    for case_id, packets, marker in (
            ('tcp-conflicting-overlap', [
                _tcp('192.0.2.1', '198.51.100.1', 1, 2, 100, b'abc'),
                _tcp('192.0.2.1', '198.51.100.1', 1, 2, 101, b'XYZ')],
             'conflicting'),
            ('tcp-internal-gap', [
                _tcp('192.0.2.1', '198.51.100.1', 1, 2, 100, b'abc'),
                _tcp('192.0.2.1', '198.51.100.1', 1, 2, 105, b'xyz')],
             'sequence gap')):
        _model, inputs, error, _registry = _capture_case([
            {'raw': packet, 'logical': '%s-%d' % (case_id, number),
             'direction': 'outbound'}
            for number, packet in enumerate(packets, 1)])
        if not error or marker not in error:
            raise ValueError('%s did not fail closed: %s' % (case_id, error))
        checks.append({
            'id': case_id, 'inputs': inputs,
            'expected_error_contains': marker,
            'gap_conflict': True, 'verdict': 'PASS',
        })

    registry = SessionFlowRegistry()
    syn_a = _tcp('192.0.2.10', '198.51.100.20', 40000, 3585, 100,
                 flags=dpkt.tcp.TH_SYN)
    syn_b = _tcp('192.0.2.10', '198.51.100.20', 40000, 3585, 900,
                 flags=dpkt.tcp.TH_SYN)
    first = registry.observe_packet(
        syn_a, 'outbound', 1.0, 'reuse-generation-1')
    second = registry.observe_packet(
        syn_b, 'outbound', 2.0, 'reuse-generation-2')
    if first == second or len(registry.snapshot()) != 2:
        raise ValueError('TCP reused tuple did not create a new generation')
    checks.append({
        'id': 'tcp-port-reuse-new-syn-without-observed-close',
        'inputs': {'packets_sha256': _sha256_bytes(syn_a + syn_b)},
        'expected': {'connection_ids': 2}, 'verdict': 'PASS',
    })
    return checks


def verify(raw_pcap, index_json, converted_pcap=None, expected_json=None,
           fixture_seed='ACC-003', run_matrix=False):
    with open(index_json, 'r', encoding='utf-8') as stream:
        entries = json.load(stream)
    if not isinstance(entries, list):
        raise ValueError('observation index must be a JSON list')
    model = build_payload_report(
        raw_pcap, entries, capture_health={
            'writer_health': True, 'coverage_health': True,
            'reassembly_health': True}, converted_pcap_path=converted_pcap)
    validate_payload_model(model)
    flows = []
    for flow in model.get('flows', []):
        flows.append({
            'flow_id': flow['id'], 'protocol': flow['protocol'],
            'owner': flow['owner'],
            'directions': [{
                'direction_id': direction['id'],
                'direction': direction['direction'],
                'bytes': direction['bytes'],
                'sha256': direction['sha256'],
            } for direction in (flow.get('directions') or {}).values()],
        })
    result = {
        'schema': SCHEMA,
        'fixture_seed': fixture_seed,
        'inputs': {
            'raw_pcap_sha256': _sha256(raw_pcap),
            'index_sha256': _sha256(index_json),
            'converted_pcap_sha256': (_sha256(converted_pcap)
                                      if converted_pcap else None),
        },
        'flows': flows,
        'gap_conflict': False,
        'matrix': _matrix_checks() if run_matrix else [],
        'verdict': 'PASS',
    }
    if expected_json:
        with open(expected_json, 'r', encoding='utf-8') as stream:
            expected = json.load(stream)
        if expected.get('schema') == 'fakenet.payload-report.v1':
            validate_payload_model(expected)
            if (_payload_projection(result['flows']) !=
                    _payload_projection(expected['flows'])):
                raise ValueError(
                    'reassembled payload bytes/hash differ from expected model')
        elif expected != result:
            raise ValueError('reassembly result differs from expected JSON')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--raw-pcap', required=True)
    parser.add_argument('--index-json', required=True)
    parser.add_argument('--converted-pcap')
    parser.add_argument('--expected-json')
    parser.add_argument('--fixture-seed', default='ACC-003')
    parser.add_argument('--matrix', action='store_true')
    parser.add_argument('--output', required=True)
    args = parser.parse_args(argv)
    try:
        result = verify(args.raw_pcap, args.index_json, args.converted_pcap,
                        args.expected_json, args.fixture_seed, args.matrix)
        code = 0
    except Exception as exc:
        result = {
            'schema': SCHEMA,
            'inputs': {'raw_pcap': os.path.abspath(args.raw_pcap)},
            'gap_conflict': isinstance(exc, PayloadReportError),
            'verdict': 'FAIL', 'error': str(exc),
        }
        code = 1
    with open(args.output, 'w', encoding='utf-8', newline='\n') as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    print(json.dumps(result, ensure_ascii=False))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
