#!/usr/bin/env python3
"""Generate an isolated, deterministic healthy payload-report fixture.

This is a verifier fixture, not a production capture path.  It exercises the
same DualPcapWriter, observation index, flow registry, payload model, and HTML
template used by the application, including an 8 MiB payload in each
direction and hostile-looking text that must remain inert JSON data.
"""

import argparse
import base64
import hashlib
import json
import logging
from pathlib import Path
import socket

import dpkt
from jinja2 import Environment, FileSystemLoader

from fakenet.diverters.pcapwriter import DualPcapWriter
from fakenet.payload_report import (CaptureObservationIndex,
                                    SessionFlowRegistry, build_payload_report,
                                    safe_json_dumps, validate_payload_model)


TARGET_BYTES = 8 * 1024 * 1024
CHUNK_BYTES = 60000
FIXTURE_SCHEMA = 'fakenet.payload-report-fixture.v1'


def _tcp_packet(source, destination, sport, dport, sequence, payload):
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, seq=sequence, ack=1,
                       flags=dpkt.tcp.TH_ACK, data=payload)
    tcp.off = 5
    packet = dpkt.ip.IP(src=socket.inet_aton(source),
                        dst=socket.inet_aton(destination),
                        p=dpkt.ip.IP_PROTO_TCP, ttl=64, data=tcp)
    packet.len = len(packet)
    return bytes(packet)


def _payload(prefix, fill):
    hostile = (b'</script><script>alert(1)</script>|<b>tag</b>|"quoted"|'
               b'\xff\xfe\xfa')
    seed = (prefix + b'|' + hostile + b'|' +
            bytes((index * 29 + 7) % 256 for index in range(257)))
    repeated = bytearray(seed)
    while len(repeated) < TARGET_BYTES:
        repeated.extend(fill)
    return bytes(repeated[:TARGET_BYTES])


def _write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2,
                               sort_keys=True) + '\n', encoding='utf-8')


def generate(output_root):
    output_root = Path(output_root).resolve()
    if output_root.exists():
        raise RuntimeError('refusing to overwrite fixture directory: %s' %
                           output_root)
    output_root.mkdir(parents=True)
    raw_path = output_root / 'packets-fixture.pcap'
    converted_path = output_root / 'packets-fixture-converted.pcap'
    writer = DualPcapWriter(
        raw_path, converted_path, logging.getLogger('payload-fixture'),
        clock=lambda: 1700000000.0 + writer.last_record_ordinal * 0.001)
    index = CaptureObservationIndex()
    registry = SessionFlowRegistry()
    outbound = _payload(b'outbound', bytes(range(1, 251)))
    inbound = _payload(b'inbound', bytes(range(251, 256)) + bytes(range(1, 6)))
    packet_specs = (
        ('outbound', '192.0.2.10', '198.51.100.20', 40000, 3585, outbound),
        ('inbound', '198.51.100.20', '192.0.2.10', 3585, 40000, inbound),
    )
    first_flow = None
    for direction, source, destination, sport, dport, payload in packet_specs:
        sequence = 100000 if direction == 'outbound' else 500000
        offset = 0
        while offset < len(payload):
            chunk = payload[offset:offset + CHUNK_BYTES]
            raw = _tcp_packet(source, destination, sport, dport, sequence,
                              chunk)
            logical = index.new_logical_packet_id(direction)
            flow_id = registry.observe_packet(
                raw, direction=direction, timestamp=1700000000.0,
                logical_packet_id=logical)
            if first_flow is None:
                first_flow = flow_id
            if not writer.write_ip_packet(raw):
                raise RuntimeError('fixture writer rejected packet')
            index.record(raw, 'initial', logical_packet_id=logical,
                         flow_id=flow_id, direction=direction,
                         timestamp=writer.last_timestamp,
                         record_ordinal=writer.last_record_ordinal)
            offset += len(chunk)
            sequence += len(chunk)
    writer.close()
    registry.update(first_flow, owner='sample.exe', pid=4321,
                    process='sample.exe', disposition='ALLOW_TAKEOVER_SINK',
                    domain='sample.invalid')
    model = build_payload_report(
        raw_path, index, flow_registry=registry,
        nbis={(4321, 'sample.exe'): {'HTTP': [{
            'transport_layer_proto': 'TCP', 'sport': 40000,
            'dst_ip': '198.51.100.20', 'dport': 3585,
            'nbi': {'url': 'https://example.invalid/path',
                    'dom_text': 'innerHTML',
                    'html_text': '<b>text only</b>'},
        }]}},
        capture_health={'writer_health': True, 'coverage_health': True,
                        'reassembly_health': True},
        converted_pcap_path=converted_path)
    validate_payload_model(model)
    index_path = output_root / 'observation-index.json'
    model_path = output_root / 'payload-model.json'
    _write_json(index_path, index.snapshot())
    _write_json(model_path, model)
    template_root = Path(__file__).resolve().parents[2] / 'fakenet' / 'configs'
    template = Environment(loader=FileSystemLoader(str(template_root))).get_template(
        'html_report_template.html')
    html_path = output_root / 'report.html'
    html_path.write_text(template.render(
        payload_report_json=safe_json_dumps(model)), encoding='utf-8')
    result = {
        'schema': FIXTURE_SCHEMA,
        'target_bytes_per_direction': TARGET_BYTES,
        'records': len(index),
        'raw_pcap': {'path': raw_path.name,
                     'sha256': hashlib.sha256(raw_path.read_bytes()).hexdigest()},
        'converted_pcap': {
            'path': converted_path.name,
            'sha256': hashlib.sha256(converted_path.read_bytes()).hexdigest()},
        'observation_index': {'path': index_path.name,
                              'sha256': hashlib.sha256(index_path.read_bytes()).hexdigest()},
        'model': {'path': model_path.name,
                  'sha256': hashlib.sha256(model_path.read_bytes()).hexdigest()},
        'html': {'path': html_path.name,
                 'sha256': hashlib.sha256(html_path.read_bytes()).hexdigest()},
        'verdict': 'PASS',
    }
    _write_json(output_root / 'fixture-manifest.json', result)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-root', required=True)
    args = parser.parse_args(argv)
    generate(args.output_root)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
