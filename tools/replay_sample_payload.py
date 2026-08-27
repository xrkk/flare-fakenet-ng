#!/usr/bin/env python3
"""Read-only replay of the historical EVD-PCAP-001 sample evidence.

This adapter is intentionally not used by production reporting.  It reads
the fixed evidence directory, reconstructs an observation index in memory,
and writes a separate diagnostic report whose capture health explicitly says
that the old session is incomplete.  The source evidence is never copied or
modified.
"""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re

import dpkt
from jinja2 import Environment, FileSystemLoader

from fakenet.payload_report import (_packet_parts, build_payload_report,
                                    safe_json_dumps, SessionFlowRegistry)


SCHEMA = 'fakenet.payload-replay.v1'
SAMPLE_IP = '192.168.204.187'
SINK_IP = '192.168.204.1'
EXPECTED_DIRECTIONS = {
    ('192.168.204.1', 3585, '192.168.204.187', 49774): {
        'bytes': 597,
        'sha256': 'd5708b8d6a6a2b4949a4e8b2df502b05ba5bf70fb261452981a0a8e5069dd506',
    },
    ('192.168.204.187', 49772, '192.168.204.1', 3585): {
        'bytes': 341,
        'sha256': '70bf126e1a0d3fbce78ffcd158ab690962d42b056644daa770f4789e06aa4fbb',
    },
    ('192.168.204.187', 49774, '192.168.204.1', 3585): {
        'bytes': 531,
        'sha256': '3741f27a701c9a27091c8074c9aba58bb23c1e48935fa5e08861e3a7b4317153',
    },
}
PROCESS_FLOW_RE = re.compile(r'\bPROCESS_FLOW\s+(?P<fields>.+)$')
FIELD_RE = re.compile(r'(?P<key>\w+)=(?P<value>\S+)')


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def _direction(facts):
    if facts['src'] == SAMPLE_IP and facts['dst'] == SINK_IP:
        return 'outbound'
    if facts['src'] == SINK_IP and facts['dst'] == SAMPLE_IP:
        return 'inbound'
    return 'unknown'


def _read_records(path):
    records = []
    try:
        with open(path, 'rb') as stream:
            for ordinal, (timestamp, raw) in enumerate(
                    dpkt.pcap.Reader(stream), 1):
                raw = bytes(raw)
                facts = _packet_parts(raw)
                records.append((ordinal, float(timestamp), raw, facts))
    except Exception as exc:
        raise RuntimeError('unable to read historical PCAP: %s' % exc) from exc
    if not records:
        raise RuntimeError('historical PCAP has no records')
    return records


def _build_index(records):
    registry = SessionFlowRegistry()
    entries = []
    for ordinal, timestamp, raw, facts in records:
        logical = 'legacy-%08d' % ordinal
        direction = _direction(facts)
        flow_id = registry.observe_packet(
            raw, direction=direction, timestamp=timestamp,
            logical_packet_id=logical)
        entries.append({
            'ordinal': ordinal,
            'logical_packet_id': logical,
            'observation_role': 'initial',
            'direction': direction,
            'length': len(raw),
            'sha256': hashlib.sha256(raw).hexdigest(),
            'timestamp': timestamp,
            **({'flow_id': flow_id} if flow_id is not None else {}),
        })
    return entries, registry


def _apply_historical_ownership(log_path, registry):
    """Use PROCESS_FLOW only for this historical adapter, never production."""
    patterns = []
    with open(log_path, 'r', encoding='utf-8', errors='replace') as stream:
        for line in stream:
            match = PROCESS_FLOW_RE.search(line)
            if not match:
                continue
            fields = {item.group('key'): item.group('value')
                      for item in FIELD_RE.finditer(match.group('fields'))}
            if fields.get('disposition') != 'ALLOW_TAKEOVER_SINK':
                continue
            try:
                patterns.append({
                    'protocol': fields['proto'].upper(),
                    'src': fields['src'], 'sport': int(fields['sport']),
                    'dst': fields['dst'], 'dport': int(fields['dport']),
                    'pid': int(fields['pid']) if fields.get('pid') != 'unknown'
                           else None,
                    'process': fields.get('process', 'unknown'),
                    'disposition': fields['disposition'],
                    'domain': fields.get('domain', 'unknown'),
                })
            except (KeyError, TypeError, ValueError):
                continue
    for flow in registry.snapshot():
        source = flow.get('source') or {}
        destination = flow.get('destination') or {}
        for item in patterns:
            if flow.get('protocol') != item['protocol']:
                continue
            same = (source.get('ip') == item['src'] and
                    source.get('port') == item['sport'] and
                    destination.get('ip') == item['dst'] and
                    destination.get('port') == item['dport'])
            reverse = (source.get('ip') == item['dst'] and
                       source.get('port') == item['dport'] and
                       destination.get('ip') == item['src'] and
                       destination.get('port') == item['sport'])
            if same or reverse:
                registry.update(
                    flow['id'], owner=item['process'], pid=item['pid'],
                    process=item['process'], disposition=item['disposition'],
                    domain=item['domain'])
                break


def _direction_results(model):
    results = []
    for flow in model.get('flows', []):
        for direction in (flow.get('directions') or {}).values():
            source = direction.get('source') or {}
            destination = direction.get('destination') or {}
            key = (source.get('ip'), source.get('port'),
                   destination.get('ip'), destination.get('port'))
            expected = EXPECTED_DIRECTIONS.get(key)
            if expected is None:
                continue
            payload = base64.b64decode(direction.get('base64', ''))
            actual = {
                'flow_id': flow.get('id'),
                'direction_id': direction.get('id'),
                'source': source,
                'destination': destination,
                'bytes': len(payload),
                'sha256': hashlib.sha256(payload).hexdigest(),
                'expected_bytes': expected['bytes'],
                'expected_sha256': expected['sha256'],
            }
            actual['match'] = (actual['bytes'] == expected['bytes'] and
                               actual['sha256'] == expected['sha256'])
            results.append(actual)
    results.sort(key=lambda item: (
        item['source']['ip'], item['source']['port'],
        item['destination']['ip'], item['destination']['port']))
    return results


def _write_text_atomic(path, text):
    temporary = path.with_name(path.name + '.tmp-%s' % os.getpid())
    try:
        with open(temporary, 'x', encoding='utf-8', newline='\n') as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise


def replay(input_root, output_root):
    input_root = Path(input_root).resolve()
    output_root = Path(output_root).resolve()
    if output_root.exists():
        raise RuntimeError('refusing to overwrite replay output: %s' % output_root)
    raw_path = input_root / 'packets_20260827_112433.pcap'
    converted_path = input_root / 'packets_20260827_112433-converted.pcap'
    log_path = input_root / 'Logs' / 'fakenet-20260827-112427-753398-gui-p5972.log'
    for path in (raw_path, converted_path, log_path):
        if not path.is_file():
            raise RuntimeError('historical evidence is missing: %s' % path)

    records = _read_records(raw_path)
    index, registry = _build_index(records)
    _apply_historical_ownership(log_path, registry)
    model = build_payload_report(
        raw_path, index, flow_registry=registry,
        capture_health={'writer_health': True, 'coverage_health': True,
                        'reassembly_health': True},
        converted_pcap_path=converted_path)
    directions = _direction_results(model)
    expected_keys = set(EXPECTED_DIRECTIONS)
    actual_keys = {(item['source']['ip'], item['source']['port'],
                    item['destination']['ip'], item['destination']['port'])
                   for item in directions}
    if actual_keys != expected_keys:
        raise RuntimeError(
            'historical payload directions differ: expected %r got %r' %
            (sorted(expected_keys), sorted(actual_keys)))
    if not all(item['match'] for item in directions):
        raise RuntimeError('historical payload bytes/hash differ from §2.3')

    # This is a diagnostic replay, not a new successful capture.  Preserve the
    # complete reconstructed bytes while making the known runtime gap visible.
    model['capture'].update({
        'coverage_health': False,
        'overall_health': False,
        'marker': 'historical-replay-runtime-coverage-unhealthy',
        'limitation': (
            'Historical EVD-PCAP-001 contains a known 266-second runtime '
            'capture gap; replay is complete for observed bytes only and is '
            'not a healthy capture report.'),
    })

    output_root.mkdir(parents=True, exist_ok=False)
    index_path = output_root / 'observation-index.json'
    _write_text_atomic(index_path, json.dumps(
        index, ensure_ascii=False, indent=2, sort_keys=True) + '\n')
    template_root = Path(__file__).resolve().parents[1] / 'fakenet' / 'configs'
    template = Environment(loader=FileSystemLoader(str(template_root))).get_template(
        'html_report_template.html')
    html_path = output_root / 'diagnostic-replay.html'
    _write_text_atomic(html_path, template.render(
        payload_report_json=safe_json_dumps(model)))

    input_files = {
        'raw_pcap': raw_path,
        'converted_pcap': converted_path,
        'log': log_path,
        'historical_html': input_root / 'report_20260827_112947.html',
    }
    result = {
        'schema': SCHEMA,
        'fixture_seed': 'EVD-PCAP-001',
        'inputs': {
            name: {'path': str(path), 'sha256': _sha256(path)}
            for name, path in input_files.items()
        },
        'directions': directions,
        'coverage': {
            'writer_health': True,
            'reassembly_health': True,
            'runtime_capture_coverage': False,
            'known_gap': '266-second runtime capture gap from EVD-LOG-001',
            'verdict': 'UNHEALTHY_HISTORICAL_REPLAY',
        },
        'report': {
            'path': html_path.name,
            'sha256': _sha256(html_path),
            'capture_marker': model['capture']['marker'],
        },
        'observation_index': {
            'path': index_path.name,
            'sha256': _sha256(index_path),
            'records': len(index),
        },
        'payload_markers': {
            marker: any(marker.encode('ascii') in base64.b64decode(
                direction.get('base64', ''))
                        for flow in model.get('flows', [])
                        for direction in (flow.get('directions') or {}).values())
            for marker in ('PING', 'SYSINFO', 'PROCLIST')
        },
        'verdict': 'PASS',
    }
    verification_path = output_root / 'replay-verification.json'
    _write_text_atomic(verification_path,
                        json.dumps(result, ensure_ascii=False, indent=2) + '\n')

    evidence_lines = ['role\tpath\tsha256']
    for role, path in (*input_files.items(),
                       ('observation_index', index_path),
                       ('diagnostic_replay', html_path),
                       ('replay_verification', verification_path)):
        evidence_lines.append('%s\t%s\t%s' %
                              (role, path.name, _sha256(path)))
    _write_text_atomic(output_root / 'evidence-sha256.tsv',
                       '\n'.join(evidence_lines) + '\n')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--input-root', default='dist/样本实测')
    parser.add_argument('--output-root', default='dist/样本实测-回放-v35')
    args = parser.parse_args(argv)
    try:
        result = replay(args.input_root, args.output_root)
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except Exception as exc:
        print('FAIL: %s' % exc)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
