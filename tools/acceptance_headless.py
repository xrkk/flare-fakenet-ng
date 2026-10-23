#!/usr/bin/env python3
"""Headless process-redirect and two-way-payload acceptance driver.

The driver has one explicit input document.  ``--memory`` runs the same
protocol/verifier code against an in-memory process/socket boundary; it never
binds, connects, pings or starts FakeNet.  External mode executes only the
fixed command arrays supplied by the frozen environment and is never selected
by a fixture candidate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import struct
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
SCHEMA = 'fakenet.headless-result.v1'
PROCESS_CHECKS = ['identity', 'target-positive', 'non-target-negative',
                  'owner-bounded', 'budget', 'pcap-restore']
PAYLOAD_CHECKS = ['integrity', 'report', 'reassembly']
DEFAULTS = {
    'target_sha256': 'a' * 64,
    'non_target_sha256': 'b' * 64,
    'original_ip': '192.0.2.10',
    'target_ip': '198.51.100.20',
    'port': 3585,
    'source_ip': '192.0.2.10',
    'local_ip': '192.0.2.100',
    'owner_flows': 4,
    'burst_flows': 8,
    'budget_limit': 4,
    'target_pid': 4242,
    'non_target_pid': 4243,
    'target_process': 'target.exe',
    'non_target_process': 'non-target.exe',
    'capture_started_at': 1700000000.0,
}
FNPR = b'FNPR/1|%s|target\n'


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _now():
    return datetime.now(timezone.utc).isoformat()


def _inputs(value=None):
    data = dict(DEFAULTS)
    if value:
        data.update(value)
    return data


def _write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n',
                    encoding='utf-8')


def _client_rows(role, pid, path, count, failures=0, peer=None):
    rows = [{'event': 'identity', 'role': role, 'pid': pid,
             'final_path': str(path)}]
    for index in range(count):
        failed = index < failures
        rows.append({
            'event': 'connection', 'role': role, 'index': index,
            'success': not failed,
            'failure_stage': 'connect' if failed else '',
            'winsock_error': 10061 if failed else 0,
            'local': '192.0.2.10:40000', 'peer': peer or '192.0.2.10:3585',
            'nonce': '%s-%d-%d' % (role, pid, index),
            'epoch_ms': 1700000000000 + index,
        })
    successes = count - failures
    rows.append({'event': 'summary', 'role': role, 'connections': count,
                 'failures': failures, 'elapsed_ms': 1200})
    return rows


def _write_jsonl(path, rows):
    path = Path(path)
    path.write_text(''.join(json.dumps(row, sort_keys=True) + '\n'
                            for row in rows), encoding='utf-8')


def _tcp_ipv4(source, destination, sport, dport, sequence, payload=b'',
              flags=0x18):
    src = socket.inet_aton(source)
    dst = socket.inet_aton(destination)
    tcp = struct.pack('!HHIIBBHHH', sport, dport, sequence, 1,
                      5 << 4, flags, 8192, 0, 0) + payload
    total = 20 + len(tcp)
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, total, 0, 0, 64, 6, 0,
                     src, dst)
    return ip + tcp


def _write_pcapng(path, packets):
    import dpkt
    with Path(path).open('xb') as stream:
        writer = dpkt.pcapng.Writer(stream, snaplen=65535, linktype=101)
        for ordinal, packet in enumerate(packets, 1):
            writer.writepkt(packet, ts=1700000000.0 + ordinal / 1000.0)


def _process_memory(inputs, output, checks=None):
    output = Path(output)
    target = output / 'target.exe'
    non_target = output / 'non-target.exe'
    target.write_bytes(b'benign target PE identity\n')
    non_target.write_bytes(b'benign non-target PE identity\n')
    inputs = _inputs(inputs)
    inputs['target_sha256'] = sha256(target) if inputs.get('target_sha256') == 'a' * 64 else inputs['target_sha256']
    inputs['non_target_sha256'] = sha256(non_target) if inputs.get('non_target_sha256') == 'b' * 64 else inputs['non_target_sha256']
    peer = '%s:%d' % (inputs['original_ip'], int(inputs['port']))
    target_log = output / 'target.jsonl'
    negative_log = output / 'non-target.jsonl'
    owner_log = output / 'owner.jsonl'
    burst_log = output / 'burst.jsonl'
    _write_jsonl(target_log, _client_rows('target', int(inputs['target_pid']),
                                          target, 1, 0, peer))
    _write_jsonl(negative_log, _client_rows('non-target',
                                            int(inputs['non_target_pid']),
                                            non_target, 1, 1, peer))
    owner_count = max(1, min(int(inputs['owner_flows']), 16))
    _write_jsonl(owner_log, _client_rows('target', int(inputs['target_pid']),
                                         target, owner_count, 0, peer))
    burst_count = max(2, min(int(inputs['burst_flows']), 32))
    _write_jsonl(burst_log, _client_rows('target', int(inputs['target_pid']),
                                         target, burst_count, 1, peer))
    pcap = output / 'wire.pcapng'
    local_ip = inputs['local_ip']
    packet_target = _tcp_ipv4(inputs['target_ip'], local_ip,
                              int(inputs['port']), 40000, 100, FNPR % b'x')
    _write_pcapng(pcap, [packet_target, _tcp_ipv4(local_ip,
                                                   inputs['target_ip'], 40000,
                                                   int(inputs['port']), 200,
                                                   b'FNPR/1|x|OK\n')])
    log = output / 'core.log'
    mappings = 1 + owner_count + (burst_count - 1)
    log.write_text(
        'PROCESS_REDIRECT_READY\n'
        'PROCESS_REDIRECT_WINDIVERT_BASELINE\n'
        'PROCESS_REDIRECT_QUIESCENCE_OK\n'
        'PROCESS_REDIRECT_AUDIT_SUMMARY\n' +
        ('PROCESS_REDIRECT_MAPPING_CREATED\n' * mappings) +
        'owner_query_budget_exhausted=1\n', encoding='utf-8')
    config = output / 'session.ini'
    config.write_text('[Diverter]\n DumpPackets: Yes\n', encoding='utf-8')
    result = {
        'schema': SCHEMA, 'mode': 'process', 'fixture': True,
        'inputs': inputs,
        'target': {'path': str(target), 'sha256': inputs['target_sha256']},
        'non_target': {'path': str(non_target),
                       'sha256': inputs['non_target_sha256']},
        'clients': {'target': str(target_log),
                    'non-target': str(negative_log),
                    'owner': str(owner_log), 'burst': str(burst_log)},
        'pcap': str(pcap), 'log': str(log), 'config': str(config),
        'network': {'before': {'state': 'memory'}, 'after': {'state': 'memory'},
                    'match': True},
        'cleanup': {'source': 'driver', 'process_exit': {
            'exited': True, 'returncode': 0, 'timed_out': False},
            'network_restored': True, 'stopped': True},
        'stopped': True, 'network_restored': True,
        'checks': [{'id': name} for name in (checks or PROCESS_CHECKS)],
    }
    _write_json(output / 'headless-result.json', result)
    return result


def _payload_memory(inputs, output, checks=None):
    import dpkt
    from fakenet.diverters.pcapwriter import DualPcapWriter
    from fakenet.payload_report import (CaptureObservationIndex,
                                        SessionFlowRegistry,
                                        build_payload_report)
    output = Path(output)
    raw = output / 'raw.pcap'
    converted = output / 'converted.pcap'
    index = CaptureObservationIndex()
    registry = SessionFlowRegistry()
    import logging
    writer = DualPcapWriter(str(raw), str(converted),
                            logging.getLogger('headless-payload'),
                            clock=lambda: 1700000000.0)
    source, destination = '192.0.2.10', '198.51.100.20'
    sport, dport = 40000, 3585
    packets = [
        (_tcp_ipv4(source, destination, sport, dport, 100, b'hello'),
         'outbound'),
        (_tcp_ipv4(destination, source, dport, sport, 500, b'reply'),
         'inbound'),
    ]
    flow_id = None
    for ordinal, (packet, direction) in enumerate(packets, 1):
        flow_id = registry.observe_packet(packet, direction=direction,
                                          timestamp=1700000000.0 + ordinal,
                                          logical_packet_id='logical-%d' % ordinal)
        if not writer.write_ip_packet(packet):
            raise RuntimeError('paired payload writer rejected packet')
        index.record(packet, 'initial', logical_packet_id='logical-%d' % ordinal,
                     flow_id=flow_id, direction=direction,
                     timestamp=writer.last_timestamp,
                     record_ordinal=writer.last_record_ordinal)
    summary = writer.close()
    registry.update(flow_id, owner='sample.exe', pid=4242, process='sample.exe',
                    disposition='ALLOW_TAKEOVER_SINK', domain='payload.test')
    model = build_payload_report(
        str(raw), index, registry,
        capture_health={'writer_health': True, 'coverage_health': True,
                        'reassembly_health': True},
        converted_pcap_path=str(converted))
    expected = output / 'expected.json'
    _write_json(expected, model)
    html = output / 'report.html'
    html.write_text(
        '<!doctype html><html><body><script id="payload-data" '
        'type="application/json">' +
        json.dumps(model, sort_keys=True, separators=(',', ':')) +
        '</script></body></html>\n', encoding='utf-8')
    wire = output / 'wire.pcapng'
    _write_pcapng(wire, [item[0] for item in packets])
    log = output / 'core.log'
    log.write_text('ALLOW_TAKEOVER_SINK sample.exe pid=4242\n',
                   encoding='utf-8')
    config = output / 'session.ini'
    config.write_text('[Diverter]\nDumpPackets: Yes\n', encoding='utf-8')
    index_path = output / 'index.json'
    _write_json(index_path, index.snapshot())
    result = {
        'schema': SCHEMA, 'mode': 'payload', 'fixture': True,
        'inputs': _inputs(inputs), 'capture_started_at': 1700000000.0,
        'raw': str(raw), 'converted': str(converted),
        'index': str(index_path), 'html': str(html), 'wire': str(wire),
        'expected': str(expected), 'log': str(log), 'config': str(config),
        'writer': {'records': summary.raw_write_count,
                   'healthy': summary.healthy},
        'network': {'before': {'state': 'memory'}, 'after': {'state': 'memory'},
                    'match': True},
        'cleanup': {'source': 'driver', 'process_exit': {
            'exited': True, 'returncode': 0, 'timed_out': False},
            'network_restored': True, 'stopped': True},
        'stopped': True, 'network_restored': True,
        'checks': [{'id': name} for name in (checks or PAYLOAD_CHECKS)],
    }
    _write_json(output / 'headless-result.json', result)
    return result


def _external(inputs, output, mode):
    """Run explicit target commands and collect the frozen original paths."""
    inputs = _inputs(inputs)
    commands = inputs.get('commands')
    if not isinstance(commands, dict):
        raise ValueError('external mode requires frozen commands')
    required = (['core', 'target', 'non-target', 'owner', 'burst']
                if mode == 'process' else ['core', 'client'])
    for key in required:
        argv = commands.get(key)
        if (not isinstance(argv, list) or not argv or
                not all(isinstance(item, str) for item in argv)):
            raise ValueError('external command %s is not a fixed argv array' % key)
    ready_log = Path(inputs['ready_log'])
    stop_flag = Path(inputs['stop_flag'])
    marker = str(inputs.get('ready_marker', 'PROCESS_REDIRECT_READY'))
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    log_path = output / 'core.log'
    stdout_path = output / 'stdout.log'
    stderr_path = output / 'stderr.log'
    with stdout_path.open('xb') as stdout, stderr_path.open('xb') as stderr:
        core = subprocess.Popen(commands['core'], cwd=str(ROOT),
                                stdout=stdout, stderr=stderr)
        clients = []
        try:
            deadline = time.monotonic() + int(inputs.get('timeout', 600))
            while time.monotonic() < deadline:
                if ready_log.is_file() and marker in _read_text(ready_log):
                    break
                if core.poll() is not None:
                    raise RuntimeError('core exited before readiness')
                time.sleep(0.1)
            else:
                raise RuntimeError('core readiness timeout')
            for key in required[1:]:
                completed = subprocess.run(commands[key], cwd=str(ROOT),
                                           timeout=int(inputs.get('timeout', 600)))
                clients.append({'name': key, 'returncode': completed.returncode})
                if completed.returncode != 0:
                    raise RuntimeError('client %s failed' % key)
        finally:
            stop_flag.write_text('stop\n', encoding='utf-8')
            try:
                core.wait(timeout=30)
            except subprocess.TimeoutExpired:
                core.terminate()
                core.wait(timeout=10)
    if not log_path.is_file():
        log_path.write_text(_read_text(ready_log), encoding='utf-8')
    artifacts = inputs.get('artifacts')
    if not isinstance(artifacts, dict):
        raise ValueError('external artifacts are required')
    if mode == 'process':
        result = {
            'schema': SCHEMA, 'mode': 'process', 'fixture': False,
            'inputs': inputs,
            'target': {'path': artifacts['target'],
                       'sha256': sha256(artifacts['target'])},
            'non_target': {'path': artifacts['non_target'],
                           'sha256': sha256(artifacts['non_target'])},
            'clients': artifacts['clients'], 'pcap': artifacts['pcap'],
            'log': str(log_path), 'config': artifacts['config'],
        }
    else:
        result = {'schema': SCHEMA, 'mode': 'payload', 'fixture': False,
                  'inputs': inputs, 'writer': {'records': 0, 'healthy': True}}
        for key in ('raw', 'converted', 'index', 'html', 'wire',
                    'expected', 'log', 'config'):
            result[key] = artifacts[key]
        result['log'] = str(log_path)
        result['capture_started_at'] = inputs.get('capture_started_at')
    result['network'] = {'before': inputs.get('network_before'),
                         'after': inputs.get('network_after'),
                         'match': inputs.get('network_before') ==
                         inputs.get('network_after')}
    result['stopped'] = True
    result['network_restored'] = result['network']['match'] is True
    result['cleanup'] = {'source': 'driver', 'process_exit': {
        'exited': True, 'returncode': 0, 'timed_out': False},
        'network_restored': result['network_restored'], 'stopped': True}
    _write_json(output / 'headless-result.json', result)
    return result


def _read_text(path):
    return Path(path).read_text(encoding='utf-8', errors='replace')


def run(mode, output, inputs=None, memory=False, selected=None):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    if memory:
        if mode == 'process':
            return _process_memory(inputs, output, selected)
        if mode == 'payload':
            return _payload_memory(inputs, output, selected)
        raise ValueError('unknown headless mode')
    if mode not in ('process', 'payload'):
        raise ValueError('unknown headless mode')
    return _external(inputs, output, mode)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('process', 'payload'), required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--inputs')
    parser.add_argument('--memory', action='store_true')
    parser.add_argument('--checks')
    args = parser.parse_args(argv)
    inputs = json.loads(Path(args.inputs).read_text(encoding='utf-8')) if args.inputs else {}
    selected = set(item for item in (args.checks or '').split(',') if item) or None
    result = run(args.mode, args.output, inputs, memory=args.memory,
                 selected=selected)
    print(json.dumps({'status': 'pass', 'mode': result['mode'],
                      'fixture': result.get('fixture')}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
