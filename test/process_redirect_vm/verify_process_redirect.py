import argparse
import ipaddress
import pathlib
import re
import socket
import sys
import json

import dpkt


def iter_packets(path):
    with path.open('rb') as handle:
        reader = dpkt.pcapng.Reader(handle)
        for unused_timestamp, frame in reader:
            yield frame


def decode_ipv4(frame):
    candidates = (frame, frame[14:] if len(frame) >= 14 else b'')
    for raw in candidates:
        if raw and raw[0] >> 4 == 4:
            try:
                return dpkt.ip.IP(raw)
            except (dpkt.UnpackError, ValueError):
                pass
    return None


def read_jsonl(path):
    return [json.loads(line) for line in path.read_text(
        encoding='utf-8', errors='strict').splitlines() if line.strip()]


def validate_client_log(path, role, connection_count, peer,
                        required_failures, minimum_elapsed_ms=0):
    rows = read_jsonl(path)
    identities = [row for row in rows if row.get('event') == 'identity']
    connections = [row for row in rows if row.get('event') == 'connection']
    summaries = [row for row in rows if row.get('event') == 'summary']
    if len(rows) != connection_count + 2:
        raise ValueError(f'{path.name} contains unexpected event rows')
    if (len(identities) != 1 or identities[0].get('role') != role or
            not isinstance(identities[0].get('pid'), int) or
            not identities[0].get('final_path')):
        raise ValueError(f'{path.name} has invalid process identity evidence')
    if len(connections) != connection_count or {
            row.get('index') for row in connections} != set(
                range(connection_count)):
        raise ValueError(f'{path.name} has incomplete connection evidence')
    if any(row.get('role') != role or
           not isinstance(row.get('success'), bool) for row in connections):
        raise ValueError(f'{path.name} has invalid connection evidence')
    nonces = [row.get('nonce') for row in connections]
    if (any(not isinstance(nonce, str) or not nonce for nonce in nonces) or
            len(set(nonces)) != connection_count or
            any(not isinstance(row.get('winsock_error'), int) or
                not isinstance(row.get('failure_stage'), str) or
                (row['success'] and (row['winsock_error'] != 0 or
                                     row['failure_stage'])) or
                (not row['success'] and not row['failure_stage'])
                for row in connections)):
        raise ValueError(f'{path.name} has invalid nonce/error evidence')
    failures = sum(row['success'] is False for row in connections)
    if required_failures == 'budget_pressure':
        if failures >= connection_count:
            raise ValueError(f'{path.name} has no successful connection')
    elif failures != required_failures:
        raise ValueError(
            f'{path.name} failures={failures}, expected={required_failures}')
    if any(row.get('peer') != peer for row in connections
           if row['success']):
        raise ValueError(f'{path.name} did not preserve the original peer')
    if (len(summaries) != 1 or summaries[0].get('role') != role or
            summaries[0].get('connections') != connection_count or
            summaries[0].get('failures') != failures or
            not isinstance(summaries[0].get('elapsed_ms'), int) or
            summaries[0]['elapsed_ms'] < minimum_elapsed_ms):
        raise ValueError(f'{path.name} has an invalid summary')
    return {'connections': connection_count,
            'successes': connection_count - failures,
            'failures': failures}


def validate_runtime_log(text):
    required = (
        'PROCESS_REDIRECT_READY',
        'PROCESS_REDIRECT_WINDIVERT_BASELINE',
        'PROCESS_REDIRECT_QUIESCENCE_OK',
        'PROCESS_REDIRECT_AUDIT_SUMMARY',
    )
    missing = [event for event in required if event not in text]
    if missing:
        raise ValueError(
            'FakeNet structured evidence is missing: ' + ', '.join(missing))
    forbidden = (
        'PROCESS_REDIRECT_SUSPEND',
        'PROCESS_REDIRECT_RESUME',
        'reason=route_query_',
        'reason=route_snapshot_changed',
        'reason=policy_exception',
        'Traceback (most recent call last):',
        'UnicodeDecodeError:',
    )
    unexpected = [marker for marker in forbidden if marker in text]
    if unexpected:
        raise ValueError(
            'FakeNet log contains unexpected runtime evidence: ' +
            ', '.join(unexpected))
    return []


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--pcap', type=pathlib.Path, required=True)
    parser.add_argument('--log', type=pathlib.Path, required=True)
    parser.add_argument('--original', type=ipaddress.IPv4Address, required=True)
    parser.add_argument('--target', type=ipaddress.IPv4Address, required=True)
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--target-client-log', type=pathlib.Path, required=True)
    parser.add_argument('--negative-client-log', type=pathlib.Path,
                        required=True)
    parser.add_argument('--owner-client-log', type=pathlib.Path, required=True)
    parser.add_argument('--burst-client-log', type=pathlib.Path, required=True)
    args = parser.parse_args()
    original = args.original.packed
    target = args.target.packed
    counts = {'original': 0, 'target': 0, 'target_port': 0}
    for frame in iter_packets(args.pcap):
        packet = decode_ipv4(frame)
        if packet is None:
            continue
        if packet.src == original or packet.dst == original:
            counts['original'] += 1
        if packet.src == target or packet.dst == target:
            counts['target'] += 1
            tcp = packet.data if isinstance(packet.data, dpkt.tcp.TCP) else None
            if tcp and args.port in (tcp.sport, tcp.dport):
                counts['target_port'] += 1
    text = args.log.read_text(encoding='utf-8', errors='replace')
    mappings = len(re.findall(r'PROCESS_REDIRECT_MAPPING_CREATED', text))
    try:
        missing = validate_runtime_log(text)
    except ValueError as exc:
        raise SystemExit(str(exc))
    peer = f'{args.original}:{args.port}'
    try:
        positive = validate_client_log(
            args.target_client_log, 'target', 1, peer, 0)
        negative = validate_client_log(
            args.negative_client_log, 'non-target', 1, peer, 1)
        owner = validate_client_log(
            args.owner_client_log, 'target', 10000, peer, 0, 399960)
        burst = validate_client_log(
            args.burst_client_log, 'target', 64, peer, 'budget_pressure')
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise SystemExit(f'client evidence is invalid: {exc}')
    minimum_mappings = (
        positive['successes'] + owner['successes'] + burst['successes'])
    budget_exhaustions = sum(int(value) for value in re.findall(
        r'owner_query_budget_exhausted=(\d+)', text))
    print({**counts, 'mapping_events': mappings, 'missing_events': missing,
           'positive': positive, 'negative': negative, 'owner': owner,
           'burst': burst, 'minimum_mappings': minimum_mappings,
           'budget_exhaustions': budget_exhaustions})
    if counts['original'] != 0:
        raise SystemExit('wire capture contains traffic to/from original A')
    if counts['target'] == 0 or counts['target_port'] == 0:
        raise SystemExit('wire capture does not contain reviewed B traffic')
    if mappings < minimum_mappings or missing:
        raise SystemExit('FakeNet structured evidence is incomplete')
    if budget_exhaustions < 1:
        raise SystemExit('synchronized burst did not exercise owner-budget denial')
    if counts['target'] > 200000:
        raise SystemExit('B packet volume suggests reinjection loop or amplification')
    return 0


if __name__ == '__main__':
    sys.exit(main())
