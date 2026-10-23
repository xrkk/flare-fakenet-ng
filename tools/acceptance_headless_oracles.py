#!/usr/bin/env python3
"""Independent oracle for headless process-redirect and payload evidence."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

SCHEMA = 'fakenet.headless-result.v1'
PROCESS_CHECKS = {'identity', 'target-positive', 'non-target-negative',
                  'owner-bounded', 'budget', 'pcap-restore'}
PAYLOAD_CHECKS = {'integrity', 'report', 'reassembly'}


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _read(path):
    return Path(path).read_text(encoding='utf-8', errors='replace')


def _load(root, relative):
    import importlib.util
    import sys
    root = str(Path(root).resolve())
    if root not in sys.path:
        sys.path.insert(0, root)
    spec = importlib.util.spec_from_file_location(
        'headless_original_' + Path(relative).stem, Path(root) / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _safe(original, item, label):
    if not isinstance(item, str):
        raise ValueError('%s path missing' % label)
    path = (Path(original) / item).resolve() if not Path(item).is_absolute() \
        else Path(item).resolve()
    if not path.is_relative_to(Path(original).resolve()):
        raise ValueError('%s escapes output directory' % label)
    if path.is_symlink() or not path.is_file():
        raise ValueError('%s is missing' % label)
    return path


def evaluate_process(root, original, checks, allow_fixture=False):
    value = json.loads(_read(Path(original) / 'headless-result.json'))
    if value.get('schema') != SCHEMA or value.get('mode') != 'process':
        raise ValueError('process result schema/mode mismatch')
    if value.get('fixture') is True and not allow_fixture:
        raise ValueError('fixture process result cannot be native credit')
    verifier = _load(root, 'test/process_redirect_vm/verify_process_redirect.py')
    target = _safe(original, value['target']['path'], 'target PE')
    non_target = _safe(original, value['non_target']['path'], 'non-target PE')
    target_hash_ok = _sha256(target) == value['target']['sha256']
    non_target_hash_ok = _sha256(non_target) == value['non_target']['sha256']
    clients = value['clients']
    logs = {name: _safe(original, path, name + ' client log')
            for name, path in clients.items()}
    pcap = _safe(original, value['pcap'], 'wire capture')
    log = _safe(original, value['log'], 'core log')
    config = _safe(original, value['config'], 'session INI')
    inputs = value.get('inputs') or {}
    original_ip = inputs['original_ip']
    target_ip = inputs['target_ip']
    port = int(inputs['port'])
    peer = '%s:%d' % (original_ip, port)
    text = _read(log)
    counts = {'original': 0, 'target': 0, 'target_port': 0}
    for frame in verifier.iter_packets(pcap):
        packet = verifier.decode_ipv4(frame)
        if packet is None:
            continue
        if packet.src == bytes(map(int, original_ip.split('.'))) or \
                packet.dst == bytes(map(int, original_ip.split('.'))):
            counts['original'] += 1
        if packet.src == bytes(map(int, target_ip.split('.'))) or \
                packet.dst == bytes(map(int, target_ip.split('.'))):
            counts['target'] += 1
            import dpkt
            if isinstance(packet.data, dpkt.tcp.TCP) and port in (
                    packet.data.sport, packet.data.dport):
                counts['target_port'] += 1
    try:
        verifier.validate_runtime_log(text)
        positive = verifier.validate_client_log(
            logs['target'], 'target', 1, peer, 0)
        negative = verifier.validate_client_log(
            logs['non-target'], 'non-target', 1, peer, 1)
        owner = verifier.validate_client_log(
            logs['owner'], 'target', int(inputs['owner_flows']), peer, 0)
        burst = verifier.validate_client_log(
            logs['burst'], 'target', int(inputs['burst_flows']), peer,
            'budget_pressure')
        structural = True
        error = ''
    except Exception as exc:
        positive = negative = owner = burst = {}
        structural = False
        error = '%s: %s' % (type(exc).__name__, exc)
    mappings = len(re.findall(r'PROCESS_REDIRECT_MAPPING_CREATED', text))
    budget = sum(int(item) for item in re.findall(
        r'owner_query_budget_exhausted=(\d+)', text))
    identity_paths = True
    try:
        target_rows = verifier.read_jsonl(logs['target'])
        negative_rows = verifier.read_jsonl(logs['non-target'])
        target_identity = next(row for row in target_rows
                               if row.get('event') == 'identity')
        negative_identity = next(row for row in negative_rows
                                 if row.get('event') == 'identity')
        identity_paths = (
            Path(target_identity.get('final_path', '')).resolve() ==
            target.resolve() and
            Path(negative_identity.get('final_path', '')).resolve() ==
            non_target.resolve())
    except (OSError, ValueError, StopIteration, TypeError):
        identity_paths = False
    pe_ok = True
    if value.get('fixture') is not True:
        pe_ok = (target.read_bytes()[:2] == b'MZ' and
                 non_target.read_bytes()[:2] == b'MZ')
    identity_ok = (
        target_hash_ok and non_target_hash_ok and pe_ok and identity_paths and
        value['target']['sha256'] == inputs.get('target_sha256') and
        value['non_target']['sha256'] == inputs.get('non_target_sha256'))
    pcap_ok = (counts['original'] == 0 and counts['target'] > 0 and
               counts['target_port'] > 0)
    rows = {
        'identity': ('pass' if identity_ok else 'fail'),
        'target-positive': ('pass' if structural and positive.get('successes') == 1
                            else 'fail'),
        'non-target-negative': ('pass' if structural and negative.get('failures') == 1
                                else 'fail'),
        'owner-bounded': ('pass' if structural and owner.get('successes') ==
                          int(inputs['owner_flows']) else 'fail'),
        'budget': ('pass' if structural and burst.get('failures', 0) >= 1 and
                   burst.get('successes', 0) >= 1 and budget >= 1 else 'fail'),
        'pcap-restore': ('pass' if pcap_ok and structural else 'fail'),
    }
    out = [{'id': name, 'status': rows.get(name, 'fail')} for name in checks]
    cleanup = value.get('cleanup') or {}
    process = cleanup.get('process_exit') or {}
    clean = (value.get('stopped') is True and
             value.get('network_restored') is True and
             (value.get('network') or {}).get('match') is True and
             cleanup.get('source') == 'driver' and
             process.get('exited') is True and
             process.get('timed_out') is False and
             process.get('returncode') == 0 and
             all(row['status'] == 'pass' for row in out))
    return out, clean, {'error': error, 'counts': counts,
                        'mappings': mappings, 'budget': budget}


def evaluate_payload(root, original, checks, allow_fixture=False):
    value = json.loads(_read(Path(original) / 'headless-result.json'))
    if value.get('schema') != SCHEMA or value.get('mode') != 'payload':
        raise ValueError('payload result schema/mode mismatch')
    if value.get('fixture') is True and not allow_fixture:
        raise ValueError('fixture payload result cannot be native credit')
    paths = {name: _safe(original, value[name], name)
             for name in ('raw', 'converted', 'index', 'html', 'wire',
                          'expected', 'log', 'config')}
    report = _load(root, 'test/gui_vm/verify_payload_report.py')
    integrity = _load(root, 'test/gui_vm/verify_payload_integrity.py')
    reassembly = _load(root, 'test/gui_vm/verify_reassembly.py')
    errors = {}
    rows = {}
    try:
        report_result = report.verify(str(paths['html']),
                                      str(paths['expected']))
        rows['report'] = 'pass' if report_result.get('verdict') == 'PASS' else 'fail'
    except Exception as exc:
        rows['report'] = 'fail'
        errors['report'] = '%s: %s' % (type(exc).__name__, exc)
    try:
        integrity_result = integrity.verify(
            str(paths['raw']), str(paths['wire']), str(paths['html']),
            str(paths['log']), str(paths['config']),
            value.get('capture_started_at'))
        rows['integrity'] = ('pass' if integrity_result.get('verdict') == 'PASS'
                             and integrity_result.get('process_binding', {}).get(
                                 'verdict') == 'PASS' else 'fail')
    except Exception as exc:
        rows['integrity'] = 'fail'
        errors['integrity'] = '%s: %s' % (type(exc).__name__, exc)
    try:
        reassembly_result = reassembly.verify(
            str(paths['raw']), str(paths['index']),
            str(paths['converted']), str(paths['expected']))
        rows['reassembly'] = ('pass' if reassembly_result.get('verdict') == 'PASS'
                              else 'fail')
    except Exception as exc:
        rows['reassembly'] = 'fail'
        errors['reassembly'] = '%s: %s' % (type(exc).__name__, exc)
    out = [{'id': name, 'status': rows.get(name, 'fail')} for name in checks]
    cleanup = value.get('cleanup') or {}
    process = cleanup.get('process_exit') or {}
    clean = (value.get('stopped') is True and
             value.get('network_restored') is True and
             (value.get('network') or {}).get('match') is True and
             cleanup.get('source') == 'driver' and
             process.get('exited') is True and
             process.get('timed_out') is False and
             process.get('returncode') == 0 and
             all(row['status'] == 'pass' for row in out))
    return out, clean, {'errors': errors,
                        'rows': rows}


def evaluate(root, original, mode, checks, allow_fixture=False):
    if mode == 'process':
        return evaluate_process(root, original, checks, allow_fixture)
    if mode == 'payload':
        return evaluate_payload(root, original, checks, allow_fixture)
    raise ValueError('unknown headless mode')
