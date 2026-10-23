#!/usr/bin/env python3
"""Independent judge for the headless policy driver result.

The oracle re-reads the original configuration, log and PCAP named by the
result, verifies their hashes, and only then inspects the check table.  A
fixture result is accepted only when the caller explicitly asks for the
fixture contract; production judging rejects it.
"""
from __future__ import annotations

import json
from pathlib import Path

SCHEMA = 'fakenet.policy-result.v1'
APPLICATION_CHECKS = {'tls_application', 'reviewed_ip_tls', 'sink_tcp',
                      'sink_udp'}
DNS_CHECKS = {'exact_domain', 'wildcard_domain', 'apex_denied',
              'default_deny'}
SINK = '192.0.2.50'
REVIEWED = '192.0.2.10'
STATUS = ('pass', 'fail', 'unknown', 'not_run', 'blocked', 'skip',
          'observed')


def _sha256(path):
    import hashlib
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _read(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def _safe_file(original, item, label):
    if not isinstance(item, dict):
        raise ValueError('%s reference missing' % label)
    relative = item.get('path')
    if not isinstance(relative, str) or Path(relative).is_absolute():
        raise ValueError('%s path is not relative' % label)
    path = (Path(original) / relative).resolve()
    if not path.is_relative_to(Path(original).resolve()):
        raise ValueError('%s path escapes original directory' % label)
    if path.is_symlink() or not path.is_file():
        raise ValueError('%s original is missing' % label)
    if item.get('sha256') != _sha256(path):
        raise ValueError('%s original hash changed' % label)
    return path


def _pcap_count(path):
    data = Path(path).read_bytes()
    if len(data) < 24:
        raise ValueError('PCAP header is truncated')
    if data[:4] not in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'):
        raise ValueError('PCAP magic is invalid')
    return 0


def evaluate(original, scenario, checks, *, allow_fixture=False):
    source = Path(original) / 'policy-result.json'
    value = _read(source)
    if value.get('schema') != SCHEMA:
        raise ValueError('unknown policy result schema')
    if value.get('scenario') != scenario:
        raise ValueError('policy scenario mismatch')
    if value.get('fixture') is True and not allow_fixture:
        raise ValueError('fixture result cannot be used as native credit')
    _safe_file(original, value.get('config'), 'configuration')
    _safe_file(original, value.get('log'), 'core log')
    pcap = value.get('pcap')
    if pcap is not None:
        _safe_file(original, pcap, 'PCAP')
        _pcap_count((Path(original) / pcap['path']).resolve())
    attempts = value.get('attempts')
    if not isinstance(attempts, list):
        raise ValueError('attempt table missing')
    attempt_by_id = {}
    for item in attempts:
        if not isinstance(item, dict) or not isinstance(item.get('id'), str):
            raise ValueError('invalid attempt row')
        if item['id'] in attempt_by_id:
            raise ValueError('duplicate attempt id: %s' % item['id'])
        if not isinstance(item.get('nonce'), str) or not item['nonce']:
            raise ValueError('attempt nonce missing: %s' % item['id'])
        attempt_by_id[item['id']] = item

    rows = []
    seen = set()
    for item in value.get('checks') or []:
        if not isinstance(item, dict) or not isinstance(item.get('id'), str):
            raise ValueError('invalid policy check row')
        name = item['id']
        status = item.get('status')
        if status not in STATUS:
            raise ValueError('invalid policy check status')
        if name not in checks:
            rows.append({'id': name, 'status': status})
            continue
        if name in seen:
            rows.append({'id': name, 'status': 'fail'})
            continue
        seen.add(name)
        valid = (status == 'pass'
                 and item.get('attempt') is True
                 and item.get('observation') is True
                 and isinstance(item.get('nonce'), str) and item['nonce']
                 and isinstance(item.get('tuple'), dict)
                 and {'proto', 'src', 'dst', 'port'} <= set(item['tuple']))
        attempt = attempt_by_id.get(name)
        if valid and attempt is None:
            valid = False
        elif valid and attempt.get('nonce') != item.get('nonce'):
            valid = False
        elif valid and not isinstance(item.get('evidence'), list):
            valid = False
        if name in APPLICATION_CHECKS:
            application = item.get('application')
            valid = valid and isinstance(application, dict) and \
                application.get('bytes_out', 0) > 0 and \
                application.get('bytes_in', 0) > 0 and \
                application.get('nonce_echo') is True
        if valid:
            rows.append({'id': name, 'status': 'pass'})
        else:
            rows.append({'id': name,
                         'status': status if status != 'pass' else 'unknown'})
    for name in checks:
        if name not in seen:
            rows.append({'id': name, 'status': 'not_run'})
    cleanup = value.get('cleanup') or {}
    process_exit = cleanup.get('process_exit') or {}
    clean = (pcap is not None
             and value.get('stopped') is True
             and value.get('network_restored') is True
             and cleanup.get('source') == 'driver'
             and process_exit.get('exited') is True
             and process_exit.get('timed_out') is False
             and process_exit.get('returncode') == 0)
    return rows, clean
