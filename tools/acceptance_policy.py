#!/usr/bin/env python3
"""Headless egress-policy driver and its deterministic fixture.

The production path owns one configuration and one bounded core lifecycle:
create the INI from the reviewed Windows template, start the core with a stop
flag, wait for the scenario readiness marker, run bounded probes, stop the
core, and write one result carrying the original config/log/PCAP references.

This round implements the configuration/lifecycle/oracle contract and the
fixture adapter, but does not invent live probe results.  If the real probe
set is unavailable, every check is recorded as ``not_run``; the independent
judge then refuses to turn that into a pass.  ``--fixture`` is only for the
offline adapter contract and is rejected by the production oracle.
"""
from __future__ import annotations

import argparse
import configparser
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = 'fakenet.policy-result.v1'
TEMPLATES = {
    'domain': 'domain_reviewed_ipv4_windows.ini',
    'ipv4': 'domain_reviewed_ipv4_windows.ini',
    'takeover': 'domain_takeover_windows.ini',
    'combined': 'domain_takeover_windows.ini',
}
READY = {
    'domain': 'EGRESS_CONTROL_READY',
    'ipv4': 'IP_ALLOW_READY',
    'takeover': 'DOMAIN_TAKEOVER_READY',
    'combined': 'DOMAIN_TAKEOVER_READY',
}
CHECKS = {
    'domain': ['exact_domain', 'wildcard_domain', 'apex_denied',
               'default_deny', 'tls_application'],
    'ipv4': ['reviewed_ip_tls', 'port_80_denied', 'port_444_denied',
             'udp443_denied', 'other_ip_denied'],
    'takeover': ['sink_tcp', 'sink_udp', 'adjacent_denied', 'icmp_denied',
                 'ipv6_denied', 'route_restore'],
    'combined': ['exact_domain', 'wildcard_domain', 'reviewed_ip_tls',
                 'sink_tcp', 'sink_udp', 'route_restore'],
}
APPLICATION_CHECKS = {'tls_application', 'reviewed_ip_tls', 'sink_tcp',
                      'sink_udp'}
ALLOWED = 'api.example.test'
WILDCARD = '*.example.test'
APEX = 'example.test'
DENIED = 'denied.example.test'
SINK = '192.0.2.50'
REVIEWED = '192.0.2.10'


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _now():
    return datetime.now(timezone.utc).isoformat()


def _template(scenario):
    path = ROOT / 'fakenet' / 'configs' / TEMPLATES[scenario]
    if not path.is_file():
        raise ValueError('reviewed policy template is missing: %s' % path)
    return path


def _base_config(scenario):
    parser = configparser.ConfigParser(interpolation=None)
    parser.optionxform = str
    parser.read(_template(scenario), encoding='utf-8-sig')
    return parser


def config_text(scenario, output=None):
    """Return a deterministic reviewed configuration, no GUI writer."""
    parser = _base_config(scenario)
    diverter = parser['Diverter']
    diverter['ExternalAllowedDomains'] = '%s, %s' % (ALLOWED, WILDCARD)
    diverter['ExternalAllowedTCPPorts'] = '443'
    diverter['ExternalNonAllowedAction'] = 'Divert'
    diverter['DumpPackets'] = 'Yes'
    prefix = str(Path(output) / 'policy') if output else 'policy'
    diverter['DumpPacketsFilePrefix'] = prefix
    if scenario in ('ipv4', 'combined'):
        diverter['ExternalAllowedIPv4'] = REVIEWED
    if scenario in ('takeover', 'combined'):
        diverter['ExternalTakeoverIPv4'] = SINK
        diverter['ExternalTakeoverDnsTTL'] = '60'
        diverter['ExternalTakeoverProbeTCPPorts'] = '18080'
        for section in parser.sections():
            if parser[section].get('Listener') == 'DNSListener':
                parser[section]['ResponseA'] = SINK
    # A placeholder is never a usable target value.  The production caller
    # must provide the already verified upstream through an environment
    # reference; fixture runs do not start the core.
    if diverter.get('ExternalDnsServer') == '__EXTERNAL_DNS__':
        diverter['ExternalDnsServer'] = '192.0.2.2'
    from io import StringIO
    stream = StringIO()
    parser.write(stream, space_around_delimiters=True)
    return stream.getvalue()


def _fixture_rows(scenario, nonce):
    rows = []
    for index, name in enumerate(CHECKS[scenario]):
        application = None
        if name in APPLICATION_CHECKS:
            application = {'bytes_out': 12, 'bytes_in': 24,
                           'nonce_echo': True}
        if name in ('exact_domain', 'wildcard_domain', 'apex_denied',
                    'default_deny'):
            proto, destination, port = 'UDP', '127.0.0.1', 53
        elif name == 'sink_tcp':
            proto, destination, port = 'TCP', SINK, 18080
        elif name == 'sink_udp':
            proto, destination, port = 'UDP', SINK, 18080
        elif name == 'adjacent_denied':
            proto, destination, port = 'UDP', '192.0.2.51', 65000
        elif name in ('icmp_denied', 'ipv6_denied'):
            proto, destination, port = 'ICMP', SINK, 0
        elif name == 'route_restore':
            proto, destination, port = 'NONE', SINK, 0
        else:
            proto, destination, port = 'TCP', REVIEWED, 443
        rows.append({
            'id': name, 'status': 'pass', 'attempt': True,
            'observation': True, 'nonce': '%s-%d' % (nonce, index),
            'tuple': {'proto': proto, 'src': '127.0.0.1',
                      'dst': destination, 'port': port},
            'application': application,
            'evidence': ['policy.pcap', 'core.log'],
        })
    return rows


def _cleanup(process_exit, stopped, restored):
    return {'source': 'driver', 'resources': ['core', 'network', 'capture'],
            'process_exit': process_exit, 'stopped': stopped,
            'network_restored': restored, 'temp_roots': []}


def fixture(scenario, output):
    """Write the adapter contract only; never native credit."""
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    config = output / 'policy.ini'
    config.write_text(config_text(scenario, output), encoding='utf-8')
    log = output / 'core.log'
    log.write_text('%s policy fixture ready\n' % READY[scenario],
                   encoding='utf-8')
    pcap = output / 'policy.pcap'
    pcap.write_bytes(b'\xd4\xc3\xb2\xa1' + b'\x02\x00\x04\x00' +
                     b'\x00' * 8 + b'\xff\xff\x00\x00' +
                     b'\x01\x00\x00\x00')
    nonce = 'fixture-' + scenario
    result = {
        'schema': SCHEMA, 'scenario': scenario, 'fixture': True,
        'config': {'path': 'policy.ini', 'sha256': sha256(config)},
        'log': {'path': 'core.log', 'sha256': sha256(log)},
        'pcap': {'path': 'policy.pcap', 'sha256': sha256(pcap),
                 'packets': 0},
        'attempts': [{'id': name, 'nonce': '%s-%d' % (nonce, index),
                      'started_at': _now(), 'ended_at': _now()}
                     for index, name in enumerate(CHECKS[scenario])],
        'checks': _fixture_rows(scenario, nonce),
        'stopped': True, 'network_restored': True,
        'cleanup': _cleanup({'exited': True, 'returncode': 0,
                             'timed_out': False}, True, True),
    }
    (output / 'policy-result.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n',
        encoding='utf-8')
    return 0


def _wait_ready(log_path, marker, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if Path(log_path).is_file() and marker in Path(log_path).read_text(
                encoding='utf-8', errors='replace'):
            return True
        time.sleep(0.2)
    return False


def run(scenario, output, core_command, timeout):
    """Run the fixed lifecycle, but never fabricate unavailable probe credit."""
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    config = output / 'policy.ini'
    config.write_text(config_text(scenario, output), encoding='utf-8')
    stop = output / 'stop.flag'
    log = output / 'core.log'
    command = list(core_command) + ['-c', str(config), '-l', str(log),
                                    '-f', str(stop), '-p', '-v']
    process = subprocess.Popen(command, shell=False)
    exited = False
    code = None
    try:
        if not _wait_ready(log, READY[scenario], timeout):
            raise RuntimeError('core readiness marker was not observed')
        # The reviewed live probe set requires the bound Windows target and
        # controlled upstream.  It is intentionally not claimed here.
        time.sleep(0.5)
    finally:
        stop.write_text('stop\n', encoding='utf-8')
        try:
            code = process.wait(timeout=30)
            exited = True
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                code = process.wait(timeout=10)
                exited = True
            except subprocess.TimeoutExpired:
                pass
    pcap = sorted(output.glob('policy*.pcap'))
    rows = [{'id': name, 'status': 'not_run', 'attempt': False,
             'observation': False, 'nonce': '',
             'reason': 'live policy probes are not implemented'}
            for name in CHECKS[scenario]]
    result = {
        'schema': SCHEMA, 'scenario': scenario, 'fixture': False,
        'config': {'path': 'policy.ini', 'sha256': sha256(config)},
        'log': {'path': 'core.log', 'sha256': sha256(log)},
        'pcap': ({'path': pcap[0].name, 'sha256': sha256(pcap[0])}
                 if pcap else None),
        'attempts': [],
        'checks': rows,
        'stopped': exited,
        'network_restored': False,
        'cleanup': _cleanup({'exited': exited, 'returncode': code,
                             'timed_out': not exited},
                            exited, False),
    }
    (output / 'policy-result.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n',
        encoding='utf-8')
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scenario', choices=sorted(CHECKS), required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--fixture', action='store_true')
    parser.add_argument('--python', default=sys.executable)
    parser.add_argument('--timeout', type=int, default=60)
    args = parser.parse_args(argv)
    if args.fixture:
        return fixture(args.scenario, args.output)
    return run(args.scenario, args.output,
               [args.python, '-m', 'fakenet.fakenet'], args.timeout)


if __name__ == '__main__':
    raise SystemExit(main())
