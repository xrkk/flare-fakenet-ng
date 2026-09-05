# Copyright 2026 Google LLC
"""P04 unit tests: incident pack, fault injector, full audit, draining."""

import json

import pytest

from fakenet.mcp import errors
from fakenet.mcp.baseline import BASELINE_FIELDS, audit_compare
from fakenet.mcp.config import ConfigError, ServiceConfig
from fakenet.mcp.coordination import Coordinator
from fakenet.mcp.faultinject import FAULTS, FaultInjector
from fakenet.mcp.incident import BASIC_ITEMS, IncidentCollector
from fakenet.mcp.testdouble import LifecycleDouble


def test_stop_grace_config_bounds():
    assert ServiceConfig(listen_ip='10.0.0.1', listen_port=1,
                         allowed_host_ips=['10.0.0.2'],
                         stop_grace_seconds=60).stop_grace_seconds == 60
    for bad in (4, 601, 0):
        with pytest.raises(ConfigError):
            ServiceConfig(listen_ip='10.0.0.1', listen_port=1,
                          allowed_host_ips=['10.0.0.2'],
                          stop_grace_seconds=bad)


def test_incident_manifest_schema(tmp_path):
    collector = IncidentCollector(tmp_path, 'run-x')
    context = {'timeline': [{'kind': 'x'}], 'versions': {'python': '3'},
               'config_path': None, 'stdout_stderr': 'out',
               'run_log': '', 'exception_text': 'Traceback',
               'final_filter': 'f', 'baseline_diff': {},
               'artifact_metadata': [], 'dump_reason': None}
    collector.collect(context)
    manifest = json.loads(
        (tmp_path / 'run-x' / 'incident' / 'manifest.json').read_text())
    names = {entry['item'] for entry in manifest['entries']}
    expected = {name for name, _ in BASIC_ITEMS} | {'userdump.dmp'}
    assert names == expected
    for entry in manifest['entries']:
        assert {'item', 'result', 'failure_reason', 'size', 'sha256'} <= \
            set(entry)
    ok_entries = [entry for entry in manifest['entries']
                  if entry['result'] == 'ok']
    assert len(ok_entries) >= 8
    for entry in ok_entries:
        assert entry['sha256'] and entry['size'] >= 0
    # config_snapshot and dump are explicitly recorded as unavailable/skip
    recorded = {entry['item']: entry['result']
                for entry in manifest['entries']}
    assert recorded['config_snapshot.ini'] == 'failed'
    assert recorded['userdump.dmp'] == 'skipped'


def test_fault_injector_requires_arm():
    injector = FaultInjector()
    assert injector.inject_diverter_stop(type('D', (), {'handle': 1})()) \
        is False


def test_fault_injector_diverter_stop_closes_handle():
    import os

    os.environ['FAKENETNG_MCP_FAULT_INJECTION'] = '1'
    try:
        injector = FaultInjector()
        injector.arm('diverter_stop')

        class FakeHandle:
            closed = False

            def close(self):
                self.closed = True

        handle = FakeHandle()
        diverter = type('D', (), {'handle': handle})()
        assert injector.inject_diverter_stop(diverter) is True
        assert handle.closed and diverter.handle is None
        # one-shot: re-arming cleared
        diverter2 = type('D', (), {'handle': FakeHandle()})()
        assert injector.inject_diverter_stop(diverter2) is False
    finally:
        os.environ.pop('FAKENETNG_MCP_FAULT_INJECTION', None)
        from fakenet.mcp import faultinject

        faultinject.clear()


def test_full_audit_normalize_ignores_pids_and_order():
    before = {'listen_ports': 'TCP 0.0.0.0:80 1.1.1.1:2 LISTENING 111\n'
                              'TCP 10.0.0.1:53 2.2.2.2:3 ESTABLISHED 9',
              'routes': 'a\nb\n', 'dns_servers': 'x\n',
              'windivert_processes': 'p1\n', 'services': 'dnscache Running'}
    after = {'listen_ports': 'TCP 0.0.0.0:80 1.1.1.1:2 LISTENING 999\n'
                             'TCP 10.0.0.1:53 8.8.8.8:1 ESTABLISHED 1',
             'routes': 'b\na\n', 'dns_servers': 'x',
             'windivert_processes': 'p1', 'services': 'dnscache Running'}
    assert audit_compare(before, after) == {}
    changed = dict(after)
    changed['listen_ports'] += '\nTCP 0.0.0.0:4444 0.0.0.0:0 LISTENING 5'
    diff = audit_compare(before, changed)
    assert set(diff) == {'listen_ports'}


def test_draining_rejects_new_mutations():
    coord = Coordinator(LifecycleDouble())
    coord.begin_draining()
    with pytest.raises(errors.McpError) as excinfo:
        coord.submit(command_id='x', expected_version=1, controller='A',
                     controller_valid=True, kind='k', describe={},
                     execute=lambda c: {})
    assert excinfo.value.code == errors.NOT_ALLOWED_IN_STATE


def test_incident_dump_escalation_bounded(tmp_path):
    """The escalation dump must terminate with an explicit manifest record
    on every platform (in-process MiniDumpWriteDump; never a cross-process
    suspension that can wedge the service)."""
    import sys

    collector = IncidentCollector(tmp_path, 'run-dump')
    context = {'timeline': [], 'versions': {}, 'config_path': None,
               'stdout_stderr': '', 'run_log': '', 'exception_text': 'x',
               'final_filter': None, 'baseline_diff': {},
               'artifact_metadata': [], 'dump_reason': 'unexplained'}
    collector.collect(context)
    manifest = json.loads(
        (tmp_path / 'run-dump' / 'incident' / 'manifest.json').read_text())
    entry = next(item for item in manifest['entries']
                 if item['item'] == 'userdump.dmp')
    assert entry['result'] in ('ok', 'failed', 'skipped')
    if sys.platform == 'win32' and entry['result'] == 'ok':
        assert entry['size'] > 0
    elif sys.platform != 'win32':
        assert entry['result'] == 'skipped'
        assert 'Windows' in (entry['failure_reason'] or '')


def test_audit_ignores_dynamic_range_listener_noise():
    """r54 round-18 stop-audit evidence: RPC/WMI endpoints in the dynamic
    port range flap transient LISTENING rows; they are OS noise, not
    FakeNet residue. Sub-1024 vanishing and any non-dynamic-range added
    listener remain attributable."""
    from fakenet.mcp.baseline import audit_compare

    before = {'listen_ports': 'TCP 0.0.0.0:135 0.0.0.0:0 LISTENING 972\n'
                              'TCP 0.0.0.0:49670 0.0.0.0:0 LISTENING 9'}
    # dynamic-range row appears + a TIME_WAIT style row never counts
    after = {'listen_ports': before['listen_ports'] +
             '\nTCP 0.0.0.0:49671 0.0.0.0:0 LISTENING 5'}
    assert audit_compare(before, after) == {}
    # a listener below the dynamic range appearing IS residue
    leaked = dict(after)
    leaked['listen_ports'] += '\nTCP 0.0.0.0:4444 0.0.0.0:0 LISTENING 5'
    delta = audit_compare(before, leaked)['listen_ports']
    assert any(':4444' in row for row in delta['fakenet_added'])
    # a vanished sub-1024 system listener IS attributable
    killed = {'listen_ports': 'TCP 0.0.0.0:49670 0.0.0.0:0 LISTENING 9'}
    delta = audit_compare(before, killed)['listen_ports']
    assert any(':135' in row for row in delta['below_1024_removed'])


def test_audit_routes_ignore_metric_flap():
    """Windows auto-tunes interface metrics around adapter
    reconfiguration; a metric-only change between baseline and audit is
    not a routing change (r54 round-18 / r56 round-2 evidence). A real
    route addition still flags."""
    from fakenet.mcp.baseline import audit_compare

    before = {'routes': '0.0.0.0 0.0.0.0 192.168.204.1 '
                        '192.168.204.149 281\n'
                        '192.168.204.0 255.255.255.0 On-link '
                        '192.168.204.149 281'}
    after = {'routes': '0.0.0.0 0.0.0.0 192.168.204.1 '
                       '192.168.204.149 286\n'
                       '192.168.204.0 255.255.255.0 On-link '
                       '192.168.204.149 281'}
    assert audit_compare(before, after) == {}
    hijack = {'routes': after['routes'] +
              '\n8.8.8.8 255.255.255.255 On-link 192.168.204.149 281'}
    assert 'routes' in audit_compare(after, hijack)
