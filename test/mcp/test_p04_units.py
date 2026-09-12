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


def test_incident_manifest_schema(tmp_path, monkeypatch):
    from fakenet.mcp import incident
    def unavailable(*args, **kwargs):
        raise RuntimeError('external collector unavailable in schema test')
    monkeypatch.setattr(incident, '_run', unavailable)
    collector = IncidentCollector(tmp_path, 'run-x')
    context = {'timeline': [{'kind': 'x'}], 'versions': {'python': '3'},
               'config_path': None, 'stdout_stderr': 'out',
               'run_log': '', 'exception_text': 'Traceback',
               'managed_thread_stacks': 'Thread 123: managed_loop',
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
    assert {entry['item'] for entry in ok_entries} == {
        'timeline.json', 'versions.json', 'stdout_stderr.log',
        'exception.txt', 'thread_stacks.txt', 'baseline_diff.json',
        'artifact_metadata.json'}
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


def test_fault_injector_diverter_stop_closes_handle(tmp_path, monkeypatch):
    import os
    monkeypatch.setenv('PROGRAMDATA', str(tmp_path))
    monkeypatch.chdir(tmp_path)
    os.environ['FAKENETNG_MCP_FAULT_INJECTION'] = '1'
    try:
        injector = FaultInjector()
        injector.arm('diverter_stop')

        class FakeHandle:
            closed = False

            def close(self):
                self.closed = True

        handle = FakeHandle()
        class FakeDiverter:
            def __init__(self, handle):
                self.handle = handle

            def _close_windivert_handle(self):
                self.handle.close()
                self.handle = None

        diverter = FakeDiverter(handle)
        assert injector.inject_diverter_stop(diverter) is True
        assert handle.closed and diverter.handle is None
        # one-shot: re-arming cleared
        diverter2 = FakeDiverter(FakeHandle())
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


def test_bounded_audit_preserves_transient_observation_and_requires_exact_return(tmp_path, monkeypatch):
    from fakenet.mcp import baseline
    sections = {field: 'baseline' for field in BASELINE_FIELDS}
    sections['listen_ports'] = 'UDP 0.0.0.0:50000 *:* 123'
    store = baseline.BaselineStore(tmp_path / 'baselines')
    store.save('run', sections)
    dirty = dict(sections, listen_ports=sections['listen_ports'] + '\nUDP 0.0.0.0:51000 *:* 456')
    observations = iter([dirty, sections, sections])
    monkeypatch.setattr(baseline, 'capture', lambda deadline: next(observations))
    monkeypatch.setattr(baseline.time, 'sleep', lambda seconds: None)
    assert store.full_audit_diff('run', settle_seconds=1) == {}
    rows = [json.loads(line) for line in next((tmp_path / 'logs').glob('*.jsonl')).read_text().splitlines()]
    assert len(rows) == 3 and rows[0]['current'] == dirty
    assert rows[0]['differences']['listen_ports']
    assert rows[1]['differences'] == rows[2]['differences'] == {}


def test_bounded_audit_never_waives_persistent_udp_residue(tmp_path, monkeypatch):
    from fakenet.mcp import baseline
    sections = {field: 'baseline' for field in BASELINE_FIELDS}
    sections['listen_ports'] = 'UDP 0.0.0.0:50000 *:* 123'
    store = baseline.BaselineStore(tmp_path / 'baselines')
    store.save('run', sections)
    dirty = dict(sections, listen_ports=sections['listen_ports'] + '\nUDP 0.0.0.0:51000 *:* 456')
    monkeypatch.setattr(baseline, 'capture', lambda deadline: dirty)
    assert 'listen_ports' in store.full_audit_diff('run', settle_seconds=0.01)


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


@pytest.mark.parametrize('change', [
    {'listen_ports': 'UDP 0.0.0.0:55555 *:* 222'},
    {'listen_ports': 'TCP 0.0.0.0:55555 0.0.0.0:0 LISTENING 222'},
    {'listen_ports': ''},
    {'routes': '0.0.0.0 0.0.0.0 10.0.0.1 10.0.0.2 35'},
    {'services': '[{"Name":"Dnscache","Status":1}]'},
])
def test_complete_audit_retains_previously_exempted_changes(change):
    before = {field: 'same' for field in BASELINE_FIELDS}
    before.update(listen_ports='TCP 0.0.0.0:29094 0.0.0.0:0 LISTENING 111',
                  routes='0.0.0.0 0.0.0.0 10.0.0.1 10.0.0.2 25',
                  services='[{"Name":"Dnscache","Status":4}]')
    after = dict(before, **change)
    assert set(audit_compare(before, after)) == set(change)


@pytest.mark.parametrize('missing', BASELINE_FIELDS)
def test_missing_baseline_section_never_passes(missing):
    complete = {field: '' for field in BASELINE_FIELDS}
    absent = dict(complete)
    del absent[missing]
    assert audit_compare(absent, complete)[missing]['collection_failed']
    assert audit_compare(complete, absent)[missing]['collection_failed']


def test_capture_nonzero_with_partial_stdout_is_failure(monkeypatch):
    import subprocess
    from fakenet.mcp import baseline
    monkeypatch.setattr(baseline.subprocess, 'run', lambda *a, **kw:
                        subprocess.CompletedProcess([], 1, 'partial', 'error'))
    assert baseline._run(['collector']) == baseline.COLLECTION_FAILED
