# Copyright 2026 Google LLC
"""P03 unit tests: exclusion clause, snapshot, baseline schema, recovery."""

import json

import pytest

from fakenet.mcp.baseline import BASELINE_FIELDS
from fakenet.mcp.controlfilter import (ControlFilterError,
                                       apply_control_link_exclusion,
                                       build_control_link_exclusion_clause)
from fakenet.mcp.snapshot import SnapshotError, StateSnapshot
from fakenet.mcp.supervisor import perform_startup_recovery


def test_clause_built_for_valid_pair():
    assert build_control_link_exclusion_clause('192.168.204.1', 28788) == \
        '(ip.DstAddr != 192.168.204.1 or (tcp.SrcPort != 28788))'
    assert build_control_link_exclusion_clause(
        '192.168.204.1', '28788,28787') == \
        '(ip.DstAddr != 192.168.204.1 or ' \
        '(tcp.SrcPort != 28788 and tcp.SrcPort != 28787))'


def test_apply_exclusion_known_shapes():
    negative = ('(ip.DstAddr != 192.168.204.1 or (tcp.SrcPort != 28788))')
    assert apply_control_link_exclusion(
        'outbound and ip', '192.168.204.1', '28788') == \
        'outbound and ip and %s' % negative
    assert apply_control_link_exclusion(
        'outbound and (ip or ipv6)', '192.168.204.1', '28788') == \
        '(outbound and ip and %s) or (outbound and ipv6)' % negative
    rebuilt = ('(outbound and (ip or ipv6)) or (inbound and ip and '
               'ip.SrcAddr == 1.2.3.4 and ip.DstAddr == 5.6.7.8 and '
               'ip.Protocol == 6)')
    applied = apply_control_link_exclusion(
        rebuilt, '192.168.204.1', '28788')
    assert applied.startswith(
        '(outbound and ip and %s) or (outbound and ipv6) or (' % negative)
    assert apply_control_link_exclusion(
        'outbound and ip', '', '') == 'outbound and ip'


def test_apply_exclusion_unknown_shape_fails_closed():
    with pytest.raises(ControlFilterError):
        apply_control_link_exclusion(
            'something else entirely', '192.168.204.1', '28788')


def test_clause_none_when_unset():
    assert build_control_link_exclusion_clause('', '') is None
    assert build_control_link_exclusion_clause(None, None) is None


@pytest.mark.parametrize('ip,port', [
    ('', '28788'), ('192.168.204.1', ''), ('192.168.204.1', 'x'),
    ('192.168.204.01', '28788'), ('::ffff:192.168.204.1', '28788'),
    ('not-an-ip', '28788'), ('192.168.204.1/24', '28788')])
def test_clause_fails_closed(ip, port):
    with pytest.raises(ControlFilterError):
        build_control_link_exclusion_clause(ip, port)


def test_snapshot_roundtrip_and_atomic_replace(tmp_path):
    snapshot = StateSnapshot(tmp_path / 'state' / 'state.json')
    snapshot.write(run_id='r1', controller_id='c', state_version=3,
                   command_id=None, config_sha256='deadbeef',
                   baseline_path='/b.json', needs_recovery=True)
    data, corrupt = snapshot.read()
    assert corrupt is False
    assert data['run_id'] == 'r1' and data['needs_recovery'] is True
    leftovers = [item.name for item in (tmp_path / 'state').iterdir()]
    assert leftovers == ['state.json']


def test_snapshot_requires_all_fields(tmp_path):
    snapshot = StateSnapshot(tmp_path / 'state.json')
    with pytest.raises(SnapshotError):
        snapshot.write(run_id='r')


def test_snapshot_detects_corrupt(tmp_path):
    snapshot = StateSnapshot(tmp_path / 'state.json')
    snapshot.write(run_id='r1', controller_id=None, state_version=1,
                   command_id=None, config_sha256='x', baseline_path='',
                   needs_recovery=False)
    (tmp_path / 'state.json').write_text('{broken', encoding='utf-8')
    data, corrupt = snapshot.read()
    assert data is None and corrupt is True


def test_baseline_schema_covers_frozen_fields(tmp_path):
    from fakenet.mcp.baseline import BaselineStore

    store = BaselineStore(tmp_path / 'baselines')
    record = store.save('run-1', sections={
        field: 'value-%s' % field for field in BASELINE_FIELDS})
    assert set(record['fields']) == set(BASELINE_FIELDS)
    loaded = store.load('run-1')
    assert loaded['run_id'] == 'run-1'
    assert set(loaded['sections']) == set(BASELINE_FIELDS)


def test_recovery_stopped_when_no_marker(tmp_path):
    snapshot = StateSnapshot(tmp_path / 'state.json')
    snapshot.write(run_id='r1', controller_id=None, state_version=1,
                   command_id=None, config_sha256='x', baseline_path='',
                   needs_recovery=False)
    view = _View()
    assert perform_startup_recovery(snapshot, None, view) == 'stopped'


def test_recovery_clean_when_baseline_matches(tmp_path):
    from fakenet.mcp.baseline import BaselineStore

    store = BaselineStore(tmp_path / 'baselines')
    store.save('r1', sections={field: '' for field in BASELINE_FIELDS})
    snapshot = StateSnapshot(tmp_path / 'state.json')
    snapshot.write(run_id='r1', controller_id='c', state_version=2,
                   command_id=None, config_sha256='x',
                   baseline_path=str(tmp_path / 'baselines'),
                   needs_recovery=True)
    view = _View()
    # monkeypatch capture to the same empty sections
    import fakenet.mcp.baseline as baseline_module

    original = baseline_module.capture
    baseline_module.capture = lambda: {
        field: '' for field in BASELINE_FIELDS}
    try:
        assert perform_startup_recovery(snapshot, store, view) == 'stopped'
    finally:
        baseline_module.capture = original
    data, _ = snapshot.read()
    assert data['needs_recovery'] is False


def test_recovery_failed_when_environment_differs(tmp_path):
    from fakenet.mcp.baseline import BaselineStore

    store = BaselineStore(tmp_path / 'baselines')
    store.save('r1', sections={field: '' for field in BASELINE_FIELDS})
    snapshot = StateSnapshot(tmp_path / 'state.json')
    snapshot.write(run_id='r1', controller_id='c', state_version=2,
                   command_id=None, config_sha256='x',
                   baseline_path=str(tmp_path / 'baselines'),
                   needs_recovery=True)
    import fakenet.mcp.baseline as baseline_module

    original = baseline_module.capture
    baseline_module.capture = lambda: {
        field: 'changed' for field in BASELINE_FIELDS}
    view = _View()
    try:
        assert perform_startup_recovery(snapshot, store, view) == 'failed'
    finally:
        baseline_module.capture = original


def test_recovery_failed_when_snapshot_corrupt_with_residue(tmp_path):
    (tmp_path / 'state.json').write_text('corrupt{', encoding='utf-8')
    snapshot = StateSnapshot(tmp_path / 'state.json')
    view = _View()
    assert perform_startup_recovery(snapshot, None, view) == 'failed'


class _View:
    def __init__(self):
        self._failure_reason = None
