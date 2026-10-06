# Copyright 2026 Google LLC
"""Run/type filtering for artifact queries keeps the byte-integrity contract.

Covers the frozen list_artifacts filter contract: the walk anchors to the
selected run's registered subtree so unselected files are never opened or
hashed, tamper detection and deadlines survive filtering, invalid filters
are structured rejections at both the tool and the diagnostic-worker
boundary, and an unknown-but-valid run is an empty match — never a silent
fallback to the full set.
"""

import hashlib
import os
import time
import uuid

import pytest

from fakenet.mcp import artifacts, diagnostic_tasks, tools as tools_module
from fakenet.mcp.errors import McpError

RUN_A = '11111111-aaaa-4bbb-8ccc-000000000001'
RUN_B = '22222222-aaaa-4bbb-8ccc-000000000002'
RUN_UNKNOWN = '33333333-aaaa-4bbb-8ccc-000000000003'


def _publish(directory, paths):
    return artifacts.write_publication(directory, paths)


def _build_tree(root):
    """Two registered runs: run_a stays under the serial threshold, run_b
    crosses it so the filtered pool path is exercised too."""
    run_a = root / RUN_A
    run_b = root / RUN_B
    run_a.mkdir(parents=True)
    run_b.mkdir(parents=True)
    published_a = []
    for index in range(12):
        path = run_a / ('evt-%02d.log' % index)
        path.write_bytes(bytes([index % 256]) * (index * 13 + 1))
        published_a.append(path)
    report = run_a / 'report-main.html'
    report.write_bytes(b'<html>ok</html>')
    published_a.append(report)
    _publish(run_a, published_a)
    published_b = []
    for index in range(18):
        path = run_b / ('capture-%02d.pcap' % index)
        path.write_bytes(b'pcap-%02d' % index * 8)
        published_b.append(path)
    _publish(run_b, published_b)
    return run_a, run_b


def test_run_filter_anchors_to_target_run_only(tmp_path):
    run_a, run_b = _build_tree(tmp_path)
    registry = artifacts.ArtifactRegistry(tmp_path)
    rows = registry.metadata(run_id=RUN_A)
    assert rows
    assert all(row['path'].startswith(str(run_a) + os.sep) for row in rows)
    assert not any(str(run_b) in row['path'] for row in rows)
    assert {row['type'] for row in rows} == {'log', 'report'}
    for row in rows:
        assert row['complete'] is True
        assert row['sha256']


def test_run_filter_reaches_bounded_pool_path(tmp_path):
    run_a, run_b = _build_tree(tmp_path)
    registry = artifacts.ArtifactRegistry(tmp_path)
    rows = registry.metadata(run_id=RUN_B)
    assert len(rows) == 18  # >= SERIAL_FILE_THRESHOLD: the pool verifies
    assert all(row['type'] == 'pcap' for row in rows)
    assert [row['path'] for row in rows] == sorted(row['path'] for row in rows)


def test_type_filter_is_precise_and_combines_with_run(tmp_path):
    _build_tree(tmp_path)
    registry = artifacts.ArtifactRegistry(tmp_path)
    pcaps = registry.metadata(artifact_type='pcap')
    assert pcaps and all(row['type'] == 'pcap' for row in pcaps)
    reports = registry.metadata(artifact_type='report')
    assert len(reports) == 1
    unknown_type = registry.metadata(artifact_type='nosuchtype')
    assert unknown_type == []
    combined = registry.metadata(run_id=RUN_A, artifact_type='log')
    assert len(combined) == 12
    assert all(row['type'] == 'log' for row in combined)


def test_unselected_files_are_never_opened_or_hashed(tmp_path, monkeypatch):
    run_a, run_b = _build_tree(tmp_path)
    real = artifacts._completion_from_entry
    hashed = []

    def observing(path, entry, deadline=None):
        hashed.append(path)
        return real(path, entry, deadline)

    monkeypatch.setattr(artifacts, '_completion_from_entry', observing)
    registry = artifacts.ArtifactRegistry(tmp_path)
    registry.metadata(run_id=RUN_A, artifact_type='log')
    assert hashed
    assert all(str(run_a) in str(path) for path in hashed)
    assert not any(str(run_b) in str(path) for path in hashed)
    # Type-filtered rows are dropped before any hash call.
    assert all(path.suffix == '.log' for path in hashed)


def test_equal_size_tamper_still_detected_within_filtered_run(tmp_path):
    run_a, _ = _build_tree(tmp_path)
    victim = run_a / 'evt-03.log'
    stamp = victim.stat()
    victim.write_bytes(bytes([7]) * victim.stat().st_size)
    os.utime(victim, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
    registry = artifacts.ArtifactRegistry(tmp_path)
    rows = {row['path']: row for row in registry.metadata(run_id=RUN_A)}
    assert rows[str(victim)]['complete'] is False
    assert rows[str(victim)]['sha256'] is None


def test_unknown_valid_run_is_empty_match_not_full_set(tmp_path):
    _build_tree(tmp_path)
    registry = artifacts.ArtifactRegistry(tmp_path)
    assert registry.metadata(run_id=RUN_UNKNOWN) == []
    # A missing run directory behaves the same: no fallback, no error.
    missing_root = tmp_path / 'empty-root'
    missing_root.mkdir()
    assert artifacts.ArtifactRegistry(missing_root).metadata(run_id=RUN_A) == []


def test_symlinked_run_anchor_is_not_followed(tmp_path):
    run_a, run_b = _build_tree(tmp_path)
    linked = tmp_path / RUN_UNKNOWN
    linked.symlink_to(run_b, target_is_directory=True)
    registry = artifacts.ArtifactRegistry(tmp_path)
    assert registry.metadata(run_id=RUN_UNKNOWN) == []
    # Unfiltered enumeration keeps its own no-symlink rule.
    assert not any(str(linked) in row['path'] for row in registry.metadata())


def test_no_filter_keeps_full_set_and_row_shape(tmp_path):
    _build_tree(tmp_path)
    registry = artifacts.ArtifactRegistry(tmp_path)
    rows = registry.metadata()
    assert len(rows) == 12 + 1 + 18
    assert set(rows[0]) == {'path', 'type', 'size', 'complete', 'sha256'}
    assert [row['path'] for row in rows] == sorted(row['path'] for row in rows)


def test_filtered_deadline_still_fails_closed(tmp_path):
    _build_tree(tmp_path)
    registry = artifacts.ArtifactRegistry(tmp_path)
    with pytest.raises(TimeoutError, match='deadline exceeded'):
        registry.metadata(run_id=RUN_A, deadline=time.monotonic() - 1)


# -- diagnostic-worker boundary (the real task code the IPC process runs) ----

def test_diagnostic_worker_validates_and_applies_filters(tmp_path, monkeypatch):
    _build_tree(tmp_path)
    # Point the worker's data root at the fixture tree: data_directories
    # derives <programdata>/FakeNet-NG-MCP/artifacts, so the registered
    # runs move there and the worker sees exactly them.
    monkeypatch.setenv('FAKENETNG_MCP_PROGRAMDATA', str(tmp_path))
    root = tmp_path / 'FakeNet-NG-MCP' / 'artifacts'
    root.mkdir(parents=True, exist_ok=True)
    (tmp_path / RUN_A).rename(root / RUN_A)
    (tmp_path / RUN_B).rename(root / RUN_B)
    deadline = time.monotonic() + 30
    rows = diagnostic_tasks.execute(
        'list-artifacts', {'run_id': RUN_A, 'artifact_type': 'report'},
        deadline)
    assert len(rows) == 1
    assert rows[0]['path'].endswith('report-main.html')


def test_diagnostic_worker_rejects_invalid_filters():
    for payload in (
            {'run_id': '../escape'},
            {'run_id': 'not-a-uuid'},
            {'run_id': RUN_A.upper()},
            {'run_id': 123},
            {'artifact_type': ''},
            {'artifact_type': 7},
    ):
        with pytest.raises(ValueError):
            diagnostic_tasks.execute(
                'list-artifacts', payload, time.monotonic() + 30)


# -- tool-boundary validation -------------------------------------------------

def test_tool_boundary_run_id_and_type_validation():
    assert tools_module._validated_run_id(None) is None
    assert tools_module._validated_run_id(RUN_A) == RUN_A
    fresh = str(uuid.uuid4())
    assert tools_module._validated_run_id(fresh) == fresh
    for bad in ('../escape', 'not-a-uuid', RUN_A.upper(), 123, ''):
        with pytest.raises(McpError) as excinfo:
            tools_module._validated_run_id(bad)
        assert excinfo.value.code == 'invalid_request'
    assert tools_module._validated_artifact_type(None) is None
    assert tools_module._validated_artifact_type('pcap') == 'pcap'
    for bad in ('', 7, b'pcap'):
        with pytest.raises(McpError):
            tools_module._validated_artifact_type(bad)
