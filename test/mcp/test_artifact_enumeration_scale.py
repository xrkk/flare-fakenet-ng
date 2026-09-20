"""Artifact enumeration scale/optimization keeps the byte-integrity contract.

Regression set for the scandir/streaming-hash metadata walk:

* same kept-set, same sorted(Path) order, same five fields as the previous
  ``sorted(root.rglob('*'))`` walk (a reference implementation in the test);
* every published file still has its CURRENT bytes re-hashed on every call —
  equal-size tampering with restored mtimes must be caught on the next call
  (defeats any cross-request digest cache or mtime shortcut), including for
  files larger than one hash chunk (defeats skip-the-big-file shortcuts);
* unpublished directories, corrupt publication records and staging files
  keep their existing semantics;
* symlinks are refused and symlinked directories are not descended;
* chunk-boundary sizes hash correctly (0, 1, chunk-1, chunk, chunk+1, 3c+7);
* a deadline that expires mid-walk or mid-chunk raises TimeoutError instead
  of returning a partial list.
"""
import hashlib
import os
import time

from fakenet.mcp import artifacts


def _publish(directory, paths):
    return artifacts.write_publication(directory, paths)


def _reference_metadata(root):
    """The previous production walk, spelled out as the behavioral oracle."""
    items = []
    publications = {}
    for path in sorted(root.rglob('*')):
        if not path.is_file() or path.is_symlink() or path.name == artifacts.PUBLICATION_RECORD:
            continue
        suffix = path.suffix.lstrip('.').lower()
        item_type = {'pcap': 'pcap', 'log': 'log', 'html': 'report',
                     'dmp': 'userdump', 'ini': 'config'}.get(suffix, suffix or 'file')
        if path.parent not in publications:
            publications[path.parent] = artifacts.publication_record(path.parent)
        entry = publications[path.parent].get(path.name)
        digest = None
        if isinstance(entry, dict):
            try:
                raw = path.read_bytes()
            except OSError:
                raw = None
            if raw is not None and len(raw) == entry.get('size'):
                candidate = hashlib.sha256(raw).hexdigest()
                digest = candidate if candidate == entry.get('sha256') else None
        items.append({'path': str(path), 'type': item_type,
                      'size': path.stat().st_size,
                      'complete': digest is not None, 'sha256': digest})
    return items


def _build_tree(root):
    run_a = root / 'runs' / 'run-a'
    run_b = root / 'runs' / 'nested' / 'run-b'
    run_a.mkdir(parents=True)
    run_b.mkdir(parents=True)
    published_a = []
    for index in range(12):
        path = run_a / ('evt-%02d.jsonl' % index)
        path.write_bytes(bytes([index % 256]) * (index * 37 + 1))
        published_a.append(path)
    report = run_a / 'report-main.html'
    report.write_bytes(b'<html>ok</html>')
    published_a.append(report)
    _publish(run_a, published_a)
    capture = run_b / 'capture.pcap'
    capture.write_bytes(b'pcap-ish-bytes')
    config = run_b / 'active-config.ini'
    config.write_bytes(b'[section]')
    _publish(run_b, [capture, config])
    # staging file: listed like the old walk, never complete
    (run_a / 'growing.pcap.part').write_bytes(b'partial')
    # directory without any publication record: listed, never complete
    loose = root / 'runs' / 'run-loose'
    loose.mkdir(parents=True)
    (loose / 'loose.log').write_bytes(b'not declared')
    return run_a, run_b


def test_metadata_matches_previous_walk_set_order_and_fields(tmp_path):
    run_a, run_b = _build_tree(tmp_path)
    registry = artifacts.ArtifactRegistry(tmp_path)
    rows = registry.metadata()
    reference = _reference_metadata(tmp_path)
    assert rows == reference
    by_path = {row['path']: row for row in rows}
    capture_row = by_path[str(run_b / 'capture.pcap')]
    assert capture_row['type'] == 'pcap' and capture_row['complete'] is True
    assert capture_row['sha256'] == hashlib.sha256(b'pcap-ish-bytes').hexdigest()
    assert by_path[str(run_a / 'report-main.html')]['type'] == 'report'
    assert by_path[str(run_b / 'active-config.ini')]['type'] == 'config'
    # Staging files stay listed (matching the previous walk) but can never be
    # complete: no producer declaration exists for them.
    staging = by_path[str(run_a / 'growing.pcap.part')]
    assert staging['complete'] is False and staging['sha256'] is None
    loose_row = by_path[str(run_a.parent / 'run-loose' / 'loose.log')]
    assert loose_row['complete'] is False and loose_row['sha256'] is None
    assert set(rows[0]) == {'path', 'type', 'size', 'complete', 'sha256'}


def test_equal_size_tamper_with_restored_mtime_detected_on_next_call(tmp_path):
    run_a, _ = _build_tree(tmp_path)
    victim = run_a / 'evt-03.jsonl'
    stamp = victim.stat()
    victim.write_bytes(bytes([9]) * victim.stat().st_size)
    os.utime(victim, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
    registry = artifacts.ArtifactRegistry(tmp_path)
    rows = {row['path']: row for row in registry.metadata(deadline=time.monotonic() + 30)}
    assert rows[str(victim)]['complete'] is False
    assert rows[str(victim)]['sha256'] is None


def test_large_multichunk_file_tamper_still_detected(tmp_path):
    run = tmp_path / 'run-big'
    run.mkdir(parents=True)
    chunk = artifacts.HASH_CHUNK_BYTES
    big = run / 'big.pcap'
    payload = bytes(range(256)) * (2 * chunk // 256)
    big.write_bytes(payload)
    _publish(run, [big])
    registry = artifacts.ArtifactRegistry(tmp_path)
    first = {row['path']: row for row in registry.metadata()}
    assert first[str(big)]['complete'] is True
    # Same-length corruption at the second chunk boundary region.
    corrupted = bytearray(payload)
    corrupted[chunk + 11] ^= 0xFF
    stamp = big.stat()
    big.write_bytes(bytes(corrupted))
    os.utime(big, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
    second = {row['path']: row for row in registry.metadata()}
    assert second[str(big)]['complete'] is False
    assert second[str(big)]['sha256'] is None


def test_chunk_boundary_sizes_hash_exactly(tmp_path):
    chunk = artifacts.HASH_CHUNK_BYTES
    sizes = [0, 1, chunk - 1, chunk, chunk + 1, 3 * chunk + 7]
    run = tmp_path / 'run-edges'
    run.mkdir(parents=True)
    paths = []
    for index, size in enumerate(sizes):
        path = run / ('edge-%d.bin' % size)
        path.write_bytes(bytes([index % 251]) * size)
        paths.append(path)
    _publish(run, paths)
    registry = artifacts.ArtifactRegistry(tmp_path)
    rows = {row['path']: row for row in registry.metadata()}
    for index, size in enumerate(sizes):
        row = rows[str(run / ('edge-%d.bin' % size))]
        assert row['complete'] is True
        assert row['sha256'] == hashlib.sha256(bytes([index % 251]) * size).hexdigest()
        assert row['size'] == size


def test_symlinks_refused_and_symlinked_directories_not_descended(tmp_path):
    run_a, run_b = _build_tree(tmp_path)
    link_file = run_a / 'linked.pcap'
    link_file.symlink_to(run_b / 'capture.pcap')
    linked_dir = tmp_path / 'runs' / 'via-link'
    linked_dir.symlink_to(run_b, target_is_directory=True)
    registry = artifacts.ArtifactRegistry(tmp_path)
    rows = registry.metadata()
    by_path = {row['path']: row for row in rows}
    assert str(link_file) not in by_path
    assert not any(str(linked_dir) in path for path in by_path)
    assert rows == _reference_metadata(tmp_path)


def test_corrupt_publication_record_behaves_as_unpublished(tmp_path):
    run_a, _ = _build_tree(tmp_path)
    (run_a / artifacts.PUBLICATION_RECORD).write_text('{ not json', encoding='utf-8')
    registry = artifacts.ArtifactRegistry(tmp_path)
    rows = {row['path']: row for row in registry.metadata()}
    for path in run_a.iterdir():
        if path.is_file() and path.name != artifacts.PUBLICATION_RECORD:
            assert rows[str(path)]['complete'] is False


def test_deadline_expiry_raises_instead_of_partial_list(tmp_path):
    run_a, _ = _build_tree(tmp_path)
    registry = artifacts.ArtifactRegistry(tmp_path)
    # Already expired: must raise before producing anything.
    try:
        registry.metadata(deadline=time.monotonic() - 1)
    except TimeoutError:
        pass
    else:
        raise AssertionError('expired deadline must raise TimeoutError')
    # A budget that dies while hashing the multi-chunk file (enumeration of a
    # two-entry tree is far faster than one chunk read) still fails closed;
    # the identical call with a real budget verifies both rows.
    chunk = artifacts.HASH_CHUNK_BYTES
    isolated = tmp_path / 'rd-root'
    run = isolated / 'run-deadline'
    run.mkdir(parents=True)
    big = run / 'big.pcap'
    big.write_bytes(bytes(range(256)) * (2 * chunk // 256))
    _publish(run, [big])
    registry = artifacts.ArtifactRegistry(isolated)
    try:
        registry.metadata(deadline=time.monotonic() + 1e-6)
    except TimeoutError:
        pass
    else:
        raise AssertionError('mid-hash deadline must raise TimeoutError')
    rows = registry.metadata(deadline=time.monotonic() + 60)
    assert len(rows) == 1 and rows[0]['complete'] is True


def test_completion_public_api_unchanged(tmp_path):
    run_b = tmp_path / 'run-b'
    run_b.mkdir(parents=True)
    capture = run_b / 'capture.pcap'
    capture.write_bytes(b'payload-bytes')
    _publish(run_b, [capture])
    assert artifacts.completion(capture, run_b) == hashlib.sha256(b'payload-bytes').hexdigest()
    capture.write_bytes(b'payload-byteS')
    assert artifacts.completion(capture, run_b) is None
    undeclared = run_b / 'undeclared.log'
    undeclared.write_bytes(b'x')
    assert artifacts.completion(undeclared, run_b) is None
