"""Bounded parallel artifact verification keeps the serial contract.

Observation seams are thin delegating wrappers around the REAL production
pieces — ``_completion_from_entry`` (the unit the pool executes) and
``_row_context`` (built on the main thread immediately before each
submission) — so submission order, the ≤4 unconsumed-future bound, deadline
stops and worker failures are all observed through the production scheduler,
never a copy of it. Every test releases its gates in a finally block or via
a timer, so the suite cannot hang on them.
"""
import hashlib
import os
import threading
import time

import pytest

from fakenet.mcp import artifacts


FILE_COUNT = 20  # above SERIAL_FILE_THRESHOLD, so the pool path runs


def _build(root, count=FILE_COUNT, per_file=b'payload-'):
    directory = root / 'run'
    directory.mkdir(parents=True)
    paths = []
    for index in range(count):
        path = directory / ('f-%03d.log' % index)
        path.write_bytes(per_file * (index + 1))
        paths.append(path)
    artifacts.write_publication(directory, paths)
    return directory, paths


class PoolProbe:
    """Gated execution + submission/concurrency counters for the real path."""

    def __init__(self):
        self.real_completion = artifacts._completion_from_entry
        self.real_context = artifacts.ArtifactRegistry._row_context
        self.lock = threading.Lock()
        self.active = 0
        self.peak = 0
        self.entered = 0
        self.contexts_built = 0
        self.gates = {}           # path text -> threading.Event (closed)
        self.fail_paths = set()

    def install(self, monkeypatch):
        probe = self

        def gated_completion(path, entry, deadline=None):
            with probe.lock:
                probe.active += 1
                probe.entered += 1
                probe.peak = max(probe.peak, probe.active)
            try:
                gate = probe.gates.get(str(path))
                if gate is not None:
                    gate.wait(timeout=30)
                if str(path) in probe.fail_paths:
                    raise RuntimeError('worker failure for %s' % path)
                return probe.real_completion(path, entry, deadline)
            finally:
                with probe.lock:
                    probe.active -= 1

        def counting_context(self, path, entry, publications):
            with probe.lock:
                probe.contexts_built += 1
            return probe.real_context(self, path, entry, publications)

        monkeypatch.setattr(artifacts, '_completion_from_entry', gated_completion)
        monkeypatch.setattr(artifacts.ArtifactRegistry, '_row_context',
                            counting_context)

    def wait_contexts(self, expected, timeout=10.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self.lock:
                if self.contexts_built >= expected:
                    return True
            time.sleep(0.01)
        return False

    def open(self, path):
        with self.lock:
            gate = self.gates.get(str(path))
        if gate is not None:
            gate.set()

    def open_all(self):
        with self.lock:
            gates = list(self.gates.values())
        for gate in gates:
            gate.set()


def test_pool_window_bounded_and_consumption_drives_submission(tmp_path, monkeypatch):
    directory, paths = _build(tmp_path)
    probe = PoolProbe()
    for path in paths:
        probe.gates[str(path)] = threading.Event()
    probe.install(monkeypatch)
    result = {}

    def run():
        try:
            result['rows'] = artifacts.ArtifactRegistry(tmp_path).metadata()
        finally:
            probe.open_all()

    thread = threading.Thread(target=run)
    thread.start()
    try:
        # All gates closed: exactly one submission per worker can be unconsumed,
        # so only HASH_WORKER_LIMIT contexts are ever built up front. An
        # unbounded pre-submitter (executor.map) would build all FILE_COUNT.
        assert probe.wait_contexts(artifacts.HASH_WORKER_LIMIT), \
            'submission window did not stop at the worker limit'
        with probe.lock:
            assert probe.contexts_built == artifacts.HASH_WORKER_LIMIT
            assert probe.entered == artifacts.HASH_WORKER_LIMIT
        # Releasing only the first (sorted-first) file lets the main thread
        # consume it and submit exactly one more context.
        probe.open(paths[0])
        assert probe.wait_contexts(artifacts.HASH_WORKER_LIMIT + 1), \
            'consumption did not unlock the next submission'
    finally:
        probe.open_all()
    thread.join(timeout=30)
    assert not thread.is_alive()
    rows = result['rows']
    assert len(rows) == FILE_COUNT
    assert [row['path'] for row in rows] == sorted(str(p) for p in paths)
    with probe.lock:
        assert probe.peak <= artifacts.HASH_WORKER_LIMIT
        assert probe.active == 0


def test_slow_first_file_keeps_path_order(tmp_path, monkeypatch):
    directory, paths = _build(tmp_path)
    first = paths[0]
    release_first = threading.Event()
    real = artifacts._completion_from_entry

    def staggered(path, entry, deadline=None):
        if str(path) == str(first):
            release_first.wait(timeout=30)
        return real(path, entry, deadline)

    monkeypatch.setattr(artifacts, '_completion_from_entry', staggered)
    result = {}

    def run():
        result['rows'] = artifacts.ArtifactRegistry(tmp_path).metadata()

    thread = threading.Thread(target=run)
    thread.start()
    time.sleep(0.5)  # every other file finishes while the first is held
    release_first.set()
    thread.join(timeout=30)
    assert not thread.is_alive()
    rows = result['rows']
    assert [row['path'] for row in rows] == sorted(str(p) for p in paths)
    for index, row in enumerate(rows):
        expected = b'payload-' * (index + 1)
        assert row['complete'] is True
        assert row['sha256'] == hashlib.sha256(expected).hexdigest()


def test_worker_error_joins_all_workers_before_raising(tmp_path, monkeypatch):
    directory, paths = _build(tmp_path)
    probe = PoolProbe()
    for path in paths:
        probe.gates[str(path)] = threading.Event()
    probe.fail_paths.add(str(paths[5]))
    probe.install(monkeypatch)
    released = {'done': False}

    def run():
        try:
            artifacts.ArtifactRegistry(tmp_path).metadata()
        except RuntimeError as exc:
            released['error'] = repr(exc)
        finally:
            released['done'] = True
            probe.open_all()

    thread = threading.Thread(target=run)
    thread.start()
    time.sleep(0.5)
    assert not released['done']  # blocked workers hold the query open
    probe.open_all()
    thread.join(timeout=30)
    assert not thread.is_alive()
    assert 'worker failure' in released.get('error', '')
    # The raise surfaced only after every started worker exited.
    with probe.lock:
        assert probe.active == 0


def test_deadline_stop_submits_no_more_and_raises(tmp_path, monkeypatch):
    directory, paths = _build(tmp_path)
    probe = PoolProbe()
    # Gate keys must be str(path) of the real files: on Windows str(Path)
    # uses backslashes, and a forward-slash key never matches, leaving the
    # gates open so the query finishes before the deadline trips (first seen
    # as the Wine gate failure recorded in build-03).
    for path in paths:
        probe.gates[str(path)] = threading.Event()
    probe.install(monkeypatch)
    # The blocked consume cannot see the deadline, so release on a timer.
    timer = threading.Timer(0.5, probe.open_all)
    timer.start()
    try:
        with pytest.raises(TimeoutError, match='deadline exceeded'):
            artifacts.ArtifactRegistry(tmp_path).metadata(
                deadline=time.monotonic() + 0.05)
    finally:
        probe.open_all()
        timer.join()
    with probe.lock:
        # No submissions beyond the initial bounded window after expiry.
        assert probe.entered <= artifacts.HASH_WORKER_LIMIT
        # Every started worker was joined before the raise returned.
        assert probe.active == 0


def test_parallel_tamper_same_size_restored_mtime_detected(tmp_path):
    directory, paths = _build(tmp_path)
    victim = paths[7]
    stamp = victim.stat()
    original = victim.read_bytes()
    victim.write_bytes(bytes([original[0] ^ 0xFF]) + original[1:])
    os.utime(victim, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
    rows = {row['path']: row
            for row in artifacts.ArtifactRegistry(tmp_path).metadata()}
    assert rows[str(victim)]['complete'] is False
    assert rows[str(victim)]['sha256'] is None
    assert rows[str(paths[6])]['complete'] is True


def test_deadline_in_worker_propagates_not_success(tmp_path, monkeypatch):
    _build(tmp_path)
    clock = [0.0]
    real_sha256 = hashlib.sha256

    class ExpiringHash:
        def __init__(self):
            self.digest = real_sha256()

        def update(self, chunk):
            self.digest.update(chunk)
            clock[0] = 2.0

        def hexdigest(self):
            return self.digest.hexdigest()

    monkeypatch.setattr(artifacts.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(artifacts.hashlib, 'sha256', ExpiringHash)
    # FILE_COUNT files force the pool path: the worker's TimeoutError must
    # cross future.result() as the query's own TimeoutError, never become an
    # incomplete-file row that lets metadata succeed.
    with pytest.raises(TimeoutError, match='deadline exceeded'):
        artifacts.ArtifactRegistry(tmp_path).metadata(deadline=1.0)


def test_small_collection_stays_serial(tmp_path, monkeypatch):
    _build(tmp_path, count=artifacts.SERIAL_FILE_THRESHOLD - 1)
    calls = []
    real = artifacts._completion_from_entry

    def observing(path, entry, deadline=None):
        calls.append(threading.current_thread().name)
        return real(path, entry, deadline)

    monkeypatch.setattr(artifacts, '_completion_from_entry', observing)
    rows = artifacts.ArtifactRegistry(tmp_path).metadata()
    assert len(rows) == artifacts.SERIAL_FILE_THRESHOLD - 1
    assert calls and len(set(calls)) == 1  # one thread, no pool startup


def test_deadline_before_pool_submission_never_returns_empty_success(tmp_path, monkeypatch):
    _build(tmp_path)
    registry = artifacts.ArtifactRegistry(tmp_path)
    real_pool = registry._metadata_bounded

    def expired_pool(ordered, publications, deadline):
        monkeypatch.setattr(artifacts.time, 'monotonic', lambda: 2.0)
        return real_pool(ordered, publications, deadline)

    monkeypatch.setattr(artifacts.time, 'monotonic', lambda: 0.0)
    monkeypatch.setattr(registry, '_metadata_bounded', expired_pool)
    with pytest.raises(TimeoutError):
        registry.metadata(deadline=1.0)
