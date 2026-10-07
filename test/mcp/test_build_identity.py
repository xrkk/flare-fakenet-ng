# Copyright 2026 Google LLC
"""ping build_identity: strict whitelist reads of the candidate manifest.

Valid manifests (temporary fixtures only — the real package and the
repository's historical manifests are untouched) surface the fixed
interface revision, the manifest's own SHA and its hex source_commit;
missing manifests answer unknown without failing; invalid JSON, wrong
schemas, malformed commits, oversize files and symlinks are refused with
a short reason; nothing beyond the whitelist (files arrays, paths,
credentials) is ever echoed; the answer is cached per process.
"""

import hashlib
import json
import os
import tempfile

import pytest

from fakenet.mcp import build_identity as bi


def _can_symlink():
    try:
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, 't.json')
            link = os.path.join(tmp, 'l.json')
            open(target, 'w').close()
            os.symlink(target, link)
            # Some Wine configurations silently materialize a copy instead
            # of a real link; refusing a symlink requires a true link.
            return os.path.islink(link)
    except OSError:
        return False


@pytest.fixture(autouse=True)
def fresh_cache(monkeypatch):
    monkeypatch.setattr(bi, '_cache', None)


def write_manifest(root, *, schema='fakenet.mcp-candidate-manifest.v1',
                   source_commit='a' * 40, extra=None):
    data = {'schema': schema, 'package_version': 'v9',
            'source_commit': source_commit,
            'mcp_sdk': 'pin', 'files': ['do-not-leak.bin']}
    if extra:
        data.update(extra)
    raw = json.dumps(data).encode('utf-8')
    (root / bi.MANIFEST_NAME).write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def point_at(tmp_path, monkeypatch):
    monkeypatch.setattr(bi, 'manifest_path', lambda: tmp_path / bi.MANIFEST_NAME)
    return tmp_path


def test_valid_manifest_whitelist_only(tmp_path, monkeypatch):
    digest = write_manifest(point_at(tmp_path, monkeypatch))
    identity = bi.build_identity()
    assert identity == {
        'interface_revision': '2026-10-06.1',
        'source_commit': 'a' * 40,
        'source': 'candidate_manifest',
        'manifest_sha256': digest,
        'error': None,
    }
    # The whitelist never leaks manifest internals.
    assert 'do-not-leak' not in json.dumps(identity)


def test_sixtyfour_hex_commit_accepted(tmp_path, monkeypatch):
    write_manifest(point_at(tmp_path, monkeypatch), source_commit='b' * 64)
    assert bi.build_identity()['source_commit'] == 'b' * 64


def test_missing_manifest_is_unknown_not_failure(tmp_path, monkeypatch):
    point_at(tmp_path, monkeypatch)
    identity = bi.build_identity()
    assert identity['source'] == 'unknown'
    assert identity['source_commit'] is None
    assert identity['manifest_sha256'] is None
    assert identity['error'] is None
    assert identity['interface_revision'] == '2026-10-06.1'


@pytest.mark.parametrize('blob,reason', [
    (b'{ not json', 'manifest is not valid JSON'),
    (b'[]', 'manifest schema mismatch'),
    (json.dumps({'schema': 'other.v1', 'source_commit': 'a' * 40}).encode(),
     'manifest schema mismatch'),
    (json.dumps({'schema': 'fakenet.mcp-candidate-manifest.v1'}).encode(),
     'manifest carries no source_commit'),
    (json.dumps({'schema': 'fakenet.mcp-candidate-manifest.v1',
                 'source_commit': 'zz'}).encode(),
     'manifest source_commit malformed'),
    (json.dumps({'schema': 'fakenet.mcp-candidate-manifest.v1',
                 'source_commit': 'HEAD'}).encode(),
     'manifest source_commit malformed'),
])
def test_malformed_manifests_refused_with_short_reason(
        tmp_path, monkeypatch, blob, reason):
    root = point_at(tmp_path, monkeypatch)
    (root / bi.MANIFEST_NAME).write_bytes(blob)
    identity = bi.build_identity()
    assert identity['source'] == 'unknown'
    assert identity['source_commit'] is None
    assert identity['error'] == reason
    # The digest of the (read) bytes is still reportable evidence.
    assert identity['manifest_sha256'] == hashlib.sha256(blob).hexdigest()


def test_oversize_manifest_refused(tmp_path, monkeypatch):
    root = point_at(tmp_path, monkeypatch)
    blob = b' ' * (bi.MANIFEST_MAX_BYTES + 1)
    (root / bi.MANIFEST_NAME).write_bytes(blob)
    identity = bi.build_identity()
    assert identity['error'] == 'manifest exceeds 4 MiB bound'
    assert identity['source'] == 'unknown'


@pytest.mark.skipif(not _can_symlink(), reason='symlink creation unavailable')
def test_symlinked_manifest_refused(tmp_path, monkeypatch):
    root = point_at(tmp_path, monkeypatch)
    real = root / 'real.json'
    real.write_text('{}', encoding='utf-8')
    (root / bi.MANIFEST_NAME).symlink_to(real)
    assert (root / bi.MANIFEST_NAME).is_symlink()
    identity = bi.build_identity()
    assert identity['error'] == 'manifest is not a regular file'
    assert identity['source_commit'] is None


def test_identity_is_cached_per_process(tmp_path, monkeypatch):
    root = point_at(tmp_path, monkeypatch)
    write_manifest(root, source_commit='c' * 40)
    first = bi.build_identity()
    # The manifest changes afterwards; the cached answer must not.
    write_manifest(root, source_commit='d' * 40)
    assert bi.build_identity() == first


class ObservingOpener:
    """Wraps the real file stream and records every read(size) request."""

    def __init__(self, real_open, reads):
        self.real_open = real_open
        self.reads = reads

    def __call__(self, path, mode):
        stream = self.real_open(path, mode)
        outer = self

        class Wrapped:
            def __enter__(self):
                outer.stream = stream.__enter__()
                return self

            def __exit__(self, *exc):
                return stream.__exit__(*exc)

            def read(self, size=-1):
                outer.reads.append(size)
                return outer.stream.read(size)

        return Wrapped()


def test_read_requests_are_bounded_never_unbounded(tmp_path, monkeypatch):
    root = tmp_path
    write_manifest(root)
    reads = []
    opener = ObservingOpener(open, reads)
    digest, commit = bi._read_manifest(root / bi.MANIFEST_NAME, opener=opener)
    assert commit == 'a' * 40
    # Exactly one read, capped at MAX+1 as the oversize sentinel — never
    # read() without an explicit bound.
    assert reads == [bi.MANIFEST_MAX_BYTES + 1]


def test_file_growing_past_stat_is_refused_not_trusted(tmp_path, monkeypatch):
    root = tmp_path
    write_manifest(root)  # small on disk per stat...

    class GrowingStream:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self, size=-1):
            assert size == bi.MANIFEST_MAX_BYTES + 1
            return b' ' * (bi.MANIFEST_MAX_BYTES + 2)  # ...but it grew

    digest, outcome = bi._read_manifest(
        root / bi.MANIFEST_NAME,
        opener=lambda path, mode: GrowingStream())
    assert outcome == 'manifest exceeds 4 MiB bound'
    assert digest is None  # nothing trusted is cached from a lying size


def test_open_failure_is_unknown_not_fatal(tmp_path, monkeypatch):
    root = tmp_path
    write_manifest(root)

    def failing_open(path, mode):
        raise OSError('device gone')

    digest, outcome = bi._read_manifest(
        root / bi.MANIFEST_NAME, opener=failing_open)
    assert outcome == 'manifest unreadable'
    assert digest is None
