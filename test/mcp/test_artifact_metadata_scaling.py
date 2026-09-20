"""Artifact enumeration keeps byte verification without rereading each index."""
import hashlib
from pathlib import Path

from fakenet.mcp import artifacts


def test_metadata_reads_publication_once_per_directory_and_rechecks_next_call(tmp_path, monkeypatch):
    root = tmp_path / 'artifacts'
    directory = root / 'run'
    directory.mkdir(parents=True)
    paths = [directory / ('file-%02d.log' % i) for i in range(20)]
    for path in paths:
        path.write_bytes(b'original')
    artifacts.write_publication(directory, paths)
    original = artifacts.publication_record
    reads = []

    def record(path):
        reads.append(Path(path))
        return original(path)

    monkeypatch.setattr(artifacts, 'publication_record', record)
    registry = artifacts.ArtifactRegistry(root)
    result = registry.metadata()
    assert len(result) == 20
    assert all(row['complete'] and row['sha256'] == hashlib.sha256(b'original').hexdigest()
               for row in result)
    assert reads == [directory]
    # Equal-size corruption must still be detected, even if metadata such as
    # the modification time is restored. No persistent stat/digest cache.
    stamp = paths[0].stat()
    paths[0].write_bytes(b'corrupt!')
    import os
    os.utime(paths[0], ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
    second = {Path(row['path']): row for row in registry.metadata()}
    assert second[paths[0]]['complete'] is False
    assert second[paths[0]]['sha256'] is None
    assert reads == [directory, directory]
    # Removing a producer declaration must also be noticed on the next call.
    (directory / artifacts.PUBLICATION_RECORD).unlink()
    assert not any(row['complete'] for row in registry.metadata())
