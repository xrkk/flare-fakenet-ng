# Copyright 2026 Google LLC
"""Managed artifact registration and metadata (P04 IMP-P04-04, OUT-015).

Products (PCAPs, run logs, reports, incident packs) register under
``%ProgramData%\\FakeNet-NG-MCP\\artifacts\\<run_id>\\``; the MCP surface
exposes ONLY normalized path/type/size/complete/sha256 — never content.
"""

import hashlib
import json
import os
from pathlib import Path
import tempfile


# Producers stage under these suffixes and publish with an atomic replace;
# anything still carrying one is not a finished artifact.
IN_PROGRESS_SUFFIXES = ('.part', '.partial')
# A producer declares its finished artifacts here, next to them, with the
# size and digest they had when it declared them finished.
PUBLICATION_RECORD = 'published.json'
# Fixed producers in run_evidence, managed IPC, creation evidence and ETW.
# Publication is called only after the managed tree and observers ended.
RUN_EVIDENCE_FILES = ('active-config.ini', 'creation.jsonl', 'ipc-parent.jsonl',
                      'ipc-child.jsonl', 'stop-thread-stacks.txt',
                      'fault-child-stacks.txt', 'udp.etl')


def is_published(name):
    """True only for names this product publishes atomically."""
    return not str(name).lower().endswith(IN_PROGRESS_SUFFIXES)


def publication_record(directory):
    path = Path(directory) / PUBLICATION_RECORD
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return {}
    files = data.get('files') if isinstance(data, dict) else None
    return files if isinstance(files, dict) else {}


def write_publication(directory, paths):
    """Record the finished artifacts of one producer, atomically."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    files = dict(publication_record(directory))
    for path in paths:
        path = Path(path)
        if not path.is_file() or path.name == PUBLICATION_RECORD:
            continue
        raw = path.read_bytes()
        files[path.name] = {'size': len(raw),
                            'sha256': hashlib.sha256(raw).hexdigest()}
    target = directory / PUBLICATION_RECORD
    fd, temporary = tempfile.mkstemp(dir=directory, prefix='.published-')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump({'schema': 'fakenet.artifact-publication.v1',
                       'files': files}, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return files


def completion(path, directory):
    """Digest of a finished artifact, or None while it is still changing.

    A name that merely lacks a staging suffix is not evidence of
    completion: the producer must have declared the artifact finished, and
    the bytes must still match that declaration.
    """
    path = Path(path)
    entry = publication_record(directory).get(path.name)
    if not isinstance(entry, dict):
        return None
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if len(raw) != entry.get('size'):
        return None
    digest = hashlib.sha256(raw).hexdigest()
    return digest if digest == entry.get('sha256') else None


class ArtifactRegistry:

    def __init__(self, artifacts_root):
        self.root = Path(artifacts_root)
        self.root.mkdir(parents=True, exist_ok=True)

    def run_dir(self, run_id):
        return self.root / str(run_id)

    def register_fakenet_outputs(self, run_id, package_root, keep=None,
                                 prefix='fakenet-'):
        """Register the artifacts a finished FakeNet run leaves next to the
        package (PCAPs, fakenet log, report) plus the incident pack.
        ``keep(path) -> bool`` filters which files belong to the run (the
        supervisor passes an mtime window so earlier runs' outputs are
        not re-registered on every stop)."""
        import shutil

        run_dir = self.run_dir(run_id)
        run_dir.mkdir(parents=True, exist_ok=True)
        source = Path(package_root)
        copied = []
        for pattern in ('*.pcap', '*.log', '*report*.html', '*.json') + RUN_EVIDENCE_FILES:
            for path in sorted(source.glob(pattern)):
                if path.parent != source or path.name == PUBLICATION_RECORD:
                    continue
                if keep is not None and not keep(path):
                    continue
                destination = run_dir / (prefix + path.name)
                if not destination.exists():
                    # Stage then replace: a reader never sees a half copy.
                    fd, temporary = tempfile.mkstemp(dir=run_dir,
                                                     prefix='.copy-')
                    os.close(fd)
                    try:
                        shutil.copy2(path, temporary)
                        os.replace(temporary, destination)
                    finally:
                        if os.path.exists(temporary):
                            os.unlink(temporary)
                copied.append(destination)
        if copied:
            write_publication(run_dir, copied)
            # These source files belong to the now-ended run as well. They
            # remain discoverable under runs/<id>, so publish both locations.
            write_publication(source, [source / p.name[len(prefix):] if prefix
                                       else source / p.name for p in copied])
        return copied

    def metadata(self):
        """All registered artifacts as metadata-only entries."""
        items = []
        if not self.root.is_dir():
            return items
        for path in sorted(self.root.rglob('*')):
            if not path.is_file() or path.is_symlink() or path.name == PUBLICATION_RECORD:
                continue
            suffix = path.suffix.lstrip('.').lower()
            item_type = {'pcap': 'pcap', 'log': 'log', 'html': 'report',
                         'dmp': 'userdump', 'ini': 'config'}.get(
                             suffix, suffix or 'file')
            digest = completion(path, path.parent)
            items.append({
                'path': str(path),
                'type': item_type,
                'size': path.stat().st_size,
                'complete': digest is not None,
                'sha256': digest,
            })
        return items
