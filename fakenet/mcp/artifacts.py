# Copyright 2026 Google LLC
"""Managed artifact registration and metadata (P04 IMP-P04-04, OUT-015).

Products (PCAPs, run logs, reports, incident packs) register under
``%ProgramData%\\FakeNet-NG-MCP\\artifacts\\<run_id>\\``; the MCP surface
exposes ONLY normalized path/type/size/complete/sha256 — never content.
"""

import hashlib
import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import time


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
# Published files are re-hashed on every metadata request; large captures
# stream through one bounded chunk instead of one whole-file bytes object.
HASH_CHUNK_BYTES = 1024 * 1024
# Larger collections verify file content with a bounded pool so reads of one
# capture overlap another; small ones stay serial because pool startup would
# dominate. The pool lives for one request only and at most one unconsumed
# submission per worker exists at any moment (executor.map pre-submits
# without bound on Python 3.11 and is not used).
HASH_WORKER_LIMIT = 4
SERIAL_FILE_THRESHOLD = 16


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
    return _completion_from_entry(path, entry)


def _completion_from_entry(path, entry, deadline=None):
    if not isinstance(entry, dict):
        return None
    digest = hashlib.sha256()
    size = 0
    try:
        with open(path, 'rb') as stream:
            while True:
                if deadline is not None and time.monotonic() >= deadline:
                    raise TimeoutError('artifact enumeration deadline exceeded')
                chunk = stream.read(HASH_CHUNK_BYTES)
                if not chunk:
                    break
                digest.update(chunk)
                size += len(chunk)
    except TimeoutError:
        # TimeoutError is an OSError subclass. A query budget expiring is
        # not evidence that this file is merely unpublished or unreadable.
        raise
    except OSError:
        return None
    if size != entry.get('size'):
        return None
    hexdigest = digest.hexdigest()
    return hexdigest if hexdigest == entry.get('sha256') else None


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

    def _enumeration_entries(self, deadline):
        """Every candidate file as (Path, DirEntry), unordered.

        Same kept-set rule as the previous ``sorted(root.rglob('*'))`` walk:
        regular non-symlink files only, publication records excluded, no
        descent into symlinked directories. scandir supplies the type and
        size attributes with the directory listing itself instead of one
        native stat per is_file/is_symlink/stat call.
        """
        stack = [str(self.root)]
        while stack:
            directory = stack.pop()
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError('artifact enumeration deadline exceeded')
            try:
                with os.scandir(directory) as scan:
                    entries = list(scan)
            except OSError:
                continue
            for entry in entries:
                try:
                    if entry.is_symlink():
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(entry.path)
                    elif (entry.is_file(follow_symlinks=False)
                          and entry.name != PUBLICATION_RECORD):
                        yield Path(entry.path), entry
                except OSError:
                    continue

    def _row_context(self, path, entry, publications):
        """Per-file row facts composed on the main thread only.

        Workers receive plain (path, publication entry, deadline) tuples and
        verify bytes; the type map, the publication cache and the row shape
        never cross threads.
        """
        suffix = path.suffix.lstrip('.').lower()
        item_type = {'pcap': 'pcap', 'log': 'log', 'html': 'report',
                     'dmp': 'userdump', 'ini': 'config'}.get(
                         suffix, suffix or 'file')
        if path.parent not in publications:
            publications[path.parent] = publication_record(path.parent)
        return (str(path), item_type,
                entry.stat(follow_symlinks=False).st_size,
                publications[path.parent].get(path.name))

    def metadata(self, deadline=None):
        """All registered artifacts as metadata-only entries.

        Enumeration is bounded: when ``deadline`` (monotonic) is supplied and
        the walk cannot finish inside it, the query fails structurally instead
        of blocking its caller past the fixed budget. The deadline is checked
        while walking directories, before every pool submission and result
        consumption, and between hash chunks of large files, so one huge
        capture cannot run far past the budget before failing.
        """
        items = []
        if not self.root.is_dir():
            return items
        # Snapshot each producer index once for this enumeration only. Every
        # artifact still has its current bytes hashed on every API request.
        publications = {}
        ordered = sorted(self._enumeration_entries(deadline), key=lambda pair: pair[0])
        if len(ordered) < SERIAL_FILE_THRESHOLD:
            for path, entry in ordered:
                if deadline is not None and time.monotonic() >= deadline:
                    raise TimeoutError('artifact enumeration deadline exceeded')
                path_text, item_type, size, published = self._row_context(
                    path, entry, publications)
                digest = _completion_from_entry(path, published, deadline)
                items.append({'path': path_text, 'type': item_type,
                              'size': size, 'complete': digest is not None,
                              'sha256': digest})
            return items
        return self._metadata_bounded(ordered, publications, deadline)

    def _metadata_bounded(self, ordered, publications, deadline):
        """Verify ordered rows through at most HASH_WORKER_LIMIT workers.

        Submission and consumption follow the sorted(Path) order: results are
        appended in consumption order, so the row order is exactly the serial
        contract. At most one unconsumed future per worker exists at any
        moment. A deadline stop or a worker failure raises the first observed
        error only after every started worker has been joined; a query never
        returns a partial list, and a worker's TimeoutError surfaces as the
        query's TimeoutError instead of an incomplete-file row.
        """
        items = []
        total = len(ordered)
        index = 0
        executor = ThreadPoolExecutor(max_workers=HASH_WORKER_LIMIT)
        window = []  # [(row facts, future, Path)] in submission order
        try:
            while True:
                if deadline is not None and time.monotonic() >= deadline:
                    raise TimeoutError('artifact enumeration deadline exceeded')
                while len(window) < HASH_WORKER_LIMIT and index < total:
                    if deadline is not None and time.monotonic() >= deadline:
                        raise TimeoutError('artifact enumeration deadline exceeded')
                    path, entry = ordered[index]
                    context = self._row_context(path, entry, publications)
                    if deadline is not None and time.monotonic() >= deadline:
                        raise TimeoutError('artifact enumeration deadline exceeded')
                    future = executor.submit(
                        _completion_from_entry, path, context[3], deadline)
                    window.append((context, future, path))
                    index += 1
                if not window:
                    break
                if deadline is not None and time.monotonic() >= deadline:
                    raise TimeoutError('artifact enumeration deadline exceeded')
                context, future, path = window.pop(0)
                digest = future.result()
                items.append({'path': context[0], 'type': context[1],
                              'size': context[2], 'complete': digest is not None,
                              'sha256': digest})
        finally:
            # Pending submissions are cancelled, running workers are waited
            # for: a native read cannot be lied about, and no thread outlives
            # this query. The original error (deadline or worker failure) is
            # re-raised after the join.
            executor.shutdown(wait=True, cancel_futures=True)
        return items
