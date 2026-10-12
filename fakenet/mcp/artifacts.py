# Copyright 2026 Google LLC
"""Managed artifact registration and metadata (P04 IMP-P04-04, OUT-015).

Products (PCAPs, run logs, reports, incident packs) register under
``%ProgramData%\\FakeNet-NG-MCP\\artifacts\\<run_id>\\``; the MCP surface
exposes ONLY normalized path/type/size/complete/sha256 — never content.
"""

import configparser
import hashlib
import json
import os
import re
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
# Runtime capture-original sidecars are exact siblings of their paired PCAP.
# They are candidates only next to the sealed producer of that same capture;
# an unsealed journal is unfinished evidence, and no other ``*.ndjson`` name
# becomes a registerable artifact.
CAPTURE_ORIGINALS_SIDECAR_SUFFIXES = ('.observations.ndjson', '.nbis.ndjson')
CAPTURE_ORIGINALS_SEAL_SUFFIX = '.capture-originals.json'
# The producer's converted side of a pair is the raw stem plus this fixed
# suffix; a seal may only confirm that name, never select another path.
CAPTURE_ORIGINALS_CONVERTED_SUFFIX = '-converted.pcap'
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


def closed_http_post_paths(directory):
    """Select only enabled HTTP producers in this run's retained config.

    Called at the existing closed-writer registration boundary. Absolute or
    directory prefixes are outside this registrar's run-owned scope; they
    are deliberately not scanned. Unrelated text and staged files stay out.
    """
    directory = Path(directory)
    config = directory / 'active-config.ini'
    if not config.is_file() or config.is_symlink() or config.stat().st_size > 1024 * 1024:
        return []
    parser = configparser.RawConfigParser()
    try:
        parser.read_string(config.read_text(encoding='utf-8-sig'))
    except (OSError, UnicodeError, configparser.Error):
        return []
    patterns = []
    for section in parser.sections():
        values = dict(parser.items(section))
        if (values.get('enabled', '').lower() != 'true' or
                values.get('listener', '') != 'HTTPListener' or
                values.get('dumphttpposts', '').lower() != 'yes'):
            continue
        prefix = values.get('dumphttppostsfileprefix', 'http')
        if (not prefix or any(char in prefix for char in '/\\:') or
                prefix in ('.', '..')):
            continue
        patterns.append(re.compile(re.escape(prefix) + r'_[0-9]{8}_[0-9]{6}\.txt\Z'))
    return sorted(path for path in directory.iterdir()
                  if path.is_file() and not path.is_symlink() and
                  any(pattern.fullmatch(path.name) for pattern in patterns))


class CaptureOriginalsRejected(Exception):
    """One capture's side originals did not qualify for publication."""


def _plain_basename(name):
    """A seal may only confirm a plain file name; it never selects a path."""
    text = name if isinstance(name, str) else ''
    return (bool(text) and text not in ('.', '..') and '/' not in text and
            '\\' not in text and not os.path.isabs(text))


def _sha256_and_size(path):
    digest = hashlib.sha256()
    size = 0
    with open(path, 'rb') as stream:
        while True:
            chunk = stream.read(HASH_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    return {'bytes': size, 'sha256': digest.hexdigest()}


def _matches_facts(path, facts):
    """True when the file's current bytes still equal approved facts."""
    try:
        return _sha256_and_size(path) == {'bytes': facts['bytes'],
                                          'sha256': facts['sha256']}
    except (OSError, KeyError):
        return False


def _qualify_capture_originals_group(source, raw_pcap):
    """Qualify one capture's originals against the real seal.

    Every member path is derived from the registry-trusted direct candidate
    ``raw_pcap``; the user-writable seal may only confirm the fixed
    basenames. The production loader re-verifies the seal schema, capture
    id, byte counts, SHA-256 digests, producer file identity, both journals
    and the PCAP pair, and its specific reason surfaces on rejection.
    Returns ``(members, facts)`` mapping each role (raw, converted, both
    journals, seal) to its Path and verified ``{'bytes', 'sha256'}``.
    """
    raw = Path(raw_pcap)
    seal_file = raw.with_name(raw.name + CAPTURE_ORIGINALS_SEAL_SUFFIX)
    try:
        seal = json.loads(seal_file.read_text(encoding='utf-8'))
    except (OSError, UnicodeError, ValueError) as exc:
        raise CaptureOriginalsRejected(
            'capture originals seal is missing or not valid JSON: %s' % exc)
    if not isinstance(seal, dict):
        raise CaptureOriginalsRejected(
            'capture originals seal is not a JSON object')
    converted = None
    converted_facts = seal.get('converted_pcap')
    if converted_facts is not None:
        if not isinstance(converted_facts, dict):
            raise CaptureOriginalsRejected(
                'seal converted PCAP facts are invalid')
        stem = (raw.name[:-len('.pcap')]
                if raw.name.endswith('.pcap') else raw.name)
        expected = stem + CAPTURE_ORIGINALS_CONVERTED_SUFFIX
        name = converted_facts.get('name')
        if not _plain_basename(name) or name != expected:
            raise CaptureOriginalsRejected(
                'seal converted PCAP name does not pair with this raw capture')
        converted = Path(source) / expected
        if converted.is_symlink() or not converted.is_file():
            raise CaptureOriginalsRejected(
                'converted PCAP named by the seal is missing or not a plain '
                'file')
    from fakenet.payload_report import (PayloadReportError,
                                        load_capture_originals)
    try:
        loaded = load_capture_originals(raw, converted)
    except PayloadReportError as exc:
        raise CaptureOriginalsRejected(str(exc))
    members = {
        'raw': raw,
        'observations': raw.with_name(
            raw.name + CAPTURE_ORIGINALS_SIDECAR_SUFFIXES[0]),
        'nbis': raw.with_name(
            raw.name + CAPTURE_ORIGINALS_SIDECAR_SUFFIXES[1]),
        'seal': seal_file,
    }
    facts = {
        'raw': {'bytes': int(loaded.seal['raw_pcap']['bytes']),
                'sha256': loaded.seal['raw_pcap']['sha256']},
        'observations': {'bytes': int(loaded.seal['observations']['bytes']),
                         'sha256': loaded.seal['observations']['sha256']},
        'nbis': {'bytes': int(loaded.seal['nbis']['bytes']),
                 'sha256': loaded.seal['nbis']['sha256']},
        'seal': _sha256_and_size(seal_file),
    }
    if converted is not None:
        members['converted'] = converted
        facts['converted'] = {
            'bytes': int(loaded.seal['converted_pcap']['bytes']),
            'sha256': loaded.seal['converted_pcap']['sha256']}
    return members, facts


class ArtifactRegistry:

    def __init__(self, artifacts_root):
        self.root = Path(artifacts_root)
        self.root.mkdir(parents=True, exist_ok=True)
        # Per-call record of capture groups refused publication, with the
        # loader's specific reason; an empty list is not evidence that any
        # capture existed, only that none was rejected.
        self.last_registration_rejections = []

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
        self.last_registration_rejections = []
        copied = []
        candidates = set(closed_http_post_paths(source))
        for pattern in ('*.pcap', '*.log', '*report*.html', '*.json') + RUN_EVIDENCE_FILES:
            candidates.update(source.glob(pattern))
        for path in sorted(candidates):
            if (path.parent != source or path.name == PUBLICATION_RECORD or
                    str(path.name).endswith(CAPTURE_ORIGINALS_SEAL_SUFFIX) or
                    not path.is_file() or path.is_symlink()):
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
        copied.extend(self._publish_capture_originals_groups(
            run_dir, source, keep, prefix))
        if copied:
            write_publication(run_dir, copied)
            # These source files belong to the now-ended run as well. They
            # remain discoverable under runs/<id>, so publish both locations.
            write_publication(source, [source / p.name[len(prefix):] if prefix
                                       else source / p.name for p in copied])
        return copied

    def _publish_capture_originals_groups(self, run_dir, source, keep,
                                          prefix):
        """Publish sealed capture-originals groups that fully qualify.

        Qualification follows the producer's seal through the production
        loader — never the seal's mere existence — and the group's side
        originals (both journals and the seal) publish only when every
        member qualifies, survives ``keep``, meets an identical existing
        destination, and still verifies at the source right before
        publication. A rejected group never blocks another capture, an
        HTTP original or any other artifact; each rejection and its
        specific reason are recorded on ``last_registration_rejections``.
        """
        import shutil

        published = []
        for raw in sorted(path for path in source.glob('*.pcap')
                          if not str(path.name).endswith(
                              CAPTURE_ORIGINALS_CONVERTED_SUFFIX)):
            try:
                members, facts = _qualify_capture_originals_group(source, raw)
            except CaptureOriginalsRejected as exc:
                self.last_registration_rejections.append(
                    {'capture': raw.name, 'stage': 'qualify',
                     'reason': str(exc)})
                continue
            group = [(role, members[role]) for role in
                     ('raw', 'observations', 'nbis', 'seal') +
                     (('converted',) if 'converted' in members else ())]
            side_originals = ('observations', 'nbis', 'seal')
            if keep is not None:
                excluded = [path.name for _, path in group if not keep(path)]
                if excluded:
                    self.last_registration_rejections.append(
                        {'capture': raw.name, 'stage': 'keep',
                         'reason': 'keep filter excluded group members: '
                                   + ', '.join(excluded)})
                    continue
            conflicts = []
            for role, path in group:
                destination = run_dir / (prefix + path.name)
                if (destination.exists() and
                        not _matches_facts(destination, facts[role])):
                    conflicts.append(destination.name)
            if conflicts:
                self.last_registration_rejections.append(
                    {'capture': raw.name, 'stage': 'destination',
                     'reason': 'existing destination differs from the '
                               'qualified source: ' + ', '.join(conflicts)})
                continue
            created = []
            try:
                for role in side_originals:
                    path = members[role]
                    destination = run_dir / (prefix + path.name)
                    if destination.exists():
                        # Verified identical above; history is never
                        # overwritten to re-export this capture.
                        continue
                    fd, temporary = tempfile.mkstemp(dir=run_dir,
                                                     prefix='.copy-')
                    os.close(fd)
                    try:
                        shutil.copy2(path, temporary)
                        os.replace(temporary, destination)
                    finally:
                        if os.path.exists(temporary):
                            os.unlink(temporary)
                    if not _matches_facts(destination, facts[role]):
                        raise CaptureOriginalsRejected(
                            '%s copy does not match the qualified source'
                            % role)
                    created.append(destination)
                # Re-verify the whole group at the source before it joins
                # this publication: a change between approval and publish
                # cannot manufacture success.
                _qualify_capture_originals_group(source, raw)
            except (CaptureOriginalsRejected, OSError) as exc:
                for destination in created:
                    try:
                        os.unlink(destination)
                    except OSError:
                        pass
                self.last_registration_rejections.append(
                    {'capture': raw.name, 'stage': 'copy',
                     'reason': str(exc)})
                continue
            published.extend(run_dir / (prefix + members[role].name)
                             for role in side_originals)
        return published

    def _enumeration_entries(self, deadline, run_id=None):
        """Every candidate file as (Path, DirEntry), unordered.

        Same kept-set rule as the previous ``sorted(root.rglob('*'))`` walk:
        regular non-symlink files only, publication records excluded, no
        descent into symlinked directories. scandir supplies the type and
        size attributes with the directory listing itself instead of one
        native stat per is_file/is_symlink/stat call. With ``run_id`` the
        walk is anchored to that run's registered subtree
               (``root/<run_id>``) so unselected runs are never even opened.
        """
        stack = [str(self.root / str(run_id)) if run_id is not None
                 else str(self.root)]
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

    def metadata(self, deadline=None, run_id=None, artifact_type=None):
        """All registered artifacts as metadata-only entries.

        Enumeration is bounded: when ``deadline`` (monotonic) is supplied and
        the walk cannot finish inside it, the query fails structurally instead
        of blocking its caller past the fixed budget. The deadline is checked
        while walking directories, before every pool submission and result
        consumption, and between hash chunks of large files, so one huge
        capture cannot run far past the budget before failing.

        ``run_id`` anchors the walk to that run's registered subtree, and
        ``artifact_type`` drops rows after their type is known; both filter
        BEFORE any hash work is submitted, so unselected files are never
        opened or hashed. Neither filter changes row shape, sorted(Path)
        order, per-request byte verification or deadline semantics; an
        unknown-but-valid run is an empty match, never a fallback to the
        full set.
        """
        items = []
        if run_id is not None:
            anchor = self.root / str(run_id)
            # The anchored walk may never leave the registry root through a
            # link: a symlinked run directory is not descended at all.
            try:
                if anchor.is_symlink() or not anchor.is_dir():
                    return items
            except OSError:
                return items
        if not self.root.is_dir():
            return items
        # Snapshot each producer index once for this enumeration only. Every
        # artifact still has its current bytes hashed on every API request.
        publications = {}
        ordered = sorted(self._enumeration_entries(deadline, run_id=run_id),
                         key=lambda pair: pair[0])
        if artifact_type is not None:
            # Type is known from the (cached-index) row context alone; rows
            # of another type are dropped here, before either hash path, so
            # their bytes are never opened. The filter loop keeps the
            # enumeration budget: a deadline that expires while filtering
            # fails structurally, never masquerading as an empty match.
            kept = []
            for path, entry in ordered:
                if deadline is not None and time.monotonic() >= deadline:
                    raise TimeoutError('artifact enumeration deadline exceeded')
                if self._row_context(path, entry, publications)[1] == artifact_type:
                    kept.append((path, entry))
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError('artifact enumeration deadline exceeded')
            ordered = kept
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
