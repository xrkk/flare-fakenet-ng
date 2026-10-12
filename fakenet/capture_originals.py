# Copyright 2026 Google LLC
"""Runtime capture originals: per-callback observation and NBI journals.

The paired PCAP remains the packet byte authority.  This module persists the
two callback streams that only existed in memory before:

* ``<raw-pcap>.observations.ndjson`` - one line per successful paired-PCAP
  writer record, appended by the capture producer itself.
* ``<raw-pcap>.nbis.ndjson`` - one line per real listener ``logNbi`` call,
  with the original indicator metrics and the session mapping that was
  actually resolved at that moment.
* ``<raw-pcap>.capture-originals.json`` - the atomic seal published only
  after both writers stopped.  It binds the journals and the paired PCAP by
  basename, byte count, SHA-256 and the producer's real file identity.

All paths are derived from the trusted writer's actual PCAP path; nothing in
an NBI or sample payload can select a path.  Journals are created with
``O_CREAT|O_EXCL|O_NOFOLLOW`` so an existing or concurrently created capture
is never overwritten, and every append is flushed before it is considered
successful.  A failed write leaves the first error with the caller, which
routes it into the existing capture-failure handling; an unsealed or partial
capture never becomes a completed artifact.
"""

import hashlib
import json
import os
import threading
import time
import uuid

CAPTURE_ORIGINALS_SCHEMA = 'fakenet.capture-originals.v1'
CAPTURE_ORIGINALS_JOURNAL_SCHEMA = 'fakenet.capture-originals-journal.v1'
OBSERVATIONS_SUFFIX = '.observations.ndjson'
NBIS_SUFFIX = '.nbis.ndjson'
SEAL_SUFFIX = '.capture-originals.json'


class CaptureOriginalsError(RuntimeError):
    """A runtime original could not be produced or sealed."""


def observations_path(raw_pcap_path):
    return str(raw_pcap_path) + OBSERVATIONS_SUFFIX


def nbis_path(raw_pcap_path):
    return str(raw_pcap_path) + NBIS_SUFFIX


def seal_path(raw_pcap_path):
    return str(raw_pcap_path) + SEAL_SUFFIX


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _plain_regular(path):
    """A plain regular file whose whole path is free of symbolic links."""
    path = os.fspath(path)
    current = os.path.abspath(path)
    while True:
        if os.path.islink(current):
            raise CaptureOriginalsError('capture original path is a symlink')
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    if not os.path.isfile(path) or os.path.islink(path):
        raise CaptureOriginalsError('capture original is not a plain file')
    return os.stat(path)


def _json_safe(value):
    """JSON data for callback-owned values; bytes keep an explicit encoding."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, bytes):
        import base64
        return {'encoding': 'base64',
                'value': base64.b64encode(value).decode('ascii')}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    return str(value)


def _open_exclusive(path):
    return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                   os.O_NOFOLLOW, 0o600)


class CaptureOriginalsWriter(object):
    """Append-only producer for one real capture's runtime originals."""

    def __init__(self, raw_pcap_path, logger=None, capture_id=None,
                 clock=time.time):
        self.raw_pcap_path = str(raw_pcap_path)
        self.pair_basename = os.path.basename(self.raw_pcap_path)
        self.capture_id = str(capture_id or uuid.uuid4())
        uuid.UUID(self.capture_id)
        self.observations_path = observations_path(self.raw_pcap_path)
        self.nbis_path = nbis_path(self.raw_pcap_path)
        self.logger = logger
        self._clock = clock
        self._lock = threading.Lock()
        self._closed = False
        self._sealed = False
        self._observation_count = 0
        self._nbi_count = 0
        self._observations_stream = None
        self._nbis_stream = None
        self._created_paths = []
        try:
            self._observations_stream = self._open_journal(
                self.observations_path, 'observations')
            self._nbis_stream = self._open_journal(
                self.nbis_path, 'nbis')
        except BaseException as exc:
            self._discard_created_journals()
            if isinstance(exc, CaptureOriginalsError):
                raise
            raise CaptureOriginalsError(
                'capture originals already exist or are unopenable for %s: %s'
                % (self.pair_basename, exc)) from exc

    def _open_journal(self, path, journal):
        fd = _open_exclusive(path)
        self._created_paths.append(path)
        stream = os.fdopen(fd, 'w', encoding='utf-8', newline='\n')
        header = {
            'schema': CAPTURE_ORIGINALS_JOURNAL_SCHEMA,
            'journal': journal,
            'capture_id': self.capture_id,
            'pair_basename': self.pair_basename,
            'created_at': float(self._clock()),
        }
        stream.write(json.dumps(header, ensure_ascii=False,
                                separators=(',', ':')) + '\n')
        stream.flush()
        os.fsync(stream.fileno())
        return stream

    def _discard_created_journals(self):
        for stream in (self._observations_stream, self._nbis_stream):
            if stream is not None and not stream.closed:
                try:
                    stream.close()
                except OSError:
                    pass
        for path in self._created_paths:
            try:
                os.unlink(path)
            except OSError:
                pass
        self._created_paths = []

    def _append(self, stream, record):
        """Write one complete JSON line and flush before reporting success."""
        if self._closed or self._sealed:
            raise CaptureOriginalsError(
                'capture originals are closed/sealed; append refused')
        line = json.dumps(record, ensure_ascii=False,
                          separators=(',', ':')) + '\n'
        stream.write(line)
        stream.flush()
        return True

    def record_observation(self, entry):
        """Persist one successful paired-PCAP writer record."""
        if not isinstance(entry, dict):
            raise CaptureOriginalsError('observation entry must be a mapping')
        with self._lock:
            self._observation_count += 1
            record = {
                'schema': CAPTURE_ORIGINALS_JOURNAL_SCHEMA,
                'journal': 'observations',
                'capture_id': self.capture_id,
                'ordinal': self._observation_count,
            }
            for key in ('logical_packet_id', 'observation_role', 'direction',
                        'length', 'sha256', 'flow_id', 'timestamp'):
                if key in entry:
                    record[key] = entry[key]
            try:
                return self._append(self._observations_stream, record)
            except OSError as exc:
                raise CaptureOriginalsError(
                    'observation original write failed: %s' % exc) from exc

    def record_nbi(self, *, session, application_layer_proto,
                   is_ssl_encrypted, network_mode, nbi):
        """Persist one real listener NBI call with its session mapping."""
        if not isinstance(nbi, dict):
            raise CaptureOriginalsError('NBI metrics must be a mapping')
        with self._lock:
            self._nbi_count += 1
            record = {
                'schema': CAPTURE_ORIGINALS_JOURNAL_SCHEMA,
                'journal': 'nbis',
                'capture_id': self.capture_id,
                'ordinal': self._nbi_count,
                'recorded_at': float(self._clock()),
                'application_layer_proto': str(application_layer_proto),
                'is_ssl_encrypted': _json_safe(is_ssl_encrypted),
                'network_mode': str(network_mode),
                'session': _json_safe(dict(session or {})),
                'metrics': _json_safe(nbi),
            }
            try:
                return self._append(self._nbis_stream, record)
            except OSError as exc:
                raise CaptureOriginalsError(
                    'NBI original write failed: %s' % exc) from exc

    def flush(self):
        with self._lock:
            for stream in (self._observations_stream, self._nbis_stream):
                if stream is not None and not stream.closed:
                    stream.flush()
                    os.fsync(stream.fileno())

    def seal(self, raw_pcap_path, converted_pcap_path=None):
        """Atomically publish the seal after both writers stopped."""
        with self._lock:
            if self._sealed:
                raise CaptureOriginalsError('capture originals already sealed')
            if self._closed:
                raise CaptureOriginalsError(
                    'capture originals already closed; seal refused')
            if str(raw_pcap_path) != self.raw_pcap_path:
                raise CaptureOriginalsError(
                    'seal target is not this capture producer')
            for stream in (self._observations_stream, self._nbis_stream):
                stream.flush()
                os.fsync(stream.fileno())
            raw = _plain_regular(raw_pcap_path)
            converted = (_plain_regular(converted_pcap_path)
                         if converted_pcap_path else None)
            observations = _plain_regular(self.observations_path)
            nbis = _plain_regular(self.nbis_path)
            seal = {
                'schema': CAPTURE_ORIGINALS_SCHEMA,
                'capture_id': self.capture_id,
                'pair_basename': self.pair_basename,
                'producer_pid': os.getpid(),
                'sealed_at': float(self._clock()),
                'raw_pcap': self._file_facts(raw_pcap_path, raw),
                'converted_pcap': (self._file_facts(converted_pcap_path,
                                                    converted)
                                   if converted is not None else None),
                'observations': self._file_facts(
                    self.observations_path, observations,
                    records=self._observation_count),
                'nbis': self._file_facts(self.nbis_path, nbis,
                                         records=self._nbi_count),
            }
            target = seal_path(self.raw_pcap_path)
            temporary = target + '.tmp-%s' % os.getpid()
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW, 0o600)
            try:
                with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as out:
                    json.dump(seal, out, ensure_ascii=False, indent=2)
                    out.write('\n')
                    out.flush()
                    os.fsync(out.fileno())
                os.replace(temporary, target)
            except BaseException:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass
                raise
            directory = os.open(os.path.dirname(os.path.abspath(target)),
                                os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            self._sealed = True
            return seal

    @staticmethod
    def _file_facts(path, facts, records=None):
        fact = {
            'name': os.path.basename(str(path)),
            'bytes': int(facts.st_size),
            'sha256': _sha256_file(path),
            'device': int(facts.st_dev),
            'inode': int(facts.st_ino),
        }
        if records is not None:
            fact['records'] = int(records)
        return fact

    def discard(self):
        """Remove this producer's own empty journals (empty-capture path)."""
        with self._lock:
            if self._sealed:
                raise CaptureOriginalsError('sealed originals are immutable')
            self._discard_created_journals()
            self._closed = True

    @property
    def sealed(self):
        return self._sealed

    @property
    def observation_count(self):
        return self._observation_count

    @property
    def nbi_count(self):
        return self._nbi_count

    def close(self):
        with self._lock:
            if self._closed:
                return
            self._closed = True
            for stream in (self._observations_stream, self._nbis_stream):
                if stream is not None and not stream.closed:
                    try:
                        stream.flush()
                        os.fsync(stream.fileno())
                    finally:
                        stream.close()
