# Copyright 2026 Google LLC
"""Opt-in observations at the owned-driver subprocess, never a recovery oracle.

Eight records/run, 128 runs, 64 KiB/record. No automatic evidence deletion.
Any preparation/output/quota failure disables this observer for this service
instance and warns in service.log; missing/incomplete observations are not pass.
Only the factory supplies the service-owned logs root and native identity.
"""
import contextlib
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import subprocess
import threading
import time
import uuid

ENVIRONMENT_SWITCH = 'FAKENET_MCP_OWNED_DRIVER_DIAGNOSTICS'
MAX_RECORD_BYTES = 64 * 1024
MAX_RECORDS_PER_RUN = 8
MAX_RUNS = 128
MAX_STREAM_CHARS = 4096
_LOCAL = threading.local()
_LOG = logging.getLogger(__name__)


def warn(reason):
    # Even a broken logging handler must not replace the compensation outcome.
    try:
        _LOG.warning('owned-driver-diagnostics incomplete: %s', reason)
    except Exception:
        pass


def create(logs_root):
    """No files/identity calls when disabled; native failure never stops service."""
    if os.environ.get(ENVIRONMENT_SWITCH) != '1':
        return None
    try:
        from fakenet.mcp.native_provenance import native_identity
        identity = native_identity()
        pid = identity['pid']
        created = identity['creation_filetime_100ns']
        if (identity.get('supported') is not True or type(pid) is not int
                or pid != os.getpid() or type(created) is not int or created <= 0):
            raise ValueError('untrusted native identity')
        return Observer(Path(logs_root) / 'owned-driver-diagnostics', pid, str(created))
    except Exception as exc:
        warn('native/preparation ' + type(exc).__name__)
        return None


def redact(value):
    if isinstance(value, bytes):
        value = value.decode('utf-8', errors='replace')
    value = value or ''
    # Redact before taking a tail so a split credential cannot reappear.
    value = re.sub(r'(?i)bearer\s+\S+', 'Bearer <REDACTED>', value)
    value = re.sub(r'(?i)((?:api[_-]?key|token|password|authorization)\s*[:=]\s*)'
                   r'(?:"[^"\r\n]*"|\'[^\'\r\n]*\'|[^\s,;]+)',
                   r'\1<REDACTED>', value)
    return value[-MAX_STREAM_CHARS:]


class Observer:
    def __init__(self, root, pid, created):
        self.root = root
        self.pid = pid
        self.created = created
        self.incomplete_reason = None
        self._lock = threading.RLock()

    def incomplete(self, reason):
        if self.incomplete_reason is None:
            self.incomplete_reason = reason
            warn(reason)

    def prepare(self, run_id, deadline):
        try:
            if self.incomplete_reason is not None:
                return None
            if str(uuid.UUID(run_id)) != run_id:
                raise ValueError('noncanonical run identity')
            return Invocation(self, run_id, deadline)
        except Exception as exc:
            self.incomplete('prepare ' + type(exc).__name__)
            return None

    def _check_quota(self, run_id):
        if self.root.is_symlink():
            raise ValueError('diagnostic root is a link')
        self.root.mkdir(parents=True, exist_ok=True)
        runs = 0
        existing_run = False
        for p in self.root.iterdir():
            runs += 1
            if runs > MAX_RUNS or p.is_symlink() or not p.is_dir():
                raise ValueError('directory quota/identity')
            existing_run |= p.name == run_id
        if not existing_run and runs >= MAX_RUNS:
            raise ValueError('run quota')
        root = self.root / run_id
        root.mkdir(exist_ok=True)
        count = 0
        for p in root.iterdir():
            count += 1
            if (count >= MAX_RECORDS_PER_RUN or p.is_symlink() or not p.is_file()
                    or p.stat().st_size > MAX_RECORD_BYTES):
                raise ValueError('record quota/identity')
        return root

    def emit(self, run_id, record):
        temporary = None
        created_staging = False
        try:
            with self._lock:
                if self.incomplete_reason is not None:
                    return
                payload = json.dumps(dict(record, schema='sst.owned-driver-diagnostics.v1',
                                          run_id=run_id, supervisor_pid=self.pid,
                                          supervisor_creation_filetime=self.created),
                                     ensure_ascii=False, allow_nan=False).encode('utf-8')
                if len(payload) > MAX_RECORD_BYTES:
                    raise ValueError('record byte quota')
                root = self._check_quota(run_id)
                unique = uuid.uuid4().hex
                temporary = root / (unique + '.tmp')
                final = root / (unique + '.json')
                with temporary.open('xb') as stream:
                    created_staging = True
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
                # Atomic no-clobber publication (same owned filesystem).
                os.link(temporary, final)
        except Exception as exc:
            self.incomplete('emit ' + type(exc).__name__)
        finally:
            # Only the unpublished staging file created by this invocation.
            if created_staging:
                try:
                    temporary.unlink()
                except Exception as exc:
                    self.incomplete('staging cleanup ' + type(exc).__name__)


class Invocation:
    def __init__(self, observer, run_id, deadline):
        self.observer = observer
        self.run_id = run_id
        self.deadline = deadline
        self.started = None

    def begin(self):
        try:
            self.started = time.monotonic()
        except Exception as exc:
            self.observer.incomplete('clock ' + type(exc).__name__)

    def finish(self, command, remaining, completed=None, exception=None,
               before_dispatch=False):
        try:
            ended = time.monotonic()
            record = {
                'stage': 'before_dispatch' if before_dispatch else 'subprocess_return',
                'clock': 'service process time.monotonic',
                'start_monotonic': self.started, 'end_monotonic': ended,
                'deadline_monotonic': self.deadline,
                'remaining_at_dispatch': self.deadline - self.started,
                'subprocess_timeout': remaining,
                'remaining_at_return': self.deadline - ended,
                'argv_program': str(command[0]),
                'argv_sha256': hashlib.sha256(json.dumps(command, separators=(',', ':')).encode()).hexdigest(),
                'returncode': completed.returncode if completed is not None else None,
                'timeout': isinstance(exception, subprocess.TimeoutExpired),
                'exception_type': type(exception).__name__ if exception is not None else None,
                'classification': 'deadline_before_dispatch' if before_dispatch else 'child_result',
                'stdout_tail': redact(completed.stdout if completed is not None else getattr(exception, 'stdout', None)),
                'stderr_tail': redact(completed.stderr if completed is not None else getattr(exception, 'stderr', None)),
            }
            self.observer.emit(self.run_id, record)
        except Exception as exc:
            self.observer.incomplete('result/serialization ' + type(exc).__name__)


def current():
    return getattr(_LOCAL, 'invocation', None)


@contextlib.contextmanager
def scope(invocation):
    previous = current()
    _LOCAL.invocation = invocation
    try:
        yield
    finally:
        _LOCAL.invocation = previous
