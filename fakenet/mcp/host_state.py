"""Durable host-side intent ledger for one verification command_id.

The host facade is a short-lived stdio process.  A command record survives a
client restart so a retry reconciles the original request instead of starting
a second probe sequence.  The record is a plain JSON file under the configured
state root, protected by an exclusive flock for the same command_id.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import uuid


class HostStateError(RuntimeError):
    pass


def _canonical_command_id(command_id):
    try:
        value = str(uuid.UUID(str(command_id)))
    except (ValueError, AttributeError, TypeError):
        raise HostStateError('command_id must be a canonical UUID') from None
    if value != str(command_id):
        raise HostStateError('command_id must be a canonical UUID')
    return value


class HostStateStore:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, command_id):
        command_id = _canonical_command_id(command_id)
        return self.root / (command_id + '.json')

    @contextmanager
    def lock(self, command_id):
        command_id = _canonical_command_id(command_id)
        lock_path = self.root / (command_id + '.lock')
        with lock_path.open('a+b') as stream:
            try:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise HostStateError('command_busy') from None
            try:
                yield
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

    def _target_path(self, target_key):
        root = self.root / 'targets'
        root.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256(str(target_key).encode('utf-8')).hexdigest()
        return root / (digest + '.lock')

    @contextmanager
    def lock_target(self, target_key):
        """Cross-process single-flight for the current target."""
        path = self._target_path(target_key)
        with path.open('a+b') as stream:
            try:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise HostStateError('target_busy') from None
            try:
                yield
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

    def find_active_target(self, target_key):
        for path in sorted(self.root.glob('*.json')):
            try:
                value = json.loads(path.read_text(encoding='utf-8'))
            except (OSError, ValueError):
                continue
            if not isinstance(value, dict):
                continue
            recorded_key = value.get('target_key')
            if recorded_key != target_key:
                scope = value.get('scope_identity') or {}
                vm_uuid = ((scope.get('vm') or {}).get('uuid')
                           if isinstance(scope, dict) else None)
                if vm_uuid:
                    import re as _re
                    legacy = hashlib.sha256(json.dumps({
                        'vm_uuid': _re.sub(r'[\s-]', '', str(vm_uuid)).lower(),
                    }, ensure_ascii=False, sort_keys=True,
                        separators=(',', ':')).encode('utf-8')).hexdigest()
                    if legacy != target_key:
                        continue
                else:
                    continue
            stage = value.get('stage')
            if stage != 'completed':
                return value
            path = value.get('result_path')
            digest = value.get('result_sha256')
            if not path or not digest:
                return value
            result_path = Path(path)
            if result_path.is_symlink() or not result_path.is_file():
                return value
            try:
                actual = hashlib.sha256(result_path.read_bytes()).hexdigest()
            except OSError:
                return value
            if actual != digest:
                return value
        return None

    def load(self, command_id):
        path = self._path(command_id)
        if not path.is_file():
            return None
        try:
            value = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, ValueError) as exc:
            raise HostStateError('host state unreadable: %r' % exc) from None
        if not isinstance(value, dict) or value.get('command_id') != str(
                command_id):
            raise HostStateError('host state identity mismatch')
        return value

    def create(self, command_id, record):
        command_id = _canonical_command_id(command_id)
        path = self._path(command_id)
        raw = (json.dumps(record, ensure_ascii=False, sort_keys=True,
                          indent=2) + '\n').encode('utf-8')
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            raise HostStateError('host state already exists') from None
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            try:
                path.unlink()
            except OSError:
                pass
            raise
        return record

    def update(self, command_id, record):
        command_id = _canonical_command_id(command_id)
        path = self._path(command_id)
        if not path.is_file():
            raise HostStateError('host state does not exist')
        record = dict(record)
        record['command_id'] = command_id
        record['updated_at'] = time.time()
        fd, temporary = tempfile.mkstemp(dir=self.root, prefix='.host-state-')
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write((json.dumps(record, ensure_ascii=False,
                                         sort_keys=True, indent=2) + '\n')
                             .encode('utf-8'))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
        return record
