# Copyright 2026 Google LLC
"""One-use diagnostic authorization for the current serial managed stop.

The supervisor's live attempt is authoritative. A claimed file alone can
never establish normal termination or restore a prior attempt after restart.
"""
import math
import os
from pathlib import Path
import secrets
import threading
import time

from fakenet.mcp.exit_registration import _save
from fakenet.mcp.exit_files import read

IDENTITY_FIELDS = ('run_id', 'pid', 'creation_time', 'supervisor_pid',
                   'supervisor_creation_time', 'supervisor_instance')


def notification(arguments):
    """Only the four unsigned decimal DWORDs supplied by Windows are accepted."""
    if len(arguments) != 4:
        raise ValueError('exit notification requires four DWORDs')
    values = []
    for arg in arguments:
        if not isinstance(arg, str) or not arg or len(arg) > 10 or any(
                ch not in '0123456789' for ch in arg):
            raise ValueError('invalid exit notification DWORD')
        value = int(arg)
        if value > 0xffffffff:
            raise ValueError('exit notification DWORD overflow')
        values.append(value)
    if not all(values[:3]):
        raise ValueError('invalid zero exit notification identity')
    return dict(zip(('target_pid', 'initiator_pid', 'initiator_tid', 'exit_status'), values))


def _matches(intent, identity, now):
    try:
        return (intent['schema'] == 'fakenet.exit-stop-intent.v1'
                and all(intent[key] == identity[key] for key in IDENTITY_FIELDS)
                and type(intent['sequence']) is int and intent['sequence'] > 0
                and isinstance(intent['nonce'], str) and len(intent['nonce']) == 64
                and all(ch in '0123456789abcdef' for ch in intent['nonce'])
                and math.isfinite(intent['issued_monotonic'])
                and math.isfinite(intent['expires_monotonic'])
                and intent['issued_monotonic'] <= now < intent['expires_monotonic'])
    except (KeyError, TypeError, ValueError):
        return False


class StopIntent:
    def __init__(self, directory, identity, clock=time.monotonic, io=None):
        self.directory = Path(directory)
        self.identity = {key: identity[key] for key in IDENTITY_FIELDS}
        self.clock = clock
        self.sequence = 0
        self.current = None
        self.consumed = False
        self.lock = threading.Lock()
        self.io = io
        self._publishing = None
        self.io_failure = None

    def publish(self, grace_deadline):
        with self.lock:
            if self.current is not None or self._publishing is not None:
                raise RuntimeError('stop intent already active')
            now = self.clock()
            if not math.isfinite(grace_deadline) or grace_deadline <= now:
                raise ValueError('stop intent requires current grace deadline')
            self.sequence += 1
            intent = dict(self.identity, schema='fakenet.exit-stop-intent.v1',
                          sequence=self.sequence, nonce=secrets.token_hex(32),
                          issued_monotonic=now, issued_time=time.time(),
                          expires_monotonic=grace_deadline)
            self._publishing = intent
        try:
            if self.io:
                self.io('publish', intent, grace_deadline)
            else:
                path = self.directory / 'stop-intent.json'
                _save(path, intent)
                if read(path, 4096) != intent:
                    raise RuntimeError('stop intent read-back mismatch')
            with self.lock:
                if self._publishing != intent or self.clock() >= grace_deadline:
                    raise RuntimeError('stop intent publication revoked/expired')
                self.current = intent
                self._publishing = None
                self.consumed = False
                return dict(intent)
        except BaseException:
            with self.lock:
                if self._publishing == intent:
                    self._publishing = None
                self.current = None
            raise

    def _remove(self):
        # Revocation is already an in-memory fact. Failure to remove an old
        # file can never restore it; keep the error for the owner to report.
        try:
            if self.io:
                self.io('remove', None, self.clock() + 30)
            else:
                (self.directory / 'stop-intent.json').unlink(missing_ok=True)
        except BaseException as exc:
            self.io_failure = repr(exc)
            return False
        return True

    def invalidate(self):
        with self.lock:
            self.current = None
            self._publishing = None
            self.consumed = False
        self._remove()

    def accept_normal(self, claim, observed):
        """Consume live authority once; never hold its lock during file I/O."""
        with self.lock:
            current = self.current
            valid = bool(not self.consumed and current is not None and current == claim
                         and _matches(current, self.identity, self.clock())
                         and observed.get('target_pid') == self.identity['pid']
                         and observed.get('initiator_pid') == self.identity['pid']
                         and observed.get('exit_status') == 0)
            if valid:
                self.consumed = True
        if not self._remove():
            with self.lock:
                self.current = None
                self.consumed = False
            return False
        return valid

    def normal_is_valid(self, claim):
        """Revalidate after the helper completes; later failure revokes the ack."""
        with self.lock:
            return bool(self.consumed and self.current == claim
                        and _matches(self.current, self.identity, self.clock()))


def claim(directory, identity, observed, now=None):
    """Called only by the single-flight helper after native target validation.

    A candidate claim is diagnostic evidence; the supervisor must separately
    accept it against its current in-memory attempt before waiving a dump.
    """
    now = time.monotonic() if now is None else now
    if (observed.get('target_pid') != identity.get('pid')
            or observed.get('initiator_pid') != identity.get('pid')
            or observed.get('exit_status') != 0):
        return None
    source = Path(directory) / 'stop-intent.json'
    try:
        data = read(source, 4096)
    except (OSError, ValueError):
        return None
    if not _matches(data, identity, now):
        return None
    # Never overwrite an earlier claim: a stale file cannot be consumed twice.
    destination = Path(directory) / ('stop-intent-claimed-%s.json' % data['nonce'])
    try:
        os.link(source, destination)
    except (FileExistsError, FileNotFoundError):
        return None
    # Re-read the pinned inode. Publication/revocation racing this operation
    # cannot turn it into another attempt, and final live acceptance still gates.
    pinned = read(destination, 4096)
    return pinned if pinned == data else None
