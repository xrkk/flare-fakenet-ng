"""Optional root-owned read-only fact channel for the local isolation fixture.

The observer is deliberately a narrow request/response protocol.  It accepts
only a registered command id, a phase and a fresh hex challenge.  It never
accepts argv, shell, paths or mutation actions.  The root coordinator is the
only producer; this client validates the root-owned channel and the live
kernel/producer identity before publishing facts to the host provider.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import time
import uuid


SCHEMA = 'fakenetng.host-observer-response.v1'
REQUEST_SCHEMA = 'fakenetng.host-observer-request.v1'
MAX_RESPONSE = 256 * 1024
MAX_REQUEST = 4096
MAX_WINDOW_SECONDS = 900
CHALLENGE_RE = re.compile(r'^[0-9a-f]{32,128}$')


class ObserverError(RuntimeError):
    pass


def _regular(path):
    try:
        return stat.S_ISREG(os.lstat(str(path)).st_mode)
    except OSError:
        return False


def _fifo(path):
    try:
        return stat.S_ISFIFO(os.lstat(str(path)).st_mode)
    except OSError:
        return False


def _safe_ancestors(path):
    path = Path(path)
    if not path.is_absolute():
        return False
    for part in [path, *path.parents]:
        try:
            st = os.lstat(str(part))
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
                return False
            # A writable ancestor lets another user replace the channel.
            if st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o022:
                return False
        except OSError:
            return False
    return True


def _proc_identity(pid):
    pid = int(pid)
    if pid <= 0:
        raise ObserverError('observer producer PID invalid')
    try:
        stat_line = Path('/proc/%d/stat' % pid).read_text(
            encoding='utf-8', errors='replace')
        status = Path('/proc/%d/status' % pid).read_text(
            encoding='utf-8', errors='replace')
    except OSError as exc:
        raise ObserverError('observer producer not live: %r' % exc) from None
    fields = stat_line.rsplit(')', 1)[-1].split()
    if not fields or fields[0] in ('Z', 'X', 'x'):
        raise ObserverError('observer producer exited')
    try:
        birth_ticks = int(fields[19])
    except (IndexError, ValueError):
        raise ObserverError('observer producer birth unavailable') from None
    uid = None
    for line in status.splitlines():
        if line.startswith('Uid:'):
            uids = list(map(int, line.split()[1:]))
            uid = uids[0] if len(uids) == 4 and all(v == 0 for v in uids) else None
            break
    if uid is None:
        raise ObserverError('observer producer UID unavailable')
    try:
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    except OSError as exc:
        raise ObserverError('observer boot identity unavailable: %r' % exc) \
            from None
    return {'pid': pid, 'birth_ticks': birth_ticks, 'uid': uid, 'boot_id': boot}


def _script_sha(pid, configured=None):
    paths = []
    try:
        cmdline = Path('/proc/%d/cmdline' % int(pid)).read_bytes()
    except OSError:
        cmdline = b''
    try:
        cwd = Path(os.readlink('/proc/%d/cwd' % int(pid)))
    except OSError:
        cwd = None
    for raw in cmdline.split(b'\0'):
        if raw.endswith(b'.py'):
            text = raw.decode('utf-8', 'replace')
            candidate = Path(text)
            if not candidate.is_absolute() and cwd is not None:
                candidate = cwd / candidate
            paths.append(candidate)
    for path in paths:
        try:
            if configured and path.absolute() != Path(configured).absolute():
                continue
            if path.is_file() and not path.is_symlink():
                return hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            continue
    return None


def validate_response(value, *, command_id, phase, challenge,
                      producer_script=None, expected_uid=0, now=None,
                      requested_at=None):
    now = time.time() if now is None else float(now)
    if expected_uid != 0:
        raise ObserverError('observer trust root must be kernel root')
    if not isinstance(value, dict) or value.get('schema') != SCHEMA:
        raise ObserverError('observer response schema invalid')
    if value.get('command_id') != str(command_id):
        raise ObserverError('observer command id mismatch')
    if value.get('phase') != phase:
        raise ObserverError('observer phase mismatch')
    if not isinstance(challenge, str) or not CHALLENGE_RE.fullmatch(challenge):
        raise ObserverError('observer challenge invalid')
    if value.get('challenge') != challenge:
        raise ObserverError('observer challenge mismatch')
    if set(value) - {'schema', 'command_id', 'phase', 'challenge',
                     'producer', 'script_sha256', 'facts', 'collected_at'}:
        raise ObserverError('observer response has extra fields')
    producer = value.get('producer')
    if not isinstance(producer, dict):
        raise ObserverError('observer producer missing')
    if set(producer) - {'uid', 'pid', 'birth_ticks', 'boot_id',
                        'script_sha256', 'window_start', 'window_end',
                        'lease_id'}:
        raise ObserverError('observer producer has extra fields')
    if producer.get('uid') != expected_uid:
        raise ObserverError('observer producer uid mismatch')
    for key in ('pid', 'birth_ticks', 'boot_id', 'script_sha256',
                'window_start', 'window_end'):
        if producer.get(key) is None:
            raise ObserverError('observer producer %s missing' % key)
    live = _proc_identity(producer['pid'])
    if live['uid'] != expected_uid:
        raise ObserverError('observer producer live uid mismatch')
    if int(producer['birth_ticks']) != live['birth_ticks']:
        raise ObserverError('observer producer birth mismatch')
    if str(producer['boot_id']) != live['boot_id']:
        raise ObserverError('observer boot mismatch')
    try:
        start = float(producer['window_start'])
        end = float(producer['window_end'])
    except (TypeError, ValueError):
        raise ObserverError('observer window invalid') from None
    if not all(map(math.isfinite, (start, end, now))) or end <= start:
        raise ObserverError('observer window invalid')
    if start > now or end < now:
        raise ObserverError('observer window inactive')
    if end - start > MAX_WINDOW_SECONDS:
        raise ObserverError('observer window too wide')
    actual_script = _script_sha(producer['pid'], producer_script)
    if actual_script is None:
        raise ObserverError('observer script identity unavailable')
    if producer.get('script_sha256') != actual_script:
        raise ObserverError('observer producer script mismatch')
    if value.get('script_sha256') != actual_script:
        raise ObserverError('observer script identity mismatch')
    collected = value.get('collected_at')
    if (type(collected) not in (int, float) or not math.isfinite(collected)
            or collected < start or collected > now + 1
            or now - collected > 5
            or requested_at is not None and collected < requested_at - 0.05):
        raise ObserverError('observer collection is not current')
    if not isinstance(producer.get('lease_id'), str) or not CHALLENGE_RE.fullmatch(producer['lease_id']):
        raise ObserverError('observer lease identity missing')
    if not isinstance(value.get('facts'), dict):
        raise ObserverError('observer facts missing')
    for key in ('pid', 'birth_ticks', 'boot_id', 'script_sha256',
                'lease_id', 'window_start', 'window_end'):
        if (value['facts'].get('observer_identity') or {}).get(key) != producer.get(key):
            raise ObserverError('observer facts and producer identity mismatch')
    return value


class RootObserverClient:
    """Read-only client for one root-owned coordinator directory."""

    def __init__(self, config):
        self.config = dict(config or {})
        self.directory = Path(str(self.config.get('directory') or ''))
        self.expected_uid = 0
        self.producer_script = self.config.get('producer_script')
        self.timeout = float(self.config.get('timeout_seconds', 2))
        self.request_path = self.directory / 'request.fifo'
        self.response_root = self.directory / 'responses'
        self._prepare()

    def _prepare(self):
        if not _safe_ancestors(self.directory):
            raise ObserverError('observer directory has an unsafe ancestor')
        try:
            st = os.lstat(str(self.directory))
        except OSError as exc:
            raise ObserverError('observer directory unavailable: %r' % exc) \
                from None
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != self.expected_uid:
            raise ObserverError('observer directory ownership invalid')
        if stat.S_IMODE(st.st_mode) & 0o022:
            raise ObserverError('observer directory is writable by others')
        if (not _fifo(self.request_path) or
                os.lstat(str(self.request_path)).st_uid != 0):
            raise ObserverError('observer request is not a FIFO')
        if not _safe_ancestors(self.response_root) or not _regular(
                self.response_root / '.keep'):
            raise ObserverError('observer response directory invalid')
        keep = self.response_root / '.keep'
        if os.stat(str(keep)).st_uid != self.expected_uid:
            raise ObserverError('observer response owner invalid')

    def request(self, command_id, phase, challenge, timeout=None):
        try:
            uuid.UUID(str(command_id))
        except (ValueError, TypeError, AttributeError):
            raise ObserverError('observer command id invalid') from None
        if phase not in ('pre', 'final'):
            raise ObserverError('observer phase invalid')
        if not isinstance(challenge, str) or not CHALLENGE_RE.fullmatch(
                challenge):
            raise ObserverError('observer challenge invalid')
        payload = json.dumps({
            'schema': REQUEST_SCHEMA,
            'version': 1,
            'command_id': str(command_id),
            'phase': phase,
            'challenge': challenge,
        }, separators=(',', ':')).encode('utf-8') + b'\n'
        if len(payload) > MAX_REQUEST:
            raise ObserverError('observer request too large')
        budget = self.timeout if timeout is None else min(
            self.timeout, float(timeout))
        if budget <= 0:
            raise ObserverError('observer budget exhausted')
        deadline = time.monotonic() + budget
        requested_at = time.time()
        self._prepare()
        try:
            fd = os.open(str(self.request_path),
                         os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW)
        except OSError as exc:
            raise ObserverError('observer request open failed: %r' % exc) \
                from None
        try:
            fifo_stat = os.fstat(fd)
            if not stat.S_ISFIFO(fifo_stat.st_mode) or fifo_stat.st_uid != 0:
                raise ObserverError('observer FIFO identity changed')
            if len(payload) > os.fpathconf(fd, 'PC_PIPE_BUF'):
                raise ObserverError('observer atomic request too large')
            written = os.write(fd, payload)
            if written != len(payload):
                raise ObserverError('observer short request write')
        finally:
            os.close(fd)
        response_path = self.response_root / (challenge + '.json')
        while time.monotonic() < deadline:
            try:
                st = os.lstat(str(response_path))
            except FileNotFoundError:
                time.sleep(0.02)
                continue
            except OSError as exc:
                raise ObserverError('observer response stat failed: %r' % exc) \
                    from None
            if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode):
                raise ObserverError('observer response is not a regular file')
            if st.st_uid != self.expected_uid or stat.S_IMODE(
                    st.st_mode) & 0o022:
                raise ObserverError('observer response ownership invalid')
            if st.st_size > MAX_RESPONSE:
                raise ObserverError('observer response too large')
            fd = os.open(str(response_path),
                         os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                opened = os.fstat(fd)
                if (opened.st_dev != st.st_dev or opened.st_ino != st.st_ino
                        or opened.st_size > MAX_RESPONSE):
                    raise ObserverError('observer response changed while opening')
                raw = b''
                while len(raw) <= MAX_RESPONSE:
                    chunk = os.read(fd, min(65536, MAX_RESPONSE + 1 - len(raw)))
                    if not chunk:
                        break
                    raw += chunk
                after = os.fstat(fd)
                if (opened.st_mtime_ns, opened.st_ctime_ns, opened.st_size) != (after.st_mtime_ns, after.st_ctime_ns, after.st_size):
                    raise ObserverError('observer response changed while reading')
            finally:
                os.close(fd)
            if len(raw) > MAX_RESPONSE:
                raise ObserverError('observer response too large')
            try:
                value = json.loads(raw.decode('utf-8'))
            except (UnicodeDecodeError, ValueError) as exc:
                raise ObserverError('observer response invalid: %r' % exc) \
                    from None
            return validate_response(
                value, command_id=command_id, phase=phase, challenge=challenge,
                producer_script=self.producer_script,
                expected_uid=self.expected_uid, requested_at=requested_at)
        raise ObserverError('observer response timeout')

    def new_challenge(self):
        return secrets.token_hex(16)
