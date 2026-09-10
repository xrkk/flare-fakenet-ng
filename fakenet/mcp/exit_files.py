# Copyright 2026 Google LLC
"""Fixed, bounded diagnostic exchange; never a lifecycle recovery source."""
import hashlib
import json
import ntpath
import os
from pathlib import Path
import uuid

from fakenet.mcp.exit_registration import _save

MAX_RECORD = 16 * 1024
QUOTA = 512 * 1024 * 1024


def root():
    # The installed notification entry ignores environment/cwd/test overrides.
    from fakenet.mcp.paths import _windows_common_appdata, DATA_DIR_NAME
    return _windows_common_appdata() / DATA_DIR_NAME / 'logs' / 'exit-evidence'


def read(path, max_bytes=MAX_RECORD):
    if os.name == 'nt':
        import win32file
        import win32con
        import pywintypes
        handle = None
        try:
            handle = win32file.CreateFile(str(path), win32con.GENERIC_READ,
                win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
                None, win32con.OPEN_EXISTING, 0, None)
            size = win32file.GetFileSize(handle)
            if size > max_bytes:
                raise ValueError('exit diagnostic record too large')
            payload = win32file.ReadFile(handle, size)[1]
        except pywintypes.error as exc:
            if exc.winerror in (2, 3):
                raise FileNotFoundError(exc.winerror, str(exc)) from exc
            raise OSError(exc.winerror, str(exc)) from exc
        finally:
            if handle is not None:
                handle.Close()
    else:
        with Path(path).open('rb') as stream:
            payload = stream.read(max_bytes + 1)
    if len(payload) > max_bytes:
        raise ValueError('exit diagnostic record too large')
    result = json.loads(payload)
    if not isinstance(result, dict):
        raise ValueError('invalid exit diagnostic record')
    return result


def publish(path, record):
    if len(json.dumps(record).encode('utf-8')) > MAX_RECORD:
        raise ValueError('exit diagnostic record too large')
    _save(path, record)
    if read(path) != record:
        raise RuntimeError('exit diagnostic publication did not persist')


def run_directory(base, run_id):
    if not isinstance(run_id, str) or str(uuid.UUID(run_id)) != run_id:
        raise ValueError('invalid diagnostic run identity')
    return Path(base) / run_id


def validate_target(record, observed_pid):
    if record.get('schema') != 'fakenet.exit-target.v1':
        raise ValueError('invalid target record schema')
    run_directory('.', record['run_id'])
    for key in ('pid', 'supervisor_pid'):
        if type(record.get(key)) is not int or not 0 < record[key] <= 0xffffffff:
            raise ValueError('invalid target record PID')
    if record['pid'] != observed_pid:
        raise ValueError('foreign notification')
    for key in ('creation_time', 'supervisor_creation_time'):
        value = record.get(key)
        if not isinstance(value, str) or not value.isascii() or not value.isdecimal() or len(value) > 20:
            raise ValueError('invalid creation FILETIME')
    if not isinstance(record.get('supervisor_instance'), str) or not record['supervisor_instance']:
        raise ValueError('missing supervisor instance')
    image = record.get('image', '')
    if (not ntpath.isabs(image) or ntpath.basename(image).lower() != 'fakenetng-mcp-managed.exe'
            or ntpath.normpath(image) != image):
        raise ValueError('invalid dedicated target image')
    if not isinstance(record.get('command_line'), str) or not record['command_line']:
        raise ValueError('missing actual command line')
    if record.get('budget_seconds') != 60:
        raise ValueError('invalid target evidence budget')
    return record


def digest(path, limit=QUOTA):
    total = 0
    hasher = hashlib.sha256()
    with Path(path).open('rb') as stream:
        while True:
            data = stream.read(1024 * 1024)
            if not data:
                break
            total += len(data)
            if total > limit:
                raise ValueError('exit evidence exceeds quota')
            hasher.update(data)
    return hasher.hexdigest(), total
