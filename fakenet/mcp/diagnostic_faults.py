"""Fixed, locally armed diagnostic stimuli; no native operation at import.

The extended arm must name this initialized managed process, its run, config,
and current Windows Job membership. Legacy two-field fault arms never select
a diagnostic stimulus. A rejected or expired arm is observational only.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import time
import uuid

CLASSES = ('stacks_unavailable', 'native_crash', 'unknown_cause')
ARM_KEYS = {'fault', 'nonce', 'run_id', 'pid', 'creation_time', 'config_sha256',
            'job_members', 'expires_ns'}


class DiagnosticUnavailable(RuntimeError):
    """A stimulus cannot establish the required real condition."""


def arm_shape(value):
    if not isinstance(value, dict) or set(value) != ARM_KEYS:
        return False
    try:
        valid_run = str(uuid.UUID(value['run_id'])) == value['run_id']
    except (ValueError, TypeError, AttributeError):
        return False
    return (value['fault'] in CLASSES and valid_run
            and isinstance(value['nonce'], str) and bool(value['nonce'])
            and type(value['pid']) is int and value['pid'] > 0
            and isinstance(value['creation_time'], str)
            and value['creation_time'].isdigit()
            and isinstance(value['config_sha256'], str)
            and len(value['config_sha256']) == 64
            and all(c in '0123456789abcdef' for c in value['config_sha256'])
            and isinstance(value['job_members'], list)
            and bool(value['job_members'])
            and all(type(pid) is int and pid > 0 for pid in value['job_members'])
            and value['job_members'] == sorted(set(value['job_members']))
            and value['pid'] in value['job_members']
            and type(value['expires_ns']) is int)


def current_job_members():
    """Query this process's current Job; no process is created or terminated."""
    if os.name != 'nt':
        raise DiagnosticUnavailable('diagnostic Job observation requires Windows')
    import ctypes as c
    from ctypes import wintypes as w
    # Fixed bound. A larger/changed Job is rejected, never silently truncated.
    class Members(c.Structure):
        _fields_ = [('assigned', w.DWORD), ('count', w.DWORD),
                    ('pids', c.c_size_t * 256)]
    kernel = c.WinDLL('kernel32', use_last_error=True)
    query = kernel.QueryInformationJobObject
    query.argtypes = [w.HANDLE, c.c_int, w.LPVOID, w.DWORD, w.LPVOID]
    query.restype = w.BOOL
    value = Members()
    if not query(None, 3, c.byref(value), c.sizeof(value), None):
        raise c.WinError(c.get_last_error())
    if not 0 < value.assigned == value.count <= 256:
        raise DiagnosticUnavailable('managed Job membership is incomplete')
    return sorted(int(pid) for pid in value.pids[:value.count])


def matching_arm(context, path):
    if os.environ.get('FAKENETNG_MCP_FAULT_INJECTION') != '1' or not context:
        return None
    if context.get('initialized') is not True:
        return None
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 4096:
        return None
    try:
        value = json.loads(path.read_text(encoding='utf-8'))
        if not arm_shape(value):
            return None
        now = time.time_ns()
        if not now < value['expires_ns'] <= now + 120_000_000_000:
            return None
        for name in ('run_id', 'pid', 'creation_time', 'config_sha256', 'nonce'):
            if value[name] != context.get(name):
                return None
        from fakenet.mcp.service_stop import process_identity
        actual = process_identity(os.getpid())
        if any(actual.get(k) != value[k] for k in ('pid', 'creation_time')):
            return None
        if current_job_members() != value['job_members']:
            return None
        config = Path(context['config_path'])
        if config.is_symlink() or hashlib.sha256(config.read_bytes()).hexdigest() != value['config_sha256']:
            return None
        return value
    except (OSError, ValueError, KeyError, TypeError, DiagnosticUnavailable):
        return None


def record_trigger(context, value):
    directory = Path(context['run_dir'])
    if directory.name != value['run_id']:
        raise DiagnosticUnavailable('diagnostic run directory differs')
    with (directory / 'diagnostic-triggered.json').open('x', encoding='utf-8') as stream:
        json.dump(dict(value, observed_time_ns=time.time_ns()), stream)
        stream.flush()
        os.fsync(stream.fileno())


def trigger_native_crash(context, path):
    value = matching_arm(context, path)
    if value is None or value['fault'] != 'native_crash':
        raise DiagnosticUnavailable('native stimulus target arm unconfirmed')
    if os.name != 'nt':
        raise DiagnosticUnavailable('native stimulus requires Windows')
    # ctypes memory reads on Windows translate access violations to Python
    # OSError. Fail-fast deliberately bypasses application exception handlers.
    import ctypes as c
    from ctypes import wintypes as w
    kernel = c.WinDLL('kernel32', use_last_error=True)
    crash = kernel.RaiseFailFastException
    crash.argtypes = [w.LPVOID, w.LPVOID, w.DWORD]
    crash.restype = None
    record_trigger(context, value)
    crash(None, None, 0)
    raise DiagnosticUnavailable('Windows fail-fast unexpectedly returned')


def unknown_cause_observation():
    # A custom RuntimeError explains its own origin and cannot establish an
    # unknown failure. Do not consume the arm or manufacture a terminal event.
    raise DiagnosticUnavailable('no verified unattributed terminal stimulus')
