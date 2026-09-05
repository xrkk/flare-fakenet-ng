# Copyright 2026 Google LLC
"""OS-level single-instance guard for fakenetng-mcp (one service per host).

Windows: named mutex in the Global\\ namespace (works across sessions; the
SCM-started LocalSystem service and any stray second copy contend on it).
Non-Windows (debug/test): an flock'd lockfile under the ProgramData root.
"""

import os
import sys

MUTEX_NAME = 'Global\\FakeNet-NG-MCP-SingleInstance'
# CHK-002 (REQ-001/CON-001/NON-001): the headless MCP supervisor and the
# interactive GUI are mutually exclusive operators. Both sides additionally
# contend on this shared cross-session mutex: the GUI takes it at launch
# (fakenet/gui/launcher.py), the service takes it here. Global\ so the
# LocalSystem session-0 service and the user-session GUI actually see each
# other (a Local\ mutex is per-session and would be invisible across them).
SHARED_OPERATOR_MUTEX_NAME = 'Global\\FakeNet-NG-SoleOperator'
ERROR_ALREADY_EXISTS = 183


class SingleInstanceError(RuntimeError):
    pass


class _PosixLock:

    def __init__(self, path):
        import fcntl

        self._path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = open(path, 'a+')
        try:
            fcntl.flock(self._handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self._handle.close()
            raise SingleInstanceError(
                'another fakenetng-mcp instance holds %s' % path)


class _Guard:
    """Owns every lock handle for the process lifetime."""

    def __init__(self, *handles):
        self.handles = handles


def _create_mutex(kernel32, wt, name):
    kernel32.CreateMutexW.restype = wt.HANDLE
    kernel32.CreateMutexW.argtypes = [wt.LPVOID, wt.BOOL, wt.LPCWSTR]
    return kernel32.CreateMutexW(None, False, name)


def acquire(programdata_root=None):
    """Acquire the single-instance guard or raise SingleInstanceError.

    Holds both the MCP-own mutex and the shared sole-operator mutex; a
    conflict on the shared mutex means the GUI is running (GUI-MCP mutual
    exclusion, CHK-002)."""
    if os.name == 'nt':
        import ctypes
        import ctypes.wintypes as wt

        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel32.CloseHandle.restype = wt.BOOL
        kernel32.CloseHandle.argtypes = [wt.HANDLE]
        own = _create_mutex(kernel32, wt, MUTEX_NAME)
        if not own:
            raise SingleInstanceError('CreateMutexW failed')
        if ctypes.get_last_error() == ERROR_ALREADY_EXISTS:
            kernel32.CloseHandle(own)
            raise SingleInstanceError(
                'another fakenetng-mcp instance already runs (%s)' % MUTEX_NAME)
        shared = _create_mutex(kernel32, wt, SHARED_OPERATOR_MUTEX_NAME)
        if not shared:
            kernel32.CloseHandle(own)
            raise SingleInstanceError('CreateMutexW failed')
        if ctypes.get_last_error() == ERROR_ALREADY_EXISTS:
            kernel32.CloseHandle(shared)
            kernel32.CloseHandle(own)
            raise SingleInstanceError(
                'the FakeNet-NG GUI is running; the headless MCP supervisor '
                'and the GUI are mutually exclusive (%s)' %
                SHARED_OPERATOR_MUTEX_NAME)
        return _Guard(int(own), int(shared))
    if programdata_root is None:
        from fakenet.mcp import paths

        programdata_root = paths.programdata_root()
    own = _PosixLock(programdata_root / 'single-instance.lock')
    try:
        shared = _PosixLock(programdata_root / 'sole-operator.lock')
    except SingleInstanceError:
        raise SingleInstanceError(
            'the FakeNet-NG GUI is running; the headless MCP supervisor '
            'and the GUI are mutually exclusive (sole-operator.lock)')
    return _Guard(own, shared)


def acquire_or_exit(programdata_root=None):
    try:
        return acquire(programdata_root)
    except SingleInstanceError as exc:
        sys.stderr.write('fakenetng-mcp: %s\n' % exc)
        raise SystemExit(3)
