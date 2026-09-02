# Copyright 2026 Google LLC
"""OS-level single-instance guard for fakenetng-mcp (one service per host).

Windows: named mutex in the Global\\ namespace (works across sessions; the
SCM-started LocalSystem service and any stray second copy contend on it).
Non-Windows (debug/test): an flock'd lockfile under the ProgramData root.
"""

import os
import sys

MUTEX_NAME = 'Global\\FakeNet-NG-MCP-SingleInstance'
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


def acquire(programdata_root=None):
    """Acquire the single-instance guard or raise SingleInstanceError."""
    if os.name == 'nt':
        import ctypes

        handle = ctypes.windll.kernel32.CreateMutexW(None, False, MUTEX_NAME)
        if not handle:
            raise SingleInstanceError('CreateMutexW failed')
        if ctypes.windll.kernel32.GetLastError() == ERROR_ALREADY_EXISTS:
            ctypes.windll.kernel32.CloseHandle(handle)
            raise SingleInstanceError(
                'another fakenetng-mcp instance already runs (%s)' % MUTEX_NAME)
        return handle
    if programdata_root is None:
        from fakenet.mcp import paths

        programdata_root = paths.programdata_root()
    return _PosixLock(programdata_root / 'single-instance.lock')


def acquire_or_exit(programdata_root=None):
    try:
        return acquire(programdata_root)
    except SingleInstanceError as exc:
        sys.stderr.write('fakenetng-mcp: %s\n' % exc)
        raise SystemExit(3)
