# Copyright 2026 Google LLC
"""Real Windows activity lock for the running config (P03 IMP-P03-05).

Frozen order (sub-plan P03 §3, record 014/013): take the OS handle FIRST,
then read/SHA/parse — eliminating the check-then-read window.  The handle
denies write/delete sharing (FILE_SHARE_READ only) so external in-place
modification or replacement is blocked while FakeNet-NG runs; the service
process itself keeps reading through its own handle.  Reparse points on
the target or any parent directory are rejected before opening.
"""

import os

FILE_SHARE_READ = 0x00000001
OPEN_EXISTING = 3
GENERIC_READ = 0x80000000
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400


def has_reparse_point(path):
    """True when the target or any parent carries a reparse attribute."""
    if os.name != 'nt':
        return False
    import ctypes
    import ctypes.wintypes as wt

    current = os.path.abspath(path)
    GetFileAttributesW = ctypes.windll.kernel32.GetFileAttributesW
    INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF
    while True:
        attrs = GetFileAttributesW(str(current))
        if attrs != INVALID_FILE_ATTRIBUTES and \
                attrs & FILE_ATTRIBUTE_REPARSE_POINT:
            return True
        parent = os.path.dirname(current)
        if parent == current:
            return False
        current = parent


class ActivityLock:

    """Hold a deny-write OS handle on the active config for the run."""

    def __init__(self, path):
        self.path = path
        self._handle = None

    def acquire(self):
        if has_reparse_point(self.path):
            raise OSError('reparse point on config path rejected')
        if os.name != 'nt':
            # Non-Windows (dev/tests): advisory presence only.
            self._handle = open(self.path, 'rb')
            return self
        import ctypes
        import ctypes.wintypes as wt

        CreateFileW = ctypes.windll.kernel32.CreateFileW
        CreateFileW.restype = wt.HANDLE
        CreateFileW.argtypes = [
            wt.LPCWSTR, wt.DWORD, wt.DWORD, wt.LPVOID, wt.DWORD, wt.DWORD,
            wt.HANDLE]
        handle = CreateFileW(str(os.path.abspath(self.path)), GENERIC_READ,
                             FILE_SHARE_READ, None, OPEN_EXISTING,
                             FILE_ATTRIBUTE_REPARSE_POINT, None)
        if handle in (None, -1) or \
                handle == ctypes.c_void_p(-1).value:
            raise OSError('activity lock open failed (sharing violation '
                          'or missing file)')
        self._handle = handle
        return self

    def release(self):
        if self._handle is None:
            return
        if os.name == 'nt':
            import ctypes

            ctypes.windll.kernel32.CloseHandle(self._handle)
        else:
            try:
                self._handle.close()
            except OSError:
                pass
        self._handle = None

    def __enter__(self):
        return self.acquire()

    def __exit__(self, *exc):
        self.release()
