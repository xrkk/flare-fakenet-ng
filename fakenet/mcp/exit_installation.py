# Copyright 2026 Google LLC
"""Fixed package/registration prerequisites for target-only exit evidence."""
import json
import os
from pathlib import Path
import time

from fakenet.mcp import exit_registration as registration
from fakenet.mcp.exit_files import root, digest

HELPER = 'exit-helper/fakenetng-mcp-exit-monitor.exe'
HELPER_IMAGE = 'fakenetng-mcp-exit-monitor.exe'
MANAGED = registration.IMAGE
# Bound the helper sweep so a large process table cannot make cleanup
# observation unbounded.
OBSERVATION_BUDGET = 4096
# ERROR_INVALID_PARAMETER / ERROR_NOT_FOUND: the PID left the process table
# between the snapshot and the native open.
_EXITED = (87, 1168)


def verify_assets(package):
    package = Path(package).resolve()
    manifest_path = package / 'mcp-candidate-manifest.json'
    if manifest_path.stat().st_size > 4 * 1024 * 1024:
        raise RuntimeError('candidate manifest exceeds installation limit')
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    if manifest.get('schema') != 'fakenet.mcp-candidate-manifest.v1':
        raise RuntimeError('candidate manifest schema mismatch')
    rows = manifest.get('files', [])
    selected = [row for row in rows if row['path'] in ('fakenetng-mcp.exe', MANAGED)
                or row['path'].startswith('exit-helper/')]
    names = {row['path'] for row in selected}
    if not {'fakenetng-mcp.exe', MANAGED, HELPER}.issubset(names) or len(names) != len(selected):
        raise RuntimeError('exit evidence assets missing/duplicated in manifest')
    actual = {path.relative_to(package).as_posix() for path in (package / 'exit-helper').rglob('*')
              if path.is_file()}
    if actual != {name for name in names if name.startswith('exit-helper/')}:
        raise RuntimeError('exit helper file set differs from manifest')
    for row in selected:
        relative = Path(row['path'])
        if relative.is_absolute() or '..' in relative.parts or '\\' in row['path']:
            raise RuntimeError('invalid asset manifest path')
        path = package / relative
        if path.is_symlink():
            raise RuntimeError('linked exit evidence asset')
        sha, size = digest(path)
        if sha != row['sha256'] or size != row['size']:
            raise RuntimeError('exit evidence asset integrity mismatch: ' + row['path'])
    return package / HELPER


def protect_directory():
    import win32security
    import win32file
    import pywintypes
    base = root()
    for parent in [base.parent, *base.parent.parents]:
        if parent.exists() and parent.lstat().st_file_attributes & 0x400:
            raise RuntimeError('linked exit diagnostic parent')
    if base.exists():
        verify_directory()
        return base
    base.parent.mkdir(parents=True, exist_ok=True)
    descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)', 1)
    attributes = pywintypes.SECURITY_ATTRIBUTES()
    attributes.SECURITY_DESCRIPTOR = descriptor
    attributes.bInheritHandle = False
    win32file.CreateDirectory(str(base), attributes)
    verify_directory()
    return base


def verify_directory():
    import win32security
    base = root()
    if not base.is_dir() or base.lstat().st_file_attributes & 0x400:
        raise RuntimeError('exit diagnostic directory unavailable/linked')
    descriptor = win32security.GetNamedSecurityInfo(str(base), win32security.SE_FILE_OBJECT,
                                                   win32security.DACL_SECURITY_INFORMATION)
    dacl = descriptor.GetSecurityDescriptorDacl()
    allowed = {'S-1-5-18', 'S-1-5-32-544'}
    if dacl is None or dacl.GetAceCount() != 2:
        raise RuntimeError('exit diagnostic ACL differs from installer contract')
    seen = set()
    for index in range(dacl.GetAceCount()):
        (kind, flags), rights, sid = dacl.GetAce(index)
        identity = win32security.ConvertSidToStringSid(sid)
        if kind != 0 or flags != 3 or rights != 0x1f01ff or identity not in allowed:
            raise RuntimeError('exit diagnostic ACL is not restricted to SYSTEM/admins')
        seen.add(identity)
    if seen != allowed or not descriptor.GetSecurityDescriptorControl()[0] & 0x1000:
        raise RuntimeError('exit diagnostic ACL inheritance is not protected')


def verify(package):
    helper = verify_assets(package)
    verify_directory()
    journal = registration._load(root() / 'registration.json')
    if journal.get('phase') != 'installed':
        raise RuntimeError('exit monitoring registration incomplete')
    expected = [1, '"%s" %%e %%i %%t %%c' % helper]
    if journal['entries'][-1]['after'] != expected:
        raise RuntimeError('exit monitor path differs from current package')
    registry = registration.WindowsRegistry()
    for entry in journal['entries']:
        if registry.read(entry['key'], entry['name']) != registration._value(entry['after']):
            raise RuntimeError('exit monitoring registration drift')
    return helper


def install(package):
    from fakenet.mcp.exit_guard import SingleFlight
    with SingleFlight():
        assert_no_helpers(package)
        helper = verify_assets(package)
        base = protect_directory()
        journal = base / 'registration.json'
        previous = registration._load(journal) if journal.exists() else None
        created = not previous or previous.get('phase') != 'installed'
        registration.install(registration.WindowsRegistry(), journal, helper)
        try:
            verify(package)
        except BaseException:
            if created:
                registration.restore(registration.WindowsRegistry(), journal)
            raise
        return created


def live_processes():
    """Return (pid, image base name) for the current process table.

    Enumeration uses the native snapshot API so the frozen package needs no
    module beyond the pinned dependency set the candidate build installs.
    """
    import ctypes as c
    from ctypes import wintypes as w

    class PROCESSENTRY32W(c.Structure):
        _fields_ = [('dwSize', w.DWORD),
                    ('cntUsage', w.DWORD),
                    ('th32ProcessID', w.DWORD),
                    ('th32DefaultHeapID', c.c_void_p),
                    ('th32ModuleID', w.DWORD),
                    ('cntThreads', w.DWORD),
                    ('th32ParentProcessID', w.DWORD),
                    ('pcPriClassBase', c.c_long),
                    ('dwFlags', w.DWORD),
                    ('szExeFile', w.WCHAR * 260)]

    kernel = c.WinDLL('kernel32', use_last_error=True)
    kernel.CreateToolhelp32Snapshot.argtypes = [w.DWORD, w.DWORD]
    kernel.CreateToolhelp32Snapshot.restype = w.HANDLE
    kernel.Process32FirstW.argtypes = [w.HANDLE, c.POINTER(PROCESSENTRY32W)]
    kernel.Process32NextW.argtypes = [w.HANDLE, c.POINTER(PROCESSENTRY32W)]
    kernel.Process32FirstW.restype = w.BOOL
    kernel.Process32NextW.restype = w.BOOL
    kernel.CloseHandle.argtypes = [w.HANDLE]
    snapshot = kernel.CreateToolhelp32Snapshot(0x2, 0)
    if not snapshot or snapshot == c.c_void_p(-1).value:
        raise c.WinError(c.get_last_error())
    found = []
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = c.sizeof(entry)
        if not kernel.Process32FirstW(snapshot, c.byref(entry)):
            raise c.WinError(c.get_last_error())
        while True:
            found.append((entry.th32ProcessID, entry.szExeFile))
            # Exhaustion reports ERROR_NO_MORE_FILES, which ends the walk.
            if not kernel.Process32NextW(snapshot, c.byref(entry)):
                break
    finally:
        kernel.CloseHandle(snapshot)
    return found


def _pin_helper(pid, expected, allow_terminate):
    """Return a native handle when this PID is the packaged helper image."""
    from fakenet.mcp.exit_native import TargetHandle
    try:
        handle = TargetHandle(pid, allow_terminate=allow_terminate)
    except OSError as exc:
        if exc.winerror in _EXITED:
            return None
        raise
    try:
        image = handle.identity()['image'].casefold()
    except OSError as exc:
        # A PID that left the process table is not this package's helper; any
        # other failure is reported instead of being silently skipped.
        if exc.winerror not in _EXITED:
            handle.close()
            raise
        image = None
    except BaseException:
        handle.close()
        raise
    if image == expected:
        return handle
    handle.close()
    return None


def _packaged_helpers(package, allow_terminate=False, deadline=None,
                      budget=None):
    """Resolve live helper processes of this exact package to native handles.

    Only an image whose full path equals the packaged helper is returned, so a
    foreign program that shares the image name is never opened or terminated.
    """
    expected = str(Path(package).resolve() / HELPER).casefold()
    handles = []
    try:
        for index, (pid, image) in enumerate(live_processes()):
            if budget is not None and index >= budget:
                raise RuntimeError('helper cleanup observation budget exhausted')
            if deadline is not None and time.monotonic() >= deadline:
                raise RuntimeError('helper cleanup observation budget exhausted')
            if pid == os.getpid() or image.casefold() != HELPER_IMAGE:
                continue
            handle = _pin_helper(pid, expected, allow_terminate)
            if handle is None:
                continue
            handles.append(handle)
            if allow_terminate:
                # Terminate as soon as one is pinned: an aborted sweep must
                # not leave an already-identified helper running.
                handle.terminate_helper()
    except BaseException:
        for handle in handles:
            handle.close()
        raise
    return handles


def assert_no_helpers(package):
    handles = _packaged_helpers(package)
    try:
        if handles:
            raise RuntimeError('exit helper still active: %d' % handles[0].pid)
    finally:
        for handle in handles:
            handle.close()


def end_helpers(package, deadline):
    """Close only native-pinned helpers from this exact installed package."""
    handles = _packaged_helpers(package, allow_terminate=True, deadline=deadline,
                                budget=OBSERVATION_BUDGET)
    try:
        while any(not handle.exited() for handle in handles) and time.monotonic() < deadline:
            time.sleep(0.01)
        if any(not handle.exited() for handle in handles):
            raise RuntimeError('helper termination did not complete')
        assert_no_helpers(package)
    finally:
        for handle in handles:
            handle.close()


def restore(package):
    from fakenet.mcp.exit_guard import SingleFlight
    with SingleFlight():
        assert_no_helpers(package)
        registration.restore(registration.WindowsRegistry(), root() / 'registration.json')
