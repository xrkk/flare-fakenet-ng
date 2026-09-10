# Copyright 2026 Google LLC
"""Fixed package/registration prerequisites for target-only exit evidence."""
import ctypes as c
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
# ERROR_NO_MORE_FILES is the only Toolhelp result that means clean exhaustion.
_EXHAUSTED = 18
_BUDGET_EXHAUSTED = 'helper cleanup observation budget exhausted'


class _ProcessEntry32W(c.Structure):
    """PROCESSENTRY32W with the field widths pinned to the documented Win64
    layout, so the walk reads the same offsets on every host."""
    _fields_ = [('dwSize', c.c_uint32),
                ('cntUsage', c.c_uint32),
                ('th32ProcessID', c.c_uint32),
                ('th32DefaultHeapID', c.c_void_p),
                ('th32ModuleID', c.c_uint32),
                ('cntThreads', c.c_uint32),
                ('th32ParentProcessID', c.c_uint32),
                ('pcPriClassBase', c.c_int32),
                ('dwFlags', c.c_uint32),
                ('szExeFile', c.c_wchar * 260)]


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


def _native_error(code):
    """Build an OSError carrying the Win32 failure code on every host."""
    win_error = getattr(c, 'WinError', None)
    if win_error is not None:
        return win_error(code)
    error = OSError(code, 'Win32 error %d' % code)
    error.winerror = code
    return error


def _kernel32():
    return c.WinDLL('kernel32', use_last_error=True)


def _last_error():
    return c.get_last_error()


class Observation:
    """One shared observation window for a whole cleanup chain.

    The first native scan, the per-candidate work, the termination wait and
    the residual check all spend the same remaining deadline and the same
    remaining observation count, so reusing a constant cannot let one chain
    consume several budgets.
    """

    def __init__(self, deadline=None, budget=None):
        self.deadline = deadline
        self.remaining = budget

    def check(self):
        """Fail closed once the shared window has closed."""
        if self.deadline is not None and time.monotonic() >= self.deadline:
            raise RuntimeError(_BUDGET_EXHAUSTED)

    def observe(self):
        """Account for one observed process entry inside the shared budget."""
        if self.remaining is not None:
            if self.remaining <= 0:
                raise RuntimeError(_BUDGET_EXHAUSTED)
            self.remaining -= 1
        self.check()


def _require_exhausted(code):
    if code != _EXHAUSTED:
        raise _native_error(code)


def _walk_snapshot(snapshot, kernel, observation, last_error):
    """Yield (pid, image base name) from a Toolhelp snapshot, failing closed.

    Only ERROR_NO_MORE_FILES means clean exhaustion; every other
    Process32FirstW/Process32NextW result is raised, so a partial process
    table can never be presented as a complete one.  Every native call is
    bracketed by the shared window, so no call is made after it has closed and
    no complete table is reported once it has closed.
    """
    entry = _ProcessEntry32W()
    entry.dwSize = c.sizeof(entry)
    observation.check()
    found = kernel.Process32FirstW(snapshot, c.byref(entry))
    observation.check()
    if not found:
        _require_exhausted(last_error())
        return
    while True:
        observation.observe()
        yield entry.th32ProcessID, entry.szExeFile
        observation.check()
        following = kernel.Process32NextW(snapshot, c.byref(entry))
        observation.check()
        if not following:
            _require_exhausted(last_error())
            return


def live_processes(observation=None):
    """Yield (pid, image base name) for the current process table.

    Enumeration is native and interruptible between calls, so the frozen
    package needs no module beyond the pinned dependency set the candidate
    build installs while the caller's window still bounds the walk itself.
    """
    observation = observation if observation is not None else Observation()
    kernel = _kernel32()
    kernel.CreateToolhelp32Snapshot.argtypes = [c.c_uint32, c.c_uint32]
    kernel.CreateToolhelp32Snapshot.restype = c.c_void_p
    kernel.Process32FirstW.argtypes = [c.c_void_p, c.POINTER(_ProcessEntry32W)]
    kernel.Process32NextW.argtypes = [c.c_void_p, c.POINTER(_ProcessEntry32W)]
    kernel.Process32FirstW.restype = c.c_int
    kernel.Process32NextW.restype = c.c_int
    kernel.CloseHandle.argtypes = [c.c_void_p]
    observation.check()
    snapshot = kernel.CreateToolhelp32Snapshot(0x2, 0)
    observation.check()
    if not snapshot or snapshot == c.c_void_p(-1).value:
        raise _native_error(_last_error())
    try:
        yield from _walk_snapshot(snapshot, kernel, observation, _last_error)
    finally:
        kernel.CloseHandle(snapshot)


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


def _packaged_helpers(package, allow_terminate=False, observation=None):
    """Resolve live helper processes of this exact package to native handles.

    Only an image whose full path equals the packaged helper is returned, so a
    foreign program that shares the image name is never opened or terminated.
    The shared window bounds the native walk and each pinned process, not just
    the consumption of an already-materialised table.
    """
    observation = observation if observation is not None else Observation()
    expected = str(Path(package).resolve() / HELPER).casefold()
    handles = []
    walk = live_processes(observation)
    try:
        for pid, image in walk:
            observation.check()
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
    finally:
        walk.close()
    return handles


def assert_no_helpers(package, observation=None):
    handles = _packaged_helpers(package, observation=observation)
    try:
        if handles:
            raise RuntimeError('exit helper still active: %d' % handles[0].pid)
    finally:
        for handle in handles:
            handle.close()


def end_helpers(package, deadline, budget=OBSERVATION_BUDGET):
    """Close only native-pinned helpers from this exact installed package.

    One observation window covers the whole sweep: the first native scan, the
    per-candidate work, the termination wait and the final residual check.
    """
    observation = Observation(deadline, budget)
    handles = _packaged_helpers(package, allow_terminate=True,
                                observation=observation)
    try:
        while any(not handle.exited() for handle in handles) and time.monotonic() < deadline:
            time.sleep(0.01)
        if any(not handle.exited() for handle in handles):
            raise RuntimeError('helper termination did not complete')
        assert_no_helpers(package, observation=observation)
    finally:
        for handle in handles:
            handle.close()


def restore(package):
    from fakenet.mcp.exit_guard import SingleFlight
    with SingleFlight():
        assert_no_helpers(package)
        registration.restore(registration.WindowsRegistry(), root() / 'registration.json')
