# Copyright 2026 Google LLC
"""Fixed package/registration prerequisites for target-only exit evidence."""
import json
from pathlib import Path

from fakenet.mcp import exit_registration as registration
from fakenet.mcp.exit_files import root, digest

HELPER = 'exit-helper/fakenetng-mcp-exit-monitor.exe'
MANAGED = registration.IMAGE


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


def assert_no_helpers(package):
    import psutil
    expected = str(Path(package).resolve() / HELPER).casefold()
    for process in psutil.process_iter(['pid', 'name']):
        if (process.info.get('name') or '').casefold() != 'fakenetng-mcp-exit-monitor.exe':
            continue
        try:
            if process.exe().casefold() == expected:
                raise RuntimeError('exit helper still active: %d' % process.pid)
        except psutil.NoSuchProcess:
            continue


def end_helpers(package, deadline):
    """Close only native-pinned helpers from this exact installed package."""
    import psutil
    import time
    from fakenet.mcp.exit_native import TargetHandle
    expected = str(Path(package).resolve() / HELPER).casefold()
    handles = []
    try:
        for index, process in enumerate(psutil.process_iter(['pid', 'name'])):
            if index >= 4096 or time.monotonic() >= deadline:
                raise RuntimeError('helper cleanup observation budget exhausted')
            if (process.info.get('name') or '').casefold() != 'fakenetng-mcp-exit-monitor.exe':
                continue
            try:
                handle = TargetHandle(process.pid, allow_terminate=True)
            except OSError:
                if not psutil.pid_exists(process.pid):
                    continue
                raise
            try:
                matches = handle.identity()['image'].casefold() == expected
            except BaseException:
                handle.close()
                raise
            if not matches:
                handle.close()
                continue
            handles.append(handle)
            handle.terminate_helper()
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
