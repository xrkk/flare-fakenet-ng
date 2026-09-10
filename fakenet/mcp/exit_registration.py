# Copyright 2026 Google LLC
"""Own exactly four per-image Silent Process Exit registry values (P01)."""
import json
import os
from pathlib import Path
import tempfile

IMAGE = 'fakenetng-mcp-managed.exe'
IFEO_PARENT = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
SPE_PARENT = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit'
IFEO = IFEO_PARENT + '\\' + IMAGE
SPE = SPE_PARENT + '\\' + IMAGE
SLOTS = ((IFEO, 'GlobalFlag'), (SPE, 'ReportingMode'),
         (SPE, 'IgnoreSelfExits'), (SPE, 'MonitorProcess'))


def _save(path, record):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix='exit-registration-', suffix='.tmp', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(record, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        from fakenet.mcp.service_stop import replace_result
        replace_result(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def _value(value):
    return tuple(value) if value is not None else None


def _load(path):
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    if data.get('schema') != 'fakenet.exit-registration.v1':
        raise RuntimeError('invalid exit registration ownership record')
    entries = data.get('entries', [])
    if [(e.get('key'), e.get('name')) for e in entries] != list(SLOTS):
        raise RuntimeError('invalid exit registration owned slots')
    if not set(data.get('created_keys', [])).issubset(
            {IFEO_PARENT, SPE_PARENT, IFEO, SPE}):
        raise RuntimeError('invalid exit registration owned keys')
    return data


def install(registry, record_path, monitor_exe):
    monitor_exe = str(Path(monitor_exe).absolute())
    if any(char in monitor_exe for char in ('"', '\r', '\n', '%')):
        raise ValueError('invalid fixed exit monitor path')
    command = '"%s" %%e %%i %%t %%c' % monitor_exe
    record_path = Path(record_path)
    if record_path.exists():
        previous = _load(record_path)
        if previous.get('phase') == 'installed':
            if previous['entries'][-1]['after'] != [1, command]:
                raise RuntimeError('exit monitor path changed; restore old owner first')
            for entry in previous['entries']:
                if registry.read(entry['key'], entry['name']) != _value(entry['after']):
                    raise RuntimeError('exit registration drift')
            return previous
        if previous.get('phase') != 'restored':
            # Reconcile an interrupted install from the exact before/after
            # values. Never infer ownership from the image name alone.
            restore(registry, record_path)
    before = [registry.read(*slot) for slot in SLOTS]
    flags = before[0]
    if flags is not None and (flags[0] != 4 or not isinstance(flags[1], int)):
        raise RuntimeError('external GlobalFlag type is incompatible')
    if (flags is not None and flags[1] & 0x200) or any(v is not None for v in before[1:]):
        raise RuntimeError('external exit monitor registration conflicts')
    after = [(4, (flags[1] if flags else 0) | 0x200), (4, 1), (4, 0), (1, command)]
    record = {'schema': 'fakenet.exit-registration.v1', 'phase': 'prepared',
              'created_keys': registry.missing_keys(),
              'entries': [dict(key=slot[0], name=slot[1], before=old, after=new)
                          for slot, old, new in zip(SLOTS, before, after)]}
    _save(record_path, record)
    try:
        for entry in record['entries'][1:] + record['entries'][:1]:
            # Enable the image flag only after the target-only reporting mode
            # and fixed helper are installed; never inherit a global dump mode.
            if registry.read(entry['key'], entry['name']) != _value(entry['before']):
                raise RuntimeError('exit registration drift before write')
            registry.write(entry['key'], entry['name'], entry['after'])
            if registry.read(entry['key'], entry['name']) != _value(entry['after']):
                raise RuntimeError('exit registration write did not persist')
        record['phase'] = 'installed'
        _save(record_path, record)
    except BaseException:
        restore(registry, record_path)
        raise
    return record


def restore(registry, record_path):
    if not Path(record_path).exists():
        return
    record = _load(record_path)
    # Preflight *all* slots before any mutation, so a foreign edit leaves
    # the scene intact for the installer to report rather than half-remove.
    for entry in record['entries']:
        actual = registry.read(entry['key'], entry['name'])
        if actual not in (_value(entry['before']), _value(entry['after'])):
            raise RuntimeError('exit registration drift; preserve external values')
    # Disable our image flag before restoring the reporting options.
    for entry in record['entries'][:1] + list(reversed(record['entries'][1:])):
        actual = registry.read(entry['key'], entry['name'])
        if actual == _value(entry['before']):
            continue
        if actual != _value(entry['after']):
            raise RuntimeError('exit registration drift during restore')
        if entry['before'] is None:
            registry.delete_value(entry['key'], entry['name'])
        else:
            registry.write(entry['key'], entry['name'], entry['before'])
        if registry.read(entry['key'], entry['name']) != _value(entry['before']):
            raise RuntimeError('exit registration restore did not persist')
    for key in sorted(record['created_keys'], key=len, reverse=True):
        registry.delete_empty_key(key)
    record['phase'] = 'restored'
    _save(record_path, record)


class WindowsRegistry:
    """The fixed 64-bit HKLM view used by the Win10 product installer."""
    def __init__(self):
        import winreg
        self.api = winreg

    def read(self, key, name):
        api = self.api
        try:
            with api.OpenKey(api.HKEY_LOCAL_MACHINE, key, 0,
                             api.KEY_READ | api.KEY_WOW64_64KEY) as handle:
                value, kind = api.QueryValueEx(handle, name)
                return kind, value
        except FileNotFoundError:
            return None

    def write(self, key, name, value):
        api = self.api
        with api.CreateKeyEx(api.HKEY_LOCAL_MACHINE, key, 0,
                             api.KEY_WRITE | api.KEY_WOW64_64KEY) as handle:
            api.SetValueEx(handle, name, 0, value[0], value[1])

    def delete_value(self, key, name):
        api = self.api
        with api.OpenKey(api.HKEY_LOCAL_MACHINE, key, 0,
                         api.KEY_WRITE | api.KEY_WOW64_64KEY) as handle:
            api.DeleteValue(handle, name)

    def missing_keys(self):
        missing = []
        api = self.api
        for key in (IFEO_PARENT, SPE_PARENT, IFEO, SPE):
            try:
                with api.OpenKey(api.HKEY_LOCAL_MACHINE, key, 0,
                                 api.KEY_READ | api.KEY_WOW64_64KEY):
                    pass
            except FileNotFoundError:
                missing.append(key)
        return missing

    def delete_empty_key(self, key):
        api = self.api
        try:
            with api.OpenKey(api.HKEY_LOCAL_MACHINE, key, 0,
                             api.KEY_READ | api.KEY_WOW64_64KEY) as handle:
                subkeys, values, _ = api.QueryInfoKey(handle)
                if subkeys or values:
                    return
            api.DeleteKeyEx(api.HKEY_LOCAL_MACHINE, key, api.KEY_WOW64_64KEY)
        except FileNotFoundError:
            pass
