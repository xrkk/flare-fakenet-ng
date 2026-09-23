# Copyright 2026 Google LLC
"""Optional Windows x64 boot/process identity for diagnostic clock evidence.

SystemBootEnvironmentInformation (class 90) is a private Native API layout
documented by System Informer/phnt, not a stable Microsoft Win32 contract.
Only the Win10 19045 x64 layout is accepted. A missing or changed API yields
an explicit unsupported observation and never affects product decisions.
"""

import ctypes
from ctypes import wintypes
import os
import sys
import uuid

BOOT_CLASS = 90
BOOT_LAYOUT = 'phnt:SYSTEM_BOOT_ENVIRONMENT_INFORMATION:win10-19045-x64'


class GUID(ctypes.Structure):
    _fields_ = [('data1', ctypes.c_uint32), ('data2', ctypes.c_uint16),
                ('data3', ctypes.c_uint16), ('data4', ctypes.c_uint8 * 8)]


class BootEnvironment(ctypes.Structure):
    _fields_ = [('boot_identifier', GUID), ('firmware_type', ctypes.c_uint32),
                ('boot_flags', ctypes.c_uint64)]


def validate_boot_layout():
    if (ctypes.sizeof(ctypes.c_void_p) != 8 or ctypes.sizeof(GUID) != 16 or
            ctypes.sizeof(BootEnvironment) != 32 or
            BootEnvironment.firmware_type.offset != 16 or
            BootEnvironment.boot_flags.offset != 24):
        raise ValueError('unsupported boot information ABI layout')


def decode_boot_result(status, returned_length, raw):
    """Reject short/extended/private-layout responses before decoding fields."""
    validate_boot_layout()
    if status != 0 or returned_length != 32 or len(raw) != 32:
        raise ValueError('NtQuerySystemInformation class 90 status/length mismatch: '
                         '%s/%s/%s' % (status, returned_length, len(raw)))
    value = BootEnvironment.from_buffer_copy(raw)
    boot = str(uuid.UUID(bytes_le=raw[:16]))
    if boot == str(uuid.UUID(int=0)):
        raise ValueError('zero BootIdentifier')
    return {'boot_identifier': boot, 'firmware_type': value.firmware_type,
            'boot_flags': value.boot_flags, 'raw_hex': raw.hex(),
            'ntstatus': status, 'return_length': returned_length,
            'buffer_length': len(raw), 'information_class': BOOT_CLASS,
            'layout': BOOT_LAYOUT}


def _filetime_value(value):
    return (int(value.dwHighDateTime) << 32) | int(value.dwLowDateTime)


def native_identity():
    """Read current process and boot identity; return unsupported on any gap."""
    base = {'schema': 'sst.native-identity.v1', 'supported': False,
            'boot_api': 'NtQuerySystemInformation', 'boot_class': BOOT_CLASS,
            'boot_layout': BOOT_LAYOUT, 'process_api': 'GetProcessTimes',
            'creation_unit': 'FILETIME_100ns_since_1601',
            'frequency_api': 'QueryPerformanceFrequency', 'frequency_unit': 'ticks_per_second'}
    if os.name != 'nt':
        return dict(base, error='native Windows required')
    try:
        version = sys.getwindowsversion()
        if (version.major, version.minor, version.build) != (10, 0, 19045):
            raise ValueError('unverified Windows build: %s.%s.%s' %
                             (version.major, version.minor, version.build))
        validate_boot_layout()
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        ntdll = ctypes.WinDLL('ntdll', use_last_error=True)
        query = ntdll.NtQuerySystemInformation
        query.argtypes = [ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32,
                          ctypes.POINTER(ctypes.c_uint32)]
        query.restype = ctypes.c_long
        blob = BootEnvironment()
        returned = ctypes.c_uint32()
        status = int(query(BOOT_CLASS, ctypes.byref(blob), ctypes.sizeof(blob),
                           ctypes.byref(returned)))
        raw = ctypes.string_at(ctypes.byref(blob), ctypes.sizeof(blob))
        boot = decode_boot_result(status, returned.value, raw)

        current = kernel.GetCurrentProcess
        current.argtypes = []
        current.restype = wintypes.HANDLE
        times = kernel.GetProcessTimes
        times.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
        times.restype = wintypes.BOOL
        creation, exit_time, kernel_time, user_time = (wintypes.FILETIME() for _ in range(4))
        if not times(current(), *(ctypes.byref(x) for x in
                                  (creation, exit_time, kernel_time, user_time))):
            raise OSError('GetProcessTimes failed: %s' % ctypes.get_last_error())
        created = _filetime_value(creation)
        if created <= 0:
            raise ValueError('invalid process creation FILETIME')
        hz = ctypes.c_longlong()
        frequency = kernel.QueryPerformanceFrequency
        frequency.argtypes = [ctypes.POINTER(ctypes.c_longlong)]
        frequency.restype = wintypes.BOOL
        if not frequency(ctypes.byref(hz)) or hz.value <= 0:
            raise OSError('QueryPerformanceFrequency failed: %s' % ctypes.get_last_error())
        pid = kernel.GetCurrentProcessId
        pid.argtypes = []
        pid.restype = wintypes.DWORD
        native_pid = int(pid())
        if native_pid <= 0 or native_pid != os.getpid():
            raise ValueError('current native PID mismatch')
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r'SOFTWARE\Microsoft\Cryptography') as key:
            machine_guid = winreg.QueryValueEx(key, 'MachineGuid')[0]
        if not isinstance(machine_guid, str) or not machine_guid:
            raise ValueError('missing machine GUID')
        return dict(base, supported=True, boot=boot, pid=native_pid,
                    creation_filetime_100ns=created, qpc_frequency=hz.value,
                    vm_identity={'computer_name': os.environ.get('COMPUTERNAME'),
                                 'machine_guid': machine_guid.lower()})
    except Exception as exc:  # noqa: BLE001 - diagnostics cannot block a fault
        return dict(base, error=type(exc).__name__ + ': ' + str(exc))
