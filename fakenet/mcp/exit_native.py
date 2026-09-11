# Copyright 2026 Google LLC
"""Read and dump only an already identity-pinned Win64 managed target."""
import ctypes as c
from ctypes import wintypes as w
import os
from pathlib import Path
import struct
import time


class TargetHandle:
    def __init__(self, pid, allow_terminate=False, allow_job=False):
        if type(pid) is not int or pid <= 0 or pid == os.getpid():
            raise ValueError('invalid managed target PID')
        self.pid = pid
        self.kernel = k = c.WinDLL('kernel32', use_last_error=True)
        k.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
        k.OpenProcess.restype = w.HANDLE
        k.CloseHandle.argtypes = [w.HANDLE]
        k.GetProcessTimes.argtypes = [w.HANDLE] + [c.POINTER(c.c_uint64)] * 4
        k.GetProcessTimes.restype = w.BOOL
        k.QueryFullProcessImageNameW.argtypes = [w.HANDLE, w.DWORD, w.LPWSTR, c.POINTER(w.DWORD)]
        k.QueryFullProcessImageNameW.restype = w.BOOL
        k.ReadProcessMemory.argtypes = [w.HANDLE, w.LPCVOID, w.LPVOID, c.c_size_t, c.POINTER(c.c_size_t)]
        k.ReadProcessMemory.restype = w.BOOL
        self.handle = k.OpenProcess(0x100000 | 0x400 | 0x10 | 0x40 |
                                   (1 if allow_terminate else 0) | (0x100 if allow_job else 0), False, pid)
        self.allow_terminate = allow_terminate
        if not self.handle:
            raise c.WinError(c.get_last_error())

    def identity(self):
        creation, exit_time, kernel_time, user_time = (c.c_uint64() for _ in range(4))
        if not self.kernel.GetProcessTimes(self.handle, c.byref(creation), c.byref(exit_time),
                                          c.byref(kernel_time), c.byref(user_time)):
            raise c.WinError(c.get_last_error())
        size = w.DWORD(32768)
        image = c.create_unicode_buffer(size.value)
        if not self.kernel.QueryFullProcessImageNameW(self.handle, 0, image, c.byref(size)):
            raise c.WinError(c.get_last_error())
        return {'pid': self.pid, 'creation_time': str(creation.value), 'image': image.value}

    def _read(self, address, size):
        if not address or not 0 < size <= 65536:
            raise RuntimeError('invalid target process-parameter range')
        buf = c.create_string_buffer(size)
        got = c.c_size_t()
        if not self.kernel.ReadProcessMemory(self.handle, address, buf, size, c.byref(got)):
            raise c.WinError(c.get_last_error())
        if got.value != size:
            raise RuntimeError('partial target process-parameter read')
        return buf.raw

    def exited(self):
        if not self.handle:
            # The handle is released only after its object was verified
            # ended; a released own handle is ended by that invariant, and
            # a later ownership continuation must not fail on it.
            return True
        self.kernel.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]
        self.kernel.WaitForSingleObject.restype = w.DWORD
        result = self.kernel.WaitForSingleObject(self.handle, 0)
        if result == 0xffffffff:
            raise c.WinError(c.get_last_error())
        return result == 0

    def terminate_helper(self):
        if not self.allow_terminate:
            raise RuntimeError('target handle cannot terminate processes; use its Job')
        self.kernel.TerminateProcess.argtypes = [w.HANDLE, w.UINT]
        self.kernel.TerminateProcess.restype = w.BOOL
        if not self.exited() and not self.kernel.TerminateProcess(self.handle, 124):
            raise c.WinError(c.get_last_error())

    def command_line(self):
        # Current release is Win64 only. These are the documented winternl
        # PEB/RTL_USER_PROCESS_PARAMETERS prefixes, queried dynamically. A
        # changed/unsupported layout must fail the native capability gate.
        # No initiator handle is opened and no initiator memory is read.
        if c.sizeof(c.c_void_p) != 8:
            raise RuntimeError('managed exit evidence requires verified Win64 ABI')
        wow = w.BOOL()
        self.kernel.IsWow64Process.argtypes = [w.HANDLE, c.POINTER(w.BOOL)]
        self.kernel.IsWow64Process.restype = w.BOOL
        if not self.kernel.IsWow64Process(self.handle, c.byref(wow)) or wow.value:
            raise RuntimeError('unverified target ABI')
        ntdll = c.WinDLL('ntdll')
        query = ntdll.NtQueryInformationProcess
        query.argtypes = [w.HANDLE, c.c_uint32, w.LPVOID, c.c_uint32, c.POINTER(c.c_uint32)]
        query.restype = c.c_int32
        basic = (c.c_uint64 * 6)()
        returned = c.c_uint32()
        code = query(self.handle, 0, c.byref(basic), c.sizeof(basic), c.byref(returned))
        if code < 0 or returned.value != c.sizeof(basic) or basic[4] != self.pid:
            raise RuntimeError('target PEB query failed: 0x%08x' % (code & 0xffffffff))
        parameters = struct.unpack('<Q', self._read(basic[1] + 0x20, 8))[0]
        length, maximum, pointer = struct.unpack('<HH4xQ', self._read(parameters + 0x70, 16))
        if length <= 0 or length % 2 or length > maximum or maximum > 65534:
            raise RuntimeError('invalid target command-line descriptor')
        return self._read(pointer, length).decode('utf-16-le', errors='strict')

    def dump(self, destination, quota=512 * 1024 * 1024, deadline=None):
        from fakenet.mcp.exit_dump_io import DumpIO
        dbg = c.WinDLL('dbghelp', use_last_error=True)
        dbg.MiniDumpWriteDump.argtypes = [w.HANDLE, w.DWORD, w.HANDLE, w.DWORD,
                                         w.LPVOID, w.LPVOID, w.LPVOID]
        dbg.MiniDumpWriteDump.restype = w.BOOL
        with Path(destination).open('xb', buffering=0) as stream:
            writer = DumpIO(stream, quota, deadline if deadline is not None else time.monotonic() + 60)
            callback = writer.callback()
            if not dbg.MiniDumpWriteDump(self.handle, self.pid,
                    None, 0x4 | 0x20 | 0x800 | 0x1000,
                    None, None, c.byref(callback)):
                if writer.error:
                    raise RuntimeError(writer.error)
                raise c.WinError(c.get_last_error())
            if not writer.started or not writer.finished or writer.writes == 0:
                raise RuntimeError('bounded dump I/O callbacks incomplete')
            return {'writes': writer.writes, 'high_water': writer.high_water}

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def verify_dump(path, expected_pid, quota=512 * 1024 * 1024):
    """Reject a partial/foreign dump before publishing a completed artifact."""
    path = Path(path)
    size = path.stat().st_size
    if not 32 <= size <= quota:
        raise RuntimeError('invalid dump size/quota')
    with path.open('rb') as stream:
        magic, version, count, directory = struct.unpack('<IIII', stream.read(16))
        if magic != 0x504d444d or not 1 <= count <= 1024 or directory < 32 or directory + count * 12 > size:
            raise RuntimeError('invalid minidump directory')
        stream.seek(directory)
        entries = [struct.unpack('<III', stream.read(12)) for _ in range(count)]
        if any(offset + length > size for kind, length, offset in entries):
            raise RuntimeError('minidump stream exceeds file')
        matches = [(length, offset) for kind, length, offset in entries if kind == 15]
        if len(matches) != 1 or matches[0][0] < 12:
            raise RuntimeError('minidump target identity absent')
        stream.seek(matches[0][1])
        structure_size, flags, pid = struct.unpack('<III', stream.read(12))
        if not 12 <= structure_size <= matches[0][0] or not flags & 1 or pid != expected_pid:
            raise RuntimeError('minidump target identity mismatch')
    return size
