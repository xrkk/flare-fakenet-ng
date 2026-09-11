# Copyright 2026 Google LLC
"""Atomic Windows Job membership for a separately managed FakeNet process.

The supervisor owns the only non-inheritable Job handle and is never a member.
There is no CreateProcess-then-Assign or uncontained fallback.
"""

import os
import subprocess
import time


def process_alive(pid):
    """True while the PID is a live process (native, no Job needed)."""
    import ctypes as c
    from ctypes import wintypes as w
    kernel = c.WinDLL('kernel32', use_last_error=True)
    open_process = kernel.OpenProcess
    open_process.argtypes = [w.DWORD, w.BOOL, w.DWORD]
    open_process.restype = w.HANDLE
    wait_one = kernel.WaitForSingleObject
    wait_one.argtypes = [w.HANDLE, w.DWORD]
    wait_one.restype = w.DWORD
    close = kernel.CloseHandle
    close.argtypes = [w.HANDLE]
    close.restype = w.BOOL
    handle = open_process(0x00100000 | 0x1000, False, int(pid))
    if not handle:
        return False
    try:
        return wait_one(handle, 0) == 258  # WAIT_TIMEOUT
    finally:
        close(handle)


class ManagedJob:
    def __init__(self):
        if os.name != 'nt':
            raise RuntimeError('managed FakeNet requires native Windows Job support')
        import ctypes as c
        from ctypes import wintypes as w
        self.c, self.w = c, w
        self.kernel = c.WinDLL('kernel32', use_last_error=True)
        self.handle = None
        self.process = None
        self.pid = None

        class IO(c.Structure):
            _fields_ = [(name, c.c_ulonglong) for name in (
                'ReadOperationCount', 'WriteOperationCount', 'OtherOperationCount',
                'ReadTransferCount', 'WriteTransferCount', 'OtherTransferCount')]
        class BASIC(c.Structure):
            _fields_ = [('PerProcessUserTimeLimit', c.c_longlong),
                        ('PerJobUserTimeLimit', c.c_longlong), ('LimitFlags', w.DWORD),
                        ('MinimumWorkingSetSize', c.c_size_t),
                        ('MaximumWorkingSetSize', c.c_size_t),
                        ('ActiveProcessLimit', w.DWORD), ('Affinity', c.c_size_t),
                        ('PriorityClass', w.DWORD), ('SchedulingClass', w.DWORD)]
        class EXTENDED(c.Structure):
            _fields_ = [('BasicLimitInformation', BASIC), ('IoInfo', IO)] + [
                (name, c.c_size_t) for name in ('ProcessMemoryLimit', 'JobMemoryLimit',
                                               'PeakProcessMemoryUsed', 'PeakJobMemoryUsed')]
        self._bind('CreateJobObjectW', [w.LPVOID, w.LPCWSTR], w.HANDLE)
        self._bind('CloseHandle', [w.HANDLE], w.BOOL)
        self._bind('SetInformationJobObject', [w.HANDLE, c.c_int, w.LPVOID, w.DWORD], w.BOOL)
        self._bind('QueryInformationJobObject', [w.HANDLE, c.c_int, w.LPVOID, w.DWORD,
                                                c.POINTER(w.DWORD)], w.BOOL)
        self._bind('TerminateJobObject', [w.HANDLE, w.UINT], w.BOOL)
        self._bind('GetExitCodeProcess', [w.HANDLE, c.POINTER(w.DWORD)], w.BOOL)
        self.handle = self.kernel.CreateJobObjectW(None, None)
        if not self.handle:
            self._error()
        settings = EXTENDED()
        settings.BasicLimitInformation.LimitFlags = 0x2000
        if not self.kernel.SetInformationJobObject(self.handle, 9, c.byref(settings),
                                                   c.sizeof(settings)):
            error = c.get_last_error()
            self.close()
            raise c.WinError(error)

    def _bind(self, name, args, result):
        function = getattr(self.kernel, name)
        function.argtypes, function.restype = args, result
        return function

    def _error(self):
        raise self.c.WinError(self.c.get_last_error())

    def spawn(self, command, cwd, handles, observe=None):
        """CreateProcess receives both JOB_LIST and explicit HANDLE_LIST."""
        c, w = self.c, self.w
        class STARTUPINFO(c.Structure):
            _fields_ = [('cb', w.DWORD), ('lpReserved', w.LPWSTR),
                        ('lpDesktop', w.LPWSTR), ('lpTitle', w.LPWSTR)] + [
                (n, w.DWORD) for n in ('dwX', 'dwY', 'dwXSize', 'dwYSize',
                                      'dwXCountChars', 'dwYCountChars',
                                      'dwFillAttribute', 'dwFlags')] + [
                ('wShowWindow', w.WORD), ('cbReserved2', w.WORD),
                ('lpReserved2', c.POINTER(c.c_byte)), ('hStdInput', w.HANDLE),
                ('hStdOutput', w.HANDLE), ('hStdError', w.HANDLE)]
        class EXTENDED(c.Structure):
            _fields_ = [('StartupInfo', STARTUPINFO), ('lpAttributeList', w.LPVOID)]
        class PROCESS(c.Structure):
            _fields_ = [('hProcess', w.HANDLE), ('hThread', w.HANDLE),
                        ('dwProcessId', w.DWORD), ('dwThreadId', w.DWORD)]
        initialize = self._bind('InitializeProcThreadAttributeList',
                                [w.LPVOID, w.DWORD, w.DWORD, c.POINTER(c.c_size_t)], w.BOOL)
        update = self._bind('UpdateProcThreadAttribute',
                            [w.LPVOID, w.DWORD, c.c_size_t, w.LPVOID, c.c_size_t,
                             w.LPVOID, c.POINTER(c.c_size_t)], w.BOOL)
        delete = self._bind('DeleteProcThreadAttributeList', [w.LPVOID], None)
        create = self._bind('CreateProcessW', [w.LPCWSTR, w.LPWSTR, w.LPVOID,
                            w.LPVOID, w.BOOL, w.DWORD, w.LPVOID, w.LPCWSTR,
                            c.POINTER(EXTENDED), c.POINTER(PROCESS)], w.BOOL)
        size = c.c_size_t()
        initialize(None, 2, 0, c.byref(size))
        if not size.value or size.value > 1024 * 1024:
            self._error()
        attributes = c.create_string_buffer(size.value)
        if not initialize(attributes, 2, 0, c.byref(size)):
            self._error()
        pi = PROCESS()
        try:
            jobs = (w.HANDLE * 1)(self.handle)
            inherited = (w.HANDLE * len(handles))(*handles)
            if not update(attributes, 0, 0x2000D, jobs, c.sizeof(jobs), None, None):
                self._error()
            if not update(attributes, 0, 0x20002, inherited, c.sizeof(inherited), None, None):
                self._error()
            if observe:
                observe('attributes_ready')
            si = EXTENDED()
            si.StartupInfo.cb = c.sizeof(si)
            si.StartupInfo.dwFlags = 0x100  # STARTF_USESTDHANDLES
            si.StartupInfo.hStdInput, si.StartupInfo.hStdOutput, si.StartupInfo.hStdError = handles
            si.lpAttributeList = c.cast(attributes, w.LPVOID)
            text = c.create_unicode_buffer(subprocess.list2cmdline(command))
            if observe:
                observe('before_api')
            if not create(None, text, None, None, True, 0x80000 | 0x8000000,
                          None, str(cwd), c.byref(si), c.byref(pi)):
                self._error()
            self.process, self.pid = pi.hProcess, pi.dwProcessId
            if observe:
                observe('after_api')
        finally:
            if pi.hThread:
                self.kernel.CloseHandle(pi.hThread)
            delete(attributes)
        return self.pid

    def adopt_notification(self, process_handle):
        """An OS-launched SPE helper is pinned before admission, never spawned
        by us without containment. Admission failure must refuse its ACK."""
        assign = self._bind('AssignProcessToJobObject',
                            [self.w.HANDLE, self.w.HANDLE], self.w.BOOL)
        if not assign(self.handle, process_handle):
            self._error()
        observed = self.w.BOOL()
        verify = self._bind('IsProcessInJob', [self.w.HANDLE, self.w.HANDLE,
                            self.c.POINTER(self.w.BOOL)], self.w.BOOL)
        if not verify(process_handle, self.handle, self.c.byref(observed)) or not observed.value:
            raise RuntimeError('SPE helper Job admission not confirmed')

    def poll(self):
        if not self.process:
            return None
        code = self.w.DWORD()
        if not self.kernel.GetExitCodeProcess(self.process, self.c.byref(code)):
            self._error()
        return None if code.value == 259 else code.value

    def members(self):
        c, w = self.c, self.w
        for count in (64, 1024, 16384):
            class LIST(c.Structure):
                _fields_ = [('assigned', w.DWORD), ('count', w.DWORD),
                            ('pids', c.c_size_t * count)]
            result = LIST()
            if self.kernel.QueryInformationJobObject(self.handle, 3, c.byref(result),
                                                      c.sizeof(result), None):
                return list(result.pids[:result.count])
            if c.get_last_error() != 234:
                self._error()
        raise RuntimeError('Job process list exceeded bound')

    def member_alive(self, pid):
        """True only while the PID is a live process, not a terminating
        entry the kernel still lists inside the Job."""
        c, w = self.c, self.w
        open_process = self._bind('OpenProcess', [w.DWORD, w.BOOL, w.DWORD], w.HANDLE)
        wait_one = self._bind('WaitForSingleObject', [w.HANDLE, w.DWORD], w.DWORD)
        close = self._bind('CloseHandle', [w.HANDLE], w.BOOL)
        handle = open_process(0x00100000 | 0x1000, False, pid)
        if not handle:
            return False
        try:
            state = wait_one(handle, 0)
        finally:
            close(handle)
        # WAIT_TIMEOUT (258) is the only state that still has live code.
        return state == 258

    def terminate(self, deadline):
        if not self.kernel.TerminateJobObject(self.handle, 1):
            self._error()
        while any(self.member_alive(pid) for pid in self.members()):
            if time.monotonic() >= deadline:
                raise TimeoutError('managed Job did not become empty')
            time.sleep(0.02)

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None
        if self.process:
            self.kernel.CloseHandle(self.process)
            self.process = None
