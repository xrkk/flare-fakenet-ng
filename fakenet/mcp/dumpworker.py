# Copyright 2026 Google LLC
"""Bounded diagnostic subprocess; never dump/suspend the MCP supervisor."""

import os
import sys
import time
from pathlib import Path


def collect_dump(pid, creation_time, target, deadline, quota=None):
    import msvcrt
    from fakenet.mcp.jobobject import ManagedJob
    target = Path(target)
    # The helper writes a staging file; only a verified MDMP is published
    # under the final name, and only inside the caller's remaining budget.
    staging = target.with_name(target.name + '.part')
    prefix = ([sys.executable] if getattr(sys, 'frozen', False) else
              [sys.executable, '-m', 'fakenet.mcp'])
    command = prefix + ['incident-dump', str(pid), str(creation_time), str(staging)]
    job = ManagedJob()
    streams = [open(os.devnull, 'rb'), target.with_suffix('.collector.log').open('wb'),
               target.with_suffix('.collector.err').open('wb')]
    handles = [msvcrt.get_osfhandle(stream.fileno()) for stream in streams]
    try:
        for handle in handles:
            os.set_handle_inheritable(handle, True)
        root = Path(sys.executable).parent if getattr(sys, 'frozen', False) else Path(__file__).resolve().parents[2]
        job.spawn(command, root, handles)
        limit = 512 * 1024 * 1024 if quota is None else min(quota, 512 * 1024 * 1024)
        while job.poll() is None:
            if time.monotonic() >= deadline:
                job.terminate(time.monotonic() + 2)
                raise TimeoutError('dump helper exceeded deadline')
            if staging.exists() and staging.stat().st_size > limit:
                job.terminate(time.monotonic() + 2)
                raise RuntimeError('dump exceeded disk quota')
            time.sleep(0.02)
        try:
            if job.poll() != 0 or not staging.exists() or staging.stat().st_size == 0:
                raise RuntimeError('dump helper failed, inspect collector stderr')
            from fakenet.mcp.exit_native import verify_dump
            # The same structural and target-identity check the exit capture
            # uses: a non-MDMP or foreign file is not evidence.
            verify_dump(staging, pid, limit)
            if time.monotonic() >= deadline:
                raise TimeoutError('dump exceeded deadline before publication')
            os.replace(staging, target)
        except BaseException:
            try:
                staging.unlink()
            except OSError:
                pass
            raise
    finally:
        for handle in handles:
            os.set_handle_inheritable(handle, False)
        job.close()
        for stream in streams:
            stream.close()


def dump_main(pid, creation_time, target):
    import ctypes as c
    from ctypes import wintypes as w
    from fakenet.mcp.service_stop import process_identity
    if pid == os.getpid() or process_identity(pid)['creation_time'] != creation_time:
        raise RuntimeError('dump target identity mismatch')
    kernel = c.WinDLL('kernel32', use_last_error=True)
    dbg = c.WinDLL('dbghelp', use_last_error=True)
    kernel.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
    kernel.OpenProcess.restype = w.HANDLE
    kernel.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, w.LPVOID, w.DWORD, w.DWORD, w.HANDLE]
    kernel.CreateFileW.restype = w.HANDLE
    kernel.CloseHandle.argtypes = [w.HANDLE]
    dbg.MiniDumpWriteDump.argtypes = [w.HANDLE, w.DWORD, w.HANDLE, w.DWORD,
                                     w.LPVOID, w.LPVOID, w.LPVOID]
    dbg.MiniDumpWriteDump.restype = w.BOOL
    process = kernel.OpenProcess(0x400 | 0x10 | 0x40, False, pid)
    if not process:
        raise c.WinError(c.get_last_error())
    kernel.GetProcessTimes.argtypes = [w.HANDLE] + [c.POINTER(c.c_uint64)] * 4
    kernel.GetProcessTimes.restype = w.BOOL
    file = None
    try:
        # Re-read the identity from the handle actually being dumped: closing
        # the gap between the PID lookup and OpenProcess keeps a reused PID
        # from being dumped under the old target's name.
        stamps = [c.c_uint64() for _ in range(4)]
        if not kernel.GetProcessTimes(process, *(c.byref(item) for item in stamps)):
            raise c.WinError(c.get_last_error())
        if str(stamps[0].value) != str(creation_time):
            raise RuntimeError('dump target identity changed before the handle opened')
        file = kernel.CreateFileW(str(target), 0x40000000, 0, None, 1, 0x80, None)
        if file in (None, c.c_void_p(-1).value):
            raise c.WinError(c.get_last_error())
        if not dbg.MiniDumpWriteDump(process, pid, file, 0x4 | 0x20 | 0x800 | 0x1000,
                                     None, None, None):
            raise c.WinError(c.get_last_error())
    finally:
        if file not in (None, c.c_void_p(-1).value):
            kernel.CloseHandle(file)
        kernel.CloseHandle(process)
    return 0
