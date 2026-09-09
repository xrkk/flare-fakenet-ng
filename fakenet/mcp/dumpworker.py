# Copyright 2026 Google LLC
"""Bounded diagnostic subprocess; never dump/suspend the MCP supervisor."""

import os
import sys
import time
from pathlib import Path


def collect_dump(pid, creation_time, target, deadline):
    import msvcrt
    from fakenet.mcp.jobobject import ManagedJob
    target = Path(target)
    prefix = ([sys.executable] if getattr(sys, 'frozen', False) else
              [sys.executable, '-m', 'fakenet.mcp'])
    command = prefix + ['incident-dump', str(pid), str(creation_time), str(target)]
    job = ManagedJob()
    streams = [open(os.devnull, 'rb'), target.with_suffix('.collector.log').open('wb'),
               target.with_suffix('.collector.err').open('wb')]
    handles = [msvcrt.get_osfhandle(stream.fileno()) for stream in streams]
    try:
        for handle in handles:
            os.set_handle_inheritable(handle, True)
        root = Path(sys.executable).parent if getattr(sys, 'frozen', False) else Path(__file__).resolve().parents[2]
        job.spawn(command, root, handles)
        while job.poll() is None:
            if time.monotonic() >= deadline:
                job.terminate(time.monotonic() + 2)
                raise TimeoutError('dump helper exceeded deadline')
            if target.exists() and target.stat().st_size > 512 * 1024 * 1024:
                job.terminate(time.monotonic() + 2)
                raise RuntimeError('dump exceeded disk quota')
            time.sleep(0.02)
        if job.poll() != 0 or not target.exists() or target.stat().st_size == 0:
            raise RuntimeError('dump helper failed, inspect collector stderr')
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
    file = None
    try:
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
