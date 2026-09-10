# Copyright 2026 Google LLC
"""Native no-network self-test of the installed managed exit handoff."""
import os
from pathlib import Path
import threading
import time
import uuid


def child_main(run_id):
    import ctypes as c
    from ctypes import wintypes as w
    from fakenet.mcp.exit_files import root, read
    if str(uuid.UUID(run_id)) != run_id:
        return 2
    kernel = c.WinDLL('kernel32', use_last_error=True)
    kernel.GetCurrentProcess.restype = w.HANDLE
    kernel.IsProcessInJob.argtypes = [w.HANDLE, w.HANDLE, c.POINTER(w.BOOL)]
    contained = w.BOOL()
    if not kernel.IsProcessInJob(kernel.GetCurrentProcess(), None, c.byref(contained)) or not contained:
        return 2
    kernel.GetCommandLineW.restype = w.LPWSTR
    actual_command = kernel.GetCommandLineW()
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            record = read(root() / 'target.json')
        except FileNotFoundError:
            time.sleep(0.02)
            continue
        if (record.get('run_id') == run_id and record.get('pid') == os.getpid()
                and record.get('command_line') == actual_command):
            kernel.ExitProcess.argtypes = [w.UINT]
            kernel.ExitProcess(0xc006)
        time.sleep(0.02)
    return 2


def verify_native(package, supervisor_identity, instance):
    import msvcrt
    from fakenet.mcp.exit_files import root, publish
    from fakenet.mcp.jobobject import ManagedJob
    from fakenet.mcp.exit_retention import ExitRetention
    from fakenet.mcp.service_stop import process_identity
    started = time.monotonic()
    deadline = started + 60
    run_id = str(uuid.uuid4())
    job = ManagedJob()
    retained = None
    fds = []
    try:
        fds = [os.open(os.devnull, os.O_RDWR | os.O_BINARY) for _ in range(3)]
        handles = [msvcrt.get_osfhandle(fd) for fd in fds]
        for handle in handles:
            os.set_handle_inheritable(handle, True)
        pid = job.spawn([str(Path(package) / 'fakenetng-mcp-managed.exe'), 'exit-capability', run_id],
                        root(), handles)
        for fd in fds:
            os.set_handle_inheritable(msvcrt.get_osfhandle(fd), False)
            os.close(fd)
        fds = []
        retained = ExitRetention(run_id, process_identity(pid), supervisor_identity,
                                 instance, package, hard_deadline=deadline)
        condition = threading.Condition()
        with condition:
            result = retained.wait(condition, deadline)
        while job.members() and time.monotonic() < deadline:
            time.sleep(0.02)
        if (not result or not result.get('complete') or not result.get('helper_ended')
                or not result.get('retained_target_handle_closed') or
                result.get('notification', {}).get('exit_status') != 0xc006 or job.members()):
            raise RuntimeError('native exit capability failed: %r' % result)
        publish(retained.directory / 'capability.json', dict(passed=True, run_id=run_id,
                elapsed_seconds=time.monotonic() - started, supervisor_instance=instance))
        return {'run_id': run_id, 'directory': str(retained.directory), 'passed': True}
    finally:
        try:
            for fd in fds:
                os.close(fd)
            if job.members():
                job.terminate(min(deadline, time.monotonic() + 1))
        finally:
            job.close()
