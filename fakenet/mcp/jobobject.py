# Copyright 2026 Google LLC
"""kill-on-close Job Object self-assignment (P03 IMP-P03-06, record 025).

The service process assigns ITSELF to an UNNAMED job with
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE at startup.  The in-process FakeNet-NG
and any children inherit job membership; when the MCP process dies for
any reason the kernel terminates the whole managed tree.  The job handle
is non-inheritable (children inherit membership, not the handle).
"""

import logging

logger = logging.getLogger('fakenetng-mcp.job')

JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JobObjectExtendedLimitInformation = 9


def setup_kill_on_close_job():
    """Assign the current process to a kill-on-close job.  Returns an
    opaque handle holder (Windows only; no-op elsewhere for dev runs)."""
    import os

    if os.name != 'nt':
        logger.info('job object self-assignment skipped (non-Windows)')
        return None
    import ctypes
    import ctypes.wintypes as wt

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [(name, ctypes.c_ulonglong) for name in
                    ('ReadOperationCount', 'WriteOperationCount',
                     'OtherOperationCount', 'ReadTransferCount',
                     'WriteTransferCount', 'OtherTransferCount')]

    class BASIC(ctypes.Structure):
        _fields_ = [
            ('PerProcessUserTimeLimit', ctypes.c_longlong),
            ('PerJobUserTimeLimit', ctypes.c_longlong),
            ('LimitFlags', wt.DWORD),
            ('MinimumWorkingSetSize', ctypes.c_size_t),
            ('MaximumWorkingSetSize', ctypes.c_size_t),
            ('ActiveProcessLimit', wt.DWORD),
            ('Affinity', ctypes.POINTER(wt.ULONG)),
            ('PriorityClass', wt.DWORD),
            ('SchedulingClass', wt.DWORD),
        ]

    class EXTENDED(ctypes.Structure):
        _fields_ = [
            ('BasicLimitInformation', BASIC),
            ('IoInfo', IO_COUNTERS),
            ('ProcessMemoryLimit', ctypes.c_size_t),
            ('JobMemoryLimit', ctypes.c_size_t),
            ('PeakProcessMemoryUsed', ctypes.c_size_t),
            ('PeakJobMemoryUsed', ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    job = kernel32.CreateJobObjectW(None, None)  # unnamed on purpose
    if not job:
        raise RuntimeError('CreateJobObjectW failed: %d' %
                           ctypes.get_last_error())
    info = EXTENDED()
    info.BasicLimitInformation.LimitFlags = \
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if not kernel32.SetInformationJobObject(
            job, JobObjectExtendedLimitInformation,
            ctypes.byref(info), ctypes.sizeof(info)):
        raise RuntimeError('SetInformationJobObject failed: %d' %
                           ctypes.get_last_error())
    if not kernel32.AssignProcessToJobObject(
            job, kernel32.GetCurrentProcess()):
        raise RuntimeError('AssignProcessToJobObject failed: %d' %
                           ctypes.get_last_error())
    logger.info('process assigned to unnamed kill-on-close job')
    return job
