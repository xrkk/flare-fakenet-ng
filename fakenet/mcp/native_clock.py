# Copyright 2026 Google LLC
"""Native clock sampling for relay connection-terminal evidence.

The relay records one native observation per connection-terminal decision so
the acceptance adjudication can compare the decision instant with kernel
trace events without the guest wall-timer's 15,625,000ns uncertainty.  The
FILETIME read is bracketed by QPC exactly like the fault-injection sampler:
a later consumer retains sampling latency instead of trusting displayed
nanoseconds.  This module never gates product behavior; a failed sample is
recorded as unsupported.
"""

import os


def native_clock_sample():
    """Return a native clock observation dict, or an unsupported marker."""
    if os.name != 'nt':
        return {'supported': False, 'reason': 'native Windows required'}
    try:
        import ctypes
        import threading
        from ctypes import wintypes
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        precise = kernel.GetSystemTimePreciseAsFileTime
        precise.argtypes = [ctypes.POINTER(wintypes.FILETIME)]
        precise.restype = None
        counter = kernel.QueryPerformanceCounter
        frequency = kernel.QueryPerformanceFrequency
        for query in (counter, frequency):
            query.argtypes = [ctypes.POINTER(ctypes.c_longlong)]
            query.restype = wintypes.BOOL
        hz, lo, hi = (ctypes.c_longlong() for _ in range(3))
        stamp = wintypes.FILETIME()
        if not frequency(ctypes.byref(hz)) or hz.value <= 0:
            raise OSError('QueryPerformanceFrequency unavailable')
        if not counter(ctypes.byref(lo)):
            raise OSError('QueryPerformanceCounter before failed')
        precise(ctypes.byref(stamp))
        if not counter(ctypes.byref(hi)) or hi.value < lo.value:
            raise OSError('QueryPerformanceCounter after invalid')
        return {
            'supported': True,
            'api': 'GetSystemTimePreciseAsFileTime',
            'filetime_100ns': (stamp.dwHighDateTime << 32) | stamp.dwLowDateTime,
            'qpc_before': lo.value,
            'qpc_after': hi.value,
            'qpc_frequency': hz.value,
        }
    except Exception as exc:  # noqa: BLE001 - diagnostic evidence only
        return {'supported': False, 'reason': repr(exc)}
