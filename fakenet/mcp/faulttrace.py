# Copyright 2026 Google LLC
"""Bounded, in-memory syscall diagnostics during an explicitly injected fault.

Supplemental evidence only: never an acceptance boundary or a cleanup policy.
No payload bytes are retained. In-flight calls may have only one boundary.
"""
import os
import threading
from .native_clock import native_clock_sample

_active = None
_lock = threading.Lock()
_LIMIT = 256


def begin(run_id, nonce):
    global _active
    if os.environ.get('FAKENETNG_MCP_FAULT_INJECTION') != '1':
        return
    with _lock:
        _active = dict(schema='fakenet.fault-call-trace.v1', run_id=run_id,
                       nonce=nonce, pid=os.getpid(), diagnostic_only=True,
                       limit=_LIMIT, dropped=0, next_call_id=0, events=[])


def finish():
    global _active
    with _lock:
        trace, _active = _active, None
        return trace


def _record(trace, operation, phase, call_id, fields):
    if trace is None:
        return
    try:
        clock = native_clock_sample()
        event = dict(operation=operation, phase=phase, call_id=call_id,
                     thread_id=threading.get_native_id(), clock=clock, **fields)
        with _lock:
            if _active is not trace:
                return
            if len(trace['events']) >= _LIMIT:
                trace['dropped'] += 1
            else:
                trace['events'].append(event)
    except Exception:
        # Diagnostics must never suppress or replace the actual operation.
        pass


def call(operation, function, *args, fields=None):
    trace = _active
    call_id = None
    if trace is not None:
        with _lock:
            trace['next_call_id'] += 1
            call_id = trace['next_call_id']
        _record(trace, operation, 'enter', call_id, fields or {})
    try:
        result = function(*args)
    except BaseException as exc:
        current = _active
        if trace is not None or current is not None:
            _record(trace or current, operation, 'raise', call_id,
                    dict(fields or {}, error_type=type(exc).__name__,
                         errno=getattr(exc, 'errno', None), entry_observed=trace is not None))
        raise
    current = _active
    if trace is not None or current is not None:
        count = len(result) if isinstance(result, (bytes, bytearray)) else result if isinstance(result, int) else None
        _record(trace or current, operation, 'return', call_id,
                dict(fields or {}, result_count=count, entry_observed=trace is not None))
    return result


def socket_call(sock, method, *args, role=None):
    fields = {'role': role}
    def identify(phase):
        fields['identity_observed'] = phase
        for key, getter in (('fd', 'fileno'), ('local', 'getsockname'), ('peer', 'getpeername')):
            try:
                fields[key] = getattr(sock, getter)()
            except Exception:
                fields[key] = None
    if _active is not None:
        identify('entry')
    operation = getattr(sock, method)
    def invoke():
        try:
            return operation(*args)
        finally:
            # A recv may have entered before the injection armed this trace.
            # Label return-time identity instead of inventing an entry sample.
            if _active is not None and 'identity_observed' not in fields:
                identify('return')
    return call('socket.' + method, invoke, fields=fields)
