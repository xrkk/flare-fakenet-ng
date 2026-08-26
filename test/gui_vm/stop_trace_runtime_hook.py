# -*- coding: utf-8 -*-
"""Diagnostic-only PyInstaller runtime trace for the frozen core.

This hook is injected only by the diagnostic package builders.  It records
the frozen Python child identity and its final atexit boundary so the external
VM runner can distinguish Python shutdown from the one-file parent's cleanup.
"""

import atexit
import datetime
import json
import os
import sys
import time


TRACE_TAG = '[DEBUG-STOP03]'
TRACE_SCHEMA = 1
_trace_path = None


def _utc_now_text():
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace(
        '+00:00', 'Z')


def _package_root():
    return os.path.dirname(os.path.abspath(sys.executable))


def _write_event(event, **fields):
    global _trace_path
    if _trace_path is None:
        log_root = os.path.join(_package_root(), 'Logs')
        os.makedirs(log_root, exist_ok=True)
        _trace_path = os.path.join(
            log_root, 'diagnostic-stop-runtime-%d.jsonl' % os.getpid())
    record = {
        'schema_version': TRACE_SCHEMA,
        'tag': TRACE_TAG,
        'event': event,
        'utc': _utc_now_text(),
        'monotonic_ns': time.monotonic_ns(),
        'pid': os.getpid(),
        'parent_pid': os.getppid(),
    }
    record.update(fields)
    with open(_trace_path, 'a', encoding='utf-8', newline='') as handle:
        handle.write(json.dumps(
            record, ensure_ascii=False, sort_keys=True) + '\n')
        handle.flush()


def _python_atexit_last():
    # Runtime hooks run before application code, while atexit callbacks run in
    # reverse registration order.  This callback therefore executes after
    # callbacks registered by FakeNet and marks the last Python-level boundary.
    try:
        _write_event('python_atexit_last')
    except Exception:
        pass


if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
    try:
        _write_event(
            'python_runtime_started',
            executable=os.path.abspath(sys.executable),
            mei_path=os.path.abspath(sys._MEIPASS),
            cwd=os.getcwd(),
            argv=list(sys.argv),
        )
        atexit.register(_python_atexit_last)
    except Exception:
        # Diagnostics must not change whether the core can start.  Absence of
        # this event is an explicit evidence failure in the outer runner.
        pass
