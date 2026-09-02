# Copyright 2026 Google LLC
"""Minimal ctypes SCM service runtime for fakenetng-mcp (no pywin32).

``run_as_service(main)`` connects the process to the Service Control
Manager (Windows only).  SCM starts the process with the ``run``
subcommand (see cli.py).  ``main(controller)`` performs the actual work:
it receives a controller exposing ``stop_event`` (set by SCM stop) and
``report_running()`` (call once the service is functional).  ``main``
returns 0 on clean stop, non-zero otherwise.  The full controlled-shutdown
contract lands in P03/P04 — P01 only keeps the SCM lifetime correct.
"""

import logging
import os
import threading

logger = logging.getLogger('fakenetng-mcp.service')

SERVICE_NAME = 'fakenetng-mcp'

_RUNNING = 4
_STOPPED = 1
_START_PENDING = 2
_STOP_PENDING = 3
_NO_ERROR = 0
_ERROR_SERVICE_SPECIFIC_ERROR = 1066
_WAIT_HINT_MS = 15000

if os.name == 'nt':
    import ctypes
    import ctypes.wintypes as wt

    _HANDLER_EX = ctypes.WINFUNCTYPE(wt.DWORD, wt.DWORD, wt.DWORD, wt.DWORD)
    _SERVICE_MAIN = ctypes.WINFUNCTYPE(
        wt.VOID, wt.DWORD, ctypes.POINTER(ctypes.c_wchar_p))

    class _SERVICE_TABLE_ENTRY(ctypes.Structure):
        _fields_ = [
            ('lpServiceName', wt.LPWSTR),
            ('lpServiceProc', _SERVICE_MAIN),
        ]

    class _SERVICE_STATUS(ctypes.Structure):
        _fields_ = [
            ('dwServiceType', wt.DWORD),
            ('dwCurrentState', wt.DWORD),
            ('dwControlsAccepted', wt.DWORD),
            ('dwWin32ExitCode', wt.DWORD),
            ('dwServiceSpecificExitCode', wt.DWORD),
            ('dwCheckPoint', wt.DWORD),
            ('dwWaitHint', wt.DWORD),
        ]

    _advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)

    class _Controller:

        def __init__(self):
            self.stop_event = threading.Event()

        def report_running(self):
            _report(_RUNNING)

        def report_stop_pending(self):
            _report(_STOP_PENDING, wait_hint=_WAIT_HINT_MS)

    _state = {
        'status_handle': None,
        'status': _SERVICE_STATUS(),
        'controller': None,
        'main': None,
        'handler_ref': None,
        'entry_ref': None,
    }

    def _report(state, exit_code=_NO_ERROR, specific=_NO_ERROR,
                checkpoint=0, wait_hint=0):
        handle = _state['status_handle']
        if not handle:
            return
        status = _state['status']
        status.dwServiceType = 0x10  # WIN32_OWN_PROCESS
        status.dwCurrentState = state
        status.dwControlsAccepted = 0x1 if state == _RUNNING else 0
        status.dwWin32ExitCode = exit_code
        status.dwServiceSpecificExitCode = specific
        status.dwCheckPoint = checkpoint
        status.dwWaitHint = wait_hint
        _advapi32.SetServiceStatus(handle, ctypes.byref(status))

    @_HANDLER_EX
    def _handler(control, event_type, event_data):
        if control == 0x1:  # SERVICE_CONTROL_STOP
            controller = _state['controller']
            if controller is not None:
                controller.report_stop_pending()
                controller.stop_event.set()
        return 0

    @_SERVICE_MAIN
    def _service_main_entry(argc, argv):
        handle = _advapi32.RegisterServiceCtrlHandlerExW(
            SERVICE_NAME, _handler, None)
        if not handle:
            return
        _state['status_handle'] = handle
        _report(_START_PENDING, checkpoint=1, wait_hint=_WAIT_HINT_MS)
        try:
            result = _state['main'](_state['controller'])
        except BaseException:
            logger.exception('service main crashed')
            result = 1
        if result:
            _report(_STOPPED, exit_code=_ERROR_SERVICE_SPECIFIC_ERROR,
                    specific=1)
        else:
            _report(_STOPPED, exit_code=_NO_ERROR)


def run_as_service(main):
    """Run ``main(controller)`` under the SCM dispatcher (Windows only)."""
    if os.name != 'nt':
        raise RuntimeError('run_as_service requires Windows')
    _state['controller'] = _Controller()
    _state['main'] = main
    _state['handler_ref'] = _handler
    _state['entry_ref'] = _service_main_entry
    table = _SERVICE_TABLE_ENTRY(SERVICE_NAME, _service_main_entry)
    if not _advapi32.StartServiceCtrlDispatcherW(ctypes.byref(table)):
        error = ctypes.get_last_error()
        raise RuntimeError(
            'StartServiceCtrlDispatcherW failed: %d' % error)
