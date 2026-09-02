# Copyright 2026 Google LLC
"""Windows SCM service runtime for fakenetng-mcp via pywin32.

P01 originally froze a hand-rolled ctypes dispatcher (DEC-003), but the
real-VM acceptance showed it never convinced the SCM (status reports were
dropped and the process hung in START_PENDING).  pywin32 ships with the
MCP SDK wheel set anyway (mcp==2.1.1 win32 marker dependency), so the
service entry now uses the battle-tested ServiceFramework.  The
controlled-shutdown contract itself still lands in P03/P04.
"""

import logging
import threading

logger = logging.getLogger('fakenetng-mcp.service')

SERVICE_NAME = 'fakenetng-mcp'
SERVICE_DISPLAY_NAME = 'FakeNet-NG MCP (fakenetng-mcp)'
_WAIT_HINT_MS = 15000
_SERVICE_EXIT_ERROR = 1066


def build_service_class(service_main, orchestrator=None):
    """Return a ServiceFramework subclass running ``service_main(stop_event)``.

    ``service_main`` returns 0 for a clean stop or non-zero for a
    service-specific failure.
    """
    import win32service
    import win32serviceutil

    class _Controller:

        def __init__(self, framework):
            self._framework = framework

        @property
        def stop_event(self):
            return self._framework.stop_event

        def report_running(self):
            # The pywin32 framework already reports SERVICE_RUNNING before
            # SvcDoRun executes; nothing to do here.
            return None

        def report_stop_pending(self):
            self._framework.ReportServiceStatus(
                win32service.SERVICE_STOP_PENDING)

    class FakenetMcpService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY_NAME
        _svc_description_ = ('FakeNet-NG MCP supervisor service '
                             '(headless, LocalSystem)')

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            import servicemanager
            import threading

            self.stop_event = threading.Event()
            self.svcmgr = servicemanager
            self.orchestrator = None

        def SvcStop(self):
            # P04 IMP-P04-06: controlled exit — checkpoint refresh keeps the
            # SCM from force-killing the long convergence (which would
            # degrade this into the ACC-007 crash path).
            self.ReportServiceStatus(
                win32service.SERVICE_STOP_PENDING,
                waitHint=_WAIT_HINT_MS + 30000)
            self._checkpoint_thread = threading.Thread(
                target=self._refresh_checkpoints, daemon=True)
            self._checkpoint_thread.start()
            hook = controlled_exit_hook
            if hook is not None:
                threading.Thread(target=hook, daemon=True).start()
            self.stop_event.set()

        def _refresh_checkpoints(self):
            import servicemanager
            import time

            checkpoint = 1
            while not self.stop_event.wait(10):
                checkpoint += 1
                try:
                    self.ReportServiceStatus(
                        win32service.SERVICE_STOP_PENDING,
                        waitHint=_WAIT_HINT_MS + 30000,
                        checkpoint=checkpoint)
                except Exception:  # noqa: BLE001 - best effort
                    return

        def SvcDoRun(self):
            self.svcmgr.LogInfoMsg('%s starting' % SERVICE_NAME)
            try:
                result = service_main(_Controller(self))
            except Exception:  # noqa: BLE001 - report and stop cleanly
                logger.exception('service main crashed')
                result = 1
            if result:
                self.ReportServiceStatus(
                    win32service.SERVICE_STOPPED,
                    win32ExitCode=_SERVICE_EXIT_ERROR, svcExitCode=1)
            else:
                self.ReportServiceStatus(win32service.SERVICE_STOPPED)

    return FakenetMcpService


def run_as_service(main):
    """Host ``main(stop_event)`` inside the SCM dispatcher (Windows only).

    Canonical frozen-service hosting: SCM starts the exe, we initialize the
    service manager, register the single hosted service class and hand the
    thread to the dispatcher.  Install/uninstall stay in cli.py (sc.exe).
    """
    import os

    if os.name != 'nt':
        raise RuntimeError('run_as_service requires Windows')
    import servicemanager

    service_class = build_service_class(main)
    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(service_class)
    servicemanager.StartServiceCtrlDispatcher()
