# Copyright 2026 Google LLC
"""SCM host: RUNNING pre-stop first, STOP_PENDING only after clean freeze."""

import logging
import threading

logger = logging.getLogger('fakenetng-mcp.service')
SERVICE_NAME = 'fakenetng-mcp'
SERVICE_DISPLAY_NAME = 'FakeNet-NG MCP (fakenetng-mcp)'


def build_service_class(service_main, orchestrator=None):
    import win32service as scm
    import win32serviceutil

    class Controller:
        def __init__(self, service):
            self.service = service
            self.stop_event = service.stop_event

        def configure_prestop(self, context, config, result_path):
            from fakenet.mcp.service_stop import ServiceStop
            import uuid
            def converge(deadline):
                coord = context.coordinator
                return coord.submit(
                    command_id='service-stop-' + str(uuid.uuid4()),
                    expected_version=coord.snapshot()['state_version'],
                    controller=coord.controller, controller_valid=True,
                    kind='service_controlled_stop', describe={}, internal=True,
                    execute=lambda c: context.runner.stop(c, deadline=deadline))
            self.service.prestop = ServiceStop(
                context.coordinator, converge, self.report_running,
                result_path, stop_grace=config.stop_grace_seconds)

        def report_running(self):
            self.service.report(scm.SERVICE_RUNNING)
            if self.service.prestop is not None and self.service.prestop.ready:
                manager = handle = None
                try:
                    manager = scm.OpenSCManager(None, None, scm.SC_MANAGER_CONNECT)
                    handle = scm.OpenService(manager, SERVICE_NAME, scm.SERVICE_QUERY_STATUS)
                    status = scm.QueryServiceStatusEx(handle)
                    if (status['CurrentState'] != scm.SERVICE_RUNNING or
                            not status['ControlsAccepted'] & scm.SERVICE_ACCEPT_STOP):
                        raise RuntimeError('SCM STOP acceptance is not observable')
                except BaseException:
                    self.service.prestop.ready = False
                    self.service.report(scm.SERVICE_RUNNING)
                    raise
                finally:
                    if handle is not None:
                        scm.CloseServiceHandle(handle)
                    if manager is not None:
                        scm.CloseServiceHandle(manager)

        def report_stop_pending(self):
            self.service.report(scm.SERVICE_STOP_PENDING)

    class FakenetMcpService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY_NAME
        _svc_description_ = 'FakeNet-NG MCP supervisor service (LocalSystem)'

        def __init__(self, args):
            self.stop_event = threading.Event()
            self.prestop = orchestrator
            self._status = scm.SERVICE_START_PENDING
            self._status_lock = threading.RLock()
            super().__init__(args)

        def GetAcceptedControls(self):
            return (scm.SERVICE_ACCEPT_STOP if self.prestop is not None
                    and self.prestop.ready and self._status == scm.SERVICE_RUNNING
                    else 0)

        def report(self, state):
            with self._status_lock:
                if self._status == scm.SERVICE_STOP_PENDING and state != scm.SERVICE_STOPPED:
                    if state != scm.SERVICE_STOP_PENDING:
                        raise RuntimeError('invalid SCM transition after STOP_PENDING')
                self._status = state
                self.ReportServiceStatus(state, waitHint=30000)

        def SvcOtherEx(self, control, event_type, data):
            from fakenet.mcp.service_stop import PRESTOP_CONTROL
            if control != PRESTOP_CONTROL:
                return 120  # ERROR_CALL_NOT_IMPLEMENTED
            if self.prestop is None or self._status != scm.SERVICE_RUNNING:
                return 1061  # ERROR_SERVICE_CANNOT_ACCEPT_CTRL
            try:
                self.prestop.request()
                return 0
            except Exception:
                logger.exception('pre-stop request failed')
                return 1061

        def SvcInterrogate(self):
            # Never use pywin32's default which blindly reports RUNNING.
            with self._status_lock:
                scm.SetServiceStatus(self.ssh, (scm.SERVICE_WIN32_OWN_PROCESS,
                    self._status, self.GetAcceptedControls(), 0, 0,
                    self.checkPoint if self._status == scm.SERVICE_STOP_PENDING else 0, 30000))

        def SvcStop(self):
            if self.prestop is None or not self.prestop.stop_authorized():
                return 1061
            self.report(scm.SERVICE_STOP_PENDING)
            self.stop_event.set()
            return 0

        def SvcRun(self):
            # Override the framework's trailing STOP_PENDING publication.
            self.report(scm.SERVICE_RUNNING)
            try:
                result = service_main(Controller(self))
            except BaseException:
                logger.exception('service main crashed')
                result = 1
            self._status = scm.SERVICE_STOPPED
            self.ReportServiceStatus(scm.SERVICE_STOPPED,
                                     win32ExitCode=1066 if result else 0,
                                     svcExitCode=1 if result else 0)

    return FakenetMcpService


def run_as_service(main):
    import os
    if os.name != 'nt':
        raise RuntimeError('run_as_service requires Windows')
    import servicemanager
    service_class = build_service_class(main)
    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(service_class)
    servicemanager.StartServiceCtrlDispatcher()
