# Copyright 2026 Google LLC
"""Exercise service handlers without requiring an SCM in the unit harness."""
import sys
import types

from fakenet.mcp.winservice import build_service_class


def service_type(monkeypatch, main, ready=False):
    reports = []
    scm = types.SimpleNamespace(SERVICE_START_PENDING=2, SERVICE_RUNNING=4,
                                SERVICE_STOP_PENDING=3, SERVICE_STOPPED=1,
                                SERVICE_ACCEPT_STOP=1, SERVICE_WIN32_OWN_PROCESS=16,
                                SetServiceStatus=lambda h, status: reports.append(status[1]))
    class Framework:
        def __init__(self, args):
            self.ssh = 1
            self.checkPoint = 0
        def ReportServiceStatus(self, state, **kwargs):
            reports.append(state)
    monkeypatch.setitem(sys.modules, 'win32service', scm)
    monkeypatch.setitem(sys.modules, 'win32serviceutil',
                        types.SimpleNamespace(ServiceFramework=Framework))
    called = []
    orchestration = types.SimpleNamespace(ready=ready, request=lambda: called.append(128))
    orchestration.stop_authorized = lambda: orchestration.ready
    service = build_service_class(main, orchestration)(['service'])
    return service, scm, reports, called


def test_standard_stop_refused_until_prestop_and_no_default_running_reset(monkeypatch):
    service, scm, reports, calls = service_type(monkeypatch, lambda c: 0)
    service.report(scm.SERVICE_RUNNING)
    assert service.GetAcceptedControls() == 0
    assert service.SvcStop() == 1061
    assert not service.stop_event.is_set()
    assert reports == [scm.SERVICE_RUNNING]
    assert service.SvcOtherEx(128, 0, None) == 0
    assert calls == [128]
    service.prestop.ready = True
    assert service.GetAcceptedControls() == 1
    assert service.SvcStop() == 0
    assert service.stop_event.is_set()
    service.SvcInterrogate()
    assert reports[-2:] == [scm.SERVICE_STOP_PENDING] * 2


def test_svc_run_has_no_framework_trailing_stop_pending(monkeypatch):
    def main(controller):
        controller.report_stop_pending()
        return 0
    service, scm, reports, _ = service_type(monkeypatch, main, ready=True)
    service.SvcRun()
    assert reports == [scm.SERVICE_RUNNING, scm.SERVICE_STOP_PENDING, scm.SERVICE_STOPPED]
