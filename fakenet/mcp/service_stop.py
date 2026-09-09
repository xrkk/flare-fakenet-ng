# Copyright 2026 Google LLC
"""Two-phase service stop. A diagnostic result is never recovery authority."""

import json
import os
import tempfile
import threading
import time
import uuid
from pathlib import Path

PRESTOP_CONTROL = 128


def process_identity(pid=None):
    """Pin a Windows PID to its creation FILETIME (not a reused PID)."""
    import ctypes
    from ctypes import wintypes as w
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
    kernel.OpenProcess.restype = w.HANDLE
    kernel.GetProcessTimes.argtypes = [w.HANDLE] + [ctypes.POINTER(w.FILETIME)] * 4
    kernel.GetProcessTimes.restype = w.BOOL
    kernel.CloseHandle.argtypes = [w.HANDLE]
    handle = kernel.OpenProcess(0x1000, False, pid or os.getpid())
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    values = [w.FILETIME() for _ in range(4)]
    try:
        if not kernel.GetProcessTimes(handle, *[ctypes.byref(v) for v in values]):
            raise ctypes.WinError(ctypes.get_last_error())
        created = (values[0].dwHighDateTime << 32) | values[0].dwLowDateTime
        return {'pid': pid or os.getpid(), 'creation_time': str(created)}
    finally:
        kernel.CloseHandle(handle)


def read_result(path):
    try:
        data = json.loads(Path(path).read_text(encoding='utf-8'))
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


class ServiceStop:
    """One pre-stop worker; control handlers and diagnostic reads stay short.

    The converge callback must obey the supplied monotonic deadline. Every
    blocking lifecycle/collector primitive also owns a timeout; the outer
    watchdog is a fail-closed backstop, never permission to overlap workers.
    """

    def __init__(self, coordinator, converge, publish_ready, result_path,
                 stop_grace=60, identity=None, inflight_limit=60):
        self.coordinator = coordinator
        self.converge = converge
        self.publish_ready = publish_ready
        self.path = Path(result_path)
        self.identity = identity if identity is not None else process_identity()
        self.instance = str(uuid.uuid4())
        self.budget = stop_grace + 420
        self.inflight_limit = inflight_limit
        self._lock = threading.RLock()
        self._worker = None
        self._attempt = 0
        self.ready = False
        self._result = None
        self._write('idle')

    def _write(self, phase, reason=None):
        data = dict(self.identity, instance_id=self.instance,
                    attempt=self._attempt, phase=phase, reason=reason,
                    timestamp=time.time())
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(dir=self.path.parent, prefix='.stop-')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                json.dump(data, stream)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        self._result = data

    def request(self):
        with self._lock:
            if self.ready or (self._worker and self._worker.is_alive()):
                return dict(self._result)
            if not self.coordinator.wait_for_idle(0) and self._attempt:
                return dict(self._result)
            self.coordinator.begin_draining()
            self._attempt += 1
            self._write('draining')
            self._worker = threading.Thread(target=self._run,
                                            name='service-prestop', daemon=True)
            self._worker.start()
            return dict(self._result)

    def _fail(self, reason):
        self.coordinator.fail_controlled_exit(reason)
        with self._lock:
            self.ready = False
            self._write('failed', reason)

    def _run(self):
        deadline = time.monotonic() + self.budget
        if not self.coordinator.wait_for_idle(min(self.inflight_limit, self.budget)):
            self._fail('inflight_timeout')
            return
        try:
            result = self.converge(deadline)
            if time.monotonic() >= deadline:
                raise TimeoutError('prestop total budget exhausted')
            if result.get('state') != 'stopped':
                raise RuntimeError(result.get('failure_reason') or 'not cleanly stopped')
            state = self.coordinator.snapshot()
            if (state['state'] != 'stopped' or state['run_id'] is not None or
                    state['controller'] is not None):
                raise RuntimeError('recovery responsibility remains')
            with self._lock:
                # SCM acceptance is published before the success file.
                self.ready = True
                try:
                    self.publish_ready()
                    self._write('succeeded')
                except BaseException:
                    self.ready = False
                    raise
        except BaseException as exc:
            self._fail(str(exc))


def stop_installed_service(config, result_path, snapshot_path):
    """Local administrator stop wrapper; no kill/delete fallback."""
    import win32service as scm
    from fakenet.mcp.snapshot import StateSnapshot
    manager = scm.OpenSCManager(None, None, scm.SC_MANAGER_CONNECT)
    service = None
    deadline = time.monotonic() + config.stop_grace_seconds + 450
    try:
        try:
            service = scm.OpenService(manager, 'fakenetng-mcp',
                                      scm.SERVICE_QUERY_STATUS | scm.SERVICE_STOP |
                                      scm.SERVICE_START | scm.SERVICE_USER_DEFINED_CONTROL)
        except Exception as exc:
            if getattr(exc, 'winerror', None) != 1060:
                raise
            marker, corrupt = StateSnapshot(snapshot_path).read()
            if corrupt or (marker and marker['needs_recovery']):
                raise RuntimeError('service absent with unresolved recovery marker')
            return
        status = scm.QueryServiceStatusEx(service)
        marker, corrupt = StateSnapshot(snapshot_path).read()
        if status['CurrentState'] == scm.SERVICE_STOPPED:
            if not corrupt and not (marker and marker['needs_recovery']):
                return
            scm.StartService(service, None)
        while status['CurrentState'] != scm.SERVICE_RUNNING:
            if time.monotonic() >= deadline:
                raise TimeoutError('service did not become available for pre-stop')
            time.sleep(0.1)
            status = scm.QueryServiceStatusEx(service)
        identity = process_identity(status['ProcessId'])
        initial = read_result(result_path)
        if not initial or any(initial.get(k) != v for k, v in identity.items()):
            raise RuntimeError('current service pre-stop identity is unavailable')
        instance = initial.get('instance_id')
        attempt = initial.get('attempt')
        if not instance or not isinstance(attempt, int):
            raise RuntimeError('invalid pre-stop diagnostic identity')
        sharing = initial.get('phase') in ('draining', 'succeeded', 'failed')
        scm.ControlService(service, PRESTOP_CONTROL)
        while time.monotonic() < deadline:
            status = scm.QueryServiceStatusEx(service)
            if status['ProcessId'] != identity['pid']:
                raise RuntimeError('service identity changed during pre-stop')
            current = read_result(result_path)
            if current and all(current.get(k) == v for k, v in identity.items()) \
                    and current.get('instance_id') == instance:
                number = current.get('attempt', -1)
                if isinstance(number, int) and (number > attempt or
                                               (sharing and number == attempt)):
                    phase = current.get('phase')
                    if phase == 'failed':
                        raise RuntimeError(current.get('reason') or 'pre-stop failed')
                    if phase == 'succeeded' and status['ControlsAccepted'] & scm.SERVICE_ACCEPT_STOP:
                        # Handle pins this service; recheck PID creation before STOP.
                        if process_identity(status['ProcessId']) != identity:
                            raise RuntimeError('service PID was reused')
                        scm.ControlService(service, scm.SERVICE_CONTROL_STOP)
                        break
            time.sleep(0.1)
        else:
            raise TimeoutError('pre-stop did not succeed within total budget')
        while time.monotonic() < deadline:
            status = scm.QueryServiceStatusEx(service)
            if status['CurrentState'] == scm.SERVICE_STOPPED:
                if status['Win32ExitCode'] or status['ServiceSpecificExitCode']:
                    raise RuntimeError('service exit was not clean')
                marker, corrupt = StateSnapshot(snapshot_path).read()
                if corrupt or (marker and marker['needs_recovery']):
                    raise RuntimeError('service exited with recovery responsibility')
                return
            if status['ProcessId'] != identity['pid']:
                raise RuntimeError('service changed instance before STOPPED')
            time.sleep(0.1)
        raise TimeoutError('service did not reach STOPPED')
    finally:
        if service is not None:
            scm.CloseServiceHandle(service)
        scm.CloseServiceHandle(manager)
