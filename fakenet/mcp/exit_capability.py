# Copyright 2026 Google LLC
"""Native no-network self-test of the installed managed exit handoff."""
import os
from pathlib import Path
import threading
import time
import uuid


def child_main(run_id, ready_handle):
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
    from fakenet.mcp.service_stop import process_identity
    process_identity()
    kernel.SetEvent.argtypes, kernel.SetEvent.restype = [w.HANDLE], w.BOOL
    kernel.CloseHandle.argtypes, kernel.CloseHandle.restype = [w.HANDLE], w.BOOL
    try:
        if not kernel.SetEvent(ready_handle):
            return 2
    finally:
        kernel.CloseHandle(ready_handle)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            record = read(root() / 'target.json')
        except FileNotFoundError:
            time.sleep(0.02)
            continue
        except (OSError, ValueError):
            # The owner republishes target.json with an atomic rename over
            # the previous probe's record; a reader in that instant can see
            # a transient access error. Retry inside the bounded deadline
            # instead of dying with an unhandled exception (discovery100-116
            # and -119 sst-034: the probe child self-exited 1 twice).
            time.sleep(0.02)
            continue
        if (record.get('run_id') == run_id and record.get('pid') == os.getpid()
                and record.get('command_line') == actual_command):
            kernel.ExitProcess.argtypes = [w.UINT]
            kernel.ExitProcess(0xc006)
        time.sleep(0.02)
    return 2


class NativeCapabilityOwner:
    """One pre-registered self-test responsibility, including failed setup."""
    def __init__(self, package, supervisor_identity, instance):
        self.package = Path(package)
        self.supervisor_identity, self.instance = supervisor_identity, instance
        self.job = self.retained = self.event = None
        self.fds, self.inherited = [], []
        self.deadline = None
        self.failure = None
        self.cleanup_errors = []
        self.attempted = False
        self._execution_done = False
        self._attempt_lock = threading.RLock()
        self._cancel = threading.Event()
        self.result = None

    def _close_event(self):
        if self.event is not None:
            if self.event in self.inherited:
                raise RuntimeError('event inheritance cleanup unconfirmed')
            if not self.job.kernel.CloseHandle(self.event):
                self.job._error()
            self.event = None

    def _release_inputs(self):
        if not self.inherited and not self.fds:
            return
        import msvcrt
        errors = []
        for handle in list(self.inherited):
            try:
                os.set_handle_inheritable(handle, False)
                self.inherited.remove(handle)
            except BaseException as exc:
                errors.append(repr(exc))
        for fd in list(self.fds):
            try:
                if msvcrt.get_osfhandle(fd) in self.inherited:
                    continue
                os.close(fd)
                self.fds.remove(fd)
            except BaseException as exc:
                errors.append(repr(exc))
        if errors:
            raise RuntimeError('capability input cleanup: ' + '; '.join(errors))

    def verify(self):
        with self._attempt_lock:
            if self.attempted:
                raise RuntimeError('native capability already attempted')
            self.attempted = True
            try:
                self._check_cancelled()
                return self._verify_attempt()
            finally:
                self._execution_done = True

    def _check_cancelled(self):
        if self._cancel.is_set():
            self.failure = self.failure or 'native capability cancelled'
            error = RuntimeError(self.failure)
            error.owner = self
            raise error

    def _verify_attempt(self):
        started = time.monotonic()
        self.deadline = started + 60
        run_id = str(uuid.uuid4())
        try:
            import msvcrt
            from fakenet.mcp.exit_files import root, publish
            from fakenet.mcp.jobobject import ManagedJob
            from fakenet.mcp.exit_retention import ExitRetention
            from fakenet.mcp.service_stop import process_identity
            self.job = ManagedJob()
            c, w = self.job.c, self.job.w
            create_event = self.job._bind('CreateEventW',
                [w.LPVOID, w.BOOL, w.BOOL, w.LPCWSTR], w.HANDLE)
            self.event = create_event(None, True, False, None)
            if not self.event:
                self.event = None
                self.job._error()
            for _ in range(3):
                self.fds.append(os.open(os.devnull, os.O_RDWR | os.O_BINARY))
            handles = [msvcrt.get_osfhandle(fd) for fd in self.fds] + [self.event]
            for handle in handles:
                os.set_handle_inheritable(handle, True)
                self.inherited.append(handle)
            pid = self.job.spawn([str(self.package / 'fakenetng-mcp-managed.exe'),
                'exit-capability', run_id, str(int(self.event))], root(), handles)
            self._release_inputs()
            self._check_cancelled()
            self.wait_ready()
            self._check_cancelled()
            self.retained = ExitRetention(run_id, process_identity(pid),
                self.supervisor_identity, self.instance, self.package,
                hard_deadline=self.deadline)
            self.retained.initialize()
            condition = threading.Condition()
            with condition:
                result = self.retained.wait(condition, self.deadline)
            while self.job.members() and time.monotonic() < self.deadline:
                time.sleep(0.02)
            if (not result or not result.get('complete') or
                    not self.retained.resources_ended() or
                    result.get('notification', {}).get('exit_status') != 0xc006 or
                    self.job.members()):
                raise RuntimeError('native exit capability failed: %r' % result)
            self._check_cancelled()
            publish(self.retained.directory / 'capability.json', dict(passed=True,
                run_id=run_id, elapsed_seconds=time.monotonic() - started,
                supervisor_instance=self.instance))
            self.result = dict(run_id=run_id, directory=str(self.retained.directory), passed=True)
        except BaseException as exc:
            self.failure = repr(exc)
            self._cleanup_resources(min(self.deadline, time.monotonic() + 1))
            exc.owner = self
            raise
        if not self._cleanup_resources(self.deadline):
            self.failure = 'native capability cleanup unconfirmed'
            error = RuntimeError(self.failure)
            error.owner = self
            raise error
        return self.result

    def wait_ready(self, budget=10):
        c, w = self.job.c, self.job.w
        wait = self.job._bind('WaitForMultipleObjects',
            [w.DWORD, c.POINTER(w.HANDLE), w.BOOL, w.DWORD], w.DWORD)
        # An exited child wins over a simultaneous event signal.
        objects = (w.HANDLE * 2)(self.job.process, self.event)
        remaining = max(0, min(10, budget, self.deadline - time.monotonic()))
        observed = wait(2, objects, False, int(remaining * 1000))
        self._close_event()
        if observed != 1:
            raise RuntimeError('native capability readiness failed: %r' % observed)

    def ended(self):
        return self._execution_done and self._resources_ended()

    def _resources_ended(self):
        return (self.job is None and self.event is None and not self.fds and
                not self.inherited and
                (self.retained is None or self.retained.resources_ended()))

    def cleanup(self, deadline):
        self._cancel.set()
        if not self._attempt_lock.acquire(timeout=max(0, deadline - time.monotonic())):
            self.cleanup_errors.append('native capability initialization still active')
            return False
        try:
            if not self.attempted:
                self.failure = self.failure or 'native capability cancelled before initialization'
                self._execution_done = True
            return self._cleanup_resources(deadline) and self.ended()
        finally:
            self._attempt_lock.release()

    def _cleanup_resources(self, deadline):
        errors = []
        for action in (self._release_inputs, self._close_event):
            try:
                action()
            except BaseException as exc:
                errors.append(repr(exc))
        if self.job is not None:
            try:
                if self.job.process:
                    self.job.terminate(deadline)
                    while self.job.poll() is None or self.job.members():
                        if time.monotonic() >= deadline:
                            raise TimeoutError('native capability Job object end unconfirmed')
                        time.sleep(min(0.02, max(0, deadline - time.monotonic())))
            except BaseException as exc:
                errors.append(repr(exc))
        if self.retained is not None:
            try:
                self.retained.cancel()
                if self.retained.done.is_set():
                    self.retained.settle(deadline)
                else:
                    condition = threading.Condition()
                    with condition:
                        self.retained.wait(condition, deadline)
            except BaseException as exc:
                errors.append(repr(exc))
        try:
            if (self.job is not None and
                    (not self.job.process or self.job.poll() is not None) and
                    not self.job.members() and not self.fds and not self.inherited and
                    self.event is None and
                    (self.retained is None or self.retained.resources_ended())):
                self.job.close()
                self.job = None
        except BaseException as exc:
            errors.append(repr(exc))
        self.cleanup_errors.extend(errors)
        return not errors and self._resources_ended()


def verify_native(package, supervisor_identity, instance, owner=None):
    owner = owner or NativeCapabilityOwner(package, supervisor_identity, instance)
    return owner.verify()
