# Copyright 2026 Google LLC
"""One fixed diagnostic call, with ownership surviving a caller's timeout.

The worker thread owns its Job and pipe handles. A deadline ends permission
for success, never ownership of an unobserved process. No command queue exists.
"""
import json
import os
from pathlib import Path
import sys
import threading
import time
import uuid

MAX_FRAME = 1024 * 1024


class DiagnosticError(RuntimeError):
    pass


class DiagnosticOwner:
    def __init__(self, package):
        self.package = Path(package)
        self._lock = threading.Lock()
        self.active = None
        self.last = None

    def pending(self):
        active = self.active
        return active is not None and not active.ended.is_set()

    def call(self, operation, payload, deadline, wait=None):
        with self._lock:
            if self.pending():
                raise DiagnosticError('previous diagnostic ownership is unresolved')
            task = DiagnosticCall(self.package, operation, payload, deadline)
            self.active = task
            task.start()
        if wait is None:
            task.done.wait(max(0, deadline - time.monotonic()))
        else:
            wait(task.done, deadline)
        # Expiration is an in-memory gate independent of publication or locks
        # held by a blocked native call in the owning worker.
        if not task.done.is_set() or time.monotonic() >= deadline:
            task.cancel.set()
            self.last = task.observation('deadline exceeded; end unconfirmed')
            raise DiagnosticError('diagnostic deadline exceeded; ownership retained')
        self.last = task.observation(task.error)
        if task.error or not task.ended.is_set():
            raise DiagnosticError(task.error or 'diagnostic resource end unconfirmed')
        return task.result


class DiagnosticCall:
    def __init__(self, package, operation, payload, deadline):
        self.package, self.deadline = package, deadline
        self.request = dict(schema='fakenet.diagnostic-call.v1',
                            attempt=str(uuid.uuid4()), parent_pid=os.getpid(),
                            operation=operation, payload=payload, deadline=deadline, started=time.monotonic())
        self.done, self.ended, self.cancel = (threading.Event() for _ in range(3))
        self.result = self.error = self.job = None
        self.native = []

    def observation(self, error=None):
        return dict(attempt=self.request['attempt'], operation=self.request['operation'],
                    deadline=self.deadline, error=error,
                    ended=self.ended.is_set(), native=list(self.native),
                    platform_blocked=False)

    def start(self):
        self.worker = threading.Thread(target=self._run, name='diagnostic-owner', daemon=True)
        self.worker.start()

    def _run(self):
        streams, descriptors, inherited = [], [], []
        response, io_errors = [], []
        writers = []
        try:
            import msvcrt
            from fakenet.mcp.jobobject import ManagedJob
            from fakenet.mcp.service_stop import process_identity
            self.request['parent_identity'] = process_identity()
            raw = json.dumps(self.request).encode('utf-8') + b'\n'
            if len(raw) > MAX_FRAME:
                raise DiagnosticError('diagnostic input exceeds fixed bound')
            self.job = ManagedJob()
            child_in, parent_out = os.pipe()
            parent_in, child_out = os.pipe()
            descriptors = [child_in, child_out]
            send = os.fdopen(parent_out, 'wb', buffering=0)
            receive = os.fdopen(parent_in, 'rb', buffering=0)
            null = open(os.devnull, 'wb')
            streams = [send, receive, null]
            inherited = [msvcrt.get_osfhandle(child_in), msvcrt.get_osfhandle(child_out),
                         msvcrt.get_osfhandle(null.fileno())]
            for handle in inherited:
                os.set_handle_inheritable(handle, True)
            command = ([str(self.package / 'fakenetng-mcp.exe')] if getattr(sys, 'frozen', False)
                       else [sys.executable, '-m', 'fakenet.mcp'])
            pid = self.job.spawn(command + ['diagnostic-task'], self.package, inherited)
            from fakenet.mcp.service_stop import process_identity
            self.native.append(dict(event='created', at=time.monotonic(), identity=process_identity(pid)))
            for handle in inherited:
                os.set_handle_inheritable(handle, False)
            inherited = []
            for fd in descriptors:
                os.close(fd)
            descriptors = []

            def exchange():
                try:
                    send.write(raw)
                    send.close()
                    frame = receive.readline(MAX_FRAME + 1)
                    if not frame.endswith(b'\n') or len(frame) > MAX_FRAME:
                        raise DiagnosticError('diagnostic result absent/oversize')
                    response.append(json.loads(frame))
                except BaseException as exc:
                    io_errors.append(repr(exc))
            writer = threading.Thread(target=exchange, name='diagnostic-pipe', daemon=True)
            writers.append(writer)
            writer.start()
            while self.job.poll() is None or self.job.members():
                if self.job.poll() is not None and self.job.members():
                    self.cancel.set()
                    self._terminate(min(self.deadline, time.monotonic()+1))
                    raise DiagnosticError('diagnostic leader exited with remaining descendants')
                if self.cancel.is_set() or time.monotonic() >= self.deadline:
                    self.cancel.set()
                    self._terminate()
                    break
                time.sleep(0.01)
            if self.cancel.is_set():
                raise DiagnosticError('diagnostic expired; result rejected')
            writer.join(max(0, self.deadline - time.monotonic()))
            if writer.is_alive() or io_errors or len(response) != 1:
                raise DiagnosticError('diagnostic IPC failed: ' + repr(io_errors))
            report = response[0]
            if (report.get('attempt') != self.request['attempt'] or
                    report.get('operation') != self.request['operation'] or
                    time.monotonic() >= self.deadline):
                raise DiagnosticError('diagnostic result identity/expiry mismatch')
            if report.get('error'):
                raise DiagnosticError(report['error'])
            if self.job.poll() != 0:
                raise DiagnosticError('diagnostic process failed')
            self.result = report['result']
        except BaseException as exc:
            self.error = repr(exc)
        finally:
            # done reports the finite attempt, ended reports actual resources.
            # Do not discard self.job when termination cannot be confirmed.
            try:
                if self.job and self.job.process and (self.job.poll() is None or self.job.members()):
                    self._terminate()
            except BaseException as exc:
                self.error = (self.error or '') + '; cleanup: ' + repr(exc)
            self.retained_streams, self.retained_descriptors = streams, descriptors
            self.retained_inherited, self.pipe_workers = inherited, writers
            try:
                self._release_if_ended()
            except BaseException as exc:
                self.error = (self.error or '') + '; observation: ' + repr(exc)
            self.done.set()
            # Keep the same owner alive to observe eventual exit. This is no
            # new task, no retry and no extension of success permission.
            while not self.ended.is_set():
                time.sleep(0.1)
                try:
                    self._release_if_ended()
                except BaseException:
                    pass

    def _release_if_ended(self):
        if self.job and self.job.process and (self.job.poll() is None or self.job.members()):
            return
        if self.job:
            self.job.close()
        for handle in self.retained_inherited:
            os.set_handle_inheritable(handle, False)
        self.retained_inherited = []
        for fd in self.retained_descriptors:
            os.close(fd)
        self.retained_descriptors = []
        # With the entire Job gone, pipe EOF is real. Wait for the exchange
        # thread before closing its streams from another thread.
        for writer in self.pipe_workers:
            writer.join(0.1)
        if any(writer.is_alive() for writer in self.pipe_workers):
            return
        for stream in self.retained_streams:
            stream.close()
        self.retained_streams = []
        self.ended.set()

    def _terminate(self, deadline=None):
        if any(item['event'] == 'terminate_requested' for item in self.native):
            return
        self.native.append(dict(event='terminate_requested', at=time.monotonic()))
        try:
            self.job.terminate(self.deadline if deadline is None else deadline)
            self.native.append(dict(event='terminate_observed', at=time.monotonic()))
        except BaseException as exc:
            self.native.append(dict(event='terminate_unconfirmed', at=time.monotonic(), error=repr(exc)))
            raise
