# Copyright 2026 Google LLC
"""Fixed lifecycle/health IPC to the current Job-contained FakeNet process."""

import json
import os
import queue
import sys
import threading
import time
from pathlib import Path


class ManagedProcess:
    def __init__(self, run_id, run_dir, package_root):
        import msvcrt
        from fakenet.mcp.jobobject import ManagedJob
        from fakenet.mcp.service_stop import process_identity
        self.run_id = run_id
        self.run_dir = Path(run_dir)
        self.job = ManagedJob()
        self._sequence = 0
        self._lock = threading.Lock()
        self._responses = queue.Queue(maxsize=64)
        self._reader = None
        self._write_failed = False
        child_in, parent_out = os.pipe()
        parent_in, child_out = os.pipe()
        self._send = os.fdopen(parent_out, 'wb', buffering=0)
        self._receive = os.fdopen(parent_in, 'rb', buffering=0)
        self.stderr = self.run_dir / 'stdout_stderr.log'
        error_log = self.stderr.open('ab', buffering=0)
        handles = [msvcrt.get_osfhandle(child_in), msvcrt.get_osfhandle(child_out),
                   msvcrt.get_osfhandle(error_log.fileno())]
        command = ([sys.executable] if getattr(sys, 'frozen', False) else
                   [sys.executable, '-m', 'fakenet.mcp'])
        command += ['managed-child', run_id, str(self.run_dir)]
        try:
            for handle in handles:
                os.set_handle_inheritable(handle, True)
            self.pid = self.job.spawn(command, package_root, handles)
            self.identity = process_identity(self.pid)
        except BaseException:
            self.job.close()
            self._send.close()
            self._receive.close()
            raise
        finally:
            for handle in handles:
                os.set_handle_inheritable(handle, False)
            os.close(child_in)
            os.close(child_out)
            error_log.close()
        self._reader = threading.Thread(target=self._read, name='managed-ipc', daemon=True)
        self._reader.start()

    def _read(self):
        try:
            while True:
                raw = self._receive.readline(4 * 1024 * 1024)
                if not raw:
                    raise EOFError('managed IPC EOF')
                if not raw.endswith(b'\n'):
                    raise ValueError('managed response exceeded size limit')
                self._responses.put_nowait(json.loads(raw))
        except BaseException as exc:
            try:
                self._responses.put_nowait(exc)
            except queue.Full:
                pass

    def alive(self):
        return self.job.poll() is None and self.pid in self.job.members()

    def request(self, kind, payload=None, timeout=1):
        if kind not in ('start', 'stop', 'health', 'stacks'):
            raise ValueError('unsupported managed operation')
        deadline = time.monotonic() + timeout
        if not self._lock.acquire(timeout=max(0, timeout)):
            raise TimeoutError('managed IPC operation busy')
        try:
            self._sequence += 1
            seq = self._sequence
            message = {'run_id': self.run_id, 'seq': seq, 'kind': kind,
                       'payload': payload or {}}
            if not self.alive():
                raise EOFError('managed process exited')
            if self._write_failed:
                raise EOFError('managed IPC write was cancelled')
            encoded = json.dumps(message).encode('utf-8') + b'\n'
            errors = []
            def write():
                try:
                    self._send.write(encoded)
                except BaseException as exc:
                    errors.append(exc)
            writer = threading.Thread(target=write, name='managed-ipc-write', daemon=True)
            writer.start()
            writer.join(max(0, deadline - time.monotonic()))
            if writer.is_alive():
                self._write_failed = True
                raise TimeoutError('managed IPC write deadline exceeded')
            if errors:
                raise errors[0]
            try:
                response = self._responses.get(timeout=max(0, deadline - time.monotonic()))
            except queue.Empty as exc:
                raise TimeoutError('managed IPC response timeout') from exc
            if isinstance(response, BaseException):
                raise response
            if response.get('run_id') != self.run_id or response.get('seq') != seq:
                raise RuntimeError('managed IPC run/sequence mismatch')
            if response.get('error'):
                raise RuntimeError(response['error'])
            return response['result']
        finally:
            self._lock.release()

    def terminate(self, deadline):
        self.job.terminate(deadline)

    def close(self):
        self.job.close()
        self._send.close()
        if self._reader:
            self._reader.join(timeout=1)
        self._receive.close()


def probe_instance(instance):
    """Observe real WinDivert/listener handles; used only inside the child."""
    diverter = getattr(instance, 'diverter', None)
    handle = getattr(diverter, 'handle', None)
    providers = getattr(instance, 'running_listener_providers', None) or []
    listeners = bool(providers)
    for provider in providers:
        sockets = [getattr(provider, attr, None) for attr in ('server', 'sock', 'socket')]
        descriptors = [sock for sock in sockets if callable(getattr(sock, 'fileno', None))]
        if not descriptors or any(sock.fileno() < 0 for sock in descriptors):
            listeners = False
    return {'init_evidence': bool(providers),
            'probe': bool(handle and getattr(handle, 'is_open', False) and listeners),
            'final_filter': str(getattr(diverter, 'filter', '')),
            'listeners': [type(p).__name__ for p in providers]}


def redirect_child_streams(run_dir):
    import ctypes as c
    from ctypes import wintypes as w
    kernel = c.WinDLL("kernel32", use_last_error=True)
    # Keep private, non-inheritable IPC duplicates, then redirect the OS
    # standard handles as well as Python's streams. certutil and other
    # subprocesses write through the OS handles, bypassing sys.stdout.
    protocol_in = os.fdopen(os.dup(sys.stdin.fileno()), 'rb', buffering=0)
    protocol_out = os.fdopen(os.dup(sys.stdout.fileno()), 'wb', buffering=0)
    directory = Path(run_dir)
    output = (directory / 'stdout_stderr.log').open('a', encoding='utf-8', buffering=1)
    import msvcrt
    kernel.SetStdHandle.argtypes = [w.DWORD, w.HANDLE]
    kernel.SetStdHandle.restype = w.BOOL
    with open(os.devnull, 'rb') as null_input:
        os.dup2(null_input.fileno(), 0)
    os.dup2(output.fileno(), 1)
    os.dup2(output.fileno(), 2)
    for standard, fd in ((-10, 0), (-11, 1), (-12, 2)):
        if not kernel.SetStdHandle(standard & 0xffffffff, msvcrt.get_osfhandle(fd)):
            raise c.WinError(c.get_last_error())
    sys.stdout = sys.stderr = output
    return protocol_in, protocol_out, output


def child_main(run_id, run_dir):
    """Internal entry; fixed commands, no arbitrary code or file RPC."""
    import ctypes as c
    from ctypes import wintypes as w
    kernel = c.WinDLL('kernel32', use_last_error=True)
    kernel.GetCurrentProcess.restype = w.HANDLE
    kernel.IsProcessInJob.argtypes = [w.HANDLE, w.HANDLE, c.POINTER(w.BOOL)]
    contained = w.BOOL()
    if not kernel.IsProcessInJob(kernel.GetCurrentProcess(), None, c.byref(contained)) or not contained:
        raise RuntimeError('managed entry requires existing Job membership')
    protocol_in, protocol_out, output = redirect_child_streams(run_dir)
    directory = Path(run_dir)
    import logging
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s %(levelname)s %(name)s %(message)s',
                        handlers=[logging.FileHandler(directory / 'run.log', encoding='utf-8'),
                                  logging.StreamHandler(output)], force=True)
    from fakenet.fakenet import Fakenet
    from fakenet.mcp.faultinject import FaultInjector
    from fakenet.mcp.incident import IncidentCollector
    instance = None
    fault = FaultInjector()
    seq = 0
    for raw in protocol_in:
        request = json.loads(raw)
        if request.get('run_id') != run_id or request.get('seq') != seq + 1:
            raise RuntimeError('invalid managed request identity/sequence')
        seq = request['seq']
        response = {'run_id': run_id, 'seq': seq}
        exiting = False
        try:
            kind = request['kind']
            if kind == 'start' and instance is None:
                payload = request['payload']
                instance = Fakenet()
                instance.parse_config(payload['config_path'])
                instance.fakenet_config.update(payload['fakenet_config'])
                instance.diverter_config.update(payload['diverter_config'])
                instance.start()
                fault.inject_listener_stop(instance.running_listener_providers)
                fault.inject_diverter_stop(instance.diverter)
                fault.inject_child_hang()
                response['result'] = probe_instance(instance)
            elif kind == 'health' and instance is not None:
                response['result'] = probe_instance(instance)
            elif kind == 'stacks':
                response['result'] = {'stacks': IncidentCollector._thread_stacks()}
            elif kind == 'stop' and instance is not None:
                fault.before_listener_phase()
                instance.stop()
                fault.on_stop_error()
                response['result'] = {'stopped': True}
                exiting = True
            else:
                raise RuntimeError('managed operation not allowed in current state')
        except BaseException:
            import traceback
            detail = traceback.format_exc()
            logging.getLogger('managed').error(detail)
            response['error'] = detail
        protocol_out.write(json.dumps(response).encode('utf-8') + b'\n')
        protocol_out.flush()
        if exiting:
            return 0
    return 1
