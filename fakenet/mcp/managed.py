# Copyright 2026 Google LLC
"""Fixed lifecycle/health IPC to the current Job-contained FakeNet process."""

import json
import os
import queue
import sys
import threading
import time
from pathlib import Path
from contextlib import contextmanager


def record_ipc(run_dir, side, event, frame=None, error=None):
    """Raw test evidence only; not a replay log or recovery state source."""
    if os.environ.get('FAKENETNG_MCP_FAULT_INJECTION') != '1':
        return
    entry = {'time': time.time(), 'monotonic': time.monotonic(),
             'pid': os.getpid(), 'side': side, 'event': event,
             'frame': frame, 'error': error}
    with (Path(run_dir) / ('ipc-' + side + '.jsonl')).open('a', encoding='utf-8') as stream:
        stream.write(json.dumps(entry, ensure_ascii=False) + '\n')


def install_thread_exception_logging():
    """Keep actual uncaught child-thread stacks in the current run log."""
    import logging
    previous = threading.excepthook
    def record(args):
        logging.getLogger('managed.thread').error(
            'Unhandled exception in managed thread %s', args.thread.name,
            exc_info=(args.exc_type, args.exc_value, args.exc_traceback))
        previous(args)
    threading.excepthook = record


@contextmanager
def capture_stop_stacks(run_dir):
    """Capture live Python stacks even while stop blocks the IPC loop."""
    import traceback
    stopped = threading.Event()
    with (Path(run_dir) / 'stop-thread-stacks.txt').open('ab', buffering=0) as stream:
        stream.write(('STOP ATTEMPT pid=%d timestamp=%.6f\n' %
                      (os.getpid(), time.time())).encode('ascii'))
        def capture():
            # Walk owned frame references under the GIL. The native faulthandler
            # watchdog walks concurrently executing frames without it; our
            # pinned Windows interpreter crashed during that walk in acceptance.
            frames = sys._current_frames()
            try:
                chunks = ['LIVE STOP STACKS timestamp=%.6f\n' % time.time()]
                for ident, frame in frames.items():
                    chunks.append('Thread 0x%x:\n' % ident)
                    chunks.extend(traceback.format_stack(frame))
                stream.write(''.join(chunks).encode('utf-8', errors='replace'))
            finally:
                frames.clear()

        def watch():
            while not stopped.wait(1):
                capture()

        watchdog = threading.Thread(target=watch, name='stop-stack-capture', daemon=True)
        watchdog.start()
        try:
            yield
        finally:
            stopped.set()
            watchdog.join()
            capture()


class ManagedProcess:
    def __init__(self, run_id, run_dir, package_root):
        import msvcrt
        from fakenet.mcp.jobobject import ManagedJob
        from fakenet.mcp.service_stop import process_identity
        self.run_id = run_id
        self.run_dir = Path(run_dir)
        from fakenet.mcp.creation_evidence import observe_creation
        observe_creation(run_id, self.run_dir, None, 'before_job')
        self.job = ManagedJob()
        self._sequence = 0
        self._lock = threading.Lock()
        self._responses = queue.Queue(maxsize=64)
        self._reader = None
        self._write_failed = False
        self._protocol_failure = None
        child_in, parent_out = os.pipe()
        parent_in, child_out = os.pipe()
        self._send = os.fdopen(parent_out, 'wb', buffering=0)
        self._receive = os.fdopen(parent_in, 'rb', buffering=0)
        self.stderr = self.run_dir / 'stdout_stderr.log'
        error_log = self.stderr.open('ab', buffering=0)
        handles = [msvcrt.get_osfhandle(child_in), msvcrt.get_osfhandle(child_out),
                   msvcrt.get_osfhandle(error_log.fileno())]
        command = ([str(Path(package_root) / 'fakenetng-mcp-managed.exe')] if getattr(sys, 'frozen', False) else
                   [sys.executable, '-m', 'fakenet.mcp'])
        command += ['managed-child', run_id, str(self.run_dir)]
        try:
            self.observe_creation('job_ready')
            for handle in handles:
                os.set_handle_inheritable(handle, True)
            self.pid = self.job.spawn(command, self.run_dir, handles,
                                      observe=self.observe_creation)
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
        self._read_failure = None
        self._reader.start()

    def observe_creation(self, stage):
        from fakenet.mcp.creation_evidence import observe_creation
        observe_creation(self.run_id, self.run_dir, self.job, stage)

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
            self._read_failure = exc
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
            record_ipc(self.run_dir, 'parent', 'request', message)
            if not self.alive():
                raise EOFError('managed process exited')
            if getattr(self, '_protocol_failure', None) is not None:
                raise self._protocol_failure.with_traceback(None)
            if getattr(self, '_read_failure', None) is not None:
                raise self._read_failure.with_traceback(None)
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
            record_ipc(self.run_dir, 'parent', 'response', response)
            if response.get('run_id') != self.run_id or response.get('seq') != seq:
                # This channel has lost its run/sequence contract. Sending stop
                # or stacks through it can consume a stale response and invent
                # a later timeout; retain the original terminal fault instead.
                self._protocol_failure = RuntimeError('managed IPC run/sequence mismatch')
                raise self._protocol_failure
            if response.get('error'):
                raise RuntimeError(response['error'])
            return response['result']
        except BaseException as exc:
            record_ipc(self.run_dir, 'parent', 'failure',
                       {'run_id': self.run_id, 'seq': self._sequence, 'kind': kind}, repr(exc))
            raise
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
    from fakenet.listeners.DomainEgressRelay import DomainEgressRelay

    diverter = getattr(instance, 'diverter', None)
    handle = getattr(diverter, 'handle', None)
    main_thread = getattr(diverter, 'diverter_thread', None)
    inbound_thread = getattr(diverter, 'inbound_capture_thread', None)
    capture_error = getattr(diverter, 'capture_failure', None)
    capture_alive = bool(main_thread and main_thread.is_alive())
    if inbound_thread is not None:
        capture_alive = capture_alive and inbound_thread.is_alive()
    if getattr(diverter, '_inbound_capture_handle', None) is not None and inbound_thread is None:
        capture_alive = False
    providers = getattr(instance, 'running_listener_providers', None) or []
    listeners = bool(providers)
    observations = []
    for provider in providers:
        if isinstance(provider, DomainEgressRelay):
            # The relay owns its listener directly rather than a socketserver.
            # Both resources are required, including during startup/teardown.
            sockets = [provider._listener]
            thread = provider._accept_thread
            thread_alive = thread is not None and thread.is_alive()
        else:
            sockets = [getattr(provider, attr, None) for attr in ('server', 'sock', 'socket')]
            sockets.append(getattr(getattr(provider, 'server', None), 'socket', None))
            thread = getattr(provider, 'server_thread', None)
            thread_alive = thread is None or thread.is_alive()
        descriptors = [sock for sock in sockets if callable(getattr(sock, 'fileno', None))]
        live = bool(descriptors) and all(sock.fileno() >= 0 for sock in descriptors) and thread_alive
        observations.append({'provider': type(provider).__name__,
                             'name': getattr(provider, 'name', None),
                             'handles': [sock.fileno() for sock in descriptors], 'alive': live})
        if not live:
            listeners = False
    return {'init_evidence': bool(providers),
            'probe': bool(handle and getattr(handle, 'is_open', False) and listeners
                          and capture_alive and capture_error is None),
            'capture_threads_alive': capture_alive,
            'capture_error': str(capture_error) if capture_error is not None else None,
            'final_filter': str(getattr(diverter, 'filter', '')),
            'listeners': observations}


def probe_with_faults(instance, fault):
    """Apply locally armed active-run failure at the actual health request."""
    fault.inject_diverter_stop(instance.diverter)
    return probe_instance(instance)


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
    install_thread_exception_logging()
    from fakenet.fakenet import Fakenet
    from fakenet.mcp.faultinject import FaultInjector
    from fakenet.mcp.incident import IncidentCollector
    from fakenet.mcp.managed_stacks import save_stacks
    from fakenet.mcp.service_stop import process_identity
    identity = process_identity(os.getpid())
    instance = None
    channel_closed = False
    fault = FaultInjector()
    seq = 0
    for raw in protocol_in:
        request = json.loads(raw)
        record_ipc(directory, 'child', 'request', request)
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
                fault.install_initialization_hook(instance)
                instance.start()
                fault.install_listener_exception_hook(instance.running_listener_providers)
                fault.install_capture_exception_hook(instance.diverter)
                fault.inject_listener_stop(instance.running_listener_providers)
                fault.inject_diverter_stop(instance.diverter)
                fault.inject_child_hang()
                response['result'] = probe_instance(instance)
            elif kind == 'health' and instance is not None:
                response['result'] = probe_with_faults(instance, fault)
            elif kind == 'stacks':
                response['result'] = {'stacks': IncidentCollector._thread_stacks()}
            elif kind == 'stop' and instance is not None:
                with capture_stop_stacks(directory):
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
        if request.get('kind') in ('start', 'health', 'stacks') and instance is not None:
            try:
                save_stacks(directory, run_id, identity, IncidentCollector._thread_stacks())
            except OSError as exc:
                logging.getLogger('managed').warning('managed stack snapshot unavailable: %r', exc)
        action, response = fault.ipc_response(request, response)
        record_ipc(directory, 'child', action,
                   response if action == 'send' else request)
        if action == 'drop':
            continue
        if action == 'eof':
            protocol_out.close()
            channel_closed = True
            continue
        if not channel_closed:
            protocol_out.write(json.dumps(response).encode('utf-8') + b'\n')
            protocol_out.flush()
        if exiting:
            return 0
    return 1
