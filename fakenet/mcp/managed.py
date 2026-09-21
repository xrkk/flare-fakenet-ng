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
    def __init__(self, run_id, run_dir, package_root, executable=None):
        # No external resources until the supervisor has stored this owner.
        self.run_id, self.run_dir = run_id, Path(run_dir)
        self.package_root, self.executable = Path(package_root), executable
        self.job = self.pid = self.identity = None
        self._sequence = 0
        self._lock = threading.Lock()
        self._responses = queue.Queue(maxsize=64)
        self._reader = self._send = self._receive = None
        self._write_failed = False
        self._protocol_failure = self._read_failure = None
        self.initialized = self._initialization_attempted = False
        self.failure = None
        self.cleanup_errors = []
        self._descriptors, self._inherited, self._streams = [], [], []
        self.stderr = self.run_dir / 'stdout_stderr.log'

    def initialize(self):
        if self._initialization_attempted:
            raise RuntimeError('managed initialization already attempted')
        self._initialization_attempted = True
        try:
            import msvcrt
            from fakenet.mcp.jobobject import ManagedJob
            from fakenet.mcp.service_stop import process_identity
            from fakenet.mcp.creation_evidence import observe_creation
            observe_creation(self.run_id, self.run_dir, None, 'before_job')
            self.job = ManagedJob()
            child_in, parent_out = os.pipe()
            self._descriptors.extend((child_in, parent_out))
            parent_in, child_out = os.pipe()
            self._descriptors.extend((parent_in, child_out))
            self._send = os.fdopen(parent_out, 'wb', buffering=0)
            self._descriptors.remove(parent_out)
            self._streams.append(self._send)
            self._receive = os.fdopen(parent_in, 'rb', buffering=0)
            self._descriptors.remove(parent_in)
            self._streams.append(self._receive)
            error_log = self.stderr.open('ab', buffering=0)
            self._streams.append(error_log)
            handles = [msvcrt.get_osfhandle(child_in), msvcrt.get_osfhandle(child_out),
                       msvcrt.get_osfhandle(error_log.fileno())]
            command = ([str(self.executable)] if self.executable else
                       [str(self.package_root / 'fakenetng-mcp-managed.exe')]
                       if getattr(sys, 'frozen', False) else
                       [sys.executable, '-m', 'fakenet.mcp'])
            command += ['managed-child', self.run_id, str(self.run_dir)]
            self.observe_creation('job_ready')
            for handle in handles:
                os.set_handle_inheritable(handle, True)
                self._inherited.append(handle)
            self.pid = self.job.spawn(command, self.run_dir, handles,
                                      observe=self.observe_creation)
            self.identity = process_identity(self.pid)
            self._release_inherited()
            for fd in (child_in, child_out):
                os.close(fd)
                self._descriptors.remove(fd)
            error_log.close()
            self._streams.remove(error_log)
            self._reader = threading.Thread(target=self._read, name='managed-ipc', daemon=True)
            self._reader.start()
            self.initialized = True
            return self
        except BaseException as exc:
            self.failure = repr(exc)
            # The pre-registered owner survives, including spawn's after_api
            # callback failure before spawn returns the PID to this frame.
            if self.job is not None:
                self.pid = self.pid or self.job.pid
            raise

    def _release_inherited(self):
        for handle in list(self._inherited):
            os.set_handle_inheritable(handle, False)
            self._inherited.remove(handle)

    def wait_ready(self, timeout=10):
        result = self.request('ready', timeout=min(10, timeout))
        identity = result.get('identity', {})
        if (result.get('ready') is not True or self.identity is None or
                any(identity.get(k) != self.identity.get(k)
                    for k in ('pid', 'creation_time'))):
            raise RuntimeError('managed readiness identity mismatch')
        return result

    def cleanup(self, deadline):
        # No IPC or diagnostic capture for an incomplete initialization.
        try:
            if self.job is not None and self.job.process:
                self.terminate(deadline)
            self.close()
            return True
        except BaseException as exc:
            self.cleanup_errors.append(repr(exc))
            return False

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
        return bool(self.job is not None and self.job.poll() is None and self.pid in self.job.members())

    def request(self, kind, payload=None, timeout=1):
        if kind not in ('ready', 'start', 'stop', 'health', 'stacks'):
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

    def _record_termination(self, event, error=None):
        # Supplemental fault-test evidence, not a filter-close timestamp or
        # recovery gate. A diagnostic failure must never prevent containment.
        try:
            if os.environ.get('FAKENETNG_MCP_FAULT_INJECTION') != '1':
                return
            from fakenet.mcp.faultinject import native_clock_observation
            record_ipc(self.run_dir, 'parent', event, dict(
                run_id=self.run_id, identity=self.identity,
                native_clock=native_clock_observation(), error=error))
        except Exception:
            pass

    def terminate(self, deadline):
        self._record_termination('job-terminate-begin')
        try:
            self.job.terminate(deadline)
            self._record_termination('job-terminate-returned')
            while self.job.poll() is None or self.job.members():
                if time.monotonic() >= deadline:
                    raise TimeoutError('managed Job object end unconfirmed')
                time.sleep(min(0.02, max(0, deadline - time.monotonic())))
        except BaseException as exc:
            self._record_termination('job-terminate-error', repr(exc))
            raise
        self._record_termination('job-empty-confirmed')

    def close(self):
        if self.job is not None:
            if self.job.process and (self.job.poll() is None or self.job.members()):
                raise RuntimeError('managed Job end unconfirmed; ownership retained')
        errors = []
        for handle in list(self._inherited):
            try:
                os.set_handle_inheritable(handle, False)
                self._inherited.remove(handle)
            except BaseException as exc:
                errors.append(repr(exc))
        for fd in list(self._descriptors):
            try:
                if self._inherited:
                    import msvcrt
                    if msvcrt.get_osfhandle(fd) in self._inherited:
                        continue
                os.close(fd)
                self._descriptors.remove(fd)
            except BaseException as exc:
                errors.append(repr(exc))
        if self._reader and self._reader.ident is not None:
            self._reader.join(timeout=1)
            if self._reader.is_alive():
                raise RuntimeError('managed pipe reader end unconfirmed')
        for stream in list(self._streams):
            try:
                if self._inherited and not stream.closed:
                    import msvcrt
                    if msvcrt.get_osfhandle(stream.fileno()) in self._inherited:
                        continue
                stream.close()
                self._streams.remove(stream)
            except BaseException as exc:
                errors.append(repr(exc))
        if self.job is not None and not errors:
            self.job.close()
            self.job = None
        if errors:
            raise RuntimeError('managed cleanup: ' + '; '.join(errors))


def probe_instance(instance):
    """Observe real WinDivert/listener handles; used only inside the child."""
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
        try:
            detail = provider.health_snapshot()
            handles = detail['handles']
            live = (detail.get('alive') is True and isinstance(handles, list) and
                    bool(handles) and all(isinstance(fd, int) and fd >= 0 for fd in handles))
            observation = {'handles': handles, 'alive': live}
            if detail.get('error'):
                observation['error'] = detail['error']
        except Exception as exc:
            live = False
            observation = {'handles': [], 'alive': False, 'error': repr(exc)}
        observations.append(dict(observation, provider=type(provider).__name__,
                                 name=getattr(provider, 'name', None)))
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
            if kind == 'ready' and instance is None:
                response['result'] = {'ready': True, 'identity': {
                    key: identity[key] for key in ('pid', 'creation_time')}}
            elif kind == 'start' and instance is None:
                payload = request['payload']
                instance = Fakenet()
                instance.parse_config(payload['config_path'])
                instance.fakenet_config.update(payload['fakenet_config'])
                instance.diverter_config.update(payload['diverter_config'])
                fault.install_initialization_hook(instance)
                instance.start()
                fault.wait_for_start_gate()
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
            elif kind == 'stop':
                if instance is not None:
                    try:
                        with capture_stop_stacks(directory):
                            fault.before_listener_phase()
                            # Inject at the resource-release entry, while the
                            # managed session is still owned and recoverable.
                            fault.on_stop_error()
                            instance.stop()
                    except BaseException:
                        # The orderly listeners-then-diverter teardown did
                        # not run.  Until the supervisor's Job termination
                        # releases the filter, reset the redirected client
                        # flows so their kernel TCBs cannot emit on the
                        # original tuples after the filter is gone
                        # (candidate10 sst-004 primary leak).  A quiesce
                        # failure is diagnostic only and never masks the
                        # original stop error.
                        try:
                            instance.quiesce_redirected_flows('managed_stop_failed')
                        except BaseException:
                            logging.getLogger('managed').exception(
                                'redirected-flow quiesce after failed stop '
                                'raised')
                        raise
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
