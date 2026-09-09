# Copyright 2026 Google LLC
"""Repeatable fault injection for acceptance (P04 IMP-P04-05).

Five RACC-013 fault classes with distinct, attributable mechanisms.  Only
active when the service process runs with
``FAKENETNG_MCP_FAULT_INJECTION=1`` AND a fault is explicitly armed via
the fixed local ``logs/fault-injection.json``; never exposed as an MCP tool, disabled by
default in production.

Faults:
  policy_pause      — the stop sequence stalls before the listener phase
  listener_stop     — a running listener's listening socket is shut down
  diverter_stop     — the main WinDivert handle is closed directly
  child_hang        — a managed-range child process refuses to exit
  cleanup_error     — the stop sequence raises at a chosen phase
"""

import os
import socket
import threading
import time
import json
from pathlib import Path

FAULTS = ('policy_pause', 'listener_stop', 'diverter_stop', 'child_hang',
          'cleanup_error', 'listener_exception', 'initialization_failure', 'ipc_once_timeout',
          'ipc_permanent_timeout', 'ipc_eof', 'ipc_wrong_run',
          'ipc_repeat', 'ipc_reverse', 'create_before_job', 'create_job_ready',
          'create_attributes_ready', 'create_before_api',
          'create_after_api', 'create_before_start')
IPC_FAULTS = frozenset(fault for fault in FAULTS if fault.startswith('ipc_'))


def enabled():
    return os.environ.get('FAKENETNG_MCP_FAULT_INJECTION') == '1'


def armed_fault():
    path = _fault_file()
    if path.is_file():
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
            if set(data) == {'fault', 'nonce'} and data['fault'] in FAULTS and data['nonce']:
                return data['fault']
        except (OSError, ValueError, TypeError):
            return None
    return None


def _fault_file():
    return Path(os.environ.get('PROGRAMDATA', 'C:/ProgramData')) / 'FakeNet-NG-MCP' / 'logs' / 'fault-injection.json'


def clear():
    path = _fault_file()
    if enabled() and path.is_file():
        receipt = Path.cwd() / 'fault-triggered.json'
        # Each run has its own directory. Retain the exact nonce/class for
        # the native runner; never overwrite another run's receipt.
        with receipt.open('x', encoding='utf-8') as stream:
            stream.write(path.read_text(encoding='utf-8'))
        path.unlink()


class FaultInjector:

    """Hooks consumed by the supervisor's stop/start path."""

    def __init__(self):
        self._held_sockets = []
        self._child = None
        self._ipc_fault = None

    def ipc_response(self, request, response):
        """Alter only actual health responses on the private child pipe.

        A one-shot timeout drops one response entirely; it never queues a
        stale frame or changes the receiver's strict sequence validation.
        """
        if not enabled() or request.get('kind') != 'health':
            return 'send', response
        armed = armed_fault()
        if armed in IPC_FAULTS:
            clear()
            self._ipc_fault = armed
        fault = self._ipc_fault
        if fault == 'ipc_permanent_timeout':
            return 'drop', None
        self._ipc_fault = None
        if fault == 'ipc_once_timeout':
            return 'drop', None
        if fault == 'ipc_eof':
            return 'eof', None
        if fault in ('ipc_wrong_run', 'ipc_repeat', 'ipc_reverse'):
            response = dict(response)
            if fault == 'ipc_wrong_run':
                response['run_id'] = '00000000-0000-0000-0000-000000000000'
            else:
                response['seq'] -= 1 if fault == 'ipc_repeat' else 2
        return 'send', response

    def arm(self, fault):
        if fault not in FAULTS:
            raise ValueError('unknown fault %r' % fault)
        import uuid
        path = _fault_file()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('x', encoding='utf-8') as stream:
            json.dump({'fault': fault, 'nonce': str(uuid.uuid4())}, stream)

    # -- stop-path hooks ---------------------------------------------------
    def before_listener_phase(self):
        if enabled() and armed_fault() == 'policy_pause':
            clear()
            time.sleep(3600)

    def on_stop_error(self):
        """cleanup_error: raise once when the stop sequence runs."""
        if enabled() and armed_fault() == 'cleanup_error':
            clear()
            raise RuntimeError('injected cleanup error')

    # -- run-path hooks -----------------------------------------------------
    def install_initialization_hook(self, instance):
        """Called only in the managed child; fail inside actual Fakenet.start."""
        if not enabled():
            return False
        def initialize():
            if enabled() and armed_fault() == 'initialization_failure':
                clear()
                raise RuntimeError('injected managed initialization failure')
        instance._managed_initialization_hook = initialize
        return True

    def install_listener_exception_hook(self, listeners):
        """Raise in the real HTTP serve_forever thread, when locally armed.

        The extra P03 anomaly case does not change the five release fault
        classes. Merely installing this test-only hook consumes no receipt.
        """
        if not enabled():
            return False
        for listener in listeners or []:
            server = getattr(listener, 'server', None)
            original = getattr(server, 'service_actions', None)
            worker = getattr(listener, 'server_thread', None)
            if callable(original) and worker is not None and worker.is_alive():
                def service_actions(original=original):
                    if enabled() and armed_fault() == 'listener_exception':
                        clear()
                        raise RuntimeError('injected listener thread exception')
                    return original()
                server.service_actions = service_actions
                return True
        return False

    def inject_listener_stop(self, listeners):
        """Close the first bound listener socket (representative class)."""
        if not (enabled() and armed_fault() == 'listener_stop'):
            return False
        clear()
        for listener in listeners or []:
            sock = getattr(listener, 'sock', None) or getattr(
                listener, 'socket', None) or getattr(getattr(listener, 'server', None), 'socket', None)
            if isinstance(sock, socket.socket):
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                    sock.close()
                    return True
                except OSError:
                    continue
        return False

    def inject_diverter_stop(self, diverter):
        if not (enabled() and armed_fault() == 'diverter_stop'):
            return False
        clear()
        handle = getattr(diverter, 'handle', None)
        if handle is None:
            return False
        try:
            handle.close()
        finally:
            diverter.handle = None
        return True

    def inject_child_hang(self):
        """Spawn a managed-range child that refuses to exit."""
        if not (enabled() and armed_fault() == 'child_hang'):
            return False
        clear()
        import subprocess
        import sys

        prefix = ([sys.executable] if getattr(sys, 'frozen', False) else
                  [sys.executable, '-m', 'fakenet.mcp'])
        self._child = subprocess.Popen(
            prefix + ['managed-fault-hang'],
            creationflags=getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0))
        return True

    def release(self):
        for sock in self._held_sockets:
            try:
                sock.close()
            except OSError:
                pass
        self._held_sockets = []
        if self._child is not None:
            try:
                self._child.terminate()
                self._child.wait(timeout=10)
            except Exception:  # noqa: BLE001
                pass
            self._child = None
